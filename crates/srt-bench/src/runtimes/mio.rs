//! mio adapter: flat single-threaded epoll loop over all sockets — mio's
//! designed primitive (no task model, no native timer wheel; timers are
//! `ManualTimerStore` inside Conn). Connection i lives on port + i, each
//! registered with Token(i).

use crate::{Aggregate, BenchConfig, BondMode, ConnStats};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, GroupExtensionData, SrtConnection};
use srt_transport::mio_transport::Conn;
use srt_transport::{Handoff, WorkerMessage};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// Upper bound on the poll timeout so the loop still notices deadlines
/// promptly when idle.
const MAX_POLL_WAIT: Duration = Duration::from_millis(20);

/// Poll tick for receivers: matches the 10ms ACK timer cadence so timers
/// are serviced on schedule without busy-polling.
const TIMER_TICK: Duration = Duration::from_millis(10);

/// Drain one socket for admission, calling `on_datagram(peer, data)` for
/// each queued datagram -- either batched (`recvmmsg`, one syscall for up
/// to `admit_bufs.len()` datagrams) or one `recv_from` syscall per
/// datagram, per `BenchConfig::batching`. This is the axis `Batching`
/// exists to let a run select: isolating whatever win (or lack of one)
/// batched admission gives at a given fan-in level from every other
/// variable. Shared by every ingress strategy that has a socket serving
/// more than one peer at once (`SharedPool`, `ReuseportMulti`,
/// `ReuseportSingle`) -- `PerPort` never shares a socket, so batching
/// doesn't apply there.
/// Scratch space for one batched-receive admission drain: fixed-capacity
/// slots reused across every readiness event instead of reallocated per
/// event (hot-path rule). `CAPACITY` is how many datagrams `recvmsg_batch`
/// is willing to fill in one syscall.
struct RecvBatch {
    bufs: Vec<Vec<u8>>,
    sizes: [usize; Self::CAPACITY],
    addrs: [Option<SocketAddr>; Self::CAPACITY],
}

impl RecvBatch {
    const CAPACITY: usize = 32;

    fn new() -> Self {
        Self {
            bufs: (0..Self::CAPACITY).map(|_| vec![0u8; 2048]).collect(),
            sizes: [0usize; Self::CAPACITY],
            addrs: [None; Self::CAPACITY],
        }
    }
}

fn drain_admission(
    listener: &UdpSocket,
    batching: crate::Batching,
    batch: &mut RecvBatch,
    buf: &mut [u8],
    mut on_datagram: impl FnMut(SocketAddr, &[u8]),
) {
    match batching {
        crate::Batching::On => loop {
            let fd = listener.as_raw_fd();
            let received = match srt_transport::recvmsg_batch(
                fd,
                &mut batch.bufs,
                &mut batch.sizes,
                &mut batch.addrs,
            ) {
                Ok(received) => received,
                Err(error) => {
                    eprintln!("[bench-mio] recvmmsg failed: {error}");
                    break;
                }
            };
            if received == 0 {
                break;
            }
            for i in 0..received {
                if let Some(peer) = batch.addrs[i] {
                    on_datagram(peer, &batch.bufs[i][..batch.sizes[i]]);
                }
            }
            if received < batch.bufs.len() {
                break;
            }
        },
        crate::Batching::Off => loop {
            match listener.recv_from(buf) {
                Ok((n, peer)) => on_datagram(peer, &buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        },
    }
}

/// One `PerPort` connection's live state -- module-scoped (not local to
/// `run`) so `spawn_driver` can name it.
struct Driver {
    conn: Conn,
    connected: bool,
    /// Ended mid-stream rather than by the ordered close. See
    /// `crate::is_ordered_close`.
    torn_down: bool,
    stream_deadline: Option<Instant>,
    data_events: u64,
    peer: Option<SocketAddr>,
    poisoned: bool,
    /// When this connection was started. Only meaningful while
    /// `!connected`: it bounds how long a handshake may stay "in flight"
    /// before the admission pipeline stops waiting on it. Without this, a
    /// single handshake that never completes pins `connect_concurrency`'s
    /// in-flight count forever and no further connection is ever started
    /// -- a deadlock, not just a slowdown.
    started_at: Instant,
}

/// Create connection `i`'s socket and protocol state and register it with
/// `poll` under `Token(i)`. Split out from `run`'s setup loop so it can be
/// called both to prime the initial batch and, for senders, to backfill
/// one at a time as `connect_concurrency` allows -- see
/// `BenchConfig::connect_concurrency`'s doc for why senders don't just
/// create everything upfront.
/// `i` identifies the *connection* (its port, its bond group); `token`
/// is its slot in this worker's `drivers` vec. They differ once
/// `--workers` shards connections across threads, and conflating them
/// would dispatch a readiness event to the wrong driver.
fn spawn_driver(
    cfg: &BenchConfig,
    poll: &mut Poll,
    start: Instant,
    i: usize,
    token: usize,
) -> Driver {
    let addr = cfg.addr_for(i);
    let mut socket = match cfg.mode {
        crate::Mode::Sender => {
            let s = UdpSocket::bind("0.0.0.0:0".parse().unwrap()).expect("bind");
            s.connect(addr).expect("connect");
            s
        }
        crate::Mode::Receiver => UdpSocket::bind(addr).expect("bind"),
    };
    let _ = srt_transport::set_sock_bufs(socket.as_raw_fd(), cfg.sock_buf_bytes);
    poll.registry()
        .register(&mut socket, Token(token), Interest::READABLE)
        .expect("register socket");

    let mut options = ConnectionOptions {
        socket_id: if cfg.mode == crate::Mode::Sender {
            cfg.caller_socket_id_for(i)
        } else {
            std::process::id()
        },
        tsbpd_delay: cfg.latency_ms,
        max_bandwidth_bytes_per_sec: match cfg.mode {
            crate::Mode::Sender => Some(cfg.bitrate_bps / 8),
            crate::Mode::Receiver => None,
        },
        ..Default::default()
    };
    cfg.encryption.apply_to(&mut options);
    let conn = match cfg.mode {
        crate::Mode::Sender => {
            let mut c = SrtConnection::new_caller(options);
            c.connect(crate::now_ts(start))
                .expect("connect() should queue INDUCTION");
            c
        }
        crate::Mode::Receiver => SrtConnection::new_listener(options),
    };
    let mut driver = Conn::new(conn, socket);
    let refused = driver.drain_outputs(crate::now_ts(start));
    Driver {
        torn_down: false,
        conn: driver,
        connected: false,
        stream_deadline: None,
        data_events: 0,
        peer: None,
        poisoned: refused,
        started_at: Instant::now(),
    }
}

fn finish_run(cfg: BenchConfig, start: Instant, stats: Vec<ConnStats>) {
    let mut aggregate = Aggregate::new(cfg);
    for stats in stats {
        aggregate.add(stats);
    }
    aggregate.print(start);
    if !aggregate.any_connected {
        std::process::exit(1);
    }
}

fn run_shared_sender_mode(cfg: &BenchConfig, start: Instant) -> bool {
    if cfg.mode != crate::Mode::Sender || cfg.egress != crate::Egress::SharedSocket {
        return false;
    }
    finish_run(cfg.clone(), start, run_shared_sender(cfg, start));
    true
}

fn run_receiver_ingress(cfg: BenchConfig) -> bool {
    // Single-port fan-in via SO_REUSEPORT + kernel sharding. This is the
    // production-like case (one SRT listener port, many callers) where a
    // single acceptor saturates at ~1200 concurrent handshakes.
    // ReuseportMulti(K) creates K acceptor sockets on the base port, each
    // in its own thread. See run_pool_receiver's doc for why only bonded
    // legs that need to relocate ever get a second socket.
    if cfg.mode != crate::Mode::Receiver || cfg.connections <= 1 {
        return false;
    }
    match cfg.ingress {
        crate::Ingress::ReuseportMulti(k) if k >= 1 => {
            run_pool_receiver(cfg, k);
        }
        crate::Ingress::SharedPool(1) => {
            run_bonded_shared_pool(cfg);
        }
        crate::Ingress::SharedPool(k) if k >= 1 => {
            run_shared_pool(cfg, k);
        }
        crate::Ingress::ReuseportSingle { workers } if workers >= 1 => {
            run_reuseport_single(cfg, workers);
        }
        _ => return false,
    }
    true
}

fn report_scale(cfg: &BenchConfig) {
    if cfg.connections <= 1 {
        return;
    }
    match cfg.ingress {
        crate::Ingress::ReuseportMulti(k) if cfg.mode == crate::Mode::Sender && k >= 1 => {
            eprintln!(
                "[bench-mio] scale: single port {} (reuseport-multi={k})",
                cfg.port
            );
        }
        crate::Ingress::ReuseportSingle { workers } if cfg.mode == crate::Mode::Sender => {
            eprintln!(
                "[bench-mio] scale: single port {} (reuseport-single, {workers} workers)",
                cfg.port
            );
        }
        crate::Ingress::SharedPool(k) if cfg.mode == crate::Mode::Sender && k >= 1 => {
            eprintln!(
                "[bench-mio] scale: shared-pool ports {}-{}",
                cfg.port,
                cfg.port + k as u16 - 1
            );
        }
        _ => {
            eprintln!(
                "[bench-mio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }
}

pub fn run(cfg: BenchConfig) {
    let start = Instant::now();
    if run_shared_sender_mode(&cfg, start) {
        return;
    }
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
    }
    if run_receiver_ingress(cfg.clone()) {
        return;
    }
    report_scale(&cfg);

    let stats = crate::run_workers(&cfg, move |cfg, mine| drive(cfg, mine, start));
    finish_run(cfg, start, stats);
}

fn run_shared_sender(cfg: &BenchConfig, start: Instant) -> Vec<ConnStats> {
    let std_socket =
        crate::bind_shared_sender_socket(cfg.sock_buf_bytes).expect("bind shared sender socket");
    let mut socket = UdpSocket::from_std(std_socket);
    let mut poll = Poll::new().expect("mio Poll::new");
    poll.registry()
        .register(
            &mut socket,
            Token(0),
            Interest::READABLE | Interest::WRITABLE,
        )
        .expect("register shared socket");
    let mut events = Events::with_capacity(32);
    let indices = (0..cfg.connections).collect::<Vec<_>>();
    let mut sender = crate::SharedSender::new(cfg, &indices, start);
    let mut generated = Vec::new();
    let mut pending = VecDeque::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        sender.tick(cfg, &mut generated);
        pending.extend(generated.drain(..));
        while let Some((peer, packet)) = pending.front() {
            match socket.send_to(packet, *peer) {
                Ok(_) => {
                    pending.pop_front();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("shared send_to: {error}"),
            }
        }
        if sender.done() && pending.is_empty() {
            break;
        }
        poll.poll(&mut events, Some(sender.next_wait()))
            .expect("mio poll");
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((size, peer)) => sender.feed(peer, &buffer[..size]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("shared recv_from: {error}"),
            }
        }
    }
    sender.finish()
}

fn prime_drivers(
    cfg: &BenchConfig,
    poll: &mut Poll,
    start: Instant,
    mine: &[usize],
) -> (Vec<Driver>, usize) {
    // Receivers create every dedicated socket up front. Senders prime only
    // their configured handshake window; `backfill_drivers` opens the rest
    // as earlier connections settle.
    let priming = match cfg.mode {
        crate::Mode::Receiver => mine.len(),
        crate::Mode::Sender => cfg.connect_concurrency.min(mine.len()),
    };
    let mut drivers = Vec::with_capacity(mine.len());
    for (token, &conn) in mine.iter().take(priming).enumerate() {
        drivers.push(spawn_driver(cfg, poll, start, conn, token));
    }
    (drivers, priming)
}

fn all_drivers_done(drivers: &[Driver], next_to_start: usize, total: usize) -> bool {
    crate::shutdown::requested()
        || next_to_start >= total
            && drivers.iter().all(|driver| {
                if driver.connected {
                    driver
                        .stream_deadline
                        .is_some_and(|deadline| Instant::now() >= deadline)
                } else {
                    driver.started_at.elapsed() >= crate::CONNECT_TIMEOUT
                }
            })
}

fn backfill_drivers(
    cfg: &BenchConfig,
    poll: &mut Poll,
    start: Instant,
    mine: &[usize],
    drivers: &mut Vec<Driver>,
    next_to_start: &mut usize,
) {
    // Only handshakes still within their connect window occupy a slot. An
    // expired handshake must not block every connection behind it.
    while *next_to_start < mine.len() {
        let in_flight = drivers
            .iter()
            .filter(|driver| {
                !driver.connected && driver.started_at.elapsed() < crate::CONNECT_TIMEOUT
            })
            .count();
        if in_flight >= cfg.connect_concurrency {
            break;
        }
        drivers.push(spawn_driver(
            cfg,
            poll,
            start,
            mine[*next_to_start],
            *next_to_start,
        ));
        *next_to_start += 1;
    }
}

fn next_poll_wait(cfg: &BenchConfig, drivers: &[Driver], start: Instant) -> Duration {
    if cfg.mode != crate::Mode::Sender {
        return TIMER_TICK;
    }
    // Senders know exactly when their next paced packet is due; receivers
    // just ride the tick (ACK timer is 10ms).
    let t = crate::now_ts(start);
    let min_wait = drivers
        .iter()
        .filter(|driver| driver.connected)
        .map(|driver| Duration::from_micros(driver.conn.conn.time_until_send(t)).min(MAX_POLL_WAIT))
        .min()
        .unwrap_or(MAX_POLL_WAIT);
    TIMER_TICK.min(min_wait)
}

fn receive_ready(
    cfg: &BenchConfig,
    drivers: &mut [Driver],
    events: &Events,
    buf: &mut [u8],
    start: Instant,
) -> [bool; 4096] {
    let mut touched = [false; 4096];
    for event in events.iter() {
        let idx = event.token().0;
        if idx >= touched.len() {
            continue;
        }
        let Some(driver) = drivers.get_mut(idx) else {
            continue;
        };
        touched[idx] = true;
        if driver.peer.is_none() && cfg.mode == crate::Mode::Receiver {
            receive_first_datagram(driver, buf, start);
        } else {
            receive_connected_datagrams(driver, idx, buf, start);
        }
    }
    touched
}

fn receive_first_datagram(driver: &mut Driver, buf: &mut [u8], start: Instant) {
    // The first datagram reveals the caller. Connect before feeding it into
    // the protocol because output draining uses connected `send()`.
    match driver.conn.socket.recv_from(buf) {
        Ok((n, addr)) => {
            if driver.conn.socket.connect(addr).is_ok() {
                driver.peer = Some(addr);
                let t = crate::now_ts(start);
                let _ = driver.conn.conn.feed_recv_buf(&buf[..n], t);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => eprintln!("[bench-mio] recv error: {error}"),
    }
}

fn receive_connected_datagrams(driver: &mut Driver, index: usize, buf: &mut [u8], start: Instant) {
    loop {
        match driver.conn.socket.recv(buf) {
            Ok(n) => {
                let t = crate::now_ts(start);
                let _ = driver.conn.conn.feed_recv_buf(&buf[..n], t);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                driver.poisoned = true;
                break;
            }
            Err(error) => {
                eprintln!("[bench-mio] recv error conn {index}: {error}");
                break;
            }
        }
    }
}

fn reconnect_poisoned(cfg: &BenchConfig, mine: &[usize], drivers: &mut [Driver]) {
    // A connected UDP socket stays poisoned for both send and recv until
    // reconnect. Scan all drivers so handshake retransmits cannot stall.
    for (index, driver) in drivers.iter_mut().enumerate() {
        if !driver.poisoned {
            continue;
        }
        let destination = driver
            .peer
            .or_else(|| (cfg.mode == crate::Mode::Sender).then(|| cfg.addr_for(mine[index])));
        let Some(destination) = destination else {
            continue;
        };
        let _ = driver.conn.socket.connect(destination);
        driver.poisoned = false;
    }
}

fn service_drivers(
    cfg: &BenchConfig,
    drivers: &mut [Driver],
    touched: &[bool; 4096],
    woke_from_timeout: bool,
    payload: &[u8],
    start: Instant,
) {
    // Timer scans are O(armed timers) per driver, so only sweep drivers that
    // saw traffic -- plus a full sweep whenever poll went idle.
    let t = crate::now_ts(start);
    for (index, driver) in drivers.iter_mut().enumerate() {
        if woke_from_timeout || touched.get(index).copied().unwrap_or(false) {
            driver.conn.fire_expired(t);
        }
        if driver.conn.drain_outputs(t) {
            driver.poisoned = true;
        }
        process_events(cfg, driver);
        send_due_payload(cfg, driver, payload, start);
    }
}

fn process_events(cfg: &BenchConfig, driver: &mut Driver) {
    while let Some(event) = driver.conn.conn.poll_event() {
        match event {
            ConnectionEvent::Connected => {
                driver.connected = true;
                // Set once: a duplicate Connected must not extend the run.
                if driver.stream_deadline.is_none() {
                    driver.stream_deadline =
                        Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                }
                if cfg.verbose() {
                    println!("CONNECTED");
                }
            }
            ConnectionEvent::DataReceived { .. } => driver.data_events += 1,
            ConnectionEvent::Disconnected { reason } => {
                let ordered = crate::is_ordered_close(&reason);
                if !ordered {
                    eprintln!("[bench-mio] disconnected: {reason}");
                }
                driver.torn_down |= !ordered;
                driver.stream_deadline = Some(Instant::now());
            }
            ConnectionEvent::Error(message) => eprintln!("[bench-mio] error: {message}"),
            _ => {}
        }
    }
}

fn send_due_payload(cfg: &BenchConfig, driver: &mut Driver, payload: &[u8], start: Instant) {
    // Gate on this connection's deadline. Sample the clock once so pacing
    // cannot turn the send loop into an unbounded busy loop.
    let past_deadline = driver
        .stream_deadline
        .is_some_and(|deadline| Instant::now() >= deadline);
    if !driver.connected || cfg.mode != crate::Mode::Sender || past_deadline {
        return;
    }
    let t = crate::now_ts(start);
    loop {
        if !driver.conn.conn.can_send_with_pacing(t) {
            break;
        }
        if driver.conn.conn.send(payload, t).is_err() {
            break;
        }
        driver.data_events += 1;
        if driver.conn.drain_outputs(t) {
            driver.poisoned = true;
        }
    }
}

fn close_drivers(cfg: &BenchConfig, drivers: &mut [Driver], start: Instant) {
    if cfg.mode != crate::Mode::Sender {
        return;
    }
    // Ordered close tells the listener to flush its receive buffer instead of
    // inferring the end of the stream from silence.
    let t = crate::now_ts(start);
    for driver in drivers {
        driver.conn.conn.disconnect(t);
        let _ = driver.conn.drain_outputs(t);
    }
}

fn driver_stats(cfg: &BenchConfig, driver: Driver) -> ConnStats {
    let mut stats = ConnStats {
        connected: driver.connected,
        torn_down: driver.torn_down,
        data_events: driver.data_events,
        ..Default::default()
    };
    match cfg.mode {
        crate::Mode::Sender => {
            if let Some(protocol) = driver.conn.conn.sender_stats() {
                stats.has_stats = true;
                stats.core_total = protocol.total_sent;
                stats.secondary_a = protocol.total_retransmits;
                stats.secondary_b = protocol.packets_in_loss_list as u64;
            }
        }
        crate::Mode::Receiver => {
            if let Some(protocol) = driver.conn.conn.receiver_stats() {
                stats.has_stats = true;
                stats.core_total = protocol.total_received;
                stats.secondary_a = protocol.total_lost;
                stats.secondary_b = protocol.total_duplicates;
                stats.rtt_us = protocol.rtt as u64;
            }
        }
    }
    stats
}

/// Drive one worker's share of the connections on its own `Poll`.
fn drive(cfg: BenchConfig, mine: Vec<usize>, start: Instant) -> Vec<ConnStats> {
    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(4096);

    let (mut drivers, mut next_to_start) = prime_drivers(&cfg, &mut poll, start, &mine);
    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let mut buf = [0u8; 2048];

    loop {
        if !drivers.iter().any(|d| d.connected) && Instant::now() >= connect_deadline {
            eprintln!("[bench-mio] connect timed out");
            break;
        }
        // A connection is settled once it has either finished streaming or
        // given up on connecting. Treating a never-connecting handshake as
        // settled keeps one dead peer from hanging the whole run.
        if all_drivers_done(&drivers, next_to_start, mine.len()) {
            break;
        }

        // Backfill starts the next connection once earlier handshakes settle.
        backfill_drivers(
            &cfg,
            &mut poll,
            start,
            &mine,
            &mut drivers,
            &mut next_to_start,
        );

        poll.poll(&mut events, Some(next_poll_wait(&cfg, &drivers, start)))
            .ok();
        let woke_from_timeout = events.is_empty();

        let touched = receive_ready(&cfg, &mut drivers, &events, &mut buf, start);
        reconnect_poisoned(&cfg, &mine, &mut drivers);

        service_drivers(
            &cfg,
            &mut drivers,
            &touched,
            woke_from_timeout,
            &payload,
            start,
        );
    }

    close_drivers(&cfg, &mut drivers, start);
    drivers
        .into_iter()
        .map(|driver| driver_stats(&cfg, driver))
        .collect()
}

/// #2 -- shared pool, no promotion: K real, distinct, plainly-bound
/// listener ports (no SO_REUSEPORT). Every one stays unconnected for its
/// whole life; connections `i` and `i+K`, `i+2K`, ... share socket `i % K`
/// and are distinguished purely by peer address (`recv_from` + a
/// `SocketAddr -> connection` lookup, `send_to` for output). One thread
/// by default (`--workers`), no promotion step -- this isolates "fewer wakeups from fewer
/// sockets" from `ReuseportMulti`'s "kernel-level demux after a one-time
/// promotion cost." Receiver-only: a sender just dials the port
/// `addr_for` already computes for it and otherwise behaves exactly like
/// `PerPort` (own local socket per connection, connected to one peer).
fn run_shared_pool(cfg: BenchConfig, k: usize) {
    let start = Instant::now();
    let agg_cfg = cfg.clone();
    // K pool sockets across `--workers` OS threads, each with its own
    // `Poll`. `workers = 1` (the default) keeps every socket on one
    // thread, preserving this strategy's role as the single-threaded
    // control. Above 1 it scales, which a strong sender needs: measured
    // at 400 conns x 8 Mbps, one listener thread delivers 13% with 1.6M
    // kernel rcvbuf drops while two deliver 99.9% with none.
    let threads = cfg.workers.clamp(1, k);
    let stats = crate::run_shards(threads, k, move |mine| {
        let cfg = cfg.clone();
        run_shared_pool_shard(&cfg, &mine, k, start)
    });

    let mut agg = Aggregate::new(agg_cfg);
    for s in stats {
        agg.add(s);
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-mio] shared pool admitted no connections");
        std::process::exit(1);
    }
}

/// The ordinary mio shared-pool loop predates group-aware admission and owns
/// one `SrtConnection` per address. Bonded input needs the shared
/// [`srt_transport::PeerTable`] so both legs become one logical stream.
/// This one-socket path is the only viable bonded shared-pool topology, and
/// keeps mio aligned with every completion/runtime adapter without changing
/// its unbonded benchmark path.
fn run_bonded_shared_pool(cfg: BenchConfig) {
    let start = Instant::now();
    println!("LISTENING");
    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(1024);
    let addr = SocketAddr::new(std::net::IpAddr::from([0, 0, 0, 0]), cfg.port);
    let mut socket = UdpSocket::bind(addr).expect("bind bonded shared-pool socket");
    let _ = srt_transport::set_sock_bufs(socket.as_raw_fd(), cfg.sock_buf_bytes);
    poll.registry()
        .register(&mut socket, Token(0), Interest::READABLE)
        .expect("register bonded shared-pool socket");

    let mut peers = srt_transport::PeerTable::new();
    let admission = cfg.admission_options(std::process::id(), false);
    let telemetry = srt_transport::IngressTelemetry::new();
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut buf = [0u8; 2048];
    let mut admit_batch = RecvBatch::new();
    let mut outbound = Vec::new();
    let mut connected = Vec::new();

    loop {
        let now = Instant::now();
        if now >= run_deadline
            || (now >= connect_deadline && peers.all_terminal(now, connect_deadline, IDLE_GRACE))
        {
            break;
        }
        poll.poll(&mut events, Some(TIMER_TICK)).ok();
        for event in events.iter() {
            if event.token() != Token(0) {
                continue;
            }
            let timestamp = crate::now_ts(start);
            drain_admission(
                &socket,
                cfg.batching,
                &mut admit_batch,
                &mut buf,
                |peer, data| {
                    let _ = peers.admit(peer, data, timestamp, &admission, 0, 1, &telemetry);
                },
            );
        }

        let timestamp = crate::now_ts(start);
        peers.poll_outbound(timestamp, &mut outbound);
        for (peer, packet) in outbound.drain(..) {
            let _ = socket.send_to(&packet, peer);
        }
        peers.drain_events(stream_len, &mut connected);
    }

    let mut aggregate = Aggregate::new(cfg);
    for stats in crate::collect_listener_stats(peers) {
        aggregate.add(stats);
    }
    aggregate.print(start);
    if !aggregate.any_connected {
        eprintln!("[bench-mio] bonded shared pool admitted no connections");
        std::process::exit(1);
    }
}

/// One worker's share of the pool sockets, on its own `Poll`.
///
/// `mine` names the *pool* sockets this worker owns; inside, sockets are
/// addressed by their position in `sockets`, which is what the poll token
/// carries. The two only coincide when there is a single worker.
struct SharedPoolConn {
    conn: SrtConnection,
    timers: srt_transport::ManualTimerStore,
    connected: bool,
    torn_down: bool,
    data_events: u64,
    peer: SocketAddr,
    socket_idx: usize,
    /// `None` until the first `Connected` event; doubles as "has this
    /// ever connected" so a still-handshaking entry (which is not
    /// terminal) is distinguishable from a disconnected one (which
    /// is), without a separate pending/established split.
    stream_deadline: Option<Instant>,
    last_data_at: Instant,
}

fn new_shared_pool_conn(cfg: &BenchConfig, peer: SocketAddr, socket_idx: usize) -> SharedPoolConn {
    SharedPoolConn {
        torn_down: false,
        conn: SrtConnection::new_listener({
            let mut options = ConnectionOptions {
                socket_id: std::process::id(),
                tsbpd_delay: cfg.latency_ms,
                ..Default::default()
            };
            cfg.encryption.apply_to(&mut options);
            options
        }),
        timers: srt_transport::ManualTimerStore::new(),
        connected: false,
        data_events: 0,
        peer,
        socket_idx,
        stream_deadline: None,
        last_data_at: Instant::now(),
    }
}

fn shared_pool_conn_is_terminal(
    conn: &SharedPoolConn,
    now: Instant,
    connect_deadline: Instant,
) -> bool {
    srt_lifecycle::is_terminal(
        conn.connected,
        conn.stream_deadline,
        conn.last_data_at,
        now,
        connect_deadline,
        IDLE_GRACE,
    )
}

fn admit_shared_pool_events(
    events: &Events,
    sockets: &[UdpSocket],
    cfg: &BenchConfig,
    batch: &mut RecvBatch,
    buf: &mut [u8],
    conns: &mut HashMap<SocketAddr, SharedPoolConn>,
    start: Instant,
) {
    for event in events.iter() {
        let socket_idx = event.token().0;
        let Some(socket) = sockets.get(socket_idx) else {
            continue;
        };
        let timestamp = crate::now_ts(start);
        drain_admission(socket, cfg.batching, batch, buf, |peer, data| {
            let entry = conns
                .entry(peer)
                .or_insert_with(|| new_shared_pool_conn(cfg, peer, socket_idx));
            let _ = entry.conn.feed_recv_buf(data, timestamp);
            entry.data_events += 1;
            entry.last_data_at = Instant::now();
        });
    }
}

fn drive_shared_pool_connections(
    conns: &mut HashMap<SocketAddr, SharedPoolConn>,
    sockets: &[UdpSocket],
    start: Instant,
    stream_len: Duration,
) {
    let timestamp = crate::now_ts(start);
    for conn in conns.values_mut() {
        conn.timers.fire_expired(timestamp, &mut conn.conn);
        let socket = &sockets[conn.socket_idx];
        while let Some(output) = conn.conn.poll_output() {
            match output {
                shiguredo_srt::ConnectionOutput::SendPacket(bytes) => {
                    let _ = socket.send_to(&bytes, conn.peer);
                }
                other => conn.timers.apply_output(&other, timestamp),
            }
        }
        while let Some(event) = conn.conn.poll_event() {
            match event {
                ConnectionEvent::Connected => {
                    conn.connected = true;
                    conn.stream_deadline = Some(Instant::now() + stream_len);
                }
                ConnectionEvent::Disconnected { reason } => {
                    conn.torn_down |= !crate::is_ordered_close(&reason);
                    conn.connected = false;
                }
                _ => {}
            }
        }
    }
}

fn shared_pool_stats(conns: HashMap<SocketAddr, SharedPoolConn>) -> Vec<ConnStats> {
    conns
        .into_values()
        .map(|conn| {
            let mut stats = ConnStats {
                // stream_deadline is Some as soon as Connected has fired
                // (see the struct doc) -- a session that streamed everything
                // and then tripped SRT's own peer-idle timeout is still a
                // success, not "never connected".
                connected: conn.stream_deadline.is_some(),
                torn_down: conn.torn_down,
                data_events: conn.data_events,
                ..Default::default()
            };
            if let Some(receiver_stats) = conn.conn.receiver_stats() {
                stats.has_stats = true;
                stats.core_total = receiver_stats.total_received;
                stats.secondary_a = receiver_stats.total_lost;
                stats.secondary_b = receiver_stats.total_duplicates;
                stats.rtt_us = receiver_stats.rtt as u64;
            }
            stats
        })
        .collect()
}

fn run_shared_pool_shard(
    cfg: &BenchConfig,
    mine: &[usize],
    pool_sockets: usize,
    start: Instant,
) -> Vec<ConnStats> {
    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(1024);

    let mut sockets: Vec<UdpSocket> = Vec::with_capacity(mine.len());
    for (token, &pool_index) in mine.iter().enumerate() {
        let addr = SocketAddr::new(
            std::net::IpAddr::from([0, 0, 0, 0]),
            cfg.port + pool_index as u16,
        );
        let mut socket = UdpSocket::bind(addr).expect("bind shared-pool socket");
        let _ = srt_transport::set_sock_bufs(socket.as_raw_fd(), cfg.sock_buf_bytes);
        poll.registry()
            .register(&mut socket, Token(token), Interest::READABLE)
            .expect("register shared-pool socket");
        sockets.push(socket);
    }

    let mut conns: HashMap<SocketAddr, SharedPoolConn> = HashMap::new();
    let expected_connections = (0..cfg.connections)
        .filter(|connection| mine.contains(&(connection % pool_sockets)))
        .count();
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut buf = [0u8; 2048];
    let mut admit_batch = RecvBatch::new();

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        let all_terminal = conns
            .values()
            .all(|conn| shared_pool_conn_is_terminal(conn, now, connect_deadline));
        if shared_pool_can_stop(
            conns.len(),
            expected_connections,
            all_terminal,
            now >= connect_deadline,
        ) {
            break;
        }
        poll.poll(&mut events, Some(TIMER_TICK)).ok();

        admit_shared_pool_events(
            &events,
            &sockets,
            cfg,
            &mut admit_batch,
            &mut buf,
            &mut conns,
            start,
        );
        drive_shared_pool_connections(&mut conns, &sockets, start, stream_len);
    }

    shared_pool_stats(conns)
}

fn shared_pool_can_stop(
    observed_connections: usize,
    expected_connections: usize,
    all_terminal: bool,
    past_connect_deadline: bool,
) -> bool {
    all_terminal && (observed_connections == expected_connections || past_connect_deadline)
}

/// One accepted connection on an acceptor thread: dedicated socket
/// connected to the peer's exact tuple + protocol state.
struct PoolSlot {
    /// Ended mid-stream rather than by the ordered close.
    torn_down: bool,
    conn: Conn,
    /// Live connected state: flips false on `Disconnected`, feeding
    /// `slot_is_terminal` so a dropped connection is promptly recognized
    /// as done. Always starts true (a slot only exists post-promotion,
    /// i.e. after `Connected` already fired).
    connected: bool,
    /// Never reset once true: a session that finished streaming and then
    /// legitimately tripped SRT's own peer-idle timeout (normal once the
    /// sender stops -- it can happen well before this loop notices and
    /// exits) is still a *successful* connection for reporting purposes.
    /// `connected` alone would misreport perfect delivery as "admitted
    /// no connections" the moment the live flag flips.
    ever_connected: bool,
    data_events: u64,
    poisoned: bool,
    /// Wall-clock deadline for this connection's stream, set once at slot
    /// creation (promotion only happens after the handshake completes, so
    /// every slot starts connected).
    stream_deadline: Instant,
    /// Wall-clock time of the last datagram received from the peer, used
    /// to detect a genuinely stalled connection (see `slot_is_terminal`)
    /// instead of stopping on a fixed wall-clock window that can drift out
    /// of sync with the peer's own window under load.
    last_data_at: Instant,
}

/// A slot is done -- either it disconnected, ran its full duration, or went
/// idle past `IDLE_GRACE` -- and the acceptor no longer needs to service it
/// to make progress. A slot is only ever created post-`Connected` (there's
/// no "never connected" state to represent), so `connect_deadline` is
/// unused -- `srt_lifecycle::is_terminal` only consults it when
/// `stream_deadline` is `None`, which never happens here.
fn slot_is_terminal(slot: &PoolSlot, now: Instant) -> bool {
    srt_lifecycle::is_terminal(
        slot.connected,
        Some(slot.stream_deadline),
        slot.last_data_at,
        now,
        now,
        IDLE_GRACE,
    )
}

/// How long a connected slot may go without a datagram from its peer
/// before it's retired as stalled, even if the protocol layer hasn't
/// itself noticed a disconnect.
const IDLE_GRACE: Duration = Duration::from_secs(10);

fn bind_reuseport(port: u16, sock_buf_bytes: usize) -> std::io::Result<UdpSocket> {
    Ok(UdpSocket::from_std(srt_transport::bind_reuseport(
        port,
        sock_buf_bytes,
    )?))
}

/// Drain outputs for an unconnected (handshake-phase) connection: sends go
/// via send_to to the peer; timers apply to the manual store. Returns true
/// when a send failed (treat the pending handshake as dead).
fn drain_conn_outputs(
    conn: &mut SrtConnection,
    timers: &mut srt_transport::ManualTimerStore,
    socket: &UdpSocket,
    destination: SocketAddr,
    now: shiguredo_srt::Timestamp,
) -> bool {
    use shiguredo_srt::ConnectionOutput;
    let mut refused = false;
    while let Some(out) = conn.poll_output() {
        match out {
            ConnectionOutput::SendPacket(bytes) => {
                if socket.send_to(&bytes, destination).is_err() {
                    refused = true;
                }
            }
            other => timers.apply_output(&other, now),
        }
    }
    refused
}

/// Multi-acceptor single-port receiver (`--ingress reuseport-multi=K`,
/// K>1): K SO_REUSEPORT acceptor threads share the base port; the kernel
/// hashes each flow's source tuple to one of them. Each acceptor
/// completes the handshake for every flow routed to it, then -- once, and
/// only once, that flow reaches `Connected` -- promotes it to a dedicated
/// connected socket and its own slot. Before `Connected`, every flow is
/// serviced off this thread's shared listener socket, dispatched by peer
/// address, exactly like `SharedPool`; a still-handshaking flow never gets
/// its own socket.
///
/// The kernel always prefers an exact-4-tuple connected-socket match over
/// the reuseport hash, so once a flow is `Connected`, giving it a private
/// socket is safe *for that flow* regardless of group size -- the whole
/// reuseport-hash hazard below is specifically about *other, still-
/// unconnected* flows losing their footing when a new member joins the
/// group. That's why promotion is gated on `Connected` and nothing else:
/// an unbonded connection promotes to a *local* slot on the same thread
/// that admitted it (no `WorkerRouter` consultation needed -- there's no
/// group affinity constraint to honor); a bonded leg consults
/// `srt_lifecycle::WorkerRouter` once, at that same moment, to learn its
/// group's owner, and only differs in *where* the private socket ends up:
/// a local slot if this thread already owns the group, or a one-shot
/// handoff to the owner's thread if not.
///
/// Promoting *every* connection (not just relocating bond legs) is the
/// point, not a compromise: task-per-connection steady-state service,
/// same idiom `PerPort` already uses successfully, replaces the earlier
/// design's shared per-worker maintenance loop iterating every live peer
/// sequentially every tick -- which measurably bottlenecks several other
/// runtimes' backends at real throughput (see their module docs' "KNOWN
/// LIMITATION" notes). mio's own per-operation cost is cheap enough that
/// this bottleneck was never visible here, but the fix is the same shape
/// for every runtime, and mio is the reference implementation for it.
///
/// The residual hazard -- every *new* socket bound into this port's
/// reuseport group perturbs Linux's default (non-eBPF) hash, which can
/// reroute some other still-pending flow's next datagram to a different
/// acceptor mid-handshake -- is real but transient: `connect()` removes
/// the socket from the group again, so the group returns to K and the
/// displaced flows return with it (measured net zero; see
/// crates/srt-transport/tests/reuseport_rehash.rs). The exposure is the
/// few microseconds between the two syscalls, and a CONCLUSION landing
/// inside that window is recovered by cookie routing rather than lost.
///
/// A fixed per-tick promotion budget used to live here to spread that
/// churn out. It was removed once storm loss was traced to arrival
/// concurrency instead: sweeping `--connect-concurrency` at N=150 moved
/// listener loss 11 -> 35 -> 105 -> 113 for 1/10/50/150, while the
/// promotion A/B at that point was indistinguishable (off 91/98/91, on
/// 58/159/106). It was pacing something that was not the cause, and it
/// left this backend as the only one whose promotion timing differed
/// from the other five.
fn run_pool_receiver(cfg: BenchConfig, k: usize) {
    use std::sync::mpsc;

    let worker_count = k.min(cfg.connections);
    let start = Instant::now();
    let router: crate::SharedWorkerRouter =
        Arc::new(Mutex::new(srt_lifecycle::WorkerRouter::new(worker_count)));
    // One set of counters for every acceptor thread; see
    // `srt_transport::IngressTelemetry`.
    let telemetry = Arc::new(srt_transport::IngressTelemetry::new());

    // All channels must exist before any thread is spawned: promote_slot
    // indexes `senders` by owner worker index, so every thread needs the
    // full, final-length vector -- not a partial one containing only the
    // channels created so far. Cloning `senders` mid-loop (as it grows one
    // element per iteration) would hand worker 0 a 1-element slice and
    // panic the first time a handoff resolves to any later worker.
    let (senders, receivers): (Vec<_>, Vec<_>) = (0..worker_count)
        .map(|_| mpsc::channel::<WorkerMessage>())
        .unzip();

    let mut handles = Vec::with_capacity(worker_count);
    for (worker_index, rx) in receivers.into_iter().enumerate() {
        let router = router.clone();
        let telemetry = telemetry.clone();
        let all_senders = senders.clone();
        let cfg = cfg.clone();
        handles.push(
            std::thread::Builder::new()
                .name(format!("srt-acceptor-{worker_index}"))
                .spawn(move || {
                    run_pool_acceptor(cfg, worker_index, start, router, all_senders, rx, telemetry)
                })
                .expect("spawn acceptor"),
        );
    }

    let mut agg = Aggregate::new(cfg.clone());
    for handle in handles {
        for stats in handle.join().expect("acceptor panicked") {
            agg.add(stats);
        }
    }
    // Always report, not gated on the receiver's own --bond (bonding is a
    // sender-side choice; the receiver learns it from the handshake); a
    // nonzero handoff count is the proof the bond-affinity path fired.
    eprintln!("{}", telemetry.report("mio"));
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-mio] pool receiver admitted no connections");
        std::process::exit(1);
    }
}

struct PoolAcceptorContext<'a> {
    cfg: &'a BenchConfig,
    worker_index: usize,
    start: Instant,
    admission: &'a srt_transport::AdmissionOptions,
    router: &'a crate::SharedWorkerRouter,
    senders: &'a [mpsc::Sender<WorkerMessage>],
    telemetry: &'a srt_transport::IngressTelemetry,
    poll: &'a mut Poll,
    next_token: &'a mut usize,
    slots: &'a mut Vec<PoolSlot>,
    token_index: &'a mut HashMap<usize, usize>,
}

fn drain_pool_handoffs(
    context: &mut PoolAcceptorContext<'_>,
    peers: &mut srt_transport::PeerTable,
    handoffs: &mpsc::Receiver<WorkerMessage>,
    stream_len: Duration,
) {
    while let Ok(message) = handoffs.try_recv() {
        let handoff = match message {
            WorkerMessage::Handoff(handoff) => handoff,
            WorkerMessage::Handshake { peer, data } => {
                peers.admit_and_forward(
                    peer,
                    &data,
                    crate::now_ts(context.start),
                    context.admission,
                    context.worker_index,
                    context.senders,
                    context.telemetry,
                );
                continue;
            }
            WorkerMessage::Finished { .. } => continue,
        };
        let mut socket = UdpSocket::from_std(handoff.socket);
        let token = Token(*context.next_token);
        *context.next_token += 1;
        if context
            .poll
            .registry()
            .register(&mut socket, token, Interest::READABLE)
            .is_err()
        {
            continue;
        }
        let mut conn = Conn::new(handoff.conn, socket);
        conn.fire_expired(crate::now_ts(context.start));
        conn.drain_outputs(crate::now_ts(context.start));
        let now = Instant::now();
        context.token_index.insert(token.0, context.slots.len());
        context.slots.push(PoolSlot {
            torn_down: false,
            conn,
            connected: true,
            ever_connected: true,
            data_events: 0,
            poisoned: false,
            stream_deadline: now + stream_len,
            last_data_at: now,
        });
    }
}

fn service_pool_events(
    context: &mut PoolAcceptorContext<'_>,
    peers: &mut srt_transport::PeerTable,
    events: &Events,
    listener: &UdpSocket,
    admit_batch: &mut RecvBatch,
    buf: &mut [u8; 2048],
) {
    let batching = context.cfg.batching;
    let admission = context.admission;
    let worker_index = context.worker_index;
    let senders = context.senders;
    let telemetry = context.telemetry;
    for event in events.iter() {
        match event.token().0 {
            0 => drain_admission(listener, batching, admit_batch, buf, |peer, data| {
                peers.admit_and_forward(
                    peer,
                    data,
                    crate::now_ts(context.start),
                    admission,
                    worker_index,
                    senders,
                    telemetry,
                );
            }),
            index => service_slot_event(
                context.slots,
                context.token_index,
                Token(index),
                buf,
                context.start,
            ),
        }
    }
}

fn maintain_pool_peers(
    peers: &mut srt_transport::PeerTable,
    listener: &UdpSocket,
    start: Instant,
    stream_len: Duration,
) -> Vec<SocketAddr> {
    let now = crate::now_ts(start);
    let mut newly_connected = Vec::new();
    for (peer, p) in peers.iter_direct_for_bench() {
        p.timers.fire_expired(now, &mut p.conn);
        let _ = drain_conn_outputs(&mut p.conn, &mut p.timers, listener, *peer, now);
        let mut just_connected = false;
        while let Some(event) = p.conn.poll_event() {
            just_connected |= p.apply_event(event);
        }
        if just_connected {
            p.stream_deadline = Some(Instant::now() + stream_len);
            newly_connected.push(*peer);
        }
    }
    newly_connected
}

fn promote_pool_peers(
    context: &mut PoolAcceptorContext<'_>,
    peers: &mut srt_transport::PeerTable,
    newly_connected: Vec<SocketAddr>,
) {
    for peer in newly_connected {
        let extension = peers
            .direct_for_bench(peer)
            .and_then(|p| p.conn.peer_group_extension());
        let decision = pool_promotion_decision_with_extension(context, peer, extension);
        match decision {
            srt_lifecycle::PromotionDecision::StayOnListener => {}
            srt_lifecycle::PromotionDecision::RelocateTo(owner) => {
                let Some(p) = peers.remove_direct_for_bench(peer) else {
                    continue;
                };
                relocate_to_owner(
                    context.cfg.port,
                    context.cfg.sock_buf_bytes,
                    peer,
                    p.conn,
                    owner,
                    context.senders,
                    context.telemetry,
                );
            }
            srt_lifecycle::PromotionDecision::PromoteHere => {
                let Some(p) = peers.remove_direct_for_bench(peer) else {
                    continue;
                };
                promote_locally(
                    context.poll,
                    context.next_token,
                    context.cfg.port,
                    context.cfg.sock_buf_bytes,
                    peer,
                    p.conn,
                    context.start,
                    Duration::from_secs_f64(context.cfg.duration_secs),
                    context.slots,
                    context.token_index,
                    context.telemetry,
                );
            }
        }
    }
}

fn pool_promotion_decision_with_extension(
    context: &PoolAcceptorContext<'_>,
    peer: SocketAddr,
    extension: Option<GroupExtensionData>,
) -> srt_lifecycle::PromotionDecision {
    let group = extension.map(|extension| srt_lifecycle::GroupAffinity {
        group_id: extension.group_id,
        stream_id: None,
        extension,
    });
    match context.router.lock() {
        Ok(mut router) => srt_lifecycle::decide_promotion(
            context.cfg.promotion,
            peer,
            group,
            context.worker_index,
            &mut router,
            srt_lifecycle::RoutingMode::LeastTuples,
        ),
        Err(_) => srt_lifecycle::PromotionDecision::StayOnListener,
    }
}

fn run_pool_acceptor(
    cfg: BenchConfig,
    worker_index: usize,
    start: Instant,
    router: crate::SharedWorkerRouter,
    senders: Vec<mpsc::Sender<WorkerMessage>>,
    handoffs: mpsc::Receiver<WorkerMessage>,
    telemetry: Arc<srt_transport::IngressTelemetry>,
) -> Vec<ConnStats> {
    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(1024);
    let mut listener = match bind_reuseport(cfg.port, cfg.sock_buf_bytes) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[bench-mio] acceptor {worker_index}: bind {e}");
            return Vec::new();
        }
    };
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .expect("register listener");

    // Every flow lives here from admission through `Connected` -- dispatched
    // by peer address off the *same* listener socket used for admission,
    // exactly like `SharedPool`. A flow leaves `peers` only when it is
    // promoted or relocated -- so it is always either mid-handshake here,
    // or fully promoted into `slots`, never in between.
    let mut peers = srt_transport::PeerTable::new();
    let admission = cfg.admission_options(std::process::id(), cfg.cookie_routing);
    // Promoted connections -- local or handed off in from another
    // acceptor -- each with a dedicated connected socket and mio token,
    // driven by `service_slot_event`/`maintain_slots` like any other
    // established connection.
    let mut slots: Vec<PoolSlot> = Vec::new();
    // token.0 -> index in `slots`, maintained alongside every push below --
    // see `service_slot_event`'s doc for why this matters at #4's scale.
    let mut token_index: HashMap<usize, usize> = HashMap::new();
    let mut next_token: usize = 1;
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    // Absolute safety net so a hung peer or a stuck protocol state can
    // never wedge this thread forever, no matter what `is_terminal`
    // and `connect_deadline` decide. Sized off the run's own duration
    // (plus idle grace and margin) rather than a fixed constant so it
    // never truncates a legitimate long soak run.
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);

    // Hoisted admission batch buffers: one allocation for the acceptor's
    // whole life, reused every readability event instead of once per event
    // (hot-path rule).
    let mut admit_batch = RecvBatch::new();
    let mut buf = [0u8; 2048];

    {
        let mut context = PoolAcceptorContext {
            cfg: &cfg,
            worker_index,
            start,
            admission: &admission,
            router: &router,
            senders: &senders,
            telemetry: &telemetry,
            poll: &mut poll,
            next_token: &mut next_token,
            slots: &mut slots,
            token_index: &mut token_index,
        };
        loop {
            let now = Instant::now();
            if now >= run_deadline {
                break;
            }
            // Vacuously true while nothing exists yet, so an acceptor that
            // never admits anything still exits once the connect window
            // closes instead of hanging on an empty guard.
            let all_terminal = peers.all_terminal(now, connect_deadline, IDLE_GRACE)
                && context.slots.iter().all(|s| slot_is_terminal(s, now));
            if crate::shutdown::requested() || (now >= connect_deadline && all_terminal) {
                break;
            }
            context.poll.poll(&mut events, Some(TIMER_TICK)).ok();

            drain_pool_handoffs(&mut context, &mut peers, &handoffs, stream_len);

            service_pool_events(
                &mut context,
                &mut peers,
                &events,
                &listener,
                &mut admit_batch,
                &mut buf,
            );

            let newly_connected = maintain_pool_peers(&mut peers, &listener, start, stream_len);
            promote_pool_peers(&mut context, &mut peers, newly_connected);
            maintain_slots(context.slots, start);
        }
    }

    let mut stats: Vec<ConnStats> = peers
        .into_iter()
        .map(|(peer, p)| {
            // Free this tuple's (and, if it was the last member, its
            // group's) router bookkeeping now that the connection is
            // fully done -- a no-op if this peer never touched the
            // router (unbonded). Without this a long-running listener
            // would leak router state forever; a short bench run doesn't
            // strictly need it, but this is meant to read like ordinary
            // application code, not a one-shot script.
            if let Ok(mut router) = router.lock() {
                router.release(&peer);
            }
            let mut s = ConnStats {
                // stream_deadline is Some as soon as Connected has ever
                // fired -- see the struct doc. A session that streamed
                // everything and then legitimately tripped SRT's own
                // peer-idle timeout is still a success, not "never
                // connected".
                connected: p.stream_deadline.is_some(),
                data_events: p.data_events,
                ..Default::default()
            };
            if let Some(st) = p.conn.receiver_stats() {
                s.has_stats = true;
                s.core_total = st.total_received;
                s.secondary_a = st.total_lost;
                s.secondary_b = st.total_duplicates;
                s.rtt_us = st.rtt as u64;
            }
            s
        })
        .collect();
    stats.extend(slots_to_stats(slots));
    stats
}

/// Relocate a connection that must move to a different worker: bind a
/// fresh dedicated socket (unavoidable here -- this is the one case that
/// genuinely needs to move to a different thread's event loop), connect
/// it to the peer, and ship it once over the owner's channel.
fn relocate_to_owner(
    port: u16,
    sock_buf_bytes: usize,
    peer: SocketAddr,
    pending_conn: SrtConnection,
    owner: usize,
    senders: &[mpsc::Sender<WorkerMessage>],
    telemetry: &srt_transport::IngressTelemetry,
) {
    let socket = match srt_transport::bind_reuseport(port, sock_buf_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-mio] relocate {peer}: bind {e}");
            return;
        }
    };
    if socket.connect(peer).is_err() {
        eprintln!("[bench-mio] relocate {peer}: connect failed");
        return;
    }
    let message = WorkerMessage::Handoff(Box::new(Handoff {
        socket,
        conn: pending_conn,
    }));
    if senders[owner].send(message).is_err() {
        eprintln!("[bench-mio] relocate {peer}: owner {owner} channel closed");
    } else {
        telemetry.record_handoff();
    }
}

/// Promote a connection to a dedicated connected socket on *this* thread:
/// bind a fresh reuseport socket, connect it to the peer, register it
/// with `poll` under a new token, and push it into `slots` -- the same
/// shape as a handoff arrival, just executed synchronously instead of
/// over a channel, since the destination thread is this one.
#[allow(clippy::too_many_arguments)]
fn promote_locally(
    poll: &mut Poll,
    next_token: &mut usize,
    port: u16,
    sock_buf_bytes: usize,
    peer: SocketAddr,
    pending_conn: SrtConnection,
    start: Instant,
    stream_len: Duration,
    slots: &mut Vec<PoolSlot>,
    token_index: &mut HashMap<usize, usize>,
    telemetry: &srt_transport::IngressTelemetry,
) {
    let mut socket = match bind_reuseport(port, sock_buf_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-mio] promote {peer}: bind {e}");
            return;
        }
    };
    if socket.connect(peer).is_err() {
        eprintln!("[bench-mio] promote {peer}: connect failed");
        return;
    }
    let token = Token(*next_token);
    *next_token += 1;
    if poll
        .registry()
        .register(&mut socket, token, Interest::READABLE)
        .is_err()
    {
        eprintln!("[bench-mio] promote {peer}: register failed");
        return;
    }
    let mut conn = Conn::new(pending_conn, socket);
    conn.fire_expired(crate::now_ts(start));
    conn.drain_outputs(crate::now_ts(start));
    let now = Instant::now();
    token_index.insert(token.0, slots.len());
    slots.push(PoolSlot {
        torn_down: false,
        conn,
        connected: true,
        ever_connected: true,
        data_events: 0,
        poisoned: false,
        stream_deadline: now + stream_len,
        last_data_at: now,
    });
    telemetry.record_local_promotion();
}

/// Service one readiness event against an established slot by token:
/// drain queued datagrams, feed them to the protocol, track data/idle
/// bookkeeping. Shared between `ReuseportMulti`'s merged acceptor/worker
/// loop and `ReuseportSingle`'s pure worker loop -- both drive an
/// identical `Vec<PoolSlot>` to completion once a connection is
/// promoted; they only differ in how slots *arrive* (promoted locally
/// plus occasional handoff-in, vs handoff-in only).
///
/// `token_index` maps a token to its position in `slots` -- an O(1)
/// lookup, not a linear scan. That distinction used to be free when
/// `slots` only ever held rare cross-thread bond handoffs (a handful of
/// entries at most), but #4 now promotes *every* connection through this
/// same path once it's `Connected` (see `run_pool_acceptor`'s module
/// doc), so `slots` can hold every connection a worker owns -- a scan
/// per incoming datagram at that size is real, avoidable overhead.
fn service_slot_event(
    slots: &mut [PoolSlot],
    token_index: &HashMap<usize, usize>,
    token: Token,
    buf: &mut [u8],
    start: Instant,
) {
    let Some(slot) = token_index.get(&token.0).and_then(|&i| slots.get_mut(i)) else {
        return;
    };
    let t = crate::now_ts(start);
    loop {
        match slot.conn.socket.recv(buf) {
            Ok(n) => {
                let _ = slot.conn.conn.feed_recv_buf(&buf[..n], t);
                slot.data_events += 1;
                slot.last_data_at = Instant::now();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                slot.poisoned = true;
                break;
            }
            Err(_) => break,
        }
    }
}

/// Per-tick maintenance across every established slot: fire timers,
/// drain outputs, react to Disconnected, recover from poison.
fn maintain_slots(slots: &mut [PoolSlot], start: Instant) {
    let t = crate::now_ts(start);
    for slot in slots.iter_mut() {
        slot.conn.fire_expired(t);
        if slot.conn.drain_outputs(t) {
            slot.poisoned = true;
        }
        while let Some(ev) = slot.conn.conn.poll_event() {
            if let ConnectionEvent::Disconnected { reason } = &ev {
                slot.torn_down |= !crate::is_ordered_close(reason);
                slot.connected = false;
            }
        }
        if slot.poisoned {
            // Reconnect clears ECONNREFUSED poison on connected UDP.
            if let Ok(peer) = slot.conn.socket.peer_addr() {
                let _ = slot.conn.socket.connect(peer);
                slot.poisoned = false;
            }
        }
    }
}

fn slots_to_stats(slots: Vec<PoolSlot>) -> Vec<ConnStats> {
    slots
        .into_iter()
        .map(|slot| {
            let mut s = ConnStats {
                connected: slot.ever_connected,
                data_events: slot.data_events,
                ..Default::default()
            };
            if let Some(st) = slot.conn.conn.receiver_stats() {
                s.has_stats = true;
                s.core_total = st.total_received;
                s.secondary_a = st.total_lost;
                s.secondary_b = st.total_duplicates;
                s.rtt_us = st.rtt as u64;
            }
            s
        })
        .collect()
}

// ---------------------------------------------------------------------------
// #3: ReuseportSingle -- one acceptor, W dedicated worker threads, every
// promoted connection (bonded or not) routed via
// srt_lifecycle::WorkerRouter. Unlike #4 (ReuseportMulti), admission and
// steady-state service are always on different threads, even in the
// common non-bonded case.
// ---------------------------------------------------------------------------

fn run_reuseport_single(cfg: BenchConfig, workers: usize) {
    let worker_count = workers.min(cfg.connections).max(1);
    let start = Instant::now();
    let router: crate::SharedWorkerRouter =
        Arc::new(Mutex::new(srt_lifecycle::WorkerRouter::new(worker_count)));

    let (senders, receivers): (Vec<_>, Vec<_>) = (0..worker_count)
        .map(|_| mpsc::channel::<WorkerMessage>())
        .unzip();

    let mut handles = Vec::with_capacity(worker_count);
    for (worker_index, rx) in receivers.into_iter().enumerate() {
        let cfg = cfg.clone();
        handles.push(
            std::thread::Builder::new()
                .name(format!("srt-worker-{worker_index}"))
                .spawn(move || run_worker(cfg, worker_index, start, rx))
                .expect("spawn worker"),
        );
    }

    run_single_acceptor(&cfg, start, &router, &senders);

    // Proves routing (and, when bonds are in play, group affinity)
    // actually engaged in this run rather than sitting dead -- every
    // connection goes through the router here (unlike #4's registry,
    // consulted only for bonded legs), so a nonzero tuple count on its
    // own only proves routing fired; the group count is what proves
    // bonds specifically were exercised.
    if cfg.bond_mode != BondMode::None
        && let Ok(router) = router.lock()
    {
        eprintln!(
            "[bench-mio] reuseport-single: routed {} tuples into {} bond groups",
            router.active_tuple_count(),
            router.active_group_count()
        );
    }

    let mut agg = Aggregate::new(cfg.clone());
    for handle in handles {
        for stats in handle.join().expect("worker panicked") {
            agg.add(stats);
        }
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-mio] reuseport-single admitted no connections");
        std::process::exit(1);
    }
}

/// The one acceptor: admits every flow on the shared reuseport port,
/// drives handshakes to Connected, and routes each promotion -- bonded
/// or not -- to a worker via `SharedWorkerRouter`. Unlike
/// `run_pool_acceptor`, this never services steady-state traffic itself;
/// once a connection is routed, it is entirely a worker's problem. Tells
/// every worker exactly how many connections it will ever receive once
/// admission winds down, so a worker can distinguish "no more are coming"
/// from "none have arrived yet" instead of guessing off a wall clock.
struct SinglePending {
    conn: SrtConnection,
    timers: srt_transport::ManualTimerStore,
    connected: bool,
    created_at: Instant,
}

fn new_single_pending(cfg: &BenchConfig) -> SinglePending {
    SinglePending {
        conn: SrtConnection::new_listener({
            let mut options = ConnectionOptions {
                socket_id: std::process::id(),
                tsbpd_delay: cfg.latency_ms,
                ..Default::default()
            };
            cfg.encryption.apply_to(&mut options);
            options
        }),
        timers: srt_transport::ManualTimerStore::new(),
        connected: false,
        created_at: Instant::now(),
    }
}

fn admit_single_events(
    events: &Events,
    listener: &UdpSocket,
    cfg: &BenchConfig,
    batch: &mut RecvBatch,
    buf: &mut [u8],
    pending: &mut HashMap<SocketAddr, SinglePending>,
    start: Instant,
) {
    for event in events.iter() {
        if event.token() != Token(0) {
            continue;
        }
        let t = crate::now_ts(start);
        drain_admission(listener, cfg.batching, batch, buf, |peer, data| {
            let entry = pending
                .entry(peer)
                .or_insert_with(|| new_single_pending(cfg));
            let _ = entry.conn.feed_recv_buf(data, t);
        });
    }
}

fn drive_single_pending(
    listener: &UdpSocket,
    pending: &mut HashMap<SocketAddr, SinglePending>,
    start: Instant,
) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let t = crate::now_ts(start);
    let mut promote = Vec::new();
    let mut stale = Vec::new();
    for (peer, entry) in pending.iter_mut() {
        if entry.created_at.elapsed() >= crate::CONNECT_TIMEOUT {
            stale.push(*peer);
            continue;
        }
        entry.timers.fire_expired(t, &mut entry.conn);
        if drain_conn_outputs(&mut entry.conn, &mut entry.timers, listener, *peer, t) {
            stale.push(*peer);
            continue;
        }
        while let Some(event) = entry.conn.poll_event() {
            if matches!(event, ConnectionEvent::Connected) {
                entry.connected = true;
            }
        }
        if entry.connected {
            promote.push(*peer);
        }
    }
    (stale, promote)
}

fn route_single_promotions(
    cfg: &BenchConfig,
    pending: &mut HashMap<SocketAddr, SinglePending>,
    stale: Vec<SocketAddr>,
    promote: Vec<SocketAddr>,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
    per_worker_count: &mut [usize],
) {
    for peer in stale {
        pending.remove(&peer);
    }
    for peer in promote {
        let Some(entry) = pending.remove(&peer) else {
            continue;
        };
        route_to_worker(
            cfg.port,
            cfg.sock_buf_bytes,
            peer,
            entry.conn,
            router,
            senders,
            per_worker_count,
        );
    }
}

fn run_single_acceptor(
    cfg: &BenchConfig,
    start: Instant,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(1024);
    let mut listener = match bind_reuseport(cfg.port, cfg.sock_buf_bytes) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[bench-mio] acceptor: bind {e}");
            for sender in senders {
                let _ = sender.send(WorkerMessage::Finished { total: 0 });
            }
            return;
        }
    };
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .expect("register listener");

    let mut pending: HashMap<SocketAddr, SinglePending> = HashMap::new();
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let mut admit_batch = RecvBatch::new();
    let mut buf = [0u8; 2048];
    let mut per_worker_count = vec![0usize; senders.len()];

    loop {
        let now = Instant::now();
        if now >= connect_deadline && pending.is_empty() {
            break;
        }
        poll.poll(&mut events, Some(TIMER_TICK)).ok();

        admit_single_events(
            &events,
            &listener,
            cfg,
            &mut admit_batch,
            &mut buf,
            &mut pending,
            start,
        );

        // Drive pending handshakes toward Connected, then route -- same
        // retain/promote split as run_pool_acceptor, and the same reason:
        // a connected entry must stay in `pending` until the routing loop
        // below reclaims it via `remove`, not get dropped inside `retain`.
        let (stale, promote) = drive_single_pending(&listener, &mut pending, start);
        route_single_promotions(
            cfg,
            &mut pending,
            stale,
            promote,
            router,
            senders,
            &mut per_worker_count,
        );
    }

    for (worker_index, sender) in senders.iter().enumerate() {
        let _ = sender.send(WorkerMessage::Finished {
            total: per_worker_count[worker_index],
        });
    }
}

/// Bind+connect the dedicated socket for a just-promoted connection, then
/// route it -- bonded or not -- to a worker via `WorkerRouter::assign`
/// and ship it once over that worker's channel. Every connection goes
/// through the router here (unlike #4's registry, which only bonded
/// connections consult): routing every promotion to a worker is this
/// strategy's whole point.
fn route_to_worker(
    port: u16,
    sock_buf_bytes: usize,
    peer: SocketAddr,
    pending_conn: SrtConnection,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
    per_worker_count: &mut [usize],
) {
    let socket = match srt_transport::bind_reuseport(port, sock_buf_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-mio] route {peer}: bind {e}");
            return;
        }
    };
    if socket.connect(peer).is_err() {
        eprintln!("[bench-mio] route {peer}: connect failed");
        return;
    }

    let group = pending_conn
        .peer_group_extension()
        .map(|extension| srt_lifecycle::GroupAffinity {
            group_id: extension.group_id,
            stream_id: None,
            extension,
        });
    let worker = {
        let mut router = match router.lock() {
            Ok(r) => r,
            Err(_) => return, // poisoned: drop the leg rather than corrupt routing state
        };
        router.assign(peer, group, srt_lifecycle::RoutingMode::LeastTuples)
    };
    per_worker_count[worker] += 1;

    let message = WorkerMessage::Handoff(Box::new(Handoff {
        socket,
        conn: pending_conn,
    }));
    if senders[worker].send(message).is_err() {
        eprintln!("[bench-mio] route {peer}: worker {worker} channel closed");
    }
}

/// One worker thread: pure steady-state service for whatever connections
/// the acceptor routes to it. No admission logic at all -- that's fully
/// the acceptor's job in this strategy, unlike `ReuseportMulti` where
/// acceptor and worker are the same thread.
fn run_worker(
    cfg: BenchConfig,
    worker_index: usize,
    start: Instant,
    handoffs: mpsc::Receiver<WorkerMessage>,
) -> Vec<ConnStats> {
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[bench-mio] worker {worker_index}: Poll::new {e}");
            return Vec::new();
        }
    };
    let mut events = Events::with_capacity(1024);
    let mut slots: Vec<PoolSlot> = Vec::new();
    let mut token_index: HashMap<usize, usize> = HashMap::new();
    let mut next_token: usize = 0;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    // No admission here, so no connect_deadline of its own to wait on --
    // just a generous absolute safety net plus the acceptor's own
    // `Finished` signal telling it precisely when no more are coming.
    let run_deadline =
        Instant::now() + crate::CONNECT_TIMEOUT + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut expected: Option<usize> = None;
    let mut buf = [0u8; 2048];

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        if expected == Some(slots.len()) && slots.iter().all(|s| slot_is_terminal(s, now)) {
            break;
        }
        poll.poll(&mut events, Some(TIMER_TICK)).ok();

        while let Ok(message) = handoffs.try_recv() {
            match message {
                WorkerMessage::Finished { total } => expected = Some(total),
                // #3 has a single acceptor, so nothing is ever forwarded.
                WorkerMessage::Handshake { .. } => continue,
                WorkerMessage::Handoff(handoff) => {
                    let mut socket = UdpSocket::from_std(handoff.socket);
                    let token = Token(next_token);
                    next_token += 1;
                    if poll
                        .registry()
                        .register(&mut socket, token, Interest::READABLE)
                        .is_err()
                    {
                        continue;
                    }
                    let mut conn = Conn::new(handoff.conn, socket);
                    conn.fire_expired(crate::now_ts(start));
                    conn.drain_outputs(crate::now_ts(start));
                    let now = Instant::now();
                    token_index.insert(token.0, slots.len());
                    slots.push(PoolSlot {
                        torn_down: false,
                        conn,
                        connected: true,
                        ever_connected: true,
                        data_events: 0,
                        poisoned: false,
                        stream_deadline: now + stream_len,
                        last_data_at: now,
                    });
                }
            }
        }

        for event in events.iter() {
            service_slot_event(&mut slots, &token_index, event.token(), &mut buf, start);
        }
        maintain_slots(&mut slots, start);
    }

    slots_to_stats(slots)
}

#[cfg(test)]
mod bond_affinity_tests {
    use super::*;

    // Claim/lookup/independence/concurrent-claims semantics for the
    // group-affinity registry pattern used to live here as standalone
    // tests against the ad-hoc `GroupRegistry` HashMap. Both mio's
    // `run_pool_acceptor` and tokio's `run_acceptor` now consult
    // `srt_lifecycle::WorkerRouter` instead (see `run_pool_receiver`'s
    // module doc) -- that exact set of properties is covered by
    // `srt_lifecycle`'s own `worker_router_upholds_invariants` property
    // test, which exercises the real type these `Handoff`/`WorkerMessage`
    // tests below feed into, rather than a since-unused HashMap.

    /// A Handoff carries socket+conn intact through the mpsc channel -- the
    /// exact transport promote_slot uses for a misplaced bond leg. Uses a
    /// real bound+connected socket to prove the kernel accepts the
    /// bind_reuseport -> connect sequence used at promotion time.
    #[test]
    fn handoff_round_trips_through_channel() {
        // A Handoff carries the plain std socket, not a mio one: the
        // type only accepts `Send` parts, which is what makes the
        // cross-thread move sound.
        let socket = {
            let s = srt_transport::bind_reuseport(0, srt_transport::SOCK_BUF_BYTES)
                .expect("bind ephemeral reuseport");
            s.connect("127.0.0.1:1".parse::<SocketAddr>().unwrap())
                .expect("connect");
            s
        };
        let expected_peer = socket.peer_addr().expect("peer_addr");
        let conn = SrtConnection::new_listener(ConnectionOptions::default());

        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        tx.send(WorkerMessage::Handoff(Box::new(Handoff { socket, conn })))
            .expect("send");

        let WorkerMessage::Handoff(handoff) = rx.try_recv().expect("message") else {
            panic!("expected Handoff");
        };
        assert_eq!(handoff.socket.peer_addr().unwrap(), expected_peer);
        assert!(handoff.conn.peer_group_extension().is_none());
    }

    /// Regression: `WorkerMessage` grew a `Finished` variant for #3
    /// (`ReuseportSingle`); a stray one arriving on #4's handoff channel
    /// (which never sends it, but the type is shared) must not panic or
    /// be mistaken for a Handoff.
    #[test]
    fn finished_message_does_not_panic_drain() {
        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        tx.send(WorkerMessage::Finished { total: 3 }).expect("send");
        drop(tx);
        let mut saw_finished = false;
        while let Ok(message) = rx.try_recv() {
            if matches!(message, WorkerMessage::Finished { total: 3 }) {
                saw_finished = true;
            }
        }
        assert!(saw_finished);
    }

    #[test]
    fn shared_pool_waits_for_every_expected_connection_before_exiting() {
        assert!(!shared_pool_can_stop(1, 2, true, false));
        assert!(shared_pool_can_stop(2, 2, true, false));
        assert!(shared_pool_can_stop(1, 2, true, true));
        assert!(!shared_pool_can_stop(2, 2, false, true));
    }
}
