//! tokio adapter: task-per-connection via `tokio::task::spawn_local` on a
//! `current_thread` runtime + `LocalSet` (Conn's native timers are !Send)
//! for `Ingress::PerPort`. Native `tokio::time::Sleep` timers live inside
//! `srt_transport`'s Conn.
//!
//! `Ingress::ReuseportMulti(K)` (#4) balances two needs that would
//! otherwise fight tokio's idiom if forced into one shape: bond affinity
//! needs a *deterministic* owner -- a stable, addressable unit of
//! execution a handoff channel can target -- but tokio's normal
//! multi-threaded runtime freely migrates tasks between worker threads,
//! so "the task that promoted this connection" isn't a stable identity.
//! The fix is the same one mio already uses: K independent OS threads,
//! each running its own `current_thread` runtime (a standard, supported
//! tokio pattern -- thread-per-core servers do exactly this), gives
//! `worker_index` real, stable thread identity for the registry/handoff
//! mechanism.
//!
//! *Within* each acceptor thread, though, a connection only ever gets its
//! own `spawn_local` task -- and its own socket -- if it actually has to
//! relocate to a different acceptor's owner thread for bond affinity. The
//! common case (unbonded, or bonded but already on its owner) is serviced
//! straight off the shared listener socket, dispatched by peer address,
//! same as `SharedPool`. This isn't optional style: promoting *every*
//! connection to its own `bind_reuseport`+`connect` socket, even ones that
//! never move, was measured to cost 5-6x listener CPU-sys time and
//! nonzero retransmits at 150 connections, because every new socket
//! joining the reuseport group can reroute some other still-pending
//! flow's next datagram to a different acceptor mid-handshake. See
//! `run_acceptor`'s doc for the full explanation -- it's the identical
//! fix and identical reasoning as mio's `run_pool_acceptor`.

use crate::{Aggregate, BenchConfig, BondMode, ConnStats};
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, SrtConnection};
use srt_transport::tokio_transport::Conn;
use srt_transport::{Handoff, WorkerMessage};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected task may go without a datagram from its peer
/// before it's retired as stalled. Mirrors mio's `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

/// Send queued datagrams via `sendmmsg`.  Only the datagrams the kernel
/// accepted are drained; unsent ones stay in `outbound` for retry.
/// Non-retriable errors clear the buffer and are logged.
fn flush_outbound(fd: std::os::fd::RawFd, outbound: &mut Vec<(SocketAddr, Vec<u8>)>) {
    if outbound.is_empty() {
        return;
    }
    let refs: Vec<(SocketAddr, &[u8])> = outbound.iter().map(|(a, b)| (*a, b.as_slice())).collect();
    match srt_transport::sendmsg_batch(fd, &refs) {
        Ok(sent) => {
            outbound.drain(..sent);
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => {
            eprintln!(
                "tokio flush_outbound: dropping {} datagrams: {e}",
                outbound.len()
            );
            outbound.clear();
        }
    }
}

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

/// Receive datagrams via `recvmmsg`, routing through Tokio's `try_io` so
/// readiness is properly cleared when the socket has nothing left.
/// Bounded to `MAX_RECV_ROUNDS` iterations so sustained ingress cannot
/// starve timers and sibling tasks.
fn drain_recv(
    sock: &tokio::net::UdpSocket,
    batch: &mut RecvBatch,
    mut on_datagram: impl FnMut(SocketAddr, &[u8]),
) {
    const MAX_RECV_ROUNDS: usize = 8;
    use std::os::fd::AsRawFd;
    let mut rounds = 0;
    while let Ok(received) = sock.try_io(tokio::io::Interest::READABLE, || {
        let n = srt_transport::recvmsg_batch(
            sock.as_raw_fd(),
            &mut batch.bufs,
            &mut batch.sizes,
            &mut batch.addrs,
        )?;
        if n == 0 {
            Err(std::io::ErrorKind::WouldBlock.into())
        } else {
            Ok(n)
        }
    }) {
        for i in 0..received {
            if let Some(peer) = batch.addrs[i] {
                on_datagram(peer, &batch.bufs[i][..batch.sizes[i]]);
            }
        }
        rounds += 1;
        if received < batch.bufs.len() || rounds >= MAX_RECV_ROUNDS {
            break;
        }
    }
}

async fn drain_outputs(driver: &mut Conn, now: shiguredo_srt::Timestamp) {
    super::report_drain_error("tokio", driver.drain_outputs(now).await);
}

/// Give one established connection its own connected socket, so the kernel
/// matches its packets by exact 4-tuple and an independent task can drive
/// it instead of the shared per-peer maintenance loop. `None` if the
/// socket could not be created.
fn promote_locally(
    port: u16,
    sock_buf_bytes: usize,
    peer: SocketAddr,
    conn: SrtConnection,
) -> Option<Conn> {
    let std_socket = srt_transport::bind_reuseport(port, sock_buf_bytes).ok()?;
    std_socket.connect(peer).ok()?;
    let sock = tokio::net::UdpSocket::from_std(std_socket).ok()?;
    Some(Conn::new(conn, sock))
}

pub fn run(cfg: BenchConfig) {
    if cfg.mode == crate::Mode::Sender && cfg.egress == crate::Egress::SharedSocket {
        let start = Instant::now();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let (stats, cc_peak) = rt.block_on(run_shared_sender(&cfg, start));
        let mut agg = Aggregate::new(cfg);
        agg.cc_peak = cc_peak;
        for stat in stats {
            agg.add(stat);
        }
        agg.print(start);
        if !agg.any_connected {
            std::process::exit(1);
        }
        return;
    }
    if crate::dispatch_ingress(
        &cfg,
        "tokio",
        run_reuseport_multi,
        run_shared_pool,
        run_reuseport_single,
    ) {
        return;
    }
    let start = Instant::now();
    let limiter = std::sync::Arc::new(std::sync::Mutex::new(crate::ConnectLimiter::new(
        cfg.connect_concurrency,
    )));
    let limiter2 = limiter.clone();

    let stats = crate::run_workers(&cfg, move |cfg, mine| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(tokio::task::LocalSet::new().run_until(drive(
            cfg,
            mine,
            start,
            limiter2.clone(),
        )))
    });

    let mut agg = Aggregate::new(cfg);
    for s in stats {
        agg.add(s);
    }
    agg.cc_peak = limiter.lock().unwrap().peak();
    agg.print(start);
    if !agg.any_connected {
        std::process::exit(1);
    }
}

async fn run_shared_sender(cfg: &BenchConfig, start: Instant) -> (Vec<ConnStats>, usize) {
    let socket = tokio::net::UdpSocket::from_std(
        crate::bind_shared_sender_socket(cfg.sock_buf_bytes).expect("bind shared sender socket"),
    )
    .expect("register shared sender socket");
    let indices = (0..cfg.connections).collect::<Vec<_>>();
    let limiter = std::sync::Arc::new(std::sync::Mutex::new(crate::ConnectLimiter::new(
        cfg.connect_concurrency,
    )));
    let mut sender = crate::SharedSender::new(cfg, &indices, start, limiter);
    let mut outbound = Vec::new();
    let mut buffer = [0_u8; 65_536];
    let fd = {
        use std::os::fd::AsRawFd;
        socket.as_raw_fd()
    };
    loop {
        sender.tick(cfg, &mut outbound);
        flush_outbound(fd, &mut outbound);
        if sender.done() {
            break;
        }
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                if let Ok((size, peer)) = received {
                    sender.feed(peer, &buffer[..size]);
                }
            }
            _ = tokio::time::sleep(sender.next_wait()) => {}
        }
    }
    let cc_peak = sender.cc_peak();
    (sender.finish(), cc_peak)
}

/// Drive one worker's share of the connections on this thread's runtime.
async fn drive(
    cfg: BenchConfig,
    mine: Vec<usize>,
    start: Instant,
    limiter: std::sync::Arc<std::sync::Mutex<crate::ConnectLimiter>>,
) -> Vec<crate::ConnStats> {
    let mut handles = Vec::with_capacity(mine.len());
    for i in mine {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        let lim = if c2.mode == crate::Mode::Sender {
            Some(limiter.clone())
        } else {
            None
        };
        handles.push(tokio::task::spawn_local(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, i, endpoint, start, lim).await,
                crate::Mode::Receiver => receiver_task(c2, endpoint.port(), start).await,
            }
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(stats) = h.await {
            out.push(stats);
        }
    }
    out
}

fn drain_sender_packets(driver: &mut Conn, buffer: &mut [u8; 2048], start: Instant) {
    loop {
        match driver.sock.try_recv(buffer) {
            Ok(size) => {
                let now = crate::now_ts(start);
                let _ = driver.conn.feed_recv_buf(&buffer[..size], now);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn handle_sender_events(
    cfg: &BenchConfig,
    driver: &mut Conn,
    stats: &mut ConnStats,
    stream_deadline: &mut Option<Instant>,
) {
    while let Some(event) = driver.conn.poll_event() {
        match event {
            ConnectionEvent::Connected => {
                stats.connected = true;
                if cfg.verbose() {
                    println!("CONNECTED");
                }
                if stream_deadline.is_none() {
                    *stream_deadline =
                        Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                }
            }
            ConnectionEvent::Disconnected { reason } => {
                eprintln!("[bench-tokio] disconnected: {reason}");
                stats.torn_down |= !crate::is_ordered_close(&reason);
                *stream_deadline = Some(Instant::now());
            }
            ConnectionEvent::Error(message) => {
                eprintln!("[bench-tokio] error: {message}");
            }
            _ => {}
        }
    }
}

async fn send_paced_payload(
    driver: &mut Conn,
    payload: &[u8],
    now: shiguredo_srt::Timestamp,
    stats: &mut ConnStats,
) {
    while driver.send_paced(payload, now).await.is_ok() {
        stats.data_events += 1;
    }
}

async fn wait_for_sender(
    driver: &mut Conn,
    connected: bool,
    buffer: &mut [u8; 2048],
    start: Instant,
) {
    let wait = if connected {
        Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
            .min(crate::MAX_WAIT)
    } else {
        crate::MAX_WAIT
    };
    let block_for = wait.saturating_sub(crate::TAIL_SPIN);
    if block_for > Duration::ZERO {
        tokio::select! {
            result = driver.sock.recv(buffer) => {
                if let Ok(size) = result {
                    let now = crate::now_ts(start);
                    let _ = driver.conn.feed_recv_buf(&buffer[..size], now);
                }
            }
            _ = tokio::time::sleep(block_for) => {}
        }
    }
}

async fn send_sender_payload_if_due(
    driver: &mut Conn,
    payload: &[u8],
    stats: &mut ConnStats,
    stream_deadline: Option<Instant>,
    start: Instant,
) {
    if stats.connected && !crate::shutdown::past(stream_deadline) {
        let now = crate::now_ts(start);
        send_paced_payload(driver, payload, now, stats).await;
    }
}

fn record_sender_stats(driver: &Conn, stats: &mut ConnStats) {
    if let Some(sender) = driver.conn.sender_stats() {
        stats.has_stats = true;
        stats.core_total = sender.total_sent;
        stats.secondary_a = sender.total_retransmits;
        stats.secondary_b = sender.packets_in_loss_list as u64;
    }
}

#[allow(clippy::cognitive_complexity)]
async fn sender_task(
    cfg: BenchConfig,
    index: usize,
    endpoint: std::net::SocketAddr,
    start: Instant,
    limiter: Option<std::sync::Arc<std::sync::Mutex<crate::ConnectLimiter>>>,
) -> ConnStats {
    // Park until a permit is free rather than polling on a timer: with
    // `--connect-concurrency 1` and 1000 connections, all 1000 tasks exist
    // from the start, and a periodic re-check here would cost ~1000 timer
    // wakeups per millisecond of the admission phase.
    let mut permit = crate::HandshakeAdmission::acquire_optional(limiter.as_ref()).await;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind");
    socket.connect(endpoint).await.expect("connect");

    let mut options = ConnectionOptions {
        socket_id: cfg.caller_socket_id_for(index),
        tsbpd_delay: cfg.latency_ms,
        max_bandwidth_bytes_per_sec: Some(cfg.bitrate_bps / 8),
        ..Default::default()
    };
    cfg.encryption.apply_to(&mut options);
    let mut conn = SrtConnection::new_caller(options);
    conn.connect(crate::now_ts(start))
        .expect("connect() should queue INDUCTION");

    let mut driver = Conn::new(conn, socket);
    drain_outputs(&mut driver, crate::now_ts(start)).await;

    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let handshake_started = Instant::now();
    let connect_deadline = handshake_started + crate::CONNECT_TIMEOUT;
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-tokio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if crate::shutdown::past(stream_deadline) {
            break;
        }

        wait_for_sender(&mut driver, stats.connected, &mut buf, start).await;

        drain_sender_packets(&mut driver, &mut buf, start);

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        drain_outputs(&mut driver, t).await;

        let was_connected = stats.connected;
        handle_sender_events(&cfg, &mut driver, &mut stats, &mut stream_deadline);
        if stats.connected && !was_connected {
            crate::HandshakePermit::settle(&mut permit, true);
        }

        // The send helper samples the clock once so pacing cannot turn this
        // loop into an unbounded busy section past the configured window.
        send_sender_payload_if_due(&mut driver, &payload, &mut stats, stream_deadline, start).await;
    }

    // Ordered close at the protocol level: tell the peer we are done
    // instead of just vanishing. `disconnect` emits an SRT SHUTDOWN,
    // which on the listener flushes its receive buffer *ignoring TSBPD*
    // and raises `Disconnected { peer shutdown }` -- so pending data is
    // delivered rather than aged out, and the listener learns the stream
    // ended instead of inferring it from five seconds of silence.
    crate::HandshakePermit::settle(&mut permit, stats.connected);
    let t = crate::now_ts(start);
    driver.conn.disconnect(t);
    drain_outputs(&mut driver, t).await;
    record_sender_stats(&driver, &mut stats);
    stats
}

async fn receive_receiver_packets(
    driver: &mut Conn,
    peer: &mut Option<SocketAddr>,
    buffer: &mut [u8; 2048],
    start: Instant,
) -> bool {
    if peer.is_none() {
        let received = tokio::time::timeout(crate::MAX_WAIT, driver.sock.recv_from(buffer)).await;
        if let Ok(Ok((size, addr))) = received {
            if let Err(error) = driver.sock.connect(addr).await {
                eprintln!("[bench-tokio] connect to peer failed: {error}");
                return false;
            }
            *peer = Some(addr);
            let now = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buffer[..size], now);
        }
    } else {
        tokio::select! {
            result = driver.sock.recv(buffer) => {
                if let Ok(size) = result {
                    let now = crate::now_ts(start);
                    let _ = driver.conn.feed_recv_buf(&buffer[..size], now);
                }
            }
            _ = tokio::time::sleep(crate::MAX_WAIT) => {}
        }
        while let Ok(size) = driver.sock.try_recv(buffer) {
            let now = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buffer[..size], now);
        }
    }
    true
}

fn handle_receiver_events(
    cfg: &BenchConfig,
    driver: &mut Conn,
    stats: &mut ConnStats,
    stream_deadline: &mut Option<Instant>,
) {
    while let Some(event) = driver.conn.poll_event() {
        match event {
            ConnectionEvent::Connected => {
                stats.connected = true;
                if cfg.verbose() {
                    println!("CONNECTED");
                }
                if stream_deadline.is_none() {
                    *stream_deadline =
                        Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                }
            }
            ConnectionEvent::DataReceived { .. } => {
                stats.data_events += 1;
            }
            ConnectionEvent::Disconnected { reason } => {
                eprintln!("[bench-tokio] disconnected: {reason}");
                stats.torn_down |= !crate::is_ordered_close(&reason);
                *stream_deadline = Some(Instant::now());
            }
            ConnectionEvent::Error(message) => {
                eprintln!("[bench-tokio] error: {message}");
            }
            _ => {}
        }
    }
}

fn record_receiver_stats(driver: &Conn, stats: &mut ConnStats) {
    if let Some(receiver) = driver.conn.receiver_stats() {
        stats.has_stats = true;
        stats.core_total = receiver.total_received;
        stats.secondary_a = receiver.total_lost;
        stats.secondary_b = receiver.total_duplicates;
        stats.rtt_us = receiver.rtt as u64;
    }
}

async fn receiver_task(cfg: BenchConfig, listen_port: u16, start: Instant) -> ConnStats {
    let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .await
        .expect("bind");

    let mut options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    cfg.encryption.apply_to(&mut options);
    let conn = SrtConnection::new_listener(options);
    let mut driver = Conn::new(conn, socket);

    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let mut peer: Option<SocketAddr> = None;
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-tokio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if crate::shutdown::past(stream_deadline) {
            break;
        }

        if !receive_receiver_packets(&mut driver, &mut peer, &mut buf, start).await {
            continue;
        }

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        drain_outputs(&mut driver, t).await;

        handle_receiver_events(&cfg, &mut driver, &mut stats, &mut stream_deadline);
    }

    record_receiver_stats(&driver, &mut stats);
    stats
}

// ---------------------------------------------------------------------------
// #4: ReuseportMulti -- K deterministic acceptor threads, per-connection
// spawn_local tasks for steady state.
// ---------------------------------------------------------------------------

fn run_reuseport_multi(cfg: BenchConfig, k: usize) {
    let worker_count = k.min(cfg.connections);
    let start = Instant::now();
    println!("LISTENING");
    let router: crate::SharedWorkerRouter =
        Arc::new(Mutex::new(srt_lifecycle::WorkerRouter::new(worker_count)));
    // One set of counters for every acceptor thread; see
    // `srt_transport::IngressTelemetry`.
    let telemetry = Arc::new(srt_transport::IngressTelemetry::new());

    // All channels exist before any thread spawns -- see the identical
    // mio bug this avoids: cloning a partially-built `Vec<Sender>` mid-loop
    // hands early threads a truncated view and panics on out-of-bounds
    // indexing the first time a handoff resolves to a later worker.
    let (senders, receivers): (Vec<_>, Vec<_>) = (0..worker_count)
        .map(|_| mpsc::channel::<WorkerMessage>())
        .unzip();

    let mut handles = Vec::with_capacity(worker_count);
    for (worker_index, rx) in receivers.into_iter().enumerate() {
        let cfg = cfg.clone();
        let router = router.clone();
        let telemetry = telemetry.clone();
        let all_senders = senders.clone();
        handles.push(
            std::thread::Builder::new()
                .name(format!("srt-acceptor-{worker_index}"))
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("tokio current_thread runtime");
                    rt.block_on(tokio::task::LocalSet::new().run_until(run_acceptor(
                        cfg,
                        worker_index,
                        start,
                        router,
                        all_senders,
                        rx,
                        telemetry,
                    )))
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
    eprintln!("{}", telemetry.report("tokio"));
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-tokio] pool receiver admitted no connections");
        std::process::exit(1);
    }
}

/// One acceptor thread's whole life: admits handshakes on its reuseport
/// listener socket, drives every tracked peer to completion, and only
/// ever creates a *second* socket for the rare case where a bonded leg
/// must physically relocate to a different acceptor's owner thread.
///
/// The common case -- unbonded, or bonded but already on its group's
/// owner thread -- is serviced straight off this thread's existing
/// listener socket, dispatched by peer address, never spawning a task or
/// binding anything new: this is the same fix as mio's `run_pool_acceptor`
/// (see its module doc for why -- every *new* socket bound into this
/// port's reuseport group can reroute some other pending flow's next
/// datagram to a different acceptor, measured at 5-6x listener CPU-sys
/// time and non-zero retransmits when every connection got promoted).
/// Only a leg that actually needs to relocate gets `spawn_local`'d as its
/// own task, via a handoff -- tokio's ordinary task-per-connection idiom
/// stays exactly right for that genuinely-independent case, just not for
/// the common one anymore.
struct AcceptorContext<'a> {
    cfg: &'a BenchConfig,
    worker_index: usize,
    start: Instant,
    admission: &'a srt_transport::AdmissionOptions,
    router: &'a crate::SharedWorkerRouter,
    senders: &'a [mpsc::Sender<WorkerMessage>],
    telemetry: &'a srt_transport::IngressTelemetry,
    tasks: &'a mut Vec<tokio::task::JoinHandle<ConnStats>>,
}

async fn wait_for_acceptor_input(
    listener: &tokio::net::UdpSocket,
    tick: &mut tokio::time::Interval,
    recv_batch: &mut RecvBatch,
    peers: &mut srt_transport::PeerTable,
    context: &AcceptorContext<'_>,
) {
    tokio::select! {
        _ = listener.readable() => {
            drain_recv(listener, recv_batch, |peer, data| {
                peers.admit_and_forward(
                    peer,
                    data,
                    crate::now_ts(context.start),
                    context.admission,
                    context.worker_index,
                    context.senders,
                    context.telemetry,
                );
            });
        }
        _ = tick.tick() => {}
    }
}

fn promotion_decision(
    context: &AcceptorContext<'_>,
    peer: SocketAddr,
) -> srt_lifecycle::PromotionDecision {
    match context.router.lock() {
        Ok(mut router) => srt_lifecycle::decide_promotion(
            context.cfg.promotion,
            peer,
            None,
            context.worker_index,
            &mut router,
            srt_lifecycle::RoutingMode::LeastTuples,
        ),
        Err(_) => srt_lifecycle::PromotionDecision::StayOnListener,
    }
}

fn promote_connected_peers(
    context: &mut AcceptorContext<'_>,
    peers: &mut srt_transport::PeerTable,
    stream_len: Duration,
) {
    let mut connected = Vec::new();
    peers.drain_events(stream_len, &mut connected);
    for connected in connected {
        let peer = connected.representative_peer;
        if peers
            .logical_peer(&connected.logical_peer)
            .and_then(|logical| logical.group_affinity())
            .is_some()
        {
            continue;
        }
        let decision = promotion_decision(context, peer);
        if matches!(decision, srt_lifecycle::PromotionDecision::StayOnListener) {
            continue;
        }
        let Some(srt_transport::RemovedLogicalPeer::Direct(p)) =
            peers.remove(connected.logical_peer)
        else {
            continue;
        };
        match decision {
            srt_lifecycle::PromotionDecision::RelocateTo(owner) => relocate_to_owner(
                context.cfg.port,
                context.cfg.sock_buf_bytes,
                peer,
                p.connection,
                owner,
                context.senders,
                context.telemetry,
            ),
            srt_lifecycle::PromotionDecision::PromoteHere => {
                if let Some(driver) = promote_locally(
                    context.cfg.port,
                    context.cfg.sock_buf_bytes,
                    peer,
                    p.connection,
                ) {
                    let cfg = context.cfg.clone();
                    let start = context.start;
                    context.tasks.push(tokio::task::spawn_local(async move {
                        established_conn_task(driver, cfg, start).await
                    }));
                    context.telemetry.record_local_promotion();
                }
            }
            srt_lifecycle::PromotionDecision::StayOnListener => {}
        }
    }
}

fn drain_acceptor_handoffs(
    context: &mut AcceptorContext<'_>,
    peers: &mut srt_transport::PeerTable,
    handoffs: &mpsc::Receiver<WorkerMessage>,
) {
    while let Ok(message) = handoffs.try_recv() {
        let handoff = match message {
            WorkerMessage::Handoff(handoff) => handoff,
            WorkerMessage::Finished { .. } => continue,
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
        };
        let socket = match tokio::net::UdpSocket::from_std(handoff.socket) {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!(
                    "[bench-tokio] acceptor {}: handoff register {error}",
                    context.worker_index
                );
                continue;
            }
        };
        let driver = Conn::new(handoff.conn, socket);
        let cfg = context.cfg.clone();
        let start = context.start;
        context.tasks.push(tokio::task::spawn_local(async move {
            established_conn_task(driver, cfg, start).await
        }));
    }
}

async fn run_acceptor(
    cfg: BenchConfig,
    worker_index: usize,
    start: Instant,
    router: crate::SharedWorkerRouter,
    senders: Vec<mpsc::Sender<WorkerMessage>>,
    handoffs: mpsc::Receiver<WorkerMessage>,
    telemetry: Arc<srt_transport::IngressTelemetry>,
) -> Vec<ConnStats> {
    let std_listener = match srt_transport::bind_reuseport(cfg.port, cfg.sock_buf_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-tokio] acceptor {worker_index}: bind {e}");
            return Vec::new();
        }
    };
    let listener = tokio::net::UdpSocket::from_std(std_listener).expect("register listener");
    let listener_fd = {
        use std::os::fd::AsRawFd;
        listener.as_raw_fd()
    };

    let mut peers = srt_transport::PeerTable::new();
    let admission = cfg.admission_options(std::process::id(), cfg.cookie_routing);
    let mut tasks: Vec<tokio::task::JoinHandle<ConnStats>> = Vec::new();
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut tick = tokio::time::interval(TIMER_TICK);
    let mut recv_batch = RecvBatch::new();
    let mut outbound = Vec::new();

    {
        let mut context = AcceptorContext {
            cfg: &cfg,
            worker_index,
            start,
            admission: &admission,
            router: &router,
            senders: &senders,
            telemetry: &telemetry,
            tasks: &mut tasks,
        };
        loop {
            let now = Instant::now();
            if now >= run_deadline {
                break;
            }
            // Vacuously true while nothing exists yet, so an acceptor that
            // never admits anything still exits once the connect window
            // closes instead of hanging on an empty guard.
            let all_terminal = peers.all_terminal(now, connect_deadline, IDLE_GRACE);
            if crate::shutdown::requested() || (now >= connect_deadline && all_terminal) {
                break;
            }

            wait_for_acceptor_input(&listener, &mut tick, &mut recv_batch, &mut peers, &context)
                .await;

            let t = crate::now_ts(start);
            peers.poll_outbound(t, &mut outbound);
            flush_outbound(listener_fd, &mut outbound);
            promote_connected_peers(&mut context, &mut peers, stream_len);

            drain_acceptor_handoffs(&mut context, &mut peers, &handoffs);
        }
    }

    let mut stats: Vec<ConnStats> = peers
        .into_iter()
        .map(|(peer, p)| {
            // Free this tuple's (and, if it was the last member, its
            // group's) router bookkeeping now that the connection is
            // fully done -- a no-op if this peer never touched the
            // router (unbonded).
            if let Ok(mut router) = router.lock() {
                router.release(&peer);
            }
            let mut s = ConnStats {
                connected: p.stream_deadline.is_some(),
                torn_down: p.torn_down,
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
    for task in tasks {
        if let Ok(s) = task.await {
            stats.push(s);
        }
    }
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
    let std_socket = match srt_transport::bind_reuseport(port, sock_buf_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-tokio] relocate {peer}: bind {e}");
            return;
        }
    };
    if std_socket.connect(peer).is_err() {
        eprintln!("[bench-tokio] relocate {peer}: connect failed");
        return;
    }
    let message = WorkerMessage::Handoff(Box::new(Handoff {
        socket: std_socket,
        conn: pending_conn,
    }));
    if senders[owner].send(message).is_err() {
        eprintln!("[bench-tokio] relocate {peer}: owner {owner} channel closed");
    } else {
        telemetry.record_handoff();
    }
}

/// Steady-state loop for one promoted (already-connected) connection,
/// running as its own `spawn_local` task -- tokio's ordinary
/// task-per-connection idiom, same as the `PerPort` path above, just fed
/// a socket that admission already connected instead of discovering the
/// peer itself.
async fn established_conn_task(mut driver: Conn, cfg: BenchConfig, start: Instant) -> ConnStats {
    // `connected` is live state, used only for the loop-exit check below
    // (it flips false on Disconnected). The task is only ever spawned
    // post-promotion (Connected has already fired), so it was *always*
    // connected at some point -- reported unconditionally as `true` in
    // the final ConnStats, not this live flag: a session that streamed
    // everything and then legitimately tripped SRT's own peer-idle
    // timeout is still a success, and reporting the live flag alone
    // would misreport perfect delivery as a failed connection the moment
    // it flips.
    let mut connected = true;
    let mut torn_down = false;
    let mut data_events = 0u64;
    let stream_deadline = Instant::now() + Duration::from_secs_f64(cfg.duration_secs);
    let mut last_data_at = Instant::now();
    let mut buf = [0u8; 2048];
    // This task is only ever spawned post-Connected, so `connect_deadline`
    // (srt_lifecycle::is_terminal's other exit path, for "never
    // connected") never applies -- pass `now` for it so it's inert.

    loop {
        let now = Instant::now();
        // Also honour the harness's stop signal directly, not just via
        // `!connected` from a received Disconnected -- the sender's
        // ordered close should reach this task through the protocol, but
        // if it doesn't (or races), this task should not be the reason a
        // whole cell hangs well past its backstop.
        if crate::shutdown::requested()
            || srt_lifecycle::is_terminal(
                connected,
                Some(stream_deadline),
                last_data_at,
                now,
                now,
                IDLE_GRACE,
            )
        {
            break;
        }

        tokio::select! {
            res = driver.sock.recv(&mut buf) => {
                if let Ok(n) = res {
                    let t = crate::now_ts(start);
                    let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                    data_events += 1;
                    last_data_at = Instant::now();
                }
            }
            _ = tokio::time::sleep(crate::MAX_WAIT) => {}
        }
        while let Ok(n) = driver.sock.try_recv(&mut buf) {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf[..n], t);
            data_events += 1;
            last_data_at = Instant::now();
        }

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        drain_outputs(&mut driver, t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-tokio] disconnected: {reason}");
                    torn_down |= !crate::is_ordered_close(&reason);
                    connected = false;
                }
                ConnectionEvent::Error(msg) => eprintln!("[bench-tokio] error: {msg}"),
                _ => {}
            }
        }
    }

    let mut stats = ConnStats {
        connected: true,
        torn_down,
        data_events,
        ..Default::default()
    };
    if let Some(s) = driver.conn.receiver_stats() {
        stats.has_stats = true;
        stats.core_total = s.total_received;
        stats.secondary_a = s.total_lost;
        stats.secondary_b = s.total_duplicates;
        stats.rtt_us = s.rtt as u64;
    }
    stats
}

// ---------------------------------------------------------------------------
// #2: SharedPool -- K plainly-bound ports, no SO_REUSEPORT, no promotion
// ---------------------------------------------------------------------------

/// K real ports, each socket serving many peers by peer-address dispatch
/// for their whole life. The control the reuseport strategies are
/// measured against: it isolates "fewer sockets and wakeups" from
/// "kernel-level demux", which is `ReuseportMulti`'s job. Single-threaded
/// by design, so any win here is not just extra cores.
fn run_shared_pool(cfg: BenchConfig, k: usize) {
    let start = Instant::now();
    println!("LISTENING");
    let agg_cfg = cfg.clone();
    // K pool sockets across `--workers` OS threads. `workers = 1` (the
    // default) keeps every socket on one thread, which is what makes this
    // strategy the single-threaded control it was designed to be: it
    // isolates "fewer wakeups" from "kernel-level demux", which is
    // ReuseportMulti's job.
    //
    // But one thread is also a hard ceiling, and a sender strong enough to
    // exceed it does not look like a ceiling in the results -- it looks
    // like a collapse. Measured at 400 conns x 8 Mbps with the listener on
    // its own cores: 2 sender workers deliver 94% with zero rcvbuf drops,
    // 3 deliver 13% with 1.7M drops. Nothing about that reads as "one core
    // was the limit" unless the knob to add a second one exists.
    let threads = cfg.workers.clamp(1, k);
    let stats = crate::run_shards(threads, k, move |mine| {
        let cfg = cfg.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio current_thread runtime");
        rt.block_on(tokio::task::LocalSet::new().run_until(async move {
            let mut tasks = Vec::new();
            for index in mine {
                let cfg = cfg.clone();
                tasks.push(tokio::task::spawn_local(async move {
                    serve_pool_socket(cfg, index, start).await
                }));
            }
            let mut all = Vec::new();
            for t in tasks {
                if let Ok(s) = t.await {
                    all.extend(s);
                }
            }
            all
        }))
    });

    let mut agg = Aggregate::new(agg_cfg);
    for s in stats {
        agg.add(s);
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-tokio] shared pool admitted no connections");
        std::process::exit(1);
    }
}

/// One pool socket, from bind to the last peer going terminal.
async fn serve_pool_socket(cfg: BenchConfig, index: usize, start: Instant) -> Vec<ConnStats> {
    let addr = SocketAddr::new(
        std::net::IpAddr::from([0, 0, 0, 0]),
        cfg.port + index as u16,
    );
    let std_socket = std::net::UdpSocket::bind(addr).expect("bind shared-pool socket");
    std_socket
        .set_nonblocking(true)
        .expect("nonblocking shared-pool socket");
    {
        use std::os::fd::AsRawFd;
        let _ = srt_transport::set_sock_bufs(std_socket.as_raw_fd(), cfg.sock_buf_bytes);
    }
    let sock = tokio::net::UdpSocket::from_std(std_socket).expect("register pool socket");
    let sock_fd = {
        use std::os::fd::AsRawFd;
        sock.as_raw_fd()
    };

    let mut peers = srt_transport::PeerTable::new();
    // No SO_REUSEPORT group here, so nothing can rehash and there is
    // nowhere to forward to: one worker, cookie routing inert.
    let admission = cfg.admission_options(std::process::id(), false);
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut recv_batch = RecvBatch::new();
    let mut outbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    let mut connected = Vec::new();
    let mut connected_streams = 0usize;
    let mut logical_run_deadline = None;

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        if logical_run_deadline.is_none()
            && peers.logical_started_count() >= cfg.logical_connection_count()
        {
            logical_run_deadline = Some(now + stream_len);
        }
        if logical_run_deadline.is_some_and(|deadline| now >= deadline) {
            break;
        }
        if crate::shutdown::requested()
            || ((!peers.is_empty() || now >= connect_deadline)
                && peers.all_terminal(now, connect_deadline, IDLE_GRACE))
        {
            break;
        }

        tokio::select! {
            _ = sock.readable() => {
                drain_recv(&sock, &mut recv_batch, |peer, data| {
                    admit_one(&mut peers, &admission, peer, data, start);
                });
            }
            _ = tokio::time::sleep(TIMER_TICK) => {}
        }

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        flush_outbound(sock_fd, &mut outbound);
        // SharedPool never promotes, so a first Connected only starts the
        // stream clock -- which drain_events already did.
        peers.drain_events(stream_len, &mut connected);
        connected_streams = connected_streams.saturating_add(connected.len());
        if connected_streams >= cfg.logical_connection_count() {
            logical_run_deadline = Some(Instant::now() + stream_len);
        }
    }

    crate::collect_listener_stats(peers)
}

/// Admit one datagram. No reuseport group means no cookie forwarding, so
/// this is the table's admit with a single-worker view.
fn admit_one(
    peers: &mut srt_transport::PeerTable,
    admission: &srt_transport::AdmissionOptions,
    peer: SocketAddr,
    data: &[u8],
    start: Instant,
) {
    let telemetry = srt_transport::IngressTelemetry::new();
    let _ = peers.admit(
        peer,
        data,
        crate::now_ts(start),
        admission,
        0,
        1,
        &telemetry,
    );
}

// ---------------------------------------------------------------------------
// #3: ReuseportSingle -- one acceptor, W dedicated worker threads
// ---------------------------------------------------------------------------

/// One acceptor owns the listening socket and every half-open handshake;
/// workers only ever receive connections that are already established.
///
/// Because a single thread holds all handshake state, no reuseport rehash
/// can separate a datagram from the state it belongs to -- the
/// mid-handshake stranding that `ReuseportMulti` needs cookie routing to
/// survive cannot arise here. The cost is that every connection has to
/// move, so every one is promoted, which is the tradeoff being measured.
fn run_reuseport_single(cfg: BenchConfig, workers: usize) {
    let worker_count = workers.min(cfg.connections).max(1);
    let start = Instant::now();
    println!("LISTENING");
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
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("tokio current_thread runtime");
                    rt.block_on(
                        tokio::task::LocalSet::new().run_until(run_pool_worker(cfg, start, rx)),
                    )
                })
                .expect("spawn worker"),
        );
    }

    let agg_cfg = cfg.clone();
    {
        let router = router.clone();
        let senders = senders.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio current_thread runtime");
        rt.block_on(
            tokio::task::LocalSet::new()
                .run_until(run_single_acceptor(&cfg, start, &router, &senders)),
        );
    }
    // Workers stop when their tally is met; dropping the last senders
    // also unblocks any that never received one.
    drop(senders);

    let mut agg = Aggregate::new(agg_cfg);
    for handle in handles {
        for s in handle.join().expect("worker panicked") {
            agg.add(s);
        }
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-tokio] reuseport-single admitted no connections");
        std::process::exit(1);
    }
}

/// The single acceptor: admit every flow, route each to a worker as soon
/// as it is established.
async fn admit_single_until_tick(
    listener: &tokio::net::UdpSocket,
    recv_batch: &mut RecvBatch,
    peers: &mut srt_transport::PeerTable,
    admission: &srt_transport::AdmissionOptions,
    start: Instant,
) {
    tokio::select! {
        _ = listener.readable() => {
            drain_recv(listener, recv_batch, |peer, data| {
                admit_one(peers, admission, peer, data, start);
            });
        }
        _ = tokio::time::sleep(TIMER_TICK) => {}
    }
}

struct SingleAcceptorContext<'a> {
    cfg: &'a BenchConfig,
    stream_len: Duration,
    router: &'a crate::SharedWorkerRouter,
    senders: &'a [mpsc::Sender<WorkerMessage>],
    telemetry: &'a srt_transport::IngressTelemetry,
}

fn route_one_connected_peer(
    context: &SingleAcceptorContext<'_>,
    peers: &mut srt_transport::PeerTable,
    connected: srt_transport::NewlyConnectedPeer,
    routed: &mut usize,
) {
    let peer = connected.representative_peer;
    let group = peers
        .logical_peer(&connected.logical_peer)
        .and_then(|logical| logical.group_affinity());
    let Some(srt_transport::RemovedLogicalPeer::Direct(entry)) =
        peers.remove(connected.logical_peer)
    else {
        return;
    };
    let owner = match context.router.lock() {
        Ok(mut router) => router.assign(peer, group, srt_lifecycle::RoutingMode::LeastTuples),
        Err(_) => 0,
    };
    let Ok(socket) = srt_transport::bind_reuseport(context.cfg.port, context.cfg.sock_buf_bytes)
    else {
        return;
    };
    if socket.connect(peer).is_err() {
        return;
    }
    let message = WorkerMessage::Handoff(Box::new(srt_transport::Handoff {
        socket,
        conn: entry.connection,
    }));
    if context.senders[owner].send(message).is_ok() {
        context.telemetry.record_handoff();
        *routed += 1;
    }
}

fn route_connected_peers(
    context: &SingleAcceptorContext<'_>,
    peers: &mut srt_transport::PeerTable,
    connected: &mut Vec<srt_transport::NewlyConnectedPeer>,
    routed: &mut usize,
) {
    peers.drain_events(context.stream_len, connected);
    for connected in std::mem::take(connected) {
        route_one_connected_peer(context, peers, connected, routed);
    }
}

async fn run_single_acceptor(
    cfg: &BenchConfig,
    start: Instant,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let Ok(std_socket) = srt_transport::bind_reuseport(cfg.port, cfg.sock_buf_bytes) else {
        eprintln!("[bench-tokio] reuseport-single: bind failed");
        return;
    };
    let Some(listener) = tokio::net::UdpSocket::from_std(std_socket).ok() else {
        eprintln!("[bench-tokio] reuseport-single: register failed");
        return;
    };
    let listener_fd = {
        use std::os::fd::AsRawFd;
        listener.as_raw_fd()
    };

    let mut peers = srt_transport::PeerTable::new();
    // One acceptor means one owner for every handshake, so there is
    // nobody a stray CONCLUSION could need forwarding to.
    let admission = cfg.admission_options(std::process::id(), false);
    let telemetry = srt_transport::IngressTelemetry::new();
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let mut routed = 0usize;
    let mut recv_batch = RecvBatch::new();
    let mut outbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    let mut connected = Vec::new();
    let context = SingleAcceptorContext {
        cfg,
        stream_len,
        router,
        senders,
        telemetry: &telemetry,
    };

    // Admission ends with the connect window: anything not established by
    // then never will be.
    while Instant::now() < connect_deadline && routed < cfg.connections {
        admit_single_until_tick(&listener, &mut recv_batch, &mut peers, &admission, start).await;

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        flush_outbound(listener_fd, &mut outbound);
        route_connected_peers(&context, &mut peers, &mut connected, &mut routed);
    }

    // Tell each worker its final tally so it can stop waiting rather than
    // guess from a clock.
    for sender in senders {
        let _ = sender.send(WorkerMessage::Finished { total: routed });
    }
    if cfg.bond_mode != BondMode::None
        && let Ok(router) = router.lock()
    {
        eprintln!(
            "[bench-tokio] reuseport-single: routed {} tuples into {} bond groups",
            router.active_tuple_count(),
            router.active_group_count()
        );
    }
}

/// One worker: drive whatever the acceptor hands it, to completion.
async fn run_pool_worker(
    cfg: BenchConfig,
    start: Instant,
    handoffs: mpsc::Receiver<WorkerMessage>,
) -> Vec<ConnStats> {
    let mut tasks = Vec::new();
    let mut stats: Vec<ConnStats> = Vec::new();
    let mut expected: Option<usize> = None;
    let mut received = 0usize;
    let deadline = Instant::now()
        + crate::CONNECT_TIMEOUT
        + Duration::from_secs_f64(cfg.duration_secs)
        + IDLE_GRACE
        + Duration::from_secs(30);

    // Stop once the acceptor's tally is in and all of them have arrived;
    // the deadline is only a backstop against a wedged acceptor.
    while Instant::now() < deadline && !crate::shutdown::requested() {
        while let Ok(message) = handoffs.try_recv() {
            match message {
                WorkerMessage::Finished { total } => expected = Some(total),
                // Only ReuseportMulti forwards handshakes, and never here.
                WorkerMessage::Handshake { .. } => {}
                WorkerMessage::Handoff(handoff) => {
                    let std_socket = handoff.socket;
                    let Some(sock) = tokio::net::UdpSocket::from_std(std_socket).ok() else {
                        continue;
                    };
                    let driver = Conn::new(handoff.conn, sock);
                    let cfg2 = cfg.clone();
                    tasks.push(tokio::task::spawn_local(async move {
                        established_conn_task(driver, cfg2, start).await
                    }));
                    received += 1;
                }
            }
        }
        if expected.is_some_and(|total| received >= total) {
            break;
        }
        tokio::time::sleep(TIMER_TICK).await;
    }

    for task in tasks {
        if let Ok(s) = task.await {
            stats.push(s);
        }
    }
    stats
}
