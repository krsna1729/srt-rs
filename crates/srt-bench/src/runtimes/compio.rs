//! compio adapter: task-per-connection via `compio::runtime::spawn` —
//! compio's designed primitive. Completion-based (owned-buffer) I/O has no
//! non-blocking try_recv, so each connection gets a detached continuous
//! reader feeding a channel plus the protocol loop. The pacing loop never
//! cancels a receive operation — cancel churn collapses io_uring
//! throughput at scale. Native `compio::time::sleep` timers live inside
//! Conn.
//!
//! # Buffer lifecycle
//!
//! Receive buffers are allocated once and recycled end-to-end: the reader
//! task sends the buffer (with its valid length) through the data channel,
//! the consumer borrows it for `feed_recv_buf`, then returns it via a
//! recycle channel. The reader swaps in the recycled buffer for the next
//! recv; only when the recycle channel is empty does it allocate a fresh
//! one. The protocol layer's own `DataPacket::decode` still does a
//! `to_vec` internally — fixing that requires a protocol-layer API change.
//!
//! `Ingress::ReuseportMulti(K)` (#4) uses the identical fix and reasoning
//! as mio's `run_pool_acceptor`, tokio's `run_acceptor`, smol's
//! `run_acceptor`, monoio's `run_acceptor`, and glommio's `run_acceptor`:
//! K OS threads, each running its own compio `Runtime` (spawned manually,
//! same as mio/monoio -- compio's `Runtime` doesn't create its own thread
//! the way glommio's `LocalExecutorBuilder` does), gives `worker_index`
//! stable thread identity for the bond-affinity registry/handoff
//! mechanism. Within each acceptor thread, a connection only ever gets its
//! own task -- and its own socket -- if it actually needs to relocate for
//! bond affinity; the common case is serviced straight off the shared
//! listener socket by peer-address dispatch, bypassing the `Conn` wrapper
//! in favor of direct `SrtConnection` + `srt_transport::ManualTimerStore`
//! + `listener.send_to`.
//!
//! Admission reuses the exact reader-task + bounded-channel shape already
//! proven above in `receiver_task` (compio has no non-blocking try_recv
//! either): a dedicated task recvs in a genuine `.await` loop -- never
//! cancelled, same reasoning as the module doc above -- and hands
//! `(peer, datagram)` pairs to the maintenance loop through the channel,
//! decoupled from the maintenance tick. Unlike `receiver_task`'s reader
//! (which connects the socket to its one discovered peer), this reader
//! never calls `connect` -- the shared listener must stay unconnected to
//! keep admitting every peer, not just the first.
//!
//! THROUGHPUT AND `--promote-all` (measured; supersedes an earlier,
//! wrong "KNOWN LIMITATION" note here).
//!
//! With the default bond-only promotion, #4 under-delivers badly at
//! the default 8Mbps/conn -- at N=25 the listener took only 49.1% of what
//! the caller sent. That was blamed here on owned-buffer completion round-trips
//! being intrinsically too costly per packet. That explanation was wrong.
//! Raising K changes nothing (measured identical for K=2..25), and this
//! runtime's own `PerPort` path is clean at the same load.
//!
//! The real cause is this file's shared-listener design: every live peer
//! is serviced from one worker's sequential per-tick maintenance loop, so
//! the runtime's scheduler never gets to interleave them. Giving each
//! connection its own connected socket and its own task
//! (`--promote-all=on`) removes the bottleneck:
//!
//!   N=25, K=4, 8Mbps/conn:  49.1% -> 99.9% delivered, RTT 11.1ms -> 20.6ms
//!
//! Promotion is therefore not a uniform cost to be avoided: on a runtime
//! with a real task scheduler it is the point. (On mio -- a flat epoll
//! loop with no task model -- the same change measures
//! neutral-to-negative, which is why this is a flag and not a default.)
//!
//! Residual cost with promotion on: sec_a=0 retransmits, from
//! SO_REUSEPORT group churn rerouting flows mid-handshake. See
//! crates/srt-transport/tests/reuseport_rehash.rs and mio.rs's
//! ORPHAN_CONCLUSION_COUNT; cookie-keyed handshake routing is the
//! outstanding fix for that.

use crate::{Aggregate, BenchConfig, BondMode, ConnStats};
use compio::buf::BufResult;
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, GroupExtensionData, SrtConnection};
use srt_transport::compio_transport::Conn;
use srt_transport::{Handoff, WorkerMessage};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected peer may go without a datagram from its peer
/// before it's retired as stalled. Mirrors the other backends' `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);
type Received = crate::queue::BoundedReceiver<(Vec<u8>, usize)>;
type Recycle = crate::queue::BoundedSender<Vec<u8>>;
type AddressedReceived = crate::queue::BoundedReceiver<(SocketAddr, Vec<u8>, usize)>;

fn enqueue_received(
    sender: &crate::queue::BoundedSender<(Vec<u8>, usize)>,
    buffer: &mut Vec<u8>,
    replacement: Vec<u8>,
    size: usize,
) -> bool {
    let owned = std::mem::replace(buffer, replacement);
    match sender.try_send((owned, size)) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full((returned, _))) => {
            *buffer = returned;
            true
        }
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

fn enqueue_addressed(
    sender: &crate::queue::BoundedSender<(SocketAddr, Vec<u8>, usize)>,
    peer: SocketAddr,
    buffer: &mut Vec<u8>,
    replacement: Vec<u8>,
    size: usize,
) -> bool {
    let owned = std::mem::replace(buffer, replacement);
    match sender.try_send((peer, owned, size)) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full((_, returned, _))) => {
            *buffer = returned;
            true
        }
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

async fn drain_outputs(driver: &mut Conn, now: shiguredo_srt::Timestamp) {
    super::report_drain_error("compio", driver.drain_outputs(now).await);
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
    let sock = compio::net::UdpSocket::from_std(std_socket).ok()?;
    Some(Conn::new(conn, sock))
}

pub fn run(cfg: BenchConfig) {
    if cfg.mode == crate::Mode::Sender && cfg.egress == crate::Egress::SharedSocket {
        let start = Instant::now();
        let (stats, cc_peak) = compio::runtime::Runtime::builder()
            .build()
            .expect("compio runtime")
            .block_on(run_shared_sender(&cfg, start));
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
        "compio",
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
        compio::runtime::Runtime::builder()
            .build()
            .expect("compio runtime")
            .block_on(drive(cfg, mine, start, limiter2.clone()))
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
    let socket = compio::net::UdpSocket::from_std(
        crate::bind_shared_sender_socket(cfg.sock_buf_bytes).expect("bind shared sender socket"),
    )
    .expect("register shared sender socket");
    let (inbox_tx, inbox_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let (recycle_tx, recycle_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let reader = socket.clone();
    let _reader = compio::runtime::spawn(async move {
        let mut buffer = vec![0_u8; 65_536];
        loop {
            let BufResult(result, returned) = reader.recv_from(buffer).await;
            buffer = returned;
            let Ok((size, peer)) = result else { break };
            let recycled = recycle_rx.try_recv().unwrap_or_else(|_| vec![0u8; 65_536]);
            if !enqueue_addressed(&inbox_tx, peer, &mut buffer, recycled, size) {
                break;
            }
        }
    });
    let indices = (0..cfg.connections).collect::<Vec<_>>();
    let limiter = std::sync::Arc::new(std::sync::Mutex::new(crate::ConnectLimiter::new(
        cfg.connect_concurrency,
    )));
    let mut sender = crate::SharedSender::new(cfg, &indices, start, limiter);
    let mut outbound = Vec::new();
    loop {
        while let Ok((peer, buf, size)) = inbox_rx.try_recv() {
            sender.feed(peer, &buf[..size]);
            let _ = recycle_tx.try_send(buf);
        }
        sender.tick(cfg, &mut outbound);
        for (peer, packet) in outbound.drain(..) {
            let BufResult(result, _) = socket.send_to(packet, peer).await;
            result.expect("shared send_to");
        }
        if sender.done() {
            break;
        }
        compio::time::sleep(sender.next_wait()).await;
    }
    let cc_peak = sender.cc_peak();
    let mut stats = sender.finish();
    if let Some(first) = stats.first_mut() {
        first.datapath_queue.merge(inbox_rx.stats());
    }
    (stats, cc_peak)
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
        handles.push(compio::runtime::spawn(async move {
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

fn drain_sender_packets(driver: &mut Conn, received: &Received, recycle: &Recycle, start: Instant) {
    while let Ok((buffer, size)) = received.try_recv() {
        let now = crate::now_ts(start);
        let _ = driver.conn.feed_recv_buf(&buffer[..size], now);
        let _ = recycle.try_send(buffer);
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
                eprintln!("[bench-compio] disconnected: {reason}");
                stats.torn_down |= !crate::is_ordered_close(&reason);
                *stream_deadline = Some(Instant::now());
            }
            ConnectionEvent::Error(message) => {
                eprintln!("[bench-compio] error: {message}");
            }
            _ => {}
        }
    }
}

/// Offer the application source's pending payload to SRT.
///
/// The source clock, not SRT's pacing, decides how much payload exists;
/// SRT only decides how much of it gets through. Draining "while SRT
/// allows" -- which is what this used to do -- made the workload rate and
/// the pacing ceiling the same quantity.
async fn send_paced_payload(
    driver: &mut Conn,
    payload: &[u8],
    now: shiguredo_srt::Timestamp,
    stats: &mut ConnStats,
    source: &mut crate::source::SourceClock,
) {
    let mut accepted = 0;
    while source.pending() > accepted {
        if driver.send_paced(payload, now).await.is_err() {
            source.refused();
            break;
        }
        stats.data_events += 1;
        accepted += 1;
    }
    for _ in 0..accepted {
        source.accepted();
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
    endpoint: SocketAddr,
    start: Instant,
    limiter: Option<std::sync::Arc<std::sync::Mutex<crate::ConnectLimiter>>>,
) -> ConnStats {
    let mut permit = crate::HandshakeAdmission::acquire_optional(limiter.as_ref()).await;
    let socket = compio::net::UdpSocket::from_std(
        crate::bind_configured_socket(SocketAddr::from(([0, 0, 0, 0], 0)), cfg.sock_buf_bytes)
            .expect("bind"),
    )
    .expect("register socket");
    socket.connect(endpoint).await.expect("connect");

    let mut options = ConnectionOptions {
        socket_id: cfg.caller_socket_id_for(index),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    // One resolution point for every runtime: the pacing policy comes
    // from the config, not from a local `bitrate / 8` that would make the
    // workload rate and the pacing ceiling the same number again.
    cfg.apply_srt_bandwidth(&mut options);
    cfg.encryption.apply_to(&mut options);
    let mut conn = SrtConnection::new_caller(options);
    conn.connect(crate::now_ts(start))
        .expect("connect() should queue INDUCTION");

    let mut driver = Conn::new(conn, socket);

    let (received_sender, received_receiver) =
        crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let (recycle_tx, recycle_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    spawn_reader(&driver, received_sender, recycle_rx);
    drain_outputs(&mut driver, crate::now_ts(start)).await;

    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let mut source = cfg.source_clock();
    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let handshake_started = Instant::now();
    let connect_deadline = handshake_started + crate::CONNECT_TIMEOUT;

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-compio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if crate::shutdown::past(stream_deadline) {
            break;
        }

        // Sleep until the next send is due; the reader keeps draining the
        // socket into the channel meanwhile. Two clocks gate that: SRT's
        // pacing and the application source, whichever is binding.
        let wait = if stats.connected {
            let pacing = driver.conn.time_until_send(crate::now_ts(start));
            Duration::from_micros(source.wait_micros(start.elapsed(), pacing)).min(crate::MAX_WAIT)
        } else {
            crate::MAX_WAIT
        };
        compio::time::sleep(wait).await;

        drain_sender_packets(&mut driver, &received_receiver, &recycle_tx, start);

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        drain_outputs(&mut driver, t).await;

        let was_connected = stats.connected;
        handle_sender_events(&cfg, &mut driver, &mut stats, &mut stream_deadline);
        if stats.connected && !was_connected {
            crate::HandshakePermit::settle(&mut permit, true);
        }

        // The top-of-loop deadline check passed some work ago; time has
        // moved since. Re-check at the send site or the connection keeps
        // streaming past its window, which shows up as offering more load
        // than was configured.
        if stats.connected && !crate::shutdown::past(stream_deadline) {
            // Sample the clock ONCE: this loop must drain only what pacing
            // says is due at instant `t`. Re-reading it per iteration makes
            // the condition self-fulfilling -- each `send_paced` awaits a
            // socket write that costs roughly one pacing interval, so `t`
            // advances far enough to permit the next packet and the loop
            // never exits. The task then never returns to the outer loop,
            // so it stops firing timers (no TLPKTDROP) and stops draining
            // received ACKs, and the send buffer grows to the full flow
            // window. That was ~12 MB per connection under overload.
            source.tick(start.elapsed());
            let now = crate::now_ts(start);
            send_paced_payload(&mut driver, &payload, now, &mut stats, &mut source).await;
        }
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
    stats.source = source.stats();
    stats.has_source = true;
    stats.datapath_queue = received_receiver.stats();
    stats
}

fn spawn_reader(
    driver: &Conn,
    received_sender: crate::queue::BoundedSender<(Vec<u8>, usize)>,
    recycle_rx: crate::queue::BoundedReceiver<Vec<u8>>,
) {
    let received_socket = driver.sock.clone();
    compio::runtime::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        loop {
            let BufResult(result, returned) = received_socket.recv(buffer).await;
            buffer = returned;
            let Ok(size) = result else {
                break;
            };
            let recycled = recycle_rx.try_recv().unwrap_or_else(|_| vec![0u8; 2048]);
            if !enqueue_received(&received_sender, &mut buffer, recycled, size) {
                break;
            }
        }
    })
    .detach();
}

fn drain_receiver_packets(
    driver: &mut Conn,
    received: &Received,
    recycle: &Recycle,
    start: Instant,
) {
    while let Ok((buffer, size)) = received.try_recv() {
        let now = crate::now_ts(start);
        let _ = driver.conn.feed_recv_buf(&buffer[..size], now);
        let _ = recycle.try_send(buffer);
    }
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
                eprintln!("[bench-compio] disconnected: {reason}");
                stats.torn_down |= !crate::is_ordered_close(&reason);
                *stream_deadline = Some(Instant::now());
            }
            ConnectionEvent::Error(message) => {
                eprintln!("[bench-compio] error: {message}");
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
    let socket = compio::net::UdpSocket::from_std(
        crate::bind_configured_socket(
            SocketAddr::from(([0, 0, 0, 0], listen_port)),
            cfg.sock_buf_bytes,
        )
        .expect("bind"),
    )
    .expect("register socket");

    let mut options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    cfg.encryption.apply_to(&mut options);
    let conn = SrtConnection::new_listener(options);
    let mut driver = Conn::new(conn, socket);
    drain_outputs(&mut driver, crate::now_ts(start)).await;

    let (received_sender, received_receiver) =
        crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let (recycle_tx, recycle_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let received_socket = driver.sock.clone();
    let _reader = compio::runtime::spawn(async move {
        let mut first = true;
        let mut buffer = vec![0u8; 2048];
        loop {
            let BufResult(result, returned) = received_socket.recv_from(buffer).await;
            buffer = returned;
            let Ok((size, addr)) = result else {
                break;
            };
            if first && received_socket.connect(addr).await.is_err() {
                break;
            }
            first = false;
            let recycled = recycle_rx.try_recv().unwrap_or_else(|_| vec![0u8; 2048]);
            if !enqueue_received(&received_sender, &mut buffer, recycled, size) {
                break;
            }
        }
    });

    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-compio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if crate::shutdown::past(stream_deadline) {
            break;
        }

        // The reader drains the socket continuously; this side only pays
        // for protocol maintenance once per MAX_WAIT.
        compio::time::sleep(crate::MAX_WAIT).await;

        drain_receiver_packets(&mut driver, &received_receiver, &recycle_tx, start);

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        drain_outputs(&mut driver, t).await;

        handle_receiver_events(&cfg, &mut driver, &mut stats, &mut stream_deadline);
    }

    record_receiver_stats(&driver, &mut stats);
    stats.datapath_queue = received_receiver.stats();
    stats
}

// ---------------------------------------------------------------------------
// #4: ReuseportMulti -- K deterministic acceptor threads, per-connection
// tasks for steady state.
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
    // mio/tokio/smol/monoio/glommio bug this avoids: cloning a
    // partially-built `Vec<Sender>` mid-loop hands early threads a
    // truncated view and panics on out-of-bounds indexing the first time
    // a handoff resolves to a later worker.
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
                    let rt = compio::runtime::Runtime::builder()
                        .build()
                        .expect("compio runtime");
                    rt.block_on(run_acceptor(
                        cfg,
                        worker_index,
                        start,
                        router,
                        all_senders,
                        rx,
                        telemetry,
                    ))
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
    eprintln!("{}", telemetry.report("compio"));
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-compio] pool receiver admitted no connections");
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
/// binding anything new: this is the same fix as the other four backends'
/// `run_acceptor`/`run_pool_acceptor`. Only a leg that actually needs to
/// relocate gets `compio::runtime::spawn`'d as its own task, via a
/// handoff.
struct AcceptorContext<'a> {
    cfg: &'a BenchConfig,
    worker_index: usize,
    start: Instant,
    admission: &'a srt_transport::AdmissionOptions,
    router: &'a crate::SharedWorkerRouter,
    senders: &'a [mpsc::Sender<WorkerMessage>],
    telemetry: &'a srt_transport::IngressTelemetry,
    tasks: &'a mut Vec<compio::runtime::JoinHandle<ConnStats>>,
}

fn drain_acceptor_inbox(
    inbox: &AddressedReceived,
    recycle: &Recycle,
    peers: &mut srt_transport::PeerTable,
    context: &AcceptorContext<'_>,
) {
    while let Ok((peer, buffer, size)) = inbox.try_recv() {
        peers.admit_and_forward(
            peer,
            &buffer[..size],
            crate::now_ts(context.start),
            context.admission,
            context.worker_index,
            context.senders,
            context.telemetry,
        );
        let _ = recycle.try_send(buffer);
    }
}

async fn maintain_acceptor_peers(
    peers: &mut srt_transport::PeerTable,
    listener: &compio::net::UdpSocket,
    start: Instant,
    stream_len: Duration,
) -> Vec<(SocketAddr, Option<GroupExtensionData>)> {
    let now = crate::now_ts(start);
    let mut relocate = Vec::new();
    for (peer, p) in peers.iter_direct_for_bench() {
        p.timers.fire_expired(now, &mut p.conn);
        let _ = drain_pending_outputs(&mut p.conn, &mut p.timers, listener, *peer).await;
        let mut newly_connected = false;
        while let Some(event) = p.conn.poll_event() {
            newly_connected |= p.apply_event(event);
        }
        if newly_connected {
            p.stream_deadline = Some(Instant::now() + stream_len);
            relocate.push((*peer, p.conn.peer_group_extension()));
        }
    }
    relocate
}

fn promotion_decision(
    context: &AcceptorContext<'_>,
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

fn apply_acceptor_promotions(
    context: &mut AcceptorContext<'_>,
    peers: &mut srt_transport::PeerTable,
    relocations: Vec<(SocketAddr, Option<GroupExtensionData>)>,
) {
    for (peer, extension) in relocations {
        match promotion_decision(context, peer, extension) {
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
                match promote_locally(context.cfg.port, context.cfg.sock_buf_bytes, peer, p.conn) {
                    Some(driver) => {
                        let cfg = context.cfg.clone();
                        let start = context.start;
                        context.tasks.push(compio::runtime::spawn(async move {
                            established_conn_task(driver, cfg, start).await
                        }));
                        context.telemetry.record_local_promotion();
                    }
                    None => eprintln!("[bench-compio] promote {peer}: failed"),
                }
            }
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
        let socket = match compio::net::UdpSocket::from_std(handoff.socket) {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!(
                    "[bench-compio] acceptor {}: handoff register {error}",
                    context.worker_index
                );
                continue;
            }
        };
        let driver = Conn::new(handoff.conn, socket);
        let cfg = context.cfg.clone();
        let start = context.start;
        context.tasks.push(compio::runtime::spawn(async move {
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
            eprintln!("[bench-compio] acceptor {worker_index}: bind {e}");
            return Vec::new();
        }
    };
    let listener = match compio::net::UdpSocket::from_std(std_listener) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-compio] acceptor {worker_index}: register listener {e}");
            return Vec::new();
        }
    };

    // Same reader-task + bounded-channel shape as receiver_task's proven
    // admission pattern above (see the module doc): compio has no
    // non-blocking recv, so a dedicated task recvs in a genuine `.await`
    // loop, decoupled from the maintenance tick, and hands datagrams to
    // the main loop through the channel. Never calls connect -- this
    // listener must stay unconnected to keep admitting every peer.
    let (inbox_tx, inbox_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let (recycle_tx, recycle_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let reader_listener = listener.clone();
    let _reader = compio::runtime::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        loop {
            let BufResult(result, returned) = reader_listener.recv_from(buffer).await;
            buffer = returned;
            let Ok((size, peer)) = result else {
                break;
            };
            let recycled = recycle_rx.try_recv().unwrap_or_else(|_| vec![0u8; 2048]);
            if !enqueue_addressed(&inbox_tx, peer, &mut buffer, recycled, size) {
                break;
            }
        }
    });

    let mut peers = srt_transport::PeerTable::new();
    let admission = cfg.admission_options(std::process::id(), cfg.cookie_routing);
    let mut tasks: Vec<compio::runtime::JoinHandle<ConnStats>> = Vec::new();
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);

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

            compio::time::sleep(TIMER_TICK).await;
            drain_acceptor_inbox(&inbox_rx, &recycle_tx, &mut peers, &context);
            let relocations =
                maintain_acceptor_peers(&mut peers, &listener, start, stream_len).await;
            apply_acceptor_promotions(&mut context, &mut peers, relocations);
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
    if let Some(first) = stats.first_mut() {
        first.datapath_queue.merge(inbox_rx.stats());
    }
    stats
}

async fn drain_pending_outputs(
    conn: &mut SrtConnection,
    timers: &mut srt_transport::ManualTimerStore,
    listener: &compio::net::UdpSocket,
    destination: SocketAddr,
) -> bool {
    use shiguredo_srt::ConnectionOutput;
    let now = crate::now_ts(Instant::now());
    let mut refused = false;
    while let Some(out) = conn.poll_output() {
        match out {
            ConnectionOutput::SendPacket(bytes) => {
                let BufResult(res, _buf) = listener.send_to(bytes, destination).await;
                if res.is_err() {
                    refused = true;
                }
            }
            other => timers.apply_output(&other, now),
        }
    }
    refused
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
            eprintln!("[bench-compio] relocate {peer}: bind {e}");
            return;
        }
    };
    if std_socket.connect(peer).is_err() {
        eprintln!("[bench-compio] relocate {peer}: connect failed");
        return;
    }
    let message = WorkerMessage::Handoff(Box::new(Handoff {
        socket: std_socket,
        conn: pending_conn,
    }));
    if senders[owner].send(message).is_err() {
        eprintln!("[bench-compio] relocate {peer}: owner {owner} channel closed");
    } else {
        telemetry.record_handoff();
    }
}

/// Steady-state loop for one promoted (already-connected) connection,
/// running as its own `compio::runtime::spawn`'d task -- compio's
/// ordinary task-per-connection idiom, same as the `PerPort` path above
/// (including its own reader-task + bounded channel, since a promoted
/// connection has no in-flight admission reader to lean on), just fed a
/// socket that admission already connected instead of discovering the
/// peer itself.
async fn established_conn_task(mut driver: Conn, cfg: BenchConfig, start: Instant) -> ConnStats {
    // `connected` is live state, used only for the loop-exit check below
    // (it flips false on Disconnected). The task is only ever spawned
    // post-promotion (Connected has already fired), so it was *always*
    // connected at some point -- reported unconditionally as `true` in
    // the final ConnStats, not this live flag (see tokio's identical
    // comment for the full reasoning).
    let mut connected = true;
    let mut torn_down = false;
    let mut data_events = 0u64;
    let stream_deadline = Instant::now() + Duration::from_secs_f64(cfg.duration_secs);
    let mut last_data_at = Instant::now();

    let (received_sender, received_receiver) =
        crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let (recycle_tx, recycle_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let received_socket = driver.sock.clone();
    let _reader = compio::runtime::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        loop {
            let BufResult(result, returned) = received_socket.recv(buffer).await;
            buffer = returned;
            let Ok(size) = result else {
                break;
            };
            let recycled = recycle_rx.try_recv().unwrap_or_else(|_| vec![0u8; 2048]);
            if !enqueue_received(&received_sender, &mut buffer, recycled, size) {
                break;
            }
        }
    });

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

        compio::time::sleep(crate::MAX_WAIT).await;

        while let Ok((buf, size)) = received_receiver.try_recv() {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf[..size], t);
            let _ = recycle_tx.try_send(buf);
        }

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        drain_outputs(&mut driver, t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::DataReceived { .. } => {
                    data_events += 1;
                    last_data_at = Instant::now();
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-compio] disconnected: {reason}");
                    torn_down |= !crate::is_ordered_close(&reason);
                    connected = false;
                }
                ConnectionEvent::Error(msg) => eprintln!("[bench-compio] error: {msg}"),
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
    stats.datapath_queue = received_receiver.stats();
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
    // default) keeps every socket on one thread, preserving this
    // strategy's role as the single-threaded control. Above 1 it scales,
    // which a strong sender needs: measured at 400 conns x 8 Mbps, one
    // listener thread delivers 13% with 1.6M kernel rcvbuf drops while two
    // deliver 99.9% with none.
    let threads = cfg.workers.clamp(1, k);
    let stats = crate::run_shards(threads, k, move |mine| {
        let cfg = cfg.clone();
        compio::runtime::Runtime::builder()
            .build()
            .expect("compio runtime")
            .block_on(async move {
                let mut tasks = Vec::new();
                for index in mine {
                    let cfg = cfg.clone();
                    tasks.push(compio::runtime::spawn(async move {
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
            })
    });

    let mut agg = Aggregate::new(agg_cfg);
    for s in stats {
        agg.add(s);
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-compio] shared pool admitted no connections");
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
    let sock = compio::net::UdpSocket::from_std(std_socket).expect("register pool socket");

    // compio has no non-blocking recv, so a reader task keeps one
    // owned-buffer recv in flight and feeds the maintenance loop, exactly
    // as the PerPort path does.
    let (inbox_tx, inbox_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let (recycle_tx, recycle_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let reader_sock = sock.clone();
    let _reader = compio::runtime::spawn(async move {
        let mut b = vec![0u8; 2048];
        loop {
            let BufResult(res, returned) = reader_sock.recv_from(b).await;
            b = returned;
            let Ok((n, peer)) = res else { break };
            let recycled = recycle_rx.try_recv().unwrap_or_else(|_| vec![0u8; 2048]);
            if !enqueue_addressed(&inbox_tx, peer, &mut b, recycled, n) {
                break;
            }
        }
    });

    let mut peers = srt_transport::PeerTable::new();
    // No SO_REUSEPORT group here, so nothing can rehash and there is
    // nowhere to forward to: one worker, cookie routing inert.
    let admission = cfg.admission_options(std::process::id(), false);
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
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

        compio::time::sleep(TIMER_TICK).await;
        while let Ok((peer, buf, size)) = inbox_rx.try_recv() {
            admit_one(&mut peers, &admission, peer, &buf[..size], start);
            let _ = recycle_tx.try_send(buf);
        }

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        for (peer, bytes) in outbound.drain(..) {
            let BufResult(_r, _b) = sock.send_to(bytes, peer).await;
        }
        // SharedPool never promotes, so a first Connected only starts the
        // stream clock -- which drain_events already did.
        peers.drain_events(stream_len, &mut connected);
        connected_streams = connected_streams.saturating_add(connected.len());
        if connected_streams >= cfg.logical_connection_count() {
            logical_run_deadline = Some(Instant::now() + stream_len);
        }
    }

    let mut stats = crate::collect_listener_stats(peers);
    if let Some(first) = stats.first_mut() {
        first.datapath_queue.merge(inbox_rx.stats());
    }
    stats
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
                    let rt = compio::runtime::Runtime::builder()
                        .build()
                        .expect("compio runtime");
                    rt.block_on(run_pool_worker(cfg, start, rx))
                })
                .expect("spawn worker"),
        );
    }

    let agg_cfg = cfg.clone();
    let acceptor_queue = {
        let router = router.clone();
        let senders = senders.clone();
        let rt = compio::runtime::Runtime::builder()
            .build()
            .expect("compio runtime");
        rt.block_on(run_single_acceptor(&cfg, start, &router, &senders))
    };
    // Workers stop when their tally is met; dropping the last senders
    // also unblocks any that never received one.
    drop(senders);

    let mut agg = Aggregate::new(agg_cfg);
    agg.datapath_queue.merge(acceptor_queue);
    for handle in handles {
        for s in handle.join().expect("worker panicked") {
            agg.add(s);
        }
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-compio] reuseport-single admitted no connections");
        std::process::exit(1);
    }
}

/// The single acceptor: admit every flow, route each to a worker as soon
/// as it is established.
fn drain_single_inbox(
    inbox: &AddressedReceived,
    recycle: &Recycle,
    peers: &mut srt_transport::PeerTable,
    admission: &srt_transport::AdmissionOptions,
    start: Instant,
) {
    while let Ok((peer, buffer, size)) = inbox.try_recv() {
        admit_one(peers, admission, peer, &buffer[..size], start);
        let _ = recycle.try_send(buffer);
    }
}

async fn flush_single_outbound(
    listener: &compio::net::UdpSocket,
    outbound: &mut Vec<(SocketAddr, Vec<u8>)>,
) {
    for (peer, bytes) in outbound.drain(..) {
        let BufResult(_result, _returned) = listener.send_to(bytes, peer).await;
    }
}

struct SingleAcceptorContext<'a> {
    cfg: &'a BenchConfig,
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
    stream_len: Duration,
    peers: &mut srt_transport::PeerTable,
    connected: &mut Vec<srt_transport::NewlyConnectedPeer>,
    routed: &mut usize,
) {
    peers.drain_events(stream_len, connected);
    for connected in std::mem::take(connected) {
        route_one_connected_peer(context, peers, connected, routed);
    }
}

async fn run_single_acceptor(
    cfg: &BenchConfig,
    start: Instant,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
) -> crate::queue::QueueStats {
    let Ok(std_socket) = srt_transport::bind_reuseport(cfg.port, cfg.sock_buf_bytes) else {
        eprintln!("[bench-compio] reuseport-single: bind failed");
        return crate::queue::QueueStats::default();
    };
    let Some(listener) = compio::net::UdpSocket::from_std(std_socket).ok() else {
        eprintln!("[bench-compio] reuseport-single: register failed");
        return crate::queue::QueueStats::default();
    };

    let (inbox_tx, inbox_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let (recycle_tx, recycle_rx) = crate::queue::bounded_channel(cfg.datapath_queue_capacity());
    let reader_sock = listener.clone();
    let _reader = compio::runtime::spawn(async move {
        let mut b = vec![0u8; 2048];
        loop {
            let BufResult(res, returned) = reader_sock.recv_from(b).await;
            b = returned;
            let Ok((n, peer)) = res else { break };
            let recycled = recycle_rx.try_recv().unwrap_or_else(|_| vec![0u8; 2048]);
            if !enqueue_addressed(&inbox_tx, peer, &mut b, recycled, n) {
                break;
            }
        }
    });

    let mut peers = srt_transport::PeerTable::new();
    // One acceptor means one owner for every handshake, so there is
    // nobody a stray CONCLUSION could need forwarding to.
    let admission = cfg.admission_options(std::process::id(), false);
    let telemetry = srt_transport::IngressTelemetry::new();
    let connect_deadline = Instant::now() + crate::CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let mut routed = 0usize;
    let mut outbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    let mut connected = Vec::new();
    let context = SingleAcceptorContext {
        cfg,
        router,
        senders,
        telemetry: &telemetry,
    };

    // Admission ends with the connect window: anything not established by
    // then never will be.
    while Instant::now() < connect_deadline && routed < cfg.connections {
        compio::time::sleep(TIMER_TICK).await;
        drain_single_inbox(&inbox_rx, &recycle_tx, &mut peers, &admission, start);

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        flush_single_outbound(&listener, &mut outbound).await;
        route_connected_peers(
            &context,
            stream_len,
            &mut peers,
            &mut connected,
            &mut routed,
        );
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
            "[bench-compio] reuseport-single: routed {} tuples into {} bond groups",
            router.active_tuple_count(),
            router.active_group_count()
        );
    }
    inbox_rx.stats()
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
                    let Some(sock) = compio::net::UdpSocket::from_std(std_socket).ok() else {
                        continue;
                    };
                    let driver = Conn::new(handoff.conn, sock);
                    let cfg2 = cfg.clone();
                    tasks.push(compio::runtime::spawn(async move {
                        established_conn_task(driver, cfg2, start).await
                    }));
                    received += 1;
                }
            }
        }
        if expected.is_some_and(|total| received >= total) {
            break;
        }
        compio::time::sleep(TIMER_TICK).await;
    }

    for task in tasks {
        if let Ok(s) = task.await {
            stats.push(s);
        }
    }
    stats
}
