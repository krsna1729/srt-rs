//! monoio adapter: task-per-connection via `monoio::spawn` — monoio is
//! thread-per-core with completion-based (owned-buffer) I/O and no
//! non-blocking try_recv, so each task owns its blocking recv. Native
//! io_uring timers live inside Conn.
//!
//! Receive shape (proven): ONE datagram per loop iteration via a blocking
//! timeout-wrapped recv, protocol maintenance after each. Timeouts only
//! ever fire when idle, so in-flight recvs are essentially never cancelled.
//!
//! Receive buffers are recycled when the recv completes (success or error).
//! On timeout the buffer is consumed by the dropped io_uring future and a
//! fresh one is allocated — but at steady state timeouts are rare, so the
//! common path is zero-alloc per recv. The `run_acceptor` reader task
//! additionally recycles buffers through a local pool instead of copying
//! with `.to_vec()` into the shared VecDeque.
//!
//! Known limitation, inherent to this shape rather than to any one ingress
//! mode: at several concurrent connections' combined throughput, one
//! recv-then-maintain iteration per task/tick can't always keep pace, so
//! SRT sees occasional loss and retransmits under load (observed on
//! `PerPort` itself, independent of reuseport/bonding -- e.g. 122
//! retransmits at 6 connections x 500kbps with no reuseport group
//! involved at all). Correctness holds regardless (SRT's own
//! retransmission delivers every byte -- `core_total` never trails
//! `pkt_sent`); this is a throughput/CPU cost, not a data-loss bug. mio,
//! tokio, and smol don't pay it because they can drain a burst
//! non-blockingly; monoio has no non-blocking recv to do that with.
//!
//! `Ingress::ReuseportMulti(K)` (#4) uses the identical fix and reasoning
//! as mio's `run_pool_acceptor`, tokio's `run_acceptor`, and smol's
//! `run_acceptor`: K OS threads, each already running its own monoio
//! runtime by design (monoio is inherently thread-per-core, so no extra
//! LocalSet-equivalent is needed -- `monoio::spawn` already spawns onto
//! the calling thread's runtime), gives `worker_index` stable thread
//! identity for the bond-affinity registry/handoff mechanism. Within each
//! acceptor thread, a connection only ever gets its own task -- and its
//! own socket -- if it actually needs to relocate to a different
//! acceptor's owner thread for bond affinity; the common case is serviced
//! straight off the shared listener socket by peer-address dispatch,
//! bypassing the `Conn` wrapper (whose `drain_outputs`/`send` assume a
//! connected socket) in favor of direct `SrtConnection` +
//! `srt_transport::ManualTimerStore` + `listener.send_to`. Promoting every
//! connection was measured (on mio, reproduced on tokio and smol) to cost
//! 5-6x listener CPU-sys time and nonzero retransmits: every new socket
//! joining the reuseport group can reroute some other still-pending
//! flow's next datagram to a different acceptor mid-handshake.
//!
//! THROUGHPUT AND `--promote-all` (measured; supersedes an earlier,
//! wrong "KNOWN LIMITATION" note here).
//!
//! With the default bond-only promotion, #4 under-delivers badly at
//! the default 8Mbps/conn -- at N=25 the listener took only 49.4% of what
//! the caller sent. That was blamed here on owned-buffer io_uring completion round-trips
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
//!   N=25, K=4, 8Mbps/conn:  49.4% -> 99.9% delivered, RTT 27.0ms -> 2.99ms
//!
//! Promotion is therefore not a uniform cost to be avoided: on a runtime
//! with a real task scheduler it is the point. (On mio -- a flat epoll
//! loop with no task model -- the same change measures
//! neutral-to-negative, which is why this is a flag and not a default.)
//!
//! Residual cost with promotion on: sec_a=4 retransmits, from
//! SO_REUSEPORT group churn rerouting flows mid-handshake. See
//! crates/srt-transport/tests/reuseport_rehash.rs and mio.rs's
//! ORPHAN_CONCLUSION_COUNT; cookie-keyed handshake routing is the
//! outstanding fix for that.

use crate::{Aggregate, BenchConfig, BondMode, ConnStats};
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, GroupExtensionData, SrtConnection};
use srt_transport::monoio_transport::Conn;
use srt_transport::{Handoff, WorkerMessage};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected peer may go without a datagram from its peer
/// before it's retired as stalled. Mirrors mio's/tokio's/smol's `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

async fn drain_outputs(driver: &mut Conn, now: shiguredo_srt::Timestamp) {
    super::report_drain_error("monoio", driver.drain_outputs(now).await);
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
    let sock = monoio::net::udp::UdpSocket::from_std(std_socket).ok()?;
    Some(Conn::new(conn, sock))
}

pub fn run(cfg: BenchConfig) {
    if cfg.mode == crate::Mode::Sender && cfg.egress == crate::Egress::SharedSocket {
        let start = Instant::now();
        let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .expect("monoio io_uring runtime");
        let stats = rt.block_on(run_shared_sender(&cfg, start));
        let mut agg = Aggregate::new(cfg);
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
        "monoio",
        run_reuseport_multi,
        run_shared_pool,
        run_reuseport_single,
    ) {
        return;
    }
    let start = Instant::now();

    let stats = crate::run_workers(&cfg, move |cfg, mine| {
        let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .expect("monoio io_uring runtime");
        rt.block_on(drive(cfg, mine, start))
    });

    let mut agg = Aggregate::new(cfg);
    for s in stats {
        agg.add(s);
    }
    agg.print(start);
    if !agg.any_connected {
        std::process::exit(1);
    }
}

async fn run_shared_sender(cfg: &BenchConfig, start: Instant) -> Vec<ConnStats> {
    let socket = monoio::net::udp::UdpSocket::from_std(
        crate::bind_shared_sender_socket(cfg.sock_buf_bytes).expect("bind shared sender socket"),
    )
    .expect("register shared sender socket");
    let indices = (0..cfg.connections).collect::<Vec<_>>();
    let mut sender = crate::SharedSender::new(cfg, &indices, start);
    let mut outbound = Vec::new();
    let mut buffer = vec![0_u8; 65_536];
    loop {
        sender.tick(cfg, &mut outbound);
        for (peer, packet) in outbound.drain(..) {
            let (result, _) = socket.send_to(packet, peer).await;
            result.expect("shared send_to");
        }
        if sender.done() {
            break;
        }
        match monoio::time::timeout(sender.next_wait(), socket.recv_from(buffer)).await {
            Ok((Ok((size, peer)), returned)) => {
                buffer = returned;
                sender.feed(peer, &buffer[..size]);
            }
            Ok((Err(_), returned)) => buffer = returned,
            Err(_) => buffer = vec![0_u8; 65_536],
        }
    }
    sender.finish()
}

/// Drive one worker's share of the connections on this thread's runtime.
async fn drive(cfg: BenchConfig, mine: Vec<usize>, start: Instant) -> Vec<crate::ConnStats> {
    let mut handles = Vec::with_capacity(mine.len());
    for i in mine {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(monoio::spawn(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, i, endpoint, start).await,
                crate::Mode::Receiver => receiver_task(c2, endpoint.port(), start).await,
            }
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        out.push(h.await);
    }
    out
}

async fn receive_sender_packet(
    driver: &mut Conn,
    connected: bool,
    buffer: &mut Vec<u8>,
    start: Instant,
) {
    let wait = if connected {
        Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
            .min(crate::MAX_WAIT)
    } else {
        crate::MAX_WAIT
    };
    match monoio::time::timeout(wait, driver.sock.recv(std::mem::take(buffer))).await {
        Ok((Ok(size), returned)) => {
            *buffer = returned;
            let now = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buffer[..size], now);
        }
        Ok((Err(_), returned)) => *buffer = returned,
        Err(_) => *buffer = vec![0u8; 2048],
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
                eprintln!("[bench-monoio] disconnected: {reason}");
                stats.torn_down |= !crate::is_ordered_close(&reason);
                *stream_deadline = Some(Instant::now());
            }
            ConnectionEvent::Error(message) => {
                eprintln!("[bench-monoio] error: {message}");
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

fn record_sender_stats(driver: &Conn, stats: &mut ConnStats) {
    if let Some(sender) = driver.conn.sender_stats() {
        stats.has_stats = true;
        stats.core_total = sender.total_sent;
        stats.secondary_a = sender.total_retransmits;
        stats.secondary_b = sender.packets_in_loss_list as u64;
    }
}

async fn sender_task(
    cfg: BenchConfig,
    index: usize,
    endpoint: SocketAddr,
    start: Instant,
) -> ConnStats {
    let socket = monoio::net::udp::UdpSocket::bind("0.0.0.0:0").expect("bind");
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
    let connect_deadline = start + crate::CONNECT_TIMEOUT;
    let mut recv_buf = vec![0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-monoio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if crate::shutdown::past(stream_deadline) {
            break;
        }

        receive_sender_packet(&mut driver, stats.connected, &mut recv_buf, start).await;

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        drain_outputs(&mut driver, t).await;

        handle_sender_events(&cfg, &mut driver, &mut stats, &mut stream_deadline);

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
            let now = crate::now_ts(start);
            send_paced_payload(&mut driver, &payload, now, &mut stats).await;
        }
    }

    // Ordered close at the protocol level: tell the peer we are done
    // instead of just vanishing. `disconnect` emits an SRT SHUTDOWN,
    // which on the listener flushes its receive buffer *ignoring TSBPD*
    // and raises `Disconnected { peer shutdown }` -- so pending data is
    // delivered rather than aged out, and the listener learns the stream
    // ended instead of inferring it from five seconds of silence.
    let t = crate::now_ts(start);
    driver.conn.disconnect(t);
    drain_outputs(&mut driver, t).await;
    record_sender_stats(&driver, &mut stats);
    stats
}

async fn receiver_task(cfg: BenchConfig, listen_port: u16, start: Instant) -> ConnStats {
    let socket = monoio::net::udp::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
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
    let mut recv_buf = vec![0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-monoio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if crate::shutdown::past(stream_deadline) {
            break;
        }

        match monoio::time::timeout(crate::MAX_WAIT, driver.sock.recv_from(recv_buf)).await {
            Ok((Ok((n, addr)), returned)) => {
                recv_buf = returned;
                if peer.is_none() {
                    if let Err(e) = driver.sock.connect(addr).await {
                        eprintln!("[bench-monoio] connect to peer failed: {e}");
                    } else {
                        peer = Some(addr);
                    }
                }
                let t = crate::now_ts(start);
                let _ = driver.conn.feed_recv_buf(&recv_buf[..n], t);
            }
            Ok((Err(_), returned)) => recv_buf = returned,
            Err(_) => recv_buf = vec![0u8; 2048],
        }

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        drain_outputs(&mut driver, t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::Connected => {
                    stats.connected = true;
                    if cfg.verbose() {
                        println!("CONNECTED");
                    }
                    // Set once. A duplicate `Connected` -- a re-completed
                    // handshake under load -- would otherwise push the
                    // deadline out another full duration, and the run
                    // would quietly offer more than the configured load.
                    if stream_deadline.is_none() {
                        stream_deadline =
                            Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                    }
                }
                ConnectionEvent::DataReceived { .. } => {
                    stats.data_events += 1;
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-monoio] disconnected: {reason}");
                    stats.torn_down |= !crate::is_ordered_close(&reason);
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-monoio] error: {msg}");
                }
                _ => {}
            }
        }
    }

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
// #4: ReuseportMulti -- K deterministic acceptor threads, per-connection
// tasks for steady state.
// ---------------------------------------------------------------------------

/// Datagrams handed from the reader task to the maintenance loop; see
/// `run_acceptor`'s `inbox`. The `usize` is the valid byte count; the
/// `Vec<u8>` is the full recv buffer, recycled via the `Recycle` pool.
type Inbox = Rc<RefCell<VecDeque<(SocketAddr, Vec<u8>, usize)>>>;
type Recycle = Rc<RefCell<Vec<Vec<u8>>>>;

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
    // mio/tokio/smol bug this avoids: cloning a partially-built
    // `Vec<Sender>` mid-loop hands early threads a truncated view and
    // panics on out-of-bounds indexing the first time a handoff resolves
    // to a later worker.
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
                    let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                        .enable_timer()
                        .build()
                        .expect("monoio io_uring runtime");
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
    eprintln!("{}", telemetry.report("monoio"));
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-monoio] pool receiver admitted no connections");
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
/// binding anything new: this is the same fix as mio's `run_pool_acceptor`,
/// tokio's `run_acceptor`, and smol's `run_acceptor`. Only a leg that
/// actually needs to relocate gets `monoio::spawn`'d as its own task, via
/// a handoff.
///
/// Admission follows the same proven single-datagram-per-iteration shape
/// as `receiver_task` above -- monoio has no non-blocking try_recv, so
/// each tick attempts at most one `recv_from`, bounded by `TIMER_TICK` so
/// peer maintenance (timers, relocation checks, terminal-state checks)
/// still runs promptly even when nothing arrives.
struct AcceptorContext<'a> {
    cfg: &'a BenchConfig,
    worker_index: usize,
    start: Instant,
    admission: &'a srt_transport::AdmissionOptions,
    router: &'a crate::SharedWorkerRouter,
    senders: &'a [mpsc::Sender<WorkerMessage>],
    telemetry: &'a srt_transport::IngressTelemetry,
    tasks: &'a mut Vec<monoio::task::JoinHandle<ConnStats>>,
}

fn drain_acceptor_inbox(
    inbox: &Inbox,
    recycle: &Recycle,
    peers: &mut srt_transport::PeerTable,
    context: &AcceptorContext<'_>,
) {
    while let Some((peer, buf, size)) = inbox.borrow_mut().pop_front() {
        peers.admit_and_forward(
            peer,
            &buf[..size],
            crate::now_ts(context.start),
            context.admission,
            context.worker_index,
            context.senders,
            context.telemetry,
        );
        recycle.borrow_mut().push(buf);
    }
}

async fn maintain_acceptor_peers(
    peers: &mut srt_transport::PeerTable,
    listener: &monoio::net::udp::UdpSocket,
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
                        context.tasks.push(monoio::spawn(async move {
                            established_conn_task(driver, cfg, start).await
                        }));
                        context.telemetry.record_local_promotion();
                    }
                    None => eprintln!("[bench-monoio] promote {peer}: failed"),
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
        match monoio::net::udp::UdpSocket::from_std(handoff.socket) {
            Ok(socket) => {
                let driver = Conn::new(handoff.conn, socket);
                let cfg = context.cfg.clone();
                let start = context.start;
                context.tasks.push(monoio::spawn(async move {
                    established_conn_task(driver, cfg, start).await
                }));
            }
            Err(error) => eprintln!(
                "[bench-monoio] acceptor {}: handoff register {error}",
                context.worker_index
            ),
        }
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
            eprintln!("[bench-monoio] acceptor {worker_index}: bind {e}");
            return Vec::new();
        }
    };
    let listener = match monoio::net::udp::UdpSocket::from_std(std_listener) {
        Ok(s) => Rc::new(s),
        Err(e) => {
            eprintln!("[bench-monoio] acceptor {worker_index}: register listener {e}");
            return Vec::new();
        }
    };

    // monoio has no non-blocking try_recv, so a single `recv_from` bounded
    // by `TIMER_TICK` in the main loop can only ever absorb one datagram
    // per tick -- fine for one connection (PerPort), but once several
    // connections share this listener socket their combined arrival rate
    // easily exceeds that, and the excess is dropped by the OS receive
    // queue before SRT ever sees it (measured: 6 conns at ~3Mbps combined
    // lost ~20% of packets with the naive one-recv-per-tick shape, with
    // SRT's own loss tracking blind to it since the drops happen below
    // the socket). The fix: a dedicated reader task recvs in a tight loop
    // (as fast as the kernel delivers, decoupled from the maintenance
    // tick) and hands datagrams to the main loop through a shared local
    // queue -- `Rc<RefCell<..>>` is safe here because the push/pop are
    // both synchronous (never held across an `.await`), so there's no
    // reentrancy hazard between this task and the maintenance loop below
    // even though both run cooperatively on the same thread.
    let inbox: Inbox = Rc::new(RefCell::new(VecDeque::new()));
    let recycle: Recycle = Rc::new(RefCell::new(Vec::new()));
    let reader_listener = listener.clone();
    let reader_inbox = inbox.clone();
    let reader_recycle = recycle.clone();
    let _reader_task = monoio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (res, returned) = reader_listener.recv_from(buf).await;
            buf = returned;
            match res {
                Ok((n, peer)) => {
                    let recycled = reader_recycle
                        .borrow_mut()
                        .pop()
                        .unwrap_or_else(|| vec![0u8; 2048]);
                    let owned = std::mem::replace(&mut buf, recycled);
                    let mut q = reader_inbox.borrow_mut();
                    q.push_back((peer, owned, n));
                    while q.len() > 4096 {
                        if let Some((_, dropped, _)) = q.pop_front() {
                            reader_recycle.borrow_mut().push(dropped);
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut peers = srt_transport::PeerTable::new();
    let admission = cfg.admission_options(std::process::id(), cfg.cookie_routing);
    let mut tasks: Vec<monoio::task::JoinHandle<ConnStats>> = Vec::new();
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

            monoio::time::sleep(TIMER_TICK).await;
            drain_acceptor_inbox(&inbox, &recycle, &mut peers, &context);

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
        stats.push(task.await);
    }
    stats
}

async fn drain_pending_outputs(
    conn: &mut SrtConnection,
    timers: &mut srt_transport::ManualTimerStore,
    listener: &monoio::net::udp::UdpSocket,
    destination: SocketAddr,
) -> bool {
    use shiguredo_srt::ConnectionOutput;
    let now = crate::now_ts(Instant::now());
    let mut refused = false;
    while let Some(out) = conn.poll_output() {
        match out {
            ConnectionOutput::SendPacket(bytes) => {
                let (res, _buf) = listener.send_to(bytes, destination).await;
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
            eprintln!("[bench-monoio] relocate {peer}: bind {e}");
            return;
        }
    };
    if std_socket.connect(peer).is_err() {
        eprintln!("[bench-monoio] relocate {peer}: connect failed");
        return;
    }
    let message = WorkerMessage::Handoff(Box::new(Handoff {
        socket: std_socket,
        conn: pending_conn,
    }));
    if senders[owner].send(message).is_err() {
        eprintln!("[bench-monoio] relocate {peer}: owner {owner} channel closed");
    } else {
        telemetry.record_handoff();
    }
}

/// Steady-state loop for one promoted (already-connected) connection,
/// running as its own `monoio::spawn`'d task -- monoio's ordinary
/// task-per-connection idiom, same as the `PerPort` path above, just fed
/// a socket that admission already connected instead of discovering the
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
    let mut recv_buf = vec![0u8; 2048];

    loop {
        let now = Instant::now();
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

        match monoio::time::timeout(crate::MAX_WAIT, driver.sock.recv(recv_buf)).await {
            Ok((Ok(n), returned)) => {
                recv_buf = returned;
                let t = crate::now_ts(start);
                let _ = driver.conn.feed_recv_buf(&recv_buf[..n], t);
            }
            Ok((Err(_), returned)) => recv_buf = returned,
            Err(_) => recv_buf = vec![0u8; 2048],
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
                    eprintln!("[bench-monoio] disconnected: {reason}");
                    torn_down |= !crate::is_ordered_close(&reason);
                    connected = false;
                }
                ConnectionEvent::Error(msg) => eprintln!("[bench-monoio] error: {msg}"),
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
    // default) keeps every socket on one thread, preserving this
    // strategy's role as the single-threaded control. Above 1 it scales,
    // which a strong sender needs: measured at 400 conns x 8 Mbps, one
    // listener thread delivers 13% with 1.6M kernel rcvbuf drops while two
    // deliver 99.9% with none.
    let threads = cfg.workers.clamp(1, k);
    let stats = crate::run_shards(threads, k, move |mine| {
        let cfg = cfg.clone();
        let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .expect("monoio io_uring runtime");
        rt.block_on(async move {
            let mut tasks = Vec::new();
            for index in mine {
                let cfg = cfg.clone();
                tasks.push(monoio::spawn(async move {
                    serve_pool_socket(cfg, index, start).await
                }));
            }
            let mut all = Vec::new();
            for t in tasks {
                all.extend(t.await);
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
        eprintln!("[bench-monoio] shared pool admitted no connections");
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
    let sock = monoio::net::udp::UdpSocket::from_std(std_socket).expect("register pool socket");

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
    let mut recv_buf = vec![0u8; 2048];

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

        match monoio::time::timeout(TIMER_TICK, sock.recv_from(recv_buf)).await {
            Ok((Ok((n, peer)), returned)) => {
                recv_buf = returned;
                admit_one(&mut peers, &admission, peer, &recv_buf[..n], start);
            }
            Ok((Err(_), returned)) => recv_buf = returned,
            Err(_) => recv_buf = vec![0u8; 2048],
        }

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        for (peer, bytes) in outbound.drain(..) {
            let (_r, _b) = sock.send_to(bytes, peer).await;
        }
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
                    let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                        .enable_timer()
                        .build()
                        .expect("monoio io_uring runtime");
                    rt.block_on(run_pool_worker(cfg, start, rx))
                })
                .expect("spawn worker"),
        );
    }

    let agg_cfg = cfg.clone();
    {
        let router = router.clone();
        let senders = senders.clone();
        let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .enable_timer()
            .build()
            .expect("monoio io_uring runtime");
        rt.block_on(run_single_acceptor(&cfg, start, &router, &senders));
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
        eprintln!("[bench-monoio] reuseport-single admitted no connections");
        std::process::exit(1);
    }
}

/// The single acceptor: admit every flow, route each to a worker as soon
/// as it is established.
async fn run_single_acceptor(
    cfg: &BenchConfig,
    start: Instant,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let Ok(std_socket) = srt_transport::bind_reuseport(cfg.port, cfg.sock_buf_bytes) else {
        eprintln!("[bench-monoio] reuseport-single: bind failed");
        return;
    };
    let Some(listener) = monoio::net::udp::UdpSocket::from_std(std_socket).ok() else {
        eprintln!("[bench-monoio] reuseport-single: register failed");
        return;
    };

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
    let mut recv_buf = vec![0u8; 2048];

    while Instant::now() < connect_deadline && routed < cfg.connections {
        match monoio::time::timeout(TIMER_TICK, listener.recv_from(recv_buf)).await {
            Ok((Ok((n, peer)), returned)) => {
                recv_buf = returned;
                admit_one(&mut peers, &admission, peer, &recv_buf[..n], start);
            }
            Ok((Err(_), returned)) => recv_buf = returned,
            Err(_) => recv_buf = vec![0u8; 2048],
        }

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        for (peer, bytes) in outbound.drain(..) {
            let (_r, _b) = listener.send_to(bytes, peer).await;
        }
        peers.drain_events(stream_len, &mut connected);

        let newly = std::mem::take(&mut connected);
        for connected in newly {
            let peer = connected.representative_peer;
            let group = peers
                .logical_peer(&connected.logical_peer)
                .and_then(|logical| logical.group_affinity());
            let Some(srt_transport::RemovedLogicalPeer::Direct(entry)) =
                peers.remove(connected.logical_peer)
            else {
                continue;
            };
            // Unlike #4, the router is consulted for *every* connection:
            // routing each one to a worker is the whole strategy, not a
            // bond-affinity special case.
            let owner = match router.lock() {
                Ok(mut router) => {
                    router.assign(peer, group, srt_lifecycle::RoutingMode::LeastTuples)
                }
                Err(_) => 0,
            };
            let Ok(socket) = srt_transport::bind_reuseport(cfg.port, cfg.sock_buf_bytes) else {
                continue;
            };
            if socket.connect(peer).is_err() {
                continue;
            }
            let message = WorkerMessage::Handoff(Box::new(srt_transport::Handoff {
                socket,
                conn: entry.connection,
            }));
            if senders[owner].send(message).is_ok() {
                telemetry.record_handoff();
                routed += 1;
            }
        }
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
            "[bench-monoio] reuseport-single: routed {} tuples into {} bond groups",
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
                    let Some(sock) = monoio::net::udp::UdpSocket::from_std(std_socket).ok() else {
                        continue;
                    };
                    let driver = Conn::new(handoff.conn, sock);
                    let cfg2 = cfg.clone();
                    tasks.push(monoio::spawn(async move {
                        established_conn_task(driver, cfg2, start).await
                    }));
                    received += 1;
                }
            }
        }
        if expected.is_some_and(|total| received >= total) {
            break;
        }
        monoio::time::sleep(TIMER_TICK).await;
    }

    for task in tasks {
        stats.push(task.await);
    }
    stats
}
