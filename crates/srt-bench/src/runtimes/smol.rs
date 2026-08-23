//! smol adapter: task-per-connection on an `async_executor::LocalExecutor`
//! (smol's own block_on executor requires Send; Conn's native timers are
//! !Send). Native `smol::Timer` timers live inside Conn.
//!
//! `Ingress::ReuseportMulti(K)` (#4) uses the identical fix and reasoning
//! as mio's `run_pool_acceptor` and tokio's `run_acceptor`: K independent
//! OS threads, each running its own `LocalExecutor`, gives `worker_index`
//! stable thread identity for the bond-affinity registry/handoff
//! mechanism. Within each acceptor thread, a connection only ever gets its
//! own task -- and its own socket -- if it actually needs to relocate to a
//! different acceptor's owner thread for bond affinity; the common case is
//! serviced straight off the shared listener socket by peer-address
//! dispatch, same as `SharedPool`. Promoting every connection was measured
//! (on mio, then reproduced on tokio) to cost 5-6x listener CPU-sys time
//! and nonzero retransmits: every new socket joining the reuseport group
//! can reroute some other still-pending flow's next datagram to a
//! different acceptor mid-handshake.
//!
//! THROUGHPUT AND `--promote-all` (measured; supersedes an earlier,
//! wrong "KNOWN LIMITATION" note here).
//!
//! With the default bond-only promotion, #4 under-delivers badly at
//! bench.sh's 8Mbps/conn: at N=25 the listener received 75433 of 152450
//! packets sent (~50%), and at N=150, 359651 of 969994 (~37%, RTT 419ms).
//! That was previously attributed to `async-io`'s per-packet overhead and
//! to #4 concentrating load on K threads. Both explanations were wrong:
//! raising K changes nothing (K=2..25 measured identical), and smol's own
//! `PerPort` path is flawless at the same load.
//!
//! The actual cause is this file's shared-listener design: every live
//! peer is serviced from one worker's sequential per-tick maintenance
//! loop, so the executor never gets to interleave them. Giving each
//! connection its own connected socket and its own task
//! (`--promote-all=on`) removes the bottleneck outright:
//!
//!   N=25:  ~50% -> 99.99% delivered (151648/151662), RTT 1.1 -> 1.4ms
//!   N=150: ~37% -> 96.8% delivered (882614/912147),  RTT 419 -> 68ms
//!
//! So promotion is not a uniform cost to be avoided -- on a runtime with
//! a real task scheduler it is the whole point, and it is worth roughly
//! 2x here. (On mio, which is a flat epoll loop with no task model, the
//! same change measures neutral-to-negative. The right default is
//! therefore runtime-dependent, which is why it is a flag.)
//!
//! Residual cost at N=150 with promotion on: sec_a=58 retransmits, from
//! reuseport-group churn rerouting flows mid-handshake. See
//! crates/srt-transport/tests/reuseport_rehash.rs and mio.rs's
//! ORPHAN_CONCLUSION_COUNT -- cookie-keyed handshake routing is the fix
//! for that, and is not implemented yet.

use crate::{Aggregate, BondMode, ConnStats, LossConfig};
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, GroupExtensionData, GroupType, SRTGROUP_MASK, SrtConnection,
};
use srt_transport::smol_transport::{Conn, UdpSocket};
use srt_transport::{Handoff, WorkerMessage};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected peer may go without a datagram from its peer
/// before it's retired as stalled. Mirrors mio's/tokio's `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

/// Give one established connection its own connected socket, so the
/// kernel matches its packets by exact 4-tuple and it can be driven by an
/// independent task instead of the shared per-peer maintenance loop.
/// Returns `None` if the socket could not be created.
fn promote_locally(
    port: u16,
    sock_buf_bytes: usize,
    peer: SocketAddr,
    conn: SrtConnection,
) -> Option<Conn> {
    let std_socket = srt_transport::bind_reuseport(port, sock_buf_bytes).ok()?;
    std_socket.connect(peer).ok()?;
    let sock = UdpSocket::new(std_socket).ok()?;
    Some(Conn::new(conn, sock))
}

pub fn run(cfg: LossConfig) {
    if cfg.mode == crate::Mode::Receiver
        && cfg.connections > 1
        && let crate::Ingress::ReuseportMulti(k) = cfg.ingress
        && k > 1
    {
        return run_reuseport_multi(cfg, k);
    }
    smol::block_on(drive(cfg));
}

async fn drive(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-smol] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let ex = async_executor::LocalExecutor::new();
    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(ex.spawn(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, i, endpoint, start).await,
                crate::Mode::Receiver => receiver_task(c2, endpoint.port(), start).await,
            }
        }));
    }

    // Drive the executor until every task has reported its result.
    let mut agg = Aggregate::new(cfg.clone());
    ex.run(async {
        for h in handles {
            agg.add(h.await);
        }
    })
    .await;
    agg.print(start);

    if !agg.any_connected {
        std::process::exit(1);
    }
}

/// Bond exercise: connections 2g/2g+1 (for g in 0..bond_pairs) share a
/// group id, so a run can prove the reuseport receiver's registry/handoff
/// path actually fires. Sender-only -- the listener learns the group (and
/// its type) from the caller's handshake extension.
fn bond_extension_for(cfg: &LossConfig, i: usize) -> Option<GroupExtensionData> {
    if cfg.bond_mode == BondMode::None || i >= cfg.bond_pairs * 2 {
        return None;
    }
    let group_type = match cfg.bond_mode {
        BondMode::Broadcast => GroupType::Broadcast,
        BondMode::Backup => GroupType::Backup,
        BondMode::None => unreachable!("checked above"),
    };
    Some(GroupExtensionData {
        group_id: SRTGROUP_MASK | ((i / 2) as u32 + 1),
        group_type,
        flags: 0,
        weight: 0,
    })
}

async fn sender_task(
    cfg: LossConfig,
    index: usize,
    endpoint: SocketAddr,
    start: Instant,
) -> ConnStats {
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).expect("bind");
    socket.get_ref().connect(endpoint).expect("connect");

    let options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        max_bandwidth_bytes_per_sec: Some(cfg.bitrate_bps / 8),
        group_extension: bond_extension_for(&cfg, index),
        ..Default::default()
    };
    let mut conn = SrtConnection::new_caller(options);
    conn.connect(crate::now_ts(start))
        .expect("connect() should queue INDUCTION");

    let mut driver = Conn::new(conn, socket);
    driver.drain_outputs(crate::now_ts(start)).await;

    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = start + crate::INTEROP_CONNECT_TIMEOUT;
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-smol] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        let wait = if stats.connected {
            Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
                .min(crate::MAX_WAIT)
        } else {
            crate::MAX_WAIT
        };
        let block_for = wait.saturating_sub(crate::TAIL_SPIN);
        if block_for > Duration::ZERO {
            driver
                .recv_with_timeout(&mut buf, block_for, crate::now_ts(start))
                .await;
        }

        while let Some(res) = driver.try_recv(&mut buf) {
            match res {
                Ok(n) => {
                    let t = crate::now_ts(start);
                    let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                }
                Err(_) => break,
            }
        }

        let t = crate::now_ts(start);
        driver.fire_expired();
        driver.drain_outputs(t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::Connected => {
                    stats.connected = true;
                    if cfg.verbose() {
                        println!("CONNECTED");
                    }
                    stream_deadline =
                        Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-smol] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-smol] error: {msg}");
                }
                _ => {}
            }
        }

        if stats.connected {
            loop {
                let t = crate::now_ts(start);
                if driver.send_paced(&payload, t).await.is_err() {
                    break;
                }
                stats.data_events += 1;
            }
        }
    }

    if let Some(s) = driver.conn.sender_stats() {
        stats.has_stats = true;
        stats.core_total = s.total_sent;
        stats.secondary_a = s.total_retransmits as u64;
        stats.secondary_b = s.packets_in_loss_list as u64;
    }
    stats
}

async fn receiver_task(cfg: LossConfig, listen_port: u16, start: Instant) -> ConnStats {
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port))).expect("bind");

    let options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    let conn = SrtConnection::new_listener(options);
    let mut driver = Conn::new(conn, socket);
    driver.drain_outputs(crate::now_ts(start)).await;

    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let mut peer: Option<SocketAddr> = None;
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-smol] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        if peer.is_none() {
            // Unconnected phase: first datagram reveals the caller; connect
            // before anything else (drain_outputs uses connected send).
            let recv_fut = async { driver.sock.recv_from(&mut buf).await.ok() };
            let timer_fut = async {
                smol::Timer::after(crate::MAX_WAIT).await;
                None
            };
            if let Some((n, addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
                if driver.sock.get_ref().connect(addr).is_err() {
                    eprintln!("[bench-smol] connect to peer failed");
                    continue;
                }
                peer = Some(addr);
                let t = crate::now_ts(start);
                let _ = driver.conn.feed_recv_buf(&buf[..n], t);
            }
        } else {
            // Bounded wait keeps the task from busy-spinning when idle.
            driver
                .recv_with_timeout(&mut buf, crate::MAX_WAIT, crate::now_ts(start))
                .await;

            while let Some(res) = driver.try_recv(&mut buf) {
                match res {
                    Ok(n) => {
                        let t = crate::now_ts(start);
                        let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                    }
                    Err(_) => break,
                }
            }

            let t = crate::now_ts(start);
            driver.fire_expired();
            driver.drain_outputs(t).await;
        }

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::Connected => {
                    stats.connected = true;
                    if cfg.verbose() {
                        println!("CONNECTED");
                    }
                    stream_deadline =
                        Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                }
                ConnectionEvent::DataReceived { .. } => {
                    stats.data_events += 1;
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-smol] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-smol] error: {msg}");
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

fn run_reuseport_multi(cfg: LossConfig, k: usize) {
    let worker_count = k.min(cfg.connections);
    let start = Instant::now();
    println!("LISTENING");
    let router: crate::SharedWorkerRouter =
        Arc::new(Mutex::new(srt_lifecycle::WorkerRouter::new(worker_count)));
    // One set of counters for every acceptor thread; see
    // `srt_transport::IngressTelemetry`.
    let telemetry = Arc::new(srt_transport::IngressTelemetry::new());

    // All channels exist before any thread spawns -- see the identical
    // mio/tokio bug this avoids: cloning a partially-built `Vec<Sender>`
    // mid-loop hands early threads a truncated view and panics on
    // out-of-bounds indexing the first time a handoff resolves to a later
    // worker.
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
                    let ex = async_executor::LocalExecutor::new();
                    smol::block_on(ex.run(run_acceptor(
                        cfg,
                        worker_index,
                        start,
                        router,
                        all_senders,
                        rx,
                        telemetry,
                        &ex,
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
    eprintln!("{}", telemetry.report("smol"));
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-smol] pool receiver admitted no connections");
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
/// and tokio's `run_acceptor` (see their doc comments for the full
/// explanation). Only a leg that actually needs to relocate gets spawned
/// as its own task on the owner's executor, via a handoff.
async fn run_acceptor(
    cfg: LossConfig,
    worker_index: usize,
    start: Instant,
    router: crate::SharedWorkerRouter,
    senders: Vec<mpsc::Sender<WorkerMessage>>,
    handoffs: mpsc::Receiver<WorkerMessage>,
    telemetry: Arc<srt_transport::IngressTelemetry>,
    ex: &async_executor::LocalExecutor<'_>,
) -> Vec<ConnStats> {
    let std_listener = match srt_transport::bind_reuseport(cfg.port, cfg.sock_buf_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-smol] acceptor {worker_index}: bind {e}");
            return Vec::new();
        }
    };
    let listener = match UdpSocket::new(std_listener) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-smol] acceptor {worker_index}: register listener {e}");
            return Vec::new();
        }
    };

    let promotion = cfg.promotion;
    let mut peers = srt_transport::PeerTable::new();
    let admission = srt_transport::AdmissionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        cookie_routing: cfg.cookie_routing,
    };
    let mut tasks: Vec<async_executor::Task<ConnStats>> = Vec::new();
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut buf = [0u8; 2048];

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        // Vacuously true while nothing exists yet, so an acceptor that
        // never admits anything still exits once the connect window
        // closes instead of hanging on an empty guard.
        let all_terminal = peers.all_terminal(now, connect_deadline, IDLE_GRACE);
        if now >= connect_deadline && all_terminal {
            break;
        }

        let recv_fut = async { listener.recv_from(&mut buf).await.ok() };
        let timer_fut = async {
            smol::Timer::after(TIMER_TICK).await;
            None
        };
        if let Some((n, peer)) = futures_lite::future::or(recv_fut, timer_fut).await {
            peers.admit_and_forward(
                peer,
                &buf[..n],
                crate::now_ts(start),
                &admission,
                worker_index,
                &senders,
                &telemetry,
            );
            loop {
                match listener.get_ref().recv_from(&mut buf) {
                    Ok((n, peer)) => peers.admit_and_forward(
                        peer,
                        &buf[..n],
                        crate::now_ts(start),
                        &admission,
                        worker_index,
                        &senders,
                        &telemetry,
                    ),
                    Err(_) => break,
                }
            }
        }

        // Drive every tracked peer: fire timers, drain outputs (always
        // via the shared listener's unconnected `send_to` -- a peer here
        // never gets its own socket), and react to protocol events. On a
        // peer's *first* Connected, decide once whether it needs to
        // relocate.
        let t = crate::now_ts(start);
        let mut relocate: Vec<(SocketAddr, Option<GroupExtensionData>)> = Vec::new();
        for (peer, p) in peers.iter_mut() {
            p.timers.fire_expired(t, &mut p.conn);
            let _ = drain_pending_outputs(&mut p.conn, &mut p.timers, &listener, *peer).await;
            let mut newly_connected = false;
            while let Some(ev) = p.conn.poll_event() {
                match ev {
                    ConnectionEvent::Connected => {
                        if p.stream_deadline.is_none() {
                            newly_connected = true;
                        }
                        p.connected = true;
                    }
                    ConnectionEvent::DataReceived { .. } => {
                        p.data_events += 1;
                        p.last_data_at = Instant::now();
                    }
                    ConnectionEvent::Disconnected { .. } => {
                        p.connected = false;
                    }
                    _ => {}
                }
            }
            if newly_connected {
                p.stream_deadline = Some(Instant::now() + stream_len);
                relocate.push((*peer, p.conn.peer_group_extension()));
            }
        }
        for (peer, extension) in relocate {
            // The ladder itself is shared policy -- see
            // `srt_lifecycle::decide_promotion`. Only the actions below
            // are this runtime's business.
            let decision = {
                let group = extension.map(|extension| srt_lifecycle::GroupAffinity {
                    group_id: extension.group_id,
                    stream_id: None,
                    extension,
                });
                match router.lock() {
                    Ok(mut router) => srt_lifecycle::decide_promotion(
                        promotion,
                        peer,
                        group,
                        worker_index,
                        &mut router,
                        srt_lifecycle::RoutingMode::LeastTuples,
                    ),
                    // Poisoned: leave the connection where it is rather
                    // than stall admission on a dead lock.
                    Err(_) => srt_lifecycle::PromotionDecision::StayOnListener,
                }
            };

            match decision {
                srt_lifecycle::PromotionDecision::StayOnListener => {}
                srt_lifecycle::PromotionDecision::RelocateTo(owner) => {
                    let Some(p) = peers.remove(&peer) else {
                        continue;
                    };
                    relocate_to_owner(
                        cfg.port,
                        cfg.sock_buf_bytes,
                        peer,
                        p.conn,
                        owner,
                        &senders,
                        &telemetry,
                    );
                }
                srt_lifecycle::PromotionDecision::PromoteHere => {
                    let Some(p) = peers.remove(&peer) else {
                        continue;
                    };
                    match promote_locally(cfg.port, cfg.sock_buf_bytes, peer, p.conn) {
                        Some(driver) => {
                            let cfg2 = cfg.clone();
                            tasks.push(ex.spawn(async move {
                                established_conn_task(driver, cfg2, start).await
                            }));
                            telemetry.record_local_promotion();
                        }
                        None => eprintln!("[bench-smol] promote {peer}: failed"),
                    }
                }
            }
        }

        // Bond legs relocated here from another acceptor.
        while let Ok(message) = handoffs.try_recv() {
            let handoff = match message {
                WorkerMessage::Handoff(handoff) => handoff,
                // A handshake datagram routed here by its cookie: feed it
                // to the peer state that owns it.
                // Only the single-acceptor strategy sends this, and it
                // never targets a ReuseportMulti acceptor. Named rather
                // than caught by `_` so a new variant still has to be
                // considered here.
                WorkerMessage::Finished { .. } => continue,
                WorkerMessage::Handshake { peer, data } => {
                    peers.admit_and_forward(
                        peer,
                        &data,
                        crate::now_ts(start),
                        &admission,
                        worker_index,
                        &senders,
                        &telemetry,
                    );
                    continue;
                }
            };
            match UdpSocket::new(handoff.socket) {
                Ok(sock) => {
                    let driver = Conn::new(handoff.conn, sock);
                    let cfg2 = cfg.clone();
                    tasks.push(
                        ex.spawn(async move { established_conn_task(driver, cfg2, start).await }),
                    );
                }
                Err(e) => eprintln!("[bench-smol] acceptor {worker_index}: handoff register {e}"),
            }
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
    listener: &UdpSocket,
    destination: SocketAddr,
) -> bool {
    use shiguredo_srt::ConnectionOutput;
    let now = crate::now_ts(Instant::now());
    let mut refused = false;
    while let Some(out) = conn.poll_output() {
        match out {
            ConnectionOutput::SendPacket(bytes) => {
                if listener.send_to(&bytes, destination).await.is_err() {
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
            eprintln!("[bench-smol] relocate {peer}: bind {e}");
            return;
        }
    };
    if std_socket.connect(peer).is_err() {
        eprintln!("[bench-smol] relocate {peer}: connect failed");
        return;
    }
    let message = WorkerMessage::Handoff(Box::new(Handoff {
        socket: std_socket,
        conn: pending_conn,
    }));
    if senders[owner].send(message).is_err() {
        eprintln!("[bench-smol] relocate {peer}: owner {owner} channel closed");
    } else {
        telemetry.record_handoff();
    }
}

/// Steady-state loop for one promoted (already-connected) connection,
/// running as its own task on the owner's executor -- same as the
/// `PerPort` path above, just fed a socket that admission already
/// connected instead of discovering the peer itself.
async fn established_conn_task(mut driver: Conn, cfg: LossConfig, start: Instant) -> ConnStats {
    // `connected` is live state, used only for the loop-exit check below
    // (it flips false on Disconnected). The task is only ever spawned
    // post-promotion (Connected has already fired), so it was *always*
    // connected at some point -- reported unconditionally as `true` in
    // the final ConnStats, not this live flag (see tokio's identical
    // comment for the full reasoning).
    let mut connected = true;
    let mut data_events = 0u64;
    let stream_deadline = Instant::now() + Duration::from_secs_f64(cfg.duration_secs);
    let mut last_data_at = Instant::now();
    let mut buf = [0u8; 2048];

    loop {
        let now = Instant::now();
        if srt_lifecycle::is_terminal(
            connected,
            Some(stream_deadline),
            last_data_at,
            now,
            now,
            IDLE_GRACE,
        ) {
            break;
        }

        driver
            .recv_with_timeout(&mut buf, crate::MAX_WAIT, crate::now_ts(start))
            .await;
        while let Some(res) = driver.try_recv(&mut buf) {
            match res {
                Ok(n) => {
                    let t = crate::now_ts(start);
                    let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                }
                Err(_) => break,
            }
        }

        let t = crate::now_ts(start);
        driver.fire_expired();
        driver.drain_outputs(t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::DataReceived { .. } => {
                    data_events += 1;
                    last_data_at = Instant::now();
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-smol] disconnected: {reason}");
                    connected = false;
                }
                ConnectionEvent::Error(msg) => eprintln!("[bench-smol] error: {msg}"),
                _ => {}
            }
        }
    }

    let mut stats = ConnStats {
        connected: true,
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
