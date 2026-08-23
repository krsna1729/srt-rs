//! compio adapter: task-per-connection via `compio::runtime::spawn` —
//! compio's designed primitive. Completion-based (owned-buffer) I/O has no
//! non-blocking try_recv, so each connection gets a detached continuous
//! reader feeding a channel plus the protocol loop. The pacing loop never
//! cancels a receive operation — cancel churn collapses io_uring
//! throughput at scale. Native `compio::time::sleep` timers live inside
//! Conn.
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
//! Admission reuses the exact reader-task + `mpsc::channel` shape already
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

use crate::{Aggregate, BondMode, ConnStats, LossConfig};
use compio::buf::BufResult;
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, GroupExtensionData, GroupType, SRTGROUP_MASK, SrtConnection,
};
use srt_transport::compio_transport::Conn;
use srt_transport::{Handoff, WorkerMessage};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected peer may go without a datagram from its peer
/// before it's retired as stalled. Mirrors the other backends' `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

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

pub fn run(cfg: LossConfig) {
    if cfg.mode == crate::Mode::Receiver
        && cfg.connections > 1
        && let crate::Ingress::ReuseportMulti(k) = cfg.ingress
        && k > 1
    {
        return run_reuseport_multi(cfg, k);
    }
    if cfg.mode == crate::Mode::Receiver
        && cfg.connections > 1
        && let crate::Ingress::SharedPool(k) = cfg.ingress
        && k > 1
    {
        return run_shared_pool(cfg, k);
    }
    if cfg.mode == crate::Mode::Receiver
        && cfg.connections > 1
        && let crate::Ingress::ReuseportSingle { workers } = cfg.ingress
        && workers >= 1
    {
        return run_reuseport_single(cfg, workers);
    }
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        // Before any worker starts: the harness waits on this line.
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-compio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let stats = crate::run_workers(&cfg, move |cfg, mine| {
        compio::runtime::Runtime::builder()
            .build()
            .expect("compio runtime")
            .block_on(drive(cfg, mine, start))
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

/// Drive one worker's share of the connections on this thread's runtime.
async fn drive(cfg: LossConfig, mine: Vec<usize>, start: Instant) -> Vec<crate::ConnStats> {
    let mut handles = Vec::with_capacity(mine.len());
    for i in mine {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(compio::runtime::spawn(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, i, endpoint, start).await,
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
    let socket = compio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind");
    socket.connect(endpoint).await.expect("connect");

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

    // Continuous reader: keeps one owned-buffer recv in flight at a time,
    // never cancelled, forwarding payloads over the channel.
    let (received_sender, received_receiver) = mpsc::channel();
    let received_socket = driver.sock.clone();
    let _reader = compio::runtime::spawn(async move {
        loop {
            let BufResult(result, buffer) = received_socket.recv(vec![0u8; 2048]).await;
            let Ok(size) = result else {
                break;
            };
            if received_sender.send(buffer[..size].to_vec()).is_err() {
                break;
            }
        }
    });
    driver.drain_outputs(crate::now_ts(start)).await;

    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = start + crate::INTEROP_CONNECT_TIMEOUT;

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-compio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // Sleep until the next paced send is due; the reader keeps draining
        // the socket into the channel meanwhile.
        let wait = if stats.connected {
            Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
                .min(crate::MAX_WAIT)
        } else {
            crate::MAX_WAIT
        };
        compio::time::sleep(wait).await;

        while let Ok(buf) = received_receiver.try_recv() {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf, t);
        }

        let t = crate::now_ts(start);
        driver.fire_expired(t);
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
                    eprintln!("[bench-compio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-compio] error: {msg}");
                }
                _ => {}
            }
        }

        if stats.connected {
            // Sample the clock ONCE: this loop must drain only what pacing
            // says is due at instant `t`. Re-reading it per iteration makes
            // the condition self-fulfilling -- each `send_paced` awaits a
            // socket write that costs roughly one pacing interval, so `t`
            // advances far enough to permit the next packet and the loop
            // never exits. The task then never returns to the outer loop,
            // so it stops firing timers (no TLPKTDROP) and stops draining
            // received ACKs, and the send buffer grows to the full flow
            // window. That was ~12 MB per connection under overload.
            let t = crate::now_ts(start);
            loop {
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
    let socket = compio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .await
        .expect("bind");

    let options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    let conn = SrtConnection::new_listener(options);
    let mut driver = Conn::new(conn, socket);
    driver.drain_outputs(crate::now_ts(start)).await;

    // Reader task: first packet discovers the peer and connects the socket
    // (drain_outputs uses connected send), then forwards payloads.
    let (received_sender, received_receiver) = mpsc::channel();
    let received_socket = driver.sock.clone();
    let _reader = compio::runtime::spawn(async move {
        let mut first = true;
        loop {
            let BufResult(result, buffer) = received_socket.recv_from(vec![0u8; 2048]).await;
            let Ok((size, addr)) = result else {
                break;
            };
            if first && received_socket.connect(addr).await.is_err() {
                break;
            }
            first = false;
            if received_sender.send(buffer[..size].to_vec()).is_err() {
                break;
            }
        }
    });

    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-compio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // The reader drains the socket continuously; this side only pays
        // for protocol maintenance once per MAX_WAIT.
        compio::time::sleep(crate::MAX_WAIT).await;

        while let Ok(packet) = received_receiver.try_recv() {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&packet, t);
        }

        let t = crate::now_ts(start);
        driver.fire_expired(t);
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
                ConnectionEvent::DataReceived { .. } => {
                    stats.data_events += 1;
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-compio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-compio] error: {msg}");
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
async fn run_acceptor(
    cfg: LossConfig,
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

    // Same reader-task + mpsc::channel shape as receiver_task's proven
    // admission pattern above (see the module doc): compio has no
    // non-blocking recv, so a dedicated task recvs in a genuine `.await`
    // loop, decoupled from the maintenance tick, and hands datagrams to
    // the main loop through the channel. Never calls connect -- this
    // listener must stay unconnected to keep admitting every peer.
    let (inbox_tx, inbox_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>();
    let reader_listener = listener.clone();
    let _reader = compio::runtime::spawn(async move {
        loop {
            let BufResult(result, buffer) = reader_listener.recv_from(vec![0u8; 2048]).await;
            let Ok((size, peer)) = result else {
                break;
            };
            if inbox_tx.send((peer, buffer[..size].to_vec())).is_err() {
                break;
            }
        }
    });

    let promotion = cfg.promotion;
    let mut peers = srt_transport::PeerTable::new();
    let admission = srt_transport::AdmissionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        cookie_routing: cfg.cookie_routing,
    };
    let mut tasks: Vec<compio::runtime::JoinHandle<ConnStats>> = Vec::new();
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);

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

        compio::time::sleep(TIMER_TICK).await;
        while let Ok((peer, data)) = inbox_rx.try_recv() {
            peers.admit_and_forward(
                peer,
                &data,
                crate::now_ts(start),
                &admission,
                worker_index,
                &senders,
                &telemetry,
            );
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
                            tasks.push(compio::runtime::spawn(async move {
                                established_conn_task(driver, cfg2, start).await
                            }));
                            telemetry.record_local_promotion();
                        }
                        None => eprintln!("[bench-compio] promote {peer}: failed"),
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
            match compio::net::UdpSocket::from_std(handoff.socket) {
                Ok(sock) => {
                    let driver = Conn::new(handoff.conn, sock);
                    let cfg2 = cfg.clone();
                    tasks.push(compio::runtime::spawn(async move {
                        established_conn_task(driver, cfg2, start).await
                    }));
                }
                Err(e) => eprintln!("[bench-compio] acceptor {worker_index}: handoff register {e}"),
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
        if let Ok(s) = task.await {
            stats.push(s);
        }
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
/// (including its own reader-task + `mpsc::channel`, since a promoted
/// connection has no in-flight admission reader to lean on), just fed a
/// socket that admission already connected instead of discovering the
/// peer itself.
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

    // Continuous reader: keeps one owned-buffer recv in flight at a time,
    // never cancelled (see the module doc), forwarding payloads over the
    // channel.
    let (received_sender, received_receiver) = mpsc::channel();
    let received_socket = driver.sock.clone();
    let _reader = compio::runtime::spawn(async move {
        loop {
            let BufResult(result, buffer) = received_socket.recv(vec![0u8; 2048]).await;
            let Ok(size) = result else {
                break;
            };
            if received_sender.send(buffer[..size].to_vec()).is_err() {
                break;
            }
        }
    });

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

        compio::time::sleep(crate::MAX_WAIT).await;

        while let Ok(buf) = received_receiver.try_recv() {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf, t);
        }

        let t = crate::now_ts(start);
        driver.fire_expired(t);
        driver.drain_outputs(t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::DataReceived { .. } => {
                    data_events += 1;
                    last_data_at = Instant::now();
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-compio] disconnected: {reason}");
                    connected = false;
                }
                ConnectionEvent::Error(msg) => eprintln!("[bench-compio] error: {msg}"),
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

// ---------------------------------------------------------------------------
// #2: SharedPool -- K plainly-bound ports, no SO_REUSEPORT, no promotion
// ---------------------------------------------------------------------------

/// K real ports, each socket serving many peers by peer-address dispatch
/// for their whole life. The control the reuseport strategies are
/// measured against: it isolates "fewer sockets and wakeups" from
/// "kernel-level demux", which is `ReuseportMulti`'s job. Single-threaded
/// by design, so any win here is not just extra cores.
fn run_shared_pool(cfg: LossConfig, k: usize) {
    let start = Instant::now();
    println!("LISTENING");
    let agg_cfg = cfg.clone();
    let rt = compio::runtime::Runtime::builder()
        .build()
        .expect("compio runtime");
    let stats = rt.block_on(async move {
        let mut tasks = Vec::new();
        for index in 0..k {
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
async fn serve_pool_socket(cfg: LossConfig, index: usize, start: Instant) -> Vec<ConnStats> {
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
    let (inbox_tx, inbox_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>();
    let reader_sock = sock.clone();
    let _reader = compio::runtime::spawn(async move {
        loop {
            let BufResult(res, b) = reader_sock.recv_from(vec![0u8; 2048]).await;
            let Ok((n, peer)) = res else { break };
            if inbox_tx.send((peer, b[..n].to_vec())).is_err() {
                break;
            }
        }
    });

    let mut peers = srt_transport::PeerTable::new();
    // No SO_REUSEPORT group here, so nothing can rehash and there is
    // nowhere to forward to: one worker, cookie routing inert.
    let admission = srt_transport::AdmissionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        cookie_routing: false,
    };
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut buf = [0u8; 2048];
    let mut outbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    let mut connected: Vec<SocketAddr> = Vec::new();
    let _ = &mut buf;

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        if now >= connect_deadline && peers.all_terminal(now, connect_deadline, IDLE_GRACE) {
            break;
        }

        compio::time::sleep(TIMER_TICK).await;
        while let Ok((peer, packet)) = inbox_rx.try_recv() {
            admit_one(&mut peers, &admission, peer, &packet, start);
        }

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        for (peer, bytes) in outbound.drain(..) {
            let BufResult(_r, _b) = sock.send_to(bytes, peer).await;
        }
        // SharedPool never promotes, so a first Connected only starts the
        // stream clock -- which drain_events already did.
        peers.drain_events(stream_len, &mut connected);
    }

    peers
        .into_iter()
        .map(|(_peer, p)| {
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
        .collect()
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
fn run_reuseport_single(cfg: LossConfig, workers: usize) {
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
    {
        let router = router.clone();
        let senders = senders.clone();
        let rt = compio::runtime::Runtime::builder()
            .build()
            .expect("compio runtime");
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
        eprintln!("[bench-compio] reuseport-single admitted no connections");
        std::process::exit(1);
    }
}

/// The single acceptor: admit every flow, route each to a worker as soon
/// as it is established.
async fn run_single_acceptor(
    cfg: &LossConfig,
    start: Instant,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let Ok(std_socket) = srt_transport::bind_reuseport(cfg.port, cfg.sock_buf_bytes) else {
        eprintln!("[bench-compio] reuseport-single: bind failed");
        return;
    };
    let Some(listener) = compio::net::UdpSocket::from_std(std_socket).ok() else {
        eprintln!("[bench-compio] reuseport-single: register failed");
        return;
    };

    let (inbox_tx, inbox_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>();
    let reader_sock = listener.clone();
    let _reader = compio::runtime::spawn(async move {
        loop {
            let BufResult(res, b) = reader_sock.recv_from(vec![0u8; 2048]).await;
            let Ok((n, peer)) = res else { break };
            if inbox_tx.send((peer, b[..n].to_vec())).is_err() {
                break;
            }
        }
    });

    let mut peers = srt_transport::PeerTable::new();
    // One acceptor means one owner for every handshake, so there is
    // nobody a stray CONCLUSION could need forwarding to.
    let admission = srt_transport::AdmissionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        cookie_routing: false,
    };
    let telemetry = srt_transport::IngressTelemetry::new();
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let mut routed = 0usize;
    let mut buf = [0u8; 2048];
    let mut outbound: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    let mut connected: Vec<SocketAddr> = Vec::new();
    let _ = &mut buf;

    // Admission ends with the connect window: anything not established by
    // then never will be.
    while Instant::now() < connect_deadline && routed < cfg.connections {
        compio::time::sleep(TIMER_TICK).await;
        while let Ok((peer, packet)) = inbox_rx.try_recv() {
            admit_one(&mut peers, &admission, peer, &packet, start);
        }

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        for (peer, bytes) in outbound.drain(..) {
            let BufResult(_r, _b) = listener.send_to(bytes, peer).await;
        }
        peers.drain_events(stream_len, &mut connected);

        let newly: Vec<SocketAddr> = connected.drain(..).collect();
        for peer in newly {
            let Some(entry) = peers.remove(&peer) else {
                continue;
            };
            let group =
                entry
                    .conn
                    .peer_group_extension()
                    .map(|extension| srt_lifecycle::GroupAffinity {
                        group_id: extension.group_id,
                        stream_id: None,
                        extension,
                    });
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
                conn: entry.conn,
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
            "[bench-compio] reuseport-single: routed {} tuples into {} bond groups",
            router.active_tuple_count(),
            router.active_group_count()
        );
    }
}

/// One worker: drive whatever the acceptor hands it, to completion.
async fn run_pool_worker(
    cfg: LossConfig,
    start: Instant,
    handoffs: mpsc::Receiver<WorkerMessage>,
) -> Vec<ConnStats> {
    let mut tasks = Vec::new();
    let mut stats: Vec<ConnStats> = Vec::new();
    let mut expected: Option<usize> = None;
    let mut received = 0usize;
    let deadline = Instant::now()
        + crate::INTEROP_CONNECT_TIMEOUT
        + Duration::from_secs_f64(cfg.duration_secs)
        + IDLE_GRACE
        + Duration::from_secs(30);

    // Stop once the acceptor's tally is in and all of them have arrived;
    // the deadline is only a backstop against a wedged acceptor.
    while Instant::now() < deadline {
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
