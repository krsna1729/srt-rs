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
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, GroupExtensionData, GroupType, SRTGROUP_MASK, SrtConnection,
};
use srt_transport::tokio_transport::Conn;
use srt_transport::{Handoff, WorkerMessage};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected task may go without a datagram from its peer
/// before it's retired as stalled. Mirrors mio's `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

async fn drain_outputs(driver: &mut Conn, now: shiguredo_srt::Timestamp) {
    if let Err(error) = driver.drain_outputs(now).await {
        eprintln!("[bench-tokio] output send failed: {error}");
    }
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

    let stats = crate::run_workers(&cfg, move |cfg, mine| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(tokio::task::LocalSet::new().run_until(drive(cfg, mine, start)))
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
async fn drive(cfg: BenchConfig, mine: Vec<usize>, start: Instant) -> Vec<crate::ConnStats> {
    let mut handles = Vec::with_capacity(mine.len());
    for i in mine {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(tokio::task::spawn_local(async move {
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
fn bond_extension_for(cfg: &BenchConfig, i: usize) -> Option<GroupExtensionData> {
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
    cfg: BenchConfig,
    index: usize,
    endpoint: std::net::SocketAddr,
    start: Instant,
) -> ConnStats {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
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
    drain_outputs(&mut driver, crate::now_ts(start)).await;

    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = start + crate::INTEROP_CONNECT_TIMEOUT;
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

        let wait = if stats.connected {
            Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
                .min(crate::MAX_WAIT)
        } else {
            crate::MAX_WAIT
        };
        let block_for = wait.saturating_sub(crate::TAIL_SPIN);
        if block_for > Duration::ZERO {
            tokio::select! {
                res = driver.sock.recv(&mut buf) => {
                    if let Ok(n) = res {
                        let t = crate::now_ts(start);
                        let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                    }
                }
                _ = tokio::time::sleep(block_for) => {}
            }
        }

        loop {
            match driver.sock.try_recv(&mut buf) {
                Ok(n) => {
                    let t = crate::now_ts(start);
                    let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
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
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-tokio] disconnected: {reason}");
                    stats.torn_down |= !crate::is_ordered_close(&reason);
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-tokio] error: {msg}");
                }
                _ => {}
            }
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
            let t = crate::now_ts(start);
            loop {
                if driver.send_paced(&payload, t).await.is_err() {
                    break;
                }
                stats.data_events += 1;
            }
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
    if let Some(s) = driver.conn.sender_stats() {
        stats.has_stats = true;
        stats.core_total = s.total_sent;
        stats.secondary_a = s.total_retransmits;
        stats.secondary_b = s.packets_in_loss_list as u64;
    }
    stats
}

async fn receiver_task(cfg: BenchConfig, listen_port: u16, start: Instant) -> ConnStats {
    let socket = tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .await
        .expect("bind");

    let options = ConnectionOptions {
        socket_id: std::process::id(),
        tsbpd_delay: cfg.latency_ms,
        ..Default::default()
    };
    let conn = SrtConnection::new_listener(options);
    let mut driver = Conn::new(conn, socket);

    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
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

        if peer.is_none() {
            // Unconnected phase: first datagram reveals the caller; connect
            // before anything else (drain_outputs uses connected send).
            if let Ok(Ok((n, addr))) =
                tokio::time::timeout(crate::MAX_WAIT, driver.sock.recv_from(&mut buf)).await
            {
                if let Err(e) = driver.sock.connect(addr).await {
                    eprintln!("[bench-tokio] connect to peer failed: {e}");
                    continue;
                }
                peer = Some(addr);
                let t = crate::now_ts(start);
                let _ = driver.conn.feed_recv_buf(&buf[..n], t);
            }
        } else {
            tokio::select! {
                res = driver.sock.recv(&mut buf) => {
                    if let Ok(n) = res {
                        let t = crate::now_ts(start);
                        let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                    }
                }
                _ = tokio::time::sleep(crate::MAX_WAIT) => {}
            }

            while let Ok(n) = driver.sock.try_recv(&mut buf) {
                let t = crate::now_ts(start);
                let _ = driver.conn.feed_recv_buf(&buf[..n], t);
            }
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
                    eprintln!("[bench-tokio] disconnected: {reason}");
                    stats.torn_down |= !crate::is_ordered_close(&reason);
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-tokio] error: {msg}");
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

    let promotion = cfg.promotion;
    let mut peers = srt_transport::PeerTable::new();
    let admission = srt_transport::AdmissionOptions::basic(
        std::process::id(),
        cfg.latency_ms,
        cfg.cookie_routing,
    );
    let mut tasks: Vec<tokio::task::JoinHandle<ConnStats>> = Vec::new();
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut tick = tokio::time::interval(TIMER_TICK);
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
        if crate::shutdown::requested() || (now >= connect_deadline && all_terminal) {
            break;
        }

        tokio::select! {
            res = listener.recv_from(&mut buf) => {
                if let Ok((n, peer)) = res {
                    peers.admit_and_forward(peer, &buf[..n], crate::now_ts(start), &admission, worker_index, &senders, &telemetry);
                    while let Ok((n, peer)) = listener.try_recv_from(&mut buf) {
                        peers.admit_and_forward(peer, &buf[..n], crate::now_ts(start), &admission, worker_index, &senders, &telemetry);
                    }
                }
            }
            _ = tick.tick() => {}
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
            let _ = drain_pending_outputs(&mut p.conn, &mut p.timers, &listener, *peer, t).await;
            let mut newly_connected = false;
            while let Some(ev) = p.conn.poll_event() {
                newly_connected |= p.apply_event(ev);
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
                            tasks.push(tokio::task::spawn_local(async move {
                                established_conn_task(driver, cfg2, start).await
                            }));
                            telemetry.record_local_promotion();
                        }
                        None => eprintln!("[bench-tokio] promote {peer}: failed"),
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
            match tokio::net::UdpSocket::from_std(handoff.socket) {
                Ok(tokio_socket) => {
                    let driver = Conn::new(handoff.conn, tokio_socket);
                    let cfg2 = cfg.clone();
                    tasks.push(tokio::task::spawn_local(async move {
                        established_conn_task(driver, cfg2, start).await
                    }));
                }
                Err(e) => eprintln!("[bench-tokio] acceptor {worker_index}: handoff register {e}"),
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

async fn drain_pending_outputs(
    conn: &mut SrtConnection,
    timers: &mut srt_transport::ManualTimerStore,
    listener: &tokio::net::UdpSocket,
    destination: SocketAddr,
    now: shiguredo_srt::Timestamp,
) -> bool {
    use shiguredo_srt::ConnectionOutput;
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

    let mut peers = srt_transport::PeerTable::new();
    // No SO_REUSEPORT group here, so nothing can rehash and there is
    // nowhere to forward to: one worker, cookie routing inert.
    let admission =
        srt_transport::AdmissionOptions::basic(std::process::id(), cfg.latency_ms, false);
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
        if crate::shutdown::requested()
            || (now >= connect_deadline && peers.all_terminal(now, connect_deadline, IDLE_GRACE))
        {
            break;
        }

        tokio::select! {
            res = sock.recv_from(&mut buf) => {
                if let Ok((n, peer)) = res {
                    admit_one(&mut peers, &admission, peer, &buf[..n], start);
                    while let Ok((n, peer)) = sock.try_recv_from(&mut buf) {
                        admit_one(&mut peers, &admission, peer, &buf[..n], start);
                    }
                }
            }
            _ = tokio::time::sleep(TIMER_TICK) => {}
        }

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        for (peer, bytes) in outbound.drain(..) {
            let _ = sock.send_to(&bytes, peer).await;
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

    let mut peers = srt_transport::PeerTable::new();
    // One acceptor means one owner for every handshake, so there is
    // nobody a stray CONCLUSION could need forwarding to.
    let admission =
        srt_transport::AdmissionOptions::basic(std::process::id(), cfg.latency_ms, false);
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
        tokio::select! {
            res = listener.recv_from(&mut buf) => {
                if let Ok((n, peer)) = res {
                    admit_one(&mut peers, &admission, peer, &buf[..n], start);
                    while let Ok((n, peer)) = listener.try_recv_from(&mut buf) {
                        admit_one(&mut peers, &admission, peer, &buf[..n], start);
                    }
                }
            }
            _ = tokio::time::sleep(TIMER_TICK) => {}
        }

        let t = crate::now_ts(start);
        peers.poll_outbound(t, &mut outbound);
        for (peer, bytes) in outbound.drain(..) {
            let _ = listener.send_to(&bytes, peer).await;
        }
        peers.drain_events(stream_len, &mut connected);

        let newly: Vec<SocketAddr> = std::mem::take(&mut connected);
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
        + crate::INTEROP_CONNECT_TIMEOUT
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
