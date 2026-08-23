//! glommio adapter: task-per-connection via `glommio::spawn_local` —
//! glommio's designed thread-per-core primitive. Linux-only (io_uring).
//! Native `glommio::timer::sleep` timers live inside Conn.
//!
//! KNOWN LIMITATION (measured, N>=300): the listener starves under load —
//! kernel buffers overflow, sequence gaps trigger NAK storms, RTT inflates
//! to hundreds of ms. Diagnosis: every loop iteration re-creates the recv
//! future (`or(recv_from, sleep)`), submitting a fresh io_uring op per
//! datagram; at 455k pps aggregate this saturates glommio's default
//! submission queue. Candidate fixes, untested:
//!   1. `LocalExecutorBuilder::io_memory(n)` — public API knob for the SQ
//!      ring size (no glommio source changes needed).
//!   2. Batch recvs per wakeup via `poll_once` (executor-safe, unlike the
//!      removed try_recv whose futures_lite::block_on parks the whole
//!      executor thread — never reintroduce it here).
//!
//! `Ingress::ReuseportMulti(K)` (#4) uses the identical fix and reasoning
//! as mio's `run_pool_acceptor`, tokio's `run_acceptor`, smol's
//! `run_acceptor`, and monoio's `run_acceptor`: K OS threads, each already
//! running its own glommio executor by design (`LocalExecutorBuilder::spawn`
//! already creates a dedicated thread per call, same as the PerPort path
//! above), gives `worker_index` stable thread identity for the
//! bond-affinity registry/handoff mechanism. Within each acceptor thread,
//! a connection only ever gets its own task -- and its own socket -- if it
//! actually needs to relocate for bond affinity; the common case is
//! serviced straight off the shared listener socket by peer-address
//! dispatch, bypassing the `Conn` wrapper in favor of direct
//! `SrtConnection` + `srt_transport::ManualTimerStore` + `listener.send_to`.
//!
//! Like monoio, glommio has no *safe* non-blocking recv to drain a burst
//! with (`Conn::try_recv` exists but parks the executor thread via
//! `futures_lite::block_on` -- forbidden here for the same reason it's
//! forbidden in `sender_task`/`receiver_task` above). So admission uses
//! the same fix as monoio's `run_acceptor`: a dedicated reader task
//! `.await`s `recv_from` in a genuine (non-blocking-executor) loop,
//! decoupled from the maintenance tick, handing datagrams to the main
//! loop through a local `Rc<RefCell<VecDeque>>` queue.
//!
//! THROUGHPUT AND `--promote-all` (measured; supersedes an earlier,
//! wrong "KNOWN LIMITATION" note here).
//!
//! With the default bond-only promotion, #4 under-delivers badly at
//! bench.sh's 8Mbps/conn -- at N=25 the listener took only 49.4% of what
//! the caller sent. That was blamed here on per-datagram io_uring submissions
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
//!   N=25, K=4, 8Mbps/conn:  49.4% -> 95.6% delivered, RTT 13.0ms -> 17.9ms
//!
//! Promotion is therefore not a uniform cost to be avoided: on a runtime
//! with a real task scheduler it is the point. (On mio -- a flat epoll
//! loop with no task model -- the same change measures
//! neutral-to-negative, which is why this is a flag and not a default.)
//!
//! Residual cost with promotion on: sec_a=103 retransmits, from
//! SO_REUSEPORT group churn rerouting flows mid-handshake. See
//! crates/srt-transport/tests/reuseport_rehash.rs and mio.rs's
//! ORPHAN_CONCLUSION_COUNT; cookie-keyed handshake routing is the
//! outstanding fix for that.

use crate::{Aggregate, BondMode, ConnStats, LossConfig};
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, GroupExtensionData, GroupType, SRTGROUP_MASK, SrtConnection,
};
use srt_transport::glommio_transport::Conn;
use srt_transport::{Handoff, WorkerMessage};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected peer may go without a datagram from its peer
/// before it's retired as stalled. Mirrors the other backends' `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

/// Stable per-peer entropy for a cookie's upper bits, so cookies differ
/// per connection instead of being one constant per worker.
fn peer_hash(peer: SocketAddr) -> u32 {
    use std::hash::{BuildHasher, Hash, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    peer.hash(&mut hasher);
    hasher.finish() as u32
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
    let sock = srt_transport::glommio_transport::from_std(std_socket).ok()?;
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
    let c2 = cfg.clone();
    // Ring sizing expedition: the default submission queue (small) is the
    // prime suspect for listener starvation at N>=300 -- 300 tasks each
    // submitting a fresh recv SQE per datagram at 455k pps aggregate
    // saturates it. io_memory() sizes the SQ/CQ rings via glommio's public
    // builder API (no source modification).
    let any_connected = glommio::LocalExecutorBuilder::default()
        .io_memory(4096)
        .spawn(move || async move { drive(c2).await })
        .expect("failed to spawn glommio LocalExecutor")
        .join()
        .expect("glommio task panicked");

    if !any_connected {
        std::process::exit(1);
    }
}

async fn drive(cfg: LossConfig) -> bool {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-glommio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(glommio::spawn_local(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, i, endpoint, start).await,
                crate::Mode::Receiver => receiver_task(c2, endpoint.port(), start).await,
            }
        }));
    }

    let mut agg = Aggregate::new(cfg.clone());
    for h in handles {
        let stats = h.await;
        agg.add(stats);
    }
    agg.print(start);

    agg.any_connected
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
    let socket = glommio::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
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
    driver.drain_outputs(crate::now_ts(start)).await;

    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let mut stats = ConnStats::default();
    let mut stream_deadline: Option<Instant> = None;
    let connect_deadline = start + crate::INTEROP_CONNECT_TIMEOUT;
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-glommio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // One datagram per iteration. NOTE: never use Conn::try_recv here --
        // it parks the executor thread (futures_lite::block_on), starving
        // every other task under load. The or(sleep) arm only fires when
        // idle, so in-flight recvs are essentially never cancelled.
        let recv_fut = async { driver.sock.recv_from(&mut buf).await.ok() };
        let timer_fut = async {
            glommio::timer::sleep(crate::MAX_WAIT).await;
            None
        };
        if let Some((n, _addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf[..n], t);
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
                    eprintln!("[bench-glommio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-glommio] error: {msg}");
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
    let socket =
        glommio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port))).expect("bind");

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
    let mut handshook = false;
    let mut buf = [0u8; 2048];

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-glommio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // One datagram per iteration. First datagram reveals the caller;
        // connect before anything else (drain_outputs uses connected send).
        // NOTE: never use Conn::try_recv here -- it parks the executor
        // thread, starving every other task under load.
        let recv_fut = async { driver.sock.recv_from(&mut buf).await.ok() };
        let timer_fut = async {
            glommio::timer::sleep(crate::MAX_WAIT).await;
            None
        };
        if let Some((n, addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
            if !handshook && driver.sock.connect(addr).await.is_err() {
                eprintln!("[bench-glommio] connect to peer failed");
                continue;
            }
            handshook = true;
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf[..n], t);
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
                ConnectionEvent::DataReceived { .. } => {
                    stats.data_events += 1;
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-glommio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-glommio] error: {msg}");
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
/// `run_acceptor`'s `inbox`.
type Inbox = Rc<RefCell<VecDeque<(SocketAddr, Vec<u8>)>>>;

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
    // mio/tokio/smol/monoio bug this avoids: cloning a partially-built
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
            glommio::LocalExecutorBuilder::default()
                .io_memory(4096)
                .name(&format!("srt-acceptor-{worker_index}"))
                .spawn(move || async move {
                    run_acceptor(cfg, worker_index, start, router, all_senders, rx, telemetry).await
                })
                .expect("failed to spawn glommio LocalExecutor"),
        );
    }

    let mut agg = Aggregate::new(cfg.clone());
    for handle in handles {
        for stats in handle.join().expect("acceptor panicked") {
            agg.add(stats);
        }
    }
    eprintln!("{}", telemetry.report("glommio"));
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-glommio] pool receiver admitted no connections");
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
/// tokio's `run_acceptor`, smol's `run_acceptor`, and monoio's
/// `run_acceptor`. Only a leg that actually needs to relocate gets
/// `glommio::spawn_local`'d as its own task, via a handoff.
async fn run_acceptor(
    cfg: LossConfig,
    worker_index: usize,
    start: Instant,
    router: crate::SharedWorkerRouter,
    senders: Vec<mpsc::Sender<WorkerMessage>>,
    handoffs: mpsc::Receiver<WorkerMessage>,
    telemetry: Arc<srt_transport::IngressTelemetry>,
) -> Vec<ConnStats> {
    let listener =
        match srt_transport::glommio_transport::bind_reuseport(cfg.port, cfg.sock_buf_bytes) {
            Ok(s) => Rc::new(s),
            Err(e) => {
                eprintln!("[bench-glommio] acceptor {worker_index}: bind {e}");
                return Vec::new();
            }
        };

    // Same fix as monoio's run_acceptor: glommio has no *safe* non-blocking
    // recv to drain a burst with (Conn::try_recv parks the executor thread
    // via futures_lite::block_on -- forbidden, see the module doc). A
    // dedicated reader task recvs in a genuine `.await` loop, decoupled
    // from the maintenance tick below, and hands datagrams to the main
    // loop through this local queue. `Rc<RefCell<..>>` is safe without
    // synchronization because the push/pop are always synchronous, never
    // held across an `.await`, even though both tasks run cooperatively
    // on the same thread.
    let inbox: Inbox = Rc::new(RefCell::new(VecDeque::new()));
    let reader_listener = listener.clone();
    let reader_inbox = inbox.clone();
    let _reader_task = glommio::spawn_local(async move {
        let mut buf = [0u8; 2048];
        loop {
            match reader_listener.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    let mut q = reader_inbox.borrow_mut();
                    q.push_back((peer, buf[..n].to_vec()));
                    // Safety net against unbounded growth if the main
                    // loop ever falls behind; not expected in practice.
                    while q.len() > 4096 {
                        q.pop_front();
                    }
                }
                Err(_) => break,
            }
        }
    });

    let promotion = cfg.promotion;
    let mut peers: HashMap<SocketAddr, PeerEntry> = HashMap::new();
    let mut tasks: Vec<glommio::Task<ConnStats>> = Vec::new();
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
        let all_terminal = peers.values().all(|p| {
            srt_lifecycle::is_terminal(
                p.connected,
                p.stream_deadline,
                p.last_data_at,
                now,
                connect_deadline,
                IDLE_GRACE,
            )
        });
        if now >= connect_deadline && all_terminal {
            break;
        }

        glommio::timer::sleep(TIMER_TICK).await;
        while let Some((peer, data)) = inbox.borrow_mut().pop_front() {
            admit(
                &mut peers,
                &cfg,
                worker_index,
                &senders,
                &telemetry,
                peer,
                &data,
                start,
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
                            tasks.push(glommio::spawn_local(async move {
                                established_conn_task(driver, cfg2, start).await
                            }));
                            telemetry.record_local_promotion();
                        }
                        None => eprintln!("[bench-glommio] promote {peer}: failed"),
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
                    admit(
                        &mut peers,
                        &cfg,
                        worker_index,
                        &senders,
                        &telemetry,
                        peer,
                        &data,
                        start,
                    );
                    continue;
                }
            };
            let sock = match srt_transport::glommio_transport::from_std(handoff.socket) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[bench-glommio] acceptor {worker_index}: handoff register {e}");
                    continue;
                }
            };
            let driver = Conn::new(handoff.conn, sock);
            let cfg2 = cfg.clone();
            tasks.push(glommio::spawn_local(async move {
                established_conn_task(driver, cfg2, start).await
            }));
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

fn admit(
    peers: &mut HashMap<SocketAddr, PeerEntry>,
    cfg: &LossConfig,
    worker_index: usize,
    senders: &[mpsc::Sender<WorkerMessage>],
    telemetry: &srt_transport::IngressTelemetry,
    peer: SocketAddr,
    data: &[u8],
    start: Instant,
) {
    // Route by cookie before touching local state: a handshake datagram
    // whose cookie names another acceptor belongs to that acceptor's
    // half-open connection, wherever the kernel happened to deliver it.
    if cfg.cookie_routing
        && !peers.contains_key(&peer)
        && let Some(identity) = srt_lifecycle::handshake_identity(data)
        && identity.is_conclusion
        && let Some(owner) = srt_lifecycle::worker_from_cookie(identity.syn_cookie, senders.len())
        && owner != worker_index
    {
        let message = WorkerMessage::Handshake {
            peer,
            data: data.to_vec(),
        };
        if senders[owner].send(message).is_ok() {
            telemetry.record_cookie_routed();
            return;
        }
        // Owner is gone; handle it here rather than dropping it.
    }
    // A CONCLUSION is never a flow's first packet, so one arriving for an
    // unknown peer needs explaining. Two very different things look
    // identical here, and conflating them makes the cookie-routing
    // measurement meaningless:
    //   - the cookie names *this* acceptor: the flow was already promoted
    //     off the shared listener and its peer entry removed, so this is a
    //     late or duplicate CONCLUSION, not a rehash victim;
    //   - anything else: no usable routing information, a genuinely
    //     stranded handshake.
    if !peers.contains_key(&peer)
        && let Some(identity) = srt_lifecycle::handshake_identity(data)
        && identity.is_conclusion
    {
        match srt_lifecycle::worker_from_cookie(identity.syn_cookie, senders.len()) {
            Some(owner) if owner == worker_index => {
                telemetry.record_promoted_duplicate();
            }
            _ => {
                telemetry.record_stranded_conclusion();
            }
        }
    }
    let t = crate::now_ts(start);
    let entry = peers.entry(peer).or_insert_with(|| PeerEntry {
        conn: SrtConnection::new_listener(ConnectionOptions {
            socket_id: std::process::id(),
            tsbpd_delay: cfg.latency_ms,
            // Encode who owns this handshake, so a CONCLUSION rehashed to
            // another acceptor can be routed back here.
            syn_cookie: Some(srt_lifecycle::cookie_for_worker(
                worker_index,
                peer_hash(peer),
            )),
            ..Default::default()
        }),
        timers: srt_transport::ManualTimerStore::new(),
        connected: false,
        stream_deadline: None,
        data_events: 0,
        last_data_at: Instant::now(),
    });
    let _ = entry.conn.feed_recv_buf(data, t);
}

/// One tracked peer -- pending handshake or fully established, serviced
/// off the shared listener socket for its whole life unless it relocates
/// -- keyed by peer tuple in `run_acceptor`'s `peers` map. Module-scoped
/// (not local to `run_acceptor`) only because `admit` needs to name the
/// type in its signature.
struct PeerEntry {
    conn: SrtConnection,
    timers: srt_transport::ManualTimerStore,
    /// Live connected state, feeding `srt_lifecycle::is_terminal`.
    connected: bool,
    /// `None` until this peer's first `Connected` event; doubles as "has
    /// this ever connected" (see the other backends' identical pattern).
    stream_deadline: Option<Instant>,
    data_events: u64,
    last_data_at: Instant,
}

async fn drain_pending_outputs(
    conn: &mut SrtConnection,
    timers: &mut srt_transport::ManualTimerStore,
    listener: &glommio::net::UdpSocket,
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
            eprintln!("[bench-glommio] relocate {peer}: bind {e}");
            return;
        }
    };
    if std_socket.connect(peer).is_err() {
        eprintln!("[bench-glommio] relocate {peer}: connect failed");
        return;
    }
    let message = WorkerMessage::Handoff(Box::new(Handoff {
        socket: std_socket,
        conn: pending_conn,
    }));
    if senders[owner].send(message).is_err() {
        eprintln!("[bench-glommio] relocate {peer}: owner {owner} channel closed");
    } else {
        telemetry.record_handoff();
    }
}

/// Steady-state loop for one promoted (already-connected) connection,
/// running as its own `glommio::spawn_local`'d task -- glommio's ordinary
/// task-per-connection idiom, same as the `PerPort` path above, just fed
/// a socket that admission already connected instead of discovering the
/// peer itself. One datagram per iteration, same reasoning as
/// `receiver_task` above: `Conn::try_recv` is forbidden here (parks the
/// executor thread).
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
                    eprintln!("[bench-glommio] disconnected: {reason}");
                    connected = false;
                }
                ConnectionEvent::Error(msg) => eprintln!("[bench-glommio] error: {msg}"),
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
