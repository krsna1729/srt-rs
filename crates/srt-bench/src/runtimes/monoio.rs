//! monoio adapter: task-per-connection via `monoio::spawn` — monoio is
//! thread-per-core with completion-based (owned-buffer) I/O and no
//! non-blocking try_recv, so each task owns its blocking recv. Native
//! io_uring timers live inside Conn.
//!
//! Receive shape (proven): ONE datagram per loop iteration via a blocking
//! timeout-wrapped recv, protocol maintenance after each. Timeouts only
//! ever fire when idle, so in-flight recvs are essentially never cancelled.
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
//! bench.sh's 8Mbps/conn -- at N=25 the listener took only 49.4% of what
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

use crate::{Aggregate, BondMode, ConnStats, LossConfig};
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, GroupExtensionData, GroupType, SRTGROUP_MASK, SrtConnection,
};
use srt_transport::monoio_transport::Conn;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected peer may go without a datagram from its peer
/// before it's retired as stalled. Mirrors mio's/tokio's/smol's `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

/// Diagnostic counter: bond legs actually shipped cross-thread via the
/// handoff channel. See `run_reuseport_multi`'s shutdown log.
static HANDOFF_COUNT: AtomicU64 = AtomicU64::new(0);

/// Diagnostic counter: connections promoted to their own socket + task on
/// this same acceptor thread (`--promote-all`). Distinct from
/// `HANDOFF_COUNT`, which counts only cross-thread bond relocations.
static PROMOTION_COUNT: AtomicU64 = AtomicU64::new(0);

/// Diagnostic counter: handshake datagrams rescued by cookie routing.
/// Each one would otherwise have been an orphaned CONCLUSION -- a
/// handshake stranded on an acceptor with no state for it.
static COOKIE_FORWARD_COUNT: AtomicU64 = AtomicU64::new(0);

/// Diagnostic counter: CONCLUSION packets arriving at an acceptor with no
/// state for that peer -- flows the kernel rehashed between the two
/// caller->listener handshake packets. Cookie routing exists to drive
/// this to zero; comparing it with and without is how that is verified.
static ORPHAN_CONCLUSION_COUNT: AtomicU64 = AtomicU64::new(0);

/// Diagnostic counter: late or duplicate CONCLUSIONs for a flow this
/// acceptor already promoted (so its peer entry is gone). Harmless, but
/// indistinguishable from a stranded handshake without checking the
/// cookie -- which is why they are counted apart.
static PROMOTED_DUP_COUNT: AtomicU64 = AtomicU64::new(0);

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
fn promote_locally(port: u16, peer: SocketAddr, conn: SrtConnection) -> Option<Conn> {
    let std_socket = srt_transport::bind_reuseport(port).ok()?;
    std_socket.connect(peer).ok()?;
    let sock = monoio::net::udp::UdpSocket::from_std(std_socket).ok()?;
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
    let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_timer()
        .build()
        .expect("monoio io_uring runtime");
    rt.block_on(drive(cfg));
}

async fn drive(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-monoio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(monoio::spawn(async move {
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
    let socket = monoio::net::udp::UdpSocket::bind("0.0.0.0:0").expect("bind");
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

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-monoio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // Block until the next paced send is due (bounded by MAX_WAIT).
        // A fresh buffer per attempt -- io_uring ops can't be safely
        // cancelled mid-flight, so a timed-out recv's buffer is simply
        // abandoned rather than reused.
        let wait = if stats.connected {
            Duration::from_micros(driver.conn.time_until_send(crate::now_ts(start)))
                .min(crate::MAX_WAIT)
        } else {
            crate::MAX_WAIT
        };
        if let Ok((Ok(n), buf)) =
            monoio::time::timeout(wait, driver.sock.recv(vec![0u8; 2048])).await
        {
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
                    eprintln!("[bench-monoio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-monoio] error: {msg}");
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
    let socket = monoio::net::udp::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
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

    loop {
        if !stats.connected && Instant::now() >= connect_deadline {
            eprintln!(
                "[bench-monoio] connect timed out, state={:?}",
                driver.conn.state()
            );
            break;
        }
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
            break;
        }

        // One datagram per iteration: recv_from until the first packet
        // reveals the peer, then connect the socket (drain_outputs uses
        // connected send). Maintenance runs after every packet.
        if let Ok((res, buf)) =
            monoio::time::timeout(crate::MAX_WAIT, driver.sock.recv_from(vec![0u8; 2048])).await
            && let Ok((n, addr)) = res
        {
            if peer.is_none() {
                if let Err(e) = driver.sock.connect(addr).await {
                    eprintln!("[bench-monoio] connect to peer failed: {e}");
                } else {
                    peer = Some(addr);
                }
            }
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
                    eprintln!("[bench-monoio] disconnected: {reason}");
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

/// A connected socket + protocol state shipped from the acceptor that
/// completed its handshake to the thread that owns its bond group. Ships
/// the raw `std::net::UdpSocket` (plain, `Send`) rather than a
/// `monoio_transport::Conn` (whose native timer future is `!Send`, and
/// whose owned-buffer socket isn't `Send` either) -- the receiving thread
/// reconstructs `Conn` locally after re-registering the socket with its
/// own io_uring runtime.
struct Handoff {
    socket: std::net::UdpSocket,
    conn: SrtConnection,
}

enum WorkerMessage {
    Handoff(Box<Handoff>),
    /// A handshake datagram the kernel delivered to the wrong acceptor.
    /// Its SYN cookie names the acceptor that owns the half-open
    /// handshake, so it is forwarded there rather than answered here
    /// (which would fail cookie validation) or dropped (which costs a
    /// handshake retry). See `srt_lifecycle::cookie_for_worker`.
    Handshake {
        peer: SocketAddr,
        data: Vec<u8>,
    },
}

/// Datagrams handed from the reader task to the maintenance loop; see
/// `run_acceptor`'s `inbox`.
type Inbox = Rc<RefCell<VecDeque<(SocketAddr, Vec<u8>)>>>;

fn run_reuseport_multi(cfg: LossConfig, k: usize) {
    let worker_count = k.min(cfg.connections);
    let start = Instant::now();
    println!("LISTENING");
    let router: crate::SharedWorkerRouter =
        Arc::new(Mutex::new(srt_lifecycle::WorkerRouter::new(worker_count)));

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
    let handoffs = HANDOFF_COUNT.load(Ordering::Relaxed);
    let promotions = PROMOTION_COUNT.load(Ordering::Relaxed);
    let orphans = ORPHAN_CONCLUSION_COUNT.load(Ordering::Relaxed);
    let forwarded = COOKIE_FORWARD_COUNT.load(Ordering::Relaxed);
    let dups = PROMOTED_DUP_COUNT.load(Ordering::Relaxed);
    eprintln!(
        "[bench-monoio] pool receiver: {promotions} local promotions, {handoffs} bond handoffs, \
         {orphans} stranded CONCLUSIONs, {forwarded} cookie-routed, {dups} post-promotion dups"
    );
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
async fn run_acceptor(
    cfg: LossConfig,
    worker_index: usize,
    start: Instant,
    router: crate::SharedWorkerRouter,
    senders: Vec<mpsc::Sender<WorkerMessage>>,
    handoffs: mpsc::Receiver<WorkerMessage>,
) -> Vec<ConnStats> {
    let std_listener = match srt_transport::bind_reuseport(cfg.port) {
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
    let reader_listener = listener.clone();
    let reader_inbox = inbox.clone();
    let _reader_task = monoio::spawn(async move {
        loop {
            let (res, buf) = reader_listener.recv_from(vec![0u8; 2048]).await;
            match res {
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
    let mut tasks: Vec<monoio::task::JoinHandle<ConnStats>> = Vec::new();
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

        monoio::time::sleep(TIMER_TICK).await;
        while let Some((peer, data)) = inbox.borrow_mut().pop_front() {
            admit(&mut peers, &cfg, worker_index, &senders, peer, &data, start);
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
                    relocate_to_owner(cfg.port, peer, p.conn, owner, &senders);
                }
                srt_lifecycle::PromotionDecision::PromoteHere => {
                    let Some(p) = peers.remove(&peer) else {
                        continue;
                    };
                    match promote_locally(cfg.port, peer, p.conn) {
                        Some(driver) => {
                            let cfg2 = cfg.clone();
                            tasks.push(monoio::spawn(async move {
                                established_conn_task(driver, cfg2, start).await
                            }));
                            PROMOTION_COUNT.fetch_add(1, Ordering::Relaxed);
                        }
                        None => eprintln!("[bench-monoio] promote {peer}: failed"),
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
                WorkerMessage::Handshake { peer, data } => {
                    admit(&mut peers, &cfg, worker_index, &senders, peer, &data, start);
                    continue;
                }
            };
            match monoio::net::udp::UdpSocket::from_std(handoff.socket) {
                Ok(sock) => {
                    let driver = Conn::new(handoff.conn, sock);
                    let cfg2 = cfg.clone();
                    tasks.push(monoio::spawn(async move {
                        established_conn_task(driver, cfg2, start).await
                    }));
                }
                Err(e) => eprintln!("[bench-monoio] acceptor {worker_index}: handoff register {e}"),
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

fn admit(
    peers: &mut HashMap<SocketAddr, PeerEntry>,
    cfg: &LossConfig,
    worker_index: usize,
    senders: &[mpsc::Sender<WorkerMessage>],
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
            COOKIE_FORWARD_COUNT.fetch_add(1, Ordering::Relaxed);
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
                PROMOTED_DUP_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                ORPHAN_CONCLUSION_COUNT.fetch_add(1, Ordering::Relaxed);
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
    /// this ever connected" (see mio's/tokio's/smol's identical pattern).
    stream_deadline: Option<Instant>,
    data_events: u64,
    last_data_at: Instant,
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
    peer: SocketAddr,
    pending_conn: SrtConnection,
    owner: usize,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let std_socket = match srt_transport::bind_reuseport(port) {
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
        HANDOFF_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Steady-state loop for one promoted (already-connected) connection,
/// running as its own `monoio::spawn`'d task -- monoio's ordinary
/// task-per-connection idiom, same as the `PerPort` path above, just fed
/// a socket that admission already connected instead of discovering the
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

        // Fresh buffer per attempt -- same reasoning as `sender_task`:
        // io_uring ops can't be safely cancelled mid-flight.
        if let Ok((Ok(n), buf)) =
            monoio::time::timeout(crate::MAX_WAIT, driver.sock.recv(vec![0u8; 2048])).await
        {
            let t = crate::now_ts(start);
            let _ = driver.conn.feed_recv_buf(&buf[..n], t);
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
                    eprintln!("[bench-monoio] disconnected: {reason}");
                    connected = false;
                }
                ConnectionEvent::Error(msg) => eprintln!("[bench-monoio] error: {msg}"),
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
