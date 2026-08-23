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
//! bench.sh's 8Mbps/conn -- at N=25 the listener took only 49.1% of what
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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected peer may go without a datagram from its peer
/// before it's retired as stalled. Mirrors the other backends' `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

/// Diagnostic counter: bond legs actually shipped cross-thread via the
/// handoff channel. See `run_reuseport_multi`'s shutdown log.
static HANDOFF_COUNT: AtomicU64 = AtomicU64::new(0);

/// Diagnostic counter: connections promoted to their own socket + task on
/// this same acceptor thread (`--promote-all`). Distinct from
/// `HANDOFF_COUNT`, which counts only cross-thread bond relocations.
static PROMOTION_COUNT: AtomicU64 = AtomicU64::new(0);

/// Give one established connection its own connected socket, so the kernel
/// matches its packets by exact 4-tuple and an independent task can drive
/// it instead of the shared per-peer maintenance loop. `None` if the
/// socket could not be created.
fn promote_locally(port: u16, peer: SocketAddr, conn: SrtConnection) -> Option<Conn> {
    let std_socket = srt_transport::bind_reuseport(port).ok()?;
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
    let rt = compio::runtime::Runtime::builder()
        .build()
        .expect("compio runtime");
    rt.block_on(drive(cfg));
}

async fn drive(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-compio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(compio::runtime::spawn(async move {
            match c2.mode {
                crate::Mode::Sender => sender_task(c2, i, endpoint, start).await,
                crate::Mode::Receiver => receiver_task(c2, endpoint.port(), start).await,
            }
        }));
    }

    let mut agg = Aggregate::new(cfg.clone());
    for h in handles {
        if let Ok(stats) = h.await {
            agg.add(stats);
        }
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

/// A connected socket + protocol state shipped from the acceptor that
/// completed its handshake to the thread that owns its bond group. Ships
/// the raw `std::net::UdpSocket` (plain, `Send`) rather than a
/// `compio_transport::Conn` (whose native timer future is `!Send`) -- the
/// receiving thread reconstructs `Conn` locally after re-registering the
/// socket with its own runtime via `UdpSocket::from_std`.
struct Handoff {
    socket: std::net::UdpSocket,
    conn: SrtConnection,
}

enum WorkerMessage {
    Handoff(Box<Handoff>),
}

fn run_reuseport_multi(cfg: LossConfig, k: usize) {
    let worker_count = k.min(cfg.connections);
    let start = Instant::now();
    println!("LISTENING");
    let router: crate::SharedWorkerRouter =
        Arc::new(Mutex::new(srt_lifecycle::WorkerRouter::new(worker_count)));

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
    eprintln!(
        "[bench-compio] pool receiver: {promotions} local promotions, {handoffs} bond handoffs"
    );
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
) -> Vec<ConnStats> {
    let std_listener = match srt_transport::bind_reuseport(cfg.port) {
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

    let promote_everyone = cfg.promote_all;
    let mut peers: HashMap<SocketAddr, PeerEntry> = HashMap::new();
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

        compio::time::sleep(TIMER_TICK).await;
        while let Ok((peer, data)) = inbox_rx.try_recv() {
            admit(&mut peers, &cfg, peer, &data, start);
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
            // An unbonded connection has no group affinity to honor, so it
            // stays on whichever acceptor the kernel gave it; a bonded leg
            // asks the router where its group already lives.
            let owner = match extension {
                Some(extension) => {
                    let group = srt_lifecycle::GroupAffinity {
                        group_id: extension.group_id,
                        stream_id: None,
                        extension,
                    };
                    match router.lock() {
                        Ok(mut router) => router.assign(
                            peer,
                            Some(group),
                            srt_lifecycle::RoutingMode::LeastTuples,
                        ),
                        Err(_) => worker_index, // poisoned: leave it here
                    }
                }
                None => worker_index,
            };

            if owner != worker_index {
                let Some(p) = peers.remove(&peer) else {
                    continue;
                };
                relocate_to_owner(cfg.port, peer, p.conn, owner, &senders);
            } else if promote_everyone {
                // See `LossConfig::promote_all`: give this connection its
                // own socket and task so the runtime's scheduler drives it
                // independently of the shared per-peer loop.
                let Some(p) = peers.remove(&peer) else {
                    continue;
                };
                match promote_locally(cfg.port, peer, p.conn) {
                    Some(driver) => {
                        let cfg2 = cfg.clone();
                        tasks.push(compio::runtime::spawn(async move {
                            established_conn_task(driver, cfg2, start).await
                        }));
                        PROMOTION_COUNT.fetch_add(1, Ordering::Relaxed);
                    }
                    None => eprintln!("[bench-compio] promote {peer}: failed"),
                }
            }
        }

        // Bond legs relocated here from another acceptor.
        while let Ok(WorkerMessage::Handoff(handoff)) = handoffs.try_recv() {
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

fn admit(
    peers: &mut HashMap<SocketAddr, PeerEntry>,
    cfg: &LossConfig,
    peer: SocketAddr,
    data: &[u8],
    start: Instant,
) {
    let t = crate::now_ts(start);
    let entry = peers.entry(peer).or_insert_with(|| PeerEntry {
        conn: SrtConnection::new_listener(ConnectionOptions {
            socket_id: std::process::id(),
            tsbpd_delay: cfg.latency_ms,
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
    peer: SocketAddr,
    pending_conn: SrtConnection,
    owner: usize,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let std_socket = match srt_transport::bind_reuseport(port) {
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
        HANDOFF_COUNT.fetch_add(1, Ordering::Relaxed);
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
        driver.fire_expired();
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
