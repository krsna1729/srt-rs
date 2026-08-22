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

use crate::{Aggregate, BondMode, ConnStats, LossConfig};
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, GroupExtensionData, GroupType, SRTGROUP_MASK, SrtConnection,
};
use srt_transport::tokio_transport::Conn;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How long a connected task may go without a datagram from its peer
/// before it's retired as stalled. Mirrors mio's `IDLE_GRACE`.
const IDLE_GRACE: Duration = Duration::from_secs(10);
const TIMER_TICK: Duration = Duration::from_millis(10);

/// Diagnostic counter: bond legs actually shipped cross-thread via the
/// handoff channel. See `run_reuseport_multi`'s shutdown log.
static HANDOFF_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn run(cfg: LossConfig) {
    if cfg.mode == crate::Mode::Receiver
        && cfg.connections > 1
        && let crate::Ingress::ReuseportMulti(k) = cfg.ingress
        && k > 1
    {
        return run_reuseport_multi(cfg, k);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current_thread runtime");
    rt.block_on(tokio::task::LocalSet::new().run_until(drive(cfg)));
}

async fn drive(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-tokio] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }

    let mut handles = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let endpoint = cfg.addr_for(i);
        let c2 = cfg.clone();
        handles.push(tokio::task::spawn_local(async move {
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
    driver.drain_outputs(crate::now_ts(start)).await;

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
                    eprintln!("[bench-tokio] disconnected: {reason}");
                    stream_deadline = Some(Instant::now());
                }
                ConnectionEvent::Error(msg) => {
                    eprintln!("[bench-tokio] error: {msg}");
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
        if let Some(d) = stream_deadline
            && Instant::now() >= d
        {
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

            loop {
                match driver.sock.try_recv(&mut buf) {
                    Ok(n) => {
                        let t = crate::now_ts(start);
                        let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                    }
                    Err(_) => break,
                }
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
                ConnectionEvent::DataReceived { .. } => {
                    stats.data_events += 1;
                }
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-tokio] disconnected: {reason}");
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

/// A connected socket + protocol state shipped from the acceptor that
/// completed its handshake to the thread that owns its bond group. Ships
/// the raw `std::net::UdpSocket` (plain, `Send`) rather than a
/// `tokio_transport::Conn` (whose native timer future is `!Send`) --
/// the receiving thread reconstructs `Conn` locally after registering the
/// socket with its own runtime.
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
    let handoffs = HANDOFF_COUNT.load(Ordering::Relaxed);
    if handoffs > 0 {
        eprintln!("[bench-tokio] pool receiver: {handoffs} bond handoffs");
    }
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
            eprintln!("[bench-tokio] acceptor {worker_index}: bind {e}");
            return Vec::new();
        }
    };
    let listener = tokio::net::UdpSocket::from_std(std_listener).expect("register listener");

    let mut peers: HashMap<SocketAddr, PeerEntry> = HashMap::new();
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

        tokio::select! {
            res = listener.recv_from(&mut buf) => {
                if let Ok((n, peer)) = res {
                    admit(&mut peers, &cfg, peer, &buf[..n], start);
                    loop {
                        match listener.try_recv_from(&mut buf) {
                            Ok((n, peer)) => admit(&mut peers, &cfg, peer, &buf[..n], start),
                            Err(_) => break,
                        }
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
        let mut relocate: Vec<(SocketAddr, GroupExtensionData)> = Vec::new();
        for (peer, p) in peers.iter_mut() {
            p.timers.fire_expired(t, &mut p.conn);
            let _ = drain_pending_outputs(&mut p.conn, &mut p.timers, &listener, *peer, t).await;
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
                if let Some(extension) = p.conn.peer_group_extension() {
                    relocate.push((*peer, extension));
                }
            }
        }
        for (peer, extension) in relocate {
            let group = srt_lifecycle::GroupAffinity {
                group_id: extension.group_id,
                stream_id: None,
                extension,
            };
            let owner = {
                let mut router = match router.lock() {
                    Ok(r) => r,
                    Err(_) => continue, // poisoned: leave the leg where it landed
                };
                router.assign(peer, Some(group), srt_lifecycle::RoutingMode::LeastTuples)
            };
            if owner != worker_index {
                let Some(p) = peers.remove(&peer) else {
                    continue;
                };
                relocate_to_owner(cfg.port, peer, p.conn, owner, &senders);
            }
        }

        // Bond legs relocated here from another acceptor.
        while let Ok(WorkerMessage::Handoff(handoff)) = handoffs.try_recv() {
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
    /// this ever connected" (see mio's identical pattern).
    stream_deadline: Option<Instant>,
    data_events: u64,
    last_data_at: Instant,
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
    peer: SocketAddr,
    pending_conn: SrtConnection,
    owner: usize,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let std_socket = match srt_transport::bind_reuseport(port) {
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
        HANDOFF_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Steady-state loop for one promoted (already-connected) connection,
/// running as its own `spawn_local` task -- tokio's ordinary
/// task-per-connection idiom, same as the `PerPort` path above, just fed
/// a socket that admission already connected instead of discovering the
/// peer itself.
async fn established_conn_task(mut driver: Conn, cfg: LossConfig, start: Instant) -> ConnStats {
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
    let mut data_events = 0u64;
    let stream_deadline = Instant::now() + Duration::from_secs_f64(cfg.duration_secs);
    let mut last_data_at = Instant::now();
    let mut buf = [0u8; 2048];
    // This task is only ever spawned post-Connected, so `connect_deadline`
    // (srt_lifecycle::is_terminal's other exit path, for "never
    // connected") never applies -- pass `now` for it so it's inert.

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
        loop {
            match driver.sock.try_recv(&mut buf) {
                Ok(n) => {
                    let t = crate::now_ts(start);
                    let _ = driver.conn.feed_recv_buf(&buf[..n], t);
                    data_events += 1;
                    last_data_at = Instant::now();
                }
                Err(_) => break,
            }
        }

        let t = crate::now_ts(start);
        driver.fire_expired();
        driver.drain_outputs(t).await;

        while let Some(ev) = driver.conn.poll_event() {
            match ev {
                ConnectionEvent::Disconnected { reason } => {
                    eprintln!("[bench-tokio] disconnected: {reason}");
                    connected = false;
                }
                ConnectionEvent::Error(msg) => eprintln!("[bench-tokio] error: {msg}"),
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
