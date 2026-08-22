//! tokio adapter: task-per-connection via `tokio::task::spawn_local` on a
//! `current_thread` runtime + `LocalSet` (Conn's native timers are !Send).
//! Native `tokio::time::Sleep` timers live inside `srt_transport`'s Conn.
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
//! mechanism. *Within* each acceptor thread, though, steady-state I/O for
//! every promoted connection is an ordinary `spawn_local` task, exactly
//! like the `PerPort` path below -- letting tokio's own scheduler and
//! wakers drive concurrent connections is tokio's designed idiom, not
//! something to route around. Only *admission* is deterministic; per-
//! connection steady state is not.

use crate::{Aggregate, BondMode, ConnStats, GroupRegistry, LossConfig};
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, GroupExtensionData, GroupType, SRTGROUP_MASK, SrtConnection,
};
use srt_transport::tokio_transport::Conn;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
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

fn set_sock_bufs(fd: i32) -> std::io::Result<()> {
    const SOCK_BUF_BYTES: usize = 16 << 20;
    let v = SOCK_BUF_BYTES as libc::c_int;
    let len = std::mem::size_of_val(&v) as libc::socklen_t;
    unsafe {
        let r = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &v as *const _ as *const libc::c_void,
            len,
        );
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let r = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &v as *const _ as *const libc::c_void,
            len,
        );
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn bind_reuseport(port: u16) -> std::io::Result<std::net::UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
    sock.bind(&addr.into())?;
    let _ = set_sock_bufs(sock.as_raw_fd());
    Ok(sock.into())
}

fn run_reuseport_multi(cfg: LossConfig, k: usize) {
    let worker_count = k.min(cfg.connections);
    let start = Instant::now();
    println!("LISTENING");
    let group_registry: GroupRegistry = Arc::new(Mutex::new(HashMap::new()));

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
        let registry = group_registry.clone();
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
                        registry,
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
/// listener socket, drives them to `Connected`, promotes each to a
/// dedicated connected socket, and either spawns a local steady-state
/// task for it (owns the group, or unbonded) or ships it once to the
/// thread that does. Once admission winds down (no pending handshakes
/// past the connect window), it just awaits every task it spawned or
/// received and returns their stats -- steady state is no longer this
/// function's concern once a task exists for it.
async fn run_acceptor(
    cfg: LossConfig,
    worker_index: usize,
    start: Instant,
    group_registry: GroupRegistry,
    senders: Vec<mpsc::Sender<WorkerMessage>>,
    handoffs: mpsc::Receiver<WorkerMessage>,
) -> Vec<ConnStats> {
    let std_listener = match bind_reuseport(cfg.port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-tokio] acceptor {worker_index}: bind {e}");
            return Vec::new();
        }
    };
    let listener = tokio::net::UdpSocket::from_std(std_listener).expect("register listener");

    let mut pending: HashMap<SocketAddr, PendingEntry> = HashMap::new();
    let mut tasks: Vec<tokio::task::JoinHandle<ConnStats>> = Vec::new();
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    // Admission-phase safety net only -- once a connection is promoted it
    // becomes an independent task with its own lifetime, not this loop's
    // problem. Pending entries are individually bounded below, so this
    // should never actually fire; kept as cheap insurance.
    let run_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT + Duration::from_secs(30);
    let mut tick = tokio::time::interval(TIMER_TICK);
    let mut buf = [0u8; 2048];

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        if now >= connect_deadline && pending.is_empty() {
            break;
        }

        tokio::select! {
            res = listener.recv_from(&mut buf) => {
                if let Ok((n, peer)) = res {
                    admit(&mut pending, &cfg, peer, &buf[..n], start);
                    loop {
                        match listener.try_recv_from(&mut buf) {
                            Ok((n, peer)) => admit(&mut pending, &cfg, peer, &buf[..n], start),
                            Err(_) => break,
                        }
                    }
                }
            }
            _ = tick.tick() => {}
        }

        // Drive pending handshakes toward Connected, then promote. A
        // handshake stale past the connect window is dropped -- whatever
        // the cause, it's never going to promote and must not block this
        // acceptor's exit condition forever.
        let t = crate::now_ts(start);
        let mut promote_list = Vec::new();
        let mut stale = Vec::new();
        for (peer, p) in pending.iter_mut() {
            if p.created_at.elapsed() >= crate::INTEROP_CONNECT_TIMEOUT {
                stale.push(*peer);
                continue;
            }
            p.timers.fire_expired(t, &mut p.conn);
            let refused =
                drain_pending_outputs(&mut p.conn, &mut p.timers, &listener, *peer, t).await;
            if refused {
                stale.push(*peer);
                continue;
            }
            while let Some(ev) = p.conn.poll_event() {
                if matches!(ev, ConnectionEvent::Connected) {
                    p.connected = true;
                }
            }
            if p.connected {
                promote_list.push(*peer);
            }
        }
        for peer in stale {
            pending.remove(&peer);
        }
        for peer in promote_list {
            let Some(p) = pending.remove(&peer) else {
                continue;
            };
            let group_id = p.conn.peer_group_extension().map(|g| g.group_id);
            promote(
                cfg.port,
                peer,
                p.conn,
                group_id,
                &group_registry,
                worker_index,
                &senders,
                &mut tasks,
                &cfg,
                start,
            );
        }

        // Bond legs promoted on other acceptors that belong here.
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

    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(stats) = task.await {
            results.push(stats);
        }
    }
    results
}

fn admit(
    pending: &mut HashMap<SocketAddr, PendingEntry>,
    cfg: &LossConfig,
    peer: SocketAddr,
    data: &[u8],
    start: Instant,
) {
    let t = crate::now_ts(start);
    let entry = pending.entry(peer).or_insert_with(|| PendingEntry {
        conn: SrtConnection::new_listener(ConnectionOptions {
            socket_id: std::process::id(),
            tsbpd_delay: cfg.latency_ms,
            ..Default::default()
        }),
        timers: srt_transport::ManualTimerStore::new(),
        connected: false,
        created_at: Instant::now(),
    });
    let _ = entry.conn.feed_recv_buf(data, t);
}

/// One in-flight handshake, keyed by peer tuple in `run_acceptor`'s
/// `pending` map. Module-scoped (not local to `run_acceptor`) only
/// because `admit` needs to name the type in its signature.
struct PendingEntry {
    conn: SrtConnection,
    timers: srt_transport::ManualTimerStore,
    connected: bool,
    created_at: Instant,
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

#[allow(clippy::too_many_arguments)]
fn promote(
    port: u16,
    peer: SocketAddr,
    pending_conn: SrtConnection,
    group_id: Option<u32>,
    group_registry: &GroupRegistry,
    worker_index: usize,
    senders: &[mpsc::Sender<WorkerMessage>],
    tasks: &mut Vec<tokio::task::JoinHandle<ConnStats>>,
    cfg: &LossConfig,
    start: Instant,
) {
    let std_socket = match bind_reuseport(port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-tokio] promote {peer}: bind {e}");
            return;
        }
    };
    if std_socket.connect(peer).is_err() {
        eprintln!("[bench-tokio] promote {peer}: connect failed");
        return;
    }

    // Bond affinity: first acceptor to promote a group owns it. A leg
    // that landed here but belongs to another owner is promoted anyway
    // (so the kernel 4-tuple demux is correct), then shipped once.
    if let Some(group_id) = group_id {
        let owner = {
            let mut registry = match group_registry.lock() {
                Ok(r) => r,
                Err(_) => return,
            };
            *registry.entry(group_id).or_insert(worker_index)
        };
        if owner != worker_index {
            let message = WorkerMessage::Handoff(Box::new(Handoff {
                socket: std_socket,
                conn: pending_conn,
            }));
            if senders[owner].send(message).is_err() {
                eprintln!("[bench-tokio] promote {peer}: owner {owner} channel closed");
            } else {
                HANDOFF_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    }

    let Ok(tokio_socket) = tokio::net::UdpSocket::from_std(std_socket) else {
        eprintln!("[bench-tokio] promote {peer}: register failed");
        return;
    };
    let driver = Conn::new(pending_conn, tokio_socket);
    let cfg = cfg.clone();
    tasks.push(tokio::task::spawn_local(async move {
        established_conn_task(driver, cfg, start).await
    }));
}

/// Steady-state loop for one promoted (already-connected) connection,
/// running as its own `spawn_local` task -- tokio's ordinary
/// task-per-connection idiom, same as the `PerPort` path above, just fed
/// a socket that admission already connected instead of discovering the
/// peer itself.
async fn established_conn_task(mut driver: Conn, cfg: LossConfig, start: Instant) -> ConnStats {
    let mut connected = true;
    let mut data_events = 0u64;
    let stream_deadline = Instant::now() + Duration::from_secs_f64(cfg.duration_secs);
    let mut last_data_at = Instant::now();
    let mut buf = [0u8; 2048];

    loop {
        let now = Instant::now();
        if !connected
            || now >= stream_deadline
            || now.saturating_duration_since(last_data_at) >= IDLE_GRACE
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
        connected,
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
