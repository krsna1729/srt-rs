//! mio adapter: flat single-threaded epoll loop over all sockets — mio's
//! designed primitive (no task model, no native timer wheel; timers are
//! `ManualTimerStore` inside Conn). Connection i lives on port + i, each
//! registered with Token(i).

use crate::{Aggregate, BondMode, ConnStats, GroupRegistry, LossConfig};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, GroupExtensionData, GroupType, SRTGROUP_MASK, SrtConnection,
};
use srt_transport::mio_transport::Conn;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// Upper bound on the poll timeout so the loop still notices deadlines
/// promptly when idle.
const MAX_POLL_WAIT: Duration = Duration::from_millis(20);

/// Poll tick for receivers: matches the 10ms ACK timer cadence so timers
/// are serviced on schedule without busy-polling.
const TIMER_TICK: Duration = Duration::from_millis(10);

/// Target 16 MB per socket. The protocol stack sets SO_RCVBUF/SO_SNDBUF
/// explicitly on every socket it owns (never via sysctl) and reads back
/// the effective value -- Linux doubles the request and clamps to
/// net.core.rmem_max, so the granted size can be smaller than asked.
const SOCK_BUF_BYTES: usize = 16 << 20;

fn set_sock_bufs(fd: i32) -> std::io::Result<()> {
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
        // Verify effective value (Linux doubles and clamps).
        let mut got: libc::c_int = 0;
        let mut got_len = std::mem::size_of_val(&got) as libc::socklen_t;
        let r = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut got as *mut _ as *mut libc::c_void,
            &mut got_len,
        );
        if r == 0 && (got as usize) < SOCK_BUF_BYTES {
            eprintln!(
                "SO_RCVBUF clamped by host to {} (requested {})",
                got, SOCK_BUF_BYTES
            );
        }
    }
    Ok(())
}

/// Batched receive for a bound UDP socket: up to `bufs.len()` datagrams in
/// one `recvmmsg` syscall. Returns count received; `addrs[i]` holds
/// each sender, `sizes[i]` the length. Buffers are hoisted by the caller
/// and reused -- zero per-call allocation. One syscall for up to 32
/// datagrams vs one per datagram before.
fn recvmsg_batch(
    fd: std::os::fd::RawFd,
    bufs: &mut [Vec<u8>],
    sizes: &mut [usize],
    addrs: &mut [Option<std::net::SocketAddr>],
) -> usize {
    use std::cell::RefCell;
    thread_local! {
        static SCRATCH: RefCell<BatchScratch> = RefCell::new(BatchScratch::new(64));
    }
    struct BatchScratch {
        msgs: Vec<libc::mmsghdr>,
        iovs: Vec<libc::iovec>,
        addrs: Vec<libc::sockaddr_storage>,
    }
    impl BatchScratch {
        fn new(n: usize) -> Self {
            Self {
                msgs: (0..n)
                    .map(|_| libc::mmsghdr {
                        msg_hdr: unsafe { std::mem::zeroed() },
                        msg_len: 0,
                    })
                    .collect(),
                iovs: (0..n)
                    .map(|_| libc::iovec {
                        iov_base: std::ptr::null_mut(),
                        iov_len: 0,
                    })
                    .collect(),
                addrs: (0..n).map(|_| unsafe { std::mem::zeroed() }).collect(),
            }
        }
    }
    let count = bufs.len();
    SCRATCH.with(|scratch| {
        let BatchScratch {
            msgs,
            iovs,
            addrs: storage_addrs,
        } = &mut *scratch.borrow_mut();
        for (((iov, msg), storage), (buf, size)) in iovs
            .iter_mut()
            .zip(msgs.iter_mut())
            .zip(storage_addrs.iter_mut())
            .zip(bufs.iter_mut().zip(sizes.iter_mut()))
        {
            buf.resize(buf.capacity(), 0);
            *size = 0;
            *iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.capacity(),
            };
            msg.msg_hdr.msg_iov = iov;
            msg.msg_hdr.msg_iovlen = 1;
            msg.msg_hdr.msg_name = (storage as *mut libc::sockaddr_storage).cast();
            msg.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            msg.msg_len = 0;
        }
        let received = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                count as u32,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if received < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                use std::sync::atomic::{AtomicBool, Ordering};
                static LOGGED: AtomicBool = AtomicBool::new(false);
                if !LOGGED.swap(true, Ordering::Relaxed) {
                    eprintln!("recvmmsg failed once: {err} (fd={fd}, count={count})");
                }
            }
            return 0;
        }
        for i in 0..received as usize {
            addrs[i] = unsafe { sockaddr_to_addr(&storage_addrs[i]) };
            sizes[i] = msgs[i].msg_len as usize;
        }
        received as usize
    })
}

unsafe fn sockaddr_to_addr(storage: &libc::sockaddr_storage) -> Option<std::net::SocketAddr> {
    if storage.ss_family != libc::AF_INET as u16 {
        return None;
    }
    let addr = unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
    Some(std::net::SocketAddr::from((
        std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    )))
}

/// Drain one socket for admission, calling `on_datagram(peer, data)` for
/// each queued datagram -- either batched (`recvmmsg`, one syscall for up
/// to `admit_bufs.len()` datagrams) or one `recv_from` syscall per
/// datagram, per `LossConfig::batching`. This is the axis `Batching`
/// exists to let a run select: isolating whatever win (or lack of one)
/// batched admission gives at a given fan-in level from every other
/// variable. Shared by every ingress strategy that has a socket serving
/// more than one peer at once (`SharedPool`, `ReuseportMulti`,
/// `ReuseportSingle`) -- `PerPort` never shares a socket, so batching
/// doesn't apply there.
#[allow(clippy::too_many_arguments)]
fn drain_admission(
    listener: &UdpSocket,
    batching: crate::Batching,
    admit_bufs: &mut [Vec<u8>],
    admit_sizes: &mut [usize],
    admit_addrs: &mut [Option<SocketAddr>],
    buf: &mut [u8],
    mut on_datagram: impl FnMut(SocketAddr, &[u8]),
) {
    match batching {
        crate::Batching::On => loop {
            let fd = listener.as_raw_fd();
            let received = recvmsg_batch(fd, admit_bufs, admit_sizes, admit_addrs);
            if received == 0 {
                break;
            }
            for i in 0..received {
                if let Some(peer) = admit_addrs[i] {
                    on_datagram(peer, &admit_bufs[i][..admit_sizes[i]]);
                }
            }
            if received < admit_bufs.len() {
                break;
            }
        },
        crate::Batching::Off => loop {
            match listener.recv_from(buf) {
                Ok((n, peer)) => on_datagram(peer, &buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        },
    }
}

pub fn run(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
    }
    // Single-port fan-in via SO_REUSEPORT + kernel sharding. This is the
    // production-like case (one SRT listener port, many callers) where a
    // single acceptor saturates at ~1200 concurrent handshakes.
    // ReuseportMulti(K) creates K acceptor sockets on the base port, each
    // in its own thread, with a shared GroupRegistry for bond affinity
    // (first leg to promote claims the group; later legs hand off via
    // mpsc once, never per-packet).
    if cfg.mode == crate::Mode::Receiver && cfg.connections > 1 {
        match cfg.ingress {
            crate::Ingress::ReuseportMulti(k) if k > 1 => {
                return run_pool_receiver(cfg, k);
            }
            crate::Ingress::SharedPool(k) if k > 1 => {
                return run_shared_pool(cfg, k);
            }
            crate::Ingress::ReuseportSingle { workers } if workers >= 1 => {
                return run_reuseport_single(cfg, workers);
            }
            _ => {}
        }
    }
    if cfg.connections > 1 {
        match cfg.ingress {
            crate::Ingress::ReuseportMulti(k) if cfg.mode == crate::Mode::Sender && k > 1 => {
                eprintln!(
                    "[bench-mio] scale: single port {} (reuseport-multi={k})",
                    cfg.port
                );
            }
            crate::Ingress::ReuseportSingle { workers } if cfg.mode == crate::Mode::Sender => {
                eprintln!(
                    "[bench-mio] scale: single port {} (reuseport-single, {workers} workers)",
                    cfg.port
                );
            }
            crate::Ingress::SharedPool(k) if cfg.mode == crate::Mode::Sender && k > 1 => {
                eprintln!(
                    "[bench-mio] scale: shared-pool ports {}-{}",
                    cfg.port,
                    cfg.port + k as u16 - 1
                );
            }
            _ => {
                eprintln!(
                    "[bench-mio] scale: ports {}-{}",
                    cfg.port,
                    cfg.port + cfg.connections as u16 - 1
                );
            }
        }
    }

    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(4096);

    struct Driver {
        conn: Conn,
        connected: bool,
        stream_deadline: Option<Instant>,
        data_events: u64,
        peer: Option<SocketAddr>,
        poisoned: bool,
    }

    let mut drivers: Vec<Driver> = Vec::with_capacity(cfg.connections);
    for i in 0..cfg.connections {
        let addr = cfg.addr_for(i);
        let mut socket = match cfg.mode {
            crate::Mode::Sender => {
                let s = UdpSocket::bind("0.0.0.0:0".parse().unwrap()).expect("bind");
                s.connect(addr).expect("connect");
                s
            }
            crate::Mode::Receiver => UdpSocket::bind(addr).expect("bind"),
        };
        let _ = set_sock_bufs(socket.as_raw_fd());
        poll.registry()
            .register(&mut socket, Token(i), Interest::READABLE)
            .expect("register socket");

        // Bond exercise: connections 2g/2g+1 (for g in 0..bond_pairs) share
        // a group id, proving the reuseport receiver's registry/handoff
        // path actually fires in a run instead of sitting dead.
        // Sender-only -- the listener learns the group (and its type)
        // from the caller's handshake extension (`peer_group_extension`).
        let group_extension = if cfg.mode == crate::Mode::Sender
            && cfg.bond_mode != BondMode::None
            && i < cfg.bond_pairs * 2
        {
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
        } else {
            None
        };
        let options = ConnectionOptions {
            socket_id: std::process::id(),
            tsbpd_delay: cfg.latency_ms,
            max_bandwidth_bytes_per_sec: match cfg.mode {
                crate::Mode::Sender => Some(cfg.bitrate_bps / 8),
                crate::Mode::Receiver => None,
            },
            group_extension,
            ..Default::default()
        };
        let conn = match cfg.mode {
            crate::Mode::Sender => {
                let mut c = SrtConnection::new_caller(options);
                c.connect(crate::now_ts(start))
                    .expect("connect() should queue INDUCTION");
                c
            }
            crate::Mode::Receiver => SrtConnection::new_listener(options),
        };
        let mut driver = Conn::new(conn, socket);
        let refused = driver.drain_outputs(crate::now_ts(start));
        drivers.push(Driver {
            conn: driver,
            connected: false,
            stream_deadline: None,
            data_events: 0,
            peer: None,
            poisoned: refused,
        });
    }

    // Senders stream at the target bitrate once connected.
    let payload = vec![0x42u8; crate::PAYLOAD_SIZE];
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let mut buf = [0u8; 2048];

    loop {
        if !drivers.iter().any(|d| d.connected) && Instant::now() >= connect_deadline {
            eprintln!("[bench-mio] connect timed out");
            break;
        }
        let all_done = drivers.iter().all(|d| d.connected)
            && drivers.iter().all(|d| {
                d.stream_deadline
                    .map(|dl| Instant::now() >= dl)
                    .unwrap_or(false)
            });
        if all_done {
            break;
        }

        let mut poll_wait = TIMER_TICK;
        // Senders know exactly when their next paced packet is due; use the
        // tightest deadline across them so pacing doesn't quantize to the
        // tick. Receivers just ride the tick (ACK timer is 10ms).
        if cfg.mode == crate::Mode::Sender {
            let t = crate::now_ts(start);
            let min_wait = drivers
                .iter()
                .filter(|d| d.connected)
                .map(|d| Duration::from_micros(d.conn.conn.time_until_send(t)).min(MAX_POLL_WAIT))
                .min()
                .unwrap_or(MAX_POLL_WAIT);
            poll_wait = poll_wait.min(min_wait);
        }
        poll.poll(&mut events, Some(poll_wait)).ok();
        let woke_from_timeout = events.is_empty();

        let mut touched = [false; 4096];
        for event in events.iter() {
            let idx = event.token().0;
            if idx >= touched.len() || drivers.get_mut(idx).is_none() {
                continue;
            }
            touched[idx] = true;
            let d = &mut drivers[idx];
            if d.peer.is_none() && cfg.mode == crate::Mode::Receiver {
                // Unconnected phase: first datagram reveals the caller.
                // Connect before anything else -- drain_outputs uses
                // connected send(), which fails silently otherwise.
                match d.conn.socket.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        if d.conn.socket.connect(addr).is_ok() {
                            d.peer = Some(addr);
                            let t = crate::now_ts(start);
                            let _ = d.conn.conn.feed_recv_buf(&buf[..n], t);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        eprintln!("[bench-mio] recv error: {e}");
                    }
                }
            } else {
                loop {
                    match d.conn.socket.recv(&mut buf) {
                        Ok(n) => {
                            let t = crate::now_ts(start);
                            let _ = d.conn.conn.feed_recv_buf(&buf[..n], t);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                            d.poisoned = true;
                            break;
                        }
                        Err(e) => {
                            eprintln!("[bench-mio] recv error conn {}: {e}", idx);
                            break;
                        }
                    }
                }
            }
        }
        // Proactive poison clear: a connected UDP socket stays poisoned
        // for both send and recv until reconnect. Scan all drivers every
        // iteration (not just due ones) so handshake retransmits don't
        // stall. The existing handshake timer (250 ms) will fire soon
        // after reconnect and retransmit.
        for (idx, d) in drivers.iter_mut().enumerate() {
            if d.poisoned {
                let dst = if let Some(peer) = d.peer {
                    peer
                } else if cfg.mode == crate::Mode::Sender {
                    cfg.addr_for(idx)
                } else {
                    continue;
                };
                let _ = d.conn.socket.connect(dst);
                d.poisoned = false;
            }
        }

        // Protocol maintenance. Timer scans are O(armed timers) per driver,
        // so at hundreds of connections only sweep drivers that saw traffic
        // this pass -- plus a full sweep whenever the poll went idle (which
        // happens at least once per TIMER_TICK, keeping 10ms timers honest).
        let t = crate::now_ts(start);
        for (idx, d) in drivers.iter_mut().enumerate() {
            if woke_from_timeout || touched.get(idx).copied().unwrap_or(false) {
                d.conn.fire_expired(t);
            }
            if d.conn.drain_outputs(t) {
                d.poisoned = true;
            }

            while let Some(ev) = d.conn.conn.poll_event() {
                match ev {
                    ConnectionEvent::Connected => {
                        d.connected = true;
                        d.stream_deadline =
                            Some(Instant::now() + Duration::from_secs_f64(cfg.duration_secs));
                        if cfg.verbose() {
                            println!("CONNECTED");
                        } else {
                            eprintln!("[bench-mio] scale conn {idx} CONNECTED");
                        }
                    }
                    ConnectionEvent::DataReceived { .. } => {
                        d.data_events += 1;
                    }
                    ConnectionEvent::Disconnected { reason } => {
                        eprintln!("[bench-mio] disconnected: {reason}");
                        d.stream_deadline = Some(Instant::now());
                    }
                    ConnectionEvent::Error(msg) => {
                        eprintln!("[bench-mio] error: {msg}");
                    }
                    _ => {}
                }
            }

            if d.connected && cfg.mode == crate::Mode::Sender {
                loop {
                    let t = crate::now_ts(start);
                    if !d.conn.conn.can_send_with_pacing(t) {
                        break;
                    }
                    if d.conn.conn.send(&payload, t).is_err() {
                        break;
                    }
                    d.data_events += 1;
                    if d.conn.drain_outputs(t) {
                        d.poisoned = true;
                    }
                }
            }
        }
    }

    let mut agg = Aggregate::new(cfg.clone());
    for d in drivers {
        let mut s = ConnStats {
            connected: d.connected,
            data_events: d.data_events,
            ..Default::default()
        };
        match cfg.mode {
            crate::Mode::Sender => {
                if let Some(st) = d.conn.conn.sender_stats() {
                    s.has_stats = true;
                    s.core_total = st.total_sent;
                    s.secondary_a = st.total_retransmits as u64;
                    s.secondary_b = st.packets_in_loss_list as u64;
                }
            }
            crate::Mode::Receiver => {
                if let Some(st) = d.conn.conn.receiver_stats() {
                    s.has_stats = true;
                    s.core_total = st.total_received;
                    s.secondary_a = st.total_lost;
                    s.secondary_b = st.total_duplicates;
                    s.rtt_us = st.rtt as u64;
                }
            }
        }
        agg.add(s);
    }
    agg.print(start);

    if !agg.any_connected {
        std::process::exit(1);
    }
}

/// #2 -- shared pool, no promotion: K real, distinct, plainly-bound
/// listener ports (no SO_REUSEPORT). Every one stays unconnected for its
/// whole life; connections `i` and `i+K`, `i+2K`, ... share socket `i % K`
/// and are distinguished purely by peer address (`recv_from` + a
/// `SocketAddr -> connection` lookup, `send_to` for output). Single
/// thread, no promotion step -- this isolates "fewer wakeups from fewer
/// sockets" from `ReuseportMulti`'s "kernel-level demux after a one-time
/// promotion cost." Receiver-only: a sender just dials the port
/// `addr_for` already computes for it and otherwise behaves exactly like
/// `PerPort` (own local socket per connection, connected to one peer).
fn run_shared_pool(cfg: LossConfig, k: usize) {
    let start = Instant::now();
    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(1024);

    let mut sockets: Vec<UdpSocket> = Vec::with_capacity(k);
    for s in 0..k {
        let addr = SocketAddr::new(std::net::IpAddr::from([0, 0, 0, 0]), cfg.port + s as u16);
        let mut socket = UdpSocket::bind(addr).expect("bind shared-pool socket");
        let _ = set_sock_bufs(socket.as_raw_fd());
        poll.registry()
            .register(&mut socket, Token(s), Interest::READABLE)
            .expect("register shared-pool socket");
        sockets.push(socket);
    }

    struct SharedConn {
        conn: SrtConnection,
        timers: srt_transport::ManualTimerStore,
        connected: bool,
        data_events: u64,
        peer: SocketAddr,
        socket_idx: usize,
        /// `None` until the first `Connected` event; doubles as "has this
        /// ever connected" so a still-handshaking entry (which is not
        /// terminal) is distinguishable from a disconnected one (which
        /// is), without a separate pending/established split.
        stream_deadline: Option<Instant>,
        last_data_at: Instant,
    }

    fn is_terminal(c: &SharedConn, now: Instant, connect_deadline: Instant) -> bool {
        match c.stream_deadline {
            Some(deadline) => {
                !c.connected
                    || now >= deadline
                    || now.saturating_duration_since(c.last_data_at) >= IDLE_GRACE
            }
            // Never connected: keep waiting until the shared connect
            // window closes, exactly like an unresolved pending
            // handshake elsewhere in this file.
            None => now >= connect_deadline,
        }
    }

    let mut conns: HashMap<SocketAddr, SharedConn> = HashMap::new();
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);
    let mut buf = [0u8; 2048];
    let mut admit_bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
    let mut admit_sizes = [0usize; 32];
    let mut admit_addrs: [Option<SocketAddr>; 32] = [None; 32];

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        if now >= connect_deadline
            && conns
                .values()
                .all(|c| is_terminal(c, now, connect_deadline))
        {
            break;
        }
        poll.poll(&mut events, Some(TIMER_TICK)).ok();

        for event in events.iter() {
            let socket_idx = event.token().0;
            let Some(socket) = sockets.get(socket_idx) else {
                continue;
            };
            let t = crate::now_ts(start);
            drain_admission(
                socket,
                cfg.batching,
                &mut admit_bufs,
                &mut admit_sizes,
                &mut admit_addrs,
                &mut buf,
                |peer, data| {
                    let entry = conns.entry(peer).or_insert_with(|| SharedConn {
                        conn: SrtConnection::new_listener(ConnectionOptions {
                            socket_id: std::process::id(),
                            tsbpd_delay: cfg.latency_ms,
                            ..Default::default()
                        }),
                        timers: srt_transport::ManualTimerStore::new(),
                        connected: false,
                        data_events: 0,
                        peer,
                        socket_idx,
                        stream_deadline: None,
                        last_data_at: Instant::now(),
                    });
                    let _ = entry.conn.feed_recv_buf(data, t);
                    entry.data_events += 1;
                    entry.last_data_at = Instant::now();
                },
            );
        }

        let t = crate::now_ts(start);
        for conn in conns.values_mut() {
            conn.timers.fire_expired(t, &mut conn.conn);
            let socket = &sockets[conn.socket_idx];
            while let Some(out) = conn.conn.poll_output() {
                match out {
                    shiguredo_srt::ConnectionOutput::SendPacket(bytes) => {
                        let _ = socket.send_to(&bytes, conn.peer);
                    }
                    other => conn.timers.apply_output(&other, t),
                }
            }
            while let Some(ev) = conn.conn.poll_event() {
                match ev {
                    ConnectionEvent::Connected => {
                        conn.connected = true;
                        conn.stream_deadline = Some(Instant::now() + stream_len);
                    }
                    ConnectionEvent::Disconnected { .. } => {
                        conn.connected = false;
                    }
                    _ => {}
                }
            }
        }
    }

    let mut agg = Aggregate::new(cfg.clone());
    for conn in conns.into_values() {
        let mut s = ConnStats {
            // stream_deadline is Some as soon as Connected has ever fired
            // (see the struct doc) -- a session that streamed everything
            // and then tripped SRT's own peer-idle timeout is still a
            // success, not "never connected".
            connected: conn.stream_deadline.is_some(),
            data_events: conn.data_events,
            ..Default::default()
        };
        if let Some(st) = conn.conn.receiver_stats() {
            s.has_stats = true;
            s.core_total = st.total_received;
            s.secondary_a = st.total_lost;
            s.secondary_b = st.total_duplicates;
            s.rtt_us = st.rtt as u64;
        }
        agg.add(s);
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-mio] shared pool admitted no connections");
        std::process::exit(1);
    }
}

/// One accepted connection on an acceptor thread: dedicated socket
/// connected to the peer's exact tuple + protocol state.
struct PoolSlot {
    conn: Conn,
    /// Live connected state: flips false on `Disconnected`, feeding
    /// `slot_is_terminal` so a dropped connection is promptly recognized
    /// as done. Always starts true (a slot only exists post-promotion,
    /// i.e. after `Connected` already fired).
    connected: bool,
    /// Never reset once true: a session that finished streaming and then
    /// legitimately tripped SRT's own peer-idle timeout (normal once the
    /// sender stops -- it can happen well before this loop notices and
    /// exits) is still a *successful* connection for reporting purposes.
    /// `connected` alone would misreport perfect delivery as "admitted
    /// no connections" the moment the live flag flips.
    ever_connected: bool,
    data_events: u64,
    poisoned: bool,
    token: Token,
    /// Wall-clock deadline for this connection's stream, set once at slot
    /// creation (promotion only happens after the handshake completes, so
    /// every slot starts connected).
    stream_deadline: Instant,
    /// Wall-clock time of the last datagram received from the peer, used
    /// to detect a genuinely stalled connection (see `slot_is_terminal`)
    /// instead of stopping on a fixed wall-clock window that can drift out
    /// of sync with the peer's own window under load.
    last_data_at: Instant,
}

/// A slot is done -- either it disconnected, ran its full duration, or went
/// idle past `IDLE_GRACE` -- and the acceptor no longer needs to service it
/// to make progress.
fn slot_is_terminal(slot: &PoolSlot, now: Instant) -> bool {
    !slot.connected
        || now >= slot.stream_deadline
        || now.saturating_duration_since(slot.last_data_at) >= IDLE_GRACE
}

/// How long a connected slot may go without a datagram from its peer
/// before it's retired as stalled, even if the protocol layer hasn't
/// itself noticed a disconnect.
const IDLE_GRACE: Duration = Duration::from_secs(10);

/// Diagnostic counter: bond legs actually shipped cross-thread via the
/// handoff channel. Proves the registry/handoff path fired in a given run
/// instead of sitting dead -- see `run_pool_receiver`'s shutdown log.
static HANDOFF_COUNT: AtomicU64 = AtomicU64::new(0);

/// Bond-affinity handoff payload: a fully promoted slot shipped from the
/// acceptor that completed its handshake to the thread that owns the group.
struct Handoff {
    socket: UdpSocket,
    conn: SrtConnection,
}

enum WorkerMessage {
    Handoff(Box<Handoff>),
    /// #3 (`ReuseportSingle`) only: the one acceptor has stopped
    /// admitting and tells each worker exactly how many connections it
    /// will ever receive, so a worker can tell "no more are coming" apart
    /// from "none have arrived yet" instead of relying on a wall-clock
    /// guess. #4 (`ReuseportMulti`) never sends this -- every acceptor
    /// there is also a worker, so there's no separate admission-done
    /// signal to send.
    Finished {
        total: usize,
    },
}

fn bind_reuseport(port: u16) -> std::io::Result<UdpSocket> {
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
    Ok(UdpSocket::from_std(sock.into()))
}

/// Drain outputs for an unconnected (handshake-phase) connection: sends go
/// via send_to to the peer; timers apply to the manual store. Returns true
/// when a send failed (treat the pending handshake as dead).
fn drain_conn_outputs(
    conn: &mut SrtConnection,
    timers: &mut srt_transport::ManualTimerStore,
    socket: &UdpSocket,
    destination: SocketAddr,
    now: shiguredo_srt::Timestamp,
) -> bool {
    use shiguredo_srt::ConnectionOutput;
    let mut refused = false;
    while let Some(out) = conn.poll_output() {
        match out {
            ConnectionOutput::SendPacket(bytes) => {
                if socket.send_to(&bytes, destination).is_err() {
                    refused = true;
                }
            }
            other => timers.apply_output(&other, now),
        }
    }
    refused
}

/// Multi-acceptor single-port receiver (`--ingress pool=K`, K>1): K
/// SO_REUSEPORT acceptor threads share the base port; the kernel hashes
/// each flow's source tuple to one of them. Each acceptor completes the
/// handshake for every flow routed to it, then promotes the session:
/// creates a dedicated socket bound with SO_REUSEPORT on the same port and
/// connect()ed to the peer so kernel demux follows the exact 4-tuple.
///
/// Bond affinity: a shared GroupRegistry records which acceptor first
/// promoted each group id (from the peer's handshake group extension).
/// A leg landing on a non-owner thread is still promoted there, then the
/// registered slot ships to the owner over a one-shot mpsc channel. The
/// channel is admission-time only: steady-state packets flow
/// kernel -> socket -> owner poll directly, never through the channel.
/// Non-bonded connections skip the registry entirely.
fn run_pool_receiver(cfg: LossConfig, k: usize) {
    use std::sync::mpsc;

    let worker_count = k.min(cfg.connections);
    let start = Instant::now();
    let group_registry: GroupRegistry = Arc::new(Mutex::new(HashMap::new()));

    // All channels must exist before any thread is spawned: promote_slot
    // indexes `senders` by owner worker index, so every thread needs the
    // full, final-length vector -- not a partial one containing only the
    // channels created so far. Cloning `senders` mid-loop (as it grows one
    // element per iteration) would hand worker 0 a 1-element slice and
    // panic the first time a handoff resolves to any later worker.
    let (senders, receivers): (Vec<_>, Vec<_>) = (0..worker_count)
        .map(|_| mpsc::channel::<WorkerMessage>())
        .unzip();

    let mut handles = Vec::with_capacity(worker_count);
    for (worker_index, rx) in receivers.into_iter().enumerate() {
        let registry = group_registry.clone();
        let all_senders = senders.clone();
        let cfg = cfg.clone();
        handles.push(
            std::thread::Builder::new()
                .name(format!("srt-acceptor-{worker_index}"))
                .spawn(move || {
                    run_pool_acceptor(cfg, worker_index, start, registry, all_senders, rx)
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
    // Always report, not gated on the receiver's own --bond (bonding is a
    // sender-side choice; the receiver learns it from the handshake) --
    // a nonzero count is the proof the handoff path fired at all.
    let handoffs = HANDOFF_COUNT.load(Ordering::Relaxed);
    if handoffs > 0 {
        eprintln!("[bench-mio] pool receiver: {handoffs} bond handoffs");
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-mio] pool receiver admitted no connections");
        std::process::exit(1);
    }
}

fn run_pool_acceptor(
    cfg: LossConfig,
    worker_index: usize,
    start: Instant,
    group_registry: GroupRegistry,
    senders: Vec<mpsc::Sender<WorkerMessage>>,
    handoffs: mpsc::Receiver<WorkerMessage>,
) -> Vec<ConnStats> {
    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(1024);
    let mut listener = match bind_reuseport(cfg.port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[bench-mio] acceptor {worker_index}: bind {e}");
            return Vec::new();
        }
    };
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .expect("register listener");

    struct Pending {
        conn: SrtConnection,
        timers: srt_transport::ManualTimerStore,
        connected: bool,
        /// When this handshake attempt was first admitted. A pending
        /// entry can be orphaned -- e.g. Linux's default (non-eBPF)
        /// SO_REUSEPORT hash factors in current group size, and every
        /// promotion adds the new per-connection socket to this port's
        /// reuseport group, which can reroute a still-pending (not yet
        /// promoted) flow's *next* datagram to a different acceptor
        /// mid-handshake, stranding this entry with no peer traffic ever
        /// arriving again. Bounding pending lifetime by `connect_deadline`
        /// (below) means one orphan can't wedge this acceptor's exit
        /// condition until the absolute safety net.
        created_at: Instant,
    }

    // Pending handshakes keyed by peer tuple; established slots appended
    // after promotion, each with its own token.
    let mut pending: HashMap<SocketAddr, Pending> = HashMap::new();
    let mut slots: Vec<PoolSlot> = Vec::new();
    let mut next_token: usize = 1;
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    // Absolute safety net so a hung peer or a stuck protocol state can
    // never wedge this thread forever, no matter what `slot_is_terminal`
    // and `connect_deadline` decide. Sized off the run's own duration
    // (plus idle grace and margin) rather than a fixed constant so it
    // never truncates a legitimate long soak run.
    let run_deadline = Instant::now() + stream_len + IDLE_GRACE + Duration::from_secs(30);

    // Hoisted admission batch buffers: one allocation for the acceptor's
    // whole life, reused every readability event instead of once per event
    // (hot-path rule).
    let mut admit_bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
    let mut admit_sizes = [0usize; 32];
    let mut admit_addrs: [Option<SocketAddr>; 32] = [None; 32];
    let mut buf = [0u8; 2048];

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        // Vacuously true while no slot exists yet, so an acceptor that
        // never admits anything still exits once the connect window closes
        // instead of hanging on an empty `slots` guard.
        let all_terminal = slots.iter().all(|s| slot_is_terminal(s, now));
        if now >= connect_deadline && pending.is_empty() && all_terminal {
            break;
        }
        poll.poll(&mut events, Some(TIMER_TICK)).ok();

        // Accept bond legs promoted on other acceptors that belong here.
        // `Finished` is #3-only (see WorkerMessage) and never sent on this
        // channel; using `match` rather than a `while let Ok(Handoff(_))`
        // pattern means one would just be skipped, not stop the drain and
        // strand whatever Handoffs are queued behind it.
        while let Ok(message) = handoffs.try_recv() {
            let WorkerMessage::Handoff(handoff) = message else {
                continue;
            };
            let mut socket = handoff.socket;
            let token = Token(next_token);
            next_token += 1;
            if poll
                .registry()
                .register(&mut socket, token, Interest::READABLE)
                .is_err()
            {
                continue;
            }
            let mut conn = Conn::new(handoff.conn, socket);
            conn.fire_expired(crate::now_ts(start));
            conn.drain_outputs(crate::now_ts(start));
            let now = Instant::now();
            slots.push(PoolSlot {
                conn,
                connected: true,
                ever_connected: true,
                data_events: 0,
                poisoned: false,
                token,
                stream_deadline: now + stream_len,
                last_data_at: now,
            });
        }

        for event in events.iter() {
            match event.token().0 {
                0 => {
                    // Admission path: batched (recvmmsg) or per-datagram
                    // per LossConfig::batching -- see drain_admission.
                    let t = crate::now_ts(start);
                    drain_admission(
                        &listener,
                        cfg.batching,
                        &mut admit_bufs,
                        &mut admit_sizes,
                        &mut admit_addrs,
                        &mut buf,
                        |peer, data| {
                            let entry = pending.entry(peer).or_insert_with(|| Pending {
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
                        },
                    );
                }
                idx => service_slot_event(&mut slots, Token(idx), &mut buf, start),
            }
        }

        // Drive pending handshakes toward Connected, then promote. A
        // connected peer stays in `pending` here (`retain` keeps returning
        // true for it) -- only the promotion loop below actually removes
        // it, via `pending.remove`, which is what hands ownership of its
        // `SrtConnection` over to `promote_slot`. Dropping it early inside
        // `retain` would destroy the handshake-completed connection before
        // it's ever promoted: the peer would see its own handshake
        // conclusion (already sent) and believe it's connected, while the
        // acceptor silently admits nothing.
        let t = crate::now_ts(start);
        let mut promote = Vec::new();
        pending.retain(|peer, p| {
            // Give up on a handshake that never completed within the
            // connect window: whatever the cause (peer gave up, packet
            // loss, or an orphaned entry -- see `Pending::created_at`),
            // an attempt this stale is never going to promote, and must
            // not block this acceptor's exit condition forever.
            if p.created_at.elapsed() >= crate::INTEROP_CONNECT_TIMEOUT {
                return false;
            }
            p.timers.fire_expired(t, &mut p.conn);
            let refused = drain_conn_outputs(&mut p.conn, &mut p.timers, &listener, *peer, t);
            if refused {
                return false;
            }
            while let Some(ev) = p.conn.poll_event() {
                if matches!(ev, ConnectionEvent::Connected) {
                    p.connected = true;
                }
            }
            if p.connected {
                promote.push(*peer);
            }
            true
        });
        for peer in promote {
            let Some(p) = pending.remove(&peer) else {
                continue;
            };
            // Bond affinity key: the peer's handshake group extension, if
            // any. None for plain callers -- they never touch the registry.
            let group_id = p.conn.peer_group_extension().map(|g| g.group_id);
            promote_slot(
                &mut poll,
                &mut slots,
                &mut next_token,
                cfg.port,
                stream_len,
                peer,
                p.conn,
                group_id,
                &group_registry,
                worker_index,
                &senders,
            );
        }

        maintain_slots(&mut slots, start);
    }

    slots_to_stats(slots)
}

/// Service one readiness event against an established slot by token:
/// drain queued datagrams, feed them to the protocol, track data/idle
/// bookkeeping. Shared between `ReuseportMulti`'s merged acceptor/worker
/// loop and `ReuseportSingle`'s pure worker loop -- both drive an
/// identical `Vec<PoolSlot>` to completion once a connection is
/// promoted; they only differ in how slots *arrive* (promoted locally
/// plus occasional handoff-in, vs handoff-in only).
fn service_slot_event(slots: &mut [PoolSlot], token: Token, buf: &mut [u8], start: Instant) {
    let idx = token.0;
    let Some(slot) = slots.iter_mut().find(|s| s.token.0 == idx) else {
        return;
    };
    let t = crate::now_ts(start);
    loop {
        match slot.conn.socket.recv(buf) {
            Ok(n) => {
                let _ = slot.conn.conn.feed_recv_buf(&buf[..n], t);
                slot.data_events += 1;
                slot.last_data_at = Instant::now();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                slot.poisoned = true;
                break;
            }
            Err(_) => break,
        }
    }
}

/// Per-tick maintenance across every established slot: fire timers,
/// drain outputs, react to Disconnected, recover from poison.
fn maintain_slots(slots: &mut [PoolSlot], start: Instant) {
    let t = crate::now_ts(start);
    for slot in slots.iter_mut() {
        slot.conn.fire_expired(t);
        if slot.conn.drain_outputs(t) {
            slot.poisoned = true;
        }
        while let Some(ev) = slot.conn.conn.poll_event() {
            if matches!(ev, ConnectionEvent::Disconnected { .. }) {
                slot.connected = false;
            }
        }
        if slot.poisoned {
            // Reconnect clears ECONNREFUSED poison on connected UDP.
            if let Ok(peer) = slot.conn.socket.peer_addr() {
                let _ = slot.conn.socket.connect(peer);
                slot.poisoned = false;
            }
        }
    }
}

fn slots_to_stats(slots: Vec<PoolSlot>) -> Vec<ConnStats> {
    slots
        .into_iter()
        .map(|slot| {
            let mut s = ConnStats {
                connected: slot.ever_connected,
                data_events: slot.data_events,
                ..Default::default()
            };
            if let Some(st) = slot.conn.conn.receiver_stats() {
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

#[allow(clippy::too_many_arguments)]
fn promote_slot(
    poll: &mut Poll,
    slots: &mut Vec<PoolSlot>,
    next_token: &mut usize,
    base_port: u16,
    stream_len: Duration,
    peer: SocketAddr,
    pending_conn: SrtConnection,
    group_id: Option<u32>,
    group_registry: &GroupRegistry,
    worker_index: usize,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let mut socket = match bind_reuseport(base_port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-mio] promote {peer}: bind {e}");
            return;
        }
    };
    if socket.connect(peer).is_err() {
        eprintln!("[bench-mio] promote {peer}: connect failed");
        return;
    }

    // Bond affinity: first acceptor to promote a group owns it. A leg that
    // landed here but belongs to another owner is promoted anyway (so the
    // kernel 4-tuple demux is correct), then shipped once. Not registered
    // on this thread's poll -- the owner registers it on its own poll when
    // the handoff arrives, so registering it here would be pure waste.
    if let Some(group_id) = group_id {
        let owner = {
            let mut registry = match group_registry.lock() {
                Ok(r) => r,
                Err(_) => return, // poisoned: drop the leg rather than corrupt ownership
            };
            *registry.entry(group_id).or_insert(worker_index)
        };
        if owner != worker_index {
            let message = WorkerMessage::Handoff(Box::new(Handoff {
                socket,
                conn: pending_conn,
            }));
            if senders[owner].send(message).is_err() {
                eprintln!("[bench-mio] promote {peer}: owner {owner} channel closed");
            } else {
                HANDOFF_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    }

    let token = Token(*next_token);
    *next_token += 1;
    if poll
        .registry()
        .register(&mut socket, token, Interest::READABLE)
        .is_err()
    {
        return;
    }
    let now = Instant::now();
    slots.push(PoolSlot {
        conn: Conn::new(pending_conn, socket),
        connected: true,
        ever_connected: true,
        data_events: 0,
        poisoned: false,
        token,
        stream_deadline: now + stream_len,
        last_data_at: now,
    });
}

// ---------------------------------------------------------------------------
// #3: ReuseportSingle -- one acceptor, W dedicated worker threads, every
// promoted connection (bonded or not) routed via
// srt_lifecycle::WorkerRouter. Unlike #4 (ReuseportMulti), admission and
// steady-state service are always on different threads, even in the
// common non-bonded case.
// ---------------------------------------------------------------------------

fn run_reuseport_single(cfg: LossConfig, workers: usize) {
    let worker_count = workers.min(cfg.connections).max(1);
    let start = Instant::now();
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
                .spawn(move || run_worker(cfg, worker_index, start, rx))
                .expect("spawn worker"),
        );
    }

    run_single_acceptor(&cfg, start, &router, &senders);

    // Proves routing (and, when bonds are in play, group affinity)
    // actually engaged in this run rather than sitting dead -- every
    // connection goes through the router here (unlike #4's registry,
    // consulted only for bonded legs), so a nonzero tuple count on its
    // own only proves routing fired; the group count is what proves
    // bonds specifically were exercised.
    if cfg.bond_mode != BondMode::None
        && let Ok(router) = router.lock()
    {
        eprintln!(
            "[bench-mio] reuseport-single: routed {} tuples into {} bond groups",
            router.active_tuple_count(),
            router.active_group_count()
        );
    }

    let mut agg = Aggregate::new(cfg.clone());
    for handle in handles {
        for stats in handle.join().expect("worker panicked") {
            agg.add(stats);
        }
    }
    agg.print(start);
    if !agg.any_connected {
        eprintln!("[bench-mio] reuseport-single admitted no connections");
        std::process::exit(1);
    }
}

/// The one acceptor: admits every flow on the shared reuseport port,
/// drives handshakes to Connected, and routes each promotion -- bonded
/// or not -- to a worker via `SharedWorkerRouter`. Unlike
/// `run_pool_acceptor`, this never services steady-state traffic itself;
/// once a connection is routed, it is entirely a worker's problem. Tells
/// every worker exactly how many connections it will ever receive once
/// admission winds down, so a worker can distinguish "no more are coming"
/// from "none have arrived yet" instead of guessing off a wall clock.
fn run_single_acceptor(
    cfg: &LossConfig,
    start: Instant,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
) {
    let mut poll = Poll::new().expect("mio Poll::new");
    let mut events = Events::with_capacity(1024);
    let mut listener = match bind_reuseport(cfg.port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[bench-mio] acceptor: bind {e}");
            for sender in senders {
                let _ = sender.send(WorkerMessage::Finished { total: 0 });
            }
            return;
        }
    };
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .expect("register listener");

    struct Pending {
        conn: SrtConnection,
        timers: srt_transport::ManualTimerStore,
        connected: bool,
        created_at: Instant,
    }

    let mut pending: HashMap<SocketAddr, Pending> = HashMap::new();
    let connect_deadline = Instant::now() + crate::INTEROP_CONNECT_TIMEOUT;
    let mut admit_bufs: Vec<Vec<u8>> = (0..32).map(|_| vec![0u8; 2048]).collect();
    let mut admit_sizes = [0usize; 32];
    let mut admit_addrs: [Option<SocketAddr>; 32] = [None; 32];
    let mut buf = [0u8; 2048];
    let mut per_worker_count = vec![0usize; senders.len()];

    loop {
        let now = Instant::now();
        if now >= connect_deadline && pending.is_empty() {
            break;
        }
        poll.poll(&mut events, Some(TIMER_TICK)).ok();

        for event in events.iter() {
            if event.token() != Token(0) {
                continue;
            }
            let t = crate::now_ts(start);
            drain_admission(
                &listener,
                cfg.batching,
                &mut admit_bufs,
                &mut admit_sizes,
                &mut admit_addrs,
                &mut buf,
                |peer, data| {
                    let entry = pending.entry(peer).or_insert_with(|| Pending {
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
                },
            );
        }

        // Drive pending handshakes toward Connected, then route -- same
        // retain/promote split as run_pool_acceptor, and the same reason:
        // a connected entry must stay in `pending` until the routing loop
        // below reclaims it via `remove`, not get dropped inside `retain`.
        let t = crate::now_ts(start);
        let mut promote = Vec::new();
        let mut stale = Vec::new();
        for (peer, p) in pending.iter_mut() {
            if p.created_at.elapsed() >= crate::INTEROP_CONNECT_TIMEOUT {
                stale.push(*peer);
                continue;
            }
            p.timers.fire_expired(t, &mut p.conn);
            let refused = drain_conn_outputs(&mut p.conn, &mut p.timers, &listener, *peer, t);
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
                promote.push(*peer);
            }
        }
        for peer in stale {
            pending.remove(&peer);
        }
        for peer in promote {
            let Some(p) = pending.remove(&peer) else {
                continue;
            };
            route_to_worker(
                cfg.port,
                peer,
                p.conn,
                router,
                senders,
                &mut per_worker_count,
            );
        }
    }

    for (worker_index, sender) in senders.iter().enumerate() {
        let _ = sender.send(WorkerMessage::Finished {
            total: per_worker_count[worker_index],
        });
    }
}

/// Bind+connect the dedicated socket for a just-promoted connection, then
/// route it -- bonded or not -- to a worker via `WorkerRouter::assign`
/// and ship it once over that worker's channel. Every connection goes
/// through the router here (unlike #4's registry, which only bonded
/// connections consult): routing every promotion to a worker is this
/// strategy's whole point.
fn route_to_worker(
    port: u16,
    peer: SocketAddr,
    pending_conn: SrtConnection,
    router: &crate::SharedWorkerRouter,
    senders: &[mpsc::Sender<WorkerMessage>],
    per_worker_count: &mut [usize],
) {
    let socket = match bind_reuseport(port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bench-mio] route {peer}: bind {e}");
            return;
        }
    };
    if socket.connect(peer).is_err() {
        eprintln!("[bench-mio] route {peer}: connect failed");
        return;
    }

    let group = pending_conn
        .peer_group_extension()
        .map(|extension| srt_lifecycle::GroupAffinity {
            group_id: extension.group_id,
            stream_id: None,
            extension,
        });
    let worker = {
        let mut router = match router.lock() {
            Ok(r) => r,
            Err(_) => return, // poisoned: drop the leg rather than corrupt routing state
        };
        router.assign(peer, group, srt_lifecycle::RoutingMode::LeastTuples)
    };
    per_worker_count[worker] += 1;

    let message = WorkerMessage::Handoff(Box::new(Handoff {
        socket,
        conn: pending_conn,
    }));
    if senders[worker].send(message).is_err() {
        eprintln!("[bench-mio] route {peer}: worker {worker} channel closed");
    }
}

/// One worker thread: pure steady-state service for whatever connections
/// the acceptor routes to it. No admission logic at all -- that's fully
/// the acceptor's job in this strategy, unlike `ReuseportMulti` where
/// acceptor and worker are the same thread.
fn run_worker(
    cfg: LossConfig,
    worker_index: usize,
    start: Instant,
    handoffs: mpsc::Receiver<WorkerMessage>,
) -> Vec<ConnStats> {
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[bench-mio] worker {worker_index}: Poll::new {e}");
            return Vec::new();
        }
    };
    let mut events = Events::with_capacity(1024);
    let mut slots: Vec<PoolSlot> = Vec::new();
    let mut next_token: usize = 0;
    let stream_len = Duration::from_secs_f64(cfg.duration_secs);
    // No admission here, so no connect_deadline of its own to wait on --
    // just a generous absolute safety net plus the acceptor's own
    // `Finished` signal telling it precisely when no more are coming.
    let run_deadline = Instant::now()
        + crate::INTEROP_CONNECT_TIMEOUT
        + stream_len
        + IDLE_GRACE
        + Duration::from_secs(30);
    let mut expected: Option<usize> = None;
    let mut buf = [0u8; 2048];

    loop {
        let now = Instant::now();
        if now >= run_deadline {
            break;
        }
        if expected == Some(slots.len()) && slots.iter().all(|s| slot_is_terminal(s, now)) {
            break;
        }
        poll.poll(&mut events, Some(TIMER_TICK)).ok();

        while let Ok(message) = handoffs.try_recv() {
            match message {
                WorkerMessage::Finished { total } => expected = Some(total),
                WorkerMessage::Handoff(handoff) => {
                    let mut socket = handoff.socket;
                    let token = Token(next_token);
                    next_token += 1;
                    if poll
                        .registry()
                        .register(&mut socket, token, Interest::READABLE)
                        .is_err()
                    {
                        continue;
                    }
                    let mut conn = Conn::new(handoff.conn, socket);
                    conn.fire_expired(crate::now_ts(start));
                    conn.drain_outputs(crate::now_ts(start));
                    let now = Instant::now();
                    slots.push(PoolSlot {
                        conn,
                        connected: true,
                        ever_connected: true,
                        data_events: 0,
                        poisoned: false,
                        token,
                        stream_deadline: now + stream_len,
                        last_data_at: now,
                    });
                }
            }
        }

        for event in events.iter() {
            service_slot_event(&mut slots, event.token(), &mut buf, start);
        }
        maintain_slots(&mut slots, start);
    }

    slots_to_stats(slots)
}

#[cfg(test)]
mod bond_affinity_tests {
    use super::*;

    // ---- Registry semantics (pure, no threads) -------------------------

    fn registry() -> GroupRegistry {
        Arc::new(Mutex::new(HashMap::new()))
    }

    /// First leg to promote a group claims it: owner recorded = claimer.
    #[test]
    fn first_leg_claims_group() {
        let reg = registry();
        let mut map = reg.lock().unwrap();
        assert_eq!(*map.entry(42).or_insert(2), 2);
    }

    /// Second leg sees the existing owner, not its own index.
    #[test]
    fn second_leg_sees_existing_owner() {
        let reg = registry();
        {
            let mut map = reg.lock().unwrap();
            assert_eq!(*map.entry(42).or_insert(0), 0);
        }
        let map = reg.lock().unwrap();
        assert_eq!(map.get(&42), Some(&0));
        assert_ne!(map.get(&42), Some(&1));
    }

    /// Distinct groups are independent (a leg of group A must not inherit
    /// ownership state from group B).
    #[test]
    fn groups_are_independent() {
        let reg = registry();
        {
            let mut map = reg.lock().unwrap();
            assert_eq!(*map.entry(7).or_insert(1), 1);
            assert_eq!(*map.entry(8).or_insert(3), 3);
        }
        let map = reg.lock().unwrap();
        assert_eq!(map.get(&7), Some(&1));
        assert_eq!(map.get(&8), Some(&3));
    }

    /// Same-thread short-circuit: when the leg already landed on the owner
    /// thread, no handoff is sent (owner == worker_index).
    #[test]
    fn same_thread_leg_skips_handoff_decision() {
        let reg = registry();
        let worker_index = 3usize;
        let owner = {
            let mut map = reg.lock().unwrap();
            *map.entry(99).or_insert(worker_index)
        };
        assert_eq!(owner, worker_index);
    }

    /// Misplaced leg resolves to a different owner.
    #[test]
    fn misplaced_leg_resolves_to_foreign_owner() {
        let reg = registry();
        {
            let mut map = reg.lock().unwrap();
            map.insert(5, 0);
        }
        let map = reg.lock().unwrap();
        let owner = *map.get(&5).unwrap();
        assert_ne!(owner, 2);
    }

    /// Concurrent claims from many "threads": exactly one winner per group,
    /// and every thread observes that same winner. This is the property
    /// the mpsc handoff correctness depends on.
    #[test]
    fn concurrent_claims_elect_single_owner() {
        let reg = registry();
        let mut handles = Vec::new();
        for thread_index in 0..8 {
            let reg = reg.clone();
            handles.push(std::thread::spawn(move || {
                let mut map = reg.lock().unwrap();
                *map.entry(1234).or_insert(thread_index)
            }));
        }
        let mut winners = std::collections::HashSet::new();
        for handle in handles {
            winners.insert(handle.join().unwrap());
        }
        let map = reg.lock().unwrap();
        assert_eq!(winners.len(), 1, "exactly one thread won the race");
        assert_eq!(map.get(&1234), winners.iter().next());
    }

    // ---- Handoff message round-trip through a real channel -------------

    /// A Handoff carries socket+conn intact through the mpsc channel -- the
    /// exact transport promote_slot uses for a misplaced bond leg. Uses a
    /// real bound+connected socket to prove the kernel accepts the
    /// bind_reuseport -> connect sequence used at promotion time.
    #[test]
    fn handoff_round_trips_through_channel() {
        let socket = {
            let s = bind_reuseport(0).expect("bind ephemeral reuseport");
            s.connect("127.0.0.1:1".parse::<SocketAddr>().unwrap())
                .expect("connect");
            s
        };
        let expected_peer = socket.peer_addr().expect("peer_addr");
        let conn = SrtConnection::new_listener(ConnectionOptions::default());

        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        tx.send(WorkerMessage::Handoff(Box::new(Handoff { socket, conn })))
            .expect("send");

        let WorkerMessage::Handoff(handoff) = rx.try_recv().expect("message") else {
            panic!("expected Handoff");
        };
        assert_eq!(handoff.socket.peer_addr().unwrap(), expected_peer);
        assert!(handoff.conn.peer_group_extension().is_none());
    }

    /// Regression: `WorkerMessage` grew a `Finished` variant for #3
    /// (`ReuseportSingle`); a stray one arriving on #4's handoff channel
    /// (which never sends it, but the type is shared) must not panic or
    /// be mistaken for a Handoff.
    #[test]
    fn finished_message_does_not_panic_drain() {
        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        tx.send(WorkerMessage::Finished { total: 3 }).expect("send");
        drop(tx);
        let mut saw_finished = false;
        while let Ok(message) = rx.try_recv() {
            if matches!(message, WorkerMessage::Finished { total: 3 }) {
                saw_finished = true;
            }
        }
        assert!(saw_finished);
    }
}
