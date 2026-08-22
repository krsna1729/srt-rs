//! mio adapter: flat single-threaded epoll loop over all sockets — mio's
//! designed primitive (no task model, no native timer wheel; timers are
//! `ManualTimerStore` inside Conn). Connection i lives on port + i, each
//! registered with Token(i).

use crate::{Aggregate, ConnStats, LossConfig};
use libc;
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use shiguredo_srt::{ConnectionEvent, ConnectionOptions, ConnectionOutput, SrtConnection};
use srt_transport::mio_transport::Conn;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
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
/// Batched receive for a bound UDP socket: up to `bufs.len()` datagrams
/// in one `recvmmsg` syscall. Returns count received; `addrs[i]` holds
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
    const BATCH_MAX: usize = 64;
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

pub fn run(cfg: LossConfig) {
    let start = Instant::now();
    if cfg.mode == crate::Mode::Receiver {
        println!("LISTENING");
    }
    if cfg.connections > 1 {
        eprintln!(
            "[bench-mio] scale: ports {}-{}",
            cfg.port,
            cfg.port + cfg.connections as u16 - 1
        );
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

        let options = ConnectionOptions {
            socket_id: std::process::id(),
            tsbpd_delay: cfg.latency_ms,
            max_bandwidth_bytes_per_sec: match cfg.mode {
                crate::Mode::Sender => Some(cfg.bitrate_bps / 8),
                crate::Mode::Receiver => None,
            },
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
