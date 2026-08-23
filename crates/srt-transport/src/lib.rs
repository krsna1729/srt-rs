//! Shared adapter plumbing between srt-protocol (sans-I/O) and
//! runtime-specific I/O.
//!
//! # Architecture
//!
//! Two layers:
//!
//! 1. **Shared utilities** (always compiled, no runtime deps): `is_ready`,
//!    `NativeTimer` type alias, `ManualTimerStore`. Protocol-level primitives
//!    that all runtimes need.
//!
//! 2. **Per-runtime `Conn` structs** (feature-gated): each wraps
//!    `SrtConnection` + runtime-specific socket + runtime-specific timer.
//!    Provides `fire_expired`, `drain_outputs`, `send_paced`,
//!    `recv_with_timeout`.
//!
//! # Design principle: no lowest common denominator
//!
//! Each runtime's `Conn` uses native primitives directly:
//! - mio: `ManualTimerStore` (no native timer wheel)
//! - tokio: `Pin<Box<tokio::time::Sleep>>` per connection
//! - smol: `Pin<Box<dyn Future>>` wrapping `smol::Timer`
//! - monoio: `Pin<Box<dyn Future>>` wrapping `monoio::time::sleep`
//! - glommio: `Pin<Box<dyn Future>>` wrapping `glommio::timer::sleep`
//! - compio: `Pin<Box<dyn Future>>` wrapping `compio::time::sleep`
//!
//! The `is_ready` noop-waker poll pattern is shared because it's genuinely
//! identical across all 5 async runtimes.

use shiguredo_srt::{ConnectionOutput, SrtConnection, TimerId, Timestamp};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, RawWaker, RawWakerVTable};

// ---------------------------------------------------------------------------
// Shared utilities — always compiled, no runtime deps
// ---------------------------------------------------------------------------

/// Type alias for native timers across all async runtimes.
///
/// All async runtimes store their per-connection timer as
/// `Pin<Box<dyn Future<Output = ()>>>`. The concrete future type differs
/// per runtime, but they all coerce to this trait object.
pub type NativeTimer = Pin<Box<dyn std::future::Future<Output = ()>>>;

/// Check if a pinned future is ready by polling with a noop waker.
///
/// This is the core primitive for native timer expiry detection across all
/// async runtimes. The noop waker ensures the poll has no side effects.
pub fn is_ready(pin: &mut NativeTimer) -> bool {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    let waker = unsafe { std::task::Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    pin.as_mut().poll(&mut cx) == Poll::Ready(())
}

// ---------------------------------------------------------------------------
// Reuseport admission plumbing — raw fd/libc mechanics, no runtime
// dependency. Any adapter's "K sockets share one SO_REUSEPORT port, admit
// many peers on one socket" ingress strategy needs this; previously
// duplicated per-adapter (byte-identical in two, a simplified subset in a
// third) before every one of them actually needed it.
// ---------------------------------------------------------------------------

/// Target 16 MB per socket. Adapters set this explicitly on every socket
/// they own (never via sysctl) and read back the effective value --
/// Linux doubles the request and clamps to `net.core.rmem_max`, so the
/// granted size can be smaller than asked.
pub const SOCK_BUF_BYTES: usize = 16 << 20;

/// Set SO_RCVBUF/SO_SNDBUF on a raw fd to `bytes`, warning once if the
/// host clamped the request smaller. `0` leaves the OS default in place
/// and does nothing.
///
/// The size is a parameter rather than a crate-level setting on purpose:
/// a library has no business holding process-global mutable
/// configuration, and threading it explicitly keeps the choice with the
/// application that actually made it. [`SOCK_BUF_BYTES`] is the value
/// callers usually want.
pub fn set_sock_bufs(fd: std::os::fd::RawFd, bytes: usize) -> std::io::Result<()> {
    let requested = bytes;
    if requested == 0 {
        return Ok(());
    }
    let v = requested as libc::c_int;
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
        if r == 0 && (got as usize) < requested {
            eprintln!("SO_RCVBUF clamped by host to {got} (requested {requested})");
        }
    }
    Ok(())
}

/// Bind a UDP socket with SO_REUSEPORT set, 16 MB send/recv buffers, and
/// non-blocking mode. Returns a plain `std::net::UdpSocket`; each adapter
/// converts that to its own native socket type (mio's own `UdpSocket`
/// wraps it directly; tokio's needs no conversion at all -- it already
/// takes a std socket). `sock_buf_bytes` is passed to [`set_sock_bufs`];
/// `0` leaves the OS default.
pub fn bind_reuseport(port: u16, sock_buf_bytes: usize) -> std::io::Result<std::net::UdpSocket> {
    use std::os::fd::AsRawFd;
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port);
    sock.bind(&addr.into())?;
    let _ = set_sock_bufs(sock.as_raw_fd(), sock_buf_bytes);
    Ok(sock.into())
}

/// Batched receive for a bound UDP socket: up to `bufs.len()` datagrams in
/// one `recvmmsg` syscall. Returns count received; `addrs[i]` holds each
/// sender, `sizes[i]` the length. Buffers are hoisted by the caller and
/// reused -- zero per-call allocation. One syscall for up to `bufs.len()`
/// datagrams vs one per datagram with a plain `recv_from` loop.
pub fn recvmsg_batch(
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

/// SAFETY: `storage` must have been filled by `recvmmsg` with a valid
/// address (IPv4-only, matching this workspace's bench harness).
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

// ---------------------------------------------------------------------------
// Ingress telemetry — one definition, shared by every runtime adapter
// ---------------------------------------------------------------------------

/// Counters for one reuseport listener's admission path.
///
/// Every acceptor thread shares one of these, so the fields are atomics
/// and `&self` is enough to record. Each runtime adapter used to declare
/// its own five file-local statics; six copies of "the same" counters is
/// exactly how their meanings drifted apart unnoticed (one backend
/// counted relocations as promotions while five counted only local ones,
/// so identical-looking log lines meant different things). One
/// definition, one `report` line, one meaning.
#[derive(Debug, Default)]
pub struct IngressTelemetry {
    /// Connections given a private socket on the acceptor that admitted
    /// them. Disjoint from [`Self::handoffs`] -- the two never count the
    /// same connection, so total promotions is their sum.
    pub local_promotions: AtomicU64,
    /// Connections relocated to a different worker for bond affinity.
    pub handoffs: AtomicU64,
    /// CONCLUSION datagrams that reached an acceptor holding no state for
    /// the peer and carried no usable routing information -- flows the
    /// kernel rehashed mid-handshake that could not be rescued.
    pub stranded_conclusions: AtomicU64,
    /// CONCLUSION datagrams routed to their owning acceptor by SYN
    /// cookie. Each would otherwise have been stranded.
    pub cookie_routed: AtomicU64,
    /// Late or duplicate CONCLUSIONs for a connection this acceptor had
    /// already promoted (so its peer entry was gone). Harmless, but
    /// indistinguishable from a stranded handshake without checking the
    /// cookie -- counted apart so the two are never conflated again.
    pub promoted_duplicates: AtomicU64,
}

impl IngressTelemetry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_local_promotion(&self) {
        Self::bump(&self.local_promotions);
    }
    pub fn record_handoff(&self) {
        Self::bump(&self.handoffs);
    }
    pub fn record_stranded_conclusion(&self) {
        Self::bump(&self.stranded_conclusions);
    }
    pub fn record_cookie_routed(&self) {
        Self::bump(&self.cookie_routed);
    }
    pub fn record_promoted_duplicate(&self) {
        Self::bump(&self.promoted_duplicates);
    }

    /// One-line shutdown summary, identical in shape for every runtime so
    /// two backends' output can be compared directly.
    #[must_use]
    pub fn report(&self, backend: &str) -> String {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "[bench-{backend}] pool receiver: {} local promotions, {} bond handoffs, \
             {} stranded CONCLUSIONs, {} cookie-routed, {} post-promotion dups",
            get(&self.local_promotions),
            get(&self.handoffs),
            get(&self.stranded_conclusions),
            get(&self.cookie_routed),
            get(&self.promoted_duplicates),
        )
    }
}

// ---------------------------------------------------------------------------
// ManualTimerStore — correct for mio, fallback for others
// ---------------------------------------------------------------------------

/// Manual timer store — the fallback for runtimes without a built-in timer
/// engine (mio) or for code that wants explicit control over timer lifecycle.
///
/// Simple `HashMap<TimerId, Timestamp>` with O(n) scan on fire.
/// Runtimes with native timer engines should use their own primitives.
pub struct ManualTimerStore {
    timers: HashMap<TimerId, Timestamp>,
}

impl ManualTimerStore {
    pub fn new() -> Self {
        Self {
            timers: HashMap::new(),
        }
    }

    /// Fire all timers whose deadline has passed.
    pub fn fire_expired(&mut self, now: Timestamp, conn: &mut SrtConnection) {
        let due = self.due_timers(now);
        for id in due {
            let _ = conn.handle_timer(id, now);
        }
    }

    /// Find and remove all expired timer IDs.
    pub fn due_timers(&mut self, now: Timestamp) -> Vec<TimerId> {
        let due: Vec<TimerId> = self
            .timers
            .iter()
            .filter(|(_, d)| now.as_micros() >= d.as_micros())
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            self.timers.remove(id);
        }
        due
    }

    /// Apply a `SetTimer` or `ClearTimer` output from `poll_output()`.
    pub fn apply_output(&mut self, output: &ConnectionOutput, now: Timestamp) {
        match output {
            ConnectionOutput::SetTimer {
                id,
                duration_micros,
            } => {
                self.timers.insert(*id, now.add_micros(*duration_micros));
            }
            ConnectionOutput::ClearTimer { id } => {
                self.timers.remove(id);
            }
            _ => {}
        }
    }

    /// Microseconds until the next timer fires.
    pub fn time_until_earliest(&self, now: Timestamp, default_us: u64) -> u64 {
        self.timers
            .values()
            .map(|d| d.as_micros().saturating_sub(now.as_micros()))
            .min()
            .unwrap_or(default_us)
    }
}

impl Default for ManualTimerStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shiguredo_srt::{ConnectionOptions, SrtConnection};

    #[test]
    fn due_timers_returns_only_expired_and_removes_them() {
        let mut store = ManualTimerStore::new();
        let t0 = Timestamp::from_micros(0);
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Ack,
                duration_micros: 10_000,
            },
            t0,
        );
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Nak,
                duration_micros: 50_000,
            },
            t0,
        );

        // Before Ack's deadline: nothing due.
        assert!(store.due_timers(Timestamp::from_micros(5_000)).is_empty());

        // At/after Ack's deadline, before Nak's: only Ack fires, exactly
        // once (removed from the store on the first call).
        let due = store.due_timers(Timestamp::from_micros(10_000));
        assert_eq!(due, vec![TimerId::Ack]);
        assert!(store.due_timers(Timestamp::from_micros(10_000)).is_empty());

        // Nak still pending.
        let due = store.due_timers(Timestamp::from_micros(50_000));
        assert_eq!(due, vec![TimerId::Nak]);
    }

    #[test]
    fn clear_timer_removes_before_it_fires() {
        let mut store = ManualTimerStore::new();
        let t0 = Timestamp::from_micros(0);
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Retransmit,
                duration_micros: 1_000,
            },
            t0,
        );
        store.apply_output(
            &ConnectionOutput::ClearTimer {
                id: TimerId::Retransmit,
            },
            t0,
        );

        assert!(store.due_timers(Timestamp::from_micros(1_000)).is_empty());
    }

    #[test]
    fn set_timer_replaces_existing_deadline_for_same_id() {
        let mut store = ManualTimerStore::new();
        let t0 = Timestamp::from_micros(0);
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Keepalive,
                duration_micros: 1_000,
            },
            t0,
        );
        // Re-arm the same id further out -- this is what a real
        // SetTimer-on-every-tick pattern does (e.g. resetting Keepalive
        // on any inbound traffic).
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Keepalive,
                duration_micros: 5_000,
            },
            t0,
        );

        assert!(store.due_timers(Timestamp::from_micros(1_000)).is_empty());
        assert_eq!(
            store.due_timers(Timestamp::from_micros(5_000)),
            vec![TimerId::Keepalive]
        );
    }

    #[test]
    fn time_until_earliest_tracks_the_soonest_deadline() {
        let mut store = ManualTimerStore::new();
        let t0 = Timestamp::from_micros(1_000);
        // No timers armed: falls back to the caller-supplied default.
        assert_eq!(store.time_until_earliest(t0, 42), 42);

        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Nak,
                duration_micros: 20_000,
            },
            t0,
        );
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Ack,
                duration_micros: 5_000,
            },
            t0,
        );

        // Soonest deadline is Ack's (t0 + 5_000 = 6_000).
        assert_eq!(store.time_until_earliest(t0, 42), 5_000);
        // Past the deadline: saturates to 0, never underflows/panics.
        assert_eq!(
            store.time_until_earliest(Timestamp::from_micros(50_000), 42),
            0
        );
    }

    #[test]
    fn fire_expired_drains_due_timers_without_panicking() {
        let mut store = ManualTimerStore::new();
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        let t0 = Timestamp::from_micros(0);
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Handshake,
                duration_micros: 1_000,
            },
            t0,
        );

        store.fire_expired(Timestamp::from_micros(1_000), &mut conn);

        // Fired timer is gone; nothing left to time out on.
        assert_eq!(
            store.time_until_earliest(Timestamp::from_micros(1_000), 99),
            99
        );
    }
}

// ---------------------------------------------------------------------------
// Per-runtime Conn structs
// ---------------------------------------------------------------------------

#[cfg(feature = "mio")]
pub mod mio_transport {
    use super::ManualTimerStore;
    use libc;
    use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    /// Per-connection state for mio: protocol + owned socket + manual timers.
    pub struct Conn {
        pub conn: SrtConnection,
        pub socket: mio::net::UdpSocket,
        pub timers: ManualTimerStore,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, socket: mio::net::UdpSocket) -> Self {
            Self {
                conn,
                socket,
                timers: ManualTimerStore::new(),
            }
        }

        /// Fire expired manual timers.
        pub fn fire_expired(&mut self, now: Timestamp) {
            self.timers.fire_expired(now, &mut self.conn);
        }

        /// Drain all pending outputs: send packets, manage manual timers.
        /// Batches `SendPacket`s via `sendmmsg` (one syscall for up to 32
        /// datagrams). Returns true if the peer actually refused the
        /// connection (`ECONNREFUSED` on a connected UDP socket) -- the
        /// caller should reconnect.
        pub fn drain_outputs(&mut self, now: Timestamp) -> bool {
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(32);
            let mut refused = false;
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        batch.push(bytes);
                        if batch.len() == 32 {
                            refused |= Self::flush_batch(&self.socket, &mut batch);
                        }
                    }
                    ConnectionOutput::SetTimer { .. } | ConnectionOutput::ClearTimer { .. } => {
                        self.timers.apply_output(&out, now);
                    }
                }
            }
            refused |= Self::flush_batch(&self.socket, &mut batch);
            refused
        }

        /// mmsghdr/iovec scratch, reused across calls on this thread
        /// (hot path: `drain_outputs` runs every event-loop tick per
        /// connection). Capacity stabilizes at the batch cap (32) after
        /// the first few calls, giving zero-allocation steady state --
        /// mirrors `recvmsg_batch`'s scratch in srt-bench.
        fn flush_batch(socket: &mio::net::UdpSocket, batch: &mut Vec<Vec<u8>>) -> bool {
            use std::cell::RefCell;
            thread_local! {
                static SCRATCH: RefCell<(Vec<libc::mmsghdr>, Vec<libc::iovec>)> =
                    const { RefCell::new((Vec::new(), Vec::new())) };
            }
            if batch.is_empty() {
                return false;
            }
            SCRATCH.with(|scratch| {
                let (msgs, iovs) = &mut *scratch.borrow_mut();
                msgs.clear();
                iovs.clear();
                for buf in batch.iter() {
                    iovs.push(libc::iovec {
                        iov_base: buf.as_ptr() as *mut _,
                        iov_len: buf.len(),
                    });
                    msgs.push(libc::mmsghdr {
                        msg_hdr: unsafe { std::mem::zeroed() },
                        msg_len: 0,
                    });
                }
                for (msg, iov) in msgs.iter_mut().zip(iovs.iter()) {
                    msg.msg_hdr.msg_iov = iov as *const _ as *mut _;
                    msg.msg_hdr.msg_iovlen = 1;
                }
                let fd = {
                    use std::os::fd::AsRawFd;
                    socket.as_raw_fd()
                };
                let sent = unsafe {
                    libc::sendmmsg(
                        fd,
                        msgs.as_mut_ptr(),
                        batch.len() as u32,
                        libc::MSG_DONTWAIT,
                    )
                };
                let refused = if sent < 0 {
                    // Only a genuine ECONNREFUSED (ICMP port-unreachable
                    // surfaced on a connected UDP socket) means the peer
                    // is gone. Any other errno (EINTR, ENOBUFS, EAGAIN on
                    // the very first message, ...) is transient and
                    // shouldn't force a reconnect cycle.
                    std::io::Error::last_os_error().kind() == std::io::ErrorKind::ConnectionRefused
                } else {
                    // sendmmsg returns the count actually sent, which can
                    // be less than the batch once the send buffer fills
                    // mid-call -- per sendmmsg(2), the error for the
                    // unsent tail is lost. Fall back to individual sends
                    // for whatever didn't go out rather than dropping it.
                    for buf in &batch[sent as usize..] {
                        let _ = socket.send(buf);
                    }
                    false
                };
                batch.clear();
                refused
            })
        }

        /// Compute poll timeout from next timer deadline.
        pub fn poll_timeout(&self, default: Duration, now: Timestamp) -> Duration {
            Duration::from_micros(
                self.timers
                    .time_until_earliest(now, default.as_micros() as u64),
            )
        }
    }
}

#[cfg(feature = "tokio")]
pub mod tokio_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;

    /// Per-connection state for tokio: protocol + async socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        /// Poll the native timer to see if it has fired.
        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        /// Drain all protocol outputs with native tokio timer management.
        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let _ = self.sock.send(&bytes).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let deadline = Instant::now() + Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(tokio::time::sleep_until(deadline.into())));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        /// Recv with timeout, feed to protocol.
        pub async fn recv_with_timeout(
            &mut self,
            buf: &mut [u8],
            timeout: Duration,
            now: Timestamp,
        ) {
            if let Ok(Ok(n)) = tokio::time::timeout(timeout, self.sock.recv(buf)).await {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        /// Send one paced packet.
        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        /// Full event-loop tick: fire timers, recv, drain, send paced.
        pub async fn tick(&mut self, buf: &mut [u8], payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "smol")]
pub mod smol_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    pub type UdpSocket = smol::Async<std::net::UdpSocket>;

    /// Per-connection state for smol: protocol + async socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let _ = self.sock.write_with(|inner| inner.send(&bytes)).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let d = Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(async move {
                            smol::Timer::after(d).await;
                        }));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        pub async fn recv_with_timeout(
            &mut self,
            buf: &mut [u8],
            timeout: Duration,
            now: Timestamp,
        ) {
            let recv_fut = async { self.sock.recv(buf).await.ok() };
            let timer_fut = async {
                smol::Timer::after(timeout).await;
                None
            };
            if let Some(n) = futures_lite::future::or(recv_fut, timer_fut).await {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        pub fn try_recv(&self, buf: &mut [u8]) -> Option<std::io::Result<usize>> {
            match self.sock.get_ref().recv(buf) {
                Ok(n) => Some(Ok(n)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                Err(e) => Some(Err(e)),
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        pub async fn tick(&mut self, buf: &mut [u8], payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "monoio")]
pub mod monoio_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    /// Per-connection state for monoio: protocol + owned-buffer socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: monoio::net::udp::UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: monoio::net::udp::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let (_res, _buf) = self.sock.send(bytes).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let d = Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(async move {
                            monoio::time::sleep(d).await;
                        }));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        pub async fn recv_with_timeout(&mut self, timeout: Duration, now: Timestamp) {
            if let Ok((Ok(n), buf)) =
                monoio::time::timeout(timeout, self.sock.recv(vec![0u8; 2048])).await
            {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        pub async fn tick(&mut self, payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.recv_with_timeout(Duration::from_micros(100), now)
                .await;
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "glommio")]
pub mod glommio_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::io;
    use std::time::Duration;

    /// `super::bind_reuseport` plus registration with the *current*
    /// glommio executor's reactor -- must be called from inside a running
    /// `LocalExecutor` (glommio's `From<socket2::Socket>` conversion looks
    /// up the thread-local executor). Kept here rather than in bench code
    /// so the `socket2` conversion detail doesn't need its own dependency
    /// in srt-bench.
    pub fn bind_reuseport(port: u16, sock_buf_bytes: usize) -> io::Result<glommio::net::UdpSocket> {
        from_std(super::bind_reuseport(port, sock_buf_bytes)?)
    }

    /// Register an already-bound (and, for a handoff, already-connected)
    /// `std::net::UdpSocket` with the *current* glommio executor's
    /// reactor. Same executor-context requirement as `bind_reuseport`.
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<glommio::net::UdpSocket> {
        Ok(glommio::net::UdpSocket::from(
            socket2_glommio::Socket::from(socket),
        ))
    }

    /// Per-connection state for glommio: protocol + borrowed-buffer socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: glommio::net::UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: glommio::net::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let _ = self.sock.send(&bytes).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let d = Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(async move {
                            glommio::timer::sleep(d).await;
                        }));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        pub async fn recv_with_timeout(
            &mut self,
            buf: &mut [u8],
            timeout: Duration,
            now: Timestamp,
        ) {
            let recv_fut = async { self.sock.recv_from(buf).await.ok() };
            let timer_fut = async {
                glommio::timer::sleep(timeout).await;
                None
            };
            if let Some((n, _addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        pub fn try_recv(
            &self,
            buf: &mut [u8],
        ) -> Option<std::io::Result<(usize, std::net::SocketAddr)>> {
            match futures_lite::future::block_on(futures_lite::future::poll_once(
                self.sock.recv_from(buf),
            )) {
                Some(Ok((n, addr))) => Some(Ok((n, addr))),
                Some(Err(e)) => Some(Err(e.into())),
                None => None,
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        pub async fn tick(&mut self, buf: &mut [u8], payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "compio")]
pub mod compio_transport {
    use super::{NativeTimer, is_ready};
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::time::Duration;

    /// Per-connection state for compio: protocol + owned-buffer socket + native timer.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: compio::net::UdpSocket,
        timer: Option<NativeTimer>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: compio::net::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timer: None,
            }
        }

        pub fn fire_expired(&mut self) {
            if let Some(ref mut timer) = self.timer {
                if is_ready(timer) {
                    self.timer = None;
                }
            }
        }

        pub async fn drain_outputs(&mut self, _now: Timestamp) {
            while let Some(out) = self.conn.poll_output() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let _ = self.sock.send(bytes).await;
                    }
                    ConnectionOutput::SetTimer {
                        id: _,
                        duration_micros,
                    } => {
                        let d = Duration::from_micros(duration_micros);
                        self.timer = Some(Box::pin(async move {
                            compio::time::sleep(d).await;
                        }));
                    }
                    ConnectionOutput::ClearTimer { id: _ } => {
                        self.timer = None;
                    }
                }
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            self.drain_outputs(now).await;
            Ok(())
        }

        pub async fn tick(&mut self, payload: &[u8], now: Timestamp) -> TickResult {
            self.fire_expired();
            self.drain_outputs(now).await;

            let mut sent = 0u64;
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            TickResult { sent, events }
        }
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}
