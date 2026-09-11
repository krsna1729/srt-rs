use std::net;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Target 16 MB per socket. Adapters set this explicitly on every socket
/// they own (never via sysctl) and read back the effective value --
/// Linux doubles the request and clamps to `net.core.rmem_max`, so the
/// granted size can be smaller than asked.
pub const SOCK_BUF_BYTES: usize = 16 << 20;

/// Kernel-granted socket buffer sizes observed across this process's sockets.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SocketBufferStats {
    pub sockets: usize,
    pub rcvbuf_min_bytes: usize,
    pub rcvbuf_max_bytes: usize,
    pub sndbuf_min_bytes: usize,
    pub sndbuf_max_bytes: usize,
}

static SOCKET_COUNT: AtomicUsize = AtomicUsize::new(0);
static RCVBUF_MIN: AtomicUsize = AtomicUsize::new(usize::MAX);
static RCVBUF_MAX: AtomicUsize = AtomicUsize::new(0);
static SNDBUF_MIN: AtomicUsize = AtomicUsize::new(usize::MAX);
static SNDBUF_MAX: AtomicUsize = AtomicUsize::new(0);

fn record_socket_buffers(rcvbuf: usize, sndbuf: usize) {
    SOCKET_COUNT.fetch_add(1, Ordering::Relaxed);
    RCVBUF_MIN.fetch_min(rcvbuf, Ordering::Relaxed);
    RCVBUF_MAX.fetch_max(rcvbuf, Ordering::Relaxed);
    SNDBUF_MIN.fetch_min(sndbuf, Ordering::Relaxed);
    SNDBUF_MAX.fetch_max(sndbuf, Ordering::Relaxed);
}

/// Return process-wide effective socket-buffer ranges.
#[must_use]
pub fn socket_buffer_stats() -> SocketBufferStats {
    let sockets = SOCKET_COUNT.load(Ordering::Relaxed);
    if sockets == 0 {
        return SocketBufferStats::default();
    }
    SocketBufferStats {
        sockets,
        rcvbuf_min_bytes: RCVBUF_MIN.load(Ordering::Relaxed),
        rcvbuf_max_bytes: RCVBUF_MAX.load(Ordering::Relaxed),
        sndbuf_min_bytes: SNDBUF_MIN.load(Ordering::Relaxed),
        sndbuf_max_bytes: SNDBUF_MAX.load(Ordering::Relaxed),
    }
}

/// Query SO_RCVBUF and SO_SNDBUF on `fd`.
fn get_sock_bufs(fd: std::os::fd::RawFd) -> std::io::Result<(usize, usize)> {
    // SAFETY: each getsockopt call receives a live caller-owned fd, writable
    // storage for one c_int, and that storage's exact size.
    unsafe {
        let mut rcv: libc::c_int = 0;
        let mut rcv_len = std::mem::size_of_val(&rcv) as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut rcv as *mut _ as *mut libc::c_void,
            &mut rcv_len,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mut snd: libc::c_int = 0;
        let mut snd_len = std::mem::size_of_val(&snd) as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &mut snd as *mut _ as *mut libc::c_void,
            &mut snd_len,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok((rcv.max(0) as usize, snd.max(0) as usize))
    }
}

/// Set SO_RCVBUF/SO_SNDBUF on a raw fd to `bytes` and record the effective
/// values granted by the kernel. `0` leaves the OS defaults in place.
pub fn set_sock_bufs(fd: std::os::fd::RawFd, bytes: usize) -> std::io::Result<()> {
    let requested = bytes;
    if requested == 0 {
        if let Ok((rcvbuf, sndbuf)) = get_sock_bufs(fd) {
            record_socket_buffers(rcvbuf, sndbuf);
        }
        return Ok(());
    }
    if requested > libc::c_int::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket buffer request exceeds c_int",
        ));
    }
    let v = requested as libc::c_int;
    let len = std::mem::size_of_val(&v) as libc::socklen_t;
    // SAFETY: each option call receives a live caller-owned fd, a pointer to
    // an initialized `c_int`, and its exact size. The kernel does not retain
    // these pointers after the syscall returns; an invalid fd is reported as
    // an ordinary OS error.
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

    let (rcvbuf, sndbuf) = get_sock_bufs(fd)?;
    record_socket_buffers(rcvbuf, sndbuf);
    Ok(())
}

/// Bind a UDP socket with SO_REUSEPORT set, 16 MB send/recv buffers, and
/// non-blocking mode. Returns a plain `std::net::UdpSocket`; each adapter
/// converts that to its own native socket type (mio's own `UdpSocket`
/// wraps it directly; tokio's needs no conversion at all -- it already
/// takes a std socket). `sock_buf_bytes` is passed to [`set_sock_bufs`];
/// `0` leaves the OS default.
pub fn bind_reuseport(port: u16, sock_buf_bytes: usize) -> std::io::Result<net::UdpSocket> {
    use std::os::fd::AsRawFd;
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let addr = net::SocketAddrV4::new(net::Ipv4Addr::UNSPECIFIED, port);
    sock.bind(&addr.into())?;
    set_sock_bufs(sock.as_raw_fd(), sock_buf_bytes)?;
    Ok(sock.into())
}

/// Batched receive for a bound UDP socket: up to `bufs.len()` datagrams in
/// one `recvmmsg` syscall. Returns count received; `addrs[i]` holds each
/// sender, `sizes[i]` the length actually copied into `bufs[i]` (always
/// `<= bufs[i].capacity()`), `truncated[i]` whether the kernel reports
/// `MSG_TRUNC` -- for UDP, `recvmmsg` reports the *true* datagram length
/// in `msg_len` even when it exceeds the supplied buffer (Linux
/// `recvmsg(2)`: "the full length of the packet or datagram is returned,
/// even when it was longer than the passed buffer"), so `sizes[i]` is
/// clamped here rather than trusted directly -- an unclamped `msg_len`
/// used as a slice bound on `bufs[i]` would panic on an oversized
/// datagram (T01). A caller must not treat a truncated entry's (clamped,
/// incomplete) bytes as a complete datagram. Buffers are hoisted by the
/// caller and reused -- zero per-call allocation. One syscall for up to
/// `bufs.len()` datagrams vs one per datagram with a plain `recv_from` loop.
pub fn recvmsg_batch(
    fd: std::os::fd::RawFd,
    bufs: &mut [Vec<u8>],
    sizes: &mut [usize],
    addrs: &mut [Option<net::SocketAddr>],
    truncated: &mut [bool],
) -> std::io::Result<usize> {
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
                        // SAFETY: all-zero is a valid empty `msghdr`.
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
                addrs: (0..n)
                    .map(|_| {
                        // SAFETY: `sockaddr_storage` is plain C storage and
                        // all-zero is a valid uninitialized-address state.
                        unsafe { std::mem::zeroed() }
                    })
                    .collect(),
            }
        }

        fn ensure_len(&mut self, n: usize) {
            if self.msgs.len() >= n {
                return;
            }
            self.msgs.resize_with(n, || libc::mmsghdr {
                // SAFETY: all-zero is a valid empty `msghdr`.
                msg_hdr: unsafe { std::mem::zeroed() },
                msg_len: 0,
            });
            self.iovs.resize_with(n, || libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            });
            self.addrs.resize_with(n, || {
                // SAFETY: see `BatchScratch::new`; the kernel fills this
                // storage before it is interpreted.
                unsafe { std::mem::zeroed() }
            });
        }
    }
    if bufs.len() != sizes.len() || bufs.len() != addrs.len() || bufs.len() != truncated.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "recvmsg_batch slice lengths differ: bufs={}, sizes={}, addrs={}, truncated={}",
                bufs.len(),
                sizes.len(),
                addrs.len(),
                truncated.len()
            ),
        ));
    }
    let count = bufs.len();
    if count == 0 {
        return Ok(0);
    }
    let count_u32 = u32::try_from(count).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "recvmsg_batch exceeds recvmmsg count range",
        )
    })?;
    SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        scratch.ensure_len(count);
        let BatchScratch {
            msgs,
            iovs,
            addrs: storage_addrs,
        } = &mut *scratch;
        addrs.fill(None);
        for (((iov, msg), storage), (buf, size)) in iovs
            .iter_mut()
            .take(count)
            .zip(msgs.iter_mut().take(count))
            .zip(storage_addrs.iter_mut().take(count))
            .zip(bufs.iter_mut().zip(sizes.iter_mut()))
        {
            buf.resize(buf.capacity(), 0);
            *size = 0;
            *iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.capacity(),
            };
            // SAFETY: zeroed sockaddr storage is valid and is filled by the
            // kernel before any family-specific interpretation.
            *storage = unsafe { std::mem::zeroed() };
            *msg = libc::mmsghdr {
                // SAFETY: all-zero is a valid empty `msghdr`; fields needed
                // by `recvmmsg` are assigned immediately below.
                msg_hdr: unsafe { std::mem::zeroed() },
                msg_len: 0,
            };
            msg.msg_hdr.msg_iov = iov;
            msg.msg_hdr.msg_iovlen = 1;
            msg.msg_hdr.msg_name = (storage as *mut libc::sockaddr_storage).cast();
            msg.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        }
        // SAFETY: the three scratch arrays contain at least `count` elements;
        // every message points at its corresponding live iovec, address
        // storage, and initialized writable Vec allocation for the duration
        // of this synchronous syscall. `count_u32` was checked above.
        let received = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                count_u32,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if received < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(err);
        }
        for i in 0..received as usize {
            // SAFETY: this entry was filled for a successfully received
            // datagram. The helper also validates family and returned length.
            addrs[i] = unsafe { sockaddr_to_addr(&storage_addrs[i], msgs[i].msg_hdr.msg_namelen) };
            // `msg_len` is the *true* datagram length for UDP, which can
            // exceed the buffer when MSG_TRUNC is set -- clamp before this
            // is ever used as a slice bound (T01).
            let buf_capacity = bufs[i].len();
            sizes[i] = (msgs[i].msg_len as usize).min(buf_capacity);
            truncated[i] = msgs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0;
        }
        Ok(received as usize)
    })
}

/// SAFETY: `storage` must have been filled by `recvmmsg` with a valid
/// address. IPv4 and IPv6 senders both decode (A02); anything else returns
/// `None` rather than misreading unrelated bytes as an address -- a caller
/// must not silently treat that as "no sender" and keep processing the
/// datagram's payload as if the source were known.
///
/// `bind_udp` (config.rs) never sets `IPV6_V6ONLY`, so a listener bound to
/// an IPv6 wildcard address is dual-stack by default on Linux
/// (`net.ipv6.bindv6only` defaults to 0): a plain IPv4 sender's datagram
/// still arrives on that socket, but the kernel reports it as `AF_INET6`
/// with an IPv4-mapped address (`::ffff:a.b.c.d`). Returning that
/// as-is would key admission by a `SocketAddr::V6` no IPv4-only listener
/// or [`sendmsg_batch`]/[`crate::flush_destined`] reply path (both reject
/// non-`AF_INET` outright) can ever match again, so it is unmapped back to
/// the plain `SocketAddr::V4` a genuine IPv4 peer needs.
unsafe fn sockaddr_to_addr(
    storage: &libc::sockaddr_storage,
    name_len: libc::socklen_t,
) -> Option<net::SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET if (name_len as usize) >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the caller guarantees kernel-filled storage; the match
            // arm establishes the IPv4 family and sufficient initialized
            // byte length. The storage type provides alignment suitable
            // for every sockaddr variant.
            let addr =
                unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            Some(net::SocketAddr::from((
                net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                u16::from_be(addr.sin_port),
            )))
        }
        libc::AF_INET6 if (name_len as usize) >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: same reasoning as the IPv4 arm, for the IPv6 family.
            let addr = unsafe {
                &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
            };
            let ip = net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return Some(net::SocketAddr::from((mapped, port)));
            }
            Some(net::SocketAddr::V6(net::SocketAddrV6::new(
                ip,
                port,
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Send a batch of destination-addressed datagrams in a single `sendmmsg`
/// syscall. Returns the number of datagrams accepted by the kernel (may be
/// fewer than `batch.len()` under backpressure). Returns `Ok(0)` for an
/// empty batch. `WouldBlock` from the kernel is returned as `Ok(0)` so
/// callers can retry without special-casing the error.
pub fn sendmsg_batch<B: AsRef<[u8]>>(
    fd: std::os::fd::RawFd,
    batch: &[(net::SocketAddr, B)],
) -> std::io::Result<usize> {
    use std::cell::RefCell;
    thread_local! {
        static SCRATCH: RefCell<SendScratch> = RefCell::new(SendScratch::new(64));
    }
    struct SendScratch {
        msgs: Vec<libc::mmsghdr>,
        iovs: Vec<libc::iovec>,
        addrs: Vec<libc::sockaddr_in>,
    }
    impl SendScratch {
        fn new(n: usize) -> Self {
            Self {
                // SAFETY: all-zero is a valid empty mmsghdr/sockaddr_in.
                msgs: vec![unsafe { std::mem::zeroed() }; n],
                iovs: vec![
                    libc::iovec {
                        iov_base: std::ptr::null_mut(),
                        iov_len: 0,
                    };
                    n
                ],
                // SAFETY: all-zero is a valid uninitialized sockaddr_in.
                addrs: vec![unsafe { std::mem::zeroed() }; n],
            }
        }
        fn ensure_len(&mut self, n: usize) {
            if self.msgs.len() >= n {
                return;
            }
            // SAFETY: all-zero is a valid empty mmsghdr.
            self.msgs.resize_with(n, || unsafe { std::mem::zeroed() });
            self.iovs.resize_with(n, || libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            });
            // SAFETY: all-zero is a valid uninitialized sockaddr_in.
            self.addrs.resize_with(n, || unsafe { std::mem::zeroed() });
        }
    }
    let count = batch.len();
    if count == 0 {
        return Ok(0);
    }
    let count_u32 = u32::try_from(count).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sendmsg_batch exceeds sendmmsg count range",
        )
    })?;
    SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        scratch.ensure_len(count);
        let SendScratch { msgs, iovs, addrs } = &mut *scratch;
        for (i, (dest, payload)) in batch.iter().enumerate() {
            let net::SocketAddr::V4(v4) = dest else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "sendmsg_batch: only IPv4 is supported",
                ));
            };
            // SAFETY: zeroed is valid for sockaddr_in; we fill every field.
            addrs[i] = unsafe { std::mem::zeroed() };
            addrs[i].sin_family = libc::AF_INET as u16;
            addrs[i].sin_port = v4.port().to_be();
            addrs[i].sin_addr.s_addr = u32::from(*v4.ip()).to_be();

            let payload = payload.as_ref();
            iovs[i] = libc::iovec {
                iov_base: payload.as_ptr() as *mut _,
                iov_len: payload.len(),
            };
            // SAFETY: all-zero is a valid empty mmsghdr; fields are
            // assigned immediately below.
            msgs[i] = unsafe { std::mem::zeroed() };
            msgs[i].msg_hdr.msg_iov = &mut iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_name = (&mut addrs[i] as *mut libc::sockaddr_in).cast();
            msgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        }
        // SAFETY: scratch arrays are `count` long, each msg points at its
        // own iov/addr. All payload slices outlive this synchronous syscall.
        let sent = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), count_u32, libc::MSG_DONTWAIT) };
        if sent < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(sent as usize)
    })
}

/// Send a batch of datagrams on a *connected* UDP socket in one `sendmmsg`.
///
/// Destinations are omitted (`msg_name` is null) so the kernel uses the
/// connected peer. Returns the number of datagrams accepted (may be a
/// prefix under backpressure). `WouldBlock` is `Ok(0)`, matching
/// [`sendmsg_batch`].
pub fn sendmsg_connected_batch<B: AsRef<[u8]>>(
    fd: std::os::fd::RawFd,
    batch: &[B],
) -> std::io::Result<usize> {
    use std::cell::RefCell;
    thread_local! {
        static SCRATCH: RefCell<ConnectedSendScratch> =
            RefCell::new(ConnectedSendScratch::new(64));
    }
    struct ConnectedSendScratch {
        msgs: Vec<libc::mmsghdr>,
        iovs: Vec<libc::iovec>,
    }
    impl ConnectedSendScratch {
        fn new(n: usize) -> Self {
            Self {
                // SAFETY: all-zero is a valid empty mmsghdr.
                msgs: vec![unsafe { std::mem::zeroed() }; n],
                iovs: vec![
                    libc::iovec {
                        iov_base: std::ptr::null_mut(),
                        iov_len: 0,
                    };
                    n
                ],
            }
        }
        fn ensure_len(&mut self, n: usize) {
            if self.msgs.len() >= n {
                return;
            }
            // SAFETY: all-zero is a valid empty mmsghdr.
            self.msgs.resize_with(n, || unsafe { std::mem::zeroed() });
            self.iovs.resize_with(n, || libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            });
        }
    }
    let count = batch.len();
    if count == 0 {
        return Ok(0);
    }
    let count_u32 = u32::try_from(count).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sendmsg_connected_batch exceeds sendmmsg count range",
        )
    })?;
    SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        scratch.ensure_len(count);
        let ConnectedSendScratch { msgs, iovs } = &mut *scratch;
        for (i, payload) in batch.iter().enumerate() {
            let payload = payload.as_ref();
            iovs[i] = libc::iovec {
                iov_base: payload.as_ptr() as *mut _,
                iov_len: payload.len(),
            };
            // SAFETY: all-zero is a valid empty mmsghdr; fields are
            // assigned immediately below. `msg_name` stays null so the
            // connected peer is used.
            msgs[i] = unsafe { std::mem::zeroed() };
            msgs[i].msg_hdr.msg_iov = &mut iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        // SAFETY: scratch arrays are `count` long, each msg points at its
        // own iov. All payload slices outlive this synchronous syscall.
        let sent = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), count_u32, libc::MSG_DONTWAIT) };
        if sent < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(sent as usize)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recvmsg_batch_empty_is_noop() {
        assert_eq!(
            recvmsg_batch(-1, &mut [], &mut [], &mut [], &mut []).unwrap(),
            0
        );
    }

    #[test]
    fn recvmsg_batch_rejects_mismatched_lengths() {
        let mut bufs = vec![vec![0u8; 64]];
        let mut sizes = [0usize; 2];
        let mut addrs = [None; 1];
        let mut truncated = [false; 1];
        let err = recvmsg_batch(-1, &mut bufs, &mut sizes, &mut addrs, &mut truncated).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sockaddr_to_addr_rejects_ipv6_family_with_an_ipv4_sized_length() {
        // SAFETY: all-zero is a valid uninitialized sockaddr_storage.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        storage.ss_family = libc::AF_INET6 as u16;
        // SAFETY: storage is initialized with a known family; testing the
        // rejection path (an IPv6 family claiming only an IPv4-sized name
        // is too short to hold a real sockaddr_in6, so it does not decode).
        let result =
            unsafe { sockaddr_to_addr(&storage, std::mem::size_of::<libc::sockaddr_in>() as u32) };
        assert!(result.is_none());
    }

    #[test]
    fn sockaddr_to_addr_rejects_an_unrecognized_family() {
        // SAFETY: all-zero is a valid uninitialized sockaddr_storage.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // AF_UNIX is neither of the two families this crate's sockets ever
        // bind as (A02); it must not be misread as either.
        storage.ss_family = libc::AF_UNIX as u16;
        // SAFETY: storage is initialized with a known (unsupported) family;
        // testing the rejection path.
        let result = unsafe {
            sockaddr_to_addr(
                &storage,
                std::mem::size_of::<libc::sockaddr_storage>() as u32,
            )
        };
        assert!(result.is_none());
    }

    /// A02: a datagram from a real IPv6 sender must decode to a genuine
    /// `SocketAddr::V6`, not silently become `None` (previously, this whole
    /// function only recognized `AF_INET`, so every IPv6 sender's address
    /// vanished while its payload was still processed as if the source
    /// were unknown).
    #[test]
    fn sockaddr_to_addr_parses_valid_ipv6() {
        // SAFETY: all-zero is a valid uninitialized sockaddr_storage.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: sockaddr_storage is layout-compatible with sockaddr_in6
        // when the family is AF_INET6; we fill every field before reading.
        let addr = unsafe {
            &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
        };
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_port = 8080u16.to_be();
        addr.sin6_addr.s6_addr = net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        addr.sin6_scope_id = 7;
        // SAFETY: storage was filled as a valid AF_INET6 sockaddr_in6 above.
        let result =
            unsafe { sockaddr_to_addr(&storage, std::mem::size_of::<libc::sockaddr_in6>() as u32) };
        assert_eq!(
            result,
            Some(net::SocketAddr::V6(net::SocketAddrV6::new(
                net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                8080,
                0,
                7,
            )))
        );
    }

    /// A02 (Opus review): `bind_udp` never sets `IPV6_V6ONLY`, so a
    /// listener bound to an IPv6 wildcard address is dual-stack by default
    /// on Linux -- a plain IPv4 sender's datagram still arrives there, but
    /// the kernel reports its address as `AF_INET6` with an IPv4-mapped
    /// address (`::ffff:a.b.c.d`). Returning that as a raw `SocketAddr::V6`
    /// would key admission by an address no IPv4-only listener or
    /// `sendmsg_batch` reply path (which rejects non-`AF_INET` outright)
    /// can ever match again; it must unmap back to a plain `SocketAddr::V4`.
    #[test]
    fn sockaddr_to_addr_unmaps_an_ipv4_mapped_ipv6_sender() {
        // SAFETY: all-zero is a valid uninitialized sockaddr_storage.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: sockaddr_storage is layout-compatible with sockaddr_in6
        // when the family is AF_INET6; we fill every field before reading.
        let addr = unsafe {
            &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
        };
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_port = 9090u16.to_be();
        addr.sin6_addr.s6_addr = net::Ipv4Addr::new(192, 168, 1, 42)
            .to_ipv6_mapped()
            .octets();
        // SAFETY: storage was filled as a valid AF_INET6 sockaddr_in6 above.
        let result =
            unsafe { sockaddr_to_addr(&storage, std::mem::size_of::<libc::sockaddr_in6>() as u32) };
        assert_eq!(
            result,
            Some(net::SocketAddr::from((
                net::Ipv4Addr::new(192, 168, 1, 42),
                9090
            ))),
            "an IPv4-mapped IPv6 sender must unmap to a plain V4 address, \
             not surface as SocketAddr::V6"
        );
    }

    #[test]
    fn sockaddr_to_addr_rejects_short_len() {
        // SAFETY: all-zero is a valid uninitialized sockaddr_storage.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        storage.ss_family = libc::AF_INET as u16;
        // SAFETY: storage is initialized; testing the short-length rejection.
        let result = unsafe { sockaddr_to_addr(&storage, 2) };
        assert!(result.is_none());
    }

    #[test]
    fn sockaddr_to_addr_parses_valid_ipv4() {
        // SAFETY: all-zero is a valid uninitialized sockaddr_storage.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: sockaddr_storage is layout-compatible with sockaddr_in when
        // the family is AF_INET; we fill every field before reading.
        let addr = unsafe {
            &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in)
        };
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_port = 8080u16.to_be();
        addr.sin_addr.s_addr = u32::from(net::Ipv4Addr::new(192, 168, 1, 42)).to_be();
        // SAFETY: storage was filled as a valid AF_INET sockaddr_in above.
        let result =
            unsafe { sockaddr_to_addr(&storage, std::mem::size_of::<libc::sockaddr_in>() as u32) };
        assert_eq!(
            result,
            Some(net::SocketAddr::from(([192, 168, 1, 42], 8080)))
        );
    }

    #[test]
    fn set_sock_bufs_zero_is_noop() {
        assert!(set_sock_bufs(-1, 0).is_ok());
    }

    #[test]
    fn set_sock_bufs_rejects_oversized() {
        let err = set_sock_bufs(-1, usize::MAX).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn socket_buffer_stats_include_receive_and_send_ranges() {
        use std::os::fd::AsRawFd;

        let socket = net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let before = socket_buffer_stats().sockets;
        set_sock_bufs(socket.as_raw_fd(), 64 * 1024).unwrap();
        let after = socket_buffer_stats();
        assert!(after.sockets > before);
        assert!(after.rcvbuf_min_bytes > 0);
        assert!(after.rcvbuf_min_bytes <= after.rcvbuf_max_bytes);
        assert!(after.sndbuf_min_bytes > 0);
        assert!(after.sndbuf_min_bytes <= after.sndbuf_max_bytes);
    }

    #[test]
    fn bind_reuseport_returns_nonblocking_socket() {
        let sock = bind_reuseport(0, 0).expect("bind to ephemeral port");
        assert!(sock.local_addr().is_ok());
        assert!(
            sock.set_nonblocking(true).is_ok(),
            "socket should already be nonblocking"
        );
    }

    #[test]
    fn sendmsg_batch_empty_is_noop() {
        assert_eq!(
            sendmsg_batch(-1, &[] as &[(net::SocketAddr, &[u8])]).unwrap(),
            0
        );
    }

    #[test]
    fn sendmsg_batch_delivers_to_loopback() {
        use std::os::fd::AsRawFd;
        let receiver = net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let dest = receiver.local_addr().expect("receiver addr");
        let sender = net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sender.set_nonblocking(true).expect("nonblocking sender");
        let fd = sender.as_raw_fd();

        let batch: Vec<(net::SocketAddr, &[u8])> =
            vec![(dest, b"hello"), (dest, b"world"), (dest, b"!")];
        let sent = sendmsg_batch(fd, &batch).expect("sendmsg_batch");
        assert_eq!(sent, 3);

        let mut buf = [0u8; 64];
        for expected in [b"hello".as_slice(), b"world", b"!"] {
            let n = receiver.recv(&mut buf).expect("recv");
            assert_eq!(&buf[..n], expected);
        }
    }

    #[test]
    fn sendmsg_connected_batch_empty_is_noop() {
        assert_eq!(sendmsg_connected_batch(-1, &[] as &[&[u8]]).unwrap(), 0);
    }

    #[test]
    fn sendmsg_connected_batch_delivers_to_connected_peer() {
        use std::os::fd::AsRawFd;
        let receiver = net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let dest = receiver.local_addr().expect("receiver addr");
        let sender = net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sender.set_nonblocking(true).expect("nonblocking sender");
        sender.connect(dest).expect("connect to receiver");

        let sent = sendmsg_connected_batch(
            sender.as_raw_fd(),
            &[b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
        )
        .expect("sendmsg_connected_batch");
        assert_eq!(sent, 3);

        let mut buf = [0u8; 64];
        for expected in [b"alpha".as_slice(), b"beta", b"gamma"] {
            let n = receiver.recv(&mut buf).expect("recv");
            assert_eq!(&buf[..n], expected);
        }
    }

    /// T01: an oversized datagram must never become a truncated-prefix
    /// "complete packet", must not panic (the pre-fix code sliced
    /// `&buf[..msg_len]` using the kernel's *true* datagram length, which
    /// for UDP can exceed the buffer -- an out-of-bounds slice), and must
    /// not prevent a normal-sized sibling in the same batch from being
    /// received correctly.
    #[test]
    fn oversized_datagram_is_truncated_flagged_not_panicking_and_does_not_lose_its_sibling() {
        use std::os::fd::AsRawFd;
        let receiver = net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let dest = receiver.local_addr().expect("receiver addr");
        let sender = net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        sender.set_nonblocking(true).expect("nonblocking sender");

        const BUF_LEN: usize = 16;
        let oversized_payload = vec![0xEEu8; BUF_LEN * 4];
        let valid_payload = b"sibling datagram";
        assert!(valid_payload.len() <= BUF_LEN);
        sender
            .send_to(&oversized_payload, dest)
            .expect("send oversized");
        sender
            .send_to(valid_payload, dest)
            .expect("send valid sibling");

        let mut bufs: Vec<Vec<u8>> = (0..2).map(|_| Vec::with_capacity(BUF_LEN)).collect();
        let mut sizes = [0usize; 2];
        let mut addrs = [None; 2];
        let mut truncated = [false; 2];

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut received = 0;
        while received < 2 && std::time::Instant::now() < deadline {
            match recvmsg_batch(
                receiver.as_raw_fd(),
                &mut bufs[received..],
                &mut sizes[received..],
                &mut addrs[received..],
                &mut truncated[received..],
            ) {
                Ok(0) => std::thread::yield_now(),
                Ok(n) => received += n,
                Err(error) => panic!("recvmmsg failed: {error}"),
            }
        }
        assert_eq!(received, 2, "both datagrams must be observed by the kernel");

        assert!(
            truncated[0],
            "the oversized datagram must be flagged MSG_TRUNC"
        );
        assert!(
            sizes[0] <= BUF_LEN,
            "a truncated size must never exceed the buffer capacity (no OOB slice)"
        );

        assert!(
            !truncated[1],
            "the normal-sized sibling must not be flagged truncated"
        );
        assert_eq!(sizes[1], valid_payload.len());
        assert_eq!(&bufs[1][..sizes[1]], valid_payload);
    }

    /// A02: `recvmsg_batch` must complete a real loopback exchange over
    /// IPv6, not just decode a hand-built `sockaddr_storage` -- proves the
    /// actual kernel-filled `AF_INET6` path, not only `sockaddr_to_addr`'s
    /// own pure-Rust decoding logic.
    #[test]
    fn recvmsg_batch_completes_a_real_ipv6_loopback_exchange() {
        use std::os::fd::AsRawFd;
        let receiver = net::UdpSocket::bind("[::1]:0").expect("bind IPv6 receiver");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let dest = receiver.local_addr().expect("receiver addr");
        assert!(dest.is_ipv6(), "receiver must be a real IPv6 socket");
        let sender = net::UdpSocket::bind("[::1]:0").expect("bind IPv6 sender");
        sender.set_nonblocking(true).expect("nonblocking sender");
        let sender_addr = sender.local_addr().expect("sender addr");

        sender.send_to(b"ipv6 payload", dest).expect("send");

        let mut bufs: Vec<Vec<u8>> = vec![Vec::with_capacity(64)];
        let mut sizes = [0usize; 1];
        let mut addrs = [None; 1];
        let mut truncated = [false; 1];

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut received = 0;
        while received == 0 && std::time::Instant::now() < deadline {
            match recvmsg_batch(
                receiver.as_raw_fd(),
                &mut bufs,
                &mut sizes,
                &mut addrs,
                &mut truncated,
            ) {
                Ok(0) => std::thread::yield_now(),
                Ok(n) => received = n,
                Err(error) => panic!("recvmmsg failed: {error}"),
            }
        }
        assert_eq!(received, 1, "the datagram must be observed by the kernel");
        assert_eq!(&bufs[0][..sizes[0]], b"ipv6 payload");
        assert_eq!(
            addrs[0],
            Some(sender_addr),
            "the real IPv6 sender's address must decode correctly, not become None"
        );
    }
}
