use std::net;

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
        if r == 0 && got >= 0 && (got as usize) < requested {
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
/// sender, `sizes[i]` the length. Buffers are hoisted by the caller and
/// reused -- zero per-call allocation. One syscall for up to `bufs.len()`
/// datagrams vs one per datagram with a plain `recv_from` loop.
pub fn recvmsg_batch(
    fd: std::os::fd::RawFd,
    bufs: &mut [Vec<u8>],
    sizes: &mut [usize],
    addrs: &mut [Option<net::SocketAddr>],
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
    if bufs.len() != sizes.len() || bufs.len() != addrs.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "recvmsg_batch slice lengths differ: bufs={}, sizes={}, addrs={}",
                bufs.len(),
                sizes.len(),
                addrs.len()
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
            sizes[i] = msgs[i].msg_len as usize;
        }
        Ok(received as usize)
    })
}

/// SAFETY: `storage` must have been filled by `recvmmsg` with a valid
/// address (IPv4-only, matching this workspace's bench harness).
unsafe fn sockaddr_to_addr(
    storage: &libc::sockaddr_storage,
    name_len: libc::socklen_t,
) -> Option<net::SocketAddr> {
    if storage.ss_family != libc::AF_INET as u16
        || (name_len as usize) < std::mem::size_of::<libc::sockaddr_in>()
    {
        return None;
    }
    // SAFETY: the caller guarantees kernel-filled storage; the checks above
    // establish the IPv4 family and sufficient initialized byte length. The
    // storage type provides alignment suitable for every sockaddr variant.
    let addr = unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
    Some(net::SocketAddr::from((
        net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    )))
}
