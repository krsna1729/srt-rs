//! Shared adapter plumbing between srt-protocol (sans-I/O) and
//! runtime-specific I/O.
//!
//! # Architecture
//!
//! This crate owns *things*; `srt-lifecycle` owns *decisions*. That is
//! the dividing line, not subject matter -- both deal with admission.
//! Live `SrtConnection`s, their timers, and file descriptors live here,
//! which is why the admission peer table does too even though the
//! promotion rule it consults lives in lifecycle. Mechanism depends on
//! policy; policy never depends back.
//!
//! ```text
//!   srt-bench ──► srt-transport ──► srt-lifecycle ──► srt-protocol
//!                      │                                   ▲
//!                      └───────────────────────────────────┘
//! ```
//!
//! Three layers:
//!
//! 1. **Shared utilities** (always compiled, no runtime deps):
//!    `ManualTimerStore`, `bind_reuseport`,
//!    `recvmsg_batch`. Protocol-level primitives that all runtimes need.
//!
//! 2. **Admission machinery** (always compiled, runtime-neutral, performs
//!    no I/O itself -- the caller does every send): `PeerTable` and
//!    `AdmissionPeer` track peers from first datagram until promotion or
//!    retirement; `poll_outbound`/`drain_events` are the maintenance tick
//!    with only the datagrams handed back; `Handoff`/`WorkerMessage` are
//!    the acceptor-to-worker protocol, carrying `Send`-safe parts so a
//!    cross-thread move is correct by construction; `IngressTelemetry`
//!    defines the counters and the report line once.
//!
//! 3. **Per-runtime `Conn` structs** (feature-gated): each wraps
//!    `SrtConnection` + runtime-specific socket + runtime-specific timer.
//!    Provides `fire_expired`, `drain_outputs`, `send_paced`,
//!    `recv_with_timeout`.
//!
//! # Design principle: no lowest common denominator
//!
//! Each runtime's `Conn` uses its own socket and its own I/O primitives
//! directly -- no shared trait flattens them, because the completion
//! runtimes need owned buffers and the readiness runtimes do not.
//!
//! Timers are the one place where sharing is correct rather than
//! lowest-common-denominator. SRT arms four independent timers
//! (`Keepalive`, `Ack`, `Nak`, `Inactivity`) and dispatches on the
//! `TimerId` when each fires, so a `Conn` needs a *map* of deadlines, not
//! one sleep future. Every adapter already drives its loop off socket
//! readiness with a short poll timeout, which means the deadline check is
//! a comparison against `now` -- there is no native primitive being given
//! up. `ManualTimerStore` is that map, and it is what calls
//! `SrtConnection::handle_timer`.
//!

use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, SrtConnection, TimerId, Timestamp,
};
use std::cmp::Ordering as CmpOrdering;
use std::collections::hash_map::Entry as HashEntry;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

mod config;

pub use config::*;

/// Per-tick limits for moving protocol outputs into a runtime socket.
///
/// The bounds are deliberately expressed in actions, packets, and bytes:
/// timer churn cannot bypass the action cap, while a burst of large UDP
/// datagrams cannot monopolize a readiness-loop iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputDrainBudget {
    pub max_actions: usize,
    pub max_packets: usize,
    pub max_bytes: usize,
}

impl OutputDrainBudget {
    #[must_use]
    pub const fn new(max_actions: usize, max_packets: usize, max_bytes: usize) -> Self {
        Self {
            max_actions,
            max_packets,
            max_bytes,
        }
    }
}

impl Default for OutputDrainBudget {
    fn default() -> Self {
        Self::new(64, 32, 256 * 1024)
    }
}

/// Compatibility configuration for existing low-level consumers.
///
/// New applications should prefer [`SessionConfig`], [`TransportConfig`],
/// [`AdmissionConfig`], [`ListenerConfig`], and [`CallerConfig`]. This compact
/// type remains supported when an application already owns topology, workers,
/// promotion, and runtime socket construction itself.
#[derive(Clone, Debug)]
pub struct SrtStackConfig {
    pub connection: ConnectionOptions,
    pub admission: PeerTableConfig,
    pub output_drain: OutputDrainBudget,
    /// Requested SO_RCVBUF/SO_SNDBUF bytes. Zero preserves OS defaults.
    pub socket_buffer_bytes: usize,
    /// Recover rehashed CONCLUSION packets using the listener-issued cookie.
    pub cookie_routing: bool,
}

impl Default for SrtStackConfig {
    fn default() -> Self {
        Self {
            connection: ConnectionOptions::default(),
            admission: PeerTableConfig::default(),
            output_drain: OutputDrainBudget::default(),
            socket_buffer_bytes: SOCK_BUF_BYTES,
            cookie_routing: true,
        }
    }
}

impl SrtStackConfig {
    /// Validate resource bounds before opening sockets or allocating peers.
    pub fn validate(&self) -> std::io::Result<()> {
        let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
        if self.connection.flow_window_packets == 0 {
            return Err(invalid("flow_window_packets must be non-zero"));
        }
        if self.connection.receive_buffer_packets == 0 {
            return Err(invalid("receive_buffer_packets must be non-zero"));
        }
        if self.admission.max_peers == 0 {
            return Err(invalid("admission.max_peers must be non-zero"));
        }
        if self.admission.max_half_open_peers == 0 {
            return Err(invalid("admission.max_half_open_peers must be non-zero"));
        }
        if self.admission.max_established_peers == 0 {
            return Err(invalid("admission.max_established_peers must be non-zero"));
        }
        if self.admission.max_peers_per_ip == 0 {
            return Err(invalid("admission.max_peers_per_ip must be non-zero"));
        }
        if self.admission.half_open_timeout.is_zero() {
            return Err(invalid("admission.half_open_timeout must be non-zero"));
        }
        if self.output_drain.max_actions == 0
            || self.output_drain.max_packets == 0
            || self.output_drain.max_bytes == 0
        {
            return Err(invalid("all output_drain limits must be non-zero"));
        }
        if self.socket_buffer_bytes > libc::c_int::MAX as usize {
            return Err(invalid(
                "socket_buffer_bytes exceeds the OS socket option range",
            ));
        }
        Ok(())
    }

    pub fn caller(&self) -> std::io::Result<SrtConnection> {
        self.validate()?;
        Ok(SrtConnection::new_caller(self.connection.clone()))
    }

    pub fn listener(&self) -> std::io::Result<SrtConnection> {
        self.validate()?;
        Ok(SrtConnection::new_listener(self.connection.clone()))
    }

    pub fn peer_table(&self) -> std::io::Result<PeerTable> {
        self.validate()?;
        Ok(PeerTable::with_config(self.admission))
    }

    #[must_use]
    pub fn admission_options(&self) -> AdmissionOptions {
        AdmissionOptions {
            socket_id: self.connection.socket_id,
            tsbpd_delay: self.connection.tsbpd_delay,
            cookie_routing: self.cookie_routing,
            connection_template: Some(self.connection.clone()),
            handshake_retry_interval: Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            ),
            handshake_timeout: Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_TIMEOUT_MICROS,
            ),
        }
    }

    pub fn bind_reuseport(&self, port: u16) -> std::io::Result<std::net::UdpSocket> {
        self.validate()?;
        bind_reuseport(port, self.socket_buffer_bytes)
    }
}

/// Why a bounded output-pump invocation yielded to its caller.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputDrainStatus {
    #[default]
    Drained,
    BudgetExhausted,
    Backpressured,
}

/// Work completed by one bounded output-pump invocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutputDrainReport {
    pub actions: usize,
    pub packets: usize,
    pub bytes: usize,
    pub status: OutputDrainStatus,
}

#[derive(Debug)]
struct DueEntry<K> {
    deadline_micros: u64,
    key: K,
}

impl<K> PartialEq for DueEntry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_micros == other.deadline_micros
    }
}

impl<K> Eq for DueEntry<K> {}

impl<K> PartialOrd for DueEntry<K> {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for DueEntry<K> {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.deadline_micros.cmp(&other.deadline_micros)
    }
}

/// Indexes the next deadline of many timer owners without scanning every
/// owner on each shared-loop iteration. Replaced/removed heap entries are
/// discarded lazily.
#[derive(Debug)]
pub struct DueIndex<K> {
    current: HashMap<K, u64>,
    heap: BinaryHeap<std::cmp::Reverse<DueEntry<K>>>,
}

impl<K> Default for DueIndex<K> {
    fn default() -> Self {
        Self {
            current: HashMap::new(),
            heap: BinaryHeap::new(),
        }
    }
}

impl<K> DueIndex<K>
where
    K: Clone + Eq + Hash,
{
    pub fn set(&mut self, key: K, deadline: Timestamp) {
        let deadline_micros = deadline.as_micros();
        self.current.insert(key.clone(), deadline_micros);
        self.heap.push(std::cmp::Reverse(DueEntry {
            deadline_micros,
            key,
        }));
    }

    pub fn remove(&mut self, key: &K) {
        self.current.remove(key);
    }

    pub fn pop_due(&mut self, now: Timestamp, out: &mut Vec<K>) {
        out.clear();
        while let Some(std::cmp::Reverse(top)) = self.heap.peek()
            && top.deadline_micros <= now.as_micros()
        {
            let std::cmp::Reverse(entry) = self.heap.pop().expect("peeked entry exists");
            match self.current.entry(entry.key.clone()) {
                HashEntry::Occupied(slot) if *slot.get() == entry.deadline_micros => {
                    slot.remove();
                    out.push(entry.key);
                }
                _ => {}
            }
        }
    }

    /// Earliest live deadline, cleaning stale heap entries as necessary.
    pub fn peek_min_deadline(&mut self) -> Option<Timestamp> {
        loop {
            let std::cmp::Reverse(entry) = self.heap.pop()?;
            match self.current.get(&entry.key) {
                Some(&deadline) if deadline == entry.deadline_micros => {
                    let result = Timestamp::from_micros(deadline);
                    self.heap.push(std::cmp::Reverse(entry));
                    return Some(result);
                }
                _ => continue,
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.current.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }
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
    addrs: &mut [Option<std::net::SocketAddr>],
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
) -> Option<std::net::SocketAddr> {
    if storage.ss_family != libc::AF_INET as u16
        || (name_len as usize) < std::mem::size_of::<libc::sockaddr_in>()
    {
        return None;
    }
    // SAFETY: the caller guarantees kernel-filled storage; the checks above
    // establish the IPv4 family and sufficient initialized byte length. The
    // storage type provides alignment suitable for every sockaddr variant.
    let addr = unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
    Some(std::net::SocketAddr::from((
        std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    )))
}

// ---------------------------------------------------------------------------
// CPU budget
// ---------------------------------------------------------------------------

/// Parse a CPU set spec: comma-separated indices and inclusive ranges,
/// e.g. `"0-2"`, `"0,2,4"`, `"0-1,4-5"`. Empty means "leave it alone".
///
/// A list rather than a count because sender and receiver need *disjoint*
/// sets, not just budgets: giving each "4 CPUs" starting from 0 would
/// place them on the same cores and have them fight.
#[must_use]
pub fn parse_cpu_spec(spec: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((lo, hi)) => {
                if let (Ok(lo), Ok(hi)) = (lo.trim().parse(), hi.trim().parse::<usize>()) {
                    for cpu in lo..=hi {
                        cpus.push(cpu);
                    }
                }
            }
            None => {
                if let Ok(cpu) = part.parse() {
                    cpus.push(cpu);
                }
            }
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

/// Restrict this process to `cpus`.
///
/// Benchmarks that do not say how much CPU they were given are not
/// reproducible: the same binary on a 6-core and a 64-core host is two
/// different experiments. Pinning the two roles to disjoint sets goes
/// further -- it stops the sender and receiver competing, so a listener
/// that is compute-bound can be given cores without the load generator
/// taking them back.
///
/// An empty slice leaves the inherited mask alone.
pub fn restrict_to_cpu_list(cpus: &[usize]) -> std::io::Result<()> {
    if cpus.is_empty() {
        return Ok(());
    }
    // SAFETY: `set` has the exact libc type and is initialized before use;
    // indices are checked against `CPU_SETSIZE`, and the syscall only reads
    // the set during the call.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for &cpu in cpus {
            if cpu < libc::CPU_SETSIZE as usize {
                libc::CPU_SET(cpu, &mut set);
            }
        }
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// How many logical CPUs this process may currently run on.
#[must_use]
pub fn available_cpus() -> usize {
    // SAFETY: `set` is valid writable storage of the exact size supplied to
    // the syscall. On success CPU_ISSET reads only the initialized result.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        }
        (0..libc::CPU_SETSIZE as usize)
            .filter(|cpu| libc::CPU_ISSET(*cpu, &set))
            .count()
            .max(1)
    }
}

// ---------------------------------------------------------------------------
// Admission peer table — shared by every reuseport ingress strategy
// ---------------------------------------------------------------------------

/// One connection tracked from admission until it is promoted, relocated,
/// or retired -- serviced off the shared listener socket by peer-address
/// dispatch the whole time.
/// Did this `Disconnected` reason mean the ordered close, or something
/// going wrong?
///
/// The sender ends a run by calling `SrtConnection::disconnect`, which
/// emits an SRT SHUTDOWN; the peer reports that as `peer shutdown`. The
/// sender itself gets no event for its own close, so on that side every
/// `Disconnected` is by definition unplanned.
#[must_use]
pub fn is_ordered_close(reason: &str) -> bool {
    reason == "peer shutdown"
}

pub struct AdmissionPeer {
    pub conn: SrtConnection,
    pub timers: ManualTimerStore,
    /// Live connected state, feeding `srt_lifecycle::is_terminal`. Goes
    /// false again on `Disconnected`.
    pub connected: bool,
    /// `None` until this peer's first `Connected`, which also makes it
    /// the "has this ever connected" flag. Final success reporting should
    /// use this rather than `connected`: a session that streamed
    /// everything and then tripped the peer-idle timeout is still a
    /// success.
    pub stream_deadline: Option<Instant>,
    pub data_events: u64,
    pub last_data_at: Instant,
    /// This peer went away for a reason other than the ordered close --
    /// an idle timeout, or an error. Distinct from `connected`, which
    /// also goes false on a clean shutdown, and from `stream_deadline`,
    /// which records only that it once connected.
    pub torn_down: bool,
    /// A policy rejection is queued for transmission and this entry must
    /// never accept more input. It is retired after `poll_outbound` drains
    /// the rejection packet.
    rejected: bool,
    admission_established: bool,
    last_datagram_at: Timestamp,
}

impl AdmissionPeer {
    /// Apply one protocol event to this peer's bookkeeping. Returns
    /// `true` exactly once per peer: on the event that is its first-ever
    /// `Connected`, which is the caller's cue to arm `stream_deadline` and
    /// treat the peer as newly admitted (relocation, `--promotion`, etc).
    ///
    /// The single implementation of "what a Connected/DataReceived/
    /// Disconnected event means for one admitted peer" -- previously
    /// hand-copied identically into each of the six runtime adapters'
    /// per-tick admission loops, plus a seventh, slightly different copy
    /// inside `PeerTable::drain_events`.
    pub fn apply_event(&mut self, event: shiguredo_srt::ConnectionEvent) -> bool {
        use shiguredo_srt::ConnectionEvent;
        match event {
            ConnectionEvent::Connected => {
                let first_connect = self.stream_deadline.is_none();
                self.connected = true;
                first_connect
            }
            ConnectionEvent::DataReceived { .. } => {
                self.data_events += 1;
                self.last_data_at = Instant::now();
                false
            }
            ConnectionEvent::Disconnected { reason } => {
                self.torn_down |= !is_ordered_close(&reason);
                self.connected = false;
                false
            }
            _ => false,
        }
    }
}

/// Per-listener settings the table needs to mint new connections and to
/// decide cookie routing.
#[derive(Clone, Debug)]
pub struct AdmissionOptions {
    pub socket_id: u32,
    pub tsbpd_delay: u16,
    /// Forward a handshake datagram to the acceptor its SYN cookie names.
    /// Off makes a rehashed CONCLUSION strand instead, which is only
    /// useful for measuring what the routing is worth.
    pub cookie_routing: bool,
    /// Complete session template for peers created on a shared listener.
    /// `None` preserves the legacy socket-id/latency-only construction.
    pub connection_template: Option<ConnectionOptions>,
    pub handshake_retry_interval: Duration,
    pub handshake_timeout: Duration,
}

impl AdmissionOptions {
    /// Compatibility constructor for applications that configure the protocol
    /// connection separately.
    #[must_use]
    pub fn basic(socket_id: u32, tsbpd_delay: u16, cookie_routing: bool) -> Self {
        Self {
            socket_id,
            tsbpd_delay,
            cookie_routing,
            connection_template: None,
            handshake_retry_interval: Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            ),
            handshake_timeout: Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_TIMEOUT_MICROS,
            ),
        }
    }
}

impl Drop for AdmissionOptions {
    fn drop(&mut self) {
        let Some(template) = self.connection_template.as_mut() else {
            return;
        };
        if let Some(passphrase) = template.passphrase.as_mut() {
            passphrase.zeroize();
        }
        if let Some(salt) = template.crypto_salt.as_mut() {
            salt.zeroize();
        }
        if let Some(sek) = template.crypto_sek.as_mut() {
            sek.zeroize();
        }
    }
}

/// Resource limits for one shared-listener admission table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerTableConfig {
    /// Total half-open plus established peers retained by this table.
    pub max_peers: usize,
    /// Incomplete handshakes retained concurrently.
    pub max_half_open_peers: usize,
    /// Fully established peers retained concurrently.
    pub max_established_peers: usize,
    /// Total peers from one source IP (ports do not bypass this bound).
    pub max_peers_per_ip: usize,
    pub half_open_timeout: Duration,
}

impl Default for PeerTableConfig {
    fn default() -> Self {
        Self {
            max_peers: 4096,
            max_half_open_peers: 1024,
            max_established_peers: 4096,
            // Safe compatibility default: the per-source mechanism is active
            // but no tighter than the table-wide bound until an application
            // chooses a tenant/source policy.
            max_peers_per_ip: 4096,
            half_open_timeout: Duration::from_secs(10),
        }
    }
}

/// Application authorization result for a claimed, not-yet-authenticated
/// handshake identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionDecision {
    Accept,
    Reject { reason: i32 },
}

/// A libsrt-compatible application rejection code.
///
/// The 1000-1999 range is reserved for predefined meanings and 2000-2999 for
/// application-specific reasons. The legacy [`AdmissionDecision`] API remains
/// available when exact wire compatibility requires an unchecked raw value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RejectionReason(i32);

impl RejectionReason {
    pub const BAD_REQUEST: Self = Self(1400);
    pub const UNAUTHORIZED: Self = Self(1401);
    pub const OVERLOAD: Self = Self(1402);
    pub const FORBIDDEN: Self = Self(1403);
    pub const NOT_FOUND: Self = Self(1404);
    pub const BAD_MODE: Self = Self(1405);
    pub const UNACCEPTABLE: Self = Self(1406);
    pub const INTERNAL_ERROR: Self = Self(1500);

    /// Construct an application-owned rejection in libsrt's 2000-2999 range.
    #[must_use]
    pub const fn application(code: u16) -> Option<Self> {
        if code <= 999 {
            Some(Self(2000 + code as i32))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

/// Context made available after cookie validation and before the protocol core
/// processes a caller's CONCLUSION or KM request.
///
/// Every caller-controlled field is untrusted at this point. In particular,
/// StreamID and parsed access-control values are merely credential-validated
/// claims after a selected passphrase successfully validates the KM exchange;
/// SRT passphrase mode is not general peer authentication.
#[derive(Clone, Debug)]
pub struct AdmissionRequest {
    pub peer: std::net::SocketAddr,
    pub claimed_identity: srt_lifecycle::HandshakeIdentity,
    pub handshake: shiguredo_srt::HandshakePacket,
    pub access_control: Option<shiguredo_srt::stream_id::AccessControl>,
}

/// Result of resolving policy for one valid CONCLUSION.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AdmissionResolution {
    #[default]
    Accept,
    Configure(ListenerPeerPolicy),
    Reject {
        reason: RejectionReason,
    },
    /// Leave the half-open peer untouched. A retransmitted CONCLUSION may be
    /// resolved later, but the original hard half-open expiry is not extended.
    Defer,
}

enum AdmissionHookResult {
    Accept,
    Configure(ListenerPeerPolicy),
    Reject(i32),
    Defer,
}

impl From<AdmissionResolution> for AdmissionHookResult {
    fn from(value: AdmissionResolution) -> Self {
        match value {
            AdmissionResolution::Accept => Self::Accept,
            AdmissionResolution::Configure(policy) => Self::Configure(policy),
            AdmissionResolution::Reject { reason } => Self::Reject(reason.get()),
            AdmissionResolution::Defer => Self::Defer,
        }
    }
}

/// Why an admission datagram was discarded without creating connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionDropReason {
    InvalidPacket,
    InvalidCookie,
    StaleConclusion,
    RejectedPeer,
    /// Total peer-table capacity was reached.
    Capacity,
    /// Incomplete-handshake capacity was reached.
    HalfOpenCapacity,
    /// Established-peer capacity was reached.
    EstablishedCapacity,
    /// One source IP reached its configured share.
    SourceCapacity,
}

/// What [`PeerTable::admit`] did with a datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Fed to the peer's connection, creating it if this is its first
    /// packet.
    Fed,
    /// Belongs to another acceptor's half-open handshake; the caller
    /// should send it there as [`WorkerMessage::Handshake`].
    ForwardTo(usize),
    /// The application rejected the conclusion before it became connected.
    Rejected,
    /// Policy resolution intentionally retained the half-open peer without
    /// feeding or extending the CONCLUSION.
    Deferred,
    /// The datagram was invalid, stale, or exceeded the configured bound.
    Dropped(AdmissionDropReason),
}

/// One unmodified protocol event emitted by an admitted peer.
///
/// Production consumers should use [`PeerTable::poll_events`] so received
/// payloads and disconnect reasons leave the transport layer intact. The
/// benchmark-only [`PeerTable::drain_events`] adapter remains for its legacy
/// counters and promotion timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionEvent {
    pub peer: std::net::SocketAddr,
    pub event: ConnectionEvent,
}

/// The peers one acceptor is servicing off its shared listener.
///
/// This is the admission session state machine, minus I/O: it owns the
/// protocol objects and their timers, decides cookie routing, and records
/// telemetry, but never touches a socket. The caller drives the sending.
/// It lives here rather than in srt-lifecycle because it owns clocks and
/// live protocol state, which that crate deliberately does not.
pub struct PeerTable {
    peers: HashMap<std::net::SocketAddr, AdmissionPeer>,
    source_counts: HashMap<std::net::IpAddr, usize>,
    half_open_peers: usize,
    established_peers: usize,
    half_open_deadlines: DueIndex<std::net::SocketAddr>,
    deadlines: DueIndex<std::net::SocketAddr>,
    ready: VecDeque<std::net::SocketAddr>,
    ready_set: HashSet<std::net::SocketAddr>,
    event_ready: VecDeque<std::net::SocketAddr>,
    event_ready_set: HashSet<std::net::SocketAddr>,
    config: PeerTableConfig,
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::with_config(PeerTableConfig::default())
    }
}

impl PeerTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_config(mut config: PeerTableConfig) -> Self {
        config.max_peers = config.max_peers.max(1);
        config.max_half_open_peers = config.max_half_open_peers.max(1).min(config.max_peers);
        config.max_established_peers = config.max_established_peers.max(1).min(config.max_peers);
        config.max_peers_per_ip = config.max_peers_per_ip.max(1).min(config.max_peers);
        Self {
            peers: HashMap::new(),
            source_counts: HashMap::new(),
            half_open_peers: 0,
            established_peers: 0,
            half_open_deadlines: DueIndex::default(),
            deadlines: DueIndex::default(),
            ready: VecDeque::new(),
            ready_set: HashSet::new(),
            event_ready: VecDeque::new(),
            event_ready_set: HashSet::new(),
            config,
        }
    }

    /// Take one datagram for `peer`.
    ///
    /// `worker_index`/`worker_count` identify this acceptor within the
    /// reuseport group so a CONCLUSION carrying someone else's cookie can
    /// be routed home rather than answered here (cookie validation would
    /// reject it) or dropped (a handshake retry).
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
    ) -> Admit {
        self.admit_with_authorizer(
            peer,
            data,
            now,
            options,
            worker_index,
            worker_count,
            telemetry,
            |_| AdmissionDecision::Accept,
        )
    }

    /// Admit a datagram, authorizing a valid CONCLUSION before it is fed to
    /// the protocol core and can transition to `Connected`.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_authorizer<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
        authorize: F,
    ) -> Admit
    where
        F: FnOnce(&srt_lifecycle::HandshakeIdentity) -> AdmissionDecision,
    {
        self.admit_with_policy_hook(
            peer,
            data,
            now,
            options,
            worker_index,
            worker_count,
            telemetry,
            |request, _connection| match authorize(&request.claimed_identity) {
                AdmissionDecision::Accept => AdmissionHookResult::Accept,
                AdmissionDecision::Reject { reason } => AdmissionHookResult::Reject(reason),
            },
        )
    }

    /// Resolve typed per-peer policy from the caller's claimed identity and
    /// raw handshake context. The resolver runs synchronously in the packet
    /// path and should use bounded, cached work.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_resolver<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
        resolve: F,
    ) -> Admit
    where
        F: FnOnce(&AdmissionRequest) -> AdmissionResolution,
    {
        self.admit_with_policy_hook(
            peer,
            data,
            now,
            options,
            worker_index,
            worker_count,
            telemetry,
            |request, _connection| resolve(request).into(),
        )
    }

    /// Expert pre-CONCLUSION escape hatch.
    ///
    /// This exposes the guarded [`SrtConnection`] setters for protocol options
    /// not modeled by [`ListenerPeerPolicy`]. The hook is invoked only after
    /// capacity and cookie checks and immediately before protocol input. It
    /// must not retain the connection reference or perform unbounded I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_connection_hook<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
        hook: F,
    ) -> Admit
    where
        F: FnOnce(&AdmissionRequest, &mut SrtConnection) -> AdmissionResolution,
    {
        self.admit_with_policy_hook(
            peer,
            data,
            now,
            options,
            worker_index,
            worker_count,
            telemetry,
            |request, connection| hook(request, connection).into(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_with_policy_hook<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
        hook: F,
    ) -> Admit
    where
        F: FnOnce(&AdmissionRequest, &mut SrtConnection) -> AdmissionHookResult,
    {
        let expired = self.prune_half_open(now);
        telemetry.record_expired_half_open(expired);
        let known = self.peers.contains_key(&peer);
        let handshake = shiguredo_srt::peek_handshake(data);
        let identity = handshake
            .as_ref()
            .map(srt_lifecycle::handshake_identity_from_handshake);
        let conclusion = identity.as_ref().filter(|identity| identity.is_conclusion);

        if !known && let Some(identity) = conclusion {
            let owner = srt_lifecycle::worker_from_cookie(identity.syn_cookie, worker_count);
            match owner {
                Some(owner) if owner != worker_index => {
                    if options.cookie_routing {
                        telemetry.record_cookie_routed();
                        return Admit::ForwardTo(owner);
                    }
                    // Routing disabled: it will be answered here and fail
                    // cookie validation, which is the cost being measured.
                    telemetry.record_stranded_conclusion();
                }
                // The cookie names this acceptor, but the peer is gone --
                // it was already promoted off the shared listener, so
                // this is a late or duplicate CONCLUSION rather than a
                // stranded handshake. Conflating the two makes the
                // routing measurement meaningless.
                Some(_) => telemetry.record_promoted_duplicate(),
                None => telemetry.record_stranded_conclusion(),
            }
            return Admit::Dropped(AdmissionDropReason::StaleConclusion);
        }

        if !known {
            let Some(packet) = handshake.as_ref() else {
                telemetry.record_invalid_datagram();
                return Admit::Dropped(AdmissionDropReason::InvalidPacket);
            };
            if packet.handshake_type != shiguredo_srt::HandshakeType::Induction {
                telemetry.record_invalid_datagram();
                return Admit::Dropped(AdmissionDropReason::InvalidPacket);
            }
            if self.peers.len() >= self.config.max_peers {
                telemetry.record_admission_capacity_drop();
                return Admit::Dropped(AdmissionDropReason::Capacity);
            }
            if self.half_open_count() >= self.config.max_half_open_peers {
                telemetry.record_half_open_capacity_drop();
                return Admit::Dropped(AdmissionDropReason::HalfOpenCapacity);
            }
            if self.peers_for_ip(peer.ip()) >= self.config.max_peers_per_ip {
                telemetry.record_source_capacity_drop();
                return Admit::Dropped(AdmissionDropReason::SourceCapacity);
            }
        } else if let Some(identity) = conclusion {
            if self
                .peers
                .get(&peer)
                .is_some_and(|entry| !entry.admission_established)
                && self.established_count() >= self.config.max_established_peers
            {
                telemetry.record_established_capacity_drop();
                return Admit::Dropped(AdmissionDropReason::EstablishedCapacity);
            }
            let Some(entry) = self.peers.get_mut(&peer) else {
                return Admit::Dropped(AdmissionDropReason::StaleConclusion);
            };
            if entry.rejected {
                return Admit::Dropped(AdmissionDropReason::RejectedPeer);
            }
            if identity.syn_cookie != entry.conn.syn_cookie() {
                telemetry.record_invalid_cookie();
                return Admit::Dropped(AdmissionDropReason::InvalidCookie);
            }
            let packet = handshake
                .as_ref()
                .expect("a conclusion identity came from a decoded handshake");
            let request = AdmissionRequest {
                peer,
                claimed_identity: identity.clone(),
                handshake: packet.clone(),
                access_control: identity
                    .stream_id
                    .as_deref()
                    .and_then(shiguredo_srt::stream_id::AccessControl::parse),
            };
            telemetry.record_policy_request();
            match hook(&request, &mut entry.conn) {
                AdmissionHookResult::Accept => {}
                AdmissionHookResult::Configure(policy) => {
                    if policy.apply_to(&mut entry.conn).is_err() {
                        telemetry.record_policy_error();
                        if entry
                            .conn
                            .reject(RejectionReason::INTERNAL_ERROR.get(), now)
                            .is_err()
                        {
                            telemetry.record_invalid_datagram();
                            return Admit::Dropped(AdmissionDropReason::InvalidPacket);
                        }
                        entry.rejected = true;
                        self.mark_ready(peer);
                        return Admit::Rejected;
                    }
                    telemetry.record_policy_configuration();
                }
                AdmissionHookResult::Reject(reason) => {
                    if entry.conn.reject(reason, now).is_err() {
                        telemetry.record_invalid_datagram();
                        return Admit::Dropped(AdmissionDropReason::InvalidPacket);
                    }
                    telemetry.record_policy_rejection();
                    entry.rejected = true;
                    entry.last_datagram_at = now;
                    self.mark_ready(peer);
                    return Admit::Rejected;
                }
                AdmissionHookResult::Defer => {
                    telemetry.record_policy_deferred();
                    return Admit::Deferred;
                }
            }
        }

        let (fed, feed_error_kind, inserted, became_established, became_terminal) = {
            let mut inserted = false;
            let entry = self.peers.entry(peer).or_insert_with(|| {
                inserted = true;
                let mut connection_options =
                    options.connection_template.clone().unwrap_or_default();
                connection_options.socket_id = options.socket_id;
                connection_options.tsbpd_delay = options.tsbpd_delay;
                // Encode who owns this handshake, so a CONCLUSION the kernel
                // rehashes elsewhere can be routed back here.
                connection_options.syn_cookie = Some(srt_lifecycle::cookie_for_worker(
                    worker_index,
                    peer_entropy(peer),
                ));
                let mut conn = SrtConnection::new_listener(connection_options);
                conn.set_handshake_timing(
                    u64::try_from(options.handshake_retry_interval.as_micros()).unwrap_or(u64::MAX),
                    u64::try_from(options.handshake_timeout.as_micros()).unwrap_or(u64::MAX),
                );
                AdmissionPeer {
                    conn,
                    timers: ManualTimerStore::new(),
                    connected: false,
                    stream_deadline: None,
                    data_events: 0,
                    last_data_at: Instant::now(),
                    torn_down: false,
                    rejected: false,
                    admission_established: false,
                    last_datagram_at: now,
                }
            });
            let feed_result = entry.conn.feed_recv_buf(data, now);
            let feed_error_kind = feed_result.as_ref().err().map(|error| error.kind);
            let fed = feed_result.is_ok();
            if fed {
                entry.last_datagram_at = now;
            }
            let became_established = fed
                && !entry.admission_established
                && entry.conn.state() == shiguredo_srt::ConnectionState::Connected;
            if became_established {
                entry.admission_established = true;
            }
            let became_terminal =
                !fed && entry.conn.state() == shiguredo_srt::ConnectionState::Disconnected;
            if became_terminal {
                entry.rejected = true;
            }
            (
                fed,
                feed_error_kind,
                inserted,
                became_established,
                became_terminal,
            )
        };
        if inserted {
            *self.source_counts.entry(peer.ip()).or_default() += 1;
            self.half_open_peers += 1;
        }
        if !fed {
            if conclusion.is_some()
                && matches!(
                    feed_error_kind,
                    Some(
                        shiguredo_srt::ErrorKind::CryptoError
                            | shiguredo_srt::ErrorKind::HandshakeRejected
                    )
                )
            {
                telemetry.record_credential_failure();
            }
            telemetry.record_invalid_datagram();
            if !known {
                let _ = self.remove(&peer);
            } else if became_terminal {
                self.mark_ready(peer);
            }
            return Admit::Dropped(AdmissionDropReason::InvalidPacket);
        }
        if became_established {
            self.half_open_peers = self.half_open_peers.saturating_sub(1);
            self.established_peers += 1;
            self.half_open_deadlines.remove(&peer);
        } else if !self
            .peers
            .get(&peer)
            .is_some_and(|entry| entry.admission_established)
        {
            self.half_open_deadlines.set(
                peer,
                now.add_micros(half_open_timeout_micros(self.config.half_open_timeout)),
            );
        }
        self.mark_ready(peer);
        Admit::Fed
    }

    /// Remove incomplete handshakes that have stopped making progress.
    pub fn prune_half_open(&mut self, now: Timestamp) -> usize {
        let mut due = Vec::new();
        self.half_open_deadlines.pop_due(now, &mut due);
        let timeout_micros = half_open_timeout_micros(self.config.half_open_timeout);
        let mut count = 0;
        for peer in due {
            let stale = self.peers.get(&peer).is_some_and(|entry| {
                !entry.admission_established
                    && now.saturating_sub(entry.last_datagram_at) >= timeout_micros
            });
            if !stale {
                continue;
            }
            let _ = self.remove(&peer);
            count += 1;
        }
        count
    }

    /// [`Self::admit`] plus the send it implies: forward the datagram to
    /// the acceptor its cookie names, or keep it here if that channel is
    /// gone. Dropping it instead would cost a handshake retry.
    ///
    /// The send lives here rather than in each adapter because every one
    /// of them did exactly this, and the routing decision is worthless
    /// without the delivery that follows it.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_and_forward(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        senders: &[std::sync::mpsc::Sender<WorkerMessage>],
        telemetry: &IngressTelemetry,
    ) {
        match self.admit(
            peer,
            data,
            now,
            options,
            worker_index,
            senders.len(),
            telemetry,
        ) {
            Admit::Fed => {}
            Admit::ForwardTo(owner) => {
                let message = WorkerMessage::Handshake {
                    peer,
                    data: data.to_vec(),
                };
                if senders[owner].send(message).is_err() {
                    telemetry.record_cookie_route_failure();
                    // The half-open state existed only on the closed owner;
                    // another acceptor cannot safely synthesize it from a
                    // CONCLUSION. The caller's next handshake attempt starts
                    // with a fresh INDUCTION and cookie.
                }
            }
            Admit::Rejected | Admit::Deferred | Admit::Dropped(_) => {}
        }
    }

    /// Resolver-enabled form of [`Self::admit_and_forward`].
    ///
    /// The resolver is called only on the acceptor that owns the retained
    /// half-open state. A datagram forwarded to another acceptor is resolved
    /// there, so policy and credentials never need to cross worker channels.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_and_forward_with_resolver<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        senders: &[std::sync::mpsc::Sender<WorkerMessage>],
        telemetry: &IngressTelemetry,
        resolve: F,
    ) -> Admit
    where
        F: FnOnce(&AdmissionRequest) -> AdmissionResolution,
    {
        let result = self.admit_with_resolver(
            peer,
            data,
            now,
            options,
            worker_index,
            senders.len(),
            telemetry,
            resolve,
        );
        if let Admit::ForwardTo(owner) = &result {
            let message = WorkerMessage::Handshake {
                peer,
                data: data.to_vec(),
            };
            if senders[*owner].send(message).is_err() {
                telemetry.record_cookie_route_failure();
                return Admit::Dropped(AdmissionDropReason::StaleConclusion);
            }
        }
        result
    }

    /// Fire due peers' timers and collect what ready peers want to send.
    ///
    /// Timer outputs are applied to the peer's own store; only packets
    /// come back, because sending is the one part of the maintenance tick
    /// that is genuinely per-runtime. `out` is reused across ticks rather
    /// than reallocated -- this runs once per tick per acceptor.
    pub fn poll_outbound(
        &mut self,
        now: Timestamp,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        out.clear();
        let mut rejected = Vec::new();
        let mut due = Vec::new();
        self.deadlines.pop_due(now, &mut due);
        for peer in due {
            self.mark_ready(peer);
        }

        while let Some(peer) = self.ready.pop_front() {
            self.ready_set.remove(&peer);
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            entry.timers.fire_expired(now, &mut entry.conn);
            while let Some(output) = entry.conn.poll_output() {
                match output {
                    ConnectionOutput::SendPacket(bytes) => out.push((peer, bytes)),
                    other => entry.timers.apply_output(&other, now),
                }
            }
            if entry.rejected {
                rejected.push(peer);
                continue;
            }
            if let Some(deadline) = entry.timers.next_deadline() {
                self.deadlines.set(peer, deadline);
            } else {
                self.deadlines.remove(&peer);
            }
        }
        for peer in rejected {
            let _ = self.remove(&peer);
        }
    }

    /// Mark a peer whose protocol state was changed through [`Self::iter_mut`]
    /// as ready for the next indexed maintenance pass.
    pub fn mark_ready(&mut self, peer: std::net::SocketAddr) {
        self.reconcile_established(peer);
        if self.peers.contains_key(&peer) {
            if self.ready_set.insert(peer) {
                self.ready.push_back(peer);
            }
            if self.event_ready_set.insert(peer) {
                self.event_ready.push_back(peer);
            }
        }
    }

    /// Microseconds until any tracked peer's next timer deadline.
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        self.deadlines
            .peek_min_deadline()
            .map(|deadline| deadline.saturating_sub(now))
            .unwrap_or(default_us)
    }

    /// Drain unmodified protocol events for production consumers.
    pub fn poll_events(&mut self, out: &mut Vec<AdmissionEvent>) {
        out.clear();
        while let Some(peer) = self.event_ready.pop_front() {
            self.event_ready_set.remove(&peer);
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            while let Some(event) = entry.conn.poll_event() {
                out.push(AdmissionEvent { peer, event });
            }
        }
    }

    /// Drain protocol events into per-peer bookkeeping.
    ///
    /// Returns, in `newly_connected`, the peers whose *first* `Connected`
    /// fired on this tick -- the moment a promotion decision is due.
    /// `stream_len` sets each one's stream deadline from now.
    pub fn drain_events(
        &mut self,
        stream_len: Duration,
        newly_connected: &mut Vec<std::net::SocketAddr>,
    ) {
        newly_connected.clear();
        let mut events = Vec::new();
        self.poll_events(&mut events);
        let deadline = Instant::now() + stream_len;
        for admission_event in events {
            if let Some(entry) = self.peers.get_mut(&admission_event.peer)
                && entry.apply_event(admission_event.event)
            {
                entry.stream_deadline = Some(deadline);
                newly_connected.push(admission_event.peer);
            }
        }
    }

    #[must_use]
    pub fn contains(&self, peer: &std::net::SocketAddr) -> bool {
        self.peers.contains_key(peer)
    }

    #[must_use]
    pub fn get(&self, peer: &std::net::SocketAddr) -> Option<&AdmissionPeer> {
        self.peers.get(peer)
    }

    /// Mutable peer access for advanced integrations that need to inspect or
    /// drive protocol state beyond the standard admission helpers.
    ///
    /// If external work queues new output, call [`Self::mark_ready`] so the
    /// next maintenance pass observes it promptly.
    pub fn get_mut(&mut self, peer: &std::net::SocketAddr) -> Option<&mut AdmissionPeer> {
        self.peers.get_mut(peer)
    }

    pub fn remove(&mut self, peer: &std::net::SocketAddr) -> Option<AdmissionPeer> {
        self.deadlines.remove(peer);
        self.half_open_deadlines.remove(peer);
        self.ready_set.remove(peer);
        self.event_ready_set.remove(peer);
        let removed = self.peers.remove(peer);
        if let Some(entry) = &removed {
            if entry.admission_established {
                self.established_peers = self.established_peers.saturating_sub(1);
            } else {
                self.half_open_peers = self.half_open_peers.saturating_sub(1);
            }
        }
        if removed.is_some()
            && let HashEntry::Occupied(mut entry) = self.source_counts.entry(peer.ip())
        {
            let count = entry.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                entry.remove();
            }
        }
        removed
    }

    pub fn iter_mut(
        &mut self,
    ) -> impl Iterator<Item = (&std::net::SocketAddr, &mut AdmissionPeer)> {
        self.peers.iter_mut()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    #[must_use]
    pub fn half_open_count(&self) -> usize {
        self.half_open_peers
    }

    #[must_use]
    pub fn established_count(&self) -> usize {
        self.established_peers
    }

    #[must_use]
    pub fn peers_for_ip(&self, ip: std::net::IpAddr) -> usize {
        self.source_counts.get(&ip).copied().unwrap_or_default()
    }

    fn reconcile_established(&mut self, peer: std::net::SocketAddr) {
        let became_established = self.peers.get_mut(&peer).is_some_and(|entry| {
            if !entry.admission_established
                && entry.conn.state() == shiguredo_srt::ConnectionState::Connected
            {
                entry.admission_established = true;
                true
            } else {
                false
            }
        });
        if became_established {
            self.half_open_peers = self.half_open_peers.saturating_sub(1);
            self.established_peers += 1;
            self.half_open_deadlines.remove(&peer);
        }
    }

    /// Whether every tracked peer is done, so the acceptor can stop.
    /// Vacuously true when empty, so an acceptor that never admitted
    /// anything still exits once its connect window closes.
    #[must_use]
    pub fn all_terminal(
        &self,
        now: Instant,
        connect_deadline: Instant,
        idle_grace: Duration,
    ) -> bool {
        self.peers.values().all(|p| {
            srt_lifecycle::is_terminal(
                p.connected,
                p.stream_deadline,
                p.last_data_at,
                now,
                connect_deadline,
                idle_grace,
            )
        })
    }
}

impl IntoIterator for PeerTable {
    type Item = (std::net::SocketAddr, AdmissionPeer);
    type IntoIter = std::collections::hash_map::IntoIter<std::net::SocketAddr, AdmissionPeer>;
    fn into_iter(self) -> Self::IntoIter {
        self.peers.into_iter()
    }
}

/// Per-peer entropy for the upper bits of a SYN cookie, so cookies differ
/// per connection instead of being one constant per worker.
fn peer_entropy(peer: std::net::SocketAddr) -> u32 {
    use std::hash::BuildHasher;
    std::collections::hash_map::RandomState::new().hash_one(peer) as u32
}

fn half_open_timeout_micros(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_micros()).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Acceptor -> worker message protocol
// ---------------------------------------------------------------------------

/// A connection handed from the acceptor that completed its handshake to
/// the thread that will service it.
///
/// The socket is a plain `std::net::UdpSocket` and the protocol state is
/// a bare `SrtConnection` on purpose: both are `Send`, whereas every
/// runtime's own `Conn` wrapper holds a native timer future that is not.
/// Shipping the parts and rebuilding the wrapper on the receiving thread
/// makes the cross-thread move correct by construction rather than by
/// convention -- there is no way to accidentally put a `!Send` timer in
/// this struct, because the type does not have a field for one.
pub struct Handoff {
    pub socket: std::net::UdpSocket,
    pub conn: SrtConnection,
}

/// What one acceptor sends to another, or to a dedicated worker.
///
/// This is the whole acceptor-to-worker protocol for the reuseport
/// ingress strategies, in one definition rather than one per runtime
/// adapter.
pub enum WorkerMessage {
    /// Take ownership of this fully-established connection.
    Handoff(Box<Handoff>),
    /// A handshake datagram the kernel delivered to the wrong acceptor.
    /// Its SYN cookie names the acceptor that owns the half-open
    /// handshake, so it is forwarded there rather than answered locally
    /// (cookie validation would reject it) or dropped (which costs a
    /// handshake retry). See `srt_lifecycle::cookie_for_worker`.
    Handshake {
        peer: std::net::SocketAddr,
        data: Vec<u8>,
    },
    /// Admission is over and `total` connections were sent in all, so a
    /// worker can tell "no more are coming" from "none have arrived yet"
    /// instead of guessing from a wall clock. Only the single-acceptor
    /// strategy sends this; where every acceptor is also a worker there
    /// is no separate admission-done moment to report.
    Finished { total: usize },
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
    /// CONCLUSION datagrams assigned to their owning acceptor by SYN cookie.
    /// Closed-channel delivery failures are counted separately.
    pub cookie_routed: AtomicU64,
    /// Cookie-routed CONCLUSIONs whose owning worker channel was closed.
    pub cookie_route_failures: AtomicU64,
    /// Late or duplicate CONCLUSIONs for a connection this acceptor had
    /// already promoted (so its peer entry was gone). Harmless, but
    /// indistinguishable from a stranded handshake without checking the
    /// cookie -- counted apart so the two are never conflated again.
    pub promoted_duplicates: AtomicU64,
    /// Malformed or out-of-state datagrams rejected before protocol work.
    pub invalid_datagrams: AtomicU64,
    /// CONCLUSIONs whose cookie did not match the retained half-open peer.
    pub invalid_cookies: AtomicU64,
    /// Valid new inductions refused because the half-open table was full.
    pub admission_capacity_drops: AtomicU64,
    /// Valid inductions refused by the incomplete-handshake sub-limit.
    pub half_open_capacity_drops: AtomicU64,
    /// Valid conclusions refused by the established-peer sub-limit.
    pub established_capacity_drops: AtomicU64,
    /// Valid inductions refused by the per-source-IP limit.
    pub source_capacity_drops: AtomicU64,
    /// Valid-cookie CONCLUSIONs presented to application policy. Identity is
    /// still only claimed until KM succeeds.
    pub policy_requests: AtomicU64,
    /// Per-peer typed policy configurations successfully applied.
    pub policy_configurations: AtomicU64,
    /// Policy decisions deferred without extending half-open lifetime.
    pub policy_deferred: AtomicU64,
    /// Invalid or out-of-state policy configurations rejected internally.
    pub policy_errors: AtomicU64,
    /// Claimed handshake identities rejected by application policy.
    pub policy_rejections: AtomicU64,
    /// CONCLUSIONs that failed KM validation after credential selection.
    pub credential_failures: AtomicU64,
    /// Incomplete handshakes evicted after the configured inactivity bound.
    pub expired_half_open: AtomicU64,
}

/// Point-in-time, serialization-friendly admission/ingress counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngressTelemetrySnapshot {
    pub local_promotions: u64,
    pub handoffs: u64,
    pub stranded_conclusions: u64,
    pub cookie_routed: u64,
    pub cookie_route_failures: u64,
    pub promoted_duplicates: u64,
    pub invalid_datagrams: u64,
    pub invalid_cookies: u64,
    pub admission_capacity_drops: u64,
    pub half_open_capacity_drops: u64,
    pub established_capacity_drops: u64,
    pub source_capacity_drops: u64,
    pub policy_requests: u64,
    pub policy_configurations: u64,
    pub policy_deferred: u64,
    pub policy_errors: u64,
    pub policy_rejections: u64,
    pub credential_failures: u64,
    pub expired_half_open: u64,
}

impl IngressTelemetrySnapshot {
    #[must_use]
    pub fn total_promotions(self) -> u64 {
        self.local_promotions.saturating_add(self.handoffs)
    }

    #[must_use]
    pub fn total_capacity_drops(self) -> u64 {
        self.admission_capacity_drops
            .saturating_add(self.half_open_capacity_drops)
            .saturating_add(self.established_capacity_drops)
            .saturating_add(self.source_capacity_drops)
    }
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
    pub fn record_cookie_route_failure(&self) {
        Self::bump(&self.cookie_route_failures);
    }
    pub fn record_promoted_duplicate(&self) {
        Self::bump(&self.promoted_duplicates);
    }
    pub fn record_invalid_datagram(&self) {
        Self::bump(&self.invalid_datagrams);
    }
    pub fn record_invalid_cookie(&self) {
        Self::bump(&self.invalid_cookies);
    }
    pub fn record_admission_capacity_drop(&self) {
        Self::bump(&self.admission_capacity_drops);
    }
    pub fn record_half_open_capacity_drop(&self) {
        Self::bump(&self.half_open_capacity_drops);
    }
    pub fn record_established_capacity_drop(&self) {
        Self::bump(&self.established_capacity_drops);
    }
    pub fn record_source_capacity_drop(&self) {
        Self::bump(&self.source_capacity_drops);
    }
    pub fn record_policy_rejection(&self) {
        Self::bump(&self.policy_rejections);
    }
    pub fn record_policy_request(&self) {
        Self::bump(&self.policy_requests);
    }
    pub fn record_policy_configuration(&self) {
        Self::bump(&self.policy_configurations);
    }
    pub fn record_policy_deferred(&self) {
        Self::bump(&self.policy_deferred);
    }
    pub fn record_policy_error(&self) {
        Self::bump(&self.policy_errors);
    }
    pub fn record_credential_failure(&self) {
        Self::bump(&self.credential_failures);
    }
    pub fn record_expired_half_open(&self, count: usize) {
        self.expired_half_open
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Read every counter into a plain value suitable for metrics exporters,
    /// structured logs, or control-plane decisions. Individual relaxed loads
    /// intentionally do not imply a cross-counter transaction.
    #[must_use]
    pub fn snapshot(&self) -> IngressTelemetrySnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        IngressTelemetrySnapshot {
            local_promotions: get(&self.local_promotions),
            handoffs: get(&self.handoffs),
            stranded_conclusions: get(&self.stranded_conclusions),
            cookie_routed: get(&self.cookie_routed),
            cookie_route_failures: get(&self.cookie_route_failures),
            promoted_duplicates: get(&self.promoted_duplicates),
            invalid_datagrams: get(&self.invalid_datagrams),
            invalid_cookies: get(&self.invalid_cookies),
            admission_capacity_drops: get(&self.admission_capacity_drops),
            half_open_capacity_drops: get(&self.half_open_capacity_drops),
            established_capacity_drops: get(&self.established_capacity_drops),
            source_capacity_drops: get(&self.source_capacity_drops),
            policy_requests: get(&self.policy_requests),
            policy_configurations: get(&self.policy_configurations),
            policy_deferred: get(&self.policy_deferred),
            policy_errors: get(&self.policy_errors),
            policy_rejections: get(&self.policy_rejections),
            credential_failures: get(&self.credential_failures),
            expired_half_open: get(&self.expired_half_open),
        }
    }

    /// One-line shutdown summary, identical in shape for every runtime so
    /// two backends' output can be compared directly.
    #[must_use]
    pub fn report(&self, backend: &str) -> String {
        let snapshot = self.snapshot();
        format!(
            "[bench-{backend}] pool receiver: {} local promotions, {} bond handoffs, \
             {} stranded CONCLUSIONs, {} cookie-routed, {} cookie-route failures, \
             {} post-promotion dups, \
             {} invalid datagrams, {} invalid cookies, {} total-capacity drops, \
             {} half-open-capacity drops, {} established-capacity drops, \
             {} source-capacity drops, {} policy requests, {} policy configurations, \
             {} policy deferrals, {} policy errors, {} policy rejections, \
             {} credential failures, {} expired half-open",
            snapshot.local_promotions,
            snapshot.handoffs,
            snapshot.stranded_conclusions,
            snapshot.cookie_routed,
            snapshot.cookie_route_failures,
            snapshot.promoted_duplicates,
            snapshot.invalid_datagrams,
            snapshot.invalid_cookies,
            snapshot.admission_capacity_drops,
            snapshot.half_open_capacity_drops,
            snapshot.established_capacity_drops,
            snapshot.source_capacity_drops,
            snapshot.policy_requests,
            snapshot.policy_configurations,
            snapshot.policy_deferred,
            snapshot.policy_errors,
            snapshot.policy_rejections,
            snapshot.credential_failures,
            snapshot.expired_half_open,
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

    /// Absolute deadline of this connection's next armed timer.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Timestamp> {
        self.timers.values().copied().min()
    }
}

impl Default for ManualTimerStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(
    not(any(
        feature = "mio",
        feature = "tokio",
        feature = "smol",
        feature = "monoio",
        feature = "glommio",
        feature = "compio"
    )),
    allow(dead_code)
)]
fn prepend_outputs(
    pending: &mut VecDeque<ConnectionOutput>,
    outputs: impl DoubleEndedIterator<Item = ConnectionOutput>,
) {
    for output in outputs.rev() {
        pending.push_front(output);
    }
}

#[cfg_attr(
    not(any(
        feature = "mio",
        feature = "tokio",
        feature = "smol",
        feature = "monoio",
        feature = "glommio",
        feature = "compio"
    )),
    allow(dead_code)
)]
fn collect_output_work(
    conn: &mut SrtConnection,
    pending: &mut VecDeque<ConnectionOutput>,
    budget: OutputDrainBudget,
) -> (VecDeque<ConnectionOutput>, bool) {
    let max_actions = budget.max_actions.max(1);
    let max_packets = budget.max_packets.max(1);
    let max_bytes = budget.max_bytes.max(1);
    let mut work = VecDeque::new();
    let mut packets = 0usize;
    let mut bytes = 0usize;

    while work.len() < max_actions {
        let Some(output) = pending.pop_front().or_else(|| conn.poll_output()) else {
            return (work, false);
        };
        if let ConnectionOutput::SendPacket(packet) = &output {
            let exceeds_packet_cap = packets >= max_packets;
            let exceeds_byte_cap = packets > 0 && bytes.saturating_add(packet.len()) > max_bytes;
            if exceeds_packet_cap || exceeds_byte_cap {
                pending.push_front(output);
                return (work, true);
            }
            packets += 1;
            bytes = bytes.saturating_add(packet.len());
        }
        work.push_back(output);
    }

    (work, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use shiguredo_srt::{
        ConnectionOptions, ConnectionOutput, ErrorKind, HandshakePacket, SrtConnection, SrtPacket,
    };

    fn induction(socket_id: u32) -> Vec<u8> {
        let packet = HandshakePacket::new_induction_request(socket_id).encode(0, 0);
        let mut bytes = Vec::new();
        packet.encode(&mut bytes);
        bytes
    }

    fn next_packet(conn: &mut SrtConnection) -> Vec<u8> {
        loop {
            match conn.poll_output().expect("connection output") {
                ConnectionOutput::SendPacket(bytes) => return bytes,
                ConnectionOutput::SetTimer { .. } | ConnectionOutput::ClearTimer { .. } => {}
            }
        }
    }

    fn prepare_conclusion(
        table: &mut PeerTable,
        peer: std::net::SocketAddr,
        socket_id: u32,
        options: &AdmissionOptions,
        telemetry: &IngressTelemetry,
    ) -> Vec<u8> {
        prepare_conclusion_with_options(
            table,
            peer,
            ConnectionOptions {
                socket_id,
                ..ConnectionOptions::default()
            },
            options,
            telemetry,
        )
        .1
    }

    fn prepare_conclusion_with_options(
        table: &mut PeerTable,
        peer: std::net::SocketAddr,
        caller_options: ConnectionOptions,
        options: &AdmissionOptions,
        telemetry: &IngressTelemetry,
    ) -> (SrtConnection, Vec<u8>) {
        let mut caller = SrtConnection::new_caller(caller_options);
        caller.connect(Timestamp::default()).expect("start caller");
        assert_eq!(
            table.admit(
                peer,
                &next_packet(&mut caller),
                Timestamp::default(),
                options,
                0,
                1,
                telemetry,
            ),
            Admit::Fed
        );
        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::default(), &mut outbound);
        for (outbound_peer, packet) in outbound {
            if outbound_peer == peer {
                caller
                    .feed_recv_buf(&packet, Timestamp::from_micros(1))
                    .expect("induction response");
            }
        }
        let conclusion = next_packet(&mut caller);
        (caller, conclusion)
    }

    #[test]
    fn recvmsg_batch_rejects_mismatched_slices() {
        let mut bufs = (0..2).map(|_| Vec::with_capacity(64)).collect::<Vec<_>>();
        let mut sizes = vec![0; 1];
        let mut addrs = vec![None; 2];
        let error = recvmsg_batch(-1, &mut bufs, &mut sizes, &mut addrs)
            .expect_err("mismatched slices must be rejected before the syscall");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

        let mut sizes = vec![0; 2];
        let mut addrs = vec![None; 1];
        let error = recvmsg_batch(-1, &mut bufs, &mut sizes, &mut addrs)
            .expect_err("mismatched address slice must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn recvmsg_batch_accepts_an_empty_batch_without_touching_the_fd() {
        assert_eq!(
            recvmsg_batch(-1, &mut [], &mut [], &mut []).expect("empty batch is a no-op"),
            0
        );
    }

    #[test]
    fn stack_config_builds_coherent_caller_listener_and_admission_defaults() {
        let mut config = SrtStackConfig::default();
        config.connection.socket_id = 0x1234;
        config.connection.tsbpd_delay = 250;
        let caller = config.caller().expect("valid caller config");
        let listener = config.listener().expect("valid listener config");
        assert_eq!(caller.state(), shiguredo_srt::ConnectionState::Disconnected);
        assert_eq!(listener.state(), shiguredo_srt::ConnectionState::Listening);
        assert!(
            config
                .peer_table()
                .expect("valid admission config")
                .is_empty()
        );
        let admission = config.admission_options();
        assert_eq!(admission.socket_id, 0x1234);
        assert_eq!(admission.tsbpd_delay, 250);
        assert!(admission.cookie_routing);
        assert_eq!(
            admission
                .connection_template
                .as_ref()
                .expect("connection template")
                .socket_id,
            0x1234
        );
    }

    #[test]
    fn stack_config_rejects_zero_or_os_truncating_resource_limits() {
        let mut config = SrtStackConfig::default();
        config.connection.flow_window_packets = 0;
        assert_eq!(
            config.validate().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        config.connection.flow_window_packets = 1;
        config.output_drain.max_packets = 0;
        assert_eq!(
            config.validate().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        config.output_drain.max_packets = 1;
        config.socket_buffer_bytes = libc::c_int::MAX as usize + 1;
        assert_eq!(
            config.validate().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn ingress_telemetry_is_exact_under_concurrent_recording() {
        let telemetry = std::sync::Arc::new(IngressTelemetry::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let telemetry = std::sync::Arc::clone(&telemetry);
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        telemetry.record_local_promotion();
                        telemetry.record_invalid_datagram();
                        telemetry.record_cookie_route_failure();
                        telemetry.record_policy_request();
                        telemetry.record_policy_configuration();
                        telemetry.record_policy_deferred();
                        telemetry.record_policy_error();
                        telemetry.record_policy_rejection();
                        telemetry.record_credential_failure();
                        telemetry.record_expired_half_open(2);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("telemetry worker");
        }
        assert_eq!(telemetry.local_promotions.load(Ordering::Relaxed), 80_000);
        assert_eq!(telemetry.invalid_datagrams.load(Ordering::Relaxed), 80_000);
        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.cookie_route_failures, 80_000);
        assert_eq!(snapshot.policy_requests, 80_000);
        assert_eq!(snapshot.policy_configurations, 80_000);
        assert_eq!(snapshot.policy_deferred, 80_000);
        assert_eq!(snapshot.policy_errors, 80_000);
        assert_eq!(snapshot.policy_rejections, 80_000);
        assert_eq!(snapshot.credential_failures, 80_000);
        assert_eq!(telemetry.expired_half_open.load(Ordering::Relaxed), 160_000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recvmsg_batch_handles_boundaries_through_sixty_five_datagrams() {
        use std::os::fd::AsRawFd;
        use std::time::{Duration, Instant};

        for count in [1usize, 32, 64, 65] {
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
            receiver.set_nonblocking(true).expect("set nonblocking");
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
            let destination = receiver.local_addr().expect("receiver address");
            for index in 0..count {
                sender
                    .send_to(&(index as u32).to_be_bytes(), destination)
                    .expect("send datagram");
            }

            let mut bufs: Vec<Vec<u8>> = (0..count).map(|_| Vec::with_capacity(64)).collect();
            let mut sizes = vec![0usize; count];
            let mut addrs = vec![None; count];
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut received = 0usize;
            while received < count && Instant::now() < deadline {
                match recvmsg_batch(
                    receiver.as_raw_fd(),
                    &mut bufs[received..],
                    &mut sizes[received..],
                    &mut addrs[received..],
                ) {
                    Ok(0) => std::thread::yield_now(),
                    Ok(n) => received += n,
                    Err(error) => panic!("recvmmsg failed: {error}"),
                }
            }
            assert_eq!(received, count, "batch size {count}");
            for index in 0..count {
                assert_eq!(sizes[index], 4);
                assert_eq!(&bufs[index][..sizes[index]], &(index as u32).to_be_bytes());
                assert_eq!(
                    addrs[index],
                    Some(sender.local_addr().expect("sender address"))
                );
            }
        }
    }

    #[test]
    fn invalid_unknown_datagrams_do_not_allocate_admission_state() {
        let mut table = PeerTable::new();
        let options = AdmissionOptions::basic(7, 0, true);
        let result = table.admit(
            "127.0.0.1:10000".parse().expect("address"),
            &[0; 16],
            Timestamp::from_micros(0),
            &options,
            0,
            1,
            &IngressTelemetry::new(),
        );
        assert_eq!(result, Admit::Dropped(AdmissionDropReason::InvalidPacket));
        assert!(table.is_empty());
    }

    #[test]
    fn admission_capacity_and_half_open_timeout_bound_state() {
        let mut table = PeerTable::with_config(PeerTableConfig {
            max_peers: 2,
            half_open_timeout: Duration::from_micros(100),
            ..PeerTableConfig::default()
        });
        let options = AdmissionOptions::basic(7, 0, true);
        let telemetry = IngressTelemetry::new();
        let peers = [
            "127.0.0.1:10000".parse().expect("address"),
            "127.0.0.1:10001".parse().expect("address"),
            "127.0.0.1:10002".parse().expect("address"),
        ];
        assert_eq!(
            table.admit(
                peers[0],
                &induction(1),
                Timestamp::from_micros(0),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );
        assert_eq!(
            table.admit(
                peers[1],
                &induction(2),
                Timestamp::from_micros(1),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );
        assert_eq!(
            table.admit(
                peers[2],
                &induction(3),
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Dropped(AdmissionDropReason::Capacity)
        );
        assert_eq!(table.len(), 2);
        assert_eq!(
            telemetry.admission_capacity_drops.load(Ordering::Relaxed),
            1
        );

        assert_eq!(
            table.admit(
                peers[2],
                &induction(3),
                Timestamp::from_micros(101),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );
        assert_eq!(table.len(), 1);
        assert_eq!(telemetry.expired_half_open.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn admission_enforces_half_open_and_per_source_limits_separately() {
        let options = AdmissionOptions::basic(7, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut half_open = PeerTable::with_config(PeerTableConfig {
            max_peers: 8,
            max_half_open_peers: 1,
            max_established_peers: 8,
            max_peers_per_ip: 8,
            half_open_timeout: Duration::from_secs(60),
        });
        assert_eq!(
            half_open.admit(
                "127.0.0.1:10000".parse().expect("address"),
                &induction(1),
                Timestamp::default(),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );
        assert_eq!(
            half_open.admit(
                "127.0.0.2:10000".parse().expect("address"),
                &induction(2),
                Timestamp::default(),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Dropped(AdmissionDropReason::HalfOpenCapacity)
        );

        let mut per_source = PeerTable::with_config(PeerTableConfig {
            max_peers: 8,
            max_half_open_peers: 8,
            max_established_peers: 8,
            max_peers_per_ip: 1,
            half_open_timeout: Duration::from_secs(60),
        });
        assert_eq!(
            per_source.admit(
                "127.0.0.1:10000".parse().expect("address"),
                &induction(1),
                Timestamp::default(),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );
        assert_eq!(
            per_source.admit(
                "127.0.0.1:10001".parse().expect("address"),
                &induction(2),
                Timestamp::default(),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Dropped(AdmissionDropReason::SourceCapacity)
        );
        assert_eq!(
            telemetry.half_open_capacity_drops.load(Ordering::Relaxed),
            1
        );
        assert_eq!(telemetry.source_capacity_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn admission_enforces_established_limit_before_state_transition() {
        let options = AdmissionOptions::basic(7, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::with_config(PeerTableConfig {
            max_peers: 4,
            max_half_open_peers: 4,
            max_established_peers: 1,
            max_peers_per_ip: 4,
            half_open_timeout: Duration::from_secs(60),
        });
        let first = "127.0.0.1:10000".parse().expect("address");
        let first_conclusion =
            prepare_conclusion(&mut table, first, 0x1000_0001, &options, &telemetry);
        assert_eq!(
            table.admit(
                first,
                &first_conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );
        assert_eq!(table.established_count(), 1);

        let second = "127.0.0.2:10000".parse().expect("address");
        let second_conclusion =
            prepare_conclusion(&mut table, second, 0x1000_0002, &options, &telemetry);
        assert_eq!(
            table.admit(
                second,
                &second_conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Dropped(AdmissionDropReason::EstablishedCapacity)
        );
        assert_eq!(table.established_count(), 1);
        assert_eq!(
            telemetry.established_capacity_drops.load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn stream_authorizer_rejects_before_connection_is_established() {
        let peer = "127.0.0.1:10000".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 0x1111,
            stream_id: Some("publish:forbidden".to_string()),
            ..Default::default()
        });
        caller
            .connect(Timestamp::from_micros(0))
            .expect("start caller");
        let induction = next_packet(&mut caller);
        assert_eq!(
            table.admit(
                peer,
                &induction,
                Timestamp::from_micros(0),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );
        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(0), &mut outbound);
        for (_, bytes) in outbound.drain(..) {
            caller
                .feed_recv_buf(&bytes, Timestamp::from_micros(1))
                .expect("induction response");
        }
        let conclusion = next_packet(&mut caller);
        let result = table.admit_with_authorizer(
            peer,
            &conclusion,
            Timestamp::from_micros(2),
            &options,
            0,
            1,
            &telemetry,
            |identity| {
                assert_eq!(identity.stream_id.as_deref(), Some("publish:forbidden"));
                AdmissionDecision::Reject { reason: 1401 }
            },
        );
        assert_eq!(result, Admit::Rejected);
        assert_eq!(telemetry.policy_rejections.load(Ordering::Relaxed), 1);
        assert_ne!(
            table
                .get(&peer)
                .expect("peer retained to send rejection")
                .conn
                .state(),
            shiguredo_srt::ConnectionState::Connected
        );
        assert_eq!(
            table.admit(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Dropped(AdmissionDropReason::RejectedPeer)
        );
        assert_ne!(
            table.get(&peer).expect("rejected peer").conn.state(),
            shiguredo_srt::ConnectionState::Connected
        );

        table.poll_outbound(Timestamp::from_micros(2), &mut outbound);
        let rejection = outbound
            .into_iter()
            .map(|(_, bytes)| bytes)
            .find(|bytes| {
                matches!(
                    SrtPacket::decode(bytes),
                    Ok(SrtPacket::Control(ref control))
                        if HandshakePacket::decode(control)
                            .is_ok_and(|handshake| handshake.reject_reason == Some(1401))
                )
            })
            .expect("wire rejection");
        let error = caller
            .feed_recv_buf(&rejection, Timestamp::from_micros(3))
            .expect_err("caller receives rejection");
        assert_eq!(error.kind, ErrorKind::HandshakeRejected);

        // The rejected connection is retired after its response is drained,
        // and replaying the authenticated conclusion cannot bypass policy via
        // the allow-all `admit` convenience path.
        assert!(!table.contains(&peer));
        assert_eq!(
            table.admit(
                peer,
                &conclusion,
                Timestamp::from_micros(4),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Dropped(AdmissionDropReason::StaleConclusion)
        );
        assert!(!table.contains(&peer));
    }

    #[test]
    fn resolver_selects_stream_password_before_km_processing() {
        let peer = "127.0.0.1:10010".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let passphrase = "tenant-secret-123";
        let (mut caller, conclusion) = prepare_conclusion_with_options(
            &mut table,
            peer,
            ConnectionOptions {
                socket_id: 0x1111,
                stream_id: Some("#!::u=alice,r=live/camera,m=publish".to_string()),
                passphrase: Some(passphrase.to_string()),
                ..Default::default()
            },
            &options,
            &telemetry,
        );

        let result = table.admit_with_resolver(
            peer,
            &conclusion,
            Timestamp::from_micros(2),
            &options,
            0,
            1,
            &telemetry,
            |request| {
                assert_eq!(request.peer, peer);
                assert_eq!(
                    request.claimed_identity.stream_id.as_deref(),
                    Some("#!::u=alice,r=live/camera,m=publish")
                );
                let access = request
                    .access_control
                    .as_ref()
                    .expect("parsed access control");
                assert_eq!(access.user_name(), Some("alice"));
                assert_eq!(access.resource_name(), Some("live/camera"));
                AdmissionResolution::Configure(ListenerPeerPolicy {
                    encryption: PolicyOverride::Set(Some(
                        ListenerEncryptionConfig::new(passphrase, shiguredo_srt::KeyLength::Aes128)
                            .expect("valid listener secret"),
                    )),
                    ..Default::default()
                })
            },
        );
        assert_eq!(result, Admit::Fed);
        assert_eq!(
            table.get(&peer).expect("listener peer").conn.state(),
            shiguredo_srt::ConnectionState::Connected
        );

        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(2), &mut outbound);
        for (_, packet) in outbound {
            caller
                .feed_recv_buf(&packet, Timestamp::from_micros(3))
                .expect("caller accepts KM response");
        }
        assert_eq!(caller.state(), shiguredo_srt::ConnectionState::Connected);
        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.policy_requests, 1);
        assert_eq!(snapshot.policy_configurations, 1);
        assert_eq!(snapshot.credential_failures, 0);
    }

    #[test]
    fn wrong_resolved_password_is_observable_and_never_establishes() {
        let peer = "127.0.0.1:10011".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let (_, conclusion) = prepare_conclusion_with_options(
            &mut table,
            peer,
            ConnectionOptions {
                socket_id: 0x1111,
                stream_id: Some("tenant-a".to_string()),
                passphrase: Some("correct-secret-123".to_string()),
                ..Default::default()
            },
            &options,
            &telemetry,
        );
        let result = table.admit_with_resolver(
            peer,
            &conclusion,
            Timestamp::from_micros(2),
            &options,
            0,
            1,
            &telemetry,
            |_| {
                AdmissionResolution::Configure(ListenerPeerPolicy {
                    encryption: PolicyOverride::Set(Some(
                        ListenerEncryptionConfig::new(
                            "incorrect-secret-123",
                            shiguredo_srt::KeyLength::Aes128,
                        )
                        .expect("valid listener secret"),
                    )),
                    ..Default::default()
                })
            },
        );
        assert_eq!(result, Admit::Dropped(AdmissionDropReason::InvalidPacket));
        assert_ne!(
            table.get(&peer).expect("half-open peer").conn.state(),
            shiguredo_srt::ConnectionState::Connected
        );
        assert_eq!(telemetry.snapshot().credential_failures, 1);
    }

    #[test]
    fn encrypted_caller_cannot_downgrade_an_unsecured_listener() {
        let peer = "127.0.0.1:10017".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let (mut caller, conclusion) = prepare_conclusion_with_options(
            &mut table,
            peer,
            ConnectionOptions {
                socket_id: 0x1111,
                passphrase: Some("caller-secret-123".to_owned()),
                ..ConnectionOptions::default()
            },
            &options,
            &telemetry,
        );
        assert_eq!(
            table.admit_with_resolver(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
                |_| AdmissionResolution::Accept,
            ),
            Admit::Dropped(AdmissionDropReason::InvalidPacket)
        );
        assert_eq!(
            table.get(&peer).expect("terminal peer").conn.state(),
            shiguredo_srt::ConnectionState::Disconnected
        );
        assert_eq!(telemetry.snapshot().credential_failures, 1);

        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(2), &mut outbound);
        let error = outbound
            .into_iter()
            .find_map(|(_, packet)| {
                caller
                    .feed_recv_buf(&packet, Timestamp::from_micros(3))
                    .err()
            })
            .expect("caller receives KM mismatch");
        assert_eq!(error.kind, shiguredo_srt::ErrorKind::HandshakeRejected);
        assert!(
            !table.contains(&peer),
            "terminal peer retires after response"
        );
    }

    #[test]
    fn deferred_policy_does_not_extend_the_half_open_deadline() {
        let peer = "127.0.0.1:10012".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::with_config(PeerTableConfig {
            half_open_timeout: Duration::from_micros(100),
            ..PeerTableConfig::default()
        });
        let conclusion = prepare_conclusion(&mut table, peer, 0x1111, &options, &telemetry);
        assert_eq!(
            table.admit_with_resolver(
                peer,
                &conclusion,
                Timestamp::from_micros(90),
                &options,
                0,
                1,
                &telemetry,
                |_| AdmissionResolution::Defer,
            ),
            Admit::Deferred
        );
        assert!(table.contains(&peer));
        assert_eq!(table.prune_half_open(Timestamp::from_micros(101)), 1);
        assert!(!table.contains(&peer));
        assert_eq!(telemetry.snapshot().policy_deferred, 1);
    }

    #[test]
    fn connection_hook_is_a_guarded_escape_hatch() {
        let peer = "127.0.0.1:10013".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let conclusion = prepare_conclusion(&mut table, peer, 0x1111, &options, &telemetry);
        assert_eq!(
            table.admit_with_connection_hook(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
                |_request, connection| {
                    connection
                        .set_listener_bandwidth(Some(42_000_000))
                        .expect("inside pre-conclusion window");
                    AdmissionResolution::Accept
                },
            ),
            Admit::Fed
        );
    }

    #[test]
    fn invalid_resolved_policy_is_rejected_and_counted() {
        let peer = "127.0.0.1:10014".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let conclusion = prepare_conclusion(&mut table, peer, 0x1111, &options, &telemetry);
        assert_eq!(
            table.admit_with_resolver(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
                |_| AdmissionResolution::Configure(ListenerPeerPolicy {
                    latency: PolicyOverride::Set(Duration::from_secs(u64::from(u16::MAX) + 1)),
                    ..ListenerPeerPolicy::default()
                }),
            ),
            Admit::Rejected
        );
        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.policy_requests, 1);
        assert_eq!(snapshot.policy_errors, 1);
        assert_eq!(snapshot.policy_configurations, 0);
    }

    #[test]
    fn forwarded_conclusion_is_resolved_only_by_its_owner() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

        let peer = "127.0.0.1:10015".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut owner = PeerTable::new();
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 0x1111,
            stream_id: Some("tenant-a".to_owned()),
            ..ConnectionOptions::default()
        });
        caller.connect(Timestamp::default()).expect("start caller");
        assert_eq!(
            owner.admit(
                peer,
                &next_packet(&mut caller),
                Timestamp::default(),
                &options,
                0,
                2,
                &telemetry,
            ),
            Admit::Fed
        );
        let mut outbound = Vec::new();
        owner.poll_outbound(Timestamp::default(), &mut outbound);
        for (_, packet) in outbound {
            caller
                .feed_recv_buf(&packet, Timestamp::from_micros(1))
                .expect("induction response");
        }
        let conclusion = next_packet(&mut caller);
        let (owner_tx, owner_rx) = std::sync::mpsc::channel();
        let (foreign_tx, _foreign_rx) = std::sync::mpsc::channel();
        let called = AtomicBool::new(false);
        let mut foreign = PeerTable::new();
        assert_eq!(
            foreign.admit_and_forward_with_resolver(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                1,
                &[owner_tx, foreign_tx],
                &telemetry,
                |_| {
                    called.store(true, AtomicOrdering::Relaxed);
                    AdmissionResolution::Accept
                },
            ),
            Admit::ForwardTo(0)
        );
        assert!(!called.load(AtomicOrdering::Relaxed));
        assert!(matches!(
            owner_rx.recv().expect("forwarded handshake"),
            WorkerMessage::Handshake { peer: message_peer, .. } if message_peer == peer
        ));
    }

    #[test]
    fn failed_cookie_route_delivery_is_observable() {
        let peer = "127.0.0.1:10016".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut owner = PeerTable::new();
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 0x1111,
            ..ConnectionOptions::default()
        });
        caller.connect(Timestamp::default()).expect("start caller");
        let _ = owner.admit(
            peer,
            &next_packet(&mut caller),
            Timestamp::default(),
            &options,
            0,
            2,
            &telemetry,
        );
        let mut outbound = Vec::new();
        owner.poll_outbound(Timestamp::default(), &mut outbound);
        for (_, packet) in outbound {
            caller
                .feed_recv_buf(&packet, Timestamp::from_micros(1))
                .expect("induction response");
        }
        let conclusion = next_packet(&mut caller);
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        drop(closed_rx);
        let (foreign_tx, _foreign_rx) = std::sync::mpsc::channel();
        let mut foreign = PeerTable::new();
        assert_eq!(
            foreign.admit_and_forward_with_resolver(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                1,
                &[closed_tx, foreign_tx],
                &telemetry,
                |_| AdmissionResolution::Accept,
            ),
            Admit::Dropped(AdmissionDropReason::StaleConclusion)
        );
        assert_eq!(telemetry.snapshot().cookie_route_failures, 1);
    }

    #[test]
    fn rejection_reason_reserves_a_bounded_application_range() {
        assert_eq!(
            RejectionReason::application(0).map(RejectionReason::get),
            Some(2000)
        );
        assert_eq!(
            RejectionReason::application(999).map(RejectionReason::get),
            Some(2999)
        );
        assert_eq!(RejectionReason::application(1000), None);
    }

    #[test]
    fn due_index_replaces_deadlines_and_ignores_stale_entries() {
        let mut index = DueIndex::default();
        index.set("a", Timestamp::from_micros(100));
        index.set("b", Timestamp::from_micros(200));
        index.set("a", Timestamp::from_micros(300));

        assert_eq!(index.peek_min_deadline(), Some(Timestamp::from_micros(200)));
        let mut due = Vec::new();
        index.pop_due(Timestamp::from_micros(200), &mut due);
        assert_eq!(due, vec!["b"]);
        index.pop_due(Timestamp::from_micros(300), &mut due);
        assert_eq!(due, vec!["a"]);
        assert!(index.is_empty());
    }

    #[test]
    fn due_index_remove_lazily_discards_heap_entry() {
        let mut index = DueIndex::default();
        index.set(7, Timestamp::from_micros(100));
        index.remove(&7);
        assert_eq!(index.peek_min_deadline(), None);
        assert!(index.is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn due_index_matches_last_write_wins_model(
            writes in prop::collection::vec((0u8..32, any::<u16>()), 0..256),
            now in any::<u16>(),
        ) {
            let mut index = DueIndex::default();
            let mut model = HashMap::new();
            for (key, deadline) in writes {
                index.set(key, Timestamp::from_micros(u64::from(deadline)));
                model.insert(key, deadline);
            }

            let mut actual = Vec::new();
            index.pop_due(Timestamp::from_micros(u64::from(now)), &mut actual);
            actual.sort_unstable();
            let mut expected: Vec<_> = model
                .into_iter()
                .filter_map(|(key, deadline)| (deadline <= now).then_some(key))
                .collect();
            expected.sort_unstable();
            prop_assert_eq!(actual, expected);
        }

        #[test]
        fn admission_table_never_exceeds_configured_capacity(
            requested in 1usize..64,
            max_peers in 1usize..16,
        ) {
            let mut table = PeerTable::with_config(PeerTableConfig {
                max_peers,
                half_open_timeout: Duration::from_secs(60),
                ..PeerTableConfig::default()
            });
            let options = AdmissionOptions::basic(7, 0, true);
            let telemetry = IngressTelemetry::new();
            for index in 0..requested {
                let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 10_000 + index as u16));
                let result = table.admit(
                    peer,
                    &induction(index as u32 + 1),
                    Timestamp::from_micros(index as u64),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                prop_assert!(matches!(result, Admit::Fed | Admit::Dropped(AdmissionDropReason::Capacity)));
                prop_assert!(table.len() <= max_peers);
            }
            prop_assert_eq!(table.len(), requested.min(max_peers));
        }

        #[test]
        fn admission_table_never_exceeds_per_source_capacity(
            requested in 1usize..64,
            max_per_ip in 1usize..16,
        ) {
            let mut table = PeerTable::with_config(PeerTableConfig {
                max_peers: 64,
                max_half_open_peers: 64,
                max_established_peers: 64,
                max_peers_per_ip: max_per_ip,
                half_open_timeout: Duration::from_secs(60),
            });
            let options = AdmissionOptions::basic(7, 0, true);
            let telemetry = IngressTelemetry::new();
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            for index in 0..requested {
                let peer = std::net::SocketAddr::new(ip, 10_000 + index as u16);
                let _ = table.admit(
                    peer,
                    &induction(index as u32 + 1),
                    Timestamp::from_micros(index as u64),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                prop_assert!(table.peers_for_ip(ip) <= max_per_ip);
            }
            prop_assert_eq!(table.peers_for_ip(ip), requested.min(max_per_ip));
        }
    }

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
    use super::{
        ManualTimerStore, OutputDrainBudget, OutputDrainReport, OutputDrainStatus,
        collect_output_work, prepend_outputs,
    };
    use libc;
    use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
    use std::collections::VecDeque;
    use std::io;
    use std::time::Duration;

    /// Per-connection state for mio: protocol + owned socket + manual timers.
    pub struct Conn {
        pub conn: SrtConnection,
        pub socket: mio::net::UdpSocket,
        pub timers: ManualTimerStore,
        pending_outputs: VecDeque<ConnectionOutput>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, socket: mio::net::UdpSocket) -> Self {
            Self {
                conn,
                socket,
                timers: ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
            }
        }

        /// Fire expired manual timers.
        pub fn fire_expired(&mut self, now: Timestamp) {
            self.timers.fire_expired(now, &mut self.conn);
        }

        /// Compatibility wrapper using [`OutputDrainBudget::default`].
        /// Returns true only for `ECONNREFUSED`; transient failures remain
        /// queued for the next tick.
        pub fn drain_outputs(&mut self, now: Timestamp) -> bool {
            self.drain_outputs_bounded(now, OutputDrainBudget::default())
                .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused)
        }

        /// Drain a bounded amount of output, retaining every unsent datagram
        /// in protocol order on `WouldBlock`, partial `sendmmsg`, or error.
        pub fn drain_outputs_bounded(
            &mut self,
            now: Timestamp,
            budget: OutputDrainBudget,
        ) -> io::Result<OutputDrainReport> {
            drain_outputs_with(
                &mut self.conn,
                &mut self.timers,
                &mut self.pending_outputs,
                now,
                budget,
                |batch| Self::send_batch(&self.socket, batch),
            )
        }

        #[must_use]
        pub fn has_pending_outputs(&self) -> bool {
            !self.pending_outputs.is_empty()
        }

        /// mmsghdr/iovec scratch, reused across calls on this thread
        /// (hot path: `drain_outputs` runs every event-loop tick per
        /// connection). Capacity stabilizes at the batch cap (32) after
        /// the first few calls, giving zero-allocation steady state --
        /// mirrors `recvmsg_batch`'s scratch in srt-bench.
        fn send_batch(socket: &mio::net::UdpSocket, batch: &[Vec<u8>]) -> io::Result<usize> {
            use std::cell::RefCell;
            thread_local! {
                static SCRATCH: RefCell<(Vec<libc::mmsghdr>, Vec<libc::iovec>)> =
                    const { RefCell::new((Vec::new(), Vec::new())) };
            }
            if batch.is_empty() {
                return Ok(0);
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
                        // SAFETY: all-zero is a valid empty `msghdr`; the
                        // iovec pointer and count are assigned below.
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
                let count = u32::try_from(batch.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "send batch exceeds u32")
                })?;
                // SAFETY: `msgs` and `iovs` have exactly `batch.len()` live
                // elements. Each iovec points into an immutable packet Vec
                // that outlives this synchronous syscall; pointers are set
                // only after both scratch vectors finish growing.
                let sent =
                    unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), count, libc::MSG_DONTWAIT) };
                if sent < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(sent as usize)
                }
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

    /// Resolve, bind, and convert a complete listener configuration to mio
    /// sockets. Applications retain the prepared policy and may drive their
    /// own poll/worker architecture around it.
    pub fn bind_listener(
        config: &crate::ListenerConfig,
    ) -> Result<crate::RuntimeListener<mio::net::UdpSocket>, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
        let sockets = prepared
            .bind_sockets()?
            .into_iter()
            .map(mio::net::UdpSocket::from_std)
            .collect();
        Ok(crate::RuntimeListener { prepared, sockets })
    }

    /// Build one configured caller connection and connected mio socket.
    pub fn caller(
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<Conn, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
        let socket = mio::net::UdpSocket::from_std(prepared.bind_socket()?);
        Ok(Conn::new(prepared.connection(now)?, socket))
    }

    fn drain_outputs_with<F>(
        conn: &mut SrtConnection,
        timers: &mut ManualTimerStore,
        pending: &mut VecDeque<ConnectionOutput>,
        now: Timestamp,
        budget: OutputDrainBudget,
        mut send_batch: F,
    ) -> io::Result<OutputDrainReport>
    where
        F: FnMut(&[Vec<u8>]) -> io::Result<usize>,
    {
        let (mut work, budget_exhausted) = collect_output_work(conn, pending, budget);
        let mut report = OutputDrainReport {
            status: if budget_exhausted {
                OutputDrainStatus::BudgetExhausted
            } else {
                OutputDrainStatus::Drained
            },
            ..OutputDrainReport::default()
        };

        while let Some(output) = work.pop_front() {
            match output {
                ConnectionOutput::SendPacket(packet) => {
                    let mut batch = vec![packet];
                    while matches!(work.front(), Some(ConnectionOutput::SendPacket(_))) {
                        let Some(ConnectionOutput::SendPacket(packet)) = work.pop_front() else {
                            unreachable!();
                        };
                        batch.push(packet);
                    }

                    match send_batch(&batch) {
                        Ok(sent) if sent <= batch.len() => {
                            report.actions += sent;
                            report.packets += sent;
                            report.bytes += batch[..sent].iter().map(Vec::len).sum::<usize>();
                            if sent < batch.len() {
                                prepend_outputs(pending, work.into_iter());
                                prepend_outputs(
                                    pending,
                                    batch
                                        .into_iter()
                                        .skip(sent)
                                        .map(ConnectionOutput::SendPacket),
                                );
                                report.status = OutputDrainStatus::Backpressured;
                                return Ok(report);
                            }
                        }
                        Ok(_) => {
                            prepend_outputs(pending, work.into_iter());
                            prepend_outputs(
                                pending,
                                batch.into_iter().map(ConnectionOutput::SendPacket),
                            );
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "sendmmsg reported more datagrams than supplied",
                            ));
                        }
                        Err(error) => {
                            prepend_outputs(pending, work.into_iter());
                            prepend_outputs(
                                pending,
                                batch.into_iter().map(ConnectionOutput::SendPacket),
                            );
                            if error.kind() == io::ErrorKind::WouldBlock {
                                report.status = OutputDrainStatus::Backpressured;
                                return Ok(report);
                            }
                            return Err(error);
                        }
                    }
                }
                timer => {
                    timers.apply_output(&timer, now);
                    report.actions += 1;
                }
            }
        }

        Ok(report)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use shiguredo_srt::ConnectionOptions;

        fn caller_with_output() -> SrtConnection {
            let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
            conn.connect(Timestamp::from_micros(0))
                .expect("connect starts");
            conn
        }

        #[test]
        fn would_block_retains_packet_and_following_timer() {
            let mut conn = caller_with_output();
            let mut timers = ManualTimerStore::new();
            let mut pending = VecDeque::new();
            let mut attempts = 0;
            let report = drain_outputs_with(
                &mut conn,
                &mut timers,
                &mut pending,
                Timestamp::from_micros(0),
                OutputDrainBudget::default(),
                |_| {
                    attempts += 1;
                    Err(io::Error::from(io::ErrorKind::WouldBlock))
                },
            )
            .expect("WouldBlock is a yield, not packet loss");
            assert_eq!(report.status, OutputDrainStatus::Backpressured);
            assert_eq!(attempts, 1);
            assert_eq!(pending.len(), 2);

            let report = drain_outputs_with(
                &mut conn,
                &mut timers,
                &mut pending,
                Timestamp::from_micros(1),
                OutputDrainBudget::default(),
                |batch| Ok(batch.len()),
            )
            .expect("retry succeeds");
            assert_eq!(report.status, OutputDrainStatus::Drained);
            assert_eq!(report.packets, 1);
            assert!(pending.is_empty());
            assert_ne!(timers.time_until_earliest(Timestamp::from_micros(1), 0), 0);
        }

        #[test]
        fn partial_send_retains_unsent_tail_in_order() {
            let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
            let mut timers = ManualTimerStore::new();
            let mut pending = VecDeque::from([
                ConnectionOutput::SendPacket(vec![1]),
                ConnectionOutput::SendPacket(vec![2]),
                ConnectionOutput::SendPacket(vec![3]),
            ]);
            let report = drain_outputs_with(
                &mut conn,
                &mut timers,
                &mut pending,
                Timestamp::default(),
                OutputDrainBudget::default(),
                |_| Ok(1),
            )
            .expect("partial send yields");
            assert_eq!(report.packets, 1);
            assert_eq!(report.status, OutputDrainStatus::Backpressured);
            assert_eq!(
                pending.into_iter().collect::<Vec<_>>(),
                vec![
                    ConnectionOutput::SendPacket(vec![2]),
                    ConnectionOutput::SendPacket(vec![3]),
                ]
            );
        }

        #[test]
        fn packet_and_byte_budget_yields_with_tail_queued() {
            let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
            let mut timers = ManualTimerStore::new();
            let mut pending = VecDeque::from([
                ConnectionOutput::SendPacket(vec![1, 1]),
                ConnectionOutput::SendPacket(vec![2, 2]),
            ]);
            let report = drain_outputs_with(
                &mut conn,
                &mut timers,
                &mut pending,
                Timestamp::default(),
                OutputDrainBudget::new(8, 8, 2),
                |batch| Ok(batch.len()),
            )
            .expect("bounded send succeeds");

            assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
            assert_eq!(report.packets, 1);
            assert_eq!(report.bytes, 2);
            assert_eq!(
                pending,
                VecDeque::from([ConnectionOutput::SendPacket(vec![2, 2])])
            );
        }
    }
}

#[cfg(feature = "tokio")]
pub mod tokio_transport {
    use crate::{
        OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
        prepend_outputs,
    };
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::collections::VecDeque;
    use std::io;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// Per-connection state for tokio: protocol + async socket + timer deadlines.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: UdpSocket,
        timers: crate::ManualTimerStore,
        pending_outputs: VecDeque<ConnectionOutput>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timers: crate::ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
            }
        }

        /// Fire every timer whose deadline has passed, invoking the protocol.
        ///
        /// Outputs queued by `handle_timer` are drained by the caller's
        /// following `drain_outputs`.
        pub fn fire_expired(&mut self, now: Timestamp) {
            self.timers.fire_expired(now, &mut self.conn);
        }

        /// Compatibility wrapper using [`OutputDrainBudget::default`].
        pub async fn drain_outputs(&mut self, now: Timestamp) -> io::Result<OutputDrainReport> {
            self.drain_outputs_bounded(now, OutputDrainBudget::default())
                .await
        }

        /// Drain a bounded amount of output. A failed datagram and every
        /// action after it remain queued in protocol order for the next tick.
        pub async fn drain_outputs_bounded(
            &mut self,
            now: Timestamp,
            budget: OutputDrainBudget,
        ) -> io::Result<OutputDrainReport> {
            let (mut work, budget_exhausted) =
                collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
            let mut report = OutputDrainReport {
                status: if budget_exhausted {
                    OutputDrainStatus::BudgetExhausted
                } else {
                    OutputDrainStatus::Drained
                },
                ..OutputDrainReport::default()
            };

            while let Some(output) = work.pop_front() {
                match output {
                    ConnectionOutput::SendPacket(bytes) => match self.sock.send(&bytes).await {
                        Ok(sent) if sent == bytes.len() => {
                            report.actions += 1;
                            report.packets += 1;
                            report.bytes += sent;
                        }
                        Ok(_) => {
                            prepend_outputs(&mut self.pending_outputs, work.into_iter());
                            self.pending_outputs
                                .push_front(ConnectionOutput::SendPacket(bytes));
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "UDP send completed with a partial datagram",
                            ));
                        }
                        Err(error) => {
                            prepend_outputs(&mut self.pending_outputs, work.into_iter());
                            self.pending_outputs
                                .push_front(ConnectionOutput::SendPacket(bytes));
                            if error.kind() == io::ErrorKind::WouldBlock {
                                report.status = OutputDrainStatus::Backpressured;
                                return Ok(report);
                            }
                            return Err(error);
                        }
                    },
                    timer => {
                        self.timers.apply_output(&timer, now);
                        report.actions += 1;
                    }
                }
            }

            Ok(report)
        }

        #[must_use]
        pub fn has_pending_outputs(&self) -> bool {
            !self.pending_outputs.is_empty()
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
            if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            let report = self.drain_outputs(now).await.map_err(|_| ())?;
            (report.status == OutputDrainStatus::Drained)
                .then_some(())
                .ok_or(())
        }

        /// Full event-loop tick: fire timers, recv, drain, send paced.
        pub async fn tick(
            &mut self,
            buf: &mut [u8],
            payload: &[u8],
            now: Timestamp,
        ) -> io::Result<TickResult> {
            self.fire_expired(now);
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            let drained = self.drain_outputs(now).await?;

            let mut sent = 0u64;
            if drained.status == OutputDrainStatus::Drained {
                while self.send_paced(payload, now).await.is_ok() {
                    sent += 1;
                }
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            Ok(TickResult { sent, events })
        }
    }

    /// Resolve and bind a listener using Tokio-native UDP sockets. Must be
    /// called from a Tokio runtime context.
    pub fn bind_listener(
        config: &crate::ListenerConfig,
    ) -> Result<crate::RuntimeListener<UdpSocket>, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Tokio)?;
        let sockets = prepared
            .bind_sockets()?
            .into_iter()
            .map(UdpSocket::from_std)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::RuntimeListener { prepared, sockets })
    }

    /// Build one configured caller connection and connected Tokio socket.
    pub fn caller(
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<Conn, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Tokio)?;
        let socket = UdpSocket::from_std(prepared.bind_socket()?)?;
        Ok(Conn::new(prepared.connection(now)?, socket))
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "smol")]
pub mod smol_transport {
    use crate::{
        OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
        prepend_outputs,
    };
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::collections::VecDeque;
    use std::io;
    use std::time::Duration;

    pub type UdpSocket = smol::Async<std::net::UdpSocket>;

    /// Per-connection state for smol: protocol + async socket + timer deadlines.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: UdpSocket,
        timers: crate::ManualTimerStore,
        pending_outputs: VecDeque<ConnectionOutput>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timers: crate::ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
            }
        }

        /// Fire every timer whose deadline has passed, invoking the protocol.
        ///
        /// Outputs queued by `handle_timer` are drained by the caller's
        /// following `drain_outputs`.
        pub fn fire_expired(&mut self, now: Timestamp) {
            self.timers.fire_expired(now, &mut self.conn);
        }

        pub async fn drain_outputs(&mut self, now: Timestamp) -> io::Result<OutputDrainReport> {
            self.drain_outputs_bounded(now, OutputDrainBudget::default())
                .await
        }

        pub async fn drain_outputs_bounded(
            &mut self,
            now: Timestamp,
            budget: OutputDrainBudget,
        ) -> io::Result<OutputDrainReport> {
            let (mut work, exhausted) =
                collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
            let mut report = OutputDrainReport {
                status: if exhausted {
                    OutputDrainStatus::BudgetExhausted
                } else {
                    OutputDrainStatus::Drained
                },
                ..Default::default()
            };
            while let Some(out) = work.pop_front() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        match self.sock.write_with(|inner| inner.send(&bytes)).await {
                            Ok(sent) if sent == bytes.len() => {
                                report.actions += 1;
                                report.packets += 1;
                                report.bytes += sent;
                            }
                            Ok(_) => {
                                prepend_outputs(&mut self.pending_outputs, work.into_iter());
                                self.pending_outputs
                                    .push_front(ConnectionOutput::SendPacket(bytes));
                                return Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "UDP send completed with a partial datagram",
                                ));
                            }
                            Err(error) => {
                                prepend_outputs(&mut self.pending_outputs, work.into_iter());
                                self.pending_outputs
                                    .push_front(ConnectionOutput::SendPacket(bytes));
                                return Err(error);
                            }
                        }
                    }
                    other => {
                        self.timers.apply_output(&other, now);
                        report.actions += 1;
                    }
                }
            }
            Ok(report)
        }

        #[must_use]
        pub fn has_pending_outputs(&self) -> bool {
            !self.pending_outputs.is_empty()
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
            if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            let report = self.drain_outputs(now).await.map_err(|_| ())?;
            (report.status == OutputDrainStatus::Drained)
                .then_some(())
                .ok_or(())
        }

        pub async fn tick(
            &mut self,
            buf: &mut [u8],
            payload: &[u8],
            now: Timestamp,
        ) -> io::Result<TickResult> {
            self.fire_expired(now);
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            let drained = self.drain_outputs(now).await?;

            let mut sent = 0u64;
            if drained.status == OutputDrainStatus::Drained {
                while self.send_paced(payload, now).await.is_ok() {
                    sent += 1;
                }
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            Ok(TickResult { sent, events })
        }
    }

    /// Resolve and bind a listener using smol-native async sockets.
    pub fn bind_listener(
        config: &crate::ListenerConfig,
    ) -> Result<crate::RuntimeListener<UdpSocket>, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Smol)?;
        let sockets = prepared
            .bind_sockets()?
            .into_iter()
            .map(smol::Async::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::RuntimeListener { prepared, sockets })
    }

    /// Build one configured caller connection and connected smol socket.
    pub fn caller(
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<Conn, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Smol)?;
        let socket = smol::Async::new(prepared.bind_socket()?)?;
        Ok(Conn::new(prepared.connection(now)?, socket))
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "monoio")]
pub mod monoio_transport {
    use crate::{
        OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
        prepend_outputs,
    };
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::collections::VecDeque;
    use std::io;
    use std::time::Duration;

    /// Per-connection state for monoio: protocol + owned-buffer socket + timer deadlines.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: monoio::net::udp::UdpSocket,
        timers: crate::ManualTimerStore,
        pending_outputs: VecDeque<ConnectionOutput>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: monoio::net::udp::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timers: crate::ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
            }
        }

        /// Fire every timer whose deadline has passed, invoking the protocol.
        ///
        /// Outputs queued by `handle_timer` are drained by the caller's
        /// following `drain_outputs`.
        pub fn fire_expired(&mut self, now: Timestamp) {
            self.timers.fire_expired(now, &mut self.conn);
        }

        pub async fn drain_outputs(&mut self, now: Timestamp) -> io::Result<OutputDrainReport> {
            self.drain_outputs_bounded(now, OutputDrainBudget::default())
                .await
        }

        pub async fn drain_outputs_bounded(
            &mut self,
            now: Timestamp,
            budget: OutputDrainBudget,
        ) -> io::Result<OutputDrainReport> {
            let (mut work, exhausted) =
                collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
            let mut report = OutputDrainReport {
                status: if exhausted {
                    OutputDrainStatus::BudgetExhausted
                } else {
                    OutputDrainStatus::Drained
                },
                ..Default::default()
            };
            while let Some(out) = work.pop_front() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let expected = bytes.len();
                        let (result, bytes) = self.sock.send(bytes).await;
                        match result {
                            Ok(sent) if sent == expected => {
                                report.actions += 1;
                                report.packets += 1;
                                report.bytes += sent;
                            }
                            Ok(_) => {
                                prepend_outputs(&mut self.pending_outputs, work.into_iter());
                                self.pending_outputs
                                    .push_front(ConnectionOutput::SendPacket(bytes));
                                return Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "UDP send completed with a partial datagram",
                                ));
                            }
                            Err(error) => {
                                prepend_outputs(&mut self.pending_outputs, work.into_iter());
                                self.pending_outputs
                                    .push_front(ConnectionOutput::SendPacket(bytes));
                                return Err(error);
                            }
                        }
                    }
                    other => {
                        self.timers.apply_output(&other, now);
                        report.actions += 1;
                    }
                }
            }
            Ok(report)
        }

        #[must_use]
        pub fn has_pending_outputs(&self) -> bool {
            !self.pending_outputs.is_empty()
        }

        pub async fn recv_with_timeout(&mut self, timeout: Duration, now: Timestamp) {
            if let Ok((Ok(n), buf)) =
                monoio::time::timeout(timeout, self.sock.recv(vec![0u8; 2048])).await
            {
                let _ = self.conn.feed_recv_buf(&buf[..n], now);
            }
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            let report = self.drain_outputs(now).await.map_err(|_| ())?;
            (report.status == OutputDrainStatus::Drained)
                .then_some(())
                .ok_or(())
        }

        pub async fn tick(&mut self, payload: &[u8], now: Timestamp) -> io::Result<TickResult> {
            self.fire_expired(now);
            self.recv_with_timeout(Duration::from_micros(100), now)
                .await;
            let drained = self.drain_outputs(now).await?;

            let mut sent = 0u64;
            if drained.status == OutputDrainStatus::Drained {
                while self.send_paced(payload, now).await.is_ok() {
                    sent += 1;
                }
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            Ok(TickResult { sent, events })
        }
    }

    /// Resolve and bind a listener using Monoio-native UDP sockets. Call from
    /// the executor thread that will own them.
    pub fn bind_listener(
        config: &crate::ListenerConfig,
    ) -> Result<crate::RuntimeListener<monoio::net::udp::UdpSocket>, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Monoio)?;
        let sockets = prepared
            .bind_sockets()?
            .into_iter()
            .map(monoio::net::udp::UdpSocket::from_std)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::RuntimeListener { prepared, sockets })
    }

    /// Build one configured caller connection and connected Monoio socket.
    pub fn caller(
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<Conn, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Monoio)?;
        let socket = monoio::net::udp::UdpSocket::from_std(prepared.bind_socket()?)?;
        Ok(Conn::new(prepared.connection(now)?, socket))
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "glommio")]
pub mod glommio_transport {
    use crate::{
        OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
        prepend_outputs,
    };
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::collections::VecDeque;
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

    /// Per-connection state for glommio: protocol + borrowed-buffer socket + timer deadlines.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: glommio::net::UdpSocket,
        timers: crate::ManualTimerStore,
        pending_outputs: VecDeque<ConnectionOutput>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: glommio::net::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timers: crate::ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
            }
        }

        /// Fire every timer whose deadline has passed, invoking the protocol.
        ///
        /// Outputs queued by `handle_timer` are drained by the caller's
        /// following `drain_outputs`.
        pub fn fire_expired(&mut self, now: Timestamp) {
            self.timers.fire_expired(now, &mut self.conn);
        }

        pub async fn drain_outputs(&mut self, now: Timestamp) -> io::Result<OutputDrainReport> {
            self.drain_outputs_bounded(now, OutputDrainBudget::default())
                .await
        }

        pub async fn drain_outputs_bounded(
            &mut self,
            now: Timestamp,
            budget: OutputDrainBudget,
        ) -> io::Result<OutputDrainReport> {
            let (mut work, exhausted) =
                collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
            let mut report = OutputDrainReport {
                status: if exhausted {
                    OutputDrainStatus::BudgetExhausted
                } else {
                    OutputDrainStatus::Drained
                },
                ..Default::default()
            };
            while let Some(out) = work.pop_front() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => match self.sock.send(&bytes).await {
                        Ok(sent) if sent == bytes.len() => {
                            report.actions += 1;
                            report.packets += 1;
                            report.bytes += sent;
                        }
                        Ok(_) => {
                            prepend_outputs(&mut self.pending_outputs, work.into_iter());
                            self.pending_outputs
                                .push_front(ConnectionOutput::SendPacket(bytes));
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "UDP send completed with a partial datagram",
                            ));
                        }
                        Err(error) => {
                            prepend_outputs(&mut self.pending_outputs, work.into_iter());
                            self.pending_outputs
                                .push_front(ConnectionOutput::SendPacket(bytes));
                            return Err(io::Error::other(error.to_string()));
                        }
                    },
                    other => {
                        self.timers.apply_output(&other, now);
                        report.actions += 1;
                    }
                }
            }
            Ok(report)
        }

        #[must_use]
        pub fn has_pending_outputs(&self) -> bool {
            !self.pending_outputs.is_empty()
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
            if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            let report = self.drain_outputs(now).await.map_err(|_| ())?;
            (report.status == OutputDrainStatus::Drained)
                .then_some(())
                .ok_or(())
        }

        pub async fn tick(
            &mut self,
            buf: &mut [u8],
            payload: &[u8],
            now: Timestamp,
        ) -> io::Result<TickResult> {
            self.fire_expired(now);
            self.recv_with_timeout(buf, Duration::from_micros(100), now)
                .await;
            let drained = self.drain_outputs(now).await?;

            let mut sent = 0u64;
            if drained.status == OutputDrainStatus::Drained {
                while self.send_paced(payload, now).await.is_ok() {
                    sent += 1;
                }
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            Ok(TickResult { sent, events })
        }
    }

    /// Resolve and bind a listener on the current Glommio executor.
    pub fn bind_listener(
        config: &crate::ListenerConfig,
    ) -> Result<crate::RuntimeListener<glommio::net::UdpSocket>, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Glommio)?;
        let sockets = prepared
            .bind_sockets()?
            .into_iter()
            .map(from_std)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::RuntimeListener { prepared, sockets })
    }

    /// Build one configured caller connection on the current Glommio executor.
    pub fn caller(
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<Conn, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Glommio)?;
        let socket = from_std(prepared.bind_socket()?)?;
        Ok(Conn::new(prepared.connection(now)?, socket))
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}

#[cfg(feature = "compio")]
pub mod compio_transport {
    use crate::{
        OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
        prepend_outputs,
    };
    use compio::buf::BufResult;
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
    use std::collections::VecDeque;
    use std::io;

    /// Per-connection state for compio: protocol + owned-buffer socket + timer deadlines.
    pub struct Conn {
        pub conn: SrtConnection,
        pub sock: compio::net::UdpSocket,
        timers: crate::ManualTimerStore,
        pending_outputs: VecDeque<ConnectionOutput>,
    }

    impl Conn {
        pub fn new(conn: SrtConnection, sock: compio::net::UdpSocket) -> Self {
            Self {
                conn,
                sock,
                timers: crate::ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
            }
        }

        /// Fire every timer whose deadline has passed, invoking the protocol.
        ///
        /// Outputs queued by `handle_timer` are drained by the caller's
        /// following `drain_outputs`.
        pub fn fire_expired(&mut self, now: Timestamp) {
            self.timers.fire_expired(now, &mut self.conn);
        }

        pub async fn drain_outputs(&mut self, now: Timestamp) -> io::Result<OutputDrainReport> {
            self.drain_outputs_bounded(now, OutputDrainBudget::default())
                .await
        }

        pub async fn drain_outputs_bounded(
            &mut self,
            now: Timestamp,
            budget: OutputDrainBudget,
        ) -> io::Result<OutputDrainReport> {
            let (mut work, exhausted) =
                collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
            let mut report = OutputDrainReport {
                status: if exhausted {
                    OutputDrainStatus::BudgetExhausted
                } else {
                    OutputDrainStatus::Drained
                },
                ..Default::default()
            };
            while let Some(out) = work.pop_front() {
                match out {
                    ConnectionOutput::SendPacket(bytes) => {
                        let expected = bytes.len();
                        let BufResult(result, bytes) = self.sock.send(bytes).await;
                        match result {
                            Ok(sent) if sent == expected => {
                                report.actions += 1;
                                report.packets += 1;
                                report.bytes += sent;
                            }
                            Ok(_) => {
                                prepend_outputs(&mut self.pending_outputs, work.into_iter());
                                self.pending_outputs
                                    .push_front(ConnectionOutput::SendPacket(bytes));
                                return Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    "UDP send completed with a partial datagram",
                                ));
                            }
                            Err(error) => {
                                prepend_outputs(&mut self.pending_outputs, work.into_iter());
                                self.pending_outputs
                                    .push_front(ConnectionOutput::SendPacket(bytes));
                                return Err(error);
                            }
                        }
                    }
                    other => {
                        self.timers.apply_output(&other, now);
                        report.actions += 1;
                    }
                }
            }
            Ok(report)
        }

        #[must_use]
        pub fn has_pending_outputs(&self) -> bool {
            !self.pending_outputs.is_empty()
        }

        pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
            if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
                return Err(());
            }
            self.conn.send(payload, now).map_err(|_| ())?;
            let report = self.drain_outputs(now).await.map_err(|_| ())?;
            (report.status == OutputDrainStatus::Drained)
                .then_some(())
                .ok_or(())
        }

        pub async fn tick(&mut self, payload: &[u8], now: Timestamp) -> io::Result<TickResult> {
            self.fire_expired(now);
            let drained = self.drain_outputs(now).await?;

            let mut sent = 0u64;
            if drained.status == OutputDrainStatus::Drained {
                while self.send_paced(payload, now).await.is_ok() {
                    sent += 1;
                }
            }

            let mut events = Vec::new();
            while let Some(ev) = self.conn.poll_event() {
                events.push(ev);
            }

            Ok(TickResult { sent, events })
        }
    }

    /// Resolve and bind a listener using Compio-native UDP sockets. Call from
    /// the runtime thread that will own them.
    pub fn bind_listener(
        config: &crate::ListenerConfig,
    ) -> Result<crate::RuntimeListener<compio::net::UdpSocket>, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Compio)?;
        let sockets = prepared
            .bind_sockets()?
            .into_iter()
            .map(compio::net::UdpSocket::from_std)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::RuntimeListener { prepared, sockets })
    }

    /// Build one configured caller connection and connected Compio socket.
    pub fn caller(
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<Conn, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Compio)?;
        let socket = compio::net::UdpSocket::from_std(prepared.bind_socket()?)?;
        Ok(Conn::new(prepared.connection(now)?, socket))
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }
}
