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
use std::fmt;
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
    ///
    /// Delegates to the same validators the richer config types use rather
    /// than restating their rules. Restating them had already drifted: this
    /// type accepted `max_half_open_peers > max_peers` (and the two sibling
    /// cross-field bounds), which `AdmissionConfig::validate` rejects.
    ///
    /// The `io::Error` return is kept because it is this type's published
    /// signature; `ConfigError` carries the offending field name, so it is
    /// rendered into the message rather than discarded.
    pub fn validate(&self) -> std::io::Result<()> {
        let invalid =
            |message: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
        let from_config = |error: ConfigError| invalid(error.to_string());

        SessionConfig::from_connection_options(self.connection.clone())
            .validate()
            .map_err(from_config)?;
        AdmissionConfig {
            limits: self.admission,
            ..AdmissionConfig::default()
        }
        .validate()
        .map_err(from_config)?;
        validate_output_budget(self.output_drain).map_err(from_config)?;
        if self.socket_buffer_bytes > libc::c_int::MAX as usize {
            return Err(invalid(
                "socket_buffer_bytes exceeds the OS socket option range".to_string(),
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
            bonded_inputs: BondedInputPolicy::Reject,
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
/// or retired -- serviced off the shared listener socket by SRT Socket-ID
/// dispatch, with the UDP address retained as source validation.
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
    logical_peer: LogicalPeerId,
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BondedInputPolicy {
    /// Reject GROUP handshakes. This is the safe default: accepting the legs
    /// independently would silently lose the publisher's redundancy contract.
    #[default]
    Reject,
    /// Authenticate and admit GROUP handshakes, then automatically associate
    /// matching legs into one logical ingress stream.
    Accept,
}

#[derive(Clone, Debug)]
pub struct AdmissionOptions {
    pub socket_id: u32,
    pub tsbpd_delay: u16,
    /// Forward a handshake datagram to the acceptor its SYN cookie names.
    /// Off makes a rehashed CONCLUSION strand instead, which is only
    /// useful for measuring what the routing is worth.
    pub cookie_routing: bool,
    /// Whether this listener explicitly accepts bonded SRT publishers.
    pub bonded_inputs: BondedInputPolicy,
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
            bonded_inputs: BondedInputPolicy::Reject,
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

/// Stable, process-local application handle for one logical SRT connection.
///
/// It deliberately does not expose a UDP address, a physical SRT Socket ID,
/// a wire group ID, or the caller-provided StreamID. One direct connection and
/// one bonded group are both represented by exactly one handle. Retain this
/// value from [`AdmissionEvent::logical_peer`] for steady-state operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogicalPeerId(u64);

/// A logical peer which has been atomically retired from a [`PeerTable`].
///
/// The returned protocol cores let an application choose whether to drop them
/// immediately or retain them for its own post-close accounting.  The table no
/// longer owns any Socket-ID route, timer, admission slot, or event queue for
/// this session.
pub enum RemovedLogicalPeer {
    Direct(Box<RemovedPeerLeg>),
    Group(Vec<RemovedPeerLeg>),
}

/// One physical protocol core returned when retiring a logical peer.
pub struct RemovedPeerLeg {
    pub peer: std::net::SocketAddr,
    pub connection: SrtConnection,
}

/// A newly connected logical peer. `representative_peer` is diagnostic-only;
/// use [`Self::logical_peer`] for every lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewlyConnectedPeer {
    pub logical_peer: LogicalPeerId,
    pub representative_peer: std::net::SocketAddr,
}

#[derive(Clone)]
enum LogicalPeerTarget {
    Direct(PhysicalPeerKey),
    Group(srt_lifecycle::LogicalGroupKey),
}

/// One physical SRT leg on a shared UDP listener.
///
/// The SRT specification permits multiple SRT sockets to share a UDP socket;
/// after the induction handshake their Destination SRT Socket ID, together
/// with the source UDP address, selects the leg. This is deliberately private:
/// applications retain [`LogicalPeerId`] rather than an L4/protocol key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PhysicalPeerKey {
    address: std::net::SocketAddr,
    local_socket_id: u32,
}

/// Snapshot of a direct or bonded logical peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalPeerStats {
    Direct(Box<shiguredo_srt::ConnectionStats>),
    Group(Box<GroupConnectionStats>),
}

/// Borrowed steady-state view of an admitted SRT publisher.
///
/// It deliberately hides whether the peer is one socket or a bonded group:
/// callers use the same StreamID and telemetry operations for both. Physical
/// leg details remain available inside [`LogicalPeerStats::Group`].
pub struct LogicalPeer<'a> {
    table: &'a PeerTable,
    id: LogicalPeerId,
}

impl LogicalPeer<'_> {
    #[must_use]
    pub fn id(&self) -> &LogicalPeerId {
        &self.id
    }

    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        match self.table.logical_peers.get(&self.id)? {
            LogicalPeerTarget::Direct(peer) => self
                .table
                .peers
                .get(peer)
                .and_then(|entry| entry.conn.peer_stream_id()),
            LogicalPeerTarget::Group(key) => key.stream_id.as_deref(),
        }
    }

    /// GROUP metadata used by an application's worker-affinity policy. This
    /// is descriptive only; the logical peer handle remains the session key.
    #[must_use]
    pub fn group_affinity(&self) -> Option<srt_lifecycle::GroupAffinity> {
        match self.table.logical_peers.get(&self.id)? {
            LogicalPeerTarget::Direct(peer) => self.table.peers.get(peer).and_then(|entry| {
                entry
                    .conn
                    .peer_group_extension()
                    .map(|extension| srt_lifecycle::GroupAffinity {
                        group_id: extension.group_id,
                        stream_id: entry.conn.peer_stream_id().map(str::to_owned),
                        extension,
                    })
            }),
            LogicalPeerTarget::Group(key) => {
                self.table
                    .groups
                    .get(key)
                    .map(|_| srt_lifecycle::GroupAffinity {
                        group_id: key.group_id,
                        stream_id: key.stream_id.clone(),
                        extension: self
                            .table
                            .groups
                            .get(key)
                            .and_then(|group| group.group.members().first())
                            .and_then(|member| member.connection().peer_group_extension())
                            .expect("bonded group was admitted from GROUP handshakes"),
                    })
            }
        }
    }

    #[must_use]
    pub fn stats(&self) -> Option<LogicalPeerStats> {
        match self.table.logical_peers.get(&self.id)? {
            LogicalPeerTarget::Direct(peer) => self
                .table
                .peers
                .get(peer)
                .map(|entry| LogicalPeerStats::Direct(Box::new(entry.conn.stats()))),
            LogicalPeerTarget::Group(key) => self.table.groups.get(key).map(|group| {
                LogicalPeerStats::Group(Box::new(group_connection_stats(
                    &group.group,
                    GroupLogicalCounters {
                        payloads_sent: group.logical_payloads_sent,
                        payload_bytes_sent: group.logical_payload_bytes_sent,
                        payloads_received: group.logical_payloads_received,
                        payload_bytes_received: group.logical_payload_bytes_received,
                    },
                    |member_id| {
                        let peer_addr = group.legs.get(&member_id).map(|leg| leg.physical.address);
                        (None, peer_addr)
                    },
                )))
            }),
        }
    }
}

/// Mutable steady-state view of an admitted SRT publisher.
///
/// [`Self::send`] and [`Self::disconnect`] arrange the table's maintenance
/// work, so callers do not need separate direct-peer and group-peer paths.
pub struct LogicalPeerMut<'a> {
    table: &'a mut PeerTable,
    id: LogicalPeerId,
}

impl LogicalPeerMut<'_> {
    #[must_use]
    pub fn id(&self) -> &LogicalPeerId {
        &self.id
    }

    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        match self.table.logical_peers.get(&self.id)? {
            LogicalPeerTarget::Direct(peer) => self
                .table
                .peers
                .get(peer)
                .and_then(|entry| entry.conn.peer_stream_id()),
            LogicalPeerTarget::Group(key) => key.stream_id.as_deref(),
        }
    }

    #[must_use]
    pub fn stats(&self) -> Option<LogicalPeerStats> {
        self.table
            .logical_peer(&self.id)
            .and_then(|peer| peer.stats())
    }

    /// Whether a send can be accepted without violating the group's
    /// Broadcast or Backup semantics.
    pub fn can_send(&mut self) -> bool {
        match self.table.logical_peers.get(&self.id) {
            Some(LogicalPeerTarget::Direct(peer)) => self
                .table
                .peers
                .get(peer)
                .is_some_and(|entry| entry.conn.can_send()),
            Some(LogicalPeerTarget::Group(key)) => self
                .table
                .groups
                .get_mut(key)
                .is_some_and(|group| group.group.can_send()),
            None => false,
        }
    }

    /// Send one logical payload. Broadcast returns one successful physical
    /// leg per healthy active member; Backup returns one selected leg.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, shiguredo_srt::Error> {
        match self.table.logical_peers.get(&self.id).cloned() {
            Some(LogicalPeerTarget::Direct(peer)) => {
                let entry = self.table.peers.get_mut(&peer).ok_or_else(|| {
                    shiguredo_srt::Error::with_reason(
                        shiguredo_srt::ErrorKind::InvalidState,
                        "logical peer no longer exists",
                    )
                })?;
                entry.conn.send(payload, now)?;
                self.table.mark_ready_physical(peer);
                Ok(1)
            }
            Some(LogicalPeerTarget::Group(key)) => {
                let group = self.table.groups.get_mut(&key).ok_or_else(|| {
                    shiguredo_srt::Error::with_reason(
                        shiguredo_srt::ErrorKind::InvalidState,
                        "logical peer no longer exists",
                    )
                })?;
                let legs = group.group.send(payload, now)?;
                group.logical_payloads_sent = group.logical_payloads_sent.saturating_add(1);
                group.logical_payload_bytes_sent = group
                    .logical_payload_bytes_sent
                    .saturating_add(payload.len() as u64);
                Ok(legs)
            }
            None => Err(shiguredo_srt::Error::with_reason(
                shiguredo_srt::ErrorKind::InvalidState,
                "logical peer no longer exists",
            )),
        }
    }

    /// Start an orderly close. A bonded peer closes every leg but remains in
    /// the table until the usual transport lifecycle reaches its terminal
    /// state.
    pub fn disconnect(&mut self, now: Timestamp) {
        match self.table.logical_peers.get(&self.id).cloned() {
            Some(LogicalPeerTarget::Direct(peer)) => {
                if let Some(entry) = self.table.peers.get_mut(&peer) {
                    entry.conn.disconnect(now);
                    self.table.mark_ready_physical(peer);
                }
            }
            Some(LogicalPeerTarget::Group(key)) => {
                if let Some(group) = self.table.groups.get_mut(&key) {
                    group.group.disconnect(now);
                }
            }
            None => {}
        }
    }
}

/// One logical ingress event emitted by an admitted peer or bonded group.
///
/// For an opted-in bonded publisher, `representative_peer` is its first
/// admitted leg and `logical_peer` is the stable session identity. `DataReceived` has already
/// been ordered and deduplicated across legs.
/// Otherwise this is the unmodified protocol event. Production consumers
/// should use [`PeerTable::poll_events`]; the benchmark-only
/// [`PeerTable::drain_events`] adapter remains for its legacy counters and
/// promotion timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionEvent {
    /// Wire diagnostic only; never use this as an application session key.
    pub representative_peer: std::net::SocketAddr,
    pub logical_peer: LogicalPeerId,
    pub event: ConnectionEvent,
}

struct InboundGroupLeg {
    member_id: u32,
    physical: PhysicalPeerKey,
    timers: ManualTimerStore,
}

struct InboundGroup {
    group: shiguredo_srt::SrtGroup,
    legs: HashMap<u32, InboundGroupLeg>,
    representative_peer: std::net::SocketAddr,
    logical_peer: LogicalPeerId,
    connected: bool,
    stream_deadline: Option<Instant>,
    data_events: u64,
    last_data_at: Instant,
    torn_down: bool,
    logical_payloads_received: u64,
    logical_payload_bytes_received: u64,
    logical_payloads_sent: u64,
    logical_payload_bytes_sent: u64,
}

#[derive(Clone, Debug)]
struct GroupMemberHandle {
    key: srt_lifecycle::LogicalGroupKey,
    member_id: u32,
}

/// The peers one acceptor is servicing off its shared listener.
///
/// This is the admission session state machine, minus I/O: it owns the
/// protocol objects and their timers, decides cookie routing, and records
/// telemetry, but never touches a socket. The caller drives the sending.
/// It lives here rather than in srt-lifecycle because it owns clocks and
/// live protocol state, which that crate deliberately does not.
pub struct PeerTable {
    peers: HashMap<PhysicalPeerKey, AdmissionPeer>,
    logical_peers: HashMap<LogicalPeerId, LogicalPeerTarget>,
    next_logical_peer: u64,
    source_counts: HashMap<std::net::IpAddr, usize>,
    half_open_peers: usize,
    established_peers: usize,
    half_open_deadlines: DueIndex<PhysicalPeerKey>,
    deadlines: DueIndex<PhysicalPeerKey>,
    ready: VecDeque<PhysicalPeerKey>,
    ready_set: HashSet<PhysicalPeerKey>,
    event_ready: VecDeque<PhysicalPeerKey>,
    event_ready_set: HashSet<PhysicalPeerKey>,
    groups: HashMap<srt_lifecycle::LogicalGroupKey, InboundGroup>,
    group_peers: HashMap<PhysicalPeerKey, GroupMemberHandle>,
    next_listener_socket_id: u32,
    last_now: Timestamp,
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
            logical_peers: HashMap::new(),
            next_logical_peer: 1,
            source_counts: HashMap::new(),
            half_open_peers: 0,
            established_peers: 0,
            half_open_deadlines: DueIndex::default(),
            deadlines: DueIndex::default(),
            ready: VecDeque::new(),
            ready_set: HashSet::new(),
            event_ready: VecDeque::new(),
            event_ready_set: HashSet::new(),
            groups: HashMap::new(),
            group_peers: HashMap::new(),
            next_listener_socket_id: 0,
            last_now: Timestamp::default(),
            config,
        }
    }

    fn allocate_logical_peer(&mut self, target: LogicalPeerTarget) -> LogicalPeerId {
        let id = LogicalPeerId(self.next_logical_peer);
        self.next_logical_peer = self.next_logical_peer.wrapping_add(1).max(1);
        self.logical_peers.insert(id, target);
        id
    }

    fn detach_peer_for_group(&mut self, peer: &PhysicalPeerKey) -> Option<AdmissionPeer> {
        self.deadlines.remove(peer);
        self.half_open_deadlines.remove(peer);
        self.ready_set.remove(peer);
        self.event_ready_set.remove(peer);
        self.peers.remove(peer)
    }

    fn allocate_listener_socket_id(&mut self, preferred: u32) -> u32 {
        let mut candidate = if self.next_listener_socket_id == 0 {
            preferred.max(1)
        } else {
            self.next_listener_socket_id
        };
        loop {
            if !self
                .peers
                .keys()
                .any(|key| key.local_socket_id == candidate)
                && !self
                    .group_peers
                    .keys()
                    .any(|key| key.local_socket_id == candidate)
            {
                self.next_listener_socket_id = candidate.wrapping_add(1).max(1);
                return candidate;
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
    }

    fn physical_for_datagram(
        &self,
        address: std::net::SocketAddr,
        destination_socket_id: u32,
        induction_socket_id: Option<u32>,
    ) -> Option<PhysicalPeerKey> {
        if destination_socket_id != 0 {
            return Some(PhysicalPeerKey {
                address,
                local_socket_id: destination_socket_id,
            });
        }
        let caller_socket_id = induction_socket_id?;
        self.peers
            .iter()
            .find_map(|(key, entry)| {
                (key.address == address && entry.conn.peer_socket_id() == caller_socket_id)
                    .then_some(*key)
            })
            .or_else(|| {
                self.group_peers.iter().find_map(|(key, handle)| {
                    let member = self
                        .groups
                        .get(&handle.key)
                        .and_then(|group| group.group.member(handle.member_id))?;
                    (key.address == address
                        && member.connection().peer_socket_id() == caller_socket_id)
                        .then_some(*key)
                })
            })
    }

    fn physical_for_address(&self, address: std::net::SocketAddr) -> Option<PhysicalPeerKey> {
        self.peers
            .keys()
            .chain(self.group_peers.keys())
            .find(|key| key.address == address)
            .copied()
    }

    fn group_admission_allowed(
        &self,
        identity: &srt_lifecycle::HandshakeIdentity,
        handshake: &shiguredo_srt::HandshakePacket,
        options: &AdmissionOptions,
    ) -> bool {
        let Some(group) = identity.group.as_ref() else {
            return true;
        };
        let Some(mode) = shiguredo_srt::GroupMode::from_group_type(group.extension.group_type)
        else {
            return false;
        };
        if options.bonded_inputs != BondedInputPolicy::Accept
            || group.group_id & shiguredo_srt::SRTGROUP_MASK == 0
        {
            return false;
        }
        self.groups
            .get(&group.logical_key())
            .is_none_or(|existing| {
                existing.group.mode() == mode
                    && existing.group.member(handshake.socket_id).is_none()
            })
    }

    fn adopt_bonded_peer(&mut self, peer: PhysicalPeerKey) {
        let Some(entry) = self.peers.get(&peer) else {
            return;
        };
        let Some(extension) = entry.conn.peer_group_extension() else {
            return;
        };
        let Some(mode) = shiguredo_srt::GroupMode::from_group_type(extension.group_type) else {
            return;
        };
        let affinity = srt_lifecycle::GroupAffinity {
            group_id: extension.group_id,
            stream_id: entry.conn.peer_stream_id().map(str::to_owned),
            extension,
        };
        let key = affinity.logical_key();
        let member_id = entry.conn.peer_socket_id();
        let weight = extension.weight;
        let logical_peer = entry.logical_peer;

        if !self.groups.contains_key(&key) {
            let group = shiguredo_srt::SrtGroup::new(extension.group_id, mode)
                .expect("GROUP handshakes are validated before connection admission");
            self.groups.insert(
                key.clone(),
                InboundGroup {
                    group,
                    legs: HashMap::new(),
                    representative_peer: peer.address,
                    logical_peer,
                    connected: false,
                    stream_deadline: None,
                    data_events: 0,
                    last_data_at: Instant::now(),
                    torn_down: false,
                    logical_payloads_received: 0,
                    logical_payload_bytes_received: 0,
                    logical_payloads_sent: 0,
                    logical_payload_bytes_sent: 0,
                },
            );
            self.logical_peers
                .insert(logical_peer, LogicalPeerTarget::Group(key.clone()));
        } else {
            // This physical leg was briefly a direct peer only while its
            // handshake completed. The existing group's handle remains the
            // sole application-visible logical identity.
            self.logical_peers.remove(&logical_peer);
        }

        let entry = self
            .detach_peer_for_group(&peer)
            .expect("connected GROUP peer remains in the ordinary peer table until adoption");
        let group = self
            .groups
            .get_mut(&key)
            .expect("group was inserted or already existed");
        group
            .group
            .add_member(member_id, weight, entry.conn)
            .expect("duplicate GROUP member IDs are rejected before admission");
        group.legs.insert(
            member_id,
            InboundGroupLeg {
                member_id,
                physical: peer,
                timers: entry.timers,
            },
        );
        self.group_peers
            .insert(peer, GroupMemberHandle { key, member_id });
    }

    fn admit_group_leg(&mut self, peer: PhysicalPeerKey, data: &[u8], now: Timestamp) -> Admit {
        let Some(handle) = self.group_peers.get(&peer).cloned() else {
            return Admit::Dropped(AdmissionDropReason::StaleConclusion);
        };
        let Some(group) = self.groups.get_mut(&handle.key) else {
            return Admit::Dropped(AdmissionDropReason::StaleConclusion);
        };
        let Some(member) = group.group.member_mut(handle.member_id) else {
            return Admit::Dropped(AdmissionDropReason::StaleConclusion);
        };
        match member.connection_mut().feed_recv_buf(data, now) {
            Ok(()) => Admit::Fed,
            Err(_) => Admit::Dropped(AdmissionDropReason::InvalidPacket),
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
        self.last_now = now;
        let expired = self.prune_half_open(now);
        telemetry.record_expired_half_open(expired);
        // Only a CONTROL packet can be a handshake (SRT's F bit, the top bit
        // of the first word). Checking it here keeps `peek_handshake` -- a
        // full `SrtPacket::decode`, which ends in `payload.to_vec()` -- off
        // the DATA path, which is every packet of a live stream. Without the
        // guard each datagram is decoded twice, once here and once in
        // `feed_recv_buf`, and the first decode's ~1.3 KB payload copy is
        // discarded on the next line.
        let handshake = is_control_datagram(data)
            .then(|| shiguredo_srt::peek_handshake(data))
            .flatten();
        // RFC stream multiplexing routes established SRT sockets by the
        // fixed-header Destination SRT Socket ID. INDUCTION is the sole
        // exception: it targets socket ID zero and carries the caller's
        // source SRT Socket ID in the handshake body.
        let destination_socket_id = match shiguredo_srt::peek_destination_socket_id(data) {
            Ok(socket_id) => socket_id,
            Err(_) => {
                telemetry.record_invalid_datagram();
                return Admit::Dropped(AdmissionDropReason::InvalidPacket);
            }
        };
        let mut physical = self.physical_for_datagram(
            peer,
            destination_socket_id,
            handshake
                .as_ref()
                .filter(|packet| packet.handshake_type == shiguredo_srt::HandshakeType::Induction)
                .map(|packet| packet.socket_id),
        );
        if let Some(physical) = physical
            && self.group_peers.contains_key(&physical)
        {
            return self.admit_group_leg(physical, data, now);
        }
        let identity = handshake
            .as_ref()
            .map(srt_lifecycle::handshake_identity_from_handshake);
        let conclusion = identity.as_ref().filter(|identity| identity.is_conclusion);
        // Some interoperable callers retain zero in the control header for a
        // CONCLUSION. The cookie is the handshake-phase route in that case;
        // it is not used for established DATA/CONTROL traffic, which remains
        // strictly Destination-Socket-ID demultiplexed.
        if physical.is_none()
            && let Some(identity) = conclusion
        {
            physical = self.peers.iter().find_map(|(key, entry)| {
                (key.address == peer && entry.conn.syn_cookie() == identity.syn_cookie)
                    .then_some(*key)
            });
            // Legacy/raw callers that bypass `SessionConfig` can advertise
            // socket ID zero during the whole handshake. Preserve that
            // compatibility only when the UDP tuple identifies exactly one
            // half-open leg; shared-four-tuple sessions must materialize a
            // non-zero caller SRT Socket ID and are never guessed by address.
            if physical.is_none() {
                let mut candidates = self.peers.keys().filter(|key| key.address == peer);
                physical = candidates
                    .next()
                    .copied()
                    .filter(|_| candidates.next().is_none());
            }
        }
        let known = physical.is_some_and(|physical| self.peers.contains_key(&physical));

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
            let packet = handshake
                .as_ref()
                .expect("a conclusion identity came from a decoded handshake");
            let group_admission_allowed = self.group_admission_allowed(identity, packet, options);
            if self
                .peers
                .get(&physical.expect("known peer has a physical route"))
                .is_some_and(|entry| !entry.admission_established)
                && self.established_count() >= self.config.max_established_peers
            {
                telemetry.record_established_capacity_drop();
                return Admit::Dropped(AdmissionDropReason::EstablishedCapacity);
            }
            let Some(entry) = self
                .peers
                .get_mut(&physical.expect("known peer has a physical route"))
            else {
                return Admit::Dropped(AdmissionDropReason::StaleConclusion);
            };
            if entry.rejected {
                return Admit::Dropped(AdmissionDropReason::RejectedPeer);
            }
            if identity.syn_cookie != entry.conn.syn_cookie() {
                telemetry.record_invalid_cookie();
                return Admit::Dropped(AdmissionDropReason::InvalidCookie);
            }
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
            if !group_admission_allowed {
                if entry
                    .conn
                    .reject(RejectionReason::BAD_MODE.get(), now)
                    .is_err()
                {
                    telemetry.record_invalid_datagram();
                    return Admit::Dropped(AdmissionDropReason::InvalidPacket);
                }
                telemetry.record_policy_rejection();
                entry.rejected = true;
                entry.last_datagram_at = now;
                self.mark_ready_physical(physical.expect("known peer has a physical route"));
                return Admit::Rejected;
            }
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
                        self.mark_ready_physical(
                            physical.expect("known peer has a physical route"),
                        );
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
                    self.mark_ready_physical(physical.expect("known peer has a physical route"));
                    return Admit::Rejected;
                }
                AdmissionHookResult::Defer => {
                    telemetry.record_policy_deferred();
                    return Admit::Deferred;
                }
            }
        }

        let physical = physical.unwrap_or_else(|| PhysicalPeerKey {
            address: peer,
            local_socket_id: self.allocate_listener_socket_id(options.socket_id),
        });
        let new_logical_peer =
            (!known).then(|| self.allocate_logical_peer(LogicalPeerTarget::Direct(physical)));
        let (fed, feed_error_kind, inserted, became_established, became_terminal) = {
            let mut inserted = false;
            let entry = self.peers.entry(physical).or_insert_with(|| {
                inserted = true;
                let mut connection_options =
                    options.connection_template.clone().unwrap_or_default();
                connection_options.socket_id = physical.local_socket_id;
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
                    logical_peer: new_logical_peer
                        .expect("only an unknown peer can allocate an admission entry"),
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
                let _ = self.remove_physical(physical);
            } else if became_terminal {
                self.mark_ready_physical(physical);
            }
            return Admit::Dropped(AdmissionDropReason::InvalidPacket);
        }
        if became_established {
            self.half_open_peers = self.half_open_peers.saturating_sub(1);
            self.established_peers += 1;
            self.half_open_deadlines.remove(&physical);
            self.adopt_bonded_peer(physical);
        } else if !self
            .peers
            .get(&physical)
            .is_some_and(|entry| entry.admission_established)
        {
            self.half_open_deadlines.set(
                physical,
                now.add_micros(half_open_timeout_micros(self.config.half_open_timeout)),
            );
        }
        self.mark_ready_physical(physical);
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
            let _ = self.remove_physical(peer);
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
        self.last_now = now;
        out.clear();
        let mut rejected = Vec::new();
        let mut due = Vec::new();
        self.deadlines.pop_due(now, &mut due);
        for peer in due {
            self.mark_ready_physical(peer);
        }

        while let Some(peer) = self.ready.pop_front() {
            self.ready_set.remove(&peer);
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            entry.timers.fire_expired(now, &mut entry.conn);
            while let Some(output) = entry.conn.poll_output() {
                match output {
                    ConnectionOutput::SendPacket(bytes) => out.push((peer.address, bytes)),
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
            let _ = self.remove_physical(peer);
        }
        for group in self.groups.values_mut() {
            let (core, legs) = (&mut group.group, &mut group.legs);
            for leg in legs.values_mut() {
                let member = core
                    .member_mut(leg.member_id)
                    .expect("group I/O legs are built with matching members");
                leg.timers.fire_expired(now, member.connection_mut());
                while let Some(output) = member.connection_mut().poll_output() {
                    match output {
                        ConnectionOutput::SendPacket(bytes) => {
                            out.push((leg.physical.address, bytes));
                        }
                        other => leg.timers.apply_output(&other, now),
                    }
                }
            }
        }
    }

    /// Mark a peer whose protocol state was changed through [`Self::iter_mut`]
    /// as ready for the next indexed maintenance pass.
    fn mark_ready_physical(&mut self, peer: PhysicalPeerKey) {
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

    /// Mark the sole ordinary peer at `peer` ready. Applications using a
    /// shared four-tuple should use [`LogicalPeerMut`] instead; an address
    /// alone does not distinguish multiple physical SRT legs.
    pub fn mark_ready(&mut self, peer: std::net::SocketAddr) {
        if let Some(physical) = self.physical_for_address(peer) {
            self.mark_ready_physical(physical);
        }
    }

    /// Microseconds until any tracked peer's next timer deadline.
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        self.last_now = now;
        let peer_deadline = self
            .deadlines
            .peek_min_deadline()
            .map(|deadline| deadline.saturating_sub(now))
            .unwrap_or(default_us);
        self.groups
            .values()
            .flat_map(|group| group.legs.values())
            .filter_map(|leg| leg.timers.next_deadline())
            .map(|deadline| deadline.saturating_sub(now))
            .min()
            .unwrap_or(peer_deadline)
    }

    /// Drain logical ingress events for production consumers.
    pub fn poll_events(&mut self, out: &mut Vec<AdmissionEvent>) {
        out.clear();
        while let Some(peer) = self.event_ready.pop_front() {
            self.event_ready_set.remove(&peer);
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            while let Some(event) = entry.conn.poll_event() {
                out.push(AdmissionEvent {
                    representative_peer: peer.address,
                    logical_peer: entry.logical_peer,
                    event,
                });
            }
        }
        for group in self.groups.values_mut() {
            while let Some(event) = group.group.poll_event(self.last_now) {
                match event {
                    shiguredo_srt::GroupEvent::MemberConnected { .. } => {
                        if !group.connected {
                            group.connected = true;
                            out.push(AdmissionEvent {
                                representative_peer: group.representative_peer,
                                logical_peer: group.logical_peer,
                                event: ConnectionEvent::Connected,
                            });
                        }
                    }
                    shiguredo_srt::GroupEvent::DataReceived(packet) => {
                        group.logical_payloads_received =
                            group.logical_payloads_received.saturating_add(1);
                        group.data_events = group.data_events.saturating_add(1);
                        group.last_data_at = Instant::now();
                        group.logical_payload_bytes_received = group
                            .logical_payload_bytes_received
                            .saturating_add(packet.payload.len() as u64);
                        out.push(AdmissionEvent {
                            representative_peer: group.representative_peer,
                            logical_peer: group.logical_peer,
                            event: ConnectionEvent::DataReceived {
                                payload: packet.payload,
                                sequence_number: packet.sequence_number,
                                message_number: packet.message_number,
                                timestamp: packet.timestamp,
                            },
                        });
                    }
                    shiguredo_srt::GroupEvent::MemberError { error, .. }
                    | shiguredo_srt::GroupEvent::MemberDisconnected { reason: error, .. }
                        if group.connected
                            && !group.group.members().iter().any(|member| {
                                member.connection().state()
                                    == shiguredo_srt::ConnectionState::Connected
                            }) =>
                    {
                        group.connected = false;
                        group.torn_down |= !is_ordered_close(&error);
                        out.push(AdmissionEvent {
                            representative_peer: group.representative_peer,
                            logical_peer: group.logical_peer,
                            event: ConnectionEvent::Disconnected { reason: error },
                        });
                    }
                    shiguredo_srt::GroupEvent::MemberError { .. }
                    | shiguredo_srt::GroupEvent::MemberDisconnected { .. } => {}
                }
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
        newly_connected: &mut Vec<NewlyConnectedPeer>,
    ) {
        newly_connected.clear();
        let mut events = Vec::new();
        self.poll_events(&mut events);
        let deadline = Instant::now() + stream_len;
        for admission_event in events {
            let peer = admission_event.representative_peer;
            let connected = matches!(&admission_event.event, ConnectionEvent::Connected);
            match self
                .logical_peers
                .get(&admission_event.logical_peer)
                .cloned()
            {
                Some(LogicalPeerTarget::Direct(physical)) => {
                    if let Some(entry) = self.peers.get_mut(&physical)
                        && entry.apply_event(admission_event.event)
                    {
                        entry.stream_deadline = Some(deadline);
                        newly_connected.push(NewlyConnectedPeer {
                            logical_peer: admission_event.logical_peer,
                            representative_peer: peer,
                        });
                    }
                }
                Some(LogicalPeerTarget::Group(key)) => {
                    if let Some(group) = self.groups.get_mut(&key)
                        && connected
                        && group.stream_deadline.is_none()
                    {
                        group.stream_deadline = Some(deadline);
                        newly_connected.push(NewlyConnectedPeer {
                            logical_peer: admission_event.logical_peer,
                            representative_peer: peer,
                        });
                    }
                }
                None => {}
            }
        }
        // A group can become connected while its member event is drained by
        // an earlier maintenance pass. Keep the stream clock tied to the
        // persistent logical state as well as to this pass's event batch, so
        // that case cannot leave a completed bonded stream waiting for the
        // handshake deadline.
        for group in self.groups.values_mut() {
            if group.connected && group.stream_deadline.is_none() {
                group.stream_deadline = Some(deadline);
                newly_connected.push(NewlyConnectedPeer {
                    logical_peer: group.logical_peer,
                    representative_peer: group.representative_peer,
                });
            }
        }
    }

    /// Return the steady-state view for either an ordinary connection or an
    /// opted-in bonded group. New consumers should retain this identity from
    /// [`AdmissionEvent::logical_peer`] rather than using a bonded group's
    /// representative socket address as a session key.
    #[must_use]
    pub fn logical_peer(&self, id: &LogicalPeerId) -> Option<LogicalPeer<'_>> {
        match self.logical_peers.get(id)? {
            LogicalPeerTarget::Direct(peer) if self.peers.contains_key(peer) => Some(LogicalPeer {
                table: self,
                id: *id,
            }),
            LogicalPeerTarget::Group(key) if self.groups.contains_key(key) => Some(LogicalPeer {
                table: self,
                id: *id,
            }),
            LogicalPeerTarget::Direct(_) | LogicalPeerTarget::Group(_) => None,
        }
    }

    /// Return the mutable steady-state view for either an ordinary connection
    /// or an opted-in bonded group.
    pub fn logical_peer_mut(&mut self, id: &LogicalPeerId) -> Option<LogicalPeerMut<'_>> {
        self.logical_peer(id)?;
        Some(LogicalPeerMut {
            table: self,
            id: *id,
        })
    }

    /// Atomically retire one logical stream. For a bonded publisher this
    /// removes every physical leg; a late datagram for any returned Socket ID
    /// is ignored and can never recreate the retired group.
    pub fn remove(&mut self, id: LogicalPeerId) -> Option<RemovedLogicalPeer> {
        match self.logical_peers.get(&id).cloned()? {
            LogicalPeerTarget::Direct(peer) => self.remove_direct(peer).map(|entry| {
                RemovedLogicalPeer::Direct(Box::new(RemovedPeerLeg {
                    peer: peer.address,
                    connection: entry.conn,
                }))
            }),
            LogicalPeerTarget::Group(key) => self.remove_group(key),
        }
    }

    /// Benchmark-only physical extraction for the legacy reuseport promotion
    /// experiment. Production integrations use [`Self::remove`] with a
    /// [`LogicalPeerId`].
    #[cfg(feature = "bench-internals")]
    pub fn remove_direct_for_bench(&mut self, peer: std::net::SocketAddr) -> Option<AdmissionPeer> {
        self.physical_for_address(peer)
            .and_then(|physical| self.remove_direct(physical))
    }

    /// Benchmark-only direct-peer iterator for the legacy reuseport
    /// promotion experiment. It is deliberately absent from production builds.
    #[cfg(feature = "bench-internals")]
    pub fn iter_direct_for_bench(
        &mut self,
    ) -> impl Iterator<Item = (&std::net::SocketAddr, &mut AdmissionPeer)> {
        self.peers
            .iter_mut()
            .map(|(physical, entry)| (&physical.address, entry))
    }

    /// Benchmark-only direct peer inspection for the legacy reuseport
    /// promotion experiment. It is deliberately absent from production builds.
    #[cfg(feature = "bench-internals")]
    pub fn direct_for_bench(&self, peer: std::net::SocketAddr) -> Option<&AdmissionPeer> {
        self.physical_for_address(peer)
            .and_then(|physical| self.peers.get(&physical))
    }

    fn remove_physical(&mut self, peer: PhysicalPeerKey) -> Option<AdmissionPeer> {
        if let Some(handle) = self.group_peers.get(&peer).cloned() {
            let _ = self.remove_group(handle.key)?;
            return None;
        }
        self.remove_direct(peer)
    }

    fn remove_direct(&mut self, peer: PhysicalPeerKey) -> Option<AdmissionPeer> {
        self.purge_physical_indexes(peer);
        let removed = self.peers.remove(&peer);
        if let Some(entry) = &removed {
            self.logical_peers.remove(&entry.logical_peer);
            if entry.admission_established {
                self.established_peers = self.established_peers.saturating_sub(1);
            } else {
                self.half_open_peers = self.half_open_peers.saturating_sub(1);
            }
        }
        if removed.is_some()
            && let HashEntry::Occupied(mut entry) = self.source_counts.entry(peer.address.ip())
        {
            let count = entry.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                entry.remove();
            }
        }
        removed
    }

    fn remove_group(&mut self, key: srt_lifecycle::LogicalGroupKey) -> Option<RemovedLogicalPeer> {
        let mut group = self.groups.remove(&key)?;
        self.logical_peers.remove(&group.logical_peer);
        let mut removed = Vec::with_capacity(group.legs.len());
        for (member_id, leg) in std::mem::take(&mut group.legs) {
            let connection = group
                .group
                .remove_member_connection(member_id)
                .expect("group I/O legs are built with matching members");
            self.group_peers.remove(&leg.physical);
            self.purge_physical_indexes(leg.physical);
            self.peers.remove(&leg.physical);
            self.established_peers = self.established_peers.saturating_sub(1);
            self.decrement_source_count(leg.physical.address.ip());
            removed.push(RemovedPeerLeg {
                peer: leg.physical.address,
                connection,
            });
        }
        Some(RemovedLogicalPeer::Group(removed))
    }

    fn decrement_source_count(&mut self, ip: std::net::IpAddr) {
        if let HashEntry::Occupied(mut entry) = self.source_counts.entry(ip) {
            let count = entry.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                entry.remove();
            }
        }
    }

    #[cfg(test)]
    fn contains(&self, peer: &std::net::SocketAddr) -> bool {
        self.physical_for_address(*peer).is_some()
    }

    #[cfg(test)]
    fn get(&self, peer: &std::net::SocketAddr) -> Option<&AdmissionPeer> {
        self.physical_for_address(*peer)
            .and_then(|physical| self.peers.get(&physical))
    }

    fn purge_physical_indexes(&mut self, peer: PhysicalPeerKey) {
        self.deadlines.remove(&peer);
        self.half_open_deadlines.remove(&peer);
        self.ready_set.remove(&peer);
        self.ready.retain(|queued| *queued != peer);
        self.event_ready_set.remove(&peer);
        self.event_ready.retain(|queued| *queued != peer);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len() + self.group_peers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty() && self.group_peers.is_empty()
    }

    #[must_use]
    pub fn half_open_count(&self) -> usize {
        self.half_open_peers
    }

    #[must_use]
    pub fn established_count(&self) -> usize {
        self.established_peers
    }

    /// Snapshot every active bonded ingress with both logical delivery and
    /// per-leg wire telemetry. Ordinary unbonded peers are intentionally not
    /// included: their existing [`AdmissionPeer`] stats retain the normal
    /// single-connection meaning.
    #[must_use]
    pub fn bonded_stats(&self) -> Vec<InboundGroupStats> {
        self.groups
            .iter()
            .map(|(key, group)| InboundGroupStats {
                key: key.clone(),
                ever_connected: group.stream_deadline.is_some(),
                torn_down: group.torn_down,
                connection: group_connection_stats(
                    &group.group,
                    GroupLogicalCounters {
                        payloads_sent: group.logical_payloads_sent,
                        payload_bytes_sent: group.logical_payload_bytes_sent,
                        payloads_received: group.logical_payloads_received,
                        payload_bytes_received: group.logical_payload_bytes_received,
                    },
                    |member_id| {
                        let peer_addr = group.legs.get(&member_id).map(|leg| leg.physical.address);
                        (None, peer_addr)
                    },
                ),
            })
            .collect()
    }

    #[must_use]
    pub fn peers_for_ip(&self, ip: std::net::IpAddr) -> usize {
        self.source_counts.get(&ip).copied().unwrap_or_default()
    }

    fn reconcile_established(&mut self, peer: PhysicalPeerKey) {
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
        self.peers
            .iter()
            // Bonded physical legs are represented by the one logical group
            // below. Their `AdmissionPeer` bookkeeping deliberately never
            // receives direct events, so counting them here would make a
            // completed group wait for the handshake deadline.
            .filter(|(peer, _)| !self.group_peers.contains_key(peer))
            .all(|(_, p)| {
                srt_lifecycle::is_terminal(
                    p.connected,
                    p.stream_deadline,
                    p.last_data_at,
                    now,
                    connect_deadline,
                    idle_grace,
                )
            })
            && self.groups.values().all(|group| {
                srt_lifecycle::is_terminal(
                    group.connected,
                    group.stream_deadline,
                    group.last_data_at,
                    now,
                    connect_deadline,
                    idle_grace,
                )
            })
    }

    /// Number of application-visible streams with at least one live SRT leg.
    /// A bonded group contributes one even when several member connections
    /// are established on the same UDP tuple.
    #[must_use]
    pub fn logical_connected_count(&self) -> usize {
        let direct = self
            .peers
            .iter()
            .filter(|(peer, entry)| {
                !self.group_peers.contains_key(peer)
                    && entry.conn.state() == shiguredo_srt::ConnectionState::Connected
            })
            .count();
        let groups = self
            .groups
            .values()
            .filter(|group| {
                group.group.members().iter().any(|member| {
                    member.connection().state() == shiguredo_srt::ConnectionState::Connected
                })
            })
            .count();
        direct + groups
    }

    /// Number of logical streams that have completed their initial SRT
    /// handshake, even if an orderly close has already begun.
    #[must_use]
    pub fn logical_started_count(&self) -> usize {
        let direct = self
            .peers
            .iter()
            .filter(|(peer, entry)| {
                !self.group_peers.contains_key(peer) && entry.stream_deadline.is_some()
            })
            .count();
        let groups = self
            .groups
            .values()
            .filter(|group| group.stream_deadline.is_some())
            .count();
        direct + groups
    }
}

impl IntoIterator for PeerTable {
    type Item = (std::net::SocketAddr, AdmissionPeer);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.peers
            .into_iter()
            .map(|(physical, peer)| (physical.address, peer))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Per-peer entropy for the upper bits of a SYN cookie, so cookies differ
/// per connection instead of being one constant per worker.
/// Is this datagram a CONTROL packet?
///
/// SRT's first header word carries the packet type in its top bit: 1 for
/// CONTROL, 0 for DATA (`PacketType::from_first_word`). Only a CONTROL
/// packet can be a handshake, so this is the cheap pre-filter that keeps a
/// full decode off the DATA path. A datagram too short to hold a header is
/// not a handshake either.
fn is_control_datagram(data: &[u8]) -> bool {
    data.first().is_some_and(|byte| byte & 0x80 != 0)
}

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
        // Called per datagram, where nothing has expired almost every time.
        // This counter is shared by every acceptor thread, so an
        // unconditional RMW bounces its cacheline between cores on each
        // packet for no recorded change.
        if count == 0 {
            return;
        }
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

/// Opaque application identity for one outbound SRT stream. A direct caller
/// and a bonded Broadcast/Backup group have the same steady-state API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogicalCallerId(u64);

/// Coarse logical state of an outbound stream, independent of how many
/// physical SRT legs currently carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalCallerState {
    Connecting,
    Connected,
    Disconnected,
}

/// One physical caller leg for [`CallerTable::add_direct`]. The connection
/// must already have begun its caller handshake.
pub struct CallerLeg {
    pub peer: std::net::SocketAddr,
    pub connection: SrtConnection,
}

impl CallerLeg {
    #[must_use]
    pub fn new(peer: std::net::SocketAddr, connection: SrtConnection) -> Self {
        Self { peer, connection }
    }
}

/// One physical caller leg for [`CallerTable::add_group`]. `member_id` is the
/// SRT group-member identity, while the connection Socket ID remains the
/// per-leg wire demultiplexing key.
pub struct CallerGroupLeg {
    pub member_id: u32,
    pub weight: u16,
    pub peer: std::net::SocketAddr,
    pub connection: SrtConnection,
}

impl CallerGroupLeg {
    #[must_use]
    pub fn new(
        member_id: u32,
        weight: u16,
        peer: std::net::SocketAddr,
        connection: SrtConnection,
    ) -> Self {
        Self {
            member_id,
            weight,
            peer,
            connection,
        }
    }
}

/// Telemetry for an outbound logical caller. Group snapshots contain both the
/// aggregate logical/wire counters and the individual physical leg rows.
pub enum LogicalCallerStats {
    Direct(Box<shiguredo_srt::ConnectionStats>),
    Group(Box<GroupConnectionStats>),
}

/// A logical caller atomically removed from a [`CallerTable`]. Its routes,
/// timers, and pending outputs were removed from the table with it.
pub enum RemovedLogicalCaller {
    Direct(Box<RemovedCallerLeg>),
    Group(Vec<RemovedCallerLeg>),
}

/// One physical protocol core returned when retiring a logical caller.
pub struct RemovedCallerLeg {
    pub peer: std::net::SocketAddr,
    pub connection: SrtConnection,
}

/// Read-only steady-state view of one outbound logical stream.
pub struct LogicalCaller<'a> {
    table: &'a CallerTable,
    id: LogicalCallerId,
}

impl LogicalCaller<'_> {
    #[must_use]
    pub const fn id(&self) -> LogicalCallerId {
        self.id
    }

    #[must_use]
    pub fn state(&self) -> Option<LogicalCallerState> {
        self.table.sessions.get(&self.id).map(CallerSession::state)
    }

    #[must_use]
    pub fn stats(&self) -> Option<LogicalCallerStats> {
        self.table.sessions.get(&self.id).map(CallerSession::stats)
    }
}

/// Mutable steady-state view of one outbound logical stream. This deliberately
/// mirrors [`LogicalPeerMut`]: applications send, check capacity, close, and
/// collect telemetry without handling socket IDs or bond legs.
pub struct LogicalCallerMut<'a> {
    table: &'a mut CallerTable,
    id: LogicalCallerId,
}

impl LogicalCallerMut<'_> {
    #[must_use]
    pub const fn id(&self) -> LogicalCallerId {
        self.id
    }

    #[must_use]
    pub fn state(&self) -> Option<LogicalCallerState> {
        self.table
            .logical_caller(&self.id)
            .and_then(|caller| caller.state())
    }

    #[must_use]
    pub fn stats(&self) -> Option<LogicalCallerStats> {
        self.table
            .logical_caller(&self.id)
            .and_then(|caller| caller.stats())
    }

    /// Whether the next logical payload can be accepted without weakening a
    /// Broadcast or Backup delivery contract.
    pub fn can_send(&mut self) -> bool {
        self.table
            .sessions
            .get_mut(&self.id)
            .is_some_and(CallerSession::can_send)
    }

    /// Send one logical payload. Direct callers return one; Broadcast returns
    /// the successful active-leg count; Backup returns its selected leg.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, shiguredo_srt::Error> {
        self.table
            .sessions
            .get_mut(&self.id)
            .ok_or_else(|| {
                shiguredo_srt::Error::with_reason(
                    shiguredo_srt::ErrorKind::InvalidState,
                    "logical caller no longer exists",
                )
            })?
            .send(payload, now)
    }

    /// Begin an orderly close. A bonded caller closes every physical leg.
    pub fn disconnect(&mut self, now: Timestamp) {
        if let Some(caller) = self.table.sessions.get_mut(&self.id) {
            caller.disconnect(now);
        }
    }
}

/// Runtime-neutral caller-side table for many direct or bonded SRT streams
/// sharing one application-owned UDP socket.
///
/// The runtime performs `recv_from`/`send_to`; this table owns protocol cores,
/// timers, source-address validation, and SRT Socket-ID routing. Group policy
/// stays in the shared [`shiguredo_srt::SrtGroup`] core, so every runtime sees
/// identical Broadcast and Backup behavior.
pub struct CallerTable {
    sessions: HashMap<LogicalCallerId, CallerSession>,
    routes: HashMap<u32, CallerRoute>,
    round_robin: VecDeque<LogicalCallerId>,
    next_logical_caller: u64,
}

enum CallerRoute {
    Direct(LogicalCallerId),
    Group {
        caller: LogicalCallerId,
        member_id: u32,
    },
}

struct CallerLegState {
    peer: std::net::SocketAddr,
    connection: SrtConnection,
    timers: ManualTimerStore,
    pending: VecDeque<ConnectionOutput>,
}

struct CallerGroupLegState {
    peer: std::net::SocketAddr,
    timers: ManualTimerStore,
    pending: VecDeque<ConnectionOutput>,
}

struct CallerGroupState {
    group: shiguredo_srt::SrtGroup,
    legs: HashMap<u32, CallerGroupLegState>,
    leg_order: Vec<u32>,
    next_leg: usize,
    logical: GroupLogicalCounters,
}

enum CallerSession {
    Direct(Box<CallerLegState>),
    Group(Box<CallerGroupState>),
}

/// The budget, progress report, and output accumulator threaded unchanged
/// through one bounded drain pass, from [`CallerTable::poll_outbound_bounded`]
/// down to the single-output-item helpers. Bundled because the three always
/// travel together; `budget` is read-only for the pass, `report` and `out`
/// accumulate across every leg it visits.
struct DrainSink<'a> {
    budget: OutputDrainBudget,
    report: &'a mut OutputDrainReport,
    out: &'a mut Vec<(std::net::SocketAddr, Vec<u8>)>,
}

impl CallerSession {
    fn state(&self) -> LogicalCallerState {
        match self {
            Self::Direct(leg) => logical_state(&leg.connection),
            Self::Group(group) => {
                if group.group.members().iter().any(|member| {
                    member.connection().state() == shiguredo_srt::ConnectionState::Connected
                }) {
                    LogicalCallerState::Connected
                } else if group.group.members().iter().all(|member| {
                    member.connection().state() == shiguredo_srt::ConnectionState::Disconnected
                }) {
                    LogicalCallerState::Disconnected
                } else {
                    LogicalCallerState::Connecting
                }
            }
        }
    }

    fn stats(&self) -> LogicalCallerStats {
        match self {
            Self::Direct(leg) => LogicalCallerStats::Direct(Box::new(leg.connection.stats())),
            Self::Group(group) => LogicalCallerStats::Group(Box::new(group_connection_stats(
                &group.group,
                group.logical,
                |member_id| {
                    let leg = group
                        .legs
                        .get(&member_id)
                        .expect("group and caller legs are built together");
                    (None, Some(leg.peer))
                },
            ))),
        }
    }

    fn can_send(&mut self) -> bool {
        match self {
            Self::Direct(leg) => leg.connection.can_send(),
            Self::Group(group) => group.group.can_send(),
        }
    }

    fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, shiguredo_srt::Error> {
        match self {
            Self::Direct(leg) => {
                leg.connection.send(payload, now)?;
                Ok(1)
            }
            Self::Group(group) => {
                let legs = group.group.send(payload, now)?;
                group.logical.payloads_sent = group.logical.payloads_sent.saturating_add(1);
                group.logical.payload_bytes_sent = group
                    .logical
                    .payload_bytes_sent
                    .saturating_add(payload.len() as u64);
                Ok(legs)
            }
        }
    }

    fn disconnect(&mut self, now: Timestamp) {
        match self {
            Self::Direct(leg) => leg.connection.disconnect(now),
            Self::Group(group) => group.group.disconnect(now),
        }
    }

    fn fire_timers(&mut self, now: Timestamp) {
        match self {
            Self::Direct(leg) => leg.timers.fire_expired(now, &mut leg.connection),
            Self::Group(group) => {
                let (core, legs) = (&mut group.group, &mut group.legs);
                for (member_id, leg) in legs {
                    let connection = core
                        .member_mut(*member_id)
                        .expect("group and caller legs are built together")
                        .connection_mut();
                    leg.timers.fire_expired(now, connection);
                }
            }
        }
    }

    fn drain_one(&mut self, now: Timestamp, sink: &mut DrainSink) -> DrainOne {
        match self {
            Self::Direct(leg) => drain_one_caller_leg(leg, now, sink),
            Self::Group(group) => {
                for _ in 0..group.leg_order.len() {
                    let member_id = group.leg_order[group.next_leg];
                    group.next_leg = (group.next_leg + 1) % group.leg_order.len();
                    let leg = group
                        .legs
                        .get_mut(&member_id)
                        .expect("group and caller legs are built together");
                    let connection = group
                        .group
                        .member_mut(member_id)
                        .expect("group and caller legs are built together")
                        .connection_mut();
                    match drain_one_caller_leg_parts(
                        leg.peer,
                        now,
                        &mut leg.timers,
                        &mut leg.pending,
                        connection,
                        sink,
                    ) {
                        DrainOne::Empty => {}
                        result => return result,
                    }
                }
                DrainOne::Empty
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DrainOne {
    Drained,
    Empty,
    Blocked,
}

fn logical_state(connection: &SrtConnection) -> LogicalCallerState {
    match connection.state() {
        shiguredo_srt::ConnectionState::Connected => LogicalCallerState::Connected,
        shiguredo_srt::ConnectionState::Disconnected => LogicalCallerState::Disconnected,
        shiguredo_srt::ConnectionState::Induction
        | shiguredo_srt::ConnectionState::Conclusion
        | shiguredo_srt::ConnectionState::Listening
        | shiguredo_srt::ConnectionState::Closing => LogicalCallerState::Connecting,
    }
}

impl CallerTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            routes: HashMap::new(),
            round_robin: VecDeque::new(),
            next_logical_caller: 1,
        }
    }

    /// Add one direct caller. Its non-zero SRT Socket ID must be unique among
    /// all physical legs in this shared UDP socket.
    pub fn add_direct(&mut self, leg: CallerLeg) -> Result<LogicalCallerId, shiguredo_srt::Error> {
        let socket_id = self.validate_socket_id(&leg.connection)?;
        let id = self.allocate_logical_caller();
        self.sessions.insert(
            id,
            CallerSession::Direct(Box::new(CallerLegState {
                peer: leg.peer,
                connection: leg.connection,
                timers: ManualTimerStore::new(),
                pending: VecDeque::new(),
            })),
        );
        self.routes.insert(socket_id, CallerRoute::Direct(id));
        self.round_robin.push_back(id);
        Ok(id)
    }

    /// Add one logical Broadcast or Backup caller. Each member needs a
    /// distinct non-zero SRT Socket ID, even when every member shares the same
    /// UDP four-tuple; Socket IDs are the SRT-layer demultiplexing key.
    pub fn add_group(
        &mut self,
        group_id: u32,
        mode: shiguredo_srt::GroupMode,
        legs: impl IntoIterator<Item = CallerGroupLeg>,
    ) -> Result<LogicalCallerId, shiguredo_srt::Error> {
        let mut group = shiguredo_srt::SrtGroup::new(group_id, mode)?;
        let mut caller_legs = HashMap::new();
        let mut socket_ids = HashSet::new();
        let mut leg_order = Vec::new();
        for leg in legs {
            let socket_id = self.validate_socket_id(&leg.connection)?;
            if !socket_ids.insert(socket_id) {
                return Err(shiguredo_srt::Error::with_reason(
                    shiguredo_srt::ErrorKind::InvalidState,
                    "shared caller groups require distinct SRT socket IDs",
                ));
            }
            group.add_member(leg.member_id, leg.weight, leg.connection)?;
            if caller_legs
                .insert(
                    leg.member_id,
                    CallerGroupLegState {
                        peer: leg.peer,
                        timers: ManualTimerStore::new(),
                        pending: VecDeque::new(),
                    },
                )
                .is_some()
            {
                return Err(shiguredo_srt::Error::with_reason(
                    shiguredo_srt::ErrorKind::InvalidState,
                    "shared caller groups require distinct member IDs",
                ));
            }
            leg_order.push(leg.member_id);
        }

        if leg_order.is_empty() {
            return Err(shiguredo_srt::Error::with_reason(
                shiguredo_srt::ErrorKind::InvalidState,
                "shared caller groups require at least one member",
            ));
        }

        let id = self.allocate_logical_caller();
        for member in group.members() {
            let socket_id = member.connection().socket_id();
            self.routes.insert(
                socket_id,
                CallerRoute::Group {
                    caller: id,
                    member_id: member.id(),
                },
            );
        }
        self.sessions.insert(
            id,
            CallerSession::Group(Box::new(CallerGroupState {
                group,
                legs: caller_legs,
                leg_order,
                next_leg: 0,
                logical: GroupLogicalCounters::default(),
            })),
        );
        self.round_robin.push_back(id);
        Ok(id)
    }

    fn validate_socket_id(&self, connection: &SrtConnection) -> Result<u32, shiguredo_srt::Error> {
        let socket_id = connection.socket_id();
        if socket_id == 0 || self.routes.contains_key(&socket_id) {
            return Err(shiguredo_srt::Error::with_reason(
                shiguredo_srt::ErrorKind::InvalidState,
                "shared caller sockets require distinct non-zero SRT socket IDs",
            ));
        }
        Ok(socket_id)
    }

    fn allocate_logical_caller(&mut self) -> LogicalCallerId {
        let id = LogicalCallerId(self.next_logical_caller);
        self.next_logical_caller = self.next_logical_caller.wrapping_add(1).max(1);
        id
    }

    /// Feed one datagram received from the application-owned UDP socket.
    /// Unknown Socket IDs and unexpected source addresses are ignored.
    pub fn feed(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
    ) -> Result<bool, shiguredo_srt::Error> {
        let socket_id = shiguredo_srt::peek_destination_socket_id(data)?;
        let Some(route) = self.routes.get(&socket_id) else {
            return Ok(false);
        };
        match *route {
            CallerRoute::Direct(id) => {
                let Some(CallerSession::Direct(leg)) = self.sessions.get_mut(&id) else {
                    return Ok(false);
                };
                if leg.peer != peer {
                    return Ok(false);
                }
                leg.connection.feed_recv_buf(data, now)?;
            }
            CallerRoute::Group { caller, member_id } => {
                let Some(CallerSession::Group(group)) = self.sessions.get_mut(&caller) else {
                    return Ok(false);
                };
                let Some(leg) = group.legs.get(&member_id) else {
                    return Ok(false);
                };
                if leg.peer != peer {
                    return Ok(false);
                }
                group
                    .group
                    .member_mut(member_id)
                    .expect("group and caller legs are built together")
                    .connection_mut()
                    .feed_recv_buf(data, now)?;
            }
        }
        Ok(true)
    }

    /// Drive all protocol timers and collect datagrams for the application to
    /// transmit through its one shared UDP socket.
    pub fn poll_outbound(
        &mut self,
        now: Timestamp,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        out.clear();
        for session in self.sessions.values_mut() {
            match session {
                CallerSession::Direct(leg) => drain_caller_leg(leg, now, out),
                CallerSession::Group(group) => {
                    let (srt_group, legs) = (&mut group.group, &mut group.legs);
                    for (member_id, leg) in legs {
                        let connection = srt_group
                            .member_mut(*member_id)
                            .expect("group and caller legs are built together")
                            .connection_mut();
                        leg.timers.fire_expired(now, connection);
                        while let Some(output) = connection.poll_output() {
                            match output {
                                ConnectionOutput::SendPacket(packet) => {
                                    out.push((leg.peer, packet));
                                }
                                other => leg.timers.apply_output(&other, now),
                            }
                        }
                    }
                }
            }
        }
    }

    /// Fairly drain bounded work from all logical callers. Due timers are
    /// fired for every leg before the budget is shared round-robin across
    /// logical streams, so a busy caller cannot starve another caller's
    /// retransmission or close timer.
    pub fn poll_outbound_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) -> OutputDrainReport {
        out.clear();
        let budget = OutputDrainBudget::new(
            budget.max_actions.max(1),
            budget.max_packets.max(1),
            budget.max_bytes.max(1),
        );
        for session in self.sessions.values_mut() {
            session.fire_timers(now);
        }

        let mut report = OutputDrainReport::default();
        let mut sink = DrainSink {
            budget,
            report: &mut report,
            out,
        };
        let mut idle_turns = 0usize;
        while !self.round_robin.is_empty()
            && idle_turns < self.round_robin.len()
            && sink.report.actions < sink.budget.max_actions
        {
            let id = self.round_robin.pop_front().expect("checked non-empty");
            self.round_robin.push_back(id);
            let Some(session) = self.sessions.get_mut(&id) else {
                continue;
            };
            match session.drain_one(now, &mut sink) {
                DrainOne::Drained => idle_turns = 0,
                DrainOne::Empty | DrainOne::Blocked => idle_turns += 1,
            }
        }
        if report.actions >= budget.max_actions || report.packets >= budget.max_packets {
            report.status = OutputDrainStatus::BudgetExhausted;
        }
        report
    }

    /// Atomically retire a direct caller or every leg of a bonded caller.
    /// Applications normally call [`LogicalCallerMut::disconnect`] first,
    /// then call this after their own close-drain deadline.
    pub fn remove(&mut self, id: LogicalCallerId) -> Option<RemovedLogicalCaller> {
        let session = self.sessions.remove(&id)?;
        self.routes.retain(|_, route| match route {
            CallerRoute::Direct(caller) => *caller != id,
            CallerRoute::Group { caller, .. } => *caller != id,
        });
        self.round_robin.retain(|caller| *caller != id);
        Some(match session {
            CallerSession::Direct(leg) => {
                RemovedLogicalCaller::Direct(Box::new(RemovedCallerLeg {
                    peer: leg.peer,
                    connection: leg.connection,
                }))
            }
            CallerSession::Group(mut group) => {
                let legs = std::mem::take(&mut group.legs)
                    .into_iter()
                    .map(|(member_id, leg)| RemovedCallerLeg {
                        peer: leg.peer,
                        connection: group
                            .group
                            .remove_member_connection(member_id)
                            .expect("group and caller legs are built together"),
                    })
                    .collect();
                RemovedLogicalCaller::Group(legs)
            }
        })
    }

    #[must_use]
    pub fn logical_caller(&self, id: &LogicalCallerId) -> Option<LogicalCaller<'_>> {
        self.sessions.contains_key(id).then_some(LogicalCaller {
            table: self,
            id: *id,
        })
    }

    pub fn logical_caller_mut(&mut self, id: &LogicalCallerId) -> Option<LogicalCallerMut<'_>> {
        self.logical_caller(id)?;
        Some(LogicalCallerMut {
            table: self,
            id: *id,
        })
    }

    #[must_use]
    pub fn time_until_next_deadline(&self, now: Timestamp, default_micros: u64) -> u64 {
        let mut deadline = default_micros;
        for session in self.sessions.values() {
            match session {
                CallerSession::Direct(leg) => {
                    deadline = deadline.min(leg.timers.time_until_earliest(now, deadline));
                }
                CallerSession::Group(group) => {
                    for leg in group.legs.values() {
                        deadline = deadline.min(leg.timers.time_until_earliest(now, deadline));
                    }
                }
            }
        }
        deadline
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

impl Default for CallerTable {
    fn default() -> Self {
        Self::new()
    }
}

fn drain_caller_leg(
    leg: &mut CallerLegState,
    now: Timestamp,
    out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
) {
    leg.timers.fire_expired(now, &mut leg.connection);
    while let Some(output) = leg.connection.poll_output() {
        match output {
            ConnectionOutput::SendPacket(packet) => out.push((leg.peer, packet)),
            other => leg.timers.apply_output(&other, now),
        }
    }
}

fn drain_one_caller_leg(
    leg: &mut CallerLegState,
    now: Timestamp,
    sink: &mut DrainSink,
) -> DrainOne {
    drain_one_caller_leg_parts(
        leg.peer,
        now,
        &mut leg.timers,
        &mut leg.pending,
        &mut leg.connection,
        sink,
    )
}

fn drain_one_caller_leg_parts(
    peer: std::net::SocketAddr,
    now: Timestamp,
    timers: &mut ManualTimerStore,
    pending: &mut VecDeque<ConnectionOutput>,
    connection: &mut SrtConnection,
    sink: &mut DrainSink,
) -> DrainOne {
    let Some(output) = pending.pop_front().or_else(|| connection.poll_output()) else {
        return DrainOne::Empty;
    };
    if sink.report.actions >= sink.budget.max_actions {
        pending.push_front(output);
        return DrainOne::Blocked;
    }
    match output {
        ConnectionOutput::SendPacket(packet) => {
            let exceeds_packets = sink.report.packets >= sink.budget.max_packets;
            let exceeds_bytes = sink.report.packets > 0
                && sink.report.bytes.saturating_add(packet.len()) > sink.budget.max_bytes;
            if exceeds_packets || exceeds_bytes {
                pending.push_front(ConnectionOutput::SendPacket(packet));
                return DrainOne::Blocked;
            }
            sink.report.actions += 1;
            sink.report.packets += 1;
            sink.report.bytes = sink.report.bytes.saturating_add(packet.len());
            sink.out.push((peer, packet));
        }
        other => {
            sink.report.actions += 1;
            timers.apply_output(&other, now);
        }
    }
    DrainOne::Drained
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

    fn finish_conclusion(
        table: &mut PeerTable,
        peer: std::net::SocketAddr,
        caller: &mut SrtConnection,
        conclusion: &[u8],
        options: &AdmissionOptions,
        telemetry: &IngressTelemetry,
    ) {
        assert_eq!(
            table.admit(
                peer,
                conclusion,
                Timestamp::from_micros(2),
                options,
                0,
                1,
                telemetry,
            ),
            Admit::Fed
        );
        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(2), &mut outbound);
        for (outbound_peer, packet) in outbound {
            if outbound_peer == peer {
                caller
                    .feed_recv_buf(&packet, Timestamp::from_micros(3))
                    .expect("conclusion response");
            }
        }
    }

    #[test]
    fn bonded_inputs_require_explicit_listener_opt_in() {
        let peer = "127.0.0.1:10000".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let (_, conclusion) = prepare_conclusion_with_options(
            &mut table,
            peer,
            ConnectionOptions {
                socket_id: 0x1111,
                stream_id: Some("publish:bonded".to_string()),
                group_extension: Some(shiguredo_srt::GroupExtensionData {
                    group_id: shiguredo_srt::SRTGROUP_MASK | 42,
                    group_type: shiguredo_srt::GroupType::Broadcast,
                    flags: 0,
                    weight: 1,
                }),
                ..ConnectionOptions::default()
            },
            &options,
            &telemetry,
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
            Admit::Rejected
        );
        assert!(table.bonded_stats().is_empty());
    }

    #[test]
    fn opted_in_bonded_inputs_share_one_logical_event_stream_and_telemetry() {
        let first = "127.0.0.1:10000".parse().expect("address");
        let second = "127.0.0.1:10001".parse().expect("address");
        let mut options = AdmissionOptions::basic(0x2222, 0, true);
        options.bonded_inputs = BondedInputPolicy::Accept;
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let group_id = shiguredo_srt::SRTGROUP_MASK | 42;
        let caller_options = |socket_id, weight| ConnectionOptions {
            socket_id,
            initial_seq: Some(1234),
            stream_id: Some("publish:bonded".to_string()),
            group_extension: Some(shiguredo_srt::GroupExtensionData {
                group_id,
                group_type: shiguredo_srt::GroupType::Broadcast,
                flags: 0,
                weight,
            }),
            ..ConnectionOptions::default()
        };
        let (mut first_caller, first_conclusion) = prepare_conclusion_with_options(
            &mut table,
            first,
            caller_options(0x1111, 10),
            &options,
            &telemetry,
        );
        finish_conclusion(
            &mut table,
            first,
            &mut first_caller,
            &first_conclusion,
            &options,
            &telemetry,
        );
        let (mut second_caller, second_conclusion) = prepare_conclusion_with_options(
            &mut table,
            second,
            caller_options(0x2222, 20),
            &options,
            &telemetry,
        );
        finish_conclusion(
            &mut table,
            second,
            &mut second_caller,
            &second_conclusion,
            &options,
            &telemetry,
        );

        let mut events = Vec::new();
        table.poll_events(&mut events);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].representative_peer, first);
        assert!(matches!(events[0].event, ConnectionEvent::Connected));
        let logical_peer = events[0].logical_peer;
        assert_eq!(
            table
                .logical_peer(&logical_peer)
                .expect("logical group exists")
                .stream_id(),
            Some("publish:bonded")
        );
        assert_eq!(table.bonded_stats()[0].connection.legs.len(), 2);

        {
            let mut group = table
                .logical_peer_mut(&logical_peer)
                .expect("logical group exists");
            assert!(group.can_send());
            assert_eq!(
                group
                    .send(b"one logical reply", Timestamp::from_micros(3))
                    .expect("group sends on every active Broadcast leg"),
                2
            );
            let group_stats = group.stats().expect("group stats remain available");
            assert!(matches!(
                group_stats,
                LogicalPeerStats::Group(stats)
                    if stats.aggregate.logical_payloads_sent == 1
                        && stats.aggregate.logical_payload_bytes_sent == 17
                        && stats.legs.len() == 2
            ));
        }

        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(3), &mut outbound);
        assert_eq!(
            outbound
                .iter()
                .filter(|(_, packet)| matches!(
                    shiguredo_srt::SrtPacket::decode(packet),
                    Ok(shiguredo_srt::SrtPacket::Data(_))
                ))
                .count(),
            2,
            "one Broadcast logical send is emitted on both physical legs"
        );

        first_caller
            .send(b"one logical payload", Timestamp::from_micros(4))
            .expect("first caller sends");
        second_caller
            .send(b"one logical payload", Timestamp::from_micros(4))
            .expect("second caller sends");
        assert_eq!(
            table.admit(
                first,
                &next_packet(&mut first_caller),
                Timestamp::from_micros(5),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );
        assert_eq!(
            table.admit(
                second,
                &next_packet(&mut second_caller),
                Timestamp::from_micros(5),
                &options,
                0,
                1,
                &telemetry,
            ),
            Admit::Fed
        );

        table.poll_events(&mut events);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].representative_peer, first);
        assert!(matches!(
            &events[0].event,
            ConnectionEvent::DataReceived { payload, .. } if payload == b"one logical payload"
        ));
        let stats = table.bonded_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].connection.aggregate.logical_payloads_received, 1);
        assert_eq!(
            stats[0].connection.aggregate.logical_payload_bytes_received,
            19
        );
        assert_eq!(stats[0].connection.legs.len(), 2);
        assert_eq!(stats[0].connection.aggregate.wire_packets_received, 2);

        table
            .logical_peer_mut(&logical_peer)
            .expect("logical group remains until normal teardown")
            .disconnect(Timestamp::from_micros(6));
        table.poll_outbound(Timestamp::from_micros(6), &mut outbound);
        assert_eq!(
            outbound
                .iter()
                .filter(|(_, packet)| matches!(shiguredo_srt::SrtPacket::decode(packet), Ok(shiguredo_srt::SrtPacket::Control(control)) if control.control_type == shiguredo_srt::ControlType::Shutdown))
                .count(),
            2,
            "an orderly logical close shuts down every group leg"
        );
    }

    #[test]
    fn bonded_inputs_reject_a_conflicting_group_mode() {
        let first = "127.0.0.1:10000".parse().expect("address");
        let second = "127.0.0.1:10001".parse().expect("address");
        let mut options = AdmissionOptions::basic(0x2222, 0, true);
        options.bonded_inputs = BondedInputPolicy::Accept;
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let group_id = shiguredo_srt::SRTGROUP_MASK | 42;
        let caller_options = |socket_id, group_type| ConnectionOptions {
            socket_id,
            stream_id: Some("publish:bonded".to_string()),
            group_extension: Some(shiguredo_srt::GroupExtensionData {
                group_id,
                group_type,
                flags: 0,
                weight: 1,
            }),
            ..ConnectionOptions::default()
        };
        let (mut first_caller, first_conclusion) = prepare_conclusion_with_options(
            &mut table,
            first,
            caller_options(0x1111, shiguredo_srt::GroupType::Broadcast),
            &options,
            &telemetry,
        );
        finish_conclusion(
            &mut table,
            first,
            &mut first_caller,
            &first_conclusion,
            &options,
            &telemetry,
        );
        let (_, second_conclusion) = prepare_conclusion_with_options(
            &mut table,
            second,
            caller_options(0x2222, shiguredo_srt::GroupType::Backup),
            &options,
            &telemetry,
        );

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
            Admit::Rejected
        );
        assert_eq!(
            table.bonded_stats()[0].connection.mode,
            shiguredo_srt::GroupMode::Broadcast
        );
        assert_eq!(table.bonded_stats()[0].connection.legs.len(), 1);
    }

    #[test]
    fn logical_peer_api_has_the_same_steady_state_for_direct_inputs() {
        let peer = "127.0.0.1:10000".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let (mut caller, conclusion) = prepare_conclusion_with_options(
            &mut table,
            peer,
            ConnectionOptions {
                stream_id: Some("publish:direct".to_string()),
                ..ConnectionOptions::default()
            },
            &options,
            &telemetry,
        );
        finish_conclusion(
            &mut table,
            peer,
            &mut caller,
            &conclusion,
            &options,
            &telemetry,
        );

        let mut events = Vec::new();
        table.poll_events(&mut events);
        let logical_peer = events
            .iter()
            .find(|event| {
                event.representative_peer == peer
                    && matches!(event.event, ConnectionEvent::Connected)
            })
            .expect("direct connected event")
            .logical_peer;
        {
            let mut direct = table
                .logical_peer_mut(&logical_peer)
                .expect("direct logical peer exists");
            assert_eq!(direct.stream_id(), Some("publish:direct"));
            assert!(direct.can_send());
            assert_eq!(
                direct
                    .send(b"direct reply", Timestamp::from_micros(3))
                    .expect("direct logical send"),
                1
            );
            assert!(matches!(direct.stats(), Some(LogicalPeerStats::Direct(_))));
            direct.disconnect(Timestamp::from_micros(4));
        }

        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(4), &mut outbound);
        assert!(outbound.iter().any(|(_, packet)| matches!(
            shiguredo_srt::SrtPacket::decode(packet),
            Ok(shiguredo_srt::SrtPacket::Data(_))
        )));
        assert!(outbound.iter().any(|(_, packet)| matches!(
            shiguredo_srt::SrtPacket::decode(packet),
            Ok(shiguredo_srt::SrtPacket::Control(control))
                if control.control_type == shiguredo_srt::ControlType::Shutdown
        )));
    }

    fn pump_caller_table(
        callers: &mut CallerTable,
        listeners: &mut PeerTable,
        options: &AdmissionOptions,
        telemetry: &IngressTelemetry,
        now: Timestamp,
    ) {
        let mut outbound = Vec::new();
        callers.poll_outbound(now, &mut outbound);
        for (peer, packet) in outbound.drain(..) {
            assert_eq!(
                listeners.admit(peer, &packet, now, options, 0, 1, telemetry),
                Admit::Fed
            );
        }
        listeners.poll_outbound(now, &mut outbound);
        for (peer, packet) in outbound {
            assert!(
                callers
                    .feed(peer, &packet, now)
                    .expect("caller packet decodes")
            );
        }
    }

    fn caller_connection(options: ConnectionOptions) -> SrtConnection {
        let mut connection = SrtConnection::new_caller(options);
        connection
            .connect(Timestamp::default())
            .expect("caller starts handshake");
        connection
    }

    #[test]
    fn caller_table_has_one_logical_api_for_direct_and_broadcast_callers() {
        let direct_peer = "127.0.0.1:11000".parse().expect("address");
        let first_peer = "127.0.0.1:11001".parse().expect("address");
        let second_peer = first_peer;
        let group_id = shiguredo_srt::SRTGROUP_MASK | 55;
        let mut callers = CallerTable::new();
        let direct = callers
            .add_direct(CallerLeg::new(
                direct_peer,
                caller_connection(ConnectionOptions {
                    socket_id: 101,
                    ..ConnectionOptions::default()
                }),
            ))
            .expect("direct caller is admitted");
        let grouped = callers
            .add_group(
                group_id,
                shiguredo_srt::GroupMode::Broadcast,
                [
                    CallerGroupLeg::new(
                        1,
                        1,
                        first_peer,
                        caller_connection(ConnectionOptions {
                            socket_id: 102,
                            initial_seq: Some(1234),
                            group_extension: Some(shiguredo_srt::GroupExtensionData {
                                group_id,
                                group_type: shiguredo_srt::GroupType::Broadcast,
                                flags: 0,
                                weight: 1,
                            }),
                            ..ConnectionOptions::default()
                        }),
                    ),
                    CallerGroupLeg::new(
                        2,
                        1,
                        second_peer,
                        caller_connection(ConnectionOptions {
                            socket_id: 103,
                            initial_seq: Some(1234),
                            group_extension: Some(shiguredo_srt::GroupExtensionData {
                                group_id,
                                group_type: shiguredo_srt::GroupType::Broadcast,
                                flags: 0,
                                weight: 1,
                            }),
                            ..ConnectionOptions::default()
                        }),
                    ),
                ],
            )
            .expect("grouped caller is admitted");

        let mut listeners = PeerTable::new();
        let mut options = AdmissionOptions::basic(900, 0, true);
        options.bonded_inputs = BondedInputPolicy::Accept;
        let telemetry = IngressTelemetry::new();
        for round in 0..8 {
            pump_caller_table(
                &mut callers,
                &mut listeners,
                &options,
                &telemetry,
                Timestamp::from_micros(round * 10),
            );
        }
        let leg_count = listeners.len();
        let _ = listeners.admit(
            first_peer,
            &induction(102),
            Timestamp::from_micros(90),
            &options,
            0,
            1,
            &telemetry,
        );
        assert_eq!(
            listeners.len(),
            leg_count,
            "a group-leg induction retry must not allocate a rogue direct peer"
        );

        for id in [direct, grouped] {
            let mut caller = callers
                .logical_caller_mut(&id)
                .expect("logical caller exists");
            assert_eq!(caller.state(), Some(LogicalCallerState::Connected));
            assert!(caller.can_send());
        }
        assert_eq!(
            callers
                .logical_caller_mut(&direct)
                .expect("direct caller exists")
                .send(b"direct", Timestamp::from_micros(100))
                .expect("direct logical send"),
            1
        );
        assert_eq!(
            callers
                .logical_caller_mut(&grouped)
                .expect("grouped caller exists")
                .send(b"broadcast", Timestamp::from_micros(100))
                .expect("broadcast logical send"),
            2
        );

        let mut outbound = Vec::new();
        callers.poll_outbound(Timestamp::from_micros(100), &mut outbound);
        assert_eq!(
            outbound
                .iter()
                .filter(|(_, packet)| matches!(
                    shiguredo_srt::SrtPacket::decode(packet),
                    Ok(shiguredo_srt::SrtPacket::Data(_))
                ))
                .count(),
            3,
            "one direct and one Broadcast logical send use three physical legs"
        );
        assert!(matches!(
            callers
                .logical_caller(&grouped)
                .and_then(|caller| caller.stats()),
            Some(LogicalCallerStats::Group(stats))
                if stats.aggregate.logical_payloads_sent == 1 && stats.legs.len() == 2
        ));

        let mut newly_connected = Vec::new();
        listeners.drain_events(Duration::from_millis(1), &mut newly_connected);
        assert_eq!(newly_connected.len(), 2, "one direct and one group session");
        assert!(
            listeners
                .groups
                .values()
                .all(|group| group.stream_deadline.is_some()),
            "a grouped Connected event starts the logical stream clock"
        );
        let check_now = Instant::now() + Duration::from_secs(1);
        assert!(
            listeners.all_terminal(
                check_now,
                check_now + Duration::from_secs(10),
                Duration::ZERO,
            ),
            "bonded physical legs must not keep their finished logical group alive"
        );
        assert!(matches!(
            callers.remove(direct),
            Some(RemovedLogicalCaller::Direct(_))
        ));
        assert!(matches!(
            callers.remove(grouped),
            Some(RemovedLogicalCaller::Group(legs)) if legs.len() == 2
        ));
        assert!(callers.is_empty());
        for connected in newly_connected {
            assert!(listeners.remove(connected.logical_peer).is_some());
        }
        assert!(listeners.is_empty());
        assert_eq!(listeners.established_count(), 0);
        assert_eq!(listeners.half_open_count(), 0);
    }

    #[test]
    fn shared_four_tuple_demultiplexes_independent_srt_socket_ids() {
        let peer = "127.0.0.1:10000".parse().expect("address");
        let options = AdmissionOptions::basic(0x2222, 0, true);
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();

        let (mut first, first_conclusion) = prepare_conclusion_with_options(
            &mut table,
            peer,
            ConnectionOptions {
                socket_id: 0x1001,
                stream_id: Some("publish:first".to_owned()),
                ..ConnectionOptions::default()
            },
            &options,
            &telemetry,
        );
        finish_conclusion(
            &mut table,
            peer,
            &mut first,
            &first_conclusion,
            &options,
            &telemetry,
        );
        let (mut second, second_conclusion) = prepare_conclusion_with_options(
            &mut table,
            peer,
            ConnectionOptions {
                socket_id: 0x1002,
                stream_id: Some("publish:second".to_owned()),
                ..ConnectionOptions::default()
            },
            &options,
            &telemetry,
        );
        finish_conclusion(
            &mut table,
            peer,
            &mut second,
            &second_conclusion,
            &options,
            &telemetry,
        );

        first
            .send(b"first", Timestamp::from_micros(4))
            .expect("first caller sends");
        second
            .send(b"second", Timestamp::from_micros(4))
            .expect("second caller sends");
        for caller in [&mut first, &mut second] {
            assert_eq!(
                table.admit(
                    peer,
                    &next_packet(caller),
                    Timestamp::from_micros(5),
                    &options,
                    0,
                    1,
                    &telemetry,
                ),
                Admit::Fed
            );
        }

        let mut events = Vec::new();
        table.poll_events(&mut events);
        let payloads = events
            .into_iter()
            .filter_map(|event| match event.event {
                ConnectionEvent::DataReceived { payload, .. } => Some(payload),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(payloads, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn bonded_admission_keeps_matching_legs_in_one_logical_group(
            group_suffix in 1_u32..0x000f_ffff,
            initial_seq in any::<u32>(),
        ) {
            let first = "127.0.0.1:10000".parse().expect("address");
            let second = "127.0.0.1:10001".parse().expect("address");
            let mut options = AdmissionOptions::basic(0x2222, 0, true);
            options.bonded_inputs = BondedInputPolicy::Accept;
            let telemetry = IngressTelemetry::new();
            let mut table = PeerTable::new();
            let group_id = shiguredo_srt::SRTGROUP_MASK | group_suffix;
            let caller_options = |socket_id| ConnectionOptions {
                socket_id,
                initial_seq: Some(initial_seq),
                stream_id: Some("publish:property-group".to_string()),
                group_extension: Some(shiguredo_srt::GroupExtensionData {
                    group_id,
                    group_type: shiguredo_srt::GroupType::Broadcast,
                    flags: 0,
                    weight: 1,
                }),
                ..ConnectionOptions::default()
            };
            let (mut first_caller, first_conclusion) = prepare_conclusion_with_options(
                &mut table, first, caller_options(0x1111), &options, &telemetry,
            );
            finish_conclusion(
                &mut table, first, &mut first_caller, &first_conclusion, &options, &telemetry,
            );
            let (mut second_caller, second_conclusion) = prepare_conclusion_with_options(
                &mut table, second, caller_options(0x2222), &options, &telemetry,
            );
            finish_conclusion(
                &mut table, second, &mut second_caller, &second_conclusion, &options, &telemetry,
            );

            let mut events = Vec::new();
            table.poll_events(&mut events);
            prop_assert_eq!(events.len(), 1);
            prop_assert_eq!(events[0].representative_peer, first);
            prop_assert!(matches!(events[0].event, ConnectionEvent::Connected));
            let stats = table.bonded_stats();
            prop_assert_eq!(stats.len(), 1);
            prop_assert_eq!(stats[0].connection.group_id, group_id);
            prop_assert_eq!(stats[0].connection.legs.len(), 2);
        }
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

    /// The compat type restated the richer validators' rules instead of
    /// calling them, and had already fallen behind: the three cross-field
    /// peer bounds were enforced by `AdmissionConfig::validate` and not
    /// here, so this config accepted limits the real one rejects.
    #[test]
    fn stack_config_enforces_the_same_cross_field_bounds_as_admission_config() {
        for (label, mutate) in [
            (
                "max_half_open_peers",
                (|limits: &mut PeerTableConfig| {
                    limits.max_half_open_peers = limits.max_peers + 1;
                }) as fn(&mut PeerTableConfig),
            ),
            ("max_established_peers", |limits| {
                limits.max_established_peers = limits.max_peers + 1;
            }),
            ("max_peers_per_ip", |limits| {
                limits.max_peers_per_ip = limits.max_peers + 1;
            }),
        ] {
            let mut config = SrtStackConfig::default();
            mutate(&mut config.admission);
            let error = config
                .validate()
                .expect_err("a sub-limit above max_peers must be rejected");
            assert!(
                error.to_string().contains(label),
                "{label}: error should name the offending field, got {error}"
            );
        }
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
// Bonded/group caller transport
// ---------------------------------------------------------------------------

/// One outbound leg supplied when constructing a [`GroupConn`]. The socket
/// must be connected and nonblocking; [`GroupConn::caller`] constructs such
/// legs from [`CallerConfig`] when an application does not need custom I/O.
pub struct GroupConnectionLeg {
    pub member_id: u32,
    pub weight: u16,
    pub connection: SrtConnection,
    pub socket: std::net::UdpSocket,
}

/// Configuration for one outbound leg of a bonded caller.
#[derive(Clone, Debug)]
pub struct GroupCallerLeg {
    pub member_id: u32,
    pub weight: u16,
    pub caller: CallerConfig,
}

impl GroupCallerLeg {
    #[must_use]
    pub fn new(member_id: u32, weight: u16, caller: CallerConfig) -> Self {
        Self {
            member_id,
            weight,
            caller,
        }
    }
}

/// Failure while constructing a bonded caller.
#[derive(Debug)]
pub enum GroupBuildError {
    Config(ConfigError),
    Io(std::io::Error),
    Protocol(shiguredo_srt::Error),
    InvalidGroupType,
}

impl fmt::Display for GroupBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
            Self::InvalidGroupType => write!(f, "bond group type must be Broadcast or Backup"),
        }
    }
}

impl std::error::Error for GroupBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::InvalidGroupType => None,
        }
    }
}

impl From<ConfigError> for GroupBuildError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<std::io::Error> for GroupBuildError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<shiguredo_srt::Error> for GroupBuildError {
    fn from(value: shiguredo_srt::Error) -> Self {
        Self::Protocol(value)
    }
}

struct GroupLegIo {
    member_id: u32,
    socket: std::net::UdpSocket,
    timers: ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
}

/// Per-leg I/O work completed by one [`GroupConn::drive`] call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupLegDriveReport {
    pub member_id: u32,
    pub received_datagrams: usize,
    pub output: OutputDrainReport,
}

/// Work completed by one bounded bonded-transport maintenance call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupDriveReport {
    pub legs: Vec<GroupLegDriveReport>,
}

impl GroupDriveReport {
    #[must_use]
    pub fn received_datagrams(&self) -> usize {
        self.legs.iter().map(|leg| leg.received_datagrams).sum()
    }
}

/// Snapshot for one physical bonded leg. Connection counters retain their
/// normal single-SRT meaning and are never deduplicated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupLegStats {
    pub member_id: u32,
    pub weight: u16,
    pub state: shiguredo_srt::GroupMemberState,
    pub local_addr: Option<std::net::SocketAddr>,
    pub peer_addr: Option<std::net::SocketAddr>,
    pub connection: shiguredo_srt::ConnectionStats,
}

/// Group-level telemetry with explicitly separate logical and wire views.
///
/// `logical_*` counts one payload once at the group API boundary. `wire_*`
/// sums all legs, so Broadcast correctly reports duplicated media delivery
/// and retransmissions rather than disguising their network cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupAggregateStats {
    pub active_legs: usize,
    pub standby_legs: usize,
    pub pending_legs: usize,
    pub unstable_legs: usize,
    pub broken_legs: usize,
    pub logical_payloads_sent: u64,
    pub logical_payload_bytes_sent: u64,
    pub logical_payloads_received: u64,
    pub logical_payload_bytes_received: u64,
    pub wire_unique_packets_sent: u64,
    pub wire_packets_sent: u64,
    pub wire_payload_bytes_sent: u64,
    pub wire_srt_bytes_sent: u64,
    pub wire_packets_retransmitted: u64,
    /// Sum of sender-side loss occurrences reported by peers through NAKs.
    pub wire_sender_packets_lost: u64,
    pub wire_packets_received: u64,
    pub wire_unique_packets_received: u64,
    pub wire_srt_bytes_received: u64,
    /// Sum of receiver-side missing sequence numbers detected on all legs.
    pub wire_receiver_packets_lost: u64,
    pub wire_packets_undecryptable: u64,
}

/// Complete bonded-connection telemetry: one snapshot per leg plus a clearly
/// named aggregate that is safe for dashboards and alerting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupConnectionStats {
    pub group_id: u32,
    pub mode: shiguredo_srt::GroupMode,
    pub aggregate: GroupAggregateStats,
    pub legs: Vec<GroupLegStats>,
}

/// Ingress-facing bonded telemetry. The logical key disambiguates publishers
/// that happen to reuse a wire group ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundGroupStats {
    pub key: srt_lifecycle::LogicalGroupKey,
    /// Whether the logical group completed an SRT connection at least once.
    pub ever_connected: bool,
    /// Whether every leg ended unexpectedly after the group had connected.
    pub torn_down: bool,
    pub connection: GroupConnectionStats,
}

#[derive(Clone, Copy, Default)]
struct GroupLogicalCounters {
    payloads_sent: u64,
    payload_bytes_sent: u64,
    payloads_received: u64,
    payload_bytes_received: u64,
}

fn group_connection_stats(
    group: &shiguredo_srt::SrtGroup,
    logical: GroupLogicalCounters,
    mut addresses: impl FnMut(u32) -> (Option<std::net::SocketAddr>, Option<std::net::SocketAddr>),
) -> GroupConnectionStats {
    let mut aggregate = GroupAggregateStats {
        logical_payloads_sent: logical.payloads_sent,
        logical_payload_bytes_sent: logical.payload_bytes_sent,
        logical_payloads_received: logical.payloads_received,
        logical_payload_bytes_received: logical.payload_bytes_received,
        ..GroupAggregateStats::default()
    };
    let mut legs = Vec::with_capacity(group.members().len());
    for member in group.members() {
        match member.state() {
            shiguredo_srt::GroupMemberState::Active => aggregate.active_legs += 1,
            shiguredo_srt::GroupMemberState::Standby => aggregate.standby_legs += 1,
            shiguredo_srt::GroupMemberState::Pending => aggregate.pending_legs += 1,
            shiguredo_srt::GroupMemberState::Unstable => aggregate.unstable_legs += 1,
            shiguredo_srt::GroupMemberState::Broken => aggregate.broken_legs += 1,
        }
        let connection = member.connection().stats();
        if let Some(sender) = connection.sender {
            aggregate.wire_unique_packets_sent = aggregate
                .wire_unique_packets_sent
                .saturating_add(sender.total_sent);
            aggregate.wire_packets_sent = aggregate
                .wire_packets_sent
                .saturating_add(sender.total_data_packets_sent);
            aggregate.wire_payload_bytes_sent = aggregate
                .wire_payload_bytes_sent
                .saturating_add(sender.total_bytes_sent);
            aggregate.wire_srt_bytes_sent = aggregate
                .wire_srt_bytes_sent
                .saturating_add(sender.total_srt_bytes_sent);
            aggregate.wire_packets_retransmitted = aggregate
                .wire_packets_retransmitted
                .saturating_add(sender.total_retransmits);
            aggregate.wire_sender_packets_lost = aggregate
                .wire_sender_packets_lost
                .saturating_add(sender.total_lost);
        }
        if let Some(receiver) = connection.receiver {
            aggregate.wire_packets_received = aggregate
                .wire_packets_received
                .saturating_add(receiver.total_data_packets_received);
            aggregate.wire_unique_packets_received = aggregate
                .wire_unique_packets_received
                .saturating_add(receiver.total_received);
            aggregate.wire_srt_bytes_received = aggregate
                .wire_srt_bytes_received
                .saturating_add(receiver.total_srt_bytes_received);
            aggregate.wire_receiver_packets_lost = aggregate
                .wire_receiver_packets_lost
                .saturating_add(receiver.total_lost);
            aggregate.wire_packets_undecryptable = aggregate
                .wire_packets_undecryptable
                .saturating_add(receiver.total_undecryptable);
        }
        let (local_addr, peer_addr) = addresses(member.id());
        legs.push(GroupLegStats {
            member_id: member.id(),
            weight: member.weight(),
            state: member.state(),
            local_addr,
            peer_addr,
            connection,
        });
    }
    GroupConnectionStats {
        group_id: group.group_id(),
        mode: group.mode(),
        aggregate,
        legs,
    }
}

/// Runtime-neutral multi-socket driver for an SRT Broadcast or Backup group.
///
/// This is intentionally synchronous and nonblocking. Tokio, smol, mio, and
/// other runtimes can register the exposed leg sockets in their own reactors,
/// then call [`Self::drive`] when any leg is readable or a timer is due. That
/// keeps group semantics in one implementation instead of copying subtly
/// different versions into every runtime adapter.
pub struct GroupConn {
    group: shiguredo_srt::SrtGroup,
    legs: Vec<GroupLegIo>,
    logical_payloads_sent: u64,
    logical_payload_bytes_sent: u64,
    logical_payloads_received: u64,
    logical_payload_bytes_received: u64,
}

impl GroupConn {
    /// Build a group around caller configurations, binding one connected UDP
    /// socket and initiating one SRT handshake for every supplied leg.
    pub fn caller(
        group: GroupConfig,
        legs: impl IntoIterator<Item = GroupCallerLeg>,
        runtime: RuntimeFlavor,
        now: Timestamp,
    ) -> Result<Self, GroupBuildError> {
        let mut raw_legs = Vec::new();
        for leg in legs {
            let mut caller = leg.caller;
            caller.session.set_group(Some(GroupConfig {
                group_id: group.group_id,
                group_type: group.group_type,
                flags: group.flags,
                weight: leg.weight,
            }));
            let prepared = caller.prepare(runtime)?;
            raw_legs.push(GroupConnectionLeg {
                member_id: leg.member_id,
                weight: leg.weight,
                connection: prepared.connection(now)?,
                socket: prepared.bind_socket()?,
            });
        }
        let mode = shiguredo_srt::GroupMode::from_group_type(group.group_type)
            .ok_or(GroupBuildError::InvalidGroupType)?;
        Ok(Self::new(group.group_id, mode, raw_legs)?)
    }

    /// Assemble a group from application-owned protocol cores and connected,
    /// nonblocking sockets. This is the integration point for custom runtimes
    /// and for applications that own their own socket provisioning.
    pub fn new(
        group_id: u32,
        mode: shiguredo_srt::GroupMode,
        legs: impl IntoIterator<Item = GroupConnectionLeg>,
    ) -> Result<Self, shiguredo_srt::Error> {
        let mut group = shiguredo_srt::SrtGroup::new(group_id, mode)?;
        let mut io_legs = Vec::new();
        for leg in legs {
            group.add_member(leg.member_id, leg.weight, leg.connection)?;
            io_legs.push(GroupLegIo {
                member_id: leg.member_id,
                socket: leg.socket,
                timers: ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
            });
        }
        Ok(Self {
            group,
            legs: io_legs,
            logical_payloads_sent: 0,
            logical_payload_bytes_sent: 0,
            logical_payloads_received: 0,
            logical_payload_bytes_received: 0,
        })
    }

    #[must_use]
    pub fn group(&self) -> &shiguredo_srt::SrtGroup {
        &self.group
    }

    /// Physical sockets to register with an application's runtime reactor.
    /// Call [`Self::drive`] after readability or at the next timer deadline.
    pub fn leg_sockets(&self) -> impl ExactSizeIterator<Item = (u32, &std::net::UdpSocket)> {
        self.legs.iter().map(|leg| (leg.member_id, &leg.socket))
    }

    /// Microseconds until the earliest leg timer, falling back to
    /// `default_micros` when no timer is armed.
    #[must_use]
    pub fn time_until_next_deadline(&self, now: Timestamp, default_micros: u64) -> u64 {
        self.legs
            .iter()
            .map(|leg| leg.timers.time_until_earliest(now, default_micros))
            .min()
            .unwrap_or(default_micros)
    }

    /// Send one logical payload according to the group's Broadcast or Backup
    /// policy. The return value is the number of physical legs selected.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, shiguredo_srt::Error> {
        let legs = self.group.send(payload, now)?;
        self.logical_payloads_sent = self.logical_payloads_sent.saturating_add(1);
        self.logical_payload_bytes_sent = self
            .logical_payload_bytes_sent
            .saturating_add(payload.len() as u64);
        Ok(legs)
    }

    /// Whether the next logical payload can be accepted without weakening the
    /// selected Broadcast or Backup delivery contract.
    pub fn can_send(&mut self) -> bool {
        self.group.can_send()
    }

    /// Start an orderly close of every physical group leg.
    pub fn disconnect(&mut self, now: Timestamp) {
        self.group.disconnect(now);
    }

    /// Return the next deduplicated, sequence-aligned group payload.
    pub fn poll_data(&mut self, now: Timestamp) -> Option<shiguredo_srt::GroupPacket> {
        let packet = self.group.poll_data(now)?;
        self.logical_payloads_received = self.logical_payloads_received.saturating_add(1);
        self.logical_payload_bytes_received = self
            .logical_payload_bytes_received
            .saturating_add(packet.payload.len() as u64);
        Some(packet)
    }

    /// Drive timers, nonblocking UDP input, and a bounded output pump for
    /// every leg once. A readable leg may contain up to 64 datagrams per call
    /// to avoid one busy path starving the rest of the group.
    pub fn drive(
        &mut self,
        now: Timestamp,
        output_budget: OutputDrainBudget,
    ) -> std::io::Result<GroupDriveReport> {
        let mut report = GroupDriveReport {
            legs: Vec::with_capacity(self.legs.len()),
        };
        let (group, legs) = (&mut self.group, &mut self.legs);
        for leg in legs {
            let member = group
                .member_mut(leg.member_id)
                .expect("group and I/O legs are built together");
            let conn = member.connection_mut();
            leg.timers.fire_expired(now, conn);

            let mut received_datagrams = 0;
            let mut buffer = [0_u8; 65_536];
            for _ in 0..64 {
                match leg.socket.recv(&mut buffer) {
                    Ok(size) => {
                        received_datagrams += 1;
                        conn.feed_recv_buf(&buffer[..size], now).map_err(|error| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                        })?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }

            let output = drain_group_leg_outputs(conn, leg, now, output_budget)?;
            report.legs.push(GroupLegDriveReport {
                member_id: leg.member_id,
                received_datagrams,
                output,
            });
        }
        Ok(report)
    }

    /// Snapshot both physical-leg and logical-group telemetry. Do not replace
    /// the per-leg rows with the aggregate: loss, RTT, key failures, and path
    /// health are inherently leg-specific.
    #[must_use]
    pub fn stats(&self) -> GroupConnectionStats {
        group_connection_stats(
            &self.group,
            GroupLogicalCounters {
                payloads_sent: self.logical_payloads_sent,
                payload_bytes_sent: self.logical_payload_bytes_sent,
                payloads_received: self.logical_payloads_received,
                payload_bytes_received: self.logical_payload_bytes_received,
            },
            |member_id| {
                let io = self
                    .legs
                    .iter()
                    .find(|leg| leg.member_id == member_id)
                    .expect("group and I/O legs are built together");
                (io.socket.local_addr().ok(), io.socket.peer_addr().ok())
            },
        )
    }
}

fn drain_group_leg_outputs(
    conn: &mut SrtConnection,
    leg: &mut GroupLegIo,
    now: Timestamp,
    budget: OutputDrainBudget,
) -> std::io::Result<OutputDrainReport> {
    let (mut work, budget_exhausted) = collect_output_work(conn, &mut leg.pending_outputs, budget);
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
            ConnectionOutput::SendPacket(packet) => match leg.socket.send(&packet) {
                Ok(sent) if sent == packet.len() => {
                    report.actions += 1;
                    report.packets += 1;
                    report.bytes += sent;
                }
                Ok(_) => {
                    prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                    leg.pending_outputs
                        .push_front(ConnectionOutput::SendPacket(packet));
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "UDP socket reported a partial datagram send",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                    leg.pending_outputs
                        .push_front(ConnectionOutput::SendPacket(packet));
                    report.status = OutputDrainStatus::Backpressured;
                    return Ok(report);
                }
                Err(error) => {
                    prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                    leg.pending_outputs
                        .push_front(ConnectionOutput::SendPacket(packet));
                    return Err(error);
                }
            },
            timer => {
                leg.timers.apply_output(&timer, now);
                report.actions += 1;
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod group_conn_tests {
    use super::*;

    struct Peer {
        socket: std::net::UdpSocket,
        connection: SrtConnection,
        caller: Option<std::net::SocketAddr>,
    }

    impl Peer {
        fn new() -> Self {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            socket.set_nonblocking(true).expect("peer is nonblocking");
            Self {
                socket,
                connection: SrtConnection::new_listener(shiguredo_srt::ConnectionOptions {
                    tsbpd_delay: 0,
                    ..Default::default()
                }),
                caller: None,
            }
        }

        fn drive(&mut self, now: Timestamp) {
            let mut buffer = [0_u8; 65_536];
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, caller)) => {
                        self.caller = Some(caller);
                        self.connection
                            .feed_recv_buf(&buffer[..size], now)
                            .expect("group packet decodes");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("peer receive failed: {error}"),
                }
            }
            let Some(caller) = self.caller else {
                return;
            };
            while let Some(output) = self.connection.poll_output() {
                if let ConnectionOutput::SendPacket(packet) = output {
                    self.socket
                        .send_to(&packet, caller)
                        .expect("peer sends protocol response");
                }
            }
        }
    }

    #[test]
    fn bonded_egress_drives_every_leg_on_every_runtime_flavor() {
        for runtime in [
            RuntimeFlavor::Mio,
            RuntimeFlavor::Tokio,
            RuntimeFlavor::Smol,
            RuntimeFlavor::Monoio,
            RuntimeFlavor::Glommio,
            RuntimeFlavor::Compio,
        ] {
            let mut first_peer = Peer::new();
            let mut second_peer = Peer::new();
            let group = GroupConfig::new(42, shiguredo_srt::GroupType::Broadcast);
            let mut conn = GroupConn::caller(
                group,
                [
                    GroupCallerLeg::new(
                        1,
                        10,
                        CallerConfig::builder(
                            first_peer.socket.local_addr().expect("first address"),
                        )
                        .build()
                        .expect("first caller config"),
                    ),
                    GroupCallerLeg::new(
                        2,
                        20,
                        CallerConfig::builder(
                            second_peer.socket.local_addr().expect("second address"),
                        )
                        .build()
                        .expect("second caller config"),
                    ),
                ],
                runtime,
                Timestamp::from_micros(0),
            )
            .expect("bonded caller builds");

            for round in 0..20 {
                let now = Timestamp::from_micros(round * 10_000);
                conn.drive(now, OutputDrainBudget::default())
                    .expect("group sends protocol output");
                first_peer.drive(now);
                second_peer.drive(now);
                conn.drive(now, OutputDrainBudget::default())
                    .expect("group receives protocol output");
                if conn.group().members().iter().all(|member| {
                    member.connection().state() == shiguredo_srt::ConnectionState::Connected
                }) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(
                conn.group()
                    .members()
                    .iter()
                    .all(|member| member.connection().state()
                        == shiguredo_srt::ConnectionState::Connected),
                "{runtime:?} group did not connect"
            );

            assert_eq!(
                conn.send(b"bonded egress", Timestamp::from_micros(300_000))
                    .unwrap(),
                2
            );
            conn.drive(
                Timestamp::from_micros(300_000),
                OutputDrainBudget::default(),
            )
            .expect("group sends Broadcast payload");
            first_peer.drive(Timestamp::from_micros(300_000));
            second_peer.drive(Timestamp::from_micros(300_000));

            let stats = conn.stats();
            assert_eq!(stats.group_id, group.group_id);
            assert_eq!(stats.legs.len(), 2);
            assert_eq!(stats.aggregate.active_legs, 2);
            assert_eq!(stats.aggregate.logical_payloads_sent, 1);
            assert_eq!(stats.aggregate.wire_unique_packets_sent, 2);
        }
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
        GroupBuildError, GroupCallerLeg, GroupConnectionLeg, GroupConnectionStats,
        GroupDriveReport, GroupLegDriveReport, GroupLogicalCounters, ManualTimerStore,
        OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work,
        group_connection_stats, prepend_outputs,
    };
    use shiguredo_srt::{ConnectionEvent, ConnectionOutput, GroupMode, SrtConnection, Timestamp};
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

    struct GroupLeg {
        member_id: u32,
        socket: UdpSocket,
        timers: ManualTimerStore,
        pending_outputs: VecDeque<ConnectionOutput>,
    }

    /// Tokio-native multi-socket driver for an SRT Broadcast or Backup group.
    ///
    /// This owns Tokio sockets, not a synchronous [`crate::GroupConn`] wrapped
    /// in a task. Group sequencing, selection, and telemetry remain in the
    /// shared protocol core; this type supplies Tokio's nonblocking socket
    /// operations and exposes every leg for readiness registration.
    pub struct GroupConn {
        group: shiguredo_srt::SrtGroup,
        legs: Vec<GroupLeg>,
        logical_payloads_sent: u64,
        logical_payload_bytes_sent: u64,
        logical_payloads_received: u64,
        logical_payload_bytes_received: u64,
    }

    impl GroupConn {
        /// Build a Tokio-native group from application-owned protocol cores
        /// and connected standard UDP sockets.
        pub fn new(
            group_id: u32,
            mode: GroupMode,
            legs: impl IntoIterator<Item = GroupConnectionLeg>,
        ) -> Result<Self, GroupBuildError> {
            let mut group = shiguredo_srt::SrtGroup::new(group_id, mode)?;
            let mut io_legs = Vec::new();
            for leg in legs {
                group.add_member(leg.member_id, leg.weight, leg.connection)?;
                io_legs.push(GroupLeg {
                    member_id: leg.member_id,
                    socket: UdpSocket::from_std(leg.socket)?,
                    timers: ManualTimerStore::new(),
                    pending_outputs: VecDeque::new(),
                });
            }
            Ok(Self {
                group,
                legs: io_legs,
                logical_payloads_sent: 0,
                logical_payload_bytes_sent: 0,
                logical_payloads_received: 0,
                logical_payload_bytes_received: 0,
            })
        }

        /// Build a Tokio-native caller with one connected socket per group
        /// leg and begin every SRT handshake.
        pub fn caller(
            group: crate::GroupConfig,
            legs: impl IntoIterator<Item = GroupCallerLeg>,
            now: Timestamp,
        ) -> Result<Self, GroupBuildError> {
            let mut raw_legs = Vec::new();
            for leg in legs {
                let mut caller = leg.caller;
                caller.session.set_group(Some(crate::GroupConfig {
                    group_id: group.group_id,
                    group_type: group.group_type,
                    flags: group.flags,
                    weight: leg.weight,
                }));
                let prepared = caller.prepare(crate::RuntimeFlavor::Tokio)?;
                raw_legs.push(GroupConnectionLeg {
                    member_id: leg.member_id,
                    weight: leg.weight,
                    connection: prepared.connection(now)?,
                    socket: prepared.bind_socket()?,
                });
            }
            let mode = GroupMode::from_group_type(group.group_type)
                .ok_or(GroupBuildError::InvalidGroupType)?;
            Self::new(group.group_id, mode, raw_legs)
        }

        #[must_use]
        pub fn group(&self) -> &shiguredo_srt::SrtGroup {
            &self.group
        }

        /// Tokio sockets to include in the application's readiness set.
        #[must_use]
        pub fn leg_sockets(&self) -> impl ExactSizeIterator<Item = (u32, &UdpSocket)> {
            self.legs.iter().map(|leg| (leg.member_id, &leg.socket))
        }

        #[must_use]
        pub fn time_until_next_deadline(&self, now: Timestamp, default_micros: u64) -> u64 {
            self.legs
                .iter()
                .map(|leg| leg.timers.time_until_earliest(now, default_micros))
                .min()
                .unwrap_or(default_micros)
        }

        pub fn can_send(&mut self) -> bool {
            self.group.can_send()
        }

        pub fn send(
            &mut self,
            payload: &[u8],
            now: Timestamp,
        ) -> Result<usize, shiguredo_srt::Error> {
            let legs = self.group.send(payload, now)?;
            self.logical_payloads_sent = self.logical_payloads_sent.saturating_add(1);
            self.logical_payload_bytes_sent = self
                .logical_payload_bytes_sent
                .saturating_add(payload.len() as u64);
            Ok(legs)
        }

        pub fn disconnect(&mut self, now: Timestamp) {
            self.group.disconnect(now);
        }

        pub fn poll_data(&mut self, now: Timestamp) -> Option<shiguredo_srt::GroupPacket> {
            let packet = self.group.poll_data(now)?;
            self.logical_payloads_received = self.logical_payloads_received.saturating_add(1);
            self.logical_payload_bytes_received = self
                .logical_payload_bytes_received
                .saturating_add(packet.payload.len() as u64);
            Some(packet)
        }

        /// Perform bounded, nonblocking work for every leg. Call after a
        /// Tokio readiness notification or when the next timer is due; this
        /// never blocks one leg waiting for another.
        pub fn drive(
            &mut self,
            now: Timestamp,
            output_budget: OutputDrainBudget,
        ) -> io::Result<GroupDriveReport> {
            let mut report = GroupDriveReport {
                legs: Vec::with_capacity(self.legs.len()),
            };
            let (group, legs) = (&mut self.group, &mut self.legs);
            for leg in legs {
                let member = group
                    .member_mut(leg.member_id)
                    .expect("group and I/O legs are built together");
                let conn = member.connection_mut();
                leg.timers.fire_expired(now, conn);

                let mut received_datagrams = 0;
                let mut buffer = [0_u8; 65_536];
                for _ in 0..64 {
                    match leg.socket.try_recv(&mut buffer) {
                        Ok(size) => {
                            received_datagrams += 1;
                            conn.feed_recv_buf(&buffer[..size], now).map_err(|error| {
                                io::Error::new(io::ErrorKind::InvalidData, error)
                            })?;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }

                let output = drain_group_leg_outputs(conn, leg, now, output_budget)?;
                report.legs.push(GroupLegDriveReport {
                    member_id: leg.member_id,
                    received_datagrams,
                    output,
                });
            }
            Ok(report)
        }

        #[must_use]
        pub fn stats(&self) -> GroupConnectionStats {
            group_connection_stats(
                &self.group,
                GroupLogicalCounters {
                    payloads_sent: self.logical_payloads_sent,
                    payload_bytes_sent: self.logical_payload_bytes_sent,
                    payloads_received: self.logical_payloads_received,
                    payload_bytes_received: self.logical_payload_bytes_received,
                },
                |member_id| {
                    let io = self
                        .legs
                        .iter()
                        .find(|leg| leg.member_id == member_id)
                        .expect("group and I/O legs are built together");
                    (io.socket.local_addr().ok(), io.socket.peer_addr().ok())
                },
            )
        }
    }

    fn drain_group_leg_outputs(
        conn: &mut SrtConnection,
        leg: &mut GroupLeg,
        now: Timestamp,
        budget: OutputDrainBudget,
    ) -> io::Result<OutputDrainReport> {
        let (mut work, budget_exhausted) =
            collect_output_work(conn, &mut leg.pending_outputs, budget);
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
                ConnectionOutput::SendPacket(packet) => match leg.socket.try_send(&packet) {
                    Ok(sent) if sent == packet.len() => {
                        report.actions += 1;
                        report.packets += 1;
                        report.bytes += sent;
                    }
                    Ok(_) => {
                        prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                        leg.pending_outputs
                            .push_front(ConnectionOutput::SendPacket(packet));
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "UDP socket reported a partial datagram send",
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                        leg.pending_outputs
                            .push_front(ConnectionOutput::SendPacket(packet));
                        report.status = OutputDrainStatus::Backpressured;
                        return Ok(report);
                    }
                    Err(error) => {
                        prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                        leg.pending_outputs
                            .push_front(ConnectionOutput::SendPacket(packet));
                        return Err(error);
                    }
                },
                timer => {
                    leg.timers.apply_output(&timer, now);
                    report.actions += 1;
                }
            }
        }
        Ok(report)
    }

    pub struct TickResult {
        pub sent: u64,
        pub events: Vec<ConnectionEvent>,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn group_caller_uses_tokio_sockets_and_drives_every_leg() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("Tokio runtime builds");
            runtime.block_on(async {
                let first_peer =
                    std::net::UdpSocket::bind("127.0.0.1:0").expect("first peer binds");
                let second_peer =
                    std::net::UdpSocket::bind("127.0.0.1:0").expect("second peer binds");
                first_peer
                    .set_nonblocking(true)
                    .expect("first peer is nonblocking");
                second_peer
                    .set_nonblocking(true)
                    .expect("second peer is nonblocking");

                let group = crate::GroupConfig::new(42, shiguredo_srt::GroupType::Broadcast);
                let mut conn = GroupConn::caller(
                    group,
                    [
                        GroupCallerLeg::new(
                            1,
                            10,
                            crate::CallerConfig::builder(
                                first_peer.local_addr().expect("first address"),
                            )
                            .build()
                            .expect("first caller config"),
                        ),
                        GroupCallerLeg::new(
                            2,
                            20,
                            crate::CallerConfig::builder(
                                second_peer.local_addr().expect("second address"),
                            )
                            .build()
                            .expect("second caller config"),
                        ),
                    ],
                    Timestamp::from_micros(0),
                )
                .expect("bonded Tokio caller builds");

                assert_eq!(conn.leg_sockets().len(), 2);
                for (_, socket) in conn.leg_sockets() {
                    socket.writable().await.expect("leg becomes writable");
                }
                let report = conn
                    .drive(Timestamp::from_micros(0), OutputDrainBudget::default())
                    .expect("all induction packets are sent");
                assert_eq!(report.legs.len(), 2);
                assert_eq!(
                    report
                        .legs
                        .iter()
                        .map(|leg| leg.output.packets)
                        .sum::<usize>(),
                    2
                );

                let stats = conn.stats();
                assert_eq!(stats.group_id, group.group_id);
                assert_eq!(stats.legs.len(), 2);
                assert!(stats.legs.iter().all(|leg| leg.peer_addr.is_some()));
            });
        }
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
                                if error.kind() == io::ErrorKind::WouldBlock {
                                    report.status = OutputDrainStatus::Backpressured;
                                    return Ok(report);
                                }
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
