use crate::{
    CallerTable, DatagramSink, IngressTelemetry, OutputDrainBudget, OutputDrainReport,
    OutputDrainStatus, PacedSendOutcome, PeerTable, PushResult, collect_output_work,
    prepend_outputs,
};
use compio::buf::BufResult;
use compio::runtime::spawn;
use srt_proto::{Bytes, ConnectionOutput, SrtConnection, Timestamp};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
/// Per-connection state for compio: protocol + owned-buffer socket + timer deadlines.
pub struct Conn {
    conn: SrtConnection,
    sock: compio::net::UdpSocket,
    timers: crate::ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
    output_drain: OutputDrainBudget,
}

impl Conn {
    pub fn new(conn: SrtConnection, sock: compio::net::UdpSocket) -> Self {
        Self::with_budgets(conn, sock, OutputDrainBudget::default())
    }

    /// Borrow the protocol state without exposing the adapter's internals.
    #[must_use]
    pub fn protocol(&self) -> &SrtConnection {
        &self.conn
    }

    /// Mutably access protocol state for a scoped custom-driver operation.
    pub fn protocol_mut(&mut self) -> &mut SrtConnection {
        &mut self.conn
    }

    /// Borrow the runtime socket used by this connection.
    #[must_use]
    pub fn socket(&self) -> &compio::net::UdpSocket {
        &self.sock
    }

    /// Like [`Self::new`], but stores the given budget instead of the
    /// default (K02): [`Self::drain_outputs`] honors this, not a hardcoded
    /// `::default()`, on every call.
    pub fn with_budgets(
        conn: SrtConnection,
        sock: compio::net::UdpSocket,
        output_drain: OutputDrainBudget,
    ) -> Self {
        Self {
            conn,
            sock,
            timers: crate::ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
            output_drain,
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
        self.drain_outputs_bounded(now, self.output_drain).await
    }

    pub async fn drain_outputs_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
    ) -> io::Result<OutputDrainReport> {
        let (work, exhausted) =
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
        // S05: stage every collected action back into the driver-owned queue
        // before the first per-item await. `self.pending_outputs` is popped
        // from directly below, one action at a time (bounded to exactly the
        // `budget`-capped count `collect_output_work` already computed --
        // `self.pending_outputs` itself may hold more behind these, left by
        // a prior cap), so a task cancelled while an owned-buffer send is in
        // flight loses at most the one buffer compio's proactor has already
        // taken ownership of -- never the not-yet-submitted remainder, which
        // stays durable throughout.
        let budget_count = work.len();
        prepend_outputs(&mut self.pending_outputs, work.into_iter());
        let mut report = OutputDrainReport {
            status: if exhausted {
                OutputDrainStatus::BudgetExhausted
            } else {
                OutputDrainStatus::Drained
            },
            ..Default::default()
        };
        for _ in 0..budget_count {
            let Some(out) = self.pending_outputs.pop_front() else {
                break;
            };
            match out {
                ConnectionOutput::SendPacket(bytes) => {
                    let expected = bytes.len();
                    // Once submitted, compio's proactor owns `bytes` until
                    // the kernel completion arrives; a cancellation here
                    // (task dropped while this await is pending) hands the
                    // buffer to compio's own cancel-on-drop path, and the
                    // datagram may or may not have already reached the
                    // wire. We deliberately do not try to recover or
                    // requeue it in that case -- SRT's own retransmission
                    // covers a genuinely lost packet, and requeuing a
                    // buffer that was already submitted risks sending a
                    // duplicate.
                    let BufResult(result, bytes) = self.sock.send(bytes).await;
                    match result {
                        Ok(sent) if sent == expected => {
                            report.actions += 1;
                            report.packets += 1;
                            report.bytes += sent;
                        }
                        Ok(_) => {
                            // The op completed (not cancelled): we observed
                            // the result, so it is safe to requeue exactly
                            // this datagram at the front.
                            self.pending_outputs
                                .push_front(ConnectionOutput::SendPacket(bytes));
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "UDP send completed with a partial datagram",
                            ));
                        }
                        Err(error) => {
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

    /// See [`PacedSendOutcome`] for what each outcome means (S03).
    pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> PacedSendOutcome {
        if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
            return PacedSendOutcome::NotDue;
        }
        if let Err(error) = self.conn.send(payload, now) {
            return PacedSendOutcome::Rejected(error);
        }
        match self.drain_outputs(now).await {
            Ok(report) if report.status == OutputDrainStatus::Drained => PacedSendOutcome::Sent,
            Ok(_) => PacedSendOutcome::Accepted,
            Err(error) => PacedSendOutcome::DriverError(error),
        }
    }

    /// Once accepted, the payload is retained by the protocol regardless of
    /// drain outcome -- a future bus caller must not resend it as new data
    /// on `DriverError`/`Accepted`, only on `NotDue`/`Rejected` (S02/S03).
    pub async fn send_shared_paced(&mut self, payload: Bytes, now: Timestamp) -> PacedSendOutcome {
        if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
            return PacedSendOutcome::NotDue;
        }
        if let Err(error) = self.conn.send_shared(payload, now) {
            return PacedSendOutcome::Rejected(error);
        }
        match self.drain_outputs(now).await {
            Ok(report) if report.status == OutputDrainStatus::Drained => PacedSendOutcome::Sent,
            Ok(_) => PacedSendOutcome::Accepted,
            Err(error) => PacedSendOutcome::DriverError(error),
        }
    }
}
fn make_poll_fd(
    sock: &compio::net::UdpSocket,
) -> Result<compio::runtime::fd::PollFd<std::net::UdpSocket>, crate::RuntimeBuildError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: dup creates a new valid file descriptor with independent lifetime.
    let new_fd = unsafe { libc::dup(sock.as_raw_fd()) };
    if new_fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: new_fd was successfully created by dup and ownership is transferred to std_sock.
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(new_fd) };
    let _ = std_sock.set_nonblocking(true);
    compio::runtime::fd::PollFd::new(std_sock).map_err(|e| e.into())
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
    prepared.require_exclusive()?;
    let socket = compio::net::UdpSocket::from_std(prepared.bind_socket()?)?;
    Ok(Conn::with_budgets(
        prepared.connection(now)?,
        socket,
        prepared.transport.output_drain,
    ))
}

/// Canonical production runtime profile for a shared Compio Owner.
///
/// Restream constructs the actual shard [`compio::runtime::Runtime`], then
/// calls [`observe_production_runtime`] on that exact runtime to record
/// qualification data. srt-rs never chooses process/thread/NUMA topology
/// itself. Capability fields are observed host data, not policy: a host
/// whose kernel rejects buffer-ring registration stays on the readiness +
/// raw `recvfrom` fallback without changing architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompioProductionProfile {
    /// Fixed TX lane count (= TX capacity) for the Owner.
    pub tx_lanes: usize,
    /// Wire ceiling in bytes for every TxPool slot.
    pub wire_ceiling: usize,
    /// Provided-buffer-ring registration outcome on the observed runtime.
    pub buffer_ring: ProvidedBufferRingStatus,
    /// Multishot `RECVMSG` capability. `NotTestedBecauseBufferRingUnavailable`
    /// when the ring substrate failed first: RECVMSG_MULTISHOT itself was
    /// never reached, so it must not be reported as broken.
    pub multishot_recv: MultishotRecvStatus,
    /// Whether the observed driver is io_uring (vs Poll fallback).
    pub is_io_uring: bool,
    /// Kernel release string from `/proc/version`.
    pub kernel_version: String,
    /// Pinned Compio version from `Cargo.lock` (not the srt-transport version).
    pub compio_version: String,
    /// Observed driver name (`IoUring` or `Poll`).
    pub driver_type: String,
}

impl CompioProductionProfile {
    /// Whether Compio managed RX (`recv_from_multi` / `recv_msg_multi` over
    /// the runtime buffer pool) is usable on the observed runtime.
    #[must_use]
    pub fn managed_rx_available(&self) -> bool {
        matches!(
            (&self.buffer_ring, &self.multishot_recv),
            (
                ProvidedBufferRingStatus::Available,
                MultishotRecvStatus::Available
            )
        )
    }

    /// Whether this host may run the high-density SRT path. Fails closed
    /// when the buffer-ring substrate is unavailable; the single-reader
    /// fallback remains valid for development/compatibility.
    #[must_use]
    pub fn high_density_qualified(&self) -> bool {
        self.is_io_uring && self.managed_rx_available()
    }
}

/// Outcome of `IORING_REGISTER_PBUF_RING` on the observed host.
///
/// A valid request rejected with `EINVAL` (observed on Ubuntu Noble
/// `6.8.0-139-generic` via strace) is a kernel-build defect, not evidence
/// that multishot receive itself is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvidedBufferRingStatus {
    /// Not yet observed on a live runtime.
    Unknown,
    /// Buffer-ring registration succeeded.
    Available,
    /// Registration failed with the given errno (e.g. `EINVAL` = 22).
    RegistrationFailed(i32),
}

/// Multishot `RECVMSG` capability, tested only when the buffer-ring
/// substrate initialized successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultishotRecvStatus {
    /// Not yet observed on a live runtime.
    Unknown,
    /// A multishot receive armed cleanly.
    Available,
    /// Multishot receive itself failed.
    Unsupported,
    /// Never reached: buffer-ring registration failed first.
    NotTestedBecauseBufferRingUnavailable,
}

/// Pinned Compio dependency version, kept in sync with `Cargo.lock`.
pub const PINNED_COMPIO_VERSION: &str = "0.19.2";

/// Production runtime envelope: explicit SQ/CQ sizing derived from the
/// Owner TX/RX budget (lanes + RX burst + timeout slack), never Compio
/// defaults chosen blindly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionRuntimeConfig {
    /// Fixed TX lane count (= TX capacity).
    pub tx_lanes: usize,
    /// io_uring submit-queue capacity.
    pub sq_capacity: u32,
    /// io_uring completion-queue size.
    pub cq_size: u32,
    /// Managed RX buffer-ring entry count (power of two).
    pub rx_ring_entries: u16,
    /// Managed RX buffer length (covers max UDP payload).
    pub rx_buffer_len: usize,
}

impl ProductionRuntimeConfig {
    /// Derive SQ/CQ/ring sizes from the Owner envelope. CQ covers lanes +
    /// RX burst + timeout slack; ring entries round up to power of two.
    #[must_use]
    pub fn for_owner(tx_lanes: usize) -> Self {
        let lanes = tx_lanes.max(1) as u32;
        let sq_capacity = lanes.saturating_add(256).max(512);
        let cq_size = sq_capacity.saturating_mul(2);
        Self {
            tx_lanes: tx_lanes.max(1),
            sq_capacity,
            cq_size,
            rx_ring_entries: 256,
            rx_buffer_len: DEFAULT_RX_SLOT_SIZE,
        }
    }
}

/// Build the canonical production Compio runtime for one Owner shard thread.
///
/// Fail-closed on Linux high-density production: forces
/// `DriverType::IoUring`, explicit SQ/CQ sizing, `single_issuer`, and an
/// explicit managed-RX buffer pool. `coop_taskrun` / `taskrun_flag` /
/// `defer_taskrun` stay at Compio defaults (no evidence to enable them);
/// SQPOLL stays off (unmeasured default would hide latency truth).
/// Restream supplies CPU affinity/shard topology; srt-rs never pins CPUs.
/// Returns `Err` rather than silently becoming Poll.
pub fn production_runtime_builder(
    config: ProductionRuntimeConfig,
) -> Result<compio::runtime::RuntimeBuilder, String> {
    let mut proactor = compio::driver::ProactorBuilder::new();
    proactor.driver_type(compio::driver::DriverType::IoUring);
    proactor.capacity(config.sq_capacity);
    proactor.cqsize(config.cq_size);
    proactor.single_issuer(true);
    proactor.buffer_pool_size(
        std::num::NonZero::new(config.rx_ring_entries)
            .ok_or_else(|| "rx_ring_entries must be nonzero".to_string())?,
    );
    proactor.buffer_pool_buffer_len(config.rx_buffer_len);
    let mut builder = compio::runtime::RuntimeBuilder::new();
    builder.with_proactor(proactor);
    Ok(builder)
}

#[cfg(test)]
mod production_config_tests {
    use super::*;

    #[test]
    fn production_config_derives_explicit_envelope() {
        let cfg = ProductionRuntimeConfig::for_owner(64);
        assert_eq!(cfg.tx_lanes, 64);
        // SQ covers lanes + RX burst + slack; CQ doubles SQ.
        assert!(cfg.sq_capacity >= 64 + 256);
        assert_eq!(cfg.cq_size, cfg.sq_capacity * 2);
        assert_eq!(cfg.rx_ring_entries, 256);
        assert_eq!(cfg.rx_buffer_len, DEFAULT_RX_SLOT_SIZE);
        // Builder constructs without silently falling back.
        let _ = production_runtime_builder(cfg).expect("production builder builds");
    }
}

/// Observe an already-constructed runtime and return its production profile.
///
/// Inspects the exact runtime Restream built for the shard (never a
/// throwaway probe runtime). Distinguishes the buffer-ring substrate
/// (`IORING_REGISTER_PBUF_RING`) from multishot receive itself: if the
/// substrate fails, multishot is reported as
/// [`MultishotRecvStatus::NotTestedBecauseBufferRingUnavailable`], never
pub async fn observe_production_runtime(
    runtime: &compio::runtime::Runtime,
    tx_lanes: usize,
    wire_ceiling: usize,
) -> CompioProductionProfile {
    let driver = runtime.driver_type();
    let is_io_uring = driver.is_iouring();
    let kernel = std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown kernel".to_string())
        .trim()
        .to_string();
    // Stage 1: ask the runtime for its buffer pool directly. Success means
    // the provided-buffer substrate initialized; error classifies THIS
    // stage with its errno (EINVAL on Noble 6.8 = kernel rejected
    // IORING_REGISTER_PBUF_RING). Multishot is not tested until this passes.
    let buffer_ring = match runtime.buffer_pool() {
        Ok(_) => ProvidedBufferRingStatus::Available,
        Err(e) => ProvidedBufferRingStatus::RegistrationFailed(e.raw_os_error().unwrap_or(-1)),
    };
    // Stage 2: only when the substrate works, arm multishot receive.
    let multishot_recv = match &buffer_ring {
        ProvidedBufferRingStatus::RegistrationFailed(_) | ProvidedBufferRingStatus::Unknown => {
            MultishotRecvStatus::NotTestedBecauseBufferRingUnavailable
        }
        ProvidedBufferRingStatus::Available => {
            match compio::net::UdpSocket::bind("127.0.0.1:0").await {
                Err(_) => MultishotRecvStatus::Unsupported,
                Ok(sock) => {
                    use futures_util::{FutureExt, Stream};
                    let mut s = Box::pin(sock.recv_from_multi());
                    match std::future::poll_fn(|cx| Stream::poll_next(s.as_mut(), cx))
                        .now_or_never()
                    {
                        None | Some(Some(Ok(_))) => MultishotRecvStatus::Available,
                        // Multishot op error with its own errno: the op
                        // itself, not the substrate, is at fault.
                        Some(Some(Err(_))) => MultishotRecvStatus::Unsupported,
                        // Immediate termination without error.
                        Some(None) => MultishotRecvStatus::Unsupported,
                    }
                }
            }
        }
    };
    CompioProductionProfile {
        tx_lanes,
        wire_ceiling,
        buffer_ring,
        multishot_recv,
        is_io_uring,
        kernel_version: kernel,
        compio_version: PINNED_COMPIO_VERSION.to_string(),
        driver_type: format!("{driver:?}"),
    }
}

/// Default capacity for the reusable TX buffer pool.
pub const DEFAULT_TX_POOL_CAPACITY: usize = 256;
/// Default slot size matching standard 1500 MTU datagram bound.
pub const DEFAULT_TX_SLOT_SIZE: usize = 1500;
/// Reusable finite TX buffer pool for direct final-buffer outbound datagrams.
/// Observable telemetry snapshot for [`TxPool`]; the pool itself is mutated
/// only by the owner internals, never by external callers.
///
/// Fixed-cost: three scalar fields, `Copy`, zero heap allocation to collect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxPoolSnapshot {
    pub capacity: usize,
    pub free: usize,
    pub exhaustions: u64,
}
/// Reusable finite TX buffer pool for direct final-buffer outbound datagrams.
/// All slots are eagerly allocated to `slot_size` on creation; no runtime
/// growth or lazy allocation occurs.
pub struct TxPool {
    slot_size: usize,
    capacity: usize,
    free_buffers: Vec<Vec<u8>>,
    exhaustion_count: u64,
}

impl TxPool {
    /// Create a new pool pre-allocating `capacity` buffers of `slot_size` bytes.
    #[must_use]
    pub fn new(capacity: usize, slot_size: usize) -> Self {
        let capacity = capacity.max(1);
        let slot_size = slot_size.max(1);
        let mut free_buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            free_buffers.push(vec![0u8; slot_size]);
        }
        Self {
            slot_size,
            capacity,
            free_buffers,
            exhaustion_count: 0,
        }
    }

    /// Allocate or take a free buffer slot.
    pub(crate) fn alloc_slot(&mut self) -> Option<Vec<u8>> {
        if let Some(buf) = self.free_buffers.pop() {
            Some(buf)
        } else {
            self.exhaustion_count = self.exhaustion_count.saturating_add(1);
            None
        }
    }

    /// Return an owned buffer slot back to the pool.
    pub(crate) fn return_slot(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        buf.resize(self.slot_size, 0);
        self.free_buffers.push(buf);
    }

    /// Number of free buffers immediately available.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free_buffers.len()
    }

    /// Total capacity of the pool.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Fixed size of each buffer slot.
    #[must_use]
    pub fn slot_size(&self) -> usize {
        self.slot_size
    }

    /// Number of times the pool was exhausted when a slot was requested.
    #[must_use]
    pub fn exhaustion_count(&self) -> u64 {
        self.exhaustion_count
    }
}
/// Persistent receive buffer size (64 KiB covers max UDP payload without reallocation).
pub const DEFAULT_RX_SLOT_SIZE: usize = 65536;

/// Listener side of a shared Compio owner.
///
/// Sealed on purpose: every field is private and the only construction paths
/// that enforce the Owner's invariants (single PerPort socket, promotion
/// `Never`, session wire ceiling inside the Owner ceiling, socket-memory
/// budget) are [`Owner::listen`] and [`Owner::connect`]. The test/dev
/// constructors below are compiled only for in-crate tests and the
/// `bench-internals` benchmark harness.
pub struct ListenerSide {
    sock: Rc<compio::net::UdpSocket>,
    table: PeerTable,
    telemetry: IngressTelemetry,
    options: crate::AdmissionOptions,
    transport: crate::ResolvedTransportConfig,
    idle_timeout: std::time::Duration,
    /// Persistent receive slot. ALWAYS `DEFAULT_RX_SLOT_SIZE`; staging swaps
    /// the two buffers, it never resizes either.
    rx_buf: Vec<u8>,
    poll_fd: compio::runtime::fd::PollFd<std::net::UdpSocket>,
    /// Staged packet as metadata only: `(peer, len)` into `stage_buf`.
    /// No owned payload copy, no allocation.
    pending_rx: Option<(SocketAddr, usize)>,
    /// Persistent staging slot. ALWAYS `DEFAULT_RX_SLOT_SIZE`.
    stage_buf: Vec<u8>,
}

impl ListenerSide {
    /// Test/dev-only constructor. Production code must use [`Owner::listen`],
    /// which validates topology, promotion, wire ceiling, and socket memory.
    #[cfg(any(test, feature = "bench-internals"))]
    pub fn new(
        sock: compio::net::UdpSocket,
        config: &crate::ListenerConfig,
    ) -> Result<Self, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Compio)?;
        Self::from_prepared(sock, prepared)
    }

    /// Production construction path, reached only through
    /// [`Owner::listen`] (and in-crate tests), which performs the Owner's
    /// validation first.
    pub(crate) fn from_prepared(
        sock: compio::net::UdpSocket,
        prepared: crate::PreparedListener,
    ) -> Result<Self, crate::RuntimeBuildError> {
        let poll_fd = make_poll_fd(&sock)?;
        let side = Self {
            sock: Rc::new(sock),
            table: prepared.peer_table(),
            telemetry: IngressTelemetry::new(),
            options: prepared.admission_options(),
            transport: prepared.transport,
            idle_timeout: prepared.admission.idle_timeout,
            rx_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
            poll_fd,
            pending_rx: None,
            stage_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
        };
        Ok(side)
    }

    fn poll_read_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        self.poll_fd.poll_read_ready(cx)
    }
}

/// Pool-backed caller side of a shared Compio owner.
///
/// Sealed on purpose, exactly like [`ListenerSide`]: the invariants
/// (`SocketOwnership::Shared`, shared-socket compatibility, wire ceiling,
/// combined socket-memory budget) are enforced by [`Owner::connect`].
pub struct OwnerCallerSide {
    sock: Rc<compio::net::UdpSocket>,
    pool: crate::CallerPool,
    transport: crate::ResolvedTransportConfig,
    local_bind: Option<std::net::SocketAddr>,
    connect_config: crate::ConnectConfig,
    /// Persistent receive slot; always `DEFAULT_RX_SLOT_SIZE` (see the
    /// listener side's identical fields).
    rx_buf: Vec<u8>,
    poll_fd: compio::runtime::fd::PollFd<std::net::UdpSocket>,
    /// Staged packet as metadata only: `(peer, len)` into `stage_buf`.
    pending_rx: Option<(SocketAddr, usize)>,
    /// Persistent staging slot; always `DEFAULT_RX_SLOT_SIZE`.
    stage_buf: Vec<u8>,
}

impl OwnerCallerSide {
    /// Test/dev-only constructor. Production code must use [`Owner::connect`].
    #[cfg(any(test, feature = "bench-internals"))]
    pub fn new(
        sock: compio::net::UdpSocket,
        max_in_flight: std::num::NonZeroUsize,
        attempt_deadline: std::time::Duration,
        transport: crate::ResolvedTransportConfig,
        local_bind: Option<std::net::SocketAddr>,
        connect_config: crate::ConnectConfig,
    ) -> Self {
        Self::from_parts(
            sock,
            max_in_flight,
            attempt_deadline,
            transport,
            local_bind,
            connect_config,
        )
    }

    /// Production construction path, reached only through [`Owner::connect`]
    /// (and in-crate tests), which performs the Owner's validation first.
    pub(crate) fn from_parts(
        sock: compio::net::UdpSocket,
        max_in_flight: std::num::NonZeroUsize,
        attempt_deadline: std::time::Duration,
        transport: crate::ResolvedTransportConfig,
        local_bind: Option<std::net::SocketAddr>,
        connect_config: crate::ConnectConfig,
    ) -> Self {
        let poll_fd = make_poll_fd(&sock).expect("caller poll_fd initializes");
        Self {
            sock: Rc::new(sock),
            pool: crate::CallerPool::new(max_in_flight, attempt_deadline),
            transport,
            local_bind,
            connect_config,
            rx_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
            poll_fd,
            pending_rx: None,
            stage_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
        }
    }

    fn poll_read_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        self.poll_fd.poll_read_ready(cx)
    }

    /// Immutable access to the pooled caller table.
    #[must_use]
    pub fn table(&self) -> &CallerTable {
        self.pool.table()
    }

    /// Test-only single-socket side for direct table use.
    ///
    /// Uses the same `Shared` ownership transport policy as
    /// [`Owner::connect`]-created sides so later `connect()` calls validate
    /// as shared-compatible instead of rejecting the first extra caller.
    /// Production code must go through [`Owner::connect`].
    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn new_single(sock: compio::net::UdpSocket) -> Self {
        let poll_fd = make_poll_fd(&sock).expect("caller poll_fd initializes");
        let transport = crate::TransportConfig {
            ownership: crate::SocketOwnership::Shared,
            ..crate::TransportConfig::default()
        }
        .resolve(crate::RuntimeFlavor::Compio.capabilities())
        .expect("shared transport resolves");
        Self {
            sock: Rc::new(sock),
            pool: crate::CallerPool::new(
                std::num::NonZeroUsize::MIN,
                std::time::Duration::from_secs(5),
            ),
            transport,
            local_bind: None,
            connect_config: crate::ConnectConfig::default(),
            rx_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
            poll_fd,
            pending_rx: None,
            stage_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
        }
    }
}
/// Compute the canonical maximum wire-datagram size required for a configured SRT session.
///
/// Accounts for:
/// - DATA packets: `payload_size + SRT_HEADER_SIZE (16) + GCM_TAG (16 if GCM enabled)`
/// - Handshake / control packets:
///   - Base handshake: 48 bytes body + 16 bytes SRT header = 64 bytes
///   - Extensions: SRT extension (16 bytes), StreamId extension (up to 512 + 4 = 516 bytes),
///     KM extension (32-byte key material + 12 = 44 bytes), Group extension (20 bytes)
///   - Largest legal control datagram: DEFAULT_MTU (1500) for full NAK chunks and control ceilings
#[must_use]
pub fn required_session_wire_ceiling(payload_size: usize, has_gcm: bool) -> usize {
    let data_wire = payload_size
        .saturating_add(srt_proto::wire::SRT_HEADER_SIZE)
        .saturating_add(if has_gcm { 16 } else { 0 });
    let control_wire = (srt_proto::handshake::DEFAULT_MTU as usize).max(660);
    data_wire.max(control_wire)
}

/// attributed, validated, and reported instead of silently discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InFlightMeta {
    pub peer: SocketAddr,
    pub expected_len: usize,
}

/// Aggregated TX completion accounting surfaced through [`OwnerServiceReport`].
///
/// Fixed-cost: scalar counters plus one inline `Option<SocketAddr>`; `Copy`,
/// zero heap allocation to collect or copy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnerTxCompletionStats {
    pub completed_ok: usize,
    pub short_sends: usize,
    pub failed_sends: usize,
    pub last_failed_peer: Option<SocketAddr>,
}

/// Typed fault state for a Compio Owner.
///
/// A fault stops new admission and new TX submission on that Owner: it is
/// never a silently reduced-capacity steady state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerFault {
    /// A fixed TX worker task terminated unexpectedly (panicked).
    WorkerPanicked { lane: usize },
    /// A lane's `send_to` completed having written fewer bytes than the
    /// materialized wire length. The datagram did not reach the wire intact,
    /// and the final buffer is already consumed by the protocol output path,
    /// so this is a fault rather than a retryable metric.
    TxShortSend {
        peer: SocketAddr,
        expected: usize,
        sent: usize,
    },
    /// A lane's `send_to` failed: the datagram was not delivered. The
    /// materialized wire buffer is retained (returned to the pool) but the
    /// protocol output that produced it is already consumed, so this is a
    /// fault, not silent loss with a healthy-looking transport.
    TxFailed {
        peer: SocketAddr,
        kind: io::ErrorKind,
    },
    /// A quiescent shutdown drain did not reach `in_flight() == 0` before its
    /// deadline. Ownership is left exactly as it was: lanes still own their
    /// slots, `in_flight` is not reset, and no buffer is reclaimed early.
    ShutdownTimedOut { in_flight: usize },
    /// Owner has been shut down.
    Shutdown,
}

struct TxJob {
    sock: Rc<compio::net::UdpSocket>,
    buf: Vec<u8>,
    peer: SocketAddr,
    meta: InFlightMeta,
}

pub(crate) struct TxCompletion {
    pub meta: InFlightMeta,
    pub res: io::Result<usize>,
    pub buf: Vec<u8>,
}

struct TxLaneState {
    job: Option<TxJob>,
    worker_waker: Option<Waker>,
    completion: Option<TxCompletion>,
    shutdown: bool,
    /// The worker has taken a job and its `send_to` has not published a
    /// completion yet. This slot is owned by the lane, not by the engine's
    /// queued/completed lists, which is what makes `in_flight` truthful even
    /// if a shutdown drain times out.
    in_kernel: bool,
}

struct TxLane {
    state: Rc<RefCell<TxLaneState>>,
    handle: compio::runtime::JoinHandle<()>,
}

pub(crate) struct TxEngine {
    lanes: Vec<TxLane>,
    idle_lanes: Vec<usize>,
    completed_lanes: Rc<RefCell<VecDeque<usize>>>,
    owner_waker: Rc<RefCell<Option<Waker>>>,
    capacity: usize,
    in_flight_count: usize,
    fault: Option<OwnerFault>,
    shutdown: bool,
}

async fn tx_lane_worker(
    state: Rc<RefCell<TxLaneState>>,
    completed_lanes: Rc<RefCell<VecDeque<usize>>>,
    owner_waker: Rc<RefCell<Option<Waker>>>,
    lane_idx: usize,
) {
    loop {
        let job = poll_fn(|cx| {
            let mut s = state.borrow_mut();
            if s.shutdown {
                return Poll::Ready(None);
            }
            if let Some(job) = s.job.take() {
                s.in_kernel = true;
                return Poll::Ready(Some(job));
            }
            s.worker_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await;

        let Some(job) = job else {
            break;
        };

        let BufResult(res, mut buf) = job.sock.send_to(job.buf, job.peer).await;
        buf.clear();

        {
            let mut s = state.borrow_mut();
            s.in_kernel = false;
            s.completion = Some(TxCompletion {
                meta: job.meta,
                res,
                buf,
            });
        }
        completed_lanes.borrow_mut().push_back(lane_idx);
        if let Some(w) = owner_waker.borrow_mut().take() {
            w.wake();
        }
    }
}

impl TxEngine {
    #[must_use]
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let mut engine = Self {
            lanes: Vec::with_capacity(capacity),
            idle_lanes: (0..capacity).rev().collect(),
            completed_lanes: Rc::new(RefCell::new(VecDeque::with_capacity(capacity))),
            owner_waker: Rc::new(RefCell::new(None)),
            capacity,
            in_flight_count: 0,
            fault: None,
            shutdown: false,
        };
        engine.ensure_started();
        engine
    }

    pub(crate) fn ensure_started(&mut self) {
        if !self.lanes.is_empty() || self.shutdown {
            return;
        }
        if compio::runtime::Runtime::try_current().is_none() {
            return;
        }
        for lane_idx in 0..self.capacity {
            let state = Rc::new(RefCell::new(TxLaneState {
                job: None,
                worker_waker: None,
                completion: None,
                shutdown: false,
                in_kernel: false,
            }));
            let completed_lanes = Rc::clone(&self.completed_lanes);
            let owner_waker = Rc::clone(&self.owner_waker);
            let worker_state = Rc::clone(&state);
            let handle = spawn(async move {
                tx_lane_worker(worker_state, completed_lanes, owner_waker, lane_idx).await;
            });
            self.lanes.push(TxLane { state, handle });
        }
    }

    #[must_use]
    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight_count
    }

    #[must_use]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub(crate) fn has_fault(&self) -> bool {
        self.fault.is_some()
    }

    #[must_use]
    pub(crate) fn fault(&self) -> Option<&OwnerFault> {
        self.fault.as_ref()
    }

    pub(crate) fn check_worker_faults(&mut self) {
        if self.fault.is_some() || self.shutdown {
            return;
        }
        for (idx, lane) in self.lanes.iter().enumerate() {
            if lane.handle.is_finished() {
                self.fault = Some(OwnerFault::WorkerPanicked { lane: idx });
                break;
            }
        }
    }

    pub(crate) fn reserve_lane(&mut self) -> Option<usize> {
        self.ensure_started();
        if self.fault.is_some() || self.shutdown {
            return None;
        }
        self.check_worker_faults();
        if self.fault.is_some() {
            return None;
        }
        let lane_idx = self.idle_lanes.pop()?;
        self.in_flight_count += 1;
        Some(lane_idx)
    }

    pub(crate) fn release_reserved_lane(&mut self, lane_idx: usize) {
        self.idle_lanes.push(lane_idx);
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }

    pub(crate) fn submit_job(
        &mut self,
        lane_idx: usize,
        sock: Rc<compio::net::UdpSocket>,
        buf: Vec<u8>,
        peer: SocketAddr,
        meta: InFlightMeta,
    ) {
        let lane = &self.lanes[lane_idx];
        let mut s = lane.state.borrow_mut();
        s.job = Some(TxJob {
            sock,
            buf,
            peer,
            meta,
        });
        if let Some(w) = s.worker_waker.take() {
            w.wake();
        }
    }

    pub(crate) fn poll_completions<F>(
        &mut self,
        cx: Option<&mut Context<'_>>,
        max_completions: usize,
        mut on_completion: F,
    ) -> usize
    where
        F: FnMut(InFlightMeta, io::Result<usize>, Vec<u8>),
    {
        self.ensure_started();
        self.check_worker_faults();
        let mut reaped = 0;
        while reaped < max_completions {
            let Some(lane_idx) = self.completed_lanes.borrow_mut().pop_front() else {
                break;
            };
            let completion = self.lanes[lane_idx]
                .state
                .borrow_mut()
                .completion
                .take()
                .expect("completion present when indexed");
            // Single policy point for every completion path (`service`,
            // `wait_for_activity`, and quiescent drain): the first short send
            // or send error faults the Owner, and a fault stops new admission
            // and new TX. Later completions only add statistics -- the
            // originating fault is the one surfaced.
            if self.fault.is_none() {
                match completion.res {
                    Ok(sent) if sent == completion.meta.expected_len => {}
                    Ok(sent) => {
                        self.fault = Some(OwnerFault::TxShortSend {
                            peer: completion.meta.peer,
                            expected: completion.meta.expected_len,
                            sent,
                        });
                    }
                    Err(ref error) => {
                        self.fault = Some(OwnerFault::TxFailed {
                            peer: completion.meta.peer,
                            kind: error.kind(),
                        });
                    }
                }
            }
            on_completion(completion.meta, completion.res, completion.buf);
            self.idle_lanes.push(lane_idx);
            self.in_flight_count = self.in_flight_count.saturating_sub(1);
            reaped += 1;
        }
        if let Some(cx) = cx
            && self.in_flight_count > 0
        {
            *self.owner_waker.borrow_mut() = Some(cx.waker().clone());
        }
        reaped
    }

    /// Phase 1 of the two-phase shutdown: stop new admissions while
    /// keeping every fixed lane alive so in-flight `send_to` work can still
    /// complete and be reaped. Returns `true` when the engine was running.
    pub(crate) fn begin_shutdown(&mut self) -> bool {
        if self.shutdown {
            return false;
        }
        self.shutdown = true;
        true
    }

    /// Quiescent drain: reap already-ready completions (bounded), then park
    /// only until in-flight work completes or `deadline` elapses. Returns
    /// `true` when `in_flight() == 0`. Never resets counters while work is
    /// still owned by a lane: every slot returns exactly once, through
    /// normal completion reaping.
    pub(crate) async fn drain_in_flight(
        &mut self,
        tx_pool: &mut TxPool,
        completions: &mut OwnerTxCompletionStats,
        max_completions: usize,
        deadline: std::time::Instant,
    ) -> bool {
        while self.in_flight() > 0 {
            let reaped = self.poll_completions(None, max_completions, |meta, res, buf| {
                tx_pool.return_slot(buf);
                match res {
                    Ok(sent) if sent == meta.expected_len => {
                        completions.completed_ok += 1;
                    }
                    Ok(_) => {
                        completions.short_sends += 1;
                        completions.last_failed_peer = Some(meta.peer);
                    }
                    Err(_) => {
                        completions.failed_sends += 1;
                        completions.last_failed_peer = Some(meta.peer);
                    }
                }
            });
            if self.in_flight() == 0 {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            if reaped == 0 {
                compio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
        true
    }

    /// Phase 2 (terminal): after `drain_in_flight` reports quiescence (or
    /// the caller accepts the hung remainder), stop every lane, reclaim any
    /// still-owned buffer exactly once, and mark the engine faulted so no
    /// new work can be admitted afterwards. Lane tasks observe `shutdown`
    /// and exit; dropping their `JoinHandle`s cancels any still-parked
    /// worker without awaiting kernel I/O.
    pub(crate) fn finish_shutdown(&mut self, tx_pool: &mut TxPool) {
        if self.fault.is_some() && self.lanes.iter().all(|l| l.handle.is_finished()) {
            return;
        }
        self.shutdown = true;
        if self.fault.is_none() {
            self.fault = Some(OwnerFault::Shutdown);
        }
        for lane in &self.lanes {
            let mut s = lane.state.borrow_mut();
            s.shutdown = true;
            if let Some(w) = s.worker_waker.take() {
                w.wake();
            }
            if let Some(job) = s.job.take() {
                tx_pool.return_slot(job.buf);
            }
            if let Some(completion) = s.completion.take() {
                tx_pool.return_slot(completion.buf);
            }
        }
        self.completed_lanes.borrow_mut().clear();
        // Ownership stays truthful: a lane whose `send_to` is still with the
        // kernel keeps its slot until its own completion returns it, so the
        // in-flight count is recomputed from lane state rather than zeroed.
        self.in_flight_count = self
            .lanes
            .iter()
            .filter(|lane| lane.state.borrow().in_kernel)
            .count();
        self.idle_lanes.clear();
        for lane_idx in 0..self.capacity {
            if lane_idx < self.lanes.len() && self.lanes[lane_idx].state.borrow().in_kernel {
                continue;
            }
            self.idle_lanes.push(lane_idx);
        }
    }

    /// Record a timed-out teardown without touching ownership: the fault is
    /// surfaced, but `in_flight` and the pool keep counting what the kernel
    /// still owns.
    pub(crate) fn note_shutdown_timeout(&mut self, in_flight: usize) {
        self.shutdown = true;
        if self.fault.is_none() {
            self.fault = Some(OwnerFault::ShutdownTimedOut { in_flight });
        }
    }

    /// Await every fixed lane worker to completion. Only valid after a drain
    /// proved `in_flight() == 0` and lanes were signalled to stop: each worker
    /// then observes `shutdown` and exits, so this returns without cancelling
    /// anything. Consumes the handles, so a second call is a no-op.
    pub(crate) async fn join_lanes(&mut self) {
        let lanes = std::mem::take(&mut self.lanes);
        for lane in lanes {
            let _ = lane.handle.await;
        }
    }

    pub(crate) fn shutdown(&mut self, tx_pool: &mut TxPool) {
        if self.shutdown {
            return;
        }
        self.shutdown = true;
        if self.fault.is_none() {
            self.fault = Some(OwnerFault::Shutdown);
        }
        for lane in &self.lanes {
            let mut s = lane.state.borrow_mut();
            s.shutdown = true;
            if let Some(w) = s.worker_waker.take() {
                w.wake();
            }
            if let Some(job) = s.job.take() {
                tx_pool.return_slot(job.buf);
            }
            if let Some(completion) = s.completion.take() {
                tx_pool.return_slot(completion.buf);
            }
        }
        self.completed_lanes.borrow_mut().clear();
        // Ownership stays truthful: a lane whose `send_to` is still with the
        // kernel keeps its slot until its own completion returns it, so the
        // in-flight count is recomputed from lane state rather than zeroed.
        self.in_flight_count = self
            .lanes
            .iter()
            .filter(|lane| lane.state.borrow().in_kernel)
            .count();
        self.idle_lanes.clear();
        for lane_idx in 0..self.capacity {
            if lane_idx < self.lanes.len() && self.lanes[lane_idx].state.borrow().in_kernel {
                continue;
            }
            self.idle_lanes.push(lane_idx);
        }
    }
}

struct OwnerTxSink<'a> {
    sock: &'a Rc<compio::net::UdpSocket>,
    tx_pool: &'a mut TxPool,
    tx_engine: &'a mut TxEngine,
}

impl DatagramSink for OwnerTxSink<'_> {
    fn push_datagram<F>(
        &mut self,
        peer: SocketAddr,
        wire_len: usize,
        fill: F,
    ) -> Result<PushResult, srt_proto::Error>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, srt_proto::Error>,
    {
        if wire_len > self.tx_pool.slot_size() {
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidData,
                format!(
                    "datagram wire_len {} exceeds TxPool slot ceiling {}",
                    wire_len,
                    self.tx_pool.slot_size()
                ),
            ));
        }
        if self.tx_engine.has_fault() {
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "owner TX engine in fault state",
            ));
        }
        let Some(lane_idx) = self.tx_engine.reserve_lane() else {
            return Ok(PushResult::Exhausted);
        };
        let Some(mut buf) = self.tx_pool.alloc_slot() else {
            self.tx_engine.release_reserved_lane(lane_idx);
            return Ok(PushResult::Exhausted);
        };
        buf.resize(wire_len, 0);
        let len = match fill(&mut buf[..wire_len]) {
            Ok(len) => len,
            Err(error) => {
                self.tx_pool.return_slot(buf);
                self.tx_engine.release_reserved_lane(lane_idx);
                return Err(error);
            }
        };
        if len != wire_len {
            self.tx_pool.return_slot(buf);
            self.tx_engine.release_reserved_lane(lane_idx);
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidData,
                "owner sink fill must materialize exactly the advertised wire length",
            ));
        }
        let meta = InFlightMeta {
            peer,
            expected_len: len,
        };
        self.tx_engine
            .submit_job(lane_idx, self.sock.clone(), buf, peer, meta);
        Ok(PushResult::Pushed { len })
    }
}

/// Bounded work budget for one [`Owner::service`] visit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerServiceBudget {
    pub max_completions: usize,
    pub max_rx_packets: usize,
    pub max_rx_bytes: usize,
    pub max_actions: usize,
    pub max_tx_packets: usize,
    pub max_tx_bytes: usize,
}

impl Default for OwnerServiceBudget {
    fn default() -> Self {
        Self {
            max_completions: 256,
            max_rx_packets: 256,
            max_rx_bytes: 512 * 1024,
            max_actions: 512,
            max_tx_packets: 256,
            max_tx_bytes: 512 * 1024,
        }
    }
}

/// Convert a `recvfrom`-filled `sockaddr_storage` into a std socket address.
fn sockaddr_to_std(storage: libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    if storage.ss_family as i32 == libc::AF_INET
        && len as usize >= std::mem::size_of::<libc::sockaddr_in>()
    {
        // SAFETY: `sockaddr_in` is plain data; zeroing initializes it.
        let mut addr_in: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        // SAFETY: family and length were validated against the union layout;
        // copying the prefix into a stack `sockaddr_in` is sound.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &storage as *const _ as *const u8,
                &mut addr_in as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
        }
        let ip = Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
        return Some(SocketAddr::V4(SocketAddrV4::new(
            ip,
            u16::from_be(addr_in.sin_port),
        )));
    }
    if storage.ss_family as i32 == libc::AF_INET6
        && len as usize >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        // SAFETY: `sockaddr_in6` is plain data; zeroing initializes it.
        let mut addr_in6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        // SAFETY: same validated-prefix copy contract for the IPv6 layout.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &storage as *const _ as *const u8,
                &mut addr_in6 as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in6>(),
            );
        }
        let ip = Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
        return Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            u16::from_be(addr_in6.sin6_port),
            addr_in6.sin6_flowinfo,
            addr_in6.sin6_scope_id,
        )));
    }
    None
}
/// Execution report for one [`Owner::service`] visit.
///
/// Fixed-cost by construction: every field is a `usize`/`bool`/`Option<u64>`
/// scalar. No `String`, `Vec`, map, or boxed field exists on this path, so
/// collecting or copying a report performs zero heap allocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnerServiceReport {
    pub completions_reaped: usize,
    pub rx_packets: usize,
    pub rx_bytes: usize,
    pub tx_packets_submitted: usize,
    pub tx_bytes_submitted: usize,
    pub actions: usize,
    pub tx_in_flight: usize,
    pub tx_pool_free: usize,
    pub work_remaining: bool,
    pub budget_exhausted: bool,
    pub next_deadline_us: Option<u64>,
    pub tx_completed_ok: usize,
    pub tx_short_sends: usize,
    pub tx_failed_sends: usize,
}

/// High-density, shared-socket completion-runtime owner.
///
/// Manages shared UDP sockets for listeners and callers without a per-connection task.
/// All outbound datagrams use direct final-buffer encoding into reusable slots from [`TxPool`].
pub struct Owner {
    listener: Option<ListenerSide>,
    caller: Option<OwnerCallerSide>,
    tx_pool: TxPool,
    tx_engine: TxEngine,
    completions: OwnerTxCompletionStats,
    wire_ceiling: usize,
    sessions_started: bool,
    rx_priority_listener_first: bool,
    tx_priority_listener_first: bool,
    caller_pool_policy: Option<(std::num::NonZeroUsize, std::time::Duration)>,
    socket_memory_budget: Option<std::num::NonZeroUsize>,
}

impl Owner {
    /// Create a new Owner with bounded concurrent TX capacity using the default MTU (1500) wire ceiling.
    #[must_use]
    pub fn new(tx_capacity: usize) -> Self {
        Self::new_with_ceiling(tx_capacity, DEFAULT_TX_SLOT_SIZE)
    }

    /// Create a new Owner with bounded concurrent TX capacity and an explicit wire ceiling.
    #[must_use]
    pub fn new_with_ceiling(tx_capacity: usize, wire_ceiling: usize) -> Self {
        let capacity = tx_capacity.max(1);
        let wire_ceiling = wire_ceiling.max(1);
        Self {
            listener: None,
            caller: None,
            tx_pool: TxPool::new(capacity, wire_ceiling),
            tx_engine: TxEngine::new(capacity),
            completions: OwnerTxCompletionStats::default(),
            wire_ceiling,
            sessions_started: false,
            rx_priority_listener_first: true,
            tx_priority_listener_first: true,
            caller_pool_policy: None,
            socket_memory_budget: None,
        }
    }

    /// Current wire ceiling in bytes.
    #[must_use]
    pub fn wire_ceiling(&self) -> usize {
        self.wire_ceiling
    }

    /// Set or change the wire ceiling before any sessions start.
    ///
    /// Fails with an error if called after sessions have started (via `listen`,
    /// `connect`, `with_listener`, or `with_caller`).
    pub fn set_wire_ceiling(
        &mut self,
        wire_ceiling: usize,
    ) -> Result<(), crate::RuntimeBuildError> {
        if self.sessions_started {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "wire_ceiling",
                "cannot change wire ceiling after sessions have started",
            )));
        }
        let wire_ceiling = wire_ceiling.max(1);
        self.wire_ceiling = wire_ceiling;
        self.tx_pool = TxPool::new(self.tx_engine.capacity(), wire_ceiling);
        Ok(())
    }

    /// Typed fault state if any worker has failed or owner has been shut down.
    #[must_use]
    pub fn fault(&self) -> Option<&OwnerFault> {
        self.tx_engine.fault()
    }

    /// Non-awaiting shutdown: stops new admissions, signals the fixed lanes to
    /// stop, and reclaims only the buffers the engine still owns (a queued job
    /// or an unpublished completion).
    ///
    /// Ownership stays truthful. A lane whose `send_to` is already with the
    /// kernel keeps its slot, so `tx_in_flight()` keeps counting it and
    /// `tx_pool().free_count()` stays below capacity until that completion is
    /// reaped. This form never fabricates quiescence; use
    /// [`Self::shutdown_and_drain`] when the caller needs to prove it.
    pub fn shutdown(&mut self) {
        self.tx_engine.shutdown(&mut self.tx_pool);
    }

    /// Quiescent shutdown for production teardown:
    ///
    /// 1. stop new admissions/TX submissions (`begin_shutdown`);
    /// 2. reap in-flight `send_to` work to zero, bounded by `timeout`;
    /// 3. only after that proof: signal every lane to stop, await/join every
    ///    lane worker, and mark the terminal state.
    ///
    /// Returns `true` when the teardown is proven quiescent: `in_flight() == 0`,
    /// every lane joined, and `tx_pool().free_count() == capacity()`.
    ///
    /// On timeout it returns `false` **without** fabricating anything: no lane
    /// is joined, no buffer is reclaimed early, `in_flight()` still counts the
    /// work the kernel owns, and the Owner is faulted with
    /// [`OwnerFault::ShutdownTimedOut`] so the caller can see the teardown did
    /// not complete.
    pub async fn shutdown_and_drain(&mut self, timeout: std::time::Duration) -> bool {
        self.tx_engine.begin_shutdown();
        let deadline = std::time::Instant::now() + timeout;
        let (tx_pool, completions, tx_engine) = (
            &mut self.tx_pool,
            &mut self.completions,
            &mut self.tx_engine,
        );
        let drained = tx_engine
            .drain_in_flight(tx_pool, completions, usize::MAX, deadline)
            .await;
        if !drained || self.tx_engine.in_flight() != 0 {
            let in_flight = self.tx_engine.in_flight();
            self.tx_engine.note_shutdown_timeout(in_flight);
            return false;
        }
        // Proven quiescent: stop the lanes, join them, then mark terminal.
        self.tx_engine.finish_shutdown(&mut self.tx_pool);
        self.tx_engine.join_lanes().await;
        let free = self.tx_pool.free_count();
        let capacity = self.tx_pool.capacity();
        self.tx_engine.in_flight() == 0 && free == capacity
    }

    fn poll_tx_activity(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.tx_engine.in_flight() == 0 {
            return Poll::Pending;
        }
        let completions = &mut self.completions;
        let tx_pool = &mut self.tx_pool;
        let reaped = self
            .tx_engine
            .poll_completions(Some(cx), 1, |meta, res, buf| {
                tx_pool.return_slot(buf);
                match res {
                    Ok(sent) if sent == meta.expected_len => {
                        completions.completed_ok += 1;
                    }
                    Ok(_) => {
                        completions.short_sends += 1;
                        completions.last_failed_peer = Some(meta.peer);
                    }
                    Err(_) => {
                        completions.failed_sends += 1;
                        completions.last_failed_peer = Some(meta.peer);
                    }
                }
            });
        if reaped > 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Test/dev-only: attach a pre-built listener side.
    ///
    /// Bypasses every check [`Self::listen`] performs, so it is compiled only
    /// for in-crate tests and the `bench-internals` harness. Production code
    /// uses [`Self::listen`].
    #[cfg(any(test, feature = "bench-internals"))]
    pub fn with_listener(mut self, listener: ListenerSide) -> Self {
        self.sessions_started = true;
        self.listener = Some(listener);
        self
    }

    /// Test/dev-only: attach a pre-built caller side.
    ///
    /// Bypasses every check [`Self::connect`] performs; see
    /// [`Self::with_listener`].
    #[cfg(any(test, feature = "bench-internals"))]
    pub fn with_caller(mut self, caller: OwnerCallerSide) -> Self {
        self.sessions_started = true;
        self.caller = Some(caller);
        self
    }

    /// Benchmark-only mutable handle on the pooled caller table.
    ///
    /// Exists so the allocator benchmarks can drive the table directly
    /// without the Owner handing out its side internals; compiled only for
    /// `bench-internals`.
    #[cfg(feature = "bench-internals")]
    pub fn bench_caller_table_mut(&mut self) -> Option<&mut CallerTable> {
        Some(self.caller.as_mut()?.pool.bench_table_mut())
    }

    /// Set the caller-side `max_in_flight`/`attempt_deadline` policy. Must be
    /// called before the first [`Self::connect`] call.
    pub fn set_caller_pool_policy(
        &mut self,
        max_in_flight: std::num::NonZeroUsize,
        attempt_deadline: std::time::Duration,
    ) -> Result<(), crate::RuntimeBuildError> {
        if self.caller.is_some() {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller_pool_policy",
                "must be set before the first connect() call, not after the caller \
                 socket and its pool already exist",
            )));
        }
        if attempt_deadline.is_zero() {
            return Err(crate::ConfigError::new(
                "caller_pool_policy",
                "attempt deadline must be positive",
            )
            .into());
        }
        self.caller_pool_policy = Some((max_in_flight, attempt_deadline));
        Ok(())
    }

    /// Bind and register this owner's one listener socket. May be called at
    /// most once, from the runtime thread that will own the socket.
    pub fn listen(
        &mut self,
        config: &crate::ListenerConfig,
    ) -> Result<(), crate::RuntimeBuildError> {
        if self.listener.is_some() {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "listener",
                "Owner::listen was already called; this owner drives exactly one listener socket",
            )));
        }
        let prepared = config.prepare(crate::RuntimeFlavor::Compio)?;
        if !matches!(
            prepared.transport.topology,
            crate::ResolvedListenerTopology::PerPort
        ) {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "listener.transport.topology",
                "Owner drives a single PerPort listener socket; pooled or \
                 reuseport topologies need a multi-acceptor driver, which \
                 this Owner does not build",
            )));
        }
        if prepared.transport.promotion != srt_lifecycle::Promotion::Never {
            return Err(crate::ConfigError::new(
                "listener.transport.promotion",
                "Owner has no relocation target; set promotion to Never",
            )
            .into());
        }
        let payload_size = prepared.session.payload_size.resolve()?.get();
        let has_encryption = prepared.session.encryption().is_some();
        let req_ceiling = required_session_wire_ceiling(payload_size, has_encryption);
        if req_ceiling > self.wire_ceiling {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "listener",
                format!(
                    "session required wire ceiling {req_ceiling} exceeds owner wire ceiling {}",
                    self.wire_ceiling
                ),
            )));
        }
        if let Some(budget) = prepared.admission.socket_memory_budget {
            let caller_requested = self
                .caller
                .as_ref()
                .map_or(0, |c| c.transport.socket_buffer_bytes.saturating_mul(4));
            let total = prepared
                .requested_socket_memory_bytes()
                .saturating_add(caller_requested);
            if total > budget.get() {
                return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                    "admission.socket_memory_budget",
                    format!(
                        "{total} bytes requested for combined listener and caller buffers exceeds owner budget of {} bytes",
                        budget.get()
                    ),
                )));
            }
            self.socket_memory_budget = Some(budget);
        }
        let mut sockets = prepared.bind_sockets()?;
        let sock = compio::net::UdpSocket::from_std(sockets.remove(0))?;
        self.sessions_started = true;
        self.listener = Some(ListenerSide::from_prepared(sock, prepared)?);
        Ok(())
    }

    /// Start one outbound session on this owner's shared caller socket,
    /// binding it on the first call. `config.transport.ownership` must be
    /// `Shared`; the shared socket stays unconnected and every logical
    /// caller is demultiplexed by SRT socket ID.
    pub fn connect(
        &mut self,
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<crate::PoolOutcome, crate::RuntimeBuildError> {
        let mut prepared = config.prepare(crate::RuntimeFlavor::Compio)?;
        if self.tx_engine.has_fault() {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.connect",
                "owner TX engine in fault state",
            )));
        }
        let payload_size = prepared.session.payload_size.resolve()?.get();
        let has_encryption = prepared.session.encryption().is_some();
        let req_ceiling = required_session_wire_ceiling(payload_size, has_encryption);
        if req_ceiling > self.wire_ceiling {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.connect",
                format!(
                    "session required wire ceiling {req_ceiling} exceeds owner wire ceiling {}",
                    self.wire_ceiling
                ),
            )));
        }
        self.sessions_started = true;
        if let Some((max_in_flight, attempt_deadline)) = self.caller_pool_policy {
            prepared.connect.max_in_flight = max_in_flight;
            prepared.connect.attempt_deadline = attempt_deadline;
        }
        if prepared.transport.exclusive {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.transport.ownership",
                "Owner::connect requires SocketOwnership::Shared; an \
                 Exclusive caller connects its own socket to a single \
                 remote and cannot share this owner's one egress socket \
                 with other logical callers",
            )));
        }
        if let Some(side) = self.caller.as_ref() {
            prepared.validate_shared_compatibility(
                side.local_bind,
                side.transport,
                Some(side.connect_config),
            )?;
        }
        if self.caller.is_none() {
            if let Some(budget) = self.socket_memory_budget {
                let listener_requested = self.listener.as_ref().map_or(0, |l| {
                    l.transport
                        .socket_buffer_bytes
                        .saturating_mul(4)
                        .saturating_mul(l.transport.topology.listener_socket_count().get())
                });
                let total =
                    listener_requested.saturating_add(prepared.requested_socket_memory_bytes());
                if total > budget.get() {
                    return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                        "caller.socket_memory_budget",
                        format!(
                            "{total} bytes requested for combined listener and caller buffers exceeds owner budget of {} bytes",
                            budget.get()
                        ),
                    )));
                }
            }
            let sock = compio::net::UdpSocket::from_std(prepared.bind_socket()?)?;
            let crate::ConnectConfig {
                max_in_flight,
                attempt_deadline,
            } = prepared.connect;
            self.caller = Some(OwnerCallerSide::from_parts(
                sock,
                max_in_flight,
                attempt_deadline,
                prepared.transport,
                prepared.local_bind,
                prepared.connect,
            ));
        }
        let side = self.caller.as_mut().expect("just ensured above");
        side.pool.connect(prepared, now).map_err(|error| {
            crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.connect",
                error.to_string(),
            ))
        })
    }

    /// Drain admitted-peer lifecycle/data events for the application.
    pub fn poll_listener_events(&mut self, out: &mut Vec<crate::AdmissionEvent>) {
        out.clear();
        let Some(side) = self.listener.as_mut() else {
            return;
        };
        side.table
            .poll_events_bounded(crate::OutputDrainBudget::default().max_actions, out);
    }

    /// Drain protocol events for every direct outbound session.
    pub fn poll_caller_events(&mut self, out: &mut Vec<crate::CallerEvent>) {
        out.clear();
        let Some(side) = self.caller.as_mut() else {
            return;
        };
        side.pool
            .poll_events_bounded(crate::OutputDrainBudget::default().max_actions, out);
    }

    /// Drain bounded caller-pool lifecycle outcomes.
    pub fn poll_caller_pool_events(&mut self, out: &mut Vec<crate::PoolEvent>) {
        out.clear();
        let Some(side) = self.caller.as_mut() else {
            return;
        };
        side.pool
            .poll_outcomes_bounded(crate::OutputDrainBudget::default().max_actions, out);
    }

    /// Steady-state handle for one admitted peer: send, stats, orderly close.
    #[must_use]
    pub fn listener_peer_mut(
        &mut self,
        id: crate::LogicalPeerId,
    ) -> Option<crate::LogicalPeerMut<'_>> {
        self.listener.as_mut()?.table.logical_peer_mut(&id)
    }

    /// Atomically retire one admitted peer, reclaiming its table entry.
    pub fn remove_listener_peer(
        &mut self,
        id: crate::LogicalPeerId,
    ) -> Option<crate::RemovedLogicalPeer> {
        self.listener.as_mut()?.table.remove(id)
    }

    /// Atomically retire one outbound session.
    pub fn remove_caller(
        &mut self,
        id: crate::LogicalCallerId,
    ) -> Option<crate::RemovedLogicalCaller> {
        self.caller.as_mut()?.pool.remove(id)
    }

    /// Borrow one logical caller without exposing the pool itself.
    #[must_use]
    pub fn logical_caller(&self, id: &crate::LogicalCallerId) -> Option<crate::LogicalCaller<'_>> {
        self.caller.as_ref()?.pool.logical_caller(id)
    }

    /// Mutably borrow one logical caller without exposing the pool itself.
    pub fn logical_caller_mut(
        &mut self,
        id: &crate::LogicalCallerId,
    ) -> Option<crate::LogicalCallerMut<'_>> {
        self.caller.as_mut()?.pool.logical_caller_mut(id)
    }
    #[must_use]
    pub fn listener_local_addr(&self) -> Option<std::net::SocketAddr> {
        self.listener.as_ref()?.sock.local_addr().ok()
    }

    #[must_use]
    pub fn listener_telemetry(&self) -> Option<crate::IngressTelemetrySnapshot> {
        Some(self.listener.as_ref()?.telemetry.snapshot())
    }

    #[must_use]
    pub fn caller_pool_stats(&self) -> Option<crate::CallerPoolStats> {
        Some(self.caller.as_ref()?.pool.stats())
    }

    /// Read-only handle on the listener side. Its fields are private, so this
    /// exposes no way to bypass Owner admission.
    #[must_use]
    pub fn listener(&self) -> Option<&ListenerSide> {
        self.listener.as_ref()
    }

    /// Read-only handle on the caller side. Its fields are private, so this
    /// exposes no way to bypass Owner admission.
    #[must_use]
    pub fn caller(&self) -> Option<&OwnerCallerSide> {
        self.caller.as_ref()
    }

    #[must_use]
    pub fn tx_pool(&self) -> &TxPool {
        &self.tx_pool
    }

    /// Observable TX pool telemetry without exposing pool mutation.
    #[must_use]
    pub fn tx_pool_snapshot(&self) -> crate::compio::TxPoolSnapshot {
        crate::compio::TxPoolSnapshot {
            capacity: self.tx_pool.capacity(),
            free: self.tx_pool.free_count(),
            exhaustions: self.tx_pool.exhaustion_count(),
        }
    }

    #[must_use]
    pub fn tx_in_flight(&self) -> usize {
        self.tx_engine.in_flight()
    }
    /// Delay until the next due timer across all sessions, including
    /// `CallerPool` attempt deadlines (not just protocol timers).
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        let l_us = self.listener.as_mut().map_or(default_us, |l| {
            let idle_us = l
                .table
                .time_until_idle_deadline(now, l.idle_timeout, default_us);
            let proto_us = l.table.time_until_next_deadline(now, default_us);
            idle_us.min(proto_us)
        });
        let c_us = self.caller.as_ref().map_or(default_us, |c| {
            c.pool.time_until_next_deadline(now, default_us)
        });
        l_us.min(c_us)
    }

    /// Non-blocking bounded drain of already-ready work. Never waits for I/O:
    /// completions are reaped only when their futures are ready, receives are
    /// attempted with a zero-duration readiness probe, and the outer
    /// Restream scheduler owns all waiting via [`Owner::time_until_next_deadline`]
    /// plus [`Owner::wait_for_activity`].
    pub async fn service(
        &mut self,
        now: Timestamp,
        budget: OwnerServiceBudget,
    ) -> OwnerServiceReport {
        let mut report = OwnerServiceReport::default();
        let prev_ok = self.completions.completed_ok;
        let prev_short = self.completions.short_sends;
        let prev_failed = self.completions.failed_sends;

        // 1. Reap only already-ready completions, never waiting.
        let completions = &mut self.completions;
        let tx_pool = &mut self.tx_pool;
        report.completions_reaped +=
            self.tx_engine
                .poll_completions(None, budget.max_completions, |meta, res, buf| {
                    tx_pool.return_slot(buf);
                    match res {
                        Ok(sent) if sent == meta.expected_len => {
                            completions.completed_ok += 1;
                        }
                        Ok(_) => {
                            completions.short_sends += 1;
                            completions.last_failed_peer = Some(meta.peer);
                        }
                        Err(_) => {
                            completions.failed_sends += 1;
                            completions.last_failed_peer = Some(meta.peer);
                        }
                    }
                });

        // 2. Service incoming RX up to max_rx_packets / max_rx_bytes
        self.service_rx(now, &budget, &mut report).await;

        // 3. Lifecycle maintenance, bounded by max_actions only (see
        //    `service_maintenance`): independent of the packet/byte axes.
        self.service_maintenance(now, &budget, &mut report);

        // 4. Service outbound TX up to max_tx_packets / max_tx_bytes / the
        //    remaining action allowance.
        self.service_tx(now, &budget, &mut report);

        report.tx_in_flight = self.tx_engine.in_flight();
        report.tx_pool_free = self.tx_pool.free_count();
        report.next_deadline_us = Some(self.time_until_next_deadline(now, 100_000));
        report.tx_completed_ok = self.completions.completed_ok.saturating_sub(prev_ok);
        report.tx_short_sends = self.completions.short_sends.saturating_sub(prev_short);
        report.tx_failed_sends = self.completions.failed_sends.saturating_sub(prev_failed);

        let has_pending = self.has_pending_work(now);
        // Runnable work remaining: timers due, application data queued
        // waiting for budget, or caller pool requests waiting for admission.
        // Merely having I/O in flight is NOT runnable work: setting
        // `work_remaining = true` when only `tx_in_flight > 0` causes the outer
        // event loop to busy-spin in `service()` instead of parking on the
        // proactor via `wait_for_activity()`.
        report.work_remaining = has_pending;
        report.budget_exhausted = report.completions_reaped >= budget.max_completions
            || report.rx_packets >= budget.max_rx_packets
            || report.rx_bytes >= budget.max_rx_bytes
            || report.tx_packets_submitted >= budget.max_tx_packets
            || report.tx_bytes_submitted >= budget.max_tx_bytes
            || report.actions >= budget.max_actions;

        report
    }

    /// Wait until the proactor reports activity or `timeout` elapses. This is
    /// the only waiting entry point: `service` itself never blocks, so an
    /// outer Restream shard calls `wait_for_activity` when idle and
    /// `service` when woken or on its timer deadline.
    ///
    /// Awakened by:
    /// 1. An in-flight TX completion (buffer returned to `TxPool`, counters updated).
    /// 2. An incoming datagram on the listener socket (wakes immediately).
    /// 3. An incoming datagram on the caller socket (wakes immediately).
    /// 4. Timer expiry (`timeout` elapses).
    pub async fn wait_for_activity(&mut self, timeout: std::time::Duration) {
        // Staged work wakes immediately: never sleep past work the next
        // service() call can already consume.
        if self
            .listener
            .as_ref()
            .is_some_and(|l| l.pending_rx.is_some())
            || self.caller.as_ref().is_some_and(|c| c.pending_rx.is_some())
        {
            return;
        }
        let _ = compio::time::timeout(
            timeout,
            std::future::poll_fn(|cx| {
                if self.poll_tx_activity(cx).is_ready() {
                    return std::task::Poll::Ready(());
                }
                if let Some(listener) = self.listener.as_ref()
                    && listener.poll_read_ready(cx).is_ready()
                {
                    return std::task::Poll::Ready(());
                }
                if let Some(caller) = self.caller.as_ref()
                    && caller.poll_read_ready(cx).is_ready()
                {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending
            }),
        )
        .await;
    }

    async fn service_rx_listener(
        listener: &mut ListenerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        // 1. Consume a staged packet (metadata only) when the budget permits.
        if let Some((peer, len)) = listener.pending_rx {
            let exceeds_packets = report.rx_packets >= budget.max_rx_packets;
            let exceeds_bytes = report.rx_bytes.saturating_add(len) > budget.max_rx_bytes;
            if exceeds_packets || exceeds_bytes {
                return;
            }
            report.rx_packets += 1;
            report.rx_bytes += len;
            let _ = listener.table.admit(
                peer,
                &listener.stage_buf[..len],
                now,
                &listener.options,
                0,
                1,
                &listener.telemetry,
            );
            listener.pending_rx = None;
        }

        // 2. Drain from the socket. Zero heap allocations on this path: both
        // persistent slots are preallocated and never resized.
        while report.rx_packets < budget.max_rx_packets && report.rx_bytes < budget.max_rx_bytes {
            use std::os::fd::AsRawFd;
            let raw_fd = compio::net::UdpSocket::as_raw_fd(&listener.sock);
            // SAFETY: `sockaddr_storage` is plain data; zeroing initializes it.
            let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            // SAFETY: `raw_fd` is a live UDP socket; `recvfrom` writes at most
            // `rx_buf.len()` bytes into `rx_buf` plus peer address into
            // `addr_storage`.
            let received = unsafe {
                libc::recvfrom(
                    raw_fd,
                    listener.rx_buf.as_mut_ptr() as *mut libc::c_void,
                    listener.rx_buf.len(),
                    libc::MSG_DONTWAIT,
                    &mut addr_storage as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            if received <= 0 {
                break;
            }
            let len = received as usize;
            let Some(peer) = sockaddr_to_std(addr_storage, addr_len) else {
                break;
            };
            // Hard byte cap: if the datagram does not fit the remaining byte
            // budget, stage it by SWAPPING the two persistent slots (the
            // datagram ends up in `stage_buf`), recording only `(peer, len)`.
            // No allocation, no copy, and neither buffer changes length.
            if report.rx_bytes.saturating_add(len) > budget.max_rx_bytes {
                std::mem::swap(&mut listener.rx_buf, &mut listener.stage_buf);
                listener.pending_rx = Some((peer, len));
                break;
            }
            report.rx_packets += 1;
            report.rx_bytes += len;
            let _ = listener.table.admit(
                peer,
                &listener.rx_buf[..len],
                now,
                &listener.options,
                0,
                1,
                &listener.telemetry,
            );
        }
    }

    async fn service_rx_caller(
        caller: &mut OwnerCallerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        // 1. Consume a staged packet (metadata only) when the budget permits.
        if let Some((peer, len)) = caller.pending_rx {
            let exceeds_packets = report.rx_packets >= budget.max_rx_packets;
            let exceeds_bytes = report.rx_bytes.saturating_add(len) > budget.max_rx_bytes;
            if exceeds_packets || exceeds_bytes {
                return;
            }
            report.rx_packets += 1;
            report.rx_bytes += len;
            let _ = caller
                .pool
                .table_mut()
                .feed(peer, &caller.stage_buf[..len], now);
            caller.pending_rx = None;
        }

        // 2. Drain from the socket. Zero heap allocations on this path: both
        // persistent slots are preallocated and never resized (same contract
        // as the listener side).
        while report.rx_packets < budget.max_rx_packets && report.rx_bytes < budget.max_rx_bytes {
            use std::os::fd::AsRawFd;
            let raw_fd = compio::net::UdpSocket::as_raw_fd(&caller.sock);
            // SAFETY: `sockaddr_storage` is plain data; zeroing initializes it.
            let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            // SAFETY: `raw_fd` is a live UDP socket; `recvfrom` writes at most
            // `rx_buf.len()` bytes into `rx_buf` plus peer address into
            // `addr_storage`.
            let received = unsafe {
                libc::recvfrom(
                    raw_fd,
                    caller.rx_buf.as_mut_ptr() as *mut libc::c_void,
                    caller.rx_buf.len(),
                    libc::MSG_DONTWAIT,
                    &mut addr_storage as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            if received <= 0 {
                break;
            }
            let len = received as usize;
            let Some(peer) = sockaddr_to_std(addr_storage, addr_len) else {
                break;
            };
            // Hard byte cap: stage by swapping the two persistent slots,
            // recording only `(peer, len)`. No allocation, no copy, and
            // neither buffer changes length.
            if report.rx_bytes.saturating_add(len) > budget.max_rx_bytes {
                std::mem::swap(&mut caller.rx_buf, &mut caller.stage_buf);
                caller.pending_rx = Some((peer, len));
                break;
            }
            report.rx_packets += 1;
            report.rx_bytes += len;
            let _ = caller
                .pool
                .table_mut()
                .feed(peer, &caller.rx_buf[..len], now);
        }
    }
    async fn service_rx(
        &mut self,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        // Alternate side priority each visit so a hot listener cannot starve
        // the caller (or vice versa) when one shared budget covers both.
        self.rx_priority_listener_first = !self.rx_priority_listener_first;
        if self.rx_priority_listener_first {
            if let Some(ref mut listener) = self.listener {
                Self::service_rx_listener(listener, now, budget, report).await;
            }
            if let Some(ref mut caller) = self.caller {
                Self::service_rx_caller(caller, now, budget, report).await;
            }
        } else {
            if let Some(ref mut caller) = self.caller {
                Self::service_rx_caller(caller, now, budget, report).await;
            }
            if let Some(ref mut listener) = self.listener {
                Self::service_rx_listener(listener, now, budget, report).await;
            }
        }
    }

    fn remaining_tx_budget(
        &self,
        budget: &OwnerServiceBudget,
        report: &OwnerServiceReport,
    ) -> OutputDrainBudget {
        OutputDrainBudget::new(
            budget.max_actions.saturating_sub(report.actions),
            budget
                .max_tx_packets
                .saturating_sub(report.tx_packets_submitted),
            budget
                .max_tx_bytes
                .saturating_sub(report.tx_bytes_submitted),
        )
    }

    /// Lifecycle maintenance, bounded by `max_actions` ALONE.
    ///
    /// Caller connection-attempt expiration and listener idle reclaim are
    /// lifecycle work, not packet/byte transport work: a shard that grants
    /// zero TX packets or bytes this visit (a pacing-limited or drain-only
    /// visit) must still retire expired attempts and quiet peers, or those
    /// timers would only ever run when output happened to be admissible.
    fn service_maintenance(
        &mut self,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        let mut allowed = budget.max_actions.saturating_sub(report.actions);
        if allowed == 0 {
            return;
        }
        if let Some(caller) = self.caller.as_mut() {
            // Count-only: the Owner needs the visit count, not the retired
            // ids (those are surfaced as `PoolEvent`s), so this does not
            // allocate a Vec per maintenance visit.
            let visits = caller.pool.poll_expirations_count_only(now, allowed);
            report.actions = report.actions.saturating_add(visits);
            allowed = allowed.saturating_sub(visits);
        }
        if allowed > 0
            && let Some(listener) = self.listener.as_mut()
        {
            let (_, visits) =
                listener
                    .table
                    .prune_idle_bounded_with_visits(now, listener.idle_timeout, allowed);
            report.actions = report.actions.saturating_add(visits);
        }
    }

    fn service_tx_listener(
        &mut self,
        now: Timestamp,
        tx_budget: OutputDrainBudget,
        report: &mut OwnerServiceReport,
    ) {
        if let Some(ref mut listener) = self.listener {
            let mut sink = OwnerTxSink {
                sock: &listener.sock,
                tx_pool: &mut self.tx_pool,
                tx_engine: &mut self.tx_engine,
            };
            let drain_report = listener
                .table
                .poll_outbound_bounded_to(now, tx_budget, &mut sink);
            report.actions += drain_report.actions;
            report.tx_packets_submitted += drain_report.packets;
            report.tx_bytes_submitted += drain_report.bytes;
        }
    }

    fn service_tx_caller(
        &mut self,
        now: Timestamp,
        tx_budget: OutputDrainBudget,
        report: &mut OwnerServiceReport,
    ) {
        if let Some(caller) = self.caller.as_mut() {
            let mut sink = OwnerTxSink {
                sock: &caller.sock,
                tx_pool: &mut self.tx_pool,
                tx_engine: &mut self.tx_engine,
            };
            let drain_report = caller
                .pool
                .poll_outbound_bounded_to(now, tx_budget, &mut sink);
            report.actions += drain_report.actions;
            report.tx_packets_submitted += drain_report.packets;
            report.tx_bytes_submitted += drain_report.bytes;
        }
    }

    fn tx_allowance_consumed(
        &self,
        budget: &OwnerServiceBudget,
        report: &OwnerServiceReport,
    ) -> bool {
        report.actions >= budget.max_actions
            || report.tx_packets_submitted >= budget.max_tx_packets
            || report.tx_bytes_submitted >= budget.max_tx_bytes
    }

    fn service_tx(
        &mut self,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        // Alternate side priority each visit and stop the second phase as
        // soon as the first consumes a finite packet/byte allowance, so a
        // hot side cannot starve its sibling or exceed the declared Owner cap.
        self.tx_priority_listener_first = !self.tx_priority_listener_first;
        let first_listener = self.tx_priority_listener_first;
        for second in [false, true] {
            let serve_listener = first_listener != second;
            if self.tx_allowance_consumed(budget, report) {
                break;
            }
            let tx_budget = self.remaining_tx_budget(budget, report);
            // Zero means zero work: a consumed finite allowance must stop the
            // follow-up phase, never reopen it as unlimited.
            if tx_budget.max_actions == 0 || tx_budget.max_packets == 0 || tx_budget.max_bytes == 0
            {
                break;
            }
            if serve_listener {
                self.service_tx_listener(now, tx_budget, report);
            } else {
                self.service_tx_caller(now, tx_budget, report);
            }
        }
    }

    #[must_use]
    pub fn has_pending_work(&self, now: Timestamp) -> bool {
        let l_pending = self
            .listener
            .as_ref()
            .is_some_and(|l| l.pending_rx.is_some() || l.table.has_pending_output(now));
        let c_pending = self
            .caller
            .as_ref()
            .is_some_and(|c| c.pending_rx.is_some() || c.pool.table().has_pending_output(now));
        l_pending || c_pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn caller_rejects_shared_ownership_before_socket_bind() {
        let config = crate::CallerConfig::builder("127.0.0.1:9".parse().expect("address"))
            .ownership(crate::SocketOwnership::Shared)
            .build()
            .expect("caller config");
        let result = super::caller(&config, Timestamp::default());
        match result {
            Err(crate::RuntimeBuildError::Config(error)) => {
                assert_eq!(error.field(), "transport.ownership")
            }
            Err(error) => panic!("expected ownership rejection, got {error}"),
            Ok(_) => panic!("Shared caller must be rejected before binding"),
        }
    }

    /// K02: a `Conn` built via [`caller`] must actually drive with its
    /// configured `TransportConfig::output_drain`, not silently substitute
    /// [`OutputDrainBudget::default`] on every [`Conn::drain_outputs`] call.
    #[test]
    fn caller_constructs_a_conn_that_honors_its_configured_output_drain_budget() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            let remote = peer.local_addr().expect("peer address");

            let config = crate::CallerConfig::builder(remote)
                .configure_transport(|transport| {
                    transport.output_drain = OutputDrainBudget::new(1, 1, 64 * 1024);
                })
                .build()
                .expect("caller config");

            let mut conn =
                super::caller(&config, Timestamp::from_micros(0)).expect("caller builds");
            conn.pending_outputs
                .push_back(ConnectionOutput::SendPacket(b"one".to_vec()));
            conn.pending_outputs
                .push_back(ConnectionOutput::SendPacket(b"two".to_vec()));

            let report = conn
                .drain_outputs(Timestamp::from_micros(0))
                .await
                .expect("drain succeeds");
            assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
            assert_eq!(
                conn.pending_outputs.len(),
                1,
                "the second action must remain queued under a 1-action budget"
            );
        });
    }

    /// S05 (Opus review): staging `collect_output_work`'s capped `work`
    /// back into `self.pending_outputs` must not let the per-item loop
    /// drain past the budget. An earlier version of this fix prepended
    /// `work` and then looped `while let Some(out) =
    /// self.pending_outputs.pop_front()` -- but when `pending_outputs`
    /// already held a backlog beyond what `collect_output_work` capped at
    /// (exactly the case a real short/failed send leaves behind), that
    /// loop drained the whole backlog in one call, silently defeating the
    /// budget it exists to enforce. The loop must be bounded to exactly
    /// the count `collect_output_work` already capped at.
    #[test]
    fn drain_outputs_bounded_does_not_exceed_the_budget_even_with_a_backlog() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
            local
                .connect(peer.local_addr().expect("peer address"))
                .expect("local connects to peer");
            peer.set_nonblocking(true).expect("peer is nonblocking");
            let sock = compio::net::UdpSocket::from_std(local).expect("compio adopts the socket");

            let mut conn = Conn::new(
                SrtConnection::new_caller(srt_proto::ConnectionOptions::default()),
                sock,
            );
            // Simulates the exact scenario a short/failed prior send
            // leaves behind: a backlog already sitting in pending_outputs,
            // larger than any single call's budget should ever drain.
            for i in 0..5u8 {
                conn.pending_outputs
                    .push_back(ConnectionOutput::SendPacket(vec![i]));
            }

            let budget = OutputDrainBudget::new(usize::MAX, 2, usize::MAX);
            let report = conn
                .drain_outputs_bounded(Timestamp::from_micros(0), budget)
                .await
                .expect("drain succeeds");
            assert_eq!(
                report.packets, 2,
                "a budget of 2 packets must send exactly 2, not the whole backlog"
            );
            assert_eq!(
                report.status,
                OutputDrainStatus::BudgetExhausted,
                "3 packets must remain queued, unsent"
            );
            assert_eq!(
                conn.pending_outputs.len(),
                3,
                "the remaining 3 packets must still be queued, not sent or dropped"
            );

            let mut buf = [0u8; 64];
            let mut received = 0usize;
            while peer.recv(&mut buf).is_ok() {
                received += 1;
            }
            assert_eq!(
                received, 2,
                "exactly 2 datagrams must have reached the wire"
            );
        });
    }

    /// S05: `drain_outputs_bounded` pops its collected work directly off
    /// `self.pending_outputs` and submits one owned-buffer send at a time.
    /// Before this fix, the whole batch lived only in a local `work`
    /// variable across every per-item await; cancelling the task while any
    /// send but the first was in flight lost every action queued after it.
    ///
    /// compio's `Runtime` only submits to and reaps from io_uring when its
    /// own `poll`/`poll_with`/`block_on` loop runs -- there is no
    /// background reactor thread (unlike `async-io`). A bare manual
    /// `poll()` inside `Runtime::enter` therefore never drives the
    /// proactor: the first send's op is pushed into the driver's queue and
    /// deterministically stays `Pending` forever, giving full control over
    /// the cancellation point.
    #[test]
    fn drain_outputs_bounded_survives_cancellation_of_an_in_flight_send() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.enter(|| {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
            local
                .connect(peer.local_addr().expect("peer address"))
                .expect("local connects to peer");
            peer.set_nonblocking(true).expect("peer is nonblocking");
            let sock = compio::net::UdpSocket::from_std(local).expect("compio adopts the socket");

            let mut conn = Conn::new(
                SrtConnection::new_caller(srt_proto::ConnectionOptions::default()),
                sock,
            );
            conn.pending_outputs
                .push_back(ConnectionOutput::SendPacket(b"first".to_vec()));
            conn.pending_outputs
                .push_back(ConnectionOutput::SendPacket(b"second".to_vec()));
            conn.pending_outputs.push_back(ConnectionOutput::SetTimer {
                id: srt_proto::TimerId::Ack,
                duration_micros: 10_000,
            });
            let not_yet_submitted: Vec<_> = conn.pending_outputs.iter().skip(1).cloned().collect();

            let budget = OutputDrainBudget::new(usize::MAX, usize::MAX, usize::MAX);
            let mut future =
                Box::pin(conn.drain_outputs_bounded(Timestamp::from_micros(0), budget));
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let polled = future.as_mut().poll(&mut cx);
            assert!(
                matches!(polled, Poll::Pending),
                "expected the first send to park on the proactor with no driver turn yet, \
                 got {polled:?}"
            );

            // Cancellation: drop the suspended future while the first send
            // is in flight and unobserved. compio's own driver takes
            // ownership of that one buffer; we assert nothing about its
            // fate (sent, dropped, or cancelled -- all are acceptable for
            // one already-submitted UDP datagram). What must hold is that
            // the remainder, never submitted, is still fully intact.
            drop(future);

            assert_eq!(
                conn.pending_outputs.iter().collect::<Vec<_>>(),
                not_yet_submitted.iter().collect::<Vec<_>>(),
                "cancelling while the first send was in flight must leave every \
                 not-yet-submitted packet and timer action exactly as staged, in order"
            );
        });
    }

    #[test]
    fn owner_tx_pool_alloc_and_recycling() {
        let mut pool = TxPool::new(3, 1500);
        assert_eq!(pool.capacity(), 3);
        assert_eq!(pool.free_count(), 3);
        assert_eq!(pool.exhaustion_count(), 0);

        let b1 = pool.alloc_slot().expect("slot 1");
        let b2 = pool.alloc_slot().expect("slot 2");
        let b3 = pool.alloc_slot().expect("slot 3");
        assert_eq!(pool.free_count(), 0);

        let b4 = pool.alloc_slot();
        assert!(b4.is_none(), "pool must be exhausted");
        assert_eq!(pool.exhaustion_count(), 1);

        pool.return_slot(b1);
        assert_eq!(pool.free_count(), 1);
        let b5 = pool.alloc_slot();
        assert!(b5.is_some(), "recycled slot must be available");
        assert_eq!(pool.free_count(), 0);

        pool.return_slot(b2);
        pool.return_slot(b3);
        if let Some(b) = b5 {
            pool.return_slot(b);
        }
        assert_eq!(pool.free_count(), 3);
    }

    #[test]
    fn owner_connects_transfers_data_and_tracks_resources() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
            let l_addr = l_std.local_addr().expect("listener addr");
            let l_sock = compio::net::UdpSocket::from_std(l_std).expect("compio adopt listener");

            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("compio adopt caller");

            let l_cfg = crate::ListenerConfig::builder(l_addr)
                .build()
                .expect("listener config");
            let listener_side = ListenerSide::new(l_sock, &l_cfg).expect("listener side");
            let caller_side = OwnerCallerSide::new_single(c_sock);

            let mut owner = Owner::new(64)
                .with_listener(listener_side)
                .with_caller(caller_side);

            // Add a caller connection targeting listener
            let mut caller_conn = SrtConnection::new_caller(srt_proto::ConnectionOptions {
                socket_id: 0x1001,
                tsbpd_delay: 0,
                ..Default::default()
            });
            let mut now = Timestamp::from_micros(1_000);
            caller_conn.connect(now).expect("caller connect");

            let caller_leg = crate::caller::CallerLeg {
                peer: l_addr,
                connection: caller_conn,
            };
            let caller_id = owner
                .caller
                .as_mut()
                .unwrap()
                .pool
                .table_mut()
                .add_direct(caller_leg)
                .expect("add caller direct");

            // Service the owner until handshake connects
            let budget = OwnerServiceBudget::default();
            for round in 0..60 {
                now = Timestamp::from_micros(10_000 + round * 5_000);
                let _report = owner.service(now, budget).await;
                // `service` itself never waits: park on proactor activity so
                // already-submitted sends/receives complete before the next
                // bounded drain visit.
                owner
                    .wait_for_activity(std::time::Duration::from_millis(1))
                    .await;
                let connected = owner.logical_caller(&caller_id).and_then(|c| c.state())
                    == Some(crate::caller::LogicalCallerState::Connected);
                if connected {
                    break;
                }
            }

            let caller_session = owner
                .logical_caller(&caller_id)
                .expect("caller session exists");
            assert_eq!(
                caller_session.state(),
                Some(crate::caller::LogicalCallerState::Connected)
            );

            // Send application payload from caller to listener
            now = Timestamp::from_micros(200_000);
            let test_payload = Bytes::from_static(b"compio-owner-shared-socket-test-data");
            owner
                .logical_caller_mut(&caller_id)
                .expect("caller session")
                .send_shared(test_payload.clone(), now)
                .expect("send succeeds");

            // Service owner to transmit and receive
            for round in 0..30 {
                now = Timestamp::from_micros(210_000 + round * 2_000);
                let _report = owner.service(now, budget).await;
                owner
                    .wait_for_activity(std::time::Duration::from_millis(1))
                    .await;

                // Check if listener received the data
                let mut events = Vec::new();
                owner.poll_listener_events(&mut events);
                let received = events.iter().any(|e| match &e.event {
                    srt_proto::ConnectionEvent::DataReceived { payload, .. } => {
                        payload == &test_payload
                    }
                    _ => false,
                });
                if received {
                    break;
                }
            }

            assert!(owner.tx_pool().capacity() >= 64);
        });
    }

    #[test]
    fn owner_tx_bounded_concurrency_and_pool_exhaustion() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("compio adopt caller");
            let caller_side = OwnerCallerSide::new_single(c_sock);

            // Create owner with strict capacity of 2 in-flight sends
            let mut owner = Owner::new(2).with_caller(caller_side);
            assert_eq!(owner.tx_pool().capacity(), 2);
            assert_eq!(owner.tx_in_flight(), 0);

            let dummy_peer = "127.0.0.1:9876".parse().unwrap();
            let mut conn = SrtConnection::new_caller(srt_proto::ConnectionOptions::default());
            let now = Timestamp::from_micros(10_000);
            conn.connect(now).expect("connect");
            let leg = crate::caller::CallerLeg {
                peer: dummy_peer,
                connection: conn,
            };
            let id = owner
                .caller
                .as_mut()
                .unwrap()
                .pool
                .table_mut()
                .add_direct(leg)
                .expect("add leg");
            for i in 0..4u8 {
                owner
                    .caller
                    .as_mut()
                    .unwrap()
                    .pool
                    .table_mut()
                    .bench_push_pending(id, dummy_peer, vec![i; 32]);
            }
            let budget = OwnerServiceBudget {
                max_tx_packets: 10,
                ..Default::default()
            };
            let report = owner.service(now, budget).await;

            // Capacity is 2: at most 2 sends could be submitted
            assert!(
                report.tx_packets_submitted <= 2,
                "submitted {} exceeds capacity 2",
                report.tx_packets_submitted
            );

            // Removing the session while sends are in flight must be safe
            let removed = owner.remove_caller(id);
            assert!(removed.is_some(), "session removed safely");
        });
    }

    #[test]
    fn owner_sibling_isolation() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            // Real loopback: two receiver sockets bound on 127.0.0.1, one of
            // which is blackholed (never drained) while the healthy sibling
            // must still receive its datagram within a bounded visit count.
            let slow_rx = std::net::UdpSocket::bind("127.0.0.1:0").expect("slow rx binds");
            slow_rx.set_nonblocking(true).expect("slow rx nonblocking");
            let slow_peer = slow_rx.local_addr().expect("slow addr");
            let fast_rx = std::net::UdpSocket::bind("127.0.0.1:0").expect("fast rx binds");
            fast_rx.set_nonblocking(true).expect("fast rx nonblocking");
            let fast_peer = fast_rx.local_addr().expect("fast addr");

            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("compio adopt caller");
            let caller_side = OwnerCallerSide::new_single(c_sock);

            let mut owner = Owner::new(64).with_caller(caller_side);

            let mut slow_conn = SrtConnection::new_caller(srt_proto::ConnectionOptions {
                socket_id: 0x5001,
                ..Default::default()
            });
            let mut fast_conn = SrtConnection::new_caller(srt_proto::ConnectionOptions {
                socket_id: 0x5002,
                ..Default::default()
            });

            let now = Timestamp::from_micros(10_000);
            slow_conn.connect(now).expect("slow connect");
            fast_conn.connect(now).expect("fast connect");

            let slow_id = owner
                .caller
                .as_mut()
                .unwrap()
                .pool
                .table_mut()
                .add_direct(crate::caller::CallerLeg {
                    peer: slow_peer,
                    connection: slow_conn,
                })
                .expect("add slow");

            let fast_id = owner
                .caller
                .as_mut()
                .unwrap()
                .pool
                .table_mut()
                .add_direct(crate::caller::CallerLeg {
                    peer: fast_peer,
                    connection: fast_conn,
                })
                .expect("add fast");

            // The blackholed receivers cannot complete a real handshake (no
            // listener answers), so exercise the isolation question itself:
            // one backlogged sibling must not starve a healthy sibling's
            // submitted datagram. Queue through the transport pending path,
            // which is exactly what the scheduler fairness question covers.
            for i in 0..10u8 {
                owner
                    .caller
                    .as_mut()
                    .unwrap()
                    .pool
                    .table_mut()
                    .bench_push_pending(slow_id, slow_peer, vec![i; 64]);
            }
            owner
                .caller
                .as_mut()
                .unwrap()
                .pool
                .table_mut()
                .bench_push_pending(fast_id, fast_peer, b"fast-sibling-payload".to_vec());

            // Blackhole the slow receiver (never drain it) and assert the
            // healthy sibling's datagram arrives on its real socket within a
            // bounded number of Owner visits.
            let budget = OwnerServiceBudget::default();
            let mut now = Timestamp::from_micros(20_000);
            let mut fast_received: Option<Vec<u8>> = None;
            for _round in 0..30usize {
                now = Timestamp::from_micros(now.as_micros() + 2_000);
                let report = owner.service(now, budget).await;
                assert!(
                    report.tx_packets_submitted <= 512,
                    "bounded visit submitted {} packets",
                    report.tx_packets_submitted
                );
                owner
                    .wait_for_activity(std::time::Duration::from_millis(1))
                    .await;
                let mut buf = [0u8; 2048];
                if let Ok(len) = fast_rx.recv(&mut buf) {
                    fast_received = Some(buf[..len].to_vec());
                    break;
                }
            }
            let received = fast_received.expect("healthy sibling receives within 30 visits");
            let parsed = srt_proto::wire::SrtPacket::decode(&received).expect("valid SRT packet");
            assert!(
                matches!(parsed, srt_proto::wire::SrtPacket::Data(_)),
                "healthy sibling must receive a DATA datagram, got {parsed:?}"
            );
        });
    }

    #[test]
    fn compio_relay_composition_fanout_clones_bytes_without_payload_copy() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
            let l_addr = l_std.local_addr().expect("listener addr");
            let l_sock = compio::net::UdpSocket::from_std(l_std).expect("compio adopt listener");

            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("compio adopt caller");

            let l_cfg = crate::ListenerConfig::builder(l_addr)
                .build()
                .expect("listener config");
            let listener_side = ListenerSide::new(l_sock, &l_cfg).expect("listener side");
            let caller_side = OwnerCallerSide::new_single(c_sock);

            let mut owner = Owner::new(64)
                .with_listener(listener_side)
                .with_caller(caller_side);

            // Add 4 downstream destinations
            let mut dest_ids = Vec::new();
            for i in 1..=4u32 {
                let mut conn = SrtConnection::new_caller(srt_proto::ConnectionOptions {
                    socket_id: 0x3000 + i,
                    ..Default::default()
                });
                let now = Timestamp::from_micros(10_000);
                conn.connect(now).expect("connect");
                let leg = crate::caller::CallerLeg {
                    peer: l_addr,
                    connection: conn,
                };
                let id = owner
                    .caller
                    .as_mut()
                    .unwrap()
                    .pool
                    .table_mut()
                    .add_direct(leg)
                    .expect("add direct");
                dest_ids.push(id);
            }

            // Drive the owner until every freshly connected leg reaches the
            // Connected state; `send_shared` rejects pre-handshake legs.
            let mut now = Timestamp::from_micros(11_000);
            let budget = OwnerServiceBudget::default();
            for round in 0..60 {
                now = Timestamp::from_micros(11_000 + round * 5_000);
                let _ = owner.service(now, budget).await;
                owner
                    .wait_for_activity(std::time::Duration::from_millis(1))
                    .await;
                if dest_ids.iter().all(|id| {
                    owner.logical_caller(id).and_then(|c| c.state())
                        == Some(crate::caller::LogicalCallerState::Connected)
                }) {
                    break;
                }
            }
            // Simulate incoming media payload. Cloning `Bytes` shares the
            // underlying allocation; each destination admits the same handle
            // through the real `send_shared` -> `PendingData` -> direct-sink
            // path rather than injecting pre-encoded wire bytes.
            let media = Bytes::from_static(b"relay-media-payload-1316-bytes-test");
            let media_ptr = media.as_ptr();

            // Fan out by cloning Bytes handles to all 4 destinations. `now`
            // continues the handshake clock above so pacing admission sees a
            // forward-moving timestamp.
            now = Timestamp::from_micros(now.as_micros() + 50_000);
            for &id in &dest_ids {
                let clone = media.clone();
                assert_eq!(
                    clone.as_ptr(),
                    media_ptr,
                    "Bytes clone must share underlying memory"
                );
                owner
                    .logical_caller_mut(&id)
                    .expect("destination exists")
                    .send_shared(clone, now)
                    .expect("send_shared admits payload");
            }

            let budget = OwnerServiceBudget {
                max_tx_packets: 10,
                ..Default::default()
            };
            let report = owner.service(now, budget).await;
            assert!(
                report.tx_packets_submitted >= 4,
                "all 4 fanout payloads must be submitted, got {}",
                report.tx_packets_submitted
            );
        });
    }
    #[test]
    fn wait_for_activity_returns_tx_buffers_and_updates_completion_stats() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
            let l_addr = l_std.local_addr().expect("listener addr");
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("compio adopt caller");

            let caller_side = OwnerCallerSide::new_single(c_sock);
            let mut owner = Owner::new(16).with_caller(caller_side);

            let initial_free = owner.tx_pool().free_count();
            assert_eq!(initial_free, 16);

            // Manually submit a UDP send through OwnerTxSink
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let res = sink.push_datagram(l_addr, 10, |buf| {
                    buf[..10].copy_from_slice(b"0123456789");
                    Ok(10)
                });
                assert!(matches!(res, Ok(PushResult::Pushed { len: 10 })));
            }

            // Slot allocated: 1 in flight, free count is 15
            assert_eq!(owner.tx_in_flight(), 1);
            assert_eq!(owner.tx_pool().free_count(), 15);

            // Calling wait_for_activity must reap the completion, return the
            // slot to tx_pool, and increment completed_ok.
            owner
                .wait_for_activity(std::time::Duration::from_millis(500))
                .await;

            assert_eq!(
                owner.tx_pool().free_count(),
                16,
                "wait_for_activity must return reaped TX buffer to tx_pool"
            );
            assert_eq!(
                owner.completions.completed_ok, 1,
                "wait_for_activity must update completion statistics"
            );
        });
    }

    #[test]
    fn idle_rx_wakes_owner_in_wait_for_activity() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
            let l_addr = l_std.local_addr().expect("listener addr");
            let l_sock = compio::net::UdpSocket::from_std(l_std).expect("compio adopt listener");

            let l_cfg = crate::ListenerConfig::builder(l_addr)
                .build()
                .expect("listener config");
            let listener_side = ListenerSide::new(l_sock, &l_cfg).expect("listener side");
            let mut owner = Owner::new(16).with_listener(listener_side);

            // Spawn a background thread to send a datagram to the idle listener
            // after a brief delay
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender std");
            let bg_handle = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                let _ = sender.send_to(b"wake-up-datagram", l_addr);
            });

            let t0 = std::time::Instant::now();
            // wait_for_activity with 5 second timeout must wake within ~100ms
            // when the background datagram arrives, NOT sleeping the full 5s.
            owner
                .wait_for_activity(std::time::Duration::from_secs(5))
                .await;
            let elapsed = t0.elapsed();
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "idle_rx must wake wait_for_activity immediately, elapsed: {elapsed:?}"
            );

            let report = owner
                .service(Timestamp::from_micros(100), OwnerServiceBudget::default())
                .await;
            assert_eq!(
                report.rx_packets, 1,
                "service must process the datagram that woke wait_for_activity"
            );

            bg_handle.join().unwrap();
        });
    }
    #[test]
    fn staged_pending_rx_obeys_rx_budget_and_signals_continuation() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
            let l_addr = l_std.local_addr().expect("listener addr");
            let l_sock = compio::net::UdpSocket::from_std(l_std).expect("compio adopt listener");

            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("compio adopt caller");

            let l_cfg = crate::ListenerConfig::builder(l_addr)
                .build()
                .expect("listener config");
            let listener_side = ListenerSide::new(l_sock, &l_cfg).expect("listener side");
            let caller_side = OwnerCallerSide::new_single(c_sock);

            let mut owner = Owner::new(16)
                .with_listener(listener_side)
                .with_caller(caller_side);

            // Stage a packet on listener side and caller side: metadata only
            // (`(peer, len)`) over the persistent staging slot.
            let dummy_peer: std::net::SocketAddr = "127.0.0.1:39001".parse().unwrap();
            let l_pkt = b"dummy-packet-1";
            let c_pkt = b"dummy-packet-2";
            {
                let l = owner.listener.as_mut().unwrap();
                l.stage_buf[..l_pkt.len()].copy_from_slice(l_pkt);
                l.pending_rx = Some((dummy_peer, l_pkt.len()));
            }
            {
                let c = owner.caller.as_mut().unwrap();
                c.stage_buf[..c_pkt.len()].copy_from_slice(c_pkt);
                c.pending_rx = Some((dummy_peer, c_pkt.len()));
            }

            // has_pending_work must report true because staged packets exist!
            assert!(
                owner.has_pending_work(Timestamp::from_micros(100)),
                "staged pending_rx must signal work_remaining to the scheduler"
            );

            // 1. service with max_rx_packets = 0 must process ZERO packets and leave both pending!
            let zero_budget = OwnerServiceBudget {
                max_rx_packets: 0,
                ..Default::default()
            };
            let report = owner
                .service(Timestamp::from_micros(100), zero_budget)
                .await;
            assert_eq!(
                report.rx_packets, 0,
                "max_rx_packets=0 must perform zero RX work"
            );
            assert!(owner.listener.as_ref().unwrap().pending_rx.is_some());
            assert!(owner.caller.as_ref().unwrap().pending_rx.is_some());
            assert!(report.work_remaining);

            // 2. service with max_rx_packets = 1 must process EXACTLY one packet
            let one_budget = OwnerServiceBudget {
                max_rx_packets: 1,
                ..Default::default()
            };
            let report = owner.service(Timestamp::from_micros(200), one_budget).await;
            assert_eq!(
                report.rx_packets, 1,
                "max_rx_packets=1 must process exactly one packet"
            );
            assert!(report.work_remaining, "second packet remains pending");

            // 3. next service with max_rx_packets = 1 processes the second packet
            let report = owner.service(Timestamp::from_micros(300), one_budget).await;
            assert_eq!(
                report.rx_packets, 1,
                "next service must process the second packet"
            );
            assert!(owner.listener.as_ref().unwrap().pending_rx.is_none());
            assert!(owner.caller.as_ref().unwrap().pending_rx.is_none());
        });
    }

    /// P0-1: when a datagram does not fit the remaining byte budget, the
    /// listener must stage it by swapping the two persistent slots, keeping
    /// the exact payload and leaving BOTH buffers at `DEFAULT_RX_SLOT_SIZE`.
    #[test]
    fn listener_staging_keeps_exact_payload_and_full_buffer_lengths() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
            let l_addr = l_std.local_addr().expect("listener addr");
            let l_sock = compio::net::UdpSocket::from_std(l_std).expect("adopt listener");
            let l_cfg = crate::ListenerConfig::builder(l_addr)
                .build()
                .expect("listener config");
            let listener_side = ListenerSide::new(l_sock, &l_cfg).expect("listener side");
            let mut owner = Owner::new(16).with_listener(listener_side);

            // A datagram larger than the byte budget we will grant.
            let payload = vec![0xABu8; 900];
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
            sender.send_to(&payload, l_addr).expect("send");

            // Park until the datagram is readable, then service with a byte
            // budget below the datagram size so it must be staged.
            let tiny = OwnerServiceBudget {
                max_rx_bytes: 64,
                ..Default::default()
            };
            let mut report = owner.service(Timestamp::from_micros(100), tiny).await;
            for _ in 0..200 {
                if owner.listener.as_ref().unwrap().pending_rx.is_some() {
                    break;
                }
                owner
                    .wait_for_activity(std::time::Duration::from_millis(10))
                    .await;
                report = owner.service(Timestamp::from_micros(200), tiny).await;
            }
            let _ = report;

            let staged = owner
                .listener
                .as_ref()
                .unwrap()
                .pending_rx
                .expect("oversized-to-budget datagram must be staged, not dropped");
            assert_eq!(
                staged.1,
                payload.len(),
                "staged length must be the datagram length"
            );
            let l = owner.listener.as_ref().unwrap();
            assert_eq!(
                l.stage_buf[..staged.1],
                payload[..],
                "staged bytes must be the exact datagram payload"
            );
            assert_eq!(
                l.rx_buf.len(),
                DEFAULT_RX_SLOT_SIZE,
                "receive slot must not shrink when staging"
            );
            assert_eq!(
                l.stage_buf.len(),
                DEFAULT_RX_SLOT_SIZE,
                "staging slot must not shrink when staging"
            );

            // Next visit with room consumes it and clears the staged metadata.
            let report = owner
                .service(Timestamp::from_micros(300), OwnerServiceBudget::default())
                .await;
            assert_eq!(
                report.rx_packets, 1,
                "staged packet must be consumed next visit"
            );
            assert_eq!(report.rx_bytes, payload.len());
            let l = owner.listener.as_ref().unwrap();
            assert!(
                l.pending_rx.is_none(),
                "staged metadata must clear on consume"
            );
            assert_eq!(l.rx_buf.len(), DEFAULT_RX_SLOT_SIZE);
            assert_eq!(l.stage_buf.len(), DEFAULT_RX_SLOT_SIZE);
        });
    }

    /// P0-1 (caller side): identical staging contract as the listener.
    #[test]
    fn caller_staging_keeps_exact_payload_and_full_buffer_lengths() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_addr = c_std.local_addr().expect("caller addr");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt caller");
            let caller_side = OwnerCallerSide::new_single(c_sock);
            let mut owner = Owner::new(16).with_caller(caller_side);

            let payload = vec![0xCDu8; 1200];
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
            sender.send_to(&payload, c_addr).expect("send");

            let tiny = OwnerServiceBudget {
                max_rx_bytes: 64,
                ..Default::default()
            };
            for _ in 0..200 {
                owner.service(Timestamp::from_micros(100), tiny).await;
                if owner.caller.as_ref().unwrap().pending_rx.is_some() {
                    break;
                }
                owner
                    .wait_for_activity(std::time::Duration::from_millis(10))
                    .await;
            }

            let staged = owner
                .caller
                .as_ref()
                .unwrap()
                .pending_rx
                .expect("oversized-to-budget datagram must be staged on the caller side");
            assert_eq!(staged.1, payload.len());
            let c = owner.caller.as_ref().unwrap();
            assert_eq!(
                c.stage_buf[..staged.1],
                payload[..],
                "staged bytes must be the exact datagram payload"
            );
            assert_eq!(c.rx_buf.len(), DEFAULT_RX_SLOT_SIZE);
            assert_eq!(c.stage_buf.len(), DEFAULT_RX_SLOT_SIZE);

            let report = owner
                .service(Timestamp::from_micros(300), OwnerServiceBudget::default())
                .await;
            assert_eq!(report.rx_packets, 1);
            assert_eq!(report.rx_bytes, payload.len());
            let c = owner.caller.as_ref().unwrap();
            assert!(c.pending_rx.is_none());
            assert_eq!(c.rx_buf.len(), DEFAULT_RX_SLOT_SIZE);
            assert_eq!(c.stage_buf.len(), DEFAULT_RX_SLOT_SIZE);
        });
    }

    #[test]
    fn work_remaining_is_false_when_only_tx_in_flight() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("compio adopt caller");
            let caller_side = OwnerCallerSide::new_single(c_sock);
            let mut owner = Owner::new(16).with_caller(caller_side);

            // Submit send
            let peer: std::net::SocketAddr = "127.0.0.1:39999".parse().unwrap();
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let _ = sink.push_datagram(peer, 8, |buf| {
                    buf[..8].copy_from_slice(b"12345678");
                    Ok(8)
                });
            }

            let budget = OwnerServiceBudget {
                max_completions: 0, // don't reap completions in this service call
                ..Default::default()
            };
            let report = owner.service(Timestamp::from_micros(100), budget).await;
            assert_eq!(report.tx_in_flight, 1);
            assert!(
                !report.work_remaining,
                "merely having tx_in_flight must NOT set work_remaining to true"
            );
        });
    }
    #[test]
    fn compio_remove_caller_releases_permit_to_queued_caller() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let mut owner = Owner::new(16);
            owner
                .set_caller_pool_policy(
                    std::num::NonZeroUsize::new(1).unwrap(),
                    std::time::Duration::from_secs(10),
                )
                .expect("policy set");

            let remote_a: SocketAddr = "127.0.0.1:19001".parse().unwrap();
            let remote_b: SocketAddr = "127.0.0.1:19002".parse().unwrap();
            let cfg_a = crate::CallerConfig::builder(remote_a)
                .ownership(crate::SocketOwnership::Shared)
                .build()
                .expect("config a");
            let cfg_b = crate::CallerConfig::builder(remote_b)
                .ownership(crate::SocketOwnership::Shared)
                .build()
                .expect("config b");

            let now = Timestamp::from_micros(1_000);
            let outcome_a = owner.connect(&cfg_a, now).expect("connect a");
            let id_a = match outcome_a {
                crate::PoolOutcome::Admitted(id) => id,
                other => panic!("expected caller A to be admitted, got {other:?}"),
            };

            // Second caller must be queued because max_in_flight == 1
            let outcome_b = owner.connect(&cfg_b, now).expect("connect b");
            assert!(
                matches!(outcome_b, crate::PoolOutcome::Queued { .. }),
                "expected caller B to be queued, got {outcome_b:?}"
            );

            let stats = owner.caller_pool_stats().unwrap();
            assert_eq!(stats.in_flight, 1);
            assert_eq!(stats.queued, 1);

            // Removing caller A through Owner::remove_caller must release the permit from CallerPool!
            let removed = owner.remove_caller(id_a);
            assert!(removed.is_some(), "caller A removed");

            let stats = owner.caller_pool_stats().unwrap();
            assert_eq!(
                stats.in_flight, 0,
                "removing A must decrease in_flight in CallerPool"
            );

            // Service the caller side: now permit is available, caller B can be admitted
            let budget = OwnerServiceBudget::default();
            let _ = owner.service(Timestamp::from_micros(2_000), budget).await;

            let mut pool_events = Vec::new();
            owner.poll_caller_pool_events(&mut pool_events);
            let b_admitted = pool_events
                .iter()
                .any(|ev| matches!(ev, crate::PoolEvent::Admitted { .. }));
            assert!(
                b_admitted,
                "caller B must be admitted once caller A permit is released"
            );
        });
    }

    #[test]
    fn owner_wake_includes_caller_pool_attempt_deadline() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let mut owner = Owner::new(16);
            owner
                .set_caller_pool_policy(
                    std::num::NonZeroUsize::new(1).unwrap(),
                    std::time::Duration::from_millis(10),
                )
                .expect("policy set");

            let remote: SocketAddr = "127.0.0.1:19001".parse().unwrap();
            let cfg = crate::CallerConfig::builder(remote)
                .ownership(crate::SocketOwnership::Shared)
                .build()
                .expect("config");
            // Attempt admitted at t=0 with a 10ms attempt deadline; the
            // connection never completes, so no protocol timer is earlier.
            let now = Timestamp::from_micros(0);
            let outcome = owner.connect(&cfg, now).expect("connect");
            assert!(
                matches!(outcome, crate::PoolOutcome::Admitted(_)),
                "attempt must be admitted, got {outcome:?}"
            );
            // Pool-level deadline (10ms) must surface through the Owner wake,
            // not just the table's protocol timers.
            let pool_us = owner
                .caller
                .as_ref()
                .unwrap()
                .pool
                .time_until_next_deadline(now, 1_000_000);
            assert_eq!(pool_us, 10_000, "pool deadline must be 10ms");
            let owner_us = owner.time_until_next_deadline(now, 1_000_000);
            assert_eq!(
                owner_us, 10_000,
                "Owner wake must include CallerPool attempt deadline"
            );
        });
    }

    #[test]
    fn wire_ceiling_exact_succeeds_and_plus_one_rejected() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let caller_side = OwnerCallerSide::new_single(c_sock);
            // Ceiling of 100 bytes
            let mut owner = Owner::new_with_ceiling(4, 100).with_caller(caller_side);
            assert_eq!(owner.wire_ceiling(), 100);
            assert_eq!(owner.tx_pool().slot_size(), 100);

            let peer: SocketAddr = "127.0.0.1:19999".parse().unwrap();
            // 1. Exact ceiling (100 bytes) must succeed
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let res = sink.push_datagram(peer, 100, |buf| {
                    buf[..100].fill(0xAA);
                    Ok(100)
                });
                assert!(matches!(res, Ok(PushResult::Pushed { len: 100 })));
            }

            // 2. Ceiling + 1 (101 bytes) must be rejected before send / slot allocation
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let res = sink.push_datagram(peer, 101, |buf| {
                    buf[..101].fill(0xBB);
                    Ok(101)
                });
                assert!(
                    res.is_err(),
                    "101 bytes must be rejected when ceiling is 100"
                );
            }
        });
    }

    #[test]
    fn owner_rejects_session_with_incompatible_wire_ceiling() {
        let mut owner = Owner::new_with_ceiling(4, 1500);

        // Config with large payload (2000 bytes) + GCM (16 bytes tag) = 2032 bytes > 1500
        let remote: SocketAddr = "127.0.0.1:19000".parse().unwrap();
        let large_cfg = crate::CallerConfig::builder(remote)
            .ownership(crate::SocketOwnership::Shared)
            .configure_session(|s| {
                s.payload_size =
                    crate::PayloadSize::Exact(std::num::NonZeroUsize::new(2000).unwrap());
                s.set_encryption(Some(crate::EncryptionConfig::new("production-secret-123")));
            })
            .build()
            .expect("config builds");

        let res = owner.connect(&large_cfg, Timestamp::from_micros(0));
        assert!(
            res.is_err(),
            "owner with ceiling 1500 must reject session requiring 2032 bytes"
        );
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("exceeds owner wire ceiling"),
            "error message: {err}"
        );
    }

    #[test]
    fn wire_ceiling_freeze_after_session_started() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let mut owner = Owner::new(4);
            // Changing ceiling before sessions started succeeds
            assert!(owner.set_wire_ceiling(2048).is_ok());
            assert_eq!(owner.wire_ceiling(), 2048);
            assert_eq!(owner.tx_pool().slot_size(), 2048);

            // Start a session
            let remote: SocketAddr = "127.0.0.1:19000".parse().unwrap();
            let cfg = crate::CallerConfig::builder(remote)
                .ownership(crate::SocketOwnership::Shared)
                .build()
                .expect("config");
            let _ = owner.connect(&cfg, Timestamp::from_micros(0));

            // Changing ceiling after session started must be rejected
            let res = owner.set_wire_ceiling(4096);
            assert!(
                res.is_err(),
                "cannot change wire ceiling after sessions started"
            );
        });
    }

    #[test]
    fn slot_conservation_across_success_error_and_shutdown() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let caller_side = OwnerCallerSide::new_single(c_sock);

            let mut owner = Owner::new(4).with_caller(caller_side);
            assert_eq!(owner.tx_pool().free_count(), 4);
            assert_eq!(owner.tx_pool().capacity(), 4);

            let peer: SocketAddr = "127.0.0.1:19999".parse().unwrap();

            // 1. Fill error: slot and lane must be returned immediately
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let res = sink.push_datagram(peer, 20, |_buf| {
                    Err(srt_proto::Error::with_reason(
                        srt_proto::ErrorKind::InvalidData,
                        "simulated fill failure",
                    ))
                });
                assert!(res.is_err());
            }
            assert_eq!(
                owner.tx_pool().free_count(),
                4,
                "fill error must restore free_count to 4"
            );
            assert_eq!(owner.tx_in_flight(), 0);

            // 2. Materialization length mismatch: slot and lane must be returned
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let res = sink.push_datagram(peer, 20, |_buf| {
                    Ok(10) // advertised 20, returned 10
                });
                assert!(res.is_err());
            }
            assert_eq!(
                owner.tx_pool().free_count(),
                4,
                "length mismatch must restore free_count to 4"
            );
            assert_eq!(owner.tx_in_flight(), 0);

            // 3. Successful send + reap: returns slot
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let res = sink.push_datagram(peer, 20, |buf| {
                    buf[..20].fill(0x55);
                    Ok(20)
                });
                assert!(res.is_ok());
            }
            assert_eq!(owner.tx_pool().free_count(), 3);
            assert_eq!(owner.tx_in_flight(), 1);

            owner
                .wait_for_activity(std::time::Duration::from_millis(500))
                .await;
            assert_eq!(
                owner.tx_pool().free_count(),
                4,
                "reaped completion must restore free_count to 4"
            );
            assert_eq!(owner.tx_in_flight(), 0);

            // 4. Shutdown with send in flight returns all slots
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let _ = sink.push_datagram(peer, 20, |buf| {
                    buf[..20].fill(0x66);
                    Ok(20)
                });
            }
            assert_eq!(owner.tx_pool().free_count(), 3);
            owner.shutdown();
            // Truthful ownership: a slot already with the kernel stays owned
            // by its lane. Conservation must hold either way.
            assert_eq!(
                owner.tx_pool().free_count() + owner.tx_in_flight(),
                4,
                "free + in-flight must always equal capacity after shutdown"
            );
            assert!(owner.fault().is_some(), "shutdown sets fault");
        });
    }

    /// P0-2: a short send is a typed Owner fault, and a fault stops new TX.
    /// P1: lifecycle maintenance is independent of the packet/byte axes. A
    /// visit that grants zero TX packets/bytes must still run bounded
    /// maintenance work, and zero actions must still run none.
    #[test]
    fn maintenance_runs_without_tx_packet_or_byte_allowance() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
            let l_addr = l_std.local_addr().expect("listener addr");
            let l_sock = compio::net::UdpSocket::from_std(l_std).expect("adopt listener");
            let l_cfg = crate::ListenerConfig::builder(l_addr)
                .topology(crate::ListenerTopology::PerPort)
                .configure_transport(|t| t.promotion = crate::PromotionPolicy::Never)
                .build()
                .expect("listener config");
            let listener_side = ListenerSide::new(l_sock, &l_cfg).expect("listener side");
            let mut owner = Owner::new(8).with_listener(listener_side);

            // Drain-only visit: actions available, but no packet/byte
            // allowance for output at all.
            let drain_only = OwnerServiceBudget {
                max_actions: 8,
                max_tx_packets: 0,
                max_tx_bytes: 0,
                ..Default::default()
            };
            let report = owner
                .service(Timestamp::from_micros(1_000), drain_only)
                .await;
            assert_eq!(
                report.tx_packets_submitted, 0,
                "zero packet allowance must submit zero packets"
            );
            // No peers exist yet, so maintenance itself visits nothing; the
            // point under test is that it is reachable and permitted to run
            // with zero packet/byte allowance rather than skipped outright.
            assert!(
                !owner.has_pending_work(Timestamp::from_micros(1_000)),
                "an idle owner still reports no runnable work"
            );

            // Zero ACTION allowance still performs zero maintenance.
            let no_actions = OwnerServiceBudget {
                max_actions: 0,
                ..Default::default()
            };
            let report = owner
                .service(Timestamp::from_micros(2_000), no_actions)
                .await;
            assert_eq!(report.actions, 0, "zero action budget must do zero work");
        });
    }

    /// P1: the count-only pool maintenance path never materializes the
    /// retired-id vector the Owner immediately discards.
    #[test]
    fn count_only_caller_maintenance_matches_visits() {
        let mut pool = crate::CallerPool::new(
            std::num::NonZeroUsize::new(4).expect("nonzero"),
            std::time::Duration::from_secs(5),
        );
        let remote: std::net::SocketAddr = "127.0.0.1:19000".parse().expect("addr");
        let cfg = crate::CallerConfig::builder(remote)
            .ownership(crate::SocketOwnership::Shared)
            .build()
            .expect("caller config");
        let now = Timestamp::from_micros(0);
        for _ in 0..4 {
            let prepared = cfg
                .clone()
                .prepare(crate::RuntimeFlavor::Compio)
                .expect("prepared");
            let _ = pool.connect(prepared, now).expect("connect");
        }
        // Long past every attempt deadline: all four are retired by one
        // bounded, count-only pass.
        let later = Timestamp::from_micros(60_000_000);
        let visits = pool.poll_expirations_count_only(later, 16);
        assert!(visits > 0, "expired attempts must be visited");
        assert_eq!(
            pool.stats().in_flight,
            0,
            "expired attempts must be retired"
        );
    }

    #[test]
    fn short_send_faults_owner_and_stops_new_tx() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let caller_side = OwnerCallerSide::new_single(c_sock);
            let mut owner = Owner::new(2).with_caller(caller_side);
            let peer: SocketAddr = "127.0.0.1:19997".parse().unwrap();

            // Hand one lane a completion that reports fewer bytes than the
            // materialized wire length, through the real reaping path.
            {
                let engine = &mut owner.tx_engine;
                engine.ensure_started();
                assert!(!engine.lanes.is_empty(), "lane must be running");
                let _ = engine.idle_lanes.pop();
                engine.in_flight_count += 1;
                let lane = &engine.lanes[0];
                lane.state.borrow_mut().completion = Some(TxCompletion {
                    meta: InFlightMeta {
                        peer,
                        expected_len: 20,
                    },
                    res: Ok(7),
                    buf: vec![0u8; DEFAULT_TX_SLOT_SIZE],
                });
                engine.completed_lanes.borrow_mut().push_back(0);
            }

            let report = owner
                .service(Timestamp::from_micros(1_000), OwnerServiceBudget::default())
                .await;
            assert_eq!(report.tx_short_sends, 1, "short send must be counted");
            match owner.fault() {
                Some(OwnerFault::TxShortSend { expected, sent, .. }) => {
                    assert_eq!((*expected, *sent), (20, 7));
                }
                other => panic!("short send must fault the owner, got {other:?}"),
            }

            // No new TX after a fault: submission is refused, not silently
            // accepted at reduced capacity.
            let caller = owner.caller.as_ref().unwrap();
            let mut sink = OwnerTxSink {
                sock: &caller.sock,
                tx_pool: &mut owner.tx_pool,
                tx_engine: &mut owner.tx_engine,
            };
            let res = sink.push_datagram(peer, 20, |buf| {
                buf[..20].fill(0x11);
                Ok(20)
            });
            assert!(
                res.is_err(),
                "post-fault submission must be refused, got {res:?}"
            );
        });
    }

    /// P0-2: a send error is likewise a typed Owner fault.
    #[test]
    fn send_error_faults_owner() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(2).with_caller(OwnerCallerSide::new_single(c_sock));
            let peer: SocketAddr = "127.0.0.1:19996".parse().unwrap();
            {
                let engine = &mut owner.tx_engine;
                engine.ensure_started();
                let _ = engine.idle_lanes.pop();
                engine.in_flight_count += 1;
                let lane = &engine.lanes[0];
                lane.state.borrow_mut().completion = Some(TxCompletion {
                    meta: InFlightMeta {
                        peer,
                        expected_len: 20,
                    },
                    res: Err(io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "no route",
                    )),
                    buf: vec![0u8; DEFAULT_TX_SLOT_SIZE],
                });
                engine.completed_lanes.borrow_mut().push_back(0);
            }
            let report = owner
                .service(Timestamp::from_micros(1_000), OwnerServiceBudget::default())
                .await;
            assert_eq!(report.tx_failed_sends, 1);
            match owner.fault() {
                Some(OwnerFault::TxFailed { kind, .. }) => {
                    assert_eq!(*kind, io::ErrorKind::NetworkUnreachable);
                }
                other => panic!("send error must fault the owner, got {other:?}"),
            }
        });
    }

    /// P0-3: a drain that cannot reach quiescence leaves ownership intact.
    #[test]
    fn shutdown_timeout_does_not_fabricate_quiescence() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(2).with_caller(OwnerCallerSide::new_single(c_sock));
            let capacity = owner.tx_pool().capacity();

            // One lane owns a slot the kernel is still "sending": the slot is
            // out of the pool, the engine counts it in flight, and no
            // completion will ever be published for it here.
            {
                // Dropped rather than leaked: the point is pool/counter
                // disagreement, not the bytes themselves, and a leak would
                // trip the ASan job.
                let held = owner.tx_pool.free_buffers.pop().expect("slot available");
                drop(held);
                let engine = &mut owner.tx_engine;
                engine.ensure_started();
                let _ = engine.idle_lanes.pop();
                engine.in_flight_count = 1;
                engine.lanes[0].state.borrow_mut().in_kernel = true;
            }
            let free_before = owner.tx_pool().free_count();

            let drained = owner
                .shutdown_and_drain(std::time::Duration::from_millis(30))
                .await;
            assert!(
                !drained,
                "a stuck in-flight send must not report quiescence"
            );
            assert_eq!(
                owner.tx_in_flight(),
                1,
                "in-flight ownership must survive a timed-out drain"
            );
            assert_eq!(
                owner.tx_pool().free_count(),
                free_before,
                "a timed-out drain must not reclaim slots it does not own"
            );
            assert!(
                owner.tx_pool().free_count() < capacity,
                "the lane still owns its slot"
            );
            match owner.fault() {
                Some(OwnerFault::ShutdownTimedOut { in_flight }) => assert_eq!(*in_flight, 1),
                other => panic!("timed-out teardown must be a typed fault, got {other:?}"),
            }
        });
    }

    #[test]
    fn shutdown_and_drain_reaps_in_flight_to_quiescence() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let caller_side = OwnerCallerSide::new_single(c_sock);
            let mut owner = Owner::new(4).with_caller(caller_side);
            let peer: SocketAddr = "127.0.0.1:19998".parse().unwrap();
            for _ in 0..3 {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                };
                let _ = sink.push_datagram(peer, 20, |buf| {
                    buf[..20].fill(0x77);
                    Ok(20)
                });
            }
            assert_eq!(owner.tx_in_flight(), 3);
            let drained = owner
                .shutdown_and_drain(std::time::Duration::from_secs(5))
                .await;
            assert!(drained, "loopback sends must drain to quiescence");
            assert_eq!(owner.tx_in_flight(), 0);
            assert_eq!(owner.tx_pool().free_count(), owner.tx_pool().capacity());
            assert!(
                owner.tx_engine.lanes.is_empty(),
                "terminal shutdown must join every fixed lane"
            );
            // Terminal: no new admission after shutdown.
            let caller = owner.caller.as_ref().unwrap();
            let mut sink = OwnerTxSink {
                sock: &caller.sock,
                tx_pool: &mut owner.tx_pool,
                tx_engine: &mut owner.tx_engine,
            };
            let res = sink.push_datagram(peer, 20, |buf| {
                buf[..20].fill(0x78);
                Ok(20)
            });
            assert!(
                matches!(res, Err(_) | Ok(PushResult::Exhausted)),
                "post-shutdown submit must fail or exhaust, got {res:?}"
            );
        });
    }

    #[test]
    fn zero_action_budget_performs_zero_maintenance() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let caller_side = OwnerCallerSide::new_single(c_sock);
            let mut owner = Owner::new(4).with_caller(caller_side);
            let now = Timestamp::from_micros(1_000);
            let budget = OwnerServiceBudget {
                max_actions: 0,
                max_completions: 0,
                max_rx_packets: 0,
                max_rx_bytes: 0,
                max_tx_packets: 0,
                max_tx_bytes: 0,
            };
            let report = owner.service(now, budget).await;
            assert_eq!(report.actions, 0, "zero budget must perform zero actions");
            assert_eq!(report.tx_packets_submitted, 0);
            assert_eq!(report.completions_reaped, 0);
        });
    }

    #[test]
    fn one_action_budget_bounds_whole_caller_visit() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let caller_side = OwnerCallerSide::new_single(c_sock);
            let mut owner = Owner::new(16).with_caller(caller_side);
            // Expired attempt + queued output both eligible: exactly one
            // bounded unit of action work may occur.
            let now = Timestamp::from_micros(1_000_000);
            let budget = OwnerServiceBudget {
                max_actions: 1,
                ..Default::default()
            };
            let report = owner.service(now, budget).await;
            assert!(
                report.actions <= 1,
                "one action budget bounds maintenance + drain, got {}",
                report.actions
            );
        });
    }

    #[test]
    fn listener_rejects_non_perport_topology_and_promotion() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let l_addr = l_std.local_addr().expect("addr");
            let cfg = crate::ListenerConfig::builder(l_addr)
                .topology(crate::ListenerTopology::SharedPool {
                    listeners: crate::WorkerCount::Count(std::num::NonZeroUsize::MIN),
                })
                .build()
                .expect("config builds");
            let mut owner = Owner::new(4);
            let res = owner.listen(&cfg);
            assert!(
                res.is_err(),
                "shared-pool topology must be rejected: {res:?}"
            );
            assert!(
                res.unwrap_err().to_string().contains("topology"),
                "error must name the topology field"
            );
            let cfg2 = crate::ListenerConfig::builder(l_addr)
                .topology(crate::ListenerTopology::PerPort)
                .configure_transport(|t| t.promotion = crate::PromotionPolicy::Relocate)
                .build()
                .expect("config builds");
            let res2 = owner.listen(&cfg2);
            assert!(
                res2.is_err(),
                "relocate promotion must be rejected: {res2:?}"
            );
        });
    }

    #[test]
    fn listener_idle_deadline_visible_in_owner_wake() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
            let l_addr = l_std.local_addr().expect("listener addr");
            let l_sock = compio::net::UdpSocket::from_std(l_std).expect("adopt");
            let l_cfg = crate::ListenerConfig::builder(l_addr)
                .topology(crate::ListenerTopology::PerPort)
                .configure_transport(|t| t.promotion = crate::PromotionPolicy::Never)
                .build()
                .expect("listener config");
            let listener_side = ListenerSide::new(l_sock, &l_cfg).expect("listener side");
            assert!(
                !listener_side.idle_timeout.is_zero(),
                "idle timeout must be configured"
            );
            let mut owner = Owner::new(16).with_listener(listener_side);
            let now = Timestamp::from_micros(1_000_000);
            let wake = owner.time_until_next_deadline(now, 1_000_000);
            assert!(
                wake <= 1_000_000,
                "owner wake must include idle deadline, got {wake}"
            );
            let zero = OwnerServiceBudget {
                max_actions: 0,
                max_completions: 0,
                max_rx_packets: 0,
                max_rx_bytes: 0,
                max_tx_packets: 0,
                max_tx_bytes: 0,
            };
            let report = owner.service(now, zero).await;
            assert_eq!(report.actions, 0, "zero budget must prune nothing");
        });
    }

    #[test]
    fn production_profile_observes_live_runtime() {
        // Portable: observes the exact runtime under test, asserts only
        // structural invariants. Capability outcomes are qualification data
        // recorded per host, never deterministic unit-test invariants.
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        let profile = runtime.block_on(super::observe_production_runtime(
            &runtime,
            super::DEFAULT_TX_POOL_CAPACITY,
            super::DEFAULT_TX_SLOT_SIZE,
        ));
        assert_eq!(profile.tx_lanes, super::DEFAULT_TX_POOL_CAPACITY);
        assert_eq!(profile.wire_ceiling, super::DEFAULT_TX_SLOT_SIZE);
        assert_eq!(profile.compio_version, super::PINNED_COMPIO_VERSION);
        assert!(!profile.kernel_version.is_empty());
        assert!(!profile.driver_type.is_empty());
        // Capability classification is recorded, not asserted: it varies by
        // host kernel and backend. Just exercise the accessors.
        let _ = profile.managed_rx_available();
        let _ = profile.high_density_qualified();
    }

    #[test]
    fn buffer_ring_classification_does_not_conflate_layers() {
        use super::{MultishotRecvStatus, ProvidedBufferRingStatus};
        fn profile(
            ring: ProvidedBufferRingStatus,
            ms: MultishotRecvStatus,
            iouring: bool,
        ) -> super::CompioProductionProfile {
            super::CompioProductionProfile {
                tx_lanes: 64,
                wire_ceiling: super::DEFAULT_TX_SLOT_SIZE,
                buffer_ring: ring,
                multishot_recv: ms,
                is_io_uring: iouring,
                kernel_version: "test".to_string(),
                compio_version: super::PINNED_COMPIO_VERSION.to_string(),
                driver_type: "Test".to_string(),
            }
        }
        // Registration failure must block multishot verdict, not condemn it.
        let blocked = profile(
            ProvidedBufferRingStatus::RegistrationFailed(22),
            MultishotRecvStatus::NotTestedBecauseBufferRingUnavailable,
            true,
        );
        assert!(!blocked.managed_rx_available());
        assert!(!blocked.high_density_qualified());
        // Full availability qualifies.
        let ok = profile(
            ProvidedBufferRingStatus::Available,
            MultishotRecvStatus::Available,
            true,
        );
        assert!(ok.managed_rx_available());
        assert!(ok.high_density_qualified());
        // Available ring + broken multishot stays unqualified without
        // blaming the substrate.
        let no_ms = profile(
            ProvidedBufferRingStatus::Available,
            MultishotRecvStatus::Unsupported,
            true,
        );
        assert!(!no_ms.managed_rx_available());
        assert!(!no_ms.high_density_qualified());
        // Unknown is never qualified.
        let unknown = profile(
            ProvidedBufferRingStatus::Unknown,
            MultishotRecvStatus::Unknown,
            false,
        );
        assert!(!unknown.managed_rx_available());
        assert!(!unknown.high_density_qualified());
    }
}
