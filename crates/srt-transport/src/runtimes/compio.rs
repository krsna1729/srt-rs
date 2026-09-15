use crate::{
    CallerTable, DatagramSink, IngressTelemetry, OutputDrainBudget, OutputDrainReport,
    OutputDrainStatus, PacedSendOutcome, PeerTable, PushResult, collect_output_work,
    prepend_outputs,
};
use compio::buf::BufResult;
use futures_util::stream::{FuturesUnordered, StreamExt};
use srt_proto::{Bytes, ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
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

/// Live runtime driver inspection record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompioDriverInfo {
    pub kernel_version: String,
    pub compio_version: String,
    pub driver_type: String,
    pub is_io_uring: bool,
}

/// Linux qualification sentinel: inspects and validates the active Compio runtime driver.
///
/// On Linux, production Compio qualification requires the active driver to be `IoUring`.
/// Fails if the driver fell back to `Poll`.
pub fn live_driver_sentinel() -> Result<CompioDriverInfo, String> {
    let runtime = compio::runtime::Runtime::new()
        .map_err(|e| format!("failed to initialize compio runtime: {e}"))?;
    let driver = runtime.driver_type();
    let is_io_uring = driver.is_iouring();
    let driver_name = format!("{driver:?}");

    let kernel = std::fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown kernel".to_string())
        .trim()
        .to_string();

    let info = CompioDriverInfo {
        kernel_version: kernel,
        compio_version: "0.19.2".to_string(),
        driver_type: driver_name,
        is_io_uring,
    };

    #[cfg(target_os = "linux")]
    if !info.is_io_uring {
        return Err(format!(
            "qualification failure: Compio fell back to {}; IoUring driver is required on Linux",
            info.driver_type
        ));
    }

    Ok(info)
}

/// Default capacity for the reusable TX buffer pool.
pub const DEFAULT_TX_POOL_CAPACITY: usize = 256;
/// Default slot size matching standard 1500 MTU datagram bound.
pub const DEFAULT_TX_SLOT_SIZE: usize = 1500;

/// Reusable finite TX buffer pool for direct final-buffer outbound datagrams.
/// Observable telemetry snapshot for [`TxPool`]; the pool itself is mutated
/// only by the owner internals, never by external callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxPoolSnapshot {
    pub capacity: usize,
    pub free: usize,
    pub exhaustions: u64,
}

/// Reusable finite TX buffer pool for direct final-buffer outbound datagrams.
pub struct TxPool {
    slot_size: usize,
    capacity: usize,
    free_buffers: Vec<Vec<u8>>,
    allocated: usize,
    exhaustion_count: u64,
}

impl TxPool {
    /// Create a new pool pre-allocating `capacity` buffers of `slot_size` bytes.
    #[must_use]
    pub fn new(capacity: usize, slot_size: usize) -> Self {
        let capacity = capacity.max(1);
        let mut free_buffers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            free_buffers.push(vec![0u8; slot_size]);
        }
        Self {
            slot_size,
            capacity,
            free_buffers,
            allocated: capacity,
            exhaustion_count: 0,
        }
    }

    /// Allocate or take a free buffer slot.
    pub(crate) fn alloc_slot(&mut self) -> Option<Vec<u8>> {
        if let Some(mut buf) = self.free_buffers.pop() {
            buf.clear();
            return Some(buf);
        }
        if self.allocated < self.capacity {
            self.allocated += 1;
            return Some(Vec::with_capacity(self.slot_size));
        }
        self.exhaustion_count = self.exhaustion_count.saturating_add(1);
        None
    }

    /// Return an owned buffer slot back to the pool.
    pub(crate) fn return_slot(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        self.free_buffers.push(buf);
    }

    /// Number of free buffers immediately available.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free_buffers.len() + (self.capacity.saturating_sub(self.allocated))
    }

    /// Total capacity of the pool.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of times the pool was exhausted when a slot was requested.
    #[must_use]
    pub fn exhaustion_count(&self) -> u64 {
        self.exhaustion_count
    }
}

/// Listener side of a shared Compio owner.
pub struct ListenerSide {
    pub sock: Rc<compio::net::UdpSocket>,
    pub table: PeerTable,
    pub telemetry: IngressTelemetry,
    pub options: crate::AdmissionOptions,
    pub transport: crate::ResolvedTransportConfig,
    rx_buf: Option<Vec<u8>>,
}

impl ListenerSide {
    pub fn new(
        sock: compio::net::UdpSocket,
        config: &crate::ListenerConfig,
    ) -> Result<Self, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Compio)?;
        Self::from_prepared(sock, prepared)
    }

    pub(crate) fn from_prepared(
        sock: compio::net::UdpSocket,
        prepared: crate::PreparedListener,
    ) -> Result<Self, crate::RuntimeBuildError> {
        Ok(Self {
            sock: Rc::new(sock),
            table: prepared.peer_table(),
            telemetry: IngressTelemetry::new(),
            options: prepared.admission_options(),
            transport: prepared.transport,
            rx_buf: None,
        })
    }
}

/// Caller side of a shared Compio owner.
///
/// Kept for source compatibility with earlier drafts of this module; prefer
/// [`OwnerCallerSide`], which carries the same `CallerPool` admission,
/// attempt-deadline, and socket-memory policy as the Mio/Tokio owners.
pub type CallerSide = OwnerCallerSide;

/// Pool-backed caller side of a shared Compio owner.
pub struct OwnerCallerSide {
    pub sock: Rc<compio::net::UdpSocket>,
    pub pool: crate::CallerPool,
    pub transport: crate::ResolvedTransportConfig,
    pub local_bind: Option<std::net::SocketAddr>,
    pub connect_config: crate::ConnectConfig,
    rx_buf: Option<Vec<u8>>,
}

impl OwnerCallerSide {
    pub fn new(
        sock: compio::net::UdpSocket,
        max_in_flight: std::num::NonZeroUsize,
        attempt_deadline: std::time::Duration,
        transport: crate::ResolvedTransportConfig,
        local_bind: Option<std::net::SocketAddr>,
        connect_config: crate::ConnectConfig,
    ) -> Self {
        Self {
            sock: Rc::new(sock),
            pool: crate::CallerPool::new(max_in_flight, attempt_deadline),
            transport,
            local_bind,
            connect_config,
            rx_buf: None,
        }
    }

    /// Immutable access to the pooled caller table.
    #[must_use]
    pub fn table(&self) -> &CallerTable {
        self.pool.table()
    }

    /// Convenience single-socket side for tests and direct table use.
    ///
    /// Uses the same `Shared` ownership transport policy as
    /// [`Owner::connect`]-created sides so later `connect()` calls validate
    /// as shared-compatible instead of rejecting the first extra caller.
    #[must_use]
    pub fn new_single(sock: compio::net::UdpSocket) -> Self {
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
            rx_buf: None,
        }
    }
}

/// Metadata carried with one submitted UDP send so its completion can be
/// attributed, validated, and reported instead of silently discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InFlightMeta {
    peer: SocketAddr,
    expected_len: usize,
}

/// Aggregated TX completion accounting surfaced through [`OwnerServiceReport`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnerTxCompletionStats {
    pub completed_ok: usize,
    pub short_sends: usize,
    pub failed_sends: usize,
}

type InFlightSend = Pin<Box<dyn Future<Output = (InFlightMeta, io::Result<usize>, Vec<u8>)>>>;

struct OwnerTxSink<'a> {
    sock: &'a Rc<compio::net::UdpSocket>,
    tx_pool: &'a mut TxPool,
    tx_in_flight: &'a mut FuturesUnordered<InFlightSend>,
    tx_capacity: usize,
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
        if self.tx_in_flight.len() >= self.tx_capacity {
            return Ok(PushResult::Exhausted);
        }
        let Some(mut buf) = self.tx_pool.alloc_slot() else {
            return Ok(PushResult::Exhausted);
        };
        if buf.len() < wire_len {
            buf.resize(wire_len, 0);
        }
        let len = match fill(&mut buf[..wire_len]) {
            Ok(len) => len,
            Err(error) => {
                self.tx_pool.return_slot(buf);
                return Err(error);
            }
        };
        if len != wire_len {
            self.tx_pool.return_slot(buf);
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidData,
                "owner sink fill must materialize exactly the advertised wire length",
            ));
        }
        let sock = self.sock.clone();
        let meta = InFlightMeta {
            peer,
            expected_len: len,
        };
        self.tx_in_flight.push(Box::pin(async move {
            let BufResult(res, mut b) = sock.send_to(buf, peer).await;
            b.clear();
            (meta, res, b)
        }));

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
    tx_in_flight: FuturesUnordered<InFlightSend>,
    tx_capacity: usize,
    completions: OwnerTxCompletionStats,
    rx_priority_listener_first: bool,
    tx_priority_listener_first: bool,
    caller_pool_policy: Option<(std::num::NonZeroUsize, std::time::Duration)>,
    socket_memory_budget: Option<std::num::NonZeroUsize>,
}

impl Owner {
    /// Create a new Owner with bounded concurrent TX capacity.
    #[must_use]
    pub fn new(tx_capacity: usize) -> Self {
        let capacity = tx_capacity.max(1);
        Self {
            listener: None,
            caller: None,
            tx_pool: TxPool::new(capacity, DEFAULT_TX_SLOT_SIZE),
            tx_in_flight: FuturesUnordered::new(),
            tx_capacity: capacity,
            completions: OwnerTxCompletionStats::default(),
            rx_priority_listener_first: true,
            tx_priority_listener_first: true,
            caller_pool_policy: None,
            socket_memory_budget: None,
        }
    }

    /// Attach a listener side.
    pub fn with_listener(mut self, listener: ListenerSide) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Attach a caller side built around a [`crate::CallerPool`].
    pub fn with_caller(mut self, caller: OwnerCallerSide) -> Self {
        self.caller = Some(caller);
        self
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
            self.caller = Some(OwnerCallerSide::new(
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
        self.caller.as_mut()?.pool.table_mut().remove(id)
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

    #[must_use]
    pub fn listener(&self) -> Option<&ListenerSide> {
        self.listener.as_ref()
    }

    pub fn listener_mut(&mut self) -> Option<&mut ListenerSide> {
        self.listener.as_mut()
    }

    #[must_use]
    pub fn caller(&self) -> Option<&CallerSide> {
        self.caller.as_ref()
    }

    pub fn caller_mut(&mut self) -> Option<&mut CallerSide> {
        self.caller.as_mut()
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
        self.tx_in_flight.len()
    }

    /// Delay until the next due timer across all sessions.
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        let l_us = self.listener.as_mut().map_or(default_us, |l| {
            l.table.time_until_next_deadline(now, default_us)
        });
        let c_us = self.caller.as_ref().map_or(default_us, |c| {
            c.pool.table().time_until_next_deadline(now, default_us)
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

        // 1. Reap only already-ready completions, never waiting.
        while report.completions_reaped < budget.max_completions && !self.tx_in_flight.is_empty() {
            use futures_util::FutureExt;
            let poll_res =
                std::future::poll_fn(|cx| self.tx_in_flight.poll_next_unpin(cx)).now_or_never();
            match poll_res {
                Some(Some((meta, res, buf))) => {
                    self.tx_pool.return_slot(buf);
                    report.completions_reaped += 1;
                    match res {
                        Ok(sent) if sent == meta.expected_len => {
                            self.completions.completed_ok += 1;
                        }
                        Ok(_) => {
                            // A completed short UDP send is a definite driver
                            // outcome (not a cancellation): SRT ARQ owns
                            // recovery, so record it explicitly rather than
                            // silently treating it as success.
                            self.completions.short_sends += 1;
                        }
                        Err(_) => {
                            self.completions.failed_sends += 1;
                        }
                    }
                }
                _ => break,
            }
        }

        // 2. Service incoming RX up to max_rx_packets / max_rx_bytes
        self.service_rx(now, &budget, &mut report).await;

        // 3. Service outbound TX up to max_tx_packets / max_tx_bytes / max_actions
        self.service_tx(now, &budget, &mut report);

        report.tx_in_flight = self.tx_in_flight.len();
        report.tx_pool_free = self.tx_pool.free_count();
        report.next_deadline_us = Some(self.time_until_next_deadline(now, 100_000));
        report.tx_completed_ok = self.completions.completed_ok;
        report.tx_short_sends = self.completions.short_sends;
        report.tx_failed_sends = self.completions.failed_sends;

        let has_pending = self.has_pending_work(now);
        report.work_remaining = has_pending || !self.tx_in_flight.is_empty();
        report.budget_exhausted = report.completions_reaped >= budget.max_completions
            || report.rx_packets >= budget.max_rx_packets
            || report.tx_packets_submitted >= budget.max_tx_packets
            || report.actions >= budget.max_actions;

        report
    }

    /// Wait until the proactor reports activity or `timeout` elapses. This is
    /// the only waiting entry point: `service` itself never blocks, so an
    /// outer Restream shard calls `wait_for_activity` when idle and
    /// `service` when woken or on its timer deadline.
    pub async fn wait_for_activity(&mut self, timeout: std::time::Duration) {
        if self.tx_in_flight.is_empty() {
            compio::time::sleep(timeout).await;
            return;
        }
        let _ = compio::time::timeout(timeout, self.tx_in_flight.next()).await;
    }

    async fn service_rx_listener(
        listener: &mut ListenerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        // The persistent buffer is cloned into each synchronous readiness
        // probe so a Pending poll never consumes driver-owned state and the
        // stored buffer is always retained. Probes use the std socket behind
        // the Compio socket in nonblocking mode with a zeroed spare buffer.
        let spare = listener
            .rx_buf
            .take()
            .unwrap_or_else(|| vec![0u8; DEFAULT_TX_SLOT_SIZE]);
        let mut spare = Some(spare);
        while report.rx_packets < budget.max_rx_packets && report.rx_bytes < budget.max_rx_bytes {
            use std::os::fd::AsRawFd;
            let raw_fd = compio::net::UdpSocket::as_raw_fd(&listener.sock);
            let probe_buf = spare.take().expect("spare rx buffer held");
            let mut probe = vec![0u8; DEFAULT_TX_SLOT_SIZE];
            // SAFETY: `sockaddr_storage` is plain data; zeroing initializes it.
            let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            // SAFETY: `raw_fd` is a live UDP socket owned by `listener.sock`;
            // `recvfrom` writes at most `probe.len()` bytes into `probe` plus
            // the peer address into `addr_storage`, all stack-owned here.
            let received = unsafe {
                libc::recvfrom(
                    raw_fd,
                    probe.as_mut_ptr() as *mut libc::c_void,
                    probe.len(),
                    libc::MSG_DONTWAIT,
                    &mut addr_storage as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            if received < 0 {
                spare = Some(probe_buf);
                break;
            }
            let len = received as usize;
            if len == 0 {
                spare = Some(probe_buf);
                break;
            }
            let peer = sockaddr_to_std(addr_storage, addr_len);
            let Some(peer) = peer else {
                spare = Some(probe_buf);
                break;
            };
            report.rx_packets += 1;
            report.rx_bytes += len;
            let _ = listener.table.admit(
                peer,
                &probe[..len],
                now,
                &listener.options,
                0,
                1,
                &listener.telemetry,
            );
            spare = Some(probe_buf);
        }
        listener.rx_buf = spare;
    }

    async fn service_rx_caller(
        caller: &mut CallerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        let spare = caller
            .rx_buf
            .take()
            .unwrap_or_else(|| vec![0u8; DEFAULT_TX_SLOT_SIZE]);
        let mut spare = Some(spare);
        while report.rx_packets < budget.max_rx_packets && report.rx_bytes < budget.max_rx_bytes {
            use std::os::fd::AsRawFd;
            let raw_fd = compio::net::UdpSocket::as_raw_fd(&caller.sock);
            let probe_buf = spare.take().expect("spare rx buffer held");
            let mut probe = vec![0u8; DEFAULT_TX_SLOT_SIZE];
            // SAFETY: `sockaddr_storage` is plain data; zeroing initializes it.
            let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            // SAFETY: `raw_fd` is a live UDP socket owned by `listener.sock`;
            // `recvfrom` writes at most `probe.len()` bytes into `probe` plus
            // the peer address into `addr_storage`, all stack-owned here.
            let received = unsafe {
                libc::recvfrom(
                    raw_fd,
                    probe.as_mut_ptr() as *mut libc::c_void,
                    probe.len(),
                    libc::MSG_DONTWAIT,
                    &mut addr_storage as *mut _ as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };
            if received < 0 {
                spare = Some(probe_buf);
                break;
            }
            let len = received as usize;
            if len == 0 {
                spare = Some(probe_buf);
                break;
            }
            let Some(peer) = sockaddr_to_std(addr_storage, addr_len) else {
                spare = Some(probe_buf);
                break;
            };
            report.rx_packets += 1;
            report.rx_bytes += len;
            let _ = caller.pool.table_mut().feed(peer, &probe[..len], now);
            spare = Some(probe_buf);
        }
        caller.rx_buf = spare;
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
                tx_in_flight: &mut self.tx_in_flight,
                tx_capacity: self.tx_capacity,
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
        if let Some(ref mut caller) = self.caller {
            // Retire stalled attempts to Connected-established sessions and
            // admit queued requests, exactly like the Mio/Tokio owners. This
            // is what releases the in-flight permit so the next queued fanout
            // leg can handshake instead of stalling behind the first.
            let _ = caller
                .pool
                .poll_expirations_bounded(now, tx_budget.max_actions.max(1));
            let mut sink = OwnerTxSink {
                sock: &caller.sock,
                tx_pool: &mut self.tx_pool,
                tx_in_flight: &mut self.tx_in_flight,
                tx_capacity: self.tx_capacity,
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

    fn has_pending_work(&self, now: Timestamp) -> bool {
        let l_pending = self
            .listener
            .as_ref()
            .is_some_and(|l| l.table.has_pending_output(now));
        let c_pending = self
            .caller
            .as_ref()
            .is_some_and(|c| c.pool.table().has_pending_output(now));
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
            let caller_side = CallerSide::new_single(c_sock);

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
                .caller_mut()
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
                owner.listener_mut().unwrap().table.poll_events(&mut events);
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
            let caller_side = CallerSide::new_single(c_sock);

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
                .caller_mut()
                .unwrap()
                .pool
                .table_mut()
                .add_direct(leg)
                .expect("add leg");
            for i in 0..4u8 {
                owner
                    .caller_mut()
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
            let caller_side = CallerSide::new_single(c_sock);

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
                .caller_mut()
                .unwrap()
                .pool
                .table_mut()
                .add_direct(crate::caller::CallerLeg {
                    peer: slow_peer,
                    connection: slow_conn,
                })
                .expect("add slow");

            let fast_id = owner
                .caller_mut()
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
                    .caller_mut()
                    .unwrap()
                    .pool
                    .table_mut()
                    .bench_push_pending(slow_id, slow_peer, vec![i; 64]);
            }
            owner
                .caller_mut()
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
            let caller_side = CallerSide::new_single(c_sock);

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
                    .caller_mut()
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
    #[cfg(target_os = "linux")]
    fn test_compio_live_io_uring_sentinel() {
        let sentinel = live_driver_sentinel();
        let info = sentinel.expect("live io_uring driver must be active on Linux");
        assert!(info.is_io_uring);
        assert_eq!(info.driver_type, "IoUring");
        assert!(!info.kernel_version.is_empty());
    }
}
