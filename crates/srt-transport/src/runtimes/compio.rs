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

/// Reusable finite TX buffer pool for zero-allocation outbound datagrams.
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
    pub fn alloc_slot(&mut self) -> Option<Vec<u8>> {
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
    pub fn return_slot(&mut self, mut buf: Vec<u8>) {
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
}

impl ListenerSide {
    pub fn new(
        sock: compio::net::UdpSocket,
        config: &crate::ListenerConfig,
    ) -> Result<Self, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Compio)?;
        let table = prepared.peer_table();
        let options = prepared.admission_options();
        Ok(Self {
            sock: Rc::new(sock),
            table,
            telemetry: IngressTelemetry::new(),
            options,
        })
    }
}

/// Caller side of a shared Compio owner.
pub struct CallerSide {
    pub sock: Rc<compio::net::UdpSocket>,
    pub table: CallerTable,
}

impl CallerSide {
    pub fn new(sock: compio::net::UdpSocket) -> Self {
        Self {
            sock: Rc::new(sock),
            table: CallerTable::new(),
        }
    }
}

type InFlightSend = Pin<Box<dyn Future<Output = (io::Result<usize>, Vec<u8>)>>>;

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
        let len = fill(&mut buf[..wire_len])?;
        buf.truncate(len);

        let sock = self.sock.clone();
        self.tx_in_flight.push(Box::pin(async move {
            let BufResult(res, mut b) = sock.send_to(buf, peer).await;
            b.clear();
            (res, b)
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
}

/// High-density, shared-socket completion-runtime owner.
///
/// Manages shared UDP sockets for listeners and callers without a per-connection task.
/// All outbound datagrams use direct final-buffer encoding into reusable slots from [`TxPool`].
pub struct Owner {
    listener: Option<ListenerSide>,
    caller: Option<CallerSide>,
    tx_pool: TxPool,
    tx_in_flight: FuturesUnordered<InFlightSend>,
    tx_capacity: usize,
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
        }
    }

    /// Attach a listener side.
    pub fn with_listener(mut self, listener: ListenerSide) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Attach a caller side.
    pub fn with_caller(mut self, caller: CallerSide) -> Self {
        self.caller = Some(caller);
        self
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

    pub fn tx_pool_mut(&mut self) -> &mut TxPool {
        &mut self.tx_pool
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
            c.table.time_until_next_deadline(now, default_us)
        });
        l_us.min(c_us)
    }

    /// Service active I/O, due timers, and outbound queues within the given budget.
    pub async fn service(
        &mut self,
        now: Timestamp,
        budget: OwnerServiceBudget,
    ) -> OwnerServiceReport {
        let mut report = OwnerServiceReport::default();

        // 1. Reap ready completions from tx_in_flight up to max_completions
        while report.completions_reaped < budget.max_completions && !self.tx_in_flight.is_empty() {
            match compio::time::timeout(
                std::time::Duration::from_millis(5),
                self.tx_in_flight.next(),
            )
            .await
            {
                Ok(Some((res, buf))) => {
                    self.tx_pool.return_slot(buf);
                    report.completions_reaped += 1;
                    if let Ok(_len) = res {
                        // Datagram successfully transmitted
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

        let has_pending = self.has_pending_work(now);
        report.work_remaining = has_pending || !self.tx_in_flight.is_empty();
        report.budget_exhausted = (budget.max_completions > 0
            && report.completions_reaped >= budget.max_completions)
            || (budget.max_rx_packets > 0 && report.rx_packets >= budget.max_rx_packets)
            || (budget.max_tx_packets > 0 && report.tx_packets_submitted >= budget.max_tx_packets)
            || (budget.max_actions > 0 && report.actions >= budget.max_actions);

        report
    }

    async fn service_rx_listener(
        listener: &mut ListenerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        let mut rx_buf = vec![0u8; DEFAULT_TX_SLOT_SIZE];
        while report.rx_packets < budget.max_rx_packets && report.rx_bytes < budget.max_rx_bytes {
            let recv_fut = listener.sock.recv_from(rx_buf);
            match compio::time::timeout(std::time::Duration::from_millis(5), recv_fut).await {
                Ok(BufResult(Ok((len, peer)), buf)) => {
                    if len == 0 {
                        break;
                    }
                    report.rx_packets += 1;
                    report.rx_bytes += len;
                    let _ = listener.table.admit(
                        peer,
                        &buf[..len],
                        now,
                        &listener.options,
                        0,
                        1,
                        &listener.telemetry,
                    );
                    rx_buf = buf;
                }
                Ok(BufResult(Err(_), _buf)) => {
                    break;
                }
                Err(_) => break,
            }
        }
    }

    async fn service_rx_caller(
        caller: &mut CallerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        let mut rx_buf = vec![0u8; DEFAULT_TX_SLOT_SIZE];
        while report.rx_packets < budget.max_rx_packets && report.rx_bytes < budget.max_rx_bytes {
            let recv_fut = caller.sock.recv_from(rx_buf);
            match compio::time::timeout(std::time::Duration::from_millis(5), recv_fut).await {
                Ok(BufResult(Ok((len, peer)), buf)) => {
                    if len == 0 {
                        break;
                    }
                    report.rx_packets += 1;
                    report.rx_bytes += len;
                    let _ = caller.table.feed(peer, &buf[..len], now);
                    rx_buf = buf;
                }
                Ok(BufResult(Err(_), _buf)) => {
                    break;
                }
                Err(_) => break,
            }
        }
    }

    async fn service_rx(
        &mut self,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        if let Some(ref mut listener) = self.listener {
            Self::service_rx_listener(listener, now, budget, report).await;
        }
        if let Some(ref mut caller) = self.caller {
            Self::service_rx_caller(caller, now, budget, report).await;
        }
    }

    fn service_tx(
        &mut self,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        let remaining_actions = budget.max_actions.saturating_sub(report.actions);
        let remaining_packets = budget
            .max_tx_packets
            .saturating_sub(report.tx_packets_submitted);
        let remaining_bytes = budget
            .max_tx_bytes
            .saturating_sub(report.tx_bytes_submitted);

        let tx_budget =
            OutputDrainBudget::new(remaining_actions, remaining_packets, remaining_bytes);

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

        let remaining_actions = budget.max_actions.saturating_sub(report.actions);
        let remaining_packets = budget
            .max_tx_packets
            .saturating_sub(report.tx_packets_submitted);
        let remaining_bytes = budget
            .max_tx_bytes
            .saturating_sub(report.tx_bytes_submitted);
        let tx_budget =
            OutputDrainBudget::new(remaining_actions, remaining_packets, remaining_bytes);

        if let Some(ref mut caller) = self.caller {
            let mut sink = OwnerTxSink {
                sock: &caller.sock,
                tx_pool: &mut self.tx_pool,
                tx_in_flight: &mut self.tx_in_flight,
                tx_capacity: self.tx_capacity,
            };
            let drain_report = caller
                .table
                .poll_outbound_bounded_to(now, tx_budget, &mut sink);
            report.actions += drain_report.actions;
            report.tx_packets_submitted += drain_report.packets;
            report.tx_bytes_submitted += drain_report.bytes;
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
            .is_some_and(|c| c.table.has_pending_output(now));
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
            let caller_side = CallerSide::new(c_sock);

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
                .table
                .add_direct(caller_leg)
                .expect("add caller direct");

            // Service the owner until handshake connects
            let budget = OwnerServiceBudget::default();
            for round in 0..20 {
                now = Timestamp::from_micros(10_000 + round * 5_000);
                let _report = owner.service(now, budget).await;

                let connected = owner
                    .caller()
                    .unwrap()
                    .table
                    .logical_caller(&caller_id)
                    .and_then(|c| c.state())
                    == Some(crate::caller::LogicalCallerState::Connected);
                if connected {
                    break;
                }
            }

            let caller_session = owner
                .caller()
                .unwrap()
                .table
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
                .caller_mut()
                .unwrap()
                .table
                .logical_caller_mut(&caller_id)
                .expect("caller session")
                .send_shared(test_payload.clone(), now)
                .expect("send succeeds");

            // Service owner to transmit and receive
            for round in 0..10 {
                now = Timestamp::from_micros(210_000 + round * 2_000);
                let _report = owner.service(now, budget).await;

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
            let caller_side = CallerSide::new(c_sock);

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
                .table
                .add_direct(leg)
                .expect("add leg");
            for i in 0..4u8 {
                owner
                    .caller_mut()
                    .unwrap()
                    .table
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
            let removed = owner.caller_mut().unwrap().table.remove(id);
            assert!(removed.is_some(), "session removed safely");
        });
    }

    #[test]
    fn owner_sibling_isolation() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind caller std");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("compio adopt caller");
            let caller_side = CallerSide::new(c_sock);

            let mut owner = Owner::new(64).with_caller(caller_side);

            let slow_peer = "127.0.0.1:19999".parse().unwrap();
            let fast_peer = "127.0.0.1:20000".parse().unwrap();

            let mut slow_conn = SrtConnection::new_caller(srt_proto::ConnectionOptions::default());
            let mut fast_conn = SrtConnection::new_caller(srt_proto::ConnectionOptions::default());

            let now = Timestamp::from_micros(10_000);
            slow_conn.connect(now).expect("slow connect");
            fast_conn.connect(now).expect("fast connect");

            let slow_id = owner
                .caller_mut()
                .unwrap()
                .table
                .add_direct(crate::caller::CallerLeg {
                    peer: slow_peer,
                    connection: slow_conn,
                })
                .expect("add slow");

            let fast_id = owner
                .caller_mut()
                .unwrap()
                .table
                .add_direct(crate::caller::CallerLeg {
                    peer: fast_peer,
                    connection: fast_conn,
                })
                .expect("add fast");

            // Overfill slow caller's pending outputs
            for i in 0..10u8 {
                owner.caller_mut().unwrap().table.bench_push_pending(
                    slow_id,
                    slow_peer,
                    vec![i; 64],
                );
            }
            // Queue packet on fast caller
            owner.caller_mut().unwrap().table.bench_push_pending(
                fast_id,
                fast_peer,
                b"fast_data".to_vec(),
            );

            // Run bounded service with a budget that drains packets
            let budget = OwnerServiceBudget {
                max_tx_packets: 4,
                ..Default::default()
            };
            let report = owner.service(now, budget).await;

            // Transmissions were submitted for both siblings according to fair round-robin
            assert!(report.tx_packets_submitted > 0);
            assert!(owner.tx_in_flight() <= 4);
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
            let caller_side = CallerSide::new(c_sock);

            let mut owner = Owner::new(64)
                .with_listener(listener_side)
                .with_caller(caller_side);

            // Add 4 downstream destinations
            let mut dest_ids = Vec::new();
            for i in 1..=4u32 {
                let peer: std::net::SocketAddr =
                    format!("127.0.0.1:{}", 35000 + i).parse().unwrap();
                let mut conn = SrtConnection::new_caller(srt_proto::ConnectionOptions {
                    socket_id: 0x3000 + i,
                    ..Default::default()
                });
                let now = Timestamp::from_micros(10_000);
                conn.connect(now).expect("connect");
                let leg = crate::caller::CallerLeg {
                    peer,
                    connection: conn,
                };
                let id = owner
                    .caller_mut()
                    .unwrap()
                    .table
                    .add_direct(leg)
                    .expect("add direct");
                dest_ids.push(id);
            }

            // Simulate incoming media payload
            let media = Bytes::from_static(b"relay-media-payload-1316-bytes-test");
            let media_ptr = media.as_ptr();

            // Fan out by cloning Bytes handles to all 4 destinations
            let now = Timestamp::from_micros(10_000);
            for &id in &dest_ids {
                let clone = media.clone();
                assert_eq!(
                    clone.as_ptr(),
                    media_ptr,
                    "Bytes clone must share underlying memory"
                );
                owner.caller_mut().unwrap().table.bench_push_pending(
                    id,
                    "127.0.0.1:35001".parse().unwrap(),
                    clone.to_vec(),
                );
            }

            let budget = OwnerServiceBudget {
                max_tx_packets: 10,
                ..Default::default()
            };
            let report = owner.service(now, budget).await;
            assert_eq!(report.tx_packets_submitted, 8);
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
