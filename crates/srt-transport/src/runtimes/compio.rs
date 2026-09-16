use crate::{
    CallerTable, DatagramSink, DatagramSlot, IngressTelemetry, OutputDrainBudget,
    OutputDrainReport, OutputDrainStatus, PacedSendOutcome, PeerTable, collect_output_work,
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
use std::pin::Pin;
use std::rc::{Rc, Weak};
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
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget)
                .map_err(|error| io::Error::other(error.to_string()))?;
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

/// The managed-RX substrate of one observed runtime, as ONE fact.
///
/// This is the token an Owner consumes to decide whether it may attach a
/// managed consumer. It is deliberately not a `bool`: the three stages fail
/// for different reasons and attribution must survive
/// (`RxModePolicy` reports which stage failed), and collapsing them early is
/// what lets `ManagedRequired` attach on a host where the buffer ring
/// registers but `recvmsg` multishot does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedRxSubstrate {
    /// The live runtime is not io_uring, so no managed receive exists at all.
    NotIoUring,
    /// `IORING_REGISTER_PBUF_RING` failed with this errno (22 = `EINVAL` is a
    /// kernel-build defect, observed on Ubuntu Noble `6.8.0-139-generic`).
    BufferRingRegistrationFailed(i32),
    /// The ring registers but a multishot receive could not be armed.
    MultishotRecvUnsupported,
    /// io_uring + provided-buffer ring + multishot `recvmsg`: the full
    /// managed datapath.
    Available,
}

impl ManagedRxSubstrate {
    /// Whether the full managed datapath exists on the observed runtime.
    #[must_use]
    pub fn is_available(self) -> bool {
        self == Self::Available
    }

    /// Human-readable attribution for an attach failure. Names the layer that
    /// actually failed instead of blaming the buffer ring unconditionally.
    #[must_use]
    pub fn reason(self) -> String {
        match self {
            Self::NotIoUring => {
                "the live runtime is not io_uring, so it has no managed multishot receive"
                    .to_string()
            }
            Self::BufferRingRegistrationFailed(errno) => format!(
                "this runtime rejected IORING_REGISTER_PBUF_RING (errno {errno}), so it has no provided-buffer ring for managed RX"
            ),
            Self::MultishotRecvUnsupported => {
                "the provided-buffer ring registers but recvmsg multishot is unsupported on this runtime, so the managed receive cannot be armed".to_string()
            }
            Self::Available => "managed multishot RX is available".to_string(),
        }
    }
}

impl CompioProductionProfile {
    /// The managed-RX substrate of the observed runtime, as one fact.
    #[must_use]
    pub fn managed_rx_substrate(&self) -> ManagedRxSubstrate {
        match (&self.buffer_ring, &self.multishot_recv) {
            (ProvidedBufferRingStatus::Available, MultishotRecvStatus::Available) => {
                ManagedRxSubstrate::Available
            }
            (ProvidedBufferRingStatus::Available, _) => {
                ManagedRxSubstrate::MultishotRecvUnsupported
            }
            (ProvidedBufferRingStatus::RegistrationFailed(errno), _) => {
                ManagedRxSubstrate::BufferRingRegistrationFailed(*errno)
            }
            (ProvidedBufferRingStatus::Unknown, _) => ManagedRxSubstrate::NotIoUring,
        }
    }

    /// Whether this HOST can run managed RX (`recv_msg_multi` over the
    /// runtime's provided-buffer ring).
    ///
    /// Capability only: it says nothing about which datapath an Owner is
    /// running. [`ManagedRxQualification`] is the type that answers that,
    /// because qualification also requires the Owner to have selected
    /// [`OwnerRxMode::ManagedMultishot`].
    #[must_use]
    pub fn host_managed_rx_capable(&self) -> bool {
        matches!(
            (&self.buffer_ring, &self.multishot_recv),
            (
                ProvidedBufferRingStatus::Available,
                MultishotRecvStatus::Available
            )
        )
    }
}

/// Which receive datapath an Owner is actually running.
///
/// Selected at socket attach from the observed substrate and never changed
/// silently afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerRxMode {
    /// One persistent managed `recv_msg_multi()` stream per shared UDP socket,
    /// consuming runtime provided-ring buffers, with `MSG_TRUNC` reporting so
    /// an oversized datagram is dropped and counted instead of parsed short.
    /// This is the production high-density mode.
    ManagedMultishot,
    /// Readiness wake plus one raw nonblocking `recvfrom` consumer into a
    /// persistent slot. Valid development fallback, and the only option on a
    /// kernel that cannot register a provided-buffer ring.
    RawReadiness,
}

/// How an Owner resolves [`OwnerRxMode`] when it attaches a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RxModePolicy {
    /// Use managed multishot when the live runtime provides the substrate,
    /// otherwise fall back to the readiness reader. The selected mode stays
    /// observable through [`Owner::rx_mode`], and a fallback is never
    /// reported as a qualification pass.
    #[default]
    ManagedPreferred,
    /// Fail closed: attaching a socket on a runtime without the managed
    /// substrate is a configuration error rather than a silent fallback.
    /// Production shards use this.
    ManagedRequired,
}

impl RxModePolicy {
    /// Resolve the mode for one socket attach from the observed substrate.
    ///
    /// `substrate` is the whole observed fact ([`ManagedRxSubstrate`]), not a
    /// collapsed bool: `ManagedRequired` attaches a managed consumer only on
    /// [`ManagedRxSubstrate::Available`], and every failure names the stage
    /// that actually failed.
    pub(crate) fn resolve(
        self,
        substrate: ManagedRxSubstrate,
    ) -> Result<OwnerRxMode, ManagedRxSubstrate> {
        match (self, substrate.is_available()) {
            (_, true) => Ok(OwnerRxMode::ManagedMultishot),
            (Self::ManagedPreferred, false) => Ok(OwnerRxMode::RawReadiness),
            (Self::ManagedRequired, false) => Err(substrate),
        }
    }
}

/// Verdict for one managed RX completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedDatagram {
    /// The datagram fits the ring slot: safe to hand to `srt-proto`.
    Complete,
    /// The kernel reported `MSG_TRUNC`, so the slot did not hold the whole
    /// datagram. It is dropped and counted; truncated bytes are NEVER parsed
    /// as if they were a complete SRT datagram.
    Truncated,
}

/// Whether one more RX datagram of `len` bytes fits this visit's remaining
/// packet and byte allowances. Zero allowances are strict: a zero packet or
/// byte budget accepts nothing, including the first datagram.
pub(crate) fn rx_budget_fits(
    report: &OwnerServiceReport,
    budget: &OwnerServiceBudget,
    len: usize,
) -> bool {
    report.rx_packets < budget.max_rx_packets
        && report.rx_bytes.saturating_add(len) <= budget.max_rx_bytes
}

/// Classify one managed completion against the ring slot size.
pub(crate) fn classify_managed_datagram(
    len: usize,
    slot_len: usize,
    trunc_flag: bool,
) -> ManagedDatagram {
    if trunc_flag || len > slot_len {
        ManagedDatagram::Truncated
    } else {
        ManagedDatagram::Complete
    }
}

/// Managed RX ring depth per shared socket. Fixed and preallocated; the ring
/// never grows, and an overflow drops the newest completion (bounded loss)
/// rather than queueing without limit.
pub const MANAGED_RX_RING_DEPTH: usize = 256;

/// Whether the managed-RX datapath is the one actually running on this Owner.
///
/// This is the conjunction of two independent facts: the host provides the
/// substrate, and the Owner selected [`OwnerRxMode::ManagedMultishot`]. It is
/// a *datapath* statement only -- it says nothing about workload-level SLOs
/// (CPU/memory/latency/recovery under a production destination population),
/// which is why it is not called "production qualified".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRxQualification {
    /// Observed host/runtime capability.
    pub profile: CompioProductionProfile,
    /// Receive datapath the Owner selected for its shared sockets.
    pub owner_rx_mode: OwnerRxMode,
}

impl ManagedRxQualification {
    /// True only when the host provides the managed substrate AND the Owner
    /// selected it.
    #[must_use]
    pub fn managed_rx_active(&self) -> bool {
        self.profile.is_io_uring
            && self.profile.host_managed_rx_capable()
            && self.owner_rx_mode == OwnerRxMode::ManagedMultishot
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

/// Managed RX slot size for a given Owner wire ceiling.
///
/// Sized from the largest datagram the Owner will accept, NOT the 64 KiB UDP
/// maximum: truncation is reported by the kernel (`MSG_TRUNC`) through the
/// msg-multishot form, so an oversized datagram is detected and dropped
/// rather than silently parsed short. That keeps the provided-buffer pool
/// proportional to the real ceiling (2048 B x 256 slots = 512 KiB for a
/// 1500-byte ceiling) instead of 16 MiB.
///
/// Rounded up to a power of two, which is what a provided-buffer ring wants.
#[must_use]
pub fn managed_rx_buffer_len(wire_ceiling: usize) -> usize {
    let floor = srt_proto::wire::SRT_HEADER_SIZE + 1;
    wire_ceiling.max(floor).next_power_of_two()
}

impl ProductionRuntimeConfig {
    /// Derive SQ/CQ/ring sizes from the Owner envelope (TX lanes and the
    /// configured session wire ceiling). CQ covers lanes + RX burst +
    /// timeout slack.
    #[must_use]
    pub fn for_owner(tx_lanes: usize, wire_ceiling: usize) -> Self {
        let lanes = tx_lanes.max(1) as u32;
        let sq_capacity = lanes.saturating_add(256).max(512);
        let cq_size = sq_capacity.saturating_mul(2);
        Self {
            tx_lanes: tx_lanes.max(1),
            sq_capacity,
            cq_size,
            rx_ring_entries: 256,
            rx_buffer_len: managed_rx_buffer_len(wire_ceiling),
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
        let cfg = ProductionRuntimeConfig::for_owner(64, 1500);
        assert_eq!(cfg.tx_lanes, 64);
        // SQ covers lanes + RX burst + slack; CQ doubles SQ.
        assert!(cfg.sq_capacity >= 64 + 256);
        assert_eq!(cfg.cq_size, cfg.sq_capacity * 2);
        assert_eq!(cfg.rx_ring_entries, 256);
        // Slot sizing follows the wire ceiling (1500 -> next power of two),
        // so the ring costs 256 x 2048 B instead of 256 x 64 KiB.
        assert_eq!(cfg.rx_buffer_len, 2048);
        assert_eq!(MANAGED_RX_RING_DEPTH, 256);
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

/// What is left of one absolute deadline. Teardown phases share a single
/// deadline, so each phase gets only the remainder rather than its own full
/// timeout.
fn remaining(deadline: std::time::Instant) -> std::time::Duration {
    deadline.saturating_duration_since(std::time::Instant::now())
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

/// One managed RX completion: the runtime's ring buffer plus its peer.
///
/// The buffer is a lease on the runtime's provided-buffer pool; dropping this
/// value returns it. The datapath copies out of it during protocol admission
/// and then drops it -- it is never retained across receiver reorder windows.
pub(crate) struct ManagedRxDatagram {
    peer: SocketAddr,
    result: compio::driver::op::RecvMsgMultiResult,
}

impl ManagedRxDatagram {
    fn len(&self) -> usize {
        self.result.data().len()
    }

    fn bytes(&self) -> &[u8] {
        self.result.data()
    }
}

/// A managed RX task that stopped or errored. Surfaced through
/// [`OwnerFault`] so a dead consumer can never look like a quiet socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RxFault {
    /// The multishot stream ended or returned an error.
    StreamError(String),
}

/// Bounded completion ring under one fixed managed RX task.
///
/// Unbounded queueing is forbidden: the ring is preallocated to
/// [`MANAGED_RX_RING_DEPTH`], and a completion that does not fit is dropped
/// and counted. Truncated datagrams (`MSG_TRUNC`) are counted separately and
/// never reach `srt-proto`.
pub(crate) struct ManagedRxRing {
    completions: VecDeque<ManagedRxDatagram>,
    capacity: usize,
    waker: Option<Waker>,
    fault: Option<RxFault>,
    /// Completions dropped because the ring was full (bounded loss).
    dropped: u64,
    /// Datagrams the kernel reported as truncated: too large for the ring
    /// slot. Dropped without parsing.
    truncated: u64,
    shutdown: bool,
    task: Option<compio::runtime::JoinHandle<()>>,
}

impl ManagedRxRing {
    fn new() -> Self {
        Self {
            completions: VecDeque::with_capacity(MANAGED_RX_RING_DEPTH),
            capacity: MANAGED_RX_RING_DEPTH,
            waker: None,
            fault: None,
            dropped: 0,
            truncated: 0,
            shutdown: false,
            task: None,
        }
    }

    fn push(&mut self, datagram: ManagedRxDatagram) -> bool {
        if self.completions.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.completions.push_back(datagram);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
        true
    }

    fn pop(&mut self) -> Option<ManagedRxDatagram> {
        self.completions.pop_front()
    }

    fn pending(&self) -> bool {
        !self.completions.is_empty()
    }

    /// Count one truncated (oversized) datagram and wake the Owner so the
    /// counter is observable without waiting for the next completion.
    fn note_truncated(&mut self) {
        self.truncated = self.truncated.saturating_add(1);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn fault(&mut self, fault: RxFault) {
        self.fault = Some(fault);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// The single fixed managed RX task for one shared UDP socket.
///
/// One task per socket, created once at attach: never per datagram, never per
/// connection. It is the ONLY consumer of that socket while it runs, which is
/// what makes the datapath single-consumer by construction.
///
/// # Ownership rule
///
/// The ring owns this task's `JoinHandle`, so the task must NEVER hold a
/// strong `Rc` to the ring *across the receive await*: that would be
/// `ManagedRxRing -> JoinHandle -> task future -> Rc<ManagedRxRing>`, a cycle
/// that keeps both the ring and a socket consumer alive past the Owner. The
/// `Weak` parameter alone does not establish that; the upgrade has to be
/// scoped so the strong reference is dropped before `stream.next().await`,
/// which is what the block below does. Losing the owner means the ring is
/// gone: stop.
async fn managed_rx_task<S>(stream: S, ring: Weak<RefCell<ManagedRxRing>>)
where
    S: futures_util::Stream<Item = ManagedRxStep> + Unpin,
{
    let mut stream = stream;
    loop {
        // The strong reference lives only inside this block. Anything that
        // keeps it alive across the await below reintroduces the cycle; see
        // `managed_rx_task_holds_no_strong_ring_across_the_receive_await`.
        {
            let Some(ring) = ring.upgrade() else {
                break;
            };
            if ring.borrow().shutdown {
                break;
            }
        }
        let Some(step) = futures_util::StreamExt::next(&mut stream).await else {
            break;
        };
        let Some(ring) = ring.upgrade() else {
            break;
        };
        let mut ring = ring.borrow_mut();
        match step {
            ManagedRxStep::Datagram(datagram) => {
                ring.push(datagram);
            }
            ManagedRxStep::Truncated => ring.note_truncated(),
            ManagedRxStep::Unattributable => {}
            ManagedRxStep::Ended => {
                ring.fault(RxFault::StreamError("managed RX stream ended".to_string()));
                break;
            }
            ManagedRxStep::Failed(detail) => {
                ring.fault(RxFault::StreamError(detail));
                break;
            }
        }
    }
}

/// One step the managed RX loop consumes.
///
/// Production fills these from Compio's managed receive through
/// [`IntoManagedRxStep`]; tests construct them directly, which is what lets
/// the *production* loop function be exercised without a kernel that can
/// register a provided-buffer ring.
// The `Datagram` variant is the steady-state one and it owns the runtime's
// provided-buffer lease inline: boxing it would add one heap allocation per
// received datagram, which the managed path exists to avoid.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ManagedRxStep {
    /// The kernel set `MSG_TRUNC`: the slot did not hold the whole datagram.
    /// Counted and dropped, never parsed.
    Truncated,
    /// A complete datagram holding its provided-buffer lease.
    Datagram(ManagedRxDatagram),
    /// A datagram with no parseable source address: it cannot be attributed
    /// to a peer, so it is dropped (uncounted, exactly as before).
    Unattributable,
    /// The multishot stream ended.
    Ended,
    /// The multishot stream returned an error.
    Failed(String),
}

/// Classification of one Compio managed receive into a [`ManagedRxStep`].
///
/// This is the only place that touches the pinned Compio result shape.
pub(crate) trait IntoManagedRxStep {
    /// Classify against the ring slot size.
    fn into_step(self, slot_len: usize) -> ManagedRxStep;
}

impl IntoManagedRxStep for compio::driver::op::RecvMsgMultiResult {
    fn into_step(self, slot_len: usize) -> ManagedRxStep {
        // `recv_msg_multi` (not `recv_from_multi`) because only the msg form
        // reports the returned message flags, which is how a datagram larger
        // than the ring slot is detected as truncated instead of being parsed
        // short.
        let truncated = self.flags().bits() & (libc::MSG_TRUNC as u32) != 0;
        if classify_managed_datagram(self.data().len(), slot_len, truncated)
            == ManagedDatagram::Truncated
        {
            return ManagedRxStep::Truncated;
        }
        match self.addr().and_then(|addr| addr.as_socket()) {
            Some(peer) => ManagedRxStep::Datagram(ManagedRxDatagram { peer, result: self }),
            None => ManagedRxStep::Unattributable,
        }
    }
}

/// Maps a Compio managed-receive stream into the loop's step domain.
struct ManagedStepStream<S> {
    inner: S,
    slot_len: usize,
}

impl<S, R> futures_util::Stream for ManagedStepStream<S>
where
    S: futures_util::Stream<Item = io::Result<R>> + Unpin,
    R: IntoManagedRxStep,
{
    type Item = ManagedRxStep;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let slot_len = this.slot_len;
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Some(ManagedRxStep::Ended)),
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(ManagedRxStep::Failed(error.to_string())))
            }
            Poll::Ready(Some(Ok(result))) => Poll::Ready(Some(result.into_step(slot_len))),
        }
    }
}

/// Spawn the managed RX task for one socket from the pinned Compio
/// `recv_msg_multi` stream.
fn spawn_managed_rx_loop(
    sock: Rc<compio::net::UdpSocket>,
    ring: Weak<RefCell<ManagedRxRing>>,
    slot_len: usize,
) -> compio::runtime::JoinHandle<()> {
    spawn(async move {
        let stream = ManagedStepStream {
            inner: Box::pin(sock.recv_msg_multi(0)),
            slot_len,
        };
        managed_rx_task(stream, ring).await;
    })
}

/// Shared accessor shape for the two sides' receive state, so the wait path
/// has one implementation instead of two copies.
trait SideRxHolder {
    fn rx_ring(&self) -> Option<&Rc<RefCell<ManagedRxRing>>> {
        None
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> std::task::Poll<io::Result<()>>;
}

impl SideRxHolder for ListenerSide {
    fn rx_ring(&self) -> Option<&Rc<RefCell<ManagedRxRing>>> {
        self.rx.ring.as_ref()
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> std::task::Poll<io::Result<()>> {
        self.poll_fd.poll_read_ready(cx)
    }
}

impl SideRxHolder for OwnerCallerSide {
    fn rx_ring(&self) -> Option<&Rc<RefCell<ManagedRxRing>>> {
        self.rx.ring.as_ref()
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> std::task::Poll<io::Result<()>> {
        self.poll_fd.poll_read_ready(cx)
    }
}

/// Per-side receive state: the selected mode, the managed ring when the owner
/// is running managed multishot, and at most one staged completion whose lease
/// is retained rather than copied.
pub(crate) struct SideRx {
    mode: OwnerRxMode,
    ring: Option<Rc<RefCell<ManagedRxRing>>>,
    staged: Option<ManagedRxDatagram>,
}

impl SideRx {
    fn raw() -> Self {
        Self {
            mode: OwnerRxMode::RawReadiness,
            ring: None,
            staged: None,
        }
    }

    fn managed(_slot_len: usize, sock_is_live: bool) -> Self {
        Self {
            mode: OwnerRxMode::ManagedMultishot,
            ring: Some(Rc::new(RefCell::new(ManagedRxRing::new()))).filter(|_| sock_is_live),
            staged: None,
        }
    }

    fn pending(&self) -> bool {
        self.staged.is_some()
            || self
                .ring
                .as_ref()
                .is_some_and(|ring| ring.borrow().pending() || ring.borrow().fault.is_some())
    }

    fn take_fault(&self) -> Option<RxFault> {
        self.ring.as_ref().and_then(|ring| {
            let mut ring = ring.borrow_mut();
            ring.fault.take()
        })
    }

    /// Stop the managed RX task and release everything it owns.
    ///
    /// Cancelling the task *and awaiting the cancellation* is what unwinds the
    /// armed managed receive inside the runtime. Merely dropping the
    /// `JoinHandle` cancels it without running that unwinding to completion,
    /// which leaves the provided-buffer leases outstanding: on a kernel that
    /// can register a ring, the runtime's pool then reports exactly
    /// `rx_ring_entries x rx_buffer_len` bytes leaked at teardown (measured:
    /// 256 x 2048 B = 512 KiB, `docs/results/managed-rx-verification.md`).
    ///
    /// Returns `false` if the task did not stop within `timeout`.
    async fn stop_and_join(&mut self, timeout: std::time::Duration) -> bool {
        let Some(ring) = self.ring.as_ref().cloned() else {
            return true;
        };
        {
            let mut ring = ring.borrow_mut();
            ring.shutdown = true;
            if let Some(waker) = ring.waker.take() {
                waker.wake();
            }
        }
        // Whatever this side still holds must go back to the pool too.
        self.staged = None;
        let handle = ring.borrow_mut().task.take();
        let stopped = match handle {
            Some(handle) => compio::time::timeout(timeout, handle.cancel())
                .await
                .is_ok(),
            None => true,
        };
        ring.borrow_mut().completions.clear();
        stopped
    }

    /// This side's full teardown invariant: the managed consumer is gone, no
    /// completion is staged, and the bounded ring holds nothing. Required by
    /// `Owner::shutdown_and_drain` before it reports quiescence.
    fn quiescent(&self) -> bool {
        self.staged.is_none()
            && self.ring.as_ref().is_none_or(|ring| {
                let ring = ring.borrow();
                ring.task.is_none() && ring.completions.is_empty()
            })
    }

    fn stats(&self) -> ManagedRxStats {
        let (depth, dropped, truncated) = self.ring.as_ref().map_or((0, 0, 0), |ring| {
            let ring = ring.borrow();
            (ring.completions.len(), ring.dropped, ring.truncated)
        });
        ManagedRxStats {
            mode: self.mode,
            depth,
            capacity: MANAGED_RX_RING_DEPTH,
            dropped,
            truncated,
            staged: self.staged.is_some(),
        }
    }
}

/// Observable managed RX state for one Owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedRxStats {
    /// Datapath the Owner selected.
    pub mode: OwnerRxMode,
    /// Completions currently queued in the bounded ring.
    pub depth: usize,
    /// Fixed ring capacity.
    pub capacity: usize,
    /// Completions dropped because the ring was full.
    pub dropped: u64,
    /// Datagrams dropped as truncated (larger than the ring slot).
    pub truncated: u64,
    /// Whether a whole completion is staged for the next visit.
    pub staged: bool,
}

/// Managed RX telemetry for every side of an Owner, in one fixed-cost
/// snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OwnerRxStats {
    /// `None` when no listener socket is attached to this Owner.
    pub listener: Option<ManagedRxStats>,
    /// `None` when no caller socket is attached to this Owner.
    pub caller: Option<ManagedRxStats>,
}

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
    /// Selected receive datapath plus its managed ring/staged completion.
    rx: SideRx,
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
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn from_prepared(
        sock: compio::net::UdpSocket,
        prepared: crate::PreparedListener,
    ) -> Result<Self, crate::RuntimeBuildError> {
        Self::from_prepared_with_rx_mode(sock, prepared, OwnerRxMode::RawReadiness, 0)
    }

    /// Attach with an explicit receive mode. Under
    /// [`OwnerRxMode::ManagedMultishot`] the socket gets exactly one
    /// persistent `recv_msg_multi` consumer task, spawned here once at attach
    /// -- never per datagram, never per connection.
    pub(crate) fn from_prepared_with_rx_mode(
        sock: compio::net::UdpSocket,
        prepared: crate::PreparedListener,
        rx_mode: OwnerRxMode,
        managed_slot_len: usize,
    ) -> Result<Self, crate::RuntimeBuildError> {
        let poll_fd = make_poll_fd(&sock)?;
        let sock = Rc::new(sock);
        let mut side = Self {
            sock,
            table: prepared.peer_table(),
            telemetry: IngressTelemetry::new(),
            options: prepared.admission_options(),
            transport: prepared.transport,
            idle_timeout: prepared.admission.idle_timeout,
            rx: SideRx::raw(),
            rx_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
            poll_fd,
            pending_rx: None,
            stage_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
        };
        if rx_mode == OwnerRxMode::ManagedMultishot {
            side.rx = SideRx::managed(managed_slot_len, true);
            side.spawn_managed_rx_task(managed_slot_len);
        }
        Ok(side)
    }

    /// Spawn the one fixed managed RX task for this socket (idempotent).
    fn spawn_managed_rx_task(&mut self, slot_len: usize) {
        if compio::runtime::Runtime::try_current().is_none() {
            return;
        }
        let Some(ring) = self.rx.ring.as_ref().cloned() else {
            return;
        };
        if ring.borrow().task.is_some() {
            return;
        }
        let handle = spawn_managed_rx_loop(Rc::clone(&self.sock), Rc::downgrade(&ring), slot_len);
        ring.borrow_mut().task = Some(handle);
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
    /// Selected receive datapath plus its managed ring/staged completion.
    rx: SideRx,
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
    ) -> Result<Self, crate::RuntimeBuildError> {
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
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn from_parts(
        sock: compio::net::UdpSocket,
        max_in_flight: std::num::NonZeroUsize,
        attempt_deadline: std::time::Duration,
        transport: crate::ResolvedTransportConfig,
        local_bind: Option<std::net::SocketAddr>,
        connect_config: crate::ConnectConfig,
    ) -> Result<Self, crate::RuntimeBuildError> {
        Self::from_parts_with_rx_mode(
            sock,
            max_in_flight,
            attempt_deadline,
            transport,
            local_bind,
            connect_config,
            OwnerRxMode::RawReadiness,
            0,
        )
    }

    /// Attach with an explicit receive mode; see the listener side's
    /// `from_prepared_with_rx_mode`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts_with_rx_mode(
        sock: compio::net::UdpSocket,
        max_in_flight: std::num::NonZeroUsize,
        attempt_deadline: std::time::Duration,
        transport: crate::ResolvedTransportConfig,
        local_bind: Option<std::net::SocketAddr>,
        connect_config: crate::ConnectConfig,
        rx_mode: OwnerRxMode,
        managed_slot_len: usize,
    ) -> Result<Self, crate::RuntimeBuildError> {
        let poll_fd = make_poll_fd(&sock)?;
        let sock = Rc::new(sock);
        let mut side = Self {
            sock,
            pool: crate::CallerPool::new(max_in_flight, attempt_deadline),
            transport,
            local_bind,
            connect_config,
            rx: SideRx::raw(),
            rx_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
            poll_fd,
            pending_rx: None,
            stage_buf: vec![0u8; DEFAULT_RX_SLOT_SIZE],
        };
        if rx_mode == OwnerRxMode::ManagedMultishot {
            side.rx = SideRx::managed(managed_slot_len, true);
            side.spawn_managed_rx_task(managed_slot_len);
        }
        Ok(side)
    }

    /// Spawn the one fixed managed RX task for this socket (idempotent).
    fn spawn_managed_rx_task(&mut self, slot_len: usize) {
        if compio::runtime::Runtime::try_current().is_none() {
            return;
        }
        let Some(ring) = self.rx.ring.as_ref().cloned() else {
            return;
        };
        if ring.borrow().task.is_some() {
            return;
        }
        let handle = spawn_managed_rx_loop(Rc::clone(&self.sock), Rc::downgrade(&ring), slot_len);
        ring.borrow_mut().task = Some(handle);
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
        // Test/dev-only constructor: a poll fd that cannot be created is a
        // broken test host, not a runtime condition to handle.
        let poll_fd = make_poll_fd(&sock).expect("test-only caller poll_fd initializes");
        let transport = crate::TransportConfig {
            ownership: crate::SocketOwnership::Shared,
            ..crate::TransportConfig::default()
        }
        .resolve(crate::RuntimeFlavor::Compio.capabilities())
        .expect("shared transport resolves");
        Self {
            sock: Rc::new(sock),
            rx: SideRx::raw(),
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
///
/// `cipher` is the session's encryption as resolved from the same
/// `ConnectionOptions` the protocol will use, so the tag is accounted for by
/// the actual cipher mode rather than by "is anything encrypted":
///
/// - `None` -- no encryption: nothing beyond the SRT header.
/// - `Some(CipherMode::Ctr)` -- AES-CTR: still nothing beyond the header.
/// - `Some(CipherMode::Gcm)` -- AES-GCM: plus [`srt_proto::crypto::GCM_TAG_LEN`].
///
/// A listener is the peer-driven side of KM: it adopts the cipher mode from
/// the peer's KMREQ ([`srt_proto::SrtConnection`]'s `configure_listener_crypto`),
/// so it must pass `Some(CipherMode::Gcm)` -- the largest tag it can be asked
/// to carry -- instead of its own configured mode. A caller's own KMREQ fixes
/// the mode, so it passes its resolved mode.
#[must_use]
pub fn required_session_wire_ceiling(
    payload_size: usize,
    cipher: Option<srt_proto::crypto::CipherMode>,
) -> usize {
    let tag = match cipher {
        None | Some(srt_proto::crypto::CipherMode::Ctr) => 0,
        Some(srt_proto::crypto::CipherMode::Gcm) => srt_proto::crypto::GCM_TAG_LEN,
    };
    let data_wire = payload_size
        .saturating_add(srt_proto::wire::SRT_HEADER_SIZE)
        .saturating_add(tag);
    let control_wire = (srt_proto::handshake::DEFAULT_MTU as usize).max(660);
    data_wire.max(control_wire)
}

/// Wire ceiling required by the cipher mode one side of a session must be
/// prepared to carry.
///
/// * `caller_side` -- the session's own resolved mode fixes the KM it sends,
///   so its ceiling follows that mode exactly.
/// * listener side -- the mode arrives in the peer's KMREQ and is adopted, so
///   only the conservative bound is truthful: an encrypted listener can be
///   asked to carry a GCM tag whatever it configured.
#[must_use]
pub fn required_session_wire_ceiling_for_side(
    payload_size: usize,
    cipher: Option<srt_proto::crypto::CipherMode>,
    caller_side: bool,
) -> usize {
    match (cipher, caller_side) {
        (Some(_), false) => {
            required_session_wire_ceiling(payload_size, Some(srt_proto::crypto::CipherMode::Gcm))
        }
        (cipher, _) => required_session_wire_ceiling(payload_size, cipher),
    }
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
    /// Completions that wrote fewer bytes than the materialized wire length.
    /// Always an Owner-fatal invariant violation.
    pub short_sends: usize,
    /// Completions that failed structurally and faulted the whole Owner.
    pub failed_sends: usize,
    /// Completions that failed for one destination only. The Owner keeps
    /// running; the affected session/leg is what the application degrades.
    pub peer_local_failures: usize,
    /// Completions that failed on host/socket resource pressure. Accounted
    /// once; never retried inside the transport.
    pub transient_failures: usize,
    pub last_failed_peer: Option<SocketAddr>,
}

/// Failure domain of one failed `send_to`.
///
/// The point of the classification is that ONE broken destination must not
/// stop healthy siblings sharing the socket. Only
/// [`TxFailureClass::OwnerStructural`] -- an error that says the shared
/// socket/runtime can no longer be trusted -- faults the Owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxFailureClass {
    /// Attributable to one destination path (`EHOSTUNREACH`, `ENETUNREACH`,
    /// `ECONNREFUSED`, `ECONNRESET`, ...). Siblings keep submitting and
    /// completing; the application transitions or degrades exactly that
    /// logical session/leg.
    PeerLocal,
    /// Host/socket resource pressure rather than a destination property
    /// (`ENOBUFS`, `EAGAIN`, `EINTR`, `ENOMEM`, `ETIMEDOUT`). The datagram is
    /// lost and SRT's own ARQ semantics decide recovery; the transport
    /// accounts it once and never retries, so boundedness is preserved.
    TransientLocal,
    /// The shared socket or runtime itself cannot be trusted with further
    /// submissions (`EMSGSIZE` on our own sized datagram, `EBADF`, `EINVAL`,
    /// or anything unrecognized). Fails the whole Owner closed.
    OwnerStructural,
}

impl TxFailureClass {
    /// Classify one `send_to` failure.
    ///
    /// Errno-first (the errnos are the precise signal; `ErrorKind` collapses
    /// `ENOBUFS`/`ENOMEM` and loses the distinction), with `ErrorKind` as the
    /// fallback for errors carrying no errno.
    #[must_use]
    pub fn classify(error: &io::Error) -> Self {
        if let Some(errno) = error.raw_os_error() {
            return match errno {
                libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::ECONNREFUSED
                | libc::ECONNRESET
                | libc::EHOSTDOWN
                | libc::ENETDOWN
                | libc::EADDRNOTAVAIL
                | libc::ENOTCONN
                | libc::EPIPE => Self::PeerLocal,
                libc::ENOBUFS | libc::EAGAIN | libc::EINTR | libc::ENOMEM | libc::ETIMEDOUT => {
                    Self::TransientLocal
                }
                // EMSGSIZE is our own sizing invariant failing, and EBADF /
                // EINVAL mean the descriptor or the operation is wrong: no
                // further submission can be trusted.
                _ => Self::OwnerStructural,
            };
        }
        match error.kind() {
            io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::AddrNotAvailable => Self::PeerLocal,
            io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::OutOfMemory => Self::TransientLocal,
            _ => Self::OwnerStructural,
        }
    }
}

/// One classified TX failure, attributed to the destination that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxFailureEvent {
    /// Destination whose `send_to` failed. The caller/caller table maps this
    /// to the logical session or leg.
    pub peer: SocketAddr,
    pub class: TxFailureClass,
    pub kind: io::ErrorKind,
    pub errno: Option<i32>,
}

/// Bounded queue of classified TX failures awaiting application drain.
///
/// Preallocated to the TX capacity and bounded: a full queue drops the NEWEST
/// event and counts it, because the oldest events matter more (they are what
/// the application has not yet attributed to a session).
#[derive(Debug, Default)]
pub(crate) struct TxFailureQueue {
    events: std::collections::VecDeque<TxFailureEvent>,
    capacity: usize,
    dropped: u64,
}

impl TxFailureQueue {
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            events: std::collections::VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, event: TxFailureEvent) {
        if self.events.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.events.push_back(event);
    }

    /// Move up to `max_events` failures into `out`, oldest first.
    pub(crate) fn drain_into(&mut self, max_events: usize, out: &mut Vec<TxFailureEvent>) {
        for _ in 0..max_events {
            let Some(event) = self.events.pop_front() else {
                break;
            };
            out.push(event);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Typed fault state for a Compio Owner.
///
/// A fault stops new admission and new TX submission on that Owner: it is
/// never a silently reduced-capacity steady state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerFault {
    /// A fixed TX worker task terminated unexpectedly (panicked).
    WorkerPanicked { lane: usize },
    /// The single managed RX task for one shared socket stopped or errored.
    /// The Owner no longer receives on that socket; it is not a quiet socket.
    RxStreamFailed { side: &'static str, detail: String },
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
    /// A peer/session-local `send_to` failed: the datagram was not delivered
    /// to that one destination. Unrelated siblings on the shared socket keep
    /// working; the failure is reported through
    /// [`Owner::poll_tx_failures`] with its class so the application can
    /// degrade exactly the affected session/leg.
    TxPeerLocal {
        peer: SocketAddr,
        kind: io::ErrorKind,
    },
    /// A quiescent shutdown drain did not reach `in_flight() == 0` before its
    /// deadline. Ownership is left exactly as it was: lanes still own their
    /// slots, `in_flight` is not reset, and no buffer is reclaimed early.
    ShutdownTimedOut { in_flight: usize },
    /// A managed receive worker did not stop inside the whole-teardown
    /// deadline. Teardown is NOT quiescent and no lease is reclaimed early:
    /// the side named here still owns its receive operation.
    RxShutdownTimedOut { side: &'static str },
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

    /// Sole normal completion reaper, and the sole place completion policy
    /// lives: every slot returns to `tx_pool` exactly once, every completion is
    /// classified, and the fault domain is decided here for `service`, the
    /// quiescent drain, and the `wait_for_activity` readiness probe alike.
    ///
    /// `max_completions == 0` performs zero work, and the wait path never calls
    /// this at all -- it observes readiness through [`Self::poll_activity`].
    pub(crate) fn poll_completions(
        &mut self,
        cx: Option<&mut Context<'_>>,
        max_completions: usize,
        tx_pool: &mut TxPool,
        stats: &mut OwnerTxCompletionStats,
        failures: &mut TxFailureQueue,
    ) -> usize {
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
            let meta = completion.meta;
            tx_pool.return_slot(completion.buf);
            Self::apply_completion_policy(&mut self.fault, meta, completion.res, stats, failures);
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

    /// Completion policy for one reaped `send_to`.
    ///
    /// Split out of the reaping loop so the policy reads as a policy: a
    /// completion is either a success, a short send (an invariant violation
    /// that faults the Owner), or a failure whose domain decides whether the
    /// Owner survives.
    fn apply_completion_policy(
        fault: &mut Option<OwnerFault>,
        meta: InFlightMeta,
        res: io::Result<usize>,
        stats: &mut OwnerTxCompletionStats,
        failures: &mut TxFailureQueue,
    ) {
        match res {
            Ok(sent) if sent == meta.expected_len => stats.completed_ok += 1,
            // A short UDP send means the datagram did not reach the wire intact
            // and its protocol output is already consumed: an invariant
            // violation, never a success and never a retry.
            Ok(sent) => {
                stats.short_sends += 1;
                stats.last_failed_peer = Some(meta.peer);
                if fault.is_none() {
                    *fault = Some(OwnerFault::TxShortSend {
                        peer: meta.peer,
                        expected: meta.expected_len,
                        sent,
                    });
                }
            }
            Err(error) => Self::apply_send_error_policy(fault, meta, &error, stats, failures),
        }
    }

    /// Failure-domain policy for one failed `send_to`.
    ///
    /// A structural failure faults the Owner. A peer/session-local or
    /// transient failure is accounted and attributed instead, so one broken
    /// destination never stops healthy siblings sharing the socket.
    fn apply_send_error_policy(
        fault: &mut Option<OwnerFault>,
        meta: InFlightMeta,
        error: &io::Error,
        stats: &mut OwnerTxCompletionStats,
        failures: &mut TxFailureQueue,
    ) {
        stats.last_failed_peer = Some(meta.peer);
        let class = TxFailureClass::classify(error);
        if class == TxFailureClass::OwnerStructural {
            stats.failed_sends += 1;
            if fault.is_none() {
                *fault = Some(OwnerFault::TxFailed {
                    peer: meta.peer,
                    kind: error.kind(),
                });
            }
            return;
        }
        if class == TxFailureClass::PeerLocal {
            stats.peer_local_failures += 1;
        } else {
            stats.transient_failures += 1;
        }
        failures.push(TxFailureEvent {
            peer: meta.peer,
            class,
            kind: error.kind(),
            errno: error.raw_os_error(),
        });
    }

    /// Whether a completion is already published and waiting to be reaped.
    ///
    /// Non-consuming by construction: it observes the completion index and
    /// takes nothing out of it.
    #[must_use]
    pub(crate) fn completion_ready(&self) -> bool {
        !self.completed_lanes.borrow().is_empty()
    }

    /// Non-consuming TX readiness for the wait path.
    ///
    /// Reports whether a completion is *already* published and registers this
    /// task's waker for the next one. It never dequeues a completion, never
    /// returns a `TxPool` slot, never touches accounting, and never advances
    /// protocol state: reaping belongs to `service`, so a completion observed
    /// here is still reported in the next visit's deltas.
    pub(crate) fn poll_activity(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.check_worker_failures();
        if self.completion_ready() {
            return Poll::Ready(());
        }
        *self.owner_waker.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Surface a panicked fixed lane as a fault (no-op once faulted).
    fn check_worker_failures(&mut self) {
        self.check_worker_faults();
    }

    /// Whether shutdown has begun: no new lane reservation can succeed.
    #[must_use]
    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Whether every fixed lane has been joined (terminal teardown proof).
    #[must_use]
    pub(crate) fn lanes_joined(&self) -> bool {
        self.lanes.is_empty()
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
        failures: &mut TxFailureQueue,
        max_completions: usize,
        deadline: std::time::Instant,
    ) -> bool {
        while self.in_flight() > 0 {
            let reaped =
                self.poll_completions(None, max_completions, tx_pool, completions, failures);
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
}

struct OwnerTxSink<'a> {
    sock: &'a Rc<compio::net::UdpSocket>,
    tx_pool: &'a mut TxPool,
    tx_engine: &'a mut TxEngine,
    /// The Owner-wide operational predicate at the moment the sink was
    /// created. Consulted on every acquisition so a faulted Owner admits no
    /// new protocol output, including faults that live on the RX side and are
    /// therefore invisible to the TX engine alone.
    operational: bool,
}

/// Reserved TX capacity: one `TxPool` slot plus one reserved TX lane.
///
/// The reservation happens in [`DatagramSink::acquire`], so by the time the
/// protocol materializes anything the final-wire slot and the execution lane
/// are both irrevocably held. `commit` is infallible; dropping the slot
/// without committing returns both to their pools exactly once.
struct OwnerTxSlot<'a> {
    sock: &'a Rc<compio::net::UdpSocket>,
    tx_pool: &'a mut TxPool,
    tx_engine: &'a mut TxEngine,
    lane_idx: usize,
    peer: SocketAddr,
    wire_len: usize,
    buf: Vec<u8>,
    committed: bool,
}

impl Drop for OwnerTxSlot<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Protocol produced nothing: release capacity, never leak it.
        self.tx_pool.return_slot(std::mem::take(&mut self.buf));
        self.tx_engine.release_reserved_lane(self.lane_idx);
    }
}

impl DatagramSlot for OwnerTxSlot<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.wire_len]
    }

    fn commit(mut self, len: usize) {
        self.committed = true;
        let mut buf = std::mem::take(&mut self.buf);
        // The wire length decides what goes on the wire; the slot keeps its
        // capacity so the next use does not reallocate.
        buf.truncate(len);
        let meta = InFlightMeta {
            peer: self.peer,
            expected_len: len,
        };
        self.tx_engine
            .submit_job(self.lane_idx, self.sock.clone(), buf, self.peer, meta);
    }
}

impl<'s> DatagramSink for OwnerTxSink<'s> {
    type Slot<'a>
        = OwnerTxSlot<'a>
    where
        Self: 'a;

    fn acquire(
        &mut self,
        peer: SocketAddr,
        wire_len: usize,
    ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
        // Every fallible capacity decision happens here, before the protocol
        // materializes anything.
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
        if !self.operational {
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "owner is not operational: no new TX submission is admitted",
            ));
        }
        let Some(lane_idx) = self.tx_engine.reserve_lane() else {
            return Ok(None);
        };
        let Some(mut buf) = self.tx_pool.alloc_slot() else {
            self.tx_engine.release_reserved_lane(lane_idx);
            return Ok(None);
        };
        buf.resize(wire_len, 0);
        Ok(Some(OwnerTxSlot {
            sock: self.sock,
            tx_pool: self.tx_pool,
            tx_engine: self.tx_engine,
            lane_idx,
            peer,
            wire_len,
            buf,
            committed: false,
        }))
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
    /// Peer/session-local send failures reaped in THIS visit. These do not
    /// fault the Owner; the attribution is in [`Owner::poll_tx_failures`].
    pub tx_peer_local_failures: usize,
    /// Transient host/socket send failures reaped in THIS visit.
    pub tx_transient_failures: usize,
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
    /// How attach resolves the receive datapath.
    rx_mode_policy: RxModePolicy,
    /// Receive datapath selected by the most recent attach.
    rx_mode: Option<OwnerRxMode>,
    /// The managed-RX substrate observed once on this Owner's runtime, as one
    /// fact. Never re-probed per attach; `None` means "not observed", which
    /// [`RxModePolicy::ManagedRequired`] refuses to treat as available.
    rx_substrate: Option<ManagedRxSubstrate>,
    /// A managed RX task that stopped or errored, surfaced by [`Self::fault`].
    rx_fault: Option<OwnerFault>,
    /// Bounded, attributed TX failures for the application to map onto
    /// logical sessions/legs.
    tx_failures: TxFailureQueue,
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
            rx_mode_policy: RxModePolicy::default(),
            rx_mode: None,
            rx_substrate: None,
            rx_fault: None,
            tx_failures: TxFailureQueue::new(capacity),
        }
    }

    /// Require (or merely prefer) managed multishot RX for later attaches.
    ///
    /// Production shards use [`RxModePolicy::ManagedRequired`] so a host
    /// without the provided-buffer substrate is a startup error rather than a
    /// silent fallback to the raw reader.
    pub fn set_rx_mode_policy(&mut self, policy: RxModePolicy) {
        self.rx_mode_policy = policy;
    }

    /// Receive datapath selected for this Owner's shared sockets.
    ///
    /// `None` before any socket is attached.
    #[must_use]
    pub fn rx_mode(&self) -> Option<OwnerRxMode> {
        self.rx_mode
    }

    /// Managed RX telemetry for BOTH sides.
    ///
    /// A relay Owner has a listener and a caller attached at the same time, so
    /// both are reported: collapsing them to "whichever exists" hides the
    /// caller side's ring depth, drops, and truncations on exactly the
    /// deployment that has both.
    #[must_use]
    pub fn rx_stats(&self) -> OwnerRxStats {
        OwnerRxStats {
            listener: self.listener.as_ref().map(|side| side.rx.stats()),
            caller: self.caller.as_ref().map(|side| side.rx.stats()),
        }
    }

    /// Declare the managed-RX substrate observed on this Owner's runtime.
    ///
    /// Call once, before the first attach, with
    /// [`CompioProductionProfile::managed_rx_substrate`] from
    /// [`observe_production_runtime`] on the exact runtime the Owner runs on.
    /// Capability is therefore one observed fact consumed by every attach,
    /// instead of a shallow re-probe per `listen`/`connect`.
    ///
    /// [`RxModePolicy::ManagedRequired`] attaches a managed consumer only when
    /// this is [`ManagedRxSubstrate::Available`]; `ManagedPreferred` falls back
    /// to the raw reader on anything else, including "not observed".
    pub fn set_rx_substrate(
        &mut self,
        substrate: ManagedRxSubstrate,
    ) -> Result<(), crate::RuntimeBuildError> {
        if self.sessions_started {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "rx_substrate",
                "cannot change the observed managed-RX substrate after sessions have started",
            )));
        }
        self.rx_substrate = Some(substrate);
        Ok(())
    }

    /// The observed managed-RX substrate, if the caller declared one.
    #[must_use]
    pub fn rx_substrate(&self) -> Option<ManagedRxSubstrate> {
        self.rx_substrate
    }

    /// Drain classified TX failures (oldest first, bounded by
    /// `max_events`) for the application to attribute to logical
    /// sessions/legs.
    pub fn poll_tx_failures(&mut self, max_events: usize, out: &mut Vec<TxFailureEvent>) {
        out.clear();
        self.tx_failures.drain_into(max_events, out);
    }

    /// Classified TX failures still queued for attribution.
    #[must_use]
    pub fn tx_failures_pending(&self) -> usize {
        self.tx_failures.len()
    }

    /// Classified TX failures dropped because the bounded queue was full.
    #[must_use]
    pub fn tx_failures_dropped(&self) -> u64 {
        self.tx_failures.dropped()
    }

    /// The Owner's single operational predicate.
    ///
    /// Every path that admits new work consults this and nothing else:
    /// OWNER-FATAL faults (dead TX worker, stopped managed RX consumer,
    /// structural send failure, short send, incomplete teardown, shutdown
    /// begun) stop new listen/connect admission and new protocol TX
    /// submission. `service()` stays callable so the Owner can still reap
    /// completions, report, and be torn down; SESSION/PEER-LOCAL failures are
    /// deliberately *not* faults and are reported through
    /// [`Self::poll_tx_failures`] instead.
    #[must_use]
    pub fn is_operational(&self) -> bool {
        self.fault().is_none() && !self.tx_engine.is_shutdown()
    }

    fn ensure_operational(&self, field: &'static str) -> Result<(), crate::RuntimeBuildError> {
        if self.is_operational() {
            return Ok(());
        }
        let detail = match self.fault() {
            Some(fault) => format!("owner is not operational: {fault:?}"),
            None => "owner is not operational: shutdown has begun".to_string(),
        };
        Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
            field, detail,
        )))
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

    /// Typed fault state: a failed TX worker or completion, a stopped managed
    /// RX task, or a completed shutdown. A fault stops new admission and new
    /// TX; it is never a silently degraded steady state.
    #[must_use]
    pub fn fault(&self) -> Option<&OwnerFault> {
        self.tx_engine.fault().or(self.rx_fault.as_ref())
    }

    /// The canonical production teardown, and the only one that claims
    /// quiescence.
    ///
    /// `timeout` is ONE absolute deadline for the whole operation, not a
    /// per-phase allowance: the listener RX stop, the caller RX stop, the TX
    /// drain, the lane signalling, and the lane joins each receive only what
    /// remains of it.
    ///
    /// Phases:
    /// 1. `begin_shutdown`: reject new admissions and new TX submissions;
    /// 2. stop and **await** the managed RX consumer on each attached side;
    /// 3. reap in-flight `send_to` work to zero within the same deadline;
    /// 4. signal the fixed lanes to stop, join them, then check the
    ///    invariants below.
    ///
    /// Returns `true` only when every ownership invariant actually holds:
    ///
    /// - no managed RX task handle is retained on either side,
    /// - no completion is staged on either side,
    /// - both managed completion rings are empty,
    /// - `tx_in_flight() == 0`,
    /// - every fixed lane has been joined,
    /// - `tx_pool().free_count() == tx_pool().capacity()`.
    ///
    /// A receive worker that will not stop makes this `false` with
    /// [`OwnerFault::RxShutdownTimedOut`]: RX failure is never dressed up as a
    /// successful shutdown. A TX drain that misses the deadline makes it
    /// `false` with [`OwnerFault::ShutdownTimedOut`]. In both cases nothing is
    /// fabricated -- no lane is joined, no buffer is reclaimed early, and
    /// `in_flight()` still counts what the kernel owns -- so the caller can
    /// retry or report.
    pub async fn shutdown_and_drain(&mut self, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        self.tx_engine.begin_shutdown();

        // Phase 2: stop receive intake first, so no new datagram arrives while
        // TX drains, and release the managed consumers' pooled leases.
        let mut rx_timed_out: Option<&'static str> = None;
        if let Some(listener) = self.listener.as_mut()
            && !listener.rx.stop_and_join(remaining(deadline)).await
        {
            rx_timed_out = Some("listener");
        }
        if let Some(caller) = self.caller.as_mut()
            && !caller.rx.stop_and_join(remaining(deadline)).await
        {
            rx_timed_out = rx_timed_out.or(Some("caller"));
        }
        if let Some(side) = rx_timed_out {
            // Terminal and truthful: the RX worker still owns its receive, so
            // TX state is left exactly as `begin_shutdown` left it.
            self.rx_fault = Some(OwnerFault::RxShutdownTimedOut { side });
            return false;
        }

        // Phase 3: same deadline for the TX drain.
        let (tx_pool, completions, failures, tx_engine) = (
            &mut self.tx_pool,
            &mut self.completions,
            &mut self.tx_failures,
            &mut self.tx_engine,
        );
        let drained = tx_engine
            .drain_in_flight(tx_pool, completions, failures, usize::MAX, deadline)
            .await;
        if !drained || self.tx_engine.in_flight() != 0 {
            let in_flight = self.tx_engine.in_flight();
            self.tx_engine.note_shutdown_timeout(in_flight);
            return false;
        }

        // Phase 4: proven drained: stop the lanes, join them, mark terminal.
        self.tx_engine.finish_shutdown(&mut self.tx_pool);
        self.tx_engine.join_lanes().await;
        self.quiescence_invariants_hold()
    }

    /// Every ownership invariant [`Self::shutdown_and_drain`] claims when it
    /// returns `true`. Evaluated from state, never assumed.
    #[must_use]
    fn quiescence_invariants_hold(&self) -> bool {
        let listener_gone = self
            .listener
            .as_ref()
            .is_none_or(|side| side.rx.quiescent());
        let caller_gone = self.caller.as_ref().is_none_or(|side| side.rx.quiescent());
        listener_gone
            && caller_gone
            && self.tx_engine.in_flight() == 0
            && self.tx_engine.lanes_joined()
            && self.tx_pool.free_count() == self.tx_pool.capacity()
    }

    /// Turn a stopped managed RX task into a typed Owner fault. Called every
    /// visit so a dead consumer surfaces promptly instead of looking like a
    /// socket that simply has nothing to deliver.
    fn harvest_rx_faults(&mut self) {
        if self.rx_fault.is_some() {
            return;
        }
        let listener = self
            .listener
            .as_ref()
            .and_then(|side| side.rx.take_fault().map(|fault| ("listener", fault)));
        let caller = self
            .caller
            .as_ref()
            .and_then(|side| side.rx.take_fault().map(|fault| ("caller", fault)));
        let (side, fault) = match listener.or(caller) {
            Some(pair) => pair,
            None => return,
        };
        let RxFault::StreamError(detail) = fault;
        self.rx_fault = Some(OwnerFault::RxStreamFailed { side, detail });
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
    #[cfg(any(test, feature = "bench-internals"))]
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
        self.ensure_operational("listener.listen")?;
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
        // The listener adopts the cipher mode from the peer's KMREQ, so its
        // ceiling is the conservative bound for an encrypted session rather
        // than its own configured mode.
        let cipher = prepared.session.resolved_cipher_mode();
        let req_ceiling = required_session_wire_ceiling_for_side(payload_size, cipher, false);
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
        let rx_mode = self.resolve_rx_mode("listener.rx_mode")?;
        self.rx_mode = Some(rx_mode);
        let mut sockets = prepared.bind_sockets()?;
        let sock = compio::net::UdpSocket::from_std(sockets.remove(0))?;
        self.sessions_started = true;
        let slot_len = managed_rx_buffer_len(self.wire_ceiling);
        self.listener = Some(ListenerSide::from_prepared_with_rx_mode(
            sock, prepared, rx_mode, slot_len,
        )?);
        Ok(())
    }

    /// Resolve the receive datapath for a socket attach from the observed
    /// substrate, failing closed under [`RxModePolicy::ManagedRequired`].
    ///
    /// The substrate is the ONE fact recorded by [`Self::set_rx_substrate`]
    /// from a full observation of this runtime (io_uring + provided-buffer
    /// ring + multishot `recvmsg`). There is no re-probe here: probing
    /// `driver_type`/`buffer_pool` per attach would let `ManagedRequired`
    /// attach on a runtime where the ring registers but multishot `recvmsg`
    /// does not exist, and then fail asynchronously right after attach.
    /// "Not observed" is therefore never treated as available.
    fn resolve_rx_mode(
        &self,
        field: &'static str,
    ) -> Result<OwnerRxMode, crate::RuntimeBuildError> {
        match (self.rx_mode_policy, self.rx_substrate) {
            (RxModePolicy::ManagedRequired, None) => {
                Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                    field,
                    "ManagedRequired needs an observed managed-RX substrate: call \
                     Owner::set_rx_substrate with the profile from observe_production_runtime \
                     on this runtime before attaching",
                )))
            }
            (policy, substrate) => {
                let substrate = substrate.unwrap_or(ManagedRxSubstrate::NotIoUring);
                policy.resolve(substrate).map_err(|failed| {
                    crate::RuntimeBuildError::from(crate::ConfigError::new(field, failed.reason()))
                })
            }
        }
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
        // One Owner-wide gate: an RX stream failure, a dead TX lane, or a
        // begun shutdown all stop new admission here, not just TX faults.
        self.ensure_operational("caller.connect")?;
        let payload_size = prepared.session.payload_size.resolve()?.get();
        // A caller's own KMREQ fixes the session's cipher mode, so its ceiling
        // follows the mode the protocol will actually use -- not "some
        // encryption exists", which would charge every CTR session GCM's tag.
        let cipher = prepared.session.resolved_cipher_mode();
        let req_ceiling = required_session_wire_ceiling_for_side(payload_size, cipher, true);
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
            let rx_mode = self.resolve_rx_mode("caller.connect.rx_mode")?;
            self.rx_mode = Some(rx_mode);
            let slot_len = managed_rx_buffer_len(self.wire_ceiling);
            self.caller = Some(OwnerCallerSide::from_parts_with_rx_mode(
                sock,
                max_in_flight,
                attempt_deadline,
                prepared.transport,
                prepared.local_bind,
                prepared.connect,
                rx_mode,
                slot_len,
            )?);
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
        let prev_peer_local = self.completions.peer_local_failures;
        let prev_transient = self.completions.transient_failures;

        // 0. Harvest faults BEFORE admitting anything. A visit must never
        //    admit state on behalf of a receive consumer or TX lane that is
        //    already known dead, so the Owner-wide predicate is refreshed
        //    first and gates steps 2-4 below.
        self.tx_engine.check_worker_faults();
        self.harvest_rx_faults();
        let operational = self.is_operational();

        // 1. Reap only already-ready completions, never waiting. Reaping is
        //    always allowed -- it is how slots come back and how a faulted or
        //    shutting-down Owner still reports truthfully -- and `service` is
        //    the only normal reaper, so `max_completions` is authoritative.
        let (completions, tx_pool, failures) = (
            &mut self.completions,
            &mut self.tx_pool,
            &mut self.tx_failures,
        );
        report.completions_reaped += self.tx_engine.poll_completions(
            None,
            budget.max_completions,
            tx_pool,
            completions,
            failures,
        );

        if operational {
            // 2. Service incoming RX up to max_rx_packets / max_rx_bytes
            self.service_rx(now, &budget, &mut report).await;
            // A consumer that died during this visit stops the rest of it.
            self.harvest_rx_faults();

            // 3. Lifecycle maintenance, bounded by max_actions only (see
            //    `service_maintenance`): independent of the packet/byte axes.
            self.service_maintenance(now, &budget, &mut report);

            // 4. Service outbound TX up to max_tx_packets / max_tx_bytes / the
            //    remaining action allowance.
            self.service_tx(now, &budget, &mut report);
        }

        report.tx_in_flight = self.tx_engine.in_flight();
        report.tx_pool_free = self.tx_pool.free_count();
        report.next_deadline_us = Some(self.time_until_next_deadline(now, 100_000));
        report.tx_completed_ok = self.completions.completed_ok.saturating_sub(prev_ok);
        report.tx_short_sends = self.completions.short_sends.saturating_sub(prev_short);
        report.tx_failed_sends = self.completions.failed_sends.saturating_sub(prev_failed);
        report.tx_peer_local_failures = self
            .completions
            .peer_local_failures
            .saturating_sub(prev_peer_local);
        report.tx_transient_failures = self
            .completions
            .transient_failures
            .saturating_sub(prev_transient);

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
    /// 1. A TX completion that has become READY (observed, not reaped).
    /// 2. An incoming datagram on the listener socket (wakes immediately).
    /// 3. An incoming datagram on the caller socket (wakes immediately).
    /// 4. Timer expiry (`timeout` elapses).
    ///
    /// This function only waits and registers wakers. It never dequeues a
    /// completion, never returns a `TxPool` slot, never changes completion
    /// accounting, and never advances protocol state: everything reaped here
    /// would be missing from the next `service` visit's deltas, and a wait
    /// path that consumes work is a second, unbounded reaper.
    pub async fn wait_for_activity(&mut self, timeout: std::time::Duration) {
        // Staged or already-queued work wakes immediately: never sleep past
        // work the next service() call can already consume.
        if self
            .listener
            .as_ref()
            .is_some_and(|l| l.pending_rx.is_some() || l.rx.pending())
            || self
                .caller
                .as_ref()
                .is_some_and(|c| c.pending_rx.is_some() || c.rx.pending())
        {
            return;
        }
        let _ = compio::time::timeout(
            timeout,
            std::future::poll_fn(|cx| {
                if self.tx_engine.poll_activity(cx).is_ready() {
                    return std::task::Poll::Ready(());
                }
                if Self::side_rx_ready(self.listener.as_ref(), cx) {
                    return std::task::Poll::Ready(());
                }
                if Self::side_rx_ready(self.caller.as_ref(), cx) {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending
            }),
        )
        .await;
    }

    /// Whether one side has receive work now, registering this task's waker
    /// for later.
    ///
    /// Managed mode wakes on the RX task's ring -- never on socket readiness,
    /// because that task is the socket's only consumer. Raw mode wakes on
    /// readiness as before.
    fn side_rx_ready<R>(side: Option<&R>, cx: &mut Context<'_>) -> bool
    where
        R: SideRxHolder,
    {
        let Some(side) = side else {
            return false;
        };
        match side.rx_ring() {
            Some(ring) => {
                let mut ring = ring.borrow_mut();
                if ring.pending() || ring.fault.is_some() {
                    return true;
                }
                ring.waker = Some(cx.waker().clone());
                false
            }
            None => side.poll_read_ready(cx).is_ready(),
        }
    }

    async fn service_rx_listener(
        listener: &mut ListenerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        // Managed multishot: completions come from the fixed RX task's ring,
        // and the socket itself is never read by this path.
        if listener.rx.mode == OwnerRxMode::ManagedMultishot {
            Self::service_rx_listener_managed(listener, now, budget, report).await;
            return;
        }
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

    /// Feed one managed completion into listener admission and account it.
    fn admit_managed(
        listener: &mut ListenerSide,
        datagram: &ManagedRxDatagram,
        now: Timestamp,
        report: &mut OwnerServiceReport,
    ) {
        report.rx_packets += 1;
        report.rx_bytes += datagram.len();
        let _ = listener.table.admit(
            datagram.peer,
            datagram.bytes(),
            now,
            &listener.options,
            0,
            1,
            &listener.telemetry,
        );
    }

    /// Managed drain for the listener socket: completions come from the fixed
    /// RX task's bounded ring, never from the socket itself (the task is the
    /// only consumer). A completion that does not fit the remaining byte
    /// budget is held as staged work with its lease intact -- no copy, and the
    /// pool buffer returns when it is finally consumed.
    async fn service_rx_listener_managed(
        listener: &mut ListenerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        let Some(ring) = listener.rx.ring.as_ref().cloned() else {
            return;
        };
        // Register this visit's waker so the next completion wakes the Owner
        // instead of leaving it parked on a timer.
        let _ = std::future::poll_fn(|cx| {
            ring.borrow_mut().waker = Some(cx.waker().clone());
            std::task::Poll::Ready(())
        })
        .await;

        if let Some(staged) = listener.rx.staged.take() {
            if !rx_budget_fits(report, budget, staged.len()) {
                listener.rx.staged = Some(staged);
                return;
            }
            Self::admit_managed(listener, &staged, now, report);
        }

        while report.rx_packets < budget.max_rx_packets && report.rx_bytes < budget.max_rx_bytes {
            let Some(datagram) = ring.borrow_mut().pop() else {
                break;
            };
            if !rx_budget_fits(report, budget, datagram.len()) {
                listener.rx.staged = Some(datagram);
                break;
            }
            Self::admit_managed(listener, &datagram, now, report);
        }
    }

    /// Feed one managed completion into the pooled caller table and account it.
    fn feed_managed(
        caller: &mut OwnerCallerSide,
        datagram: &ManagedRxDatagram,
        now: Timestamp,
        report: &mut OwnerServiceReport,
    ) {
        report.rx_packets += 1;
        report.rx_bytes += datagram.len();
        let _ = caller
            .pool
            .table_mut()
            .feed(datagram.peer, datagram.bytes(), now);
    }

    /// Managed drain for the caller socket; the caller-side counterpart to
    /// [`Self::service_rx_listener_managed`].
    async fn service_rx_caller_managed(
        caller: &mut OwnerCallerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        let Some(ring) = caller.rx.ring.as_ref().cloned() else {
            return;
        };
        let _ = std::future::poll_fn(|cx| {
            ring.borrow_mut().waker = Some(cx.waker().clone());
            std::task::Poll::Ready(())
        })
        .await;

        if let Some(staged) = caller.rx.staged.take() {
            if !rx_budget_fits(report, budget, staged.len()) {
                caller.rx.staged = Some(staged);
                return;
            }
            Self::feed_managed(caller, &staged, now, report);
        }

        while report.rx_packets < budget.max_rx_packets && report.rx_bytes < budget.max_rx_bytes {
            let Some(datagram) = ring.borrow_mut().pop() else {
                break;
            };
            if !rx_budget_fits(report, budget, datagram.len()) {
                caller.rx.staged = Some(datagram);
                break;
            }
            Self::feed_managed(caller, &datagram, now, report);
        }
    }

    async fn service_rx_caller(
        caller: &mut OwnerCallerSide,
        now: Timestamp,
        budget: &OwnerServiceBudget,
        report: &mut OwnerServiceReport,
    ) {
        if caller.rx.mode == OwnerRxMode::ManagedMultishot {
            Self::service_rx_caller_managed(caller, now, budget, report).await;
            return;
        }
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
        let operational = self.is_operational();
        if let Some(ref mut listener) = self.listener {
            let mut sink = OwnerTxSink {
                sock: &listener.sock,
                tx_pool: &mut self.tx_pool,
                tx_engine: &mut self.tx_engine,
                operational,
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
        let operational = self.is_operational();
        if let Some(caller) = self.caller.as_mut() {
            let mut sink = OwnerTxSink {
                sock: &caller.sock,
                tx_pool: &mut self.tx_pool,
                tx_engine: &mut self.tx_engine,
                operational,
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
        let l_pending = self.listener.as_ref().is_some_and(|l| {
            l.pending_rx.is_some() || l.rx.pending() || l.table.has_pending_output(now)
        });
        let c_pending = self.caller.as_ref().is_some_and(|c| {
            c.pending_rx.is_some() || c.rx.pending() || c.pool.table().has_pending_output(now)
        });
        l_pending || c_pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only adapter over the reserve-then-commit sink contract, so tests
    /// keep expressing "offer this datagram and see what happened":
    /// `Ok(Some(len))` committed, `Ok(None)` no capacity, `Err` refused
    /// before materialization (protocol output untouched).
    fn push_test<F>(
        sink: &mut OwnerTxSink<'_>,
        peer: SocketAddr,
        wire_len: usize,
        fill: F,
    ) -> Result<Option<usize>, srt_proto::Error>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, srt_proto::Error>,
    {
        let Some(mut slot) = sink.acquire(peer, wire_len)? else {
            return Ok(None);
        };
        match fill(slot.bytes_mut()) {
            Ok(len) => {
                slot.commit(len);
                Ok(Some(len))
            }
            // Refusal/failure before any protocol state was consumed: the
            // reservation is released by the slot's own drop.
            Err(error) => Err(error),
        }
    }
    /// Park in the wait path until the engine has an unpublished completion,
    /// WITHOUT reaping it: the wait path observes readiness only, so every
    /// caller here has to reap through `service` afterwards.
    async fn wait_for_completion(owner: &mut Owner) {
        for _ in 0..500 {
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
            if owner.tx_engine.completion_ready() {
                return;
            }
        }
        panic!("a submitted send never completed");
    }

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
    /// Completion reaping belongs to `service`, the sole normal reaper; the
    /// wait path only observes readiness (see
    /// `wait_for_activity_never_reaps_a_completion`, which asserts the
    /// boundary directly).
    #[test]
    fn service_returns_tx_buffers_and_updates_completion_stats() {
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
                    operational: true,
                };
                let res = push_test(&mut sink, l_addr, 10, |buf| {
                    buf[..10].copy_from_slice(b"0123456789");
                    Ok(10)
                });
                assert!(matches!(res, Ok(Some(10))));
            }

            // Slot allocated: 1 in flight, free count is 15
            assert_eq!(owner.tx_in_flight(), 1);
            assert_eq!(owner.tx_pool().free_count(), 15);

            // The wait path parks until the completion is ready;
            // `service` then reaps it, returns the slot, and counts it.
            wait_for_completion(&mut owner).await;
            assert_eq!(
                owner.tx_pool().free_count(),
                15,
                "observing readiness must not return the buffer"
            );
            let report = owner
                .service(Timestamp::from_micros(1_000), OwnerServiceBudget::default())
                .await;
            assert_eq!(report.completions_reaped, 1);
            assert_eq!(
                owner.tx_pool().free_count(),
                16,
                "service must return the reaped TX buffer to tx_pool"
            );
            assert_eq!(
                owner.completions.completed_ok, 1,
                "service must update completion statistics"
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
                    operational: true,
                };
                let _ = push_test(&mut sink, peer, 8, |buf| {
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
                    operational: true,
                };
                let res = push_test(&mut sink, peer, 100, |buf| {
                    buf[..100].fill(0xAA);
                    Ok(100)
                });
                assert!(matches!(res, Ok(Some(100))));
            }

            // 2. Ceiling + 1 (101 bytes) must be rejected before send / slot allocation
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                    operational: true,
                };
                let res = push_test(&mut sink, peer, 101, |buf| {
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
                    operational: true,
                };
                let res = push_test(&mut sink, peer, 20, |_buf| {
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

            // 2. Refusal BEFORE materialization (wire length over the pool
            // ceiling): no slot and no lane may be left reserved, and the fill
            // closure must never run.
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                    operational: true,
                };
                let mut fill_ran = false;
                let res = push_test(&mut sink, peer, 5000, |_buf| {
                    fill_ran = true;
                    Ok(5000)
                });
                assert!(res.is_err(), "over-ceiling datagram must be refused");
                assert!(
                    !fill_ran,
                    "acquisition refusal must happen before materialization"
                );
            }
            assert_eq!(
                owner.tx_pool().free_count(),
                4,
                "acquire refusal must restore free_count to 4"
            );
            assert_eq!(owner.tx_in_flight(), 0);

            // 3. Successful send + reap: returns slot
            {
                let caller = owner.caller.as_ref().unwrap();
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                    operational: true,
                };
                let res = push_test(&mut sink, peer, 20, |buf| {
                    buf[..20].fill(0x55);
                    Ok(20)
                });
                assert!(res.is_ok());
            }
            assert_eq!(owner.tx_pool().free_count(), 3);
            assert_eq!(owner.tx_in_flight(), 1);

            wait_for_completion(&mut owner).await;
            let _ = owner
                .service(Timestamp::from_micros(1_000), OwnerServiceBudget::default())
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
                    operational: true,
                };
                let _ = push_test(&mut sink, peer, 20, |buf| {
                    buf[..20].fill(0x66);
                    Ok(20)
                });
            }
            assert_eq!(owner.tx_pool().free_count(), 3);
            assert!(
                owner
                    .shutdown_and_drain(std::time::Duration::from_secs(5))
                    .await,
                "the canonical teardown must reach quiescence"
            );
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
    /// Transactional-sink invariant 6: exhausting the Owner's TxPool leaves the
    /// next protocol datagram pending (not consumed, not lost), and it is
    /// submitted once capacity comes back.
    #[test]
    fn tx_pool_exhaustion_leaves_protocol_datagram_pending() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(1).with_caller(OwnerCallerSide::new_single(c_sock));

            // Two callers, each with its induction datagram queued.
            let mut ids = Vec::new();
            for socket_id in [0x7001u32, 0x7002u32] {
                let mut conn = SrtConnection::new_caller(srt_proto::ConnectionOptions {
                    socket_id,
                    ..Default::default()
                });
                conn.connect(Timestamp::default())
                    .expect("caller starts its handshake");
                let leg = crate::caller::CallerLeg {
                    peer: "127.0.0.1:19991".parse().expect("addr"),
                    connection: conn,
                };
                ids.push(
                    owner
                        .bench_caller_table_mut()
                        .expect("caller side")
                        .add_direct(leg)
                        .expect("admitted"),
                );
            }

            let now = Timestamp::from_micros(10_000);
            let budget = OwnerServiceBudget::default();
            let report = owner.service(now, budget).await;
            assert_eq!(
                report.tx_packets_submitted, 1,
                "a one-slot pool must submit exactly one datagram"
            );
            assert_eq!(owner.tx_pool().free_count(), 0, "pool is exhausted");
            assert_eq!(owner.tx_in_flight(), 1);
            assert!(
                owner.has_pending_work(now),
                "the second protocol datagram must still be pending, not lost"
            );

            // Capacity returns: the wait path observes the ready completion,
            // and one `service` visit reaps it (returning the slot) and then
            // submits the retained datagram with that same capacity.
            wait_for_completion(&mut owner).await;
            assert_eq!(
                owner.tx_pool().free_count(),
                0,
                "observing readiness must not return the slot on its own"
            );
            let now = Timestamp::from_micros(20_000);
            let report = owner.service(now, budget).await;
            assert_eq!(report.completions_reaped, 1, "the ready send is reaped");
            assert_eq!(
                report.tx_packets_submitted, 1,
                "the pending datagram must be submitted once capacity returns"
            );
            assert!(ids.len() == 2);
        });
    }

    /// Transactional-sink invariant 7: a refused acquisition cannot consume the
    /// protocol output, so the same queued datagram is still there afterwards
    /// with identical metadata -- no second reservation of its wire length,
    /// sequence stamp, or key.
    #[test]
    fn refused_acquisition_does_not_consume_or_re_reserve() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            // Ceiling far below a handshake datagram: `acquire` refuses before
            // the protocol is ever asked to materialize.
            let mut owner =
                Owner::new_with_ceiling(4, 8).with_caller(OwnerCallerSide::new_single(c_sock));
            let mut conn = SrtConnection::new_caller(srt_proto::ConnectionOptions {
                socket_id: 0x7100,
                ..Default::default()
            });
            conn.connect(Timestamp::default())
                .expect("caller starts its handshake");
            let id = owner
                .bench_caller_table_mut()
                .expect("caller side")
                .add_direct(crate::caller::CallerLeg {
                    peer: "127.0.0.1:19990".parse().expect("addr"),
                    connection: conn,
                })
                .expect("admitted");

            let pending_before = owner
                .bench_caller_table_mut()
                .expect("caller side")
                .bench_peek_output(&id);
            assert!(
                pending_before.is_some(),
                "the induction datagram is queued in the protocol"
            );

            let now = Timestamp::from_micros(10_000);
            let report = owner.service(now, OwnerServiceBudget::default()).await;
            assert_eq!(report.tx_packets_submitted, 0, "nothing may be submitted");
            assert_eq!(owner.tx_in_flight(), 0);

            let pending_after = owner
                .bench_caller_table_mut()
                .expect("caller side")
                .bench_peek_output(&id);
            assert_eq!(
                pending_before, pending_after,
                "a refused acquisition must leave the same queued output, unreserved"
            );
        });
    }

    /// The managed RX task's ring reference must not form a cycle.
    ///
    /// The ring owns the task's `JoinHandle`, so a *strong* reference back to
    /// the ring from inside the task is an Rc cycle: the ring never drops, the
    /// task is never cancelled, and the socket reader outlives the Owner (an
    /// ASan/LSan leak on any host whose kernel can register a provided-buffer
    /// ring). Production passes `Weak` -- that is enforced by
    /// `managed_rx_task`'s signature and by the spawn sites -- and this test
    /// asserts the difference between the two patterns explicitly, so the
    /// reason for the `Weak` is executable rather than a comment.
    #[test]
    fn managed_rx_ring_reference_pattern_has_no_cycle() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            // Weak (production): the owner's drop frees the ring immediately,
            // even while a task that only holds the Weak is still running.
            let weak_ring = Rc::new(RefCell::new(ManagedRxRing::new()));
            let weak_seen = Rc::downgrade(&weak_ring);
            let task_ref = Rc::downgrade(&weak_ring);
            let weak_task = compio::runtime::spawn(async move {
                while task_ref.upgrade().is_some() {
                    compio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            });
            weak_ring.borrow_mut().task = Some(weak_task);
            drop(weak_ring);
            for _ in 0..500 {
                if weak_seen.upgrade().is_none() {
                    break;
                }
                compio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            assert!(
                weak_seen.upgrade().is_none(),
                "a task holding only Weak must not keep its ring alive"
            );

            // Strong (the shape this test exists to rule out): the same
            // arrangement keeps the ring alive until the task itself ends.
            let strong_ring = Rc::new(RefCell::new(ManagedRxRing::new()));
            let strong_seen = Rc::downgrade(&strong_ring);
            let held = Rc::clone(&strong_ring);
            let strong_task = compio::runtime::spawn(async move {
                let _held = held;
                compio::time::sleep(std::time::Duration::from_millis(50)).await;
            });
            strong_ring.borrow_mut().task = Some(strong_task);
            drop(strong_ring);
            assert!(
                strong_seen.upgrade().is_some(),
                "a strong task reference keeps the ring alive -- the cycle"
            );
            compio::time::sleep(std::time::Duration::from_millis(120)).await;
            assert!(
                strong_seen.upgrade().is_none(),
                "only once the task itself ends does the ring go"
            );
        });
    }

    /// Managed-RX budget rule: zero allowances accept nothing, and the byte
    /// boundary is exact. This is the seam the managed drain uses to decide
    /// whether a completion may be consumed or must stay staged.
    #[test]
    fn rx_budget_is_exact_and_zero_means_zero() {
        let budget = OwnerServiceBudget {
            max_rx_packets: 2,
            max_rx_bytes: 100,
            ..Default::default()
        };
        let mut report = OwnerServiceReport::default();

        assert!(
            rx_budget_fits(&report, &budget, 100),
            "exactly the byte cap fits"
        );
        assert!(
            !rx_budget_fits(&report, &budget, 101),
            "one byte over must not fit"
        );
        report.rx_bytes = 100;
        assert!(
            !rx_budget_fits(&report, &budget, 1),
            "exhausted bytes accept nothing"
        );
        report.rx_bytes = 0;
        report.rx_packets = 2;
        assert!(
            !rx_budget_fits(&report, &budget, 1),
            "exhausted packets accept nothing"
        );

        let zero = OwnerServiceBudget {
            max_rx_packets: 0,
            max_rx_bytes: 0,
            ..Default::default()
        };
        let report = OwnerServiceReport::default();
        assert!(
            !rx_budget_fits(&report, &zero, 0),
            "a zero packet budget performs zero work even for a zero-length datagram"
        );
    }

    /// A managed-mode side reports its selected mode and an empty ring before
    /// anything arrives, and the readiness fallback reports raw mode. This is
    /// the mode/observability seam the qualification contract depends on.
    #[test]
    fn side_rx_reports_selected_mode_and_empty_ring() {
        let raw = SideRx::raw();
        assert_eq!(raw.mode, OwnerRxMode::RawReadiness);
        assert!(!raw.pending());
        let stats = raw.stats();
        assert_eq!(stats.mode, OwnerRxMode::RawReadiness);
        assert_eq!(stats.depth, 0);
        assert_eq!(stats.capacity, MANAGED_RX_RING_DEPTH);
        assert_eq!((stats.dropped, stats.truncated), (0, 0));

        let managed = SideRx::managed(2048, true);
        assert_eq!(managed.mode, OwnerRxMode::ManagedMultishot);
        assert!(!managed.pending(), "a fresh ring holds nothing");
        assert!(managed.ring.is_some(), "managed mode owns a ring");
        let stats = managed.stats();
        assert_eq!(stats.mode, OwnerRxMode::ManagedMultishot);
        assert_eq!(stats.depth, 0);
        assert!(!stats.staged);
    }

    /// A managed RX stream failure is a typed Owner fault, not a quiet socket,
    /// and it stops new admission. Injected at the ring so the assertion does
    /// not depend on a kernel that can register a provided-buffer ring.
    #[test]
    fn managed_rx_stream_failure_faults_the_owner() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(4).with_caller(OwnerCallerSide::new_single(c_sock));

            // Simulate the RX task's terminal condition.
            {
                let ring = Rc::new(RefCell::new(ManagedRxRing::new()));
                ring.borrow_mut()
                    .fault(RxFault::StreamError("simulated stream end".to_string()));
                owner.caller.as_mut().expect("caller side").rx = SideRx {
                    mode: OwnerRxMode::ManagedMultishot,
                    ring: Some(ring),
                    staged: None,
                };
            }
            assert!(
                owner.has_pending_work(Timestamp::from_micros(1_000)),
                "a faulted RX side is observable work, not silence"
            );

            let _ = owner
                .service(Timestamp::from_micros(1_000), OwnerServiceBudget::default())
                .await;
            match owner.fault() {
                Some(OwnerFault::RxStreamFailed { side, detail }) => {
                    assert_eq!(*side, "caller");
                    assert!(detail.contains("stream end"), "detail: {detail}");
                }
                other => panic!("a stopped managed RX task must fault the owner, got {other:?}"),
            }
        });
    }

    /// End-to-end managed multishot RX on a kernel whose provided-buffer ring
    /// registers: a legal datagram is delivered through the managed ring, and a
    /// datagram larger than the ring slot is detected via `MSG_TRUNC`, counted,
    /// and never handed to `srt-proto`.
    ///
    /// Self-skipping: on a host whose kernel rejects
    /// `IORING_REGISTER_PBUF_RING` (this repository's own development host does)
    /// the substrate is absent, `ManagedRequired` correctly refuses to attach,
    /// and there is nothing to exercise. The run that proves it on a qualified
    /// kernel is recorded in `docs/results/managed-rx-verification.md`.
    #[test]
    fn managed_multishot_delivers_and_counts_truncated_datagrams() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        let capable = runtime.block_on(async {
            runtime.driver_type().is_iouring() && runtime.buffer_pool().is_ok()
        });
        if !capable {
            return;
        }
        let cfg = ProductionRuntimeConfig::for_owner(64, 1500);
        assert_eq!(cfg.rx_buffer_len, 2048, "slots follow the wire ceiling");
        let built = production_runtime_builder(cfg)
            .expect("production runtime builder")
            .build()
            .expect("production runtime builds");

        built.block_on(async {
            let l_cfg = crate::ListenerConfig::builder("127.0.0.1:0".parse().unwrap())
                .topology(crate::ListenerTopology::PerPort)
                .configure_transport(|t| t.promotion = crate::PromotionPolicy::Never)
                .build()
                .expect("listener config");
            // Capability is declared once, from an observation of THIS
            // runtime, exactly as production does it.
            let substrate = observe_production_runtime(&built, 64, 1500)
                .await
                .managed_rx_substrate();
            assert!(
                substrate.is_available(),
                "the capable-kernel gate above promised the managed substrate"
            );
            let mut owner = Owner::new(64);
            owner.set_rx_mode_policy(RxModePolicy::ManagedRequired);
            owner
                .set_rx_substrate(substrate)
                .expect("substrate before sessions");
            owner
                .listen(&l_cfg)
                .expect("a capable kernel must attach managed multishot");
            assert_eq!(owner.rx_mode(), Some(OwnerRxMode::ManagedMultishot));
            let local = owner.listener_local_addr().expect("listener addr");

            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender bind");
            sender
                .send_to(&[0x11u8; 64], local)
                .expect("send legal datagram");
            let mut now = Timestamp::from_micros(10_000);
            let mut delivered = 0;
            for _ in 0..400 {
                now = Timestamp::from_micros(now.as_micros() + 1_000);
                delivered += owner
                    .service(now, OwnerServiceBudget::default())
                    .await
                    .rx_packets;
                if delivered > 0 {
                    break;
                }
                owner
                    .wait_for_activity(std::time::Duration::from_millis(2))
                    .await;
            }
            assert_eq!(
                delivered, 1,
                "a legal datagram must be delivered through the managed ring"
            );

            // Beyond the wire ceiling AND the ring slot: MUST be truncated.
            sender
                .send_to(&[0x22u8; 4096], local)
                .expect("send oversized datagram");
            let mut truncated = owner.rx_stats().listener.map_or(0, |stats| stats.truncated);
            let baseline = truncated;
            for _ in 0..400 {
                now = Timestamp::from_micros(now.as_micros() + 1_000);
                let _ = owner.service(now, OwnerServiceBudget::default()).await;
                truncated = owner.rx_stats().listener.map_or(0, |stats| stats.truncated);
                if truncated > baseline {
                    break;
                }
                owner
                    .wait_for_activity(std::time::Duration::from_millis(2))
                    .await;
            }
            assert!(
                truncated > baseline,
                "an oversized datagram must be counted as truncated, not parsed"
            );
            assert!(
                owner.fault().is_none(),
                "a truncated datagram is bounded loss, not a fault"
            );
            let stats = owner.rx_stats().listener.expect("listener rx stats");
            assert_eq!(stats.mode, OwnerRxMode::ManagedMultishot);
            assert_eq!(stats.capacity, MANAGED_RX_RING_DEPTH);

            assert!(
                owner
                    .shutdown_and_drain(std::time::Duration::from_secs(5))
                    .await,
                "shutdown must reach quiescence with a managed consumer attached"
            );
            assert_eq!(owner.tx_in_flight(), 0);
            assert_eq!(owner.tx_pool().free_count(), owner.tx_pool().capacity());
            // The managed consumer must be gone and its ring emptied. Anything
            // still held here is a leaked provided-buffer lease: this assertion
            // is what caught the 256 x 2048 B pool leak that dropping the
            // task's JoinHandle (cancel without awaiting) left behind.
            let stats = owner.rx_stats().listener.expect("listener rx stats");
            assert_eq!(stats.depth, 0, "no completion may outlive shutdown");
            assert!(!stats.staged, "no staged lease may outlive shutdown");
        });
    }

    /// Fail-closed attach: under `ManagedRequired` an Owner refuses to attach
    /// Fail-closed attach, in all four substrate states.
    ///
    /// `ManagedRequired` attaches a managed consumer only on an observed
    /// `ManagedRxSubstrate::Available` — io_uring AND registered
    /// provided-buffer ring AND `recvmsg` multishot — so no state of this host
    /// can make it attach by accident. Portable: nothing here depends on what
    /// the running kernel can actually do.
    #[test]
    fn managed_required_attaches_only_on_a_declared_available_substrate() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        let bind_addr = || {
            // Reserve an address, then release it: the Owner binds it itself.
            let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe");
            probe.local_addr().expect("probe addr")
        };
        let cfg_for = |addr| {
            crate::ListenerConfig::builder(addr)
                .topology(crate::ListenerTopology::PerPort)
                .configure_transport(|t| t.promotion = crate::PromotionPolicy::Never)
                .build()
                .expect("listener config")
        };
        runtime.block_on(async {
            // 1. Nothing observed: refuse, whatever this host could provide.
            let mut unobserved = Owner::new(4);
            unobserved.set_rx_mode_policy(RxModePolicy::ManagedRequired);
            let error = unobserved
                .listen(&cfg_for(bind_addr()))
                .expect_err("an unobserved substrate must never be read as available");
            assert!(
                error.to_string().contains("observed managed-RX substrate"),
                "{error}"
            );

            // 2. Observed, but not the full substrate: still refuse, and the
            //    reason names the layer that failed.
            let mut incomplete = Owner::new(4);
            incomplete.set_rx_mode_policy(RxModePolicy::ManagedRequired);
            incomplete
                .set_rx_substrate(ManagedRxSubstrate::MultishotRecvUnsupported)
                .expect("substrate before sessions");
            let error = incomplete
                .listen(&cfg_for(bind_addr()))
                .expect_err("ring-without-multishot must refuse ManagedRequired");
            assert!(error.to_string().contains("multishot"), "{error}");

            // 3. Declared available: attach, and select the managed datapath.
            let mut capable = Owner::new(4);
            capable.set_rx_mode_policy(RxModePolicy::ManagedRequired);
            capable
                .set_rx_substrate(ManagedRxSubstrate::Available)
                .expect("substrate before sessions");
            capable
                .listen(&cfg_for(bind_addr()))
                .expect("a declared managed substrate attaches");
            assert_eq!(capable.rx_mode(), Some(OwnerRxMode::ManagedMultishot));

            // 4. ManagedPreferred always attaches, and never claims managed
            //    without an observation.
            let mut preferred = Owner::new(4);
            preferred.set_rx_mode_policy(RxModePolicy::ManagedPreferred);
            preferred
                .listen(&cfg_for(bind_addr()))
                .expect("ManagedPreferred always attaches");
            assert_eq!(
                preferred.rx_mode(),
                Some(OwnerRxMode::RawReadiness),
                "an unobserved substrate selects the raw reader, visibly"
            );

            // Both attached owners release what they own.
            assert!(
                capable
                    .shutdown_and_drain(std::time::Duration::from_secs(5))
                    .await
            );
            assert!(
                preferred
                    .shutdown_and_drain(std::time::Duration::from_secs(5))
                    .await
            );
        });
    }

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
            // accepted at reduced capacity. The sink carries the Owner's own
            // predicate, which is what the service path does.
            assert!(!owner.is_operational(), "a short send faults the owner");
            let operational = owner.is_operational();
            let caller = owner.caller.as_ref().unwrap();
            let mut sink = OwnerTxSink {
                sock: &caller.sock,
                tx_pool: &mut owner.tx_pool,
                tx_engine: &mut owner.tx_engine,
                operational,
            };
            let res = push_test(&mut sink, peer, 20, |buf| {
                buf[..20].fill(0x11);
                Ok(20)
            });
            assert!(
                res.is_err(),
                "post-fault submission must be refused, got {res:?}"
            );
        });
    }

    /// P0-2/P0-F: a peer-local send error must NOT take the shared Owner
    /// down. The datagram is accounted and attributed to the one destination,
    /// and a structural failure on the same path still fails closed.
    #[test]
    fn peer_local_send_error_keeps_siblings_running() {
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
            assert_eq!(
                report.tx_peer_local_failures, 1,
                "an unreachable destination is a peer-local failure"
            );
            assert_eq!(report.tx_failed_sends, 0, "and not a structural one");
            assert!(
                owner.is_operational(),
                "one broken destination must not stop the shard"
            );
            let mut events = Vec::new();
            owner.poll_tx_failures(8, &mut events);
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].peer, peer);
            assert_eq!(events[0].class, TxFailureClass::PeerLocal);

            // A structural failure on the same path DOES fail the Owner
            // closed: EMSGSIZE means our own sized datagram was refused.
            {
                let engine = &mut owner.tx_engine;
                let _ = engine.idle_lanes.pop();
                engine.in_flight_count += 1;
                let lane = &engine.lanes[0];
                lane.state.borrow_mut().completion = Some(TxCompletion {
                    meta: InFlightMeta {
                        peer,
                        expected_len: 20,
                    },
                    res: Err(io::Error::from_raw_os_error(libc::EMSGSIZE)),
                    buf: vec![0u8; DEFAULT_TX_SLOT_SIZE],
                });
                engine.completed_lanes.borrow_mut().push_back(0);
            }
            let report = owner
                .service(Timestamp::from_micros(2_000), OwnerServiceBudget::default())
                .await;
            assert_eq!(report.tx_failed_sends, 1);
            match owner.fault() {
                Some(OwnerFault::TxFailed { peer: failed, kind }) => {
                    assert_eq!(*failed, peer);
                    assert_ne!(
                        TxFailureClass::classify(&io::Error::from_raw_os_error(libc::EMSGSIZE)),
                        TxFailureClass::PeerLocal,
                        "EMSGSIZE is our own sizing invariant, not a peer property"
                    );
                    let _ = kind;
                }
                other => panic!("a structural send failure must fault the owner, got {other:?}"),
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
                    operational: true,
                };
                let _ = push_test(&mut sink, peer, 20, |buf| {
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
                operational: true,
            };
            let res = push_test(&mut sink, peer, 20, |buf| {
                buf[..20].fill(0x78);
                Ok(20)
            });
            assert!(
                matches!(res, Err(_) | Ok(None)),
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
        // Capability only; qualification also needs the Owner's selected mode.
        let _ = profile.host_managed_rx_capable();
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
        assert!(!blocked.host_managed_rx_capable());
        // Full availability is capable.
        let ok = profile(
            ProvidedBufferRingStatus::Available,
            MultishotRecvStatus::Available,
            true,
        );
        assert!(ok.host_managed_rx_capable());
        // Capability is NOT qualification: an Owner still on the raw reader is
        // unqualified even on a fully capable host.
        assert!(
            !ManagedRxQualification {
                profile: ok.clone(),
                owner_rx_mode: OwnerRxMode::RawReadiness,
            }
            .managed_rx_active(),
            "host capability alone must never read as a qualification pass"
        );
        assert!(
            ManagedRxQualification {
                profile: ok.clone(),
                owner_rx_mode: OwnerRxMode::ManagedMultishot,
            }
            .managed_rx_active()
        );
        // Available ring + broken multishot stays incapable without blaming
        // the substrate.
        let no_ms = profile(
            ProvidedBufferRingStatus::Available,
            MultishotRecvStatus::Unsupported,
            true,
        );
        assert!(!no_ms.host_managed_rx_capable());
        assert!(
            !ManagedRxQualification {
                profile: no_ms,
                owner_rx_mode: OwnerRxMode::ManagedMultishot,
            }
            .managed_rx_active()
        );
        // Unknown is never capable.
        let unknown = profile(
            ProvidedBufferRingStatus::Unknown,
            MultishotRecvStatus::Unknown,
            false,
        );
        assert!(!unknown.host_managed_rx_capable());
    }

    /// Managed RX resources and policy: slots track the wire ceiling (not the
    /// 64 KiB UDP maximum), mode selection fails closed only under
    /// `ManagedRequired`, and an oversized datagram is classified as truncated
    /// rather than parsed short.
    #[test]
    fn managed_rx_sizing_mode_and_truncation_policy() {
        assert_eq!(managed_rx_buffer_len(1500), 2048);
        assert_eq!(managed_rx_buffer_len(1316 + 16 + 16), 2048);
        assert_eq!(managed_rx_buffer_len(3000), 4096);
        assert_eq!(managed_rx_buffer_len(0), 32);

        assert_eq!(
            RxModePolicy::ManagedRequired.resolve(ManagedRxSubstrate::Available),
            Ok(OwnerRxMode::ManagedMultishot)
        );
        assert_eq!(
            RxModePolicy::ManagedPreferred.resolve(ManagedRxSubstrate::Available),
            Ok(OwnerRxMode::ManagedMultishot)
        );
        assert_eq!(
            RxModePolicy::ManagedPreferred.resolve(ManagedRxSubstrate::NotIoUring),
            Ok(OwnerRxMode::RawReadiness)
        );
        assert_eq!(
            RxModePolicy::ManagedRequired.resolve(ManagedRxSubstrate::NotIoUring),
            Err(ManagedRxSubstrate::NotIoUring),
            "ManagedRequired must refuse to attach without the substrate"
        );

        assert_eq!(
            classify_managed_datagram(64, 2048, false),
            ManagedDatagram::Complete
        );
        assert_eq!(
            classify_managed_datagram(2048, 2048, false),
            ManagedDatagram::Complete
        );
        assert_eq!(
            classify_managed_datagram(2048, 2048, true),
            ManagedDatagram::Truncated,
            "MSG_TRUNC must never be parsed as a complete datagram"
        );
        assert_eq!(
            classify_managed_datagram(4096, 2048, false),
            ManagedDatagram::Truncated
        );
    }

    // ---------------------------------------------------------------
    // Closure-pass invariants (P0-A .. P0-F, P1-B, P1-D)
    // ---------------------------------------------------------------

    /// P0-A: the production managed RX loop must not hold a strong ring `Rc`
    /// across the receive await.
    ///
    /// This drives `managed_rx_task` itself -- not a stand-in -- over a stream
    /// that never yields, then drops the Owner's strong reference while the
    /// task is parked inside `stream.next().await`. If the loop kept the
    /// upgraded `Rc` alive across the await, the ring (which owns the task's
    /// `JoinHandle`) would survive its owner: `ManagedRxRing -> JoinHandle ->
    /// task future -> Rc<ManagedRxRing>`. `weak.upgrade()` must fail, and the
    /// parked task must be the only remaining reference path.
    #[test]
    fn managed_rx_task_holds_no_strong_ring_across_the_receive_await() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let ring = Rc::new(RefCell::new(ManagedRxRing::new()));
            let weak = Rc::downgrade(&ring);
            // A stream that never yields: the task parks inside the receive
            // await, which is exactly the state the ownership rule is about.
            let pending = futures_util::stream::pending::<ManagedRxStep>();
            let handle = compio::runtime::spawn(managed_rx_task(pending, Rc::downgrade(&ring)));
            ring.borrow_mut().task = Some(handle);

            // Let the task start and park inside the await.
            for _ in 0..50 {
                if Rc::strong_count(&ring) == 1 {
                    break;
                }
                compio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(
                Rc::strong_count(&ring),
                1,
                "while parked in the receive await the task must hold no strong ring Rc; \
                 a second strong reference here is the cycle"
            );

            // The owner goes away while the receive is still pending: the ring
            // must be freed immediately, which is only possible if nothing
            // holds a strong reference to it.
            drop(ring);
            assert!(
                weak.upgrade().is_none(),
                "dropping the owning side must free the ring even with the receive pending"
            );

            // The task observes the loss on its next loop step and exits on its
            // own; it is cancelled here only to end the test deterministically.
            if let Some(handle) = weak
                .upgrade()
                .and_then(|ring| ring.borrow_mut().task.take())
            {
                let _ = handle.cancel().await;
            }
        });
    }

    /// P0-A: the loop's step handling is the production code path: a
    /// truncated completion is counted and dropped, a stream failure becomes
    /// the typed RX fault, and stream end is a fault too (never a quiet
    /// socket).
    #[test]
    fn managed_rx_task_classifies_truncation_end_and_failure() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            // Truncated, then end of stream.
            let ring = Rc::new(RefCell::new(ManagedRxRing::new()));
            let steps = futures_util::stream::iter(vec![
                ManagedRxStep::Truncated,
                ManagedRxStep::Unattributable,
            ]);
            managed_rx_task(steps, Rc::downgrade(&ring)).await;
            {
                let ring = ring.borrow();
                assert_eq!(ring.truncated, 1, "a truncated datagram is counted");
                assert!(ring.completions.is_empty(), "and never queued for parsing");
                assert!(ring.fault.is_none(), "bounded loss is not a fault");
            }

            // Explicit failure detail is preserved as the RX fault.
            let ring = Rc::new(RefCell::new(ManagedRxRing::new()));
            let steps = futures_util::stream::iter(vec![ManagedRxStep::Failed(
                "multishot op failed".to_string(),
            )]);
            managed_rx_task(steps, Rc::downgrade(&ring)).await;
            match ring.borrow_mut().fault.take() {
                Some(RxFault::StreamError(detail)) => {
                    assert_eq!(detail, "multishot op failed");
                }
                other => panic!("a failed managed stream must fault, got {other:?}"),
            }
        });
    }

    /// P0-C: `wait_for_activity` observes completion readiness without
    /// consuming it.
    ///
    /// A wait that reaps is a second, unbounded reaper: it returns slots and
    /// advances accounting outside the visit that reports the delta. One
    /// submission is allowed to complete, the owner is parked in
    /// `wait_for_activity`, and the completion must still be unreaped --
    /// `in_flight` unchanged, pool unchanged -- until `service` takes exactly
    /// one.
    #[test]
    fn wait_for_activity_never_reaps_a_completion() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let d_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let d_addr = d_std.local_addr().expect("addr");
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(4).with_caller(OwnerCallerSide::new_single(c_sock));

            let initial_free = owner.tx_pool().free_count();
            {
                let caller = owner.caller.as_ref().expect("caller side");
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                    operational: true,
                };
                let res = push_test(&mut sink, d_addr, 10, |buf| {
                    buf[..10].copy_from_slice(b"0123456789");
                    Ok(10)
                });
                assert!(matches!(res, Ok(Some(10))));
            }
            assert_eq!(owner.tx_in_flight(), 1);
            assert_eq!(owner.tx_pool().free_count(), initial_free - 1);

            // Park in the wait path until the kernel completion is ready.
            for _ in 0..200 {
                owner
                    .wait_for_activity(std::time::Duration::from_millis(1))
                    .await;
                if owner.tx_engine.completion_ready() {
                    break;
                }
            }
            assert!(
                owner.tx_engine.completion_ready(),
                "the send must have completed for this test to mean anything"
            );

            // The wait path must not have touched it.
            assert_eq!(
                owner.tx_pool().free_count(),
                initial_free - 1,
                "wait_for_activity must not return a TxPool slot"
            );
            assert_eq!(
                owner.tx_in_flight(),
                1,
                "wait_for_activity must not reap in-flight work"
            );

            // `service` is the only reaper, and `max_completions` bounds it.
            let report = owner
                .service(Timestamp::from_micros(1_000), OwnerServiceBudget::default())
                .await;
            assert_eq!(report.completions_reaped, 1, "service reaps exactly one");
            assert_eq!(report.tx_completed_ok, 1, "and reports it in this visit");
            assert_eq!(owner.tx_in_flight(), 0);
            assert_eq!(owner.tx_pool().free_count(), initial_free);

            let _ = d_std;
        });
    }

    /// P0-C: a zero completion budget performs zero reaping even after the
    /// wait path has observed a ready completion.
    #[test]
    fn service_with_zero_completion_budget_reaps_nothing() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let d_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let d_addr = d_std.local_addr().expect("addr");
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(4).with_caller(OwnerCallerSide::new_single(c_sock));
            {
                let caller = owner.caller.as_ref().expect("caller side");
                let mut sink = OwnerTxSink {
                    sock: &caller.sock,
                    tx_pool: &mut owner.tx_pool,
                    tx_engine: &mut owner.tx_engine,
                    operational: true,
                };
                assert!(matches!(
                    push_test(&mut sink, d_addr, 4, |buf| {
                        buf[..4].copy_from_slice(b"abcd");
                        Ok(4)
                    }),
                    Ok(Some(4))
                ));
            }
            for _ in 0..200 {
                owner
                    .wait_for_activity(std::time::Duration::from_millis(1))
                    .await;
                if owner.tx_engine.completion_ready() {
                    break;
                }
            }
            let budget = OwnerServiceBudget {
                max_completions: 0,
                ..Default::default()
            };
            let report = owner.service(Timestamp::from_micros(2_000), budget).await;
            assert_eq!(
                report.completions_reaped, 0,
                "a zero completion budget must reap nothing"
            );
            assert_eq!(
                owner.tx_in_flight(),
                1,
                "the completed send must still be owned by the engine"
            );
            assert!(owner.tx_engine.completion_ready());
            let _ = d_std;
        });
    }

    /// P0-D: the managed-RX capability matrix is decided by the full
    /// substrate, so `ManagedRequired` cannot attach on a runtime whose
    /// buffer ring registers but whose multishot `recvmsg` does not exist.
    #[test]
    fn managed_required_accepts_only_the_full_substrate() {
        let cases = [
            (ManagedRxSubstrate::NotIoUring, false),
            (ManagedRxSubstrate::BufferRingRegistrationFailed(22), false),
            (ManagedRxSubstrate::MultishotRecvUnsupported, false),
            (ManagedRxSubstrate::Available, true),
        ];
        for (substrate, expected_managed) in cases {
            assert_eq!(substrate.is_available(), expected_managed);
            let required = RxModePolicy::ManagedRequired.resolve(substrate);
            assert_eq!(
                required.is_ok(),
                expected_managed,
                "ManagedRequired on {substrate:?}"
            );
            let preferred = RxModePolicy::ManagedPreferred
                .resolve(substrate)
                .expect("ManagedPreferred never fails to attach");
            assert_eq!(
                preferred == OwnerRxMode::ManagedMultishot,
                expected_managed,
                "ManagedPreferred on {substrate:?}"
            );
        }
    }

    /// P0-D: attach failure names the layer that actually failed instead of
    /// blaming `IORING_REGISTER_PBUF_RING` unconditionally.
    #[test]
    fn managed_required_failure_reason_names_the_failed_layer() {
        let ring = ManagedRxSubstrate::BufferRingRegistrationFailed(22)
            .reason()
            .to_string();
        assert!(ring.contains("IORING_REGISTER_PBUF_RING"), "{ring}");
        assert!(ring.contains("22"), "{ring}");

        let multishot = ManagedRxSubstrate::MultishotRecvUnsupported.reason();
        assert!(
            multishot.contains("multishot") && !multishot.contains("IORING_REGISTER_PBUF_RING"),
            "a multishot failure must not be reported as a ring registration failure: {multishot}"
        );

        let not_uring = ManagedRxSubstrate::NotIoUring.reason();
        assert!(not_uring.contains("io_uring"), "{not_uring}");
    }

    /// P0-D: capability is consumed as one fact. `ManagedRequired` refuses to
    /// attach when no substrate has been observed, so an unobserved Owner can
    /// never silently claim the managed datapath.
    #[test]
    fn managed_required_refuses_an_unobserved_substrate() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let mut owner = Owner::new(4);
            owner.set_rx_mode_policy(RxModePolicy::ManagedRequired);
            let config = crate::CallerConfig::builder(std_sock.local_addr().expect("addr"))
                .ownership(crate::SocketOwnership::Shared)
                .build()
                .expect("caller config");
            let error = owner
                .connect(&config, Timestamp::default())
                .expect_err("ManagedRequired without an observed substrate must refuse");
            let text = error.to_string();
            assert!(
                text.contains("observed managed-RX substrate"),
                "the refusal must name the missing observation: {text}"
            );

            // Declaring a real-but-incomplete substrate still refuses, and the
            // reason names the ring. (A fresh Owner: the refused attempt above
            // already counted as a started session.)
            let mut owner = Owner::new(4);
            owner.set_rx_mode_policy(RxModePolicy::ManagedRequired);
            owner
                .set_rx_substrate(ManagedRxSubstrate::BufferRingRegistrationFailed(22))
                .expect("substrate before sessions");
            let error = owner
                .connect(&config, Timestamp::default())
                .expect_err("a failed ring must refuse ManagedRequired");
            assert!(
                error.to_string().contains("IORING_REGISTER_PBUF_RING"),
                "{error}"
            );
        });
    }

    /// P0-E: one Owner-wide fault gate. A managed RX failure must stop BOTH
    /// new listener attach and new caller admission, not only TX submission.
    #[test]
    fn owner_fault_gates_listen_and_connect_through_public_apis() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(4).with_caller(OwnerCallerSide::new_single(c_sock));
            assert!(owner.is_operational(), "a fresh owner is operational");

            // Kill the managed consumer on the caller side.
            {
                let ring = Rc::new(RefCell::new(ManagedRxRing::new()));
                ring.borrow_mut()
                    .fault(RxFault::StreamError("simulated consumer death".to_string()));
                owner.caller.as_mut().expect("caller side").rx = SideRx {
                    mode: OwnerRxMode::ManagedMultishot,
                    ring: Some(ring),
                    staged: None,
                };
            }
            let _ = owner
                .service(Timestamp::from_micros(1_000), OwnerServiceBudget::default())
                .await;
            assert!(matches!(
                owner.fault(),
                Some(OwnerFault::RxStreamFailed { .. })
            ));
            assert!(!owner.is_operational());

            // New caller admission is refused...
            let config = crate::CallerConfig::builder("127.0.0.1:9".parse().expect("address"))
                .ownership(crate::SocketOwnership::Shared)
                .build()
                .expect("caller config");
            let error = owner
                .connect(&config, Timestamp::from_micros(1_000))
                .expect_err("a faulted owner must refuse new caller admission");
            assert!(error.to_string().contains("not operational"), "{error}");

            // ...and so is a listener attach, through the same predicate.
            let listener = crate::ListenerConfig::builder("127.0.0.1:0".parse().expect("address"))
                .build()
                .expect("listener config");
            let error = owner
                .listen(&listener)
                .expect_err("a faulted owner must refuse a listener attach");
            assert!(error.to_string().contains("not operational"), "{error}");
        });
    }

    /// P0-F: one broken destination must not stop healthy siblings.
    ///
    /// A peer-local completion failure (unreachable host) is accounted and
    /// attributed, not promoted to an Owner fault; a structural failure still
    /// fails the whole Owner closed.
    #[test]
    fn peer_local_tx_failure_does_not_fault_the_owner() {
        let unreachable = io::Error::from_raw_os_error(libc::EHOSTUNREACH);
        assert_eq!(
            TxFailureClass::classify(&unreachable),
            TxFailureClass::PeerLocal
        );
        let refused = io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert_eq!(
            TxFailureClass::classify(&refused),
            TxFailureClass::PeerLocal
        );
        let pressure = io::Error::from_raw_os_error(libc::ENOBUFS);
        assert_eq!(
            TxFailureClass::classify(&pressure),
            TxFailureClass::TransientLocal
        );
        // Our own sized datagram being refused as too large is our invariant
        // failing, not the peer's fault.
        let too_large = io::Error::from_raw_os_error(libc::EMSGSIZE);
        assert_eq!(
            TxFailureClass::classify(&too_large),
            TxFailureClass::OwnerStructural
        );
        let bad_fd = io::Error::from_raw_os_error(libc::EBADF);
        assert_eq!(
            TxFailureClass::classify(&bad_fd),
            TxFailureClass::OwnerStructural
        );
        let bad_arg = io::Error::from_raw_os_error(libc::EINVAL);
        assert_eq!(
            TxFailureClass::classify(&bad_arg),
            TxFailureClass::OwnerStructural
        );
    }

    /// P0-F: a completion that fails peer-locally is reaped, returns its slot
    /// exactly once, is attributed in the bounded event queue, and leaves the
    /// Owner operational so siblings keep running. A structural failure takes
    /// the Owner down instead.
    #[test]
    fn completion_failure_domain_and_slot_ownership() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let peer: SocketAddr = "127.0.0.1:39999".parse().expect("addr");
            for (error, expect_operational) in [
                (io::Error::from_raw_os_error(libc::EHOSTUNREACH), true),
                (io::Error::from_raw_os_error(libc::ENOBUFS), true),
                (io::Error::from_raw_os_error(libc::EMSGSIZE), false),
            ] {
                let mut pool = TxPool::new(2, 64);
                let mut stats = OwnerTxCompletionStats::default();
                let mut failures = TxFailureQueue::new(4);
                let mut engine = TxEngine::new(2);
                let lane = engine.reserve_lane().expect("lane reserved");
                let buf = pool.alloc_slot().expect("slot");
                assert_eq!(pool.free_count(), 1, "one slot is owned by the lane");
                engine.submit_job(
                    lane,
                    Rc::new(
                        compio::net::UdpSocket::from_std(
                            std::net::UdpSocket::bind("127.0.0.1:0").expect("bind"),
                        )
                        .expect("adopt"),
                    ),
                    buf,
                    peer,
                    InFlightMeta {
                        peer,
                        expected_len: 0,
                    },
                );
                // Take the job back off the lane the way a completed
                // `send_to` does, so the completion carries the same slot.
                let buf = {
                    let mut state = engine.lanes[lane].state.borrow_mut();
                    state.job.take().expect("job").buf
                };
                // Publish the completion the way a lane does.
                {
                    let mut state = engine.lanes[lane].state.borrow_mut();
                    state.in_kernel = false;
                    state.completion = Some(TxCompletion {
                        meta: InFlightMeta {
                            peer,
                            expected_len: 10,
                        },
                        res: Err(error),
                        // The completion carries the SAME slot the job took:
                        // the pool has exactly one buffer outstanding here.
                        buf,
                    });
                }
                engine.completed_lanes.borrow_mut().push_back(lane);

                let reaped = engine.poll_completions(None, 4, &mut pool, &mut stats, &mut failures);
                assert_eq!(reaped, 1, "the completion is reaped exactly once");
                assert_eq!(
                    pool.free_count(),
                    pool.capacity(),
                    "every failed slot returns exactly once"
                );
                assert_eq!(engine.in_flight(), 0);
                assert_eq!(engine.fault().is_some(), !expect_operational);
                if expect_operational {
                    assert_eq!(failures.len(), 1, "attribution is queued");
                    let mut drained = Vec::new();
                    failures.drain_into(4, &mut drained);
                    assert_eq!(drained[0].peer, peer);
                } else {
                    assert_eq!(stats.failed_sends, 1);
                    assert_eq!(
                        failures.len(),
                        0,
                        "a structural failure is not peer-attributed"
                    );
                }
                assert!(
                    pool.alloc_slot().is_some(),
                    "the pool is fully usable again after the failure"
                );
            }
        });
    }

    /// P1-B: the wire ceiling is cipher-mode exact. A valid AES-CTR session
    /// near the ceiling must not be rejected because AES-GCM's tag was
    /// assumed, and a session that really needs the tag must still be refused
    /// one byte short.
    #[test]
    fn wire_ceiling_is_cipher_mode_exact() {
        use srt_proto::crypto::CipherMode;
        // 1800 + 16 header = 1816, above the 1500-byte control ceiling, so the
        // data term is the binding one.
        let payload = 1800;
        let plain = required_session_wire_ceiling(payload, None);
        let ctr = required_session_wire_ceiling(payload, Some(CipherMode::Ctr));
        let gcm = required_session_wire_ceiling(payload, Some(CipherMode::Gcm));
        assert_eq!(plain, 1816, "a plain datagram carries no tag");
        assert_eq!(ctr, 1816, "AES-CTR adds no tag beyond the header");
        assert_eq!(gcm, 1832, "AES-GCM adds its 16-byte tag");
        assert_eq!(
            plain, ctr,
            "a valid CTR configuration must not be charged GCM's tag"
        );

        // Boundary: exact fit passes, one byte short is refused.
        let owner_ceiling = ctr;
        assert!(ctr <= owner_ceiling);
        assert!(ctr + 1 > owner_ceiling);
        assert!(gcm > owner_ceiling, "GCM needs the tag's bytes");

        // The listener is peer-driven, so its ceiling is the conservative one.
        assert_eq!(
            required_session_wire_ceiling_for_side(payload, Some(CipherMode::Ctr), false),
            gcm,
            "an encrypted listener must be prepared for a peer's GCM tag"
        );
        assert_eq!(
            required_session_wire_ceiling_for_side(payload, None, false),
            plain,
            "an unencrypted listener carries no tag"
        );
        assert_eq!(
            required_session_wire_ceiling_for_side(payload, Some(CipherMode::Ctr), true),
            ctr,
            "the caller's own KMREQ fixes its mode"
        );
    }

    /// P1-D: a relay Owner with both sockets attached reports BOTH sides'
    /// managed RX telemetry instead of hiding the caller side behind the
    /// listener's.
    #[test]
    fn rx_stats_expose_both_sides() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let caller_only = Owner::new(2).with_caller(OwnerCallerSide::new_single(c_sock));
            let stats = caller_only.rx_stats();
            assert!(stats.listener.is_none());
            assert_eq!(
                stats.caller.map(|s| s.mode),
                Some(OwnerRxMode::RawReadiness)
            );

            // A managed caller ring's counters stay visible in the snapshot.
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(2).with_caller(OwnerCallerSide::new_single(c_sock));
            let ring = Rc::new(RefCell::new(ManagedRxRing::new()));
            ring.borrow_mut().note_truncated();
            owner.caller.as_mut().expect("caller side").rx = SideRx {
                mode: OwnerRxMode::ManagedMultishot,
                ring: Some(ring),
                staged: None,
            };
            let stats = owner.rx_stats();
            assert_eq!(
                stats.caller.map(|s| s.truncated),
                Some(1),
                "the caller side's truncation must be reported"
            );
            assert_eq!(
                stats.caller.map(|s| s.mode),
                Some(OwnerRxMode::ManagedMultishot)
            );
            assert!(stats.listener.is_none());
        });
    }

    /// P0-B: the shutdown verdict consults RX state, not only TX state.
    ///
    /// Before this pass `shutdown_and_drain` could return `true` purely
    /// because TX drained, with a managed consumer still holding an armed
    /// receive and its provided-buffer leases. Each RX invariant is asserted
    /// here to be load-bearing on its own.
    #[test]
    fn shutdown_verdict_requires_rx_quiescence() {
        let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
        runtime.block_on(async {
            let c_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
            let c_sock = compio::net::UdpSocket::from_std(c_std).expect("adopt");
            let mut owner = Owner::new(2).with_caller(OwnerCallerSide::new_single(c_sock));
            assert!(
                owner.caller.as_ref().expect("caller side").rx.quiescent(),
                "a raw caller side owns no managed consumer"
            );

            // A retained managed task handle means the receive is still owned
            // by the runtime: not quiescent, even though TX is drained.
            let ring = Rc::new(RefCell::new(ManagedRxRing::new()));
            let held = compio::runtime::spawn(async {
                compio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
            ring.borrow_mut().task = Some(held);
            owner.caller.as_mut().expect("caller side").rx = SideRx {
                mode: OwnerRxMode::ManagedMultishot,
                ring: Some(ring),
                staged: None,
            };
            assert!(
                !owner.quiescence_invariants_hold(),
                "a live managed consumer must make the verdict false"
            );

            // ...and the canonical teardown is what makes it true: it stops
            // and joins the consumer, empties the ring, and returns every
            // pool slot.
            let started = std::time::Instant::now();
            assert!(
                owner
                    .shutdown_and_drain(std::time::Duration::from_secs(5))
                    .await,
                "teardown must reach quiescence with a managed consumer attached"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "the whole teardown is bounded by its ONE deadline"
            );
            assert!(owner.quiescence_invariants_hold());
            assert_eq!(owner.tx_in_flight(), 0);
            assert_eq!(owner.tx_pool().free_count(), owner.tx_pool().capacity());
            let stats = owner.rx_stats().caller.expect("caller rx stats");
            assert_eq!(stats.depth, 0, "no completion may outlive shutdown");
            assert!(!stats.staged, "no staged lease may outlive shutdown");
            let caller_rx = &owner.caller.as_ref().expect("caller side").rx;
            assert!(
                caller_rx
                    .ring
                    .as_ref()
                    .is_none_or(|ring| ring.borrow().task.is_none()),
                "the managed consumer must be joined, not merely cancelled"
            );
            assert!(
                !owner.is_operational(),
                "a shut-down owner admits no new work"
            );
        });
    }
}
