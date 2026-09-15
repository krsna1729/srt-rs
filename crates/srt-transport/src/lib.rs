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
//!    `ManualTimerStore`, `HighResWaiter`, `bind_reuseport`, `recvmsg_batch`,
//!    `sendmsg_batch`, `RecvBatch`, `flush_destined`.
//!    Protocol-level primitives that all runtimes need. These are available
//!    under [`advanced::driver`], [`advanced::native_io`], and
//!    [`advanced::platform`]; scheduling indexes remain implementation detail.
//!    `HighResWaiter` is the issue #82 A2 worker primitive: one
//!    high-resolution wait per worker (`epoll_pwait2` / absolute `timerfd`),
//!    a min-heap of absolute `CLOCK_MONOTONIC` deadlines, and service of
//!    every due connection after a single wake. It does not spin and does
//!    not change `SrtConnection` ownership.
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

use srt_proto::{ConnectionOptions, Error as SrtError, SrtConnection};
use std::time::Duration;

// --- Private submodules ---

mod admission;
mod caller;
mod caller_pool;
mod config;
mod cpu;
mod dense_slot_arena;
pub(crate) use dense_slot_arena::{DenseSlotArena, MAX_DENSE_SLOTS, PeerSlotId};
mod dense_due_index;
pub(crate) use dense_due_index::DenseDueIndex;
mod batch;
mod deadline_heap;
mod due_index;
mod group_conn;
mod handoff;
mod high_res_waiter;
mod sink;
mod socket_io;
mod telemetry;
mod timer;
pub use sink::{DatagramSink, PushResult};

/// Explicit composition APIs for applications that own a runtime, socket
/// topology, or connection scheduling loop themselves.
pub mod advanced {
    /// Prepared configuration and runtime-neutral endpoint plans.
    pub mod prepared {
        pub use super::super::config::{
            EndpointSocketPlan, PreparedCaller, PreparedListener, ResolvedEndpointPlan,
            ResolvedListenerTopology, ResolvedTransportConfig, RuntimeListener,
            TransportCapabilities,
        };
    }

    /// Runtime-neutral admission owners and logical peer handles.
    pub mod admission {
        #[cfg(feature = "bench-internals")]
        pub use super::super::admission::AdmissionPeer;
        pub use super::super::admission::{
            AdmissionDecision, AdmissionDropReason, AdmissionEvent, AdmissionOptions,
            AdmissionRequest, AdmissionResolution, Admit, BondedInputPolicy, LogicalPeer,
            LogicalPeerId, LogicalPeerMut, LogicalPeerStats, NewlyConnectedPeer, PeerTable,
            PeerTableConfig, RejectionReason, RemovedLogicalPeer, RemovedPeerLeg, is_ordered_close,
        };
    }

    /// Runtime-neutral caller owners and logical egress handles.
    pub mod caller {
        pub use super::super::caller::{
            CallerEvent, CallerGroupLeg, CallerLeg, CallerTable, DEFAULT_MAX_CALLERS,
            LogicalCaller, LogicalCallerId, LogicalCallerMut, LogicalCallerState,
            LogicalCallerStats, MAX_CALLERS, RemovedCallerLeg, RemovedLogicalCaller,
        };
        pub use super::super::caller_pool::{
            CallerPool, CallerPoolStats, MAX_CALLER_POOL_IN_FLIGHT, MAX_CALLER_POOL_QUEUE,
            PoolEvent, PoolOutcome, PoolRequestId,
        };
    }

    /// Bonded-group socket/protocol ownership.
    pub mod group {
        pub use super::super::group_conn::{
            GroupAggregateStats, GroupBuildError, GroupCallerLeg, GroupConn, GroupConnectionLeg,
            GroupConnectionStats, GroupDriveReport, GroupLegDriveReport, GroupLegStats,
            InboundGroupStats,
        };
    }

    /// Acceptor-to-worker ownership-transfer messages.
    pub mod handoff {
        pub use super::super::handoff::{Handoff, WorkerMessage};
    }

    /// Runtime-neutral bounded driver operations.
    pub mod driver {
        pub use super::super::batch::RecvBudget;
        #[cfg(any(feature = "mio", feature = "tokio"))]
        pub use super::super::deadline_heap::schedule_wait_micros;
        pub use super::super::timer::ManualTimerStore;
        pub use super::super::{
            OutputDrainBudget, OutputDrainReport, OutputDrainStatus, PacedSendOutcome,
        };
    }

    /// Native I/O and wait primitives for custom event-loop owners.
    pub mod native_io {
        pub use super::super::batch::{
            BatchIoStats, RecvBatch, RecvDrainReport, SendFlushReport, apply_send_result,
            drain_recv_fd, flush_destined,
        };
        pub use super::super::high_res_waiter::{
            HighResWaiter, MAX_WAITER_KEYS, MonotonicDeadline, PlannedWait, WaitBackend,
            WaitOutcome, deadline_from_wait, plan_wait,
        };
        pub use super::super::socket_io::{recvmsg_batch, sendmsg_batch, sendmsg_connected_batch};
    }

    /// Platform and socket deployment helpers.
    pub mod platform {
        pub use super::super::cpu::{
            available_cpus, current_cpu_spec, parse_cpu_spec, restrict_to_cpu_list,
        };
        pub use super::super::socket_io::{
            SOCK_BUF_BYTES, SocketBufferStats, bind_reuseport, set_sock_bufs, socket_buffer_stats,
        };
    }

    /// Mutable telemetry owners used by an adapter or worker. Exporters
    /// should retain only the snapshot types from the crate root.
    pub mod telemetry {
        pub use super::super::telemetry::{IngressTelemetry, ShardTelemetry};
    }

    /// Final-storage datagram sink abstraction.
    pub mod sink {
        pub use super::super::sink::{DatagramSink, PushResult};
    }
}

/// Benchmark-only access to implementation data structures. These are kept
/// out of the production API so scheduling representation can change without
/// becoming an application contract.
#[cfg(feature = "bench-internals")]
pub mod test_support {
    pub use super::admission::PhysicalPeerKey;
    pub use super::dense_due_index::{DenseDueEntry, DenseDueIndex};
    pub use super::dense_slot_arena::{
        DenseSlotArena, MAX_DENSE_SLOTS, PeerSlot, PeerSlotId, RouteSlot, SlotMut, SlotRef,
    };
    pub use super::due_index::DueIndex;
}

// --- Feature-gated runtime adapters (src/runtimes/) ---

#[cfg(feature = "mio")]
#[path = "runtimes/mio.rs"]
pub mod mio_transport;
#[cfg(feature = "mio")]
pub use mio_transport as mio;

#[cfg(feature = "tokio")]
#[path = "runtimes/tokio.rs"]
pub mod tokio_transport;
#[cfg(feature = "tokio")]
pub use tokio_transport as tokio;

#[cfg(feature = "compio")]
#[path = "runtimes/compio.rs"]
pub mod compio_transport;
#[cfg(feature = "compio")]
pub use compio_transport as compio;

// --- Public re-exports: config ---

// Keep the implementation modules able to share the complete configuration
// vocabulary while publishing only the application-facing policy surface.
pub(crate) use config::*;
pub use config::{
    AdmissionConfig, Bandwidth, BatchingPolicy, CallerBuilder, CallerConfig, ConfigError,
    ConnectConfig, CookieRoutingPolicy, EncryptionConfig, FlowControlConfig, GroupConfig,
    HandshakeConfig, ListenerBuilder, ListenerConfig, ListenerEncryptionConfig, ListenerPeerPolicy,
    ListenerTopology, PacingPolicy, PayloadSize, PolicyOverride, PromotionPolicy,
    RuntimeBuildError, RuntimeFlavor, SessionConfig, SessionSendError, SocketBufferConfig,
    SocketOwnership, TransportConfig, TransportProfile, WorkerCount,
};

// --- Internal utility imports ---

#[allow(unused_imports)]
pub(crate) use admission::{
    AdmissionDecision, AdmissionDropReason, AdmissionEvent, AdmissionOptions, AdmissionRequest,
    AdmissionResolution, Admit, BondedInputPolicy, LogicalPeer, LogicalPeerId, LogicalPeerMut,
    LogicalPeerStats, NewlyConnectedPeer, PeerTable, PeerTableConfig, RejectionReason,
    RemovedLogicalPeer, RemovedPeerLeg, is_ordered_close,
};
#[cfg(any(feature = "mio", feature = "tokio"))]
pub(crate) use batch::destined_send_limit;
pub(crate) use batch::drain_recv_fd_with_capacity;
#[cfg(feature = "mio")]
pub(crate) use batch::flush_destined_bounded;
#[allow(unused_imports)]
pub(crate) use batch::{
    BatchIoStats, RecvBatch, RecvBudget, RecvDrainReport, SendFlushReport, apply_send_result,
    drain_recv_fd, flush_destined,
};
#[allow(unused_imports)]
pub(crate) use caller::{
    CallerEvent, CallerGroupLeg, CallerLeg, CallerTable, DEFAULT_MAX_CALLERS, LogicalCaller,
    LogicalCallerId, LogicalCallerMut, LogicalCallerState, LogicalCallerStats, MAX_CALLERS,
    RemovedCallerLeg, RemovedLogicalCaller,
};
#[allow(unused_imports)]
pub(crate) use caller_pool::{
    CallerPool, CallerPoolStats, MAX_CALLER_POOL_IN_FLIGHT, MAX_CALLER_POOL_QUEUE, PoolEvent,
    PoolOutcome, PoolRequestId,
};
#[allow(unused_imports)]
pub(crate) use cpu::{available_cpus, current_cpu_spec, parse_cpu_spec, restrict_to_cpu_list};
#[allow(unused_imports)]
#[cfg(any(test, feature = "mio", feature = "tokio"))]
pub(crate) use deadline_heap::schedule_wait_micros;
pub(crate) use due_index::DueIndex;
#[allow(unused_imports)]
pub(crate) use group_conn::{
    GroupAggregateStats, GroupBuildError, GroupCallerLeg, GroupConn, GroupConnectionLeg,
    GroupConnectionStats, GroupDriveReport, GroupLegDriveReport, GroupLegStats, InboundGroupStats,
};
#[allow(unused_imports)]
pub(crate) use handoff::{Handoff, WorkerMessage};
#[allow(unused_imports)]
pub(crate) use high_res_waiter::{
    HighResWaiter, MAX_WAITER_KEYS, MonotonicDeadline, PlannedWait, WaitBackend, WaitOutcome,
    deadline_from_wait, plan_wait,
};
#[allow(unused_imports)]
pub(crate) use socket_io::{
    SOCK_BUF_BYTES, SocketBufferStats, bind_reuseport, recvmsg_batch, sendmsg_batch,
    sendmsg_connected_batch, set_sock_bufs, socket_buffer_stats,
};
#[allow(unused_imports)]
pub(crate) use telemetry::{IngressTelemetry, ShardTelemetry};
#[allow(unused_imports)]
pub(crate) use timer::ManualTimerStore;

// --- Public re-exports: telemetry snapshots ---

pub use telemetry::{
    IngressTelemetrySnapshot, SHARD_LATENESS_BUCKETS, SHARD_OVERLOAD_REASONS, ShardOverloadReason,
    ShardTelemetrySnapshot,
};
// Internal helpers used by runtime and group_conn modules.
pub(crate) use batch::drain_connected_outputs;
#[cfg(feature = "tokio")]
pub(crate) use batch::drain_output_work;
pub(crate) use caller::{collect_output_work, prepend_outputs};

// Internal types used by admission and caller modules.
pub(crate) use group_conn::{GroupLogicalCounters, group_connection_stats};

// --- Crate-level types that bridge multiple submodules ---

/// Per-tick limits for moving protocol outputs into a runtime socket.
///
/// The bounds are deliberately expressed in actions, packets, and bytes:
/// timer churn cannot bypass the action cap, while a burst of large UDP
/// datagrams cannot monopolize a readiness-loop iteration.
///
/// Zero means zero work, never unlimited: a budget constructed with any
/// zero field performs no output work on that axis. `usize::MAX` is the
/// way to express an effectively unlimited axis.
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

    /// Apply a visit limit without exceeding the configured transport limits.
    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self::new(
            self.max_actions.min(other.max_actions),
            self.max_packets.min(other.max_packets),
            self.max_bytes.min(other.max_bytes),
        )
    }

    #[cfg(any(feature = "mio", feature = "tokio"))]
    pub(crate) fn consume(&mut self, actions: usize, packets: usize, bytes: usize) {
        self.max_actions = self.max_actions.saturating_sub(actions);
        self.max_packets = self.max_packets.saturating_sub(packets);
        self.max_bytes = self.max_bytes.saturating_sub(bytes);
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
                srt_proto::DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            ),
            handshake_timeout: Duration::from_micros(srt_proto::DEFAULT_HANDSHAKE_TIMEOUT_MICROS),
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

impl OutputDrainStatus {
    /// Ready work on either side takes precedence over socket backpressure.
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::BudgetExhausted, _) | (_, Self::BudgetExhausted) => Self::BudgetExhausted,
            (Self::Backpressured, _) | (_, Self::Backpressured) => Self::Backpressured,
            _ => Self::Drained,
        }
    }
}

/// Work completed by one bounded output-pump invocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutputDrainReport {
    pub actions: usize,
    pub packets: usize,
    pub bytes: usize,
    pub status: OutputDrainStatus,
    /// `sendmmsg` / send attempts in this visit.
    pub syscalls: usize,
    /// True when this visit stopped on `WouldBlock` or a partial `sendmmsg`.
    pub would_block: bool,
}

/// Outcome of one `send_paced`/`send_shared_paced` attempt (S03). The prior
/// `Result<(), ()>` collapsed four distinct situations into one opaque
/// `Err`: a caller following only `.is_ok()` could not tell "try again
/// later with the same payload" from "this payload is permanently
/// rejected" from "the protocol accepted it but the OS write failed" --
/// and a driver couldn't preserve the failure for its own health/terminal
/// reporting, because it had already been discarded.
#[derive(Debug)]
pub enum PacedSendOutcome {
    /// Accepted by the protocol and fully drained to the wire this call.
    Sent,
    /// Accepted by the protocol, but the output drain did not fully
    /// complete this call (budget exhausted). The remaining output stays
    /// queued in protocol order for the next drain; not a failure.
    Accepted,
    /// Pacing was not due yet, or a previous drain is still queued. Not a
    /// failure; retry with the same payload later.
    NotDue,
    /// The protocol rejected the payload. In every case this crate's own
    /// admission checks reject (state, pacing, size, the current key's
    /// ability to encrypt -- S02's `check_can_encrypt`), no output prefix
    /// or retained fragment remains, so retrying with different input is
    /// safe and retrying the identical input fails identically. The one
    /// narrow exception is an encryption failure inside the wire-encode
    /// step itself, past every pre-admission check: the payload is by then
    /// already retained in the sender buffer, so this is not a strict
    /// admission guarantee against every possible internal error, only
    /// against the checked ones.
    Rejected(SrtError),
    /// The payload was accepted by the protocol -- it is retained and
    /// eligible for retransmission -- but the runtime's output drain hit
    /// an I/O error trying to flush it. Never resend this payload as new
    /// data; the protocol already owns it (S02).
    DriverError(std::io::Error),
}
