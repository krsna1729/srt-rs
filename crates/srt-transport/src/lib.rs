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

use shiguredo_srt::{ConnectionOptions, SrtConnection};
use std::time::Duration;

// --- Private submodules ---

mod admission;
mod caller;
mod config;
mod cpu;
mod dense_slot_arena;
#[cfg(any(test, feature = "bench-internals"))]
pub use admission::PhysicalPeerKey;
#[cfg(any(test, feature = "bench-internals"))]
pub use dense_slot_arena::{DenseSlotArena, PeerSlot, PeerSlotId, RouteSlot, SlotMut, SlotRef};
#[cfg(not(any(test, feature = "bench-internals")))]
pub(crate) use dense_slot_arena::{DenseSlotArena, PeerSlotId};
mod due_index;
mod group_conn;
mod handoff;
mod socket_io;
mod telemetry;
mod timer;

// --- Feature-gated runtime adapters (src/runtimes/) ---

#[cfg(feature = "mio")]
#[path = "runtimes/mio.rs"]
pub mod mio_transport;

#[cfg(feature = "tokio")]
#[path = "runtimes/tokio.rs"]
pub mod tokio_transport;

#[cfg(feature = "smol")]
#[path = "runtimes/smol.rs"]
pub mod smol_transport;

#[cfg(feature = "monoio")]
#[path = "runtimes/monoio.rs"]
pub mod monoio_transport;

#[cfg(feature = "glommio")]
#[path = "runtimes/glommio.rs"]
pub mod glommio_transport;

#[cfg(feature = "compio")]
#[path = "runtimes/compio.rs"]
pub mod compio_transport;

// --- Public re-exports: config ---

pub use config::*;

// --- Public re-exports: utilities ---

pub use cpu::{available_cpus, parse_cpu_spec, restrict_to_cpu_list};
pub use due_index::DueIndex;
pub use socket_io::{SOCK_BUF_BYTES, bind_reuseport, recvmsg_batch, sendmsg_batch, set_sock_bufs};
pub use timer::ManualTimerStore;

// --- Public re-exports: admission ---

pub use admission::{
    AdmissionDecision, AdmissionDropReason, AdmissionEvent, AdmissionOptions, AdmissionPeer,
    AdmissionRequest, AdmissionResolution, Admit, BondedInputPolicy, LogicalPeer, LogicalPeerId,
    LogicalPeerMut, LogicalPeerStats, NewlyConnectedPeer, PeerTable, PeerTableConfig,
    RejectionReason, RemovedLogicalPeer, RemovedPeerLeg, is_ordered_close,
};

// --- Public re-exports: handoff ---

pub use handoff::{Handoff, WorkerMessage};

// --- Public re-exports: telemetry ---

pub use telemetry::{IngressTelemetry, IngressTelemetrySnapshot};

// --- Public re-exports: caller ---

pub use caller::{
    CallerGroupLeg, CallerLeg, CallerTable, LogicalCaller, LogicalCallerId, LogicalCallerMut,
    LogicalCallerState, LogicalCallerStats, RemovedCallerLeg, RemovedLogicalCaller,
};
// Internal helpers used by runtime and group_conn modules.
pub(crate) use caller::{collect_output_work, prepend_outputs};

// --- Public re-exports: group ---

pub use group_conn::{
    GroupAggregateStats, GroupBuildError, GroupCallerLeg, GroupConn, GroupConnectionLeg,
    GroupConnectionStats, GroupDriveReport, GroupLegDriveReport, GroupLegStats, InboundGroupStats,
};
// Internal types used by admission and caller modules.
pub(crate) use group_conn::{GroupLogicalCounters, group_connection_stats};

// --- Crate-level types that bridge multiple submodules ---

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
