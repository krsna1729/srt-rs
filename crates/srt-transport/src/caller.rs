use crate::sink::{DatagramTarget, ProtocolOutputFailure, TxAttribution};
use crate::{
    DatagramSink, DatagramSlot, GroupConnectionStats, GroupLogicalCounters, ManualTimerStore,
    OutputDrainBudget, OutputDrainReport, OutputDrainStatus, SinkOutcome, group_connection_stats,
};
use srt_proto::{Bytes, ConnectionOutput, OutputInto, OutputMeta, SrtConnection, Timestamp};
use std::collections::{HashMap, HashSet, VecDeque};

/// Default maximum number of logical callers held by one table.
///
/// The table is a shard-local owner, so this cap bounds the hash maps,
/// scheduler queues, protocol cores, and per-caller pending outputs together.
pub const DEFAULT_MAX_CALLERS: usize = 4096;
/// Hard upper bound for one caller-table shard. Applications can choose a
/// lower limit, but an accidental `usize::MAX` must not turn a shard into an
/// unbounded admission promise.
pub const MAX_CALLERS: usize = 1 << 16;
/// Internal cap on due-timer fires per drain visit. Production never fires
/// thousands of timers synchronously just because an outer compatibility
/// budget supplied `usize::MAX`: the remainder stays live in the heap and
/// is picked up, unchanged, by the next visit.
pub(crate) const MAX_DUE_PER_VISIT: usize = 256;
/// Opaque application identity for one outbound SRT stream. A direct caller
/// and a bonded Broadcast/Backup group have the same steady-state API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LogicalCallerId(u64);

impl LogicalCallerId {
    /// The raw id, for opaque transport attribution. Not a handle: callers
    /// outside this crate never interpret it.
    #[must_use]
    pub(crate) fn as_u64(self) -> u64 {
        self.0
    }

    /// Rebuild from a raw id minted by [`Self::as_u64`].
    #[must_use]
    pub(crate) fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// A distinct, otherwise-meaningless id for tests that only need two
    /// (or more) hashable keys and have no real `CallerTable` entry to
    /// mint one from (e.g. exercising `SessionTarget`-keyed structures in
    /// `runtimes/tokio.rs` without a full connection round trip). Gated on
    /// the `tokio` feature too, not just `test`: its only caller lives
    /// behind that feature, and an isolated `cargo test -p srt-transport`
    /// (no `--all-features`) would otherwise warn this is unused.
    #[cfg(all(test, feature = "tokio"))]
    pub(crate) fn for_test(id: u64) -> Self {
        Self(id)
    }
}

/// One logical event emitted by a direct caller (A05). The caller-side
/// counterpart to [`crate::AdmissionEvent`] -- no `representative_peer`
/// field, since a caller's own configured remote address is already known
/// to whoever holds its [`LogicalCallerId`].
#[derive(Debug, Clone)]
pub struct CallerEvent {
    pub id: LogicalCallerId,
    pub event: srt_proto::ConnectionEvent,
}

/// One node of the indexed caller-deadline min-heap.
///
/// Ordered by `(deadline_micros, id)` ascending — the exact same tie
/// semantics the previous `BTreeSet<DeadlineEntry>` had: equal deadlines
/// pop in caller-id order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DeadlineNode {
    deadline_micros: u64,
    id: LogicalCallerId,
}

/// Bounded indexed due-deadline min-heap for [`CallerTable`].
///
/// Replaces the exact `BTreeSet<DeadlineEntry>`: every deadline change
/// there was a remove+insert pair allocating a tree node, and every due
/// drain allocated a fresh scratch `Vec`. The indexed heap keeps the same
/// observable semantics with steady-state allocation stability and no
/// population scans:
///
/// - each live caller occupies exactly one heap slot; `heap_pos` in its
///   `SchedEntry` names that slot, so set/update/remove are O(log N) with
///   zero stale entries, zero rebuilds, zero lazy discards;
/// - `heap[0]` is always the earliest live deadline: `next deadline` and
///   `has due` probes are O(1) with no heap iteration;
/// - preallocated to `max_callers`: pushes never reallocate after warmup.
#[derive(Debug)]
struct LogicalDueIndex {
    heap: Vec<DeadlineNode>,
}

impl LogicalDueIndex {
    /// Pre-sized to the caller cap: every slot is reserved up front so
    /// steady-state set/update/pop never reallocates.
    fn new(capacity: usize) -> Self {
        Self {
            heap: Vec::with_capacity(capacity),
        }
    }

    #[cfg(any(test, feature = "bench-internals"))]
    fn len(&self) -> usize {
        self.heap.len()
    }

    fn peek(&self) -> Option<DeadlineNode> {
        self.heap.first().copied()
    }

    /// Insert a new node for a caller that has no live deadline.
    fn push_node(&mut self, node: DeadlineNode) {
        self.heap.push(node);
    }

    fn swap_nodes(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
    }

    fn truncate(&mut self, len: usize) {
        self.heap.truncate(len);
    }
}

/// One caller's scheduler metadata. `heap_pos` is `Some(index)` exactly when
/// the caller has a live deadline in the due-index heap at that position;
/// `None` means no live deadline. All heap movement goes through
/// [`CallerTable`] helpers that keep both sides in sync.
#[derive(Debug, Clone, Copy)]
struct SchedEntry {
    ready_queued: bool,
    event_ready_queued: bool,
    deadline_micros: Option<u64>,
    heap_pos: Option<u32>,
}

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
    Direct(Box<srt_proto::ConnectionStats>),
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

    pub fn time_until_send(&self, now: Timestamp) -> u64 {
        self.table
            .sessions
            .get(&self.id)
            .map(|s| s.time_until_send(now))
            .unwrap_or(100_000)
    }
}

/// Mutable steady-state view of one outbound logical stream. This deliberately
/// mirrors [`crate::LogicalPeerMut`]: applications send, check capacity, close, and
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

    /// Whether the next logical payload can be accepted, including pacing.
    pub fn can_send_with_pacing(&mut self, now: Timestamp) -> bool {
        self.table
            .sessions
            .get_mut(&self.id)
            .is_some_and(|s| s.can_send_with_pacing(now))
    }

    /// Microseconds until the next paced send is allowed (0 = now).
    pub fn time_until_send(&self, now: Timestamp) -> u64 {
        self.table
            .sessions
            .get(&self.id)
            .map(|s| s.time_until_send(now))
            .unwrap_or(100_000)
    }

    /// Send one logical payload. Direct callers return one; Broadcast returns
    /// the successful active-leg count; Backup returns its selected leg.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, srt_proto::Error> {
        let session = self.table.sessions.get_mut(&self.id).ok_or_else(|| {
            srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "logical caller no longer exists",
            )
        })?;
        let res = session.send(payload, now);
        self.table.sync_deadline(self.id);
        self.table.enqueue_ready(self.id);
        res
    }

    /// Send shared payload data. Uses reference-counted `Bytes` to avoid
    /// deep-copying the payload for each group leg — the fan-out path.
    pub fn send_shared(
        &mut self,
        payload: Bytes,
        now: Timestamp,
    ) -> Result<usize, srt_proto::Error> {
        let session = self.table.sessions.get_mut(&self.id).ok_or_else(|| {
            srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "logical caller no longer exists",
            )
        })?;
        let res = session.send_shared(payload, now);
        self.table.sync_deadline(self.id);
        self.table.enqueue_ready(self.id);
        res
    }

    /// Begin an orderly close. A bonded caller closes every physical leg.
    pub fn disconnect(&mut self, now: Timestamp) {
        let exists = self.table.sessions.contains_key(&self.id);
        if !exists {
            return;
        }
        if let Some(caller) = self.table.sessions.get_mut(&self.id) {
            caller.disconnect(now);
        }
        self.table.sync_deadline(self.id);
        self.table.enqueue_ready(self.id);
        // Without this, the `StateChanged(Closing)`/`Disconnected` events
        // this produces sit in the connection's own internal queue
        // forever: `poll_events_bounded` only ever visits ids in
        // `event_ready_queue`, it does not scan the table, so a caller
        // this close started must be marked event-ready explicitly, the
        // same as `enqueue_ready` already does for its output.
        self.table.enqueue_event_ready(self.id);
    }

    /// Provide a new session encryption key to the logical caller. Direct
    /// callers forward this to their connection; bonded callers refresh every
    /// physical leg so the logical stream keeps one key across its paths.
    pub fn provide_new_sek(
        &mut self,
        new_sek: &[u8],
        now: Timestamp,
    ) -> Result<(), srt_proto::Error> {
        let session = self.table.sessions.get_mut(&self.id).ok_or_else(|| {
            srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "logical caller no longer exists",
            )
        })?;
        let result = session.provide_new_sek(new_sek, now);
        self.table.sync_deadline(self.id);
        self.table.enqueue_ready(self.id);
        result
    }
}

/// Runtime-neutral caller-side table for many direct or bonded SRT streams
/// sharing one application-owned UDP socket.
///
/// The runtime performs `recv_from`/`send_to`; this table owns protocol cores,
/// timers, source-address validation, and SRT Socket-ID routing. Group policy
/// stays in the shared [`srt_proto::SrtGroup`] core, so every runtime sees
/// identical Broadcast and Backup behavior. A table has a finite logical
/// caller cap; use [`Self::with_max_callers`] when a shard needs a different
/// explicit bound.
pub struct CallerTable {
    sessions: HashMap<LogicalCallerId, CallerSession>,
    routes: HashMap<u32, CallerRoute>,
    ready_queue: VecDeque<LogicalCallerId>,
    event_ready_queue: VecDeque<LogicalCallerId>,
    deadlines: LogicalDueIndex,
    sched: HashMap<LogicalCallerId, SchedEntry>,
    /// Table-owned reusable due scratch: `pop_due_ids` fills it, the fire
    /// phase drains it, and its capacity is retained across calls so the
    /// normal service path never allocates.
    due_scratch: Vec<LogicalCallerId>,
    /// Non-lossy index of legs holding an undrained
    /// [`ProtocolOutputFailure`], in quarantine order. One entry is appended
    /// at the moment a leg is quarantined, so its length can never exceed the
    /// number of quarantined legs and there is no capacity to overflow: the
    /// retirement token for a quarantined leg is always discoverable.
    protocol_failure_index: VecDeque<(LogicalCallerId, u32)>,
    /// Reusable per-pass scratch for records produced by the drain path
    /// before the table stores them on the leg they belong to. `Option` so a
    /// pass can move it into its `DrainSink` borrow; always `Some` otherwise.
    protocol_failure_scratch: Option<Vec<ProtocolOutputFailure>>,
    next_logical_caller: u64,
    max_callers: usize,
    #[cfg(any(test, feature = "bench-internals"))]
    sched_stats: SchedCounters,
}

/// Scheduler visit counters (bench/tests).
///
/// Fixed-cost: scalar counters only, `Copy`, zero heap allocation to collect.
#[cfg(any(test, feature = "bench-internals"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct SchedCounters {
    /// Due callers whose expired timers were fired.
    pub due_callers_visited: usize,
    /// Ready queue entries visited, including stale and empty entries.
    pub ready_drain_probes: usize,
    /// Stale ready queue entries discarded during bounded visits.
    pub ready_stale_visits: usize,
    /// Live callers whose drain visit found no output.
    pub ready_empty_visits: usize,
    /// Live bonded callers visited by the output scheduler.
    pub ready_group_visits: usize,
    /// Output budget exhaustion events.
    pub budget_exhausted: usize,
    /// Ready visits whose session was quarantined by a protocol
    /// materialization failure.
    pub protocol_failed_visits: usize,
}

/// Telemetry snapshot of the indexed due min-heap (bench/tests).
///
/// Fixed-cost: two scalar fields, `Copy`, zero heap allocation to collect.
/// Every entry in the heap is live by construction: no stale entries, no
/// rebuilds, so `live == physical` always.
#[cfg(any(test, feature = "bench-internals"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DueIndexSnapshot {
    /// Live deadline entries (= heap length).
    pub live: usize,
    /// Physical heap entries (= heap length; identical to `live`).
    pub physical: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
    /// Set when `poll_output_into` refuses this leg's peeked datagram. The
    /// queue still holds that output, so the leg must not be re-offered as
    /// ordinary work: it would rediscover the same failure forever. The
    /// application retires the session through the normal removal API.
    output_faulted: bool,
    /// The attributed retirement token for this leg, written exactly once at
    /// quarantine. Stored ON THE LEG so it cannot be lost while the leg is
    /// quarantined: the record and the quarantine are created in the same
    /// step, and the table's index only points at legs that hold one.
    output_failure: Option<ProtocolOutputFailure>,
}

struct CallerGroupLegState {
    peer: std::net::SocketAddr,
    timers: ManualTimerStore,
    pending: VecDeque<ConnectionOutput>,
    /// Per-leg quarantine; see [`CallerLegState::output_faulted`]. A faulted
    /// member does not stop its siblings.
    output_faulted: bool,
    /// Per-leg retirement token; see [`CallerLegState::output_failure`].
    output_failure: Option<ProtocolOutputFailure>,
}

struct CallerGroupState {
    group: srt_proto::SrtGroup,
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
struct DrainSink<'a, S: ?Sized> {
    budget: OutputDrainBudget,
    report: &'a mut OutputDrainReport,
    sink: &'a mut S,
    /// Per-pass scratch for records produced by the leg paths. Moved out of
    /// the table for the duration of one drain pass (see
    /// `drain_ready_bounded`) so the leg paths can record failures without
    /// borrowing the table that owns the sessions they are walking. The table
    /// stores each record on the leg it belongs to (and indexes that leg)
    /// before the pass ends, so this scratch is always emptied inside the pass.
    failures: &'a mut Vec<ProtocolOutputFailure>,
}

/// Account one committed datagram.
fn record_pushed(report: &mut OutputDrainReport, len: usize) {
    report.sink_outcome = SinkOutcome::Accepted;
    report.actions += 1;
    report.packets += 1;
    report.bytes = report.bytes.saturating_add(len);
}

/// Account one protocol materialization failure. The protocol output stays
/// queued in the connection; the typed kind rides on the report and the
/// attributed record goes to the table's bounded failure queue, so an upper
/// layer can react instead of this reading as "nothing to send".
fn record_protocol_failure(
    report: &mut OutputDrainReport,
    failures: &mut Vec<ProtocolOutputFailure>,
    attribution: TxAttribution,
    error: &srt_proto::Error,
) {
    report.protocol_output_failures += 1;
    if report.protocol_output_error_kind.is_none() {
        report.protocol_output_error_kind = Some(error.kind);
    }
    report.status = OutputDrainStatus::ProtocolError;
    failures.push(ProtocolOutputFailure {
        attribution,
        kind: error.kind,
        reason: error.to_string(),
    });
}

/// Account one sink refusal, recorded BEFORE materialization. The protocol
/// output stays queued; the typed kind rides on the report so an upper layer
/// can react instead of the error being dropped.
fn record_sink_rejection(report: &mut OutputDrainReport, error: &srt_proto::Error) {
    report.sink_outcome = SinkOutcome::Rejected;
    if report.sink_error_kind.is_none() {
        report.sink_error_kind = Some(error.kind);
    }
    report.sink_rejections = report.sink_rejections.saturating_add(1);
}

fn record_unavailable(report: &mut OutputDrainReport) {
    report.sink_outcome = SinkOutcome::Unavailable;
}

/// Split a drain sink into its report and its destination, so the refusal
/// bookkeeping below can touch the report while the destination stays
/// mutably borrowed by the in-flight reservation.
fn split<'d, S: ?Sized>(sink: &'d mut DrainSink<'_, S>) -> (&'d mut OutputDrainReport, &'d mut S) {
    (&mut *sink.report, &mut *sink.sink)
}

/// What one leg's materialization path needs besides the sink itself: the
/// failure queue and the datagram's logical attribution.
struct DrainChain<'a> {
    failures: &'a mut Vec<ProtocolOutputFailure>,
}

/// Split the sink for a materialization attempt: report, queue, destination.
fn split_chain<'d, S: ?Sized>(
    sink: &'d mut DrainSink<'_, S>,
) -> (&'d mut OutputDrainReport, DrainChain<'d>, &'d mut S) {
    let chain = DrainChain {
        failures: &mut *sink.failures,
    };
    (&mut *sink.report, chain, &mut *sink.sink)
}

impl CallerSession {
    fn state(&self) -> LogicalCallerState {
        match self {
            Self::Direct(leg) => logical_state(&leg.connection),
            Self::Group(group) => {
                if group.group.members().iter().any(|member| {
                    member.connection().state() == srt_proto::ConnectionState::Connected
                }) {
                    LogicalCallerState::Connected
                } else if group.group.members().iter().all(|member| {
                    member.connection().state() == srt_proto::ConnectionState::Disconnected
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

    fn can_send_with_pacing(&mut self, now: Timestamp) -> bool {
        match self {
            Self::Direct(leg) => leg.connection.can_send_with_pacing(now),
            Self::Group(group) => group.group.can_send_with_pacing(now),
        }
    }

    fn time_until_send(&self, now: Timestamp) -> u64 {
        match self {
            Self::Direct(leg) => leg.connection.time_until_send(now),
            Self::Group(group) => group.group.time_until_send(now),
        }
    }

    fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, srt_proto::Error> {
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

    fn send_shared(&mut self, payload: Bytes, now: Timestamp) -> Result<usize, srt_proto::Error> {
        let len = payload.len() as u64;
        match self {
            Self::Direct(leg) => {
                leg.connection.send_shared(payload, now)?;
                Ok(1)
            }
            Self::Group(group) => {
                let legs = group.group.send_shared(payload, now)?;
                group.logical.payloads_sent = group.logical.payloads_sent.saturating_add(1);
                group.logical.payload_bytes_sent =
                    group.logical.payload_bytes_sent.saturating_add(len);
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

    fn provide_new_sek(&mut self, new_sek: &[u8], now: Timestamp) -> Result<(), srt_proto::Error> {
        match self {
            Self::Direct(leg) => leg.connection.provide_new_sek(new_sek, now),
            Self::Group(group) => {
                let mut first_error = None;
                for member_id in &group.leg_order {
                    let connection = group
                        .group
                        .member_mut(*member_id)
                        .expect("group and caller legs are built together")
                        .connection_mut();
                    if let Err(error) = connection.provide_new_sek(new_sek, now)
                        && first_error.is_none()
                    {
                        first_error = Some(error);
                    }
                }
                first_error.map_or(Ok(()), Err)
            }
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

    /// Drain one output item. Returns whether table-side timer state was
    /// touched (`SetTimer`/`ClearTimer` applied); callers must reindex the
    /// deadline exactly when touched (or after `fire_timers`, which always
    /// reindexes in `fire_due_ids`).
    fn drain_one<S: DatagramSink + ?Sized>(
        &mut self,
        id: LogicalCallerId,
        now: Timestamp,
        sink: &mut DrainSink<'_, S>,
        failure_index: &mut VecDeque<(LogicalCallerId, u32)>,
    ) -> (DrainOne, bool) {
        match self {
            Self::Direct(leg) => {
                if leg.output_faulted {
                    // Already reported and still holding its queued output:
                    // re-offering it would rediscover the same failure.
                    return (DrainOne::Empty, false);
                }
                let result = drain_one_caller_leg(id, leg, now, sink);
                if matches!(result.0, DrainOne::ProtocolFailed { .. }) {
                    leg.output_faulted = true;
                    // The retirement token is stored ON the leg in the same
                    // step as the quarantine, so it cannot be lost.
                    leg.output_failure = sink.failures.pop();
                    debug_assert!(
                        leg.output_failure.is_some(),
                        "quarantine always has its attributed record"
                    );
                    failure_index.push_back((id, 0));
                }
                result
            }
            Self::Group(group) => {
                let mut timers_touched = false;
                let mut failed_member: Option<u32> = None;
                for _ in 0..group.leg_order.len() {
                    let member_id = group.leg_order[group.next_leg];
                    group.next_leg = (group.next_leg + 1) % group.leg_order.len();
                    let leg = group
                        .legs
                        .get_mut(&member_id)
                        .expect("group and caller legs are built together");
                    if leg.output_faulted {
                        failed_member = Some(member_id);
                        continue;
                    }
                    let connection = group
                        .group
                        .member_mut(member_id)
                        .expect("group and caller legs are built together")
                        .connection_mut();
                    match drain_one_caller_leg_parts(
                        leg.peer,
                        TxAttribution::caller(id, member_id),
                        Some(member_id),
                        now,
                        &mut leg.timers,
                        &mut leg.pending,
                        connection,
                        sink,
                    ) {
                        (DrainOne::Empty, touched) => {
                            timers_touched |= touched;
                        }
                        // A materialization failure is quarantined to the leg
                        // that reported it: its siblings in the same bonded
                        // session keep carrying traffic.
                        (DrainOne::ProtocolFailed { .. }, touched) => {
                            leg.output_faulted = true;
                            leg.output_failure = sink.failures.pop();
                            debug_assert!(
                                leg.output_failure.is_some(),
                                "quarantine always has its attributed record"
                            );
                            failure_index.push_back((id, member_id));
                            timers_touched |= touched;
                            failed_member = Some(member_id);
                        }
                        // A refusal on one leg must not be retried against the
                        // next leg of the same group either.
                        result => return result,
                    }
                }
                match failed_member {
                    // Every leg is quarantined: the logical session has no
                    // live output path left, so say so once, at session level.
                    Some(member) if group.legs.values().all(|leg| leg.output_faulted) => (
                        DrainOne::ProtocolFailed { leg: Some(member) },
                        timers_touched,
                    ),
                    // Some legs failed and were reported; the rest still work.
                    _ => (DrainOne::Empty, timers_touched),
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DrainOne {
    Drained,
    Empty,
    Blocked,
    /// The sink refused this datagram before materialization. The protocol
    /// output is untouched, but re-offering the same item this visit would
    /// only repeat the refusal, so the visit stops; the refusal itself is
    /// reported through `sink_rejections`/`sink_error_kind`.
    SinkRejected,
    /// `poll_output_into` refused to materialize the peeked datagram. The
    /// protocol output is STILL QUEUED and the error is recorded on the
    /// report; `leg` names the physical leg (`None` for a direct session) so
    /// exactly that leg can be quarantined instead of the whole session.
    ProtocolFailed {
        leg: Option<u32>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadyVisit {
    Empty,
    Stale,
    Live(LogicalCallerId),
}

/// Outcome of servicing a single [`ReadyVisit::Live`] entry in
/// [`CallerTable::drain_ready_bounded`], used to decide whether the outer
/// loop should keep visiting, stop because the budget ran out, or stop
/// because the next item didn't fit (see the `blocked_on_next_item` note
/// on `drain_ready_bounded`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadyVisitOutcome {
    Continue,
    BudgetExhausted,
    Blocked,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EventReadyVisit {
    Empty,
    Stale,
    Live(LogicalCallerId),
}

fn logical_state(connection: &SrtConnection) -> LogicalCallerState {
    match connection.state() {
        srt_proto::ConnectionState::Connected => LogicalCallerState::Connected,
        srt_proto::ConnectionState::Disconnected => LogicalCallerState::Disconnected,
        srt_proto::ConnectionState::Induction
        | srt_proto::ConnectionState::Conclusion
        | srt_proto::ConnectionState::Listening
        | srt_proto::ConnectionState::Closing => LogicalCallerState::Connecting,
    }
}

impl CallerTable {
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_callers(DEFAULT_MAX_CALLERS)
    }

    /// Build a table with an explicit finite logical-caller cap. All
    /// scheduler containers (sessions/routes maps, both ready queues, the
    /// due index, and the due scratch) are pre-sized from the bounded cap
    /// so steady-state service never grows one.
    #[must_use]
    pub fn with_max_callers(max_callers: usize) -> Self {
        let bounded = max_callers.clamp(1, MAX_CALLERS);
        Self {
            sessions: HashMap::with_capacity(bounded),
            routes: HashMap::with_capacity(bounded),
            ready_queue: VecDeque::with_capacity(bounded),
            event_ready_queue: VecDeque::with_capacity(bounded),
            deadlines: LogicalDueIndex::new(bounded),
            sched: HashMap::with_capacity(bounded),
            due_scratch: Vec::with_capacity(bounded.min(MAX_DUE_PER_VISIT)),
            protocol_failure_index: VecDeque::new(),
            protocol_failure_scratch: Some(Vec::new()),
            next_logical_caller: 1,
            max_callers: bounded,
            #[cfg(any(test, feature = "bench-internals"))]
            sched_stats: SchedCounters::default(),
        }
    }
    fn logical_next_deadline(session: &CallerSession) -> Option<Timestamp> {
        match session {
            CallerSession::Direct(leg) => leg.timers.next_deadline(),
            CallerSession::Group(group) => group
                .legs
                .values()
                .filter_map(|leg| leg.timers.next_deadline())
                .min(),
        }
    }

    fn sync_deadline(&mut self, id: LogicalCallerId) {
        let new_micros = if self.session_output_quarantined(id) {
            // A quarantined session has no schedulable deadlines: leaving one
            // live would keep the shard reporting pending work it will never
            // act on.
            None
        } else {
            self.sessions
                .get(&id)
                .and_then(Self::logical_next_deadline)
                .map(|ts| ts.as_micros())
        };
        let entry = self.sched.entry(id).or_insert(SchedEntry {
            ready_queued: false,
            event_ready_queued: false,
            deadline_micros: None,
            heap_pos: None,
        });
        let old_micros = entry.deadline_micros;
        if old_micros == new_micros {
            return;
        }
        entry.deadline_micros = new_micros;
        match (entry.heap_pos, new_micros) {
            // No live node and no new deadline: nothing to do.
            (None, None) => {}
            // New deadline, no live node: insert.
            (None, Some(n)) => {
                let pos = self.deadlines.heap.len();
                self.deadlines.push_node(DeadlineNode {
                    deadline_micros: n,
                    id,
                });
                self.sched.get_mut(&id).expect("just inserted").heap_pos = Some(pos as u32);
                self.sift_up(pos);
            }
            // Live node but deadline cleared: remove.
            (Some(_), None) => {
                self.heap_remove(id);
            }
            // Live node with changed deadline: update key and re-sift.
            (Some(_), Some(n)) => {
                let pos = self.heap_pos_of(id).expect("live node has position");
                self.deadlines.heap[pos].deadline_micros = n;
                // Key may have moved either direction; sift both ways.
                self.sift_up(pos);
                let pos = self.heap_pos_of(id).expect("still live after sift_up");
                self.sift_down(pos);
            }
        }
    }

    /// Current heap position of a caller with a live deadline.
    fn heap_pos_of(&self, id: LogicalCallerId) -> Option<usize> {
        self.sched.get(&id)?.heap_pos.map(|p| p as usize)
    }

    /// Record that the node at `pos` belongs to `id`.
    fn set_heap_pos(&mut self, id: LogicalCallerId, pos: usize) {
        if let Some(entry) = self.sched.get_mut(&id) {
            entry.heap_pos = Some(pos as u32);
        }
    }

    /// Swap heap nodes at `a` and `b`, keeping both owners' `heap_pos` in sync.
    fn heap_swap(&mut self, a: usize, b: usize) {
        if a == b {
            return;
        }
        let id_a = self.deadlines.heap[a].id;
        let id_b = self.deadlines.heap[b].id;
        self.deadlines.swap_nodes(a, b);
        self.set_heap_pos(id_a, b);
        self.set_heap_pos(id_b, a);
    }

    /// Restore the heap property upward from `pos`.
    fn sift_up(&mut self, mut pos: usize) {
        while pos > 0 {
            let parent = (pos - 1) / 2;
            if self.deadlines.heap[pos] < self.deadlines.heap[parent] {
                self.heap_swap(pos, parent);
                pos = parent;
            } else {
                break;
            }
        }
    }

    /// Restore the heap property downward from `pos`.
    fn sift_down(&mut self, mut pos: usize) {
        let len = self.deadlines.heap.len();
        loop {
            let left = pos * 2 + 1;
            let right = left + 1;
            let mut smallest = pos;
            if left < len && self.deadlines.heap[left] < self.deadlines.heap[smallest] {
                smallest = left;
            }
            if right < len && self.deadlines.heap[right] < self.deadlines.heap[smallest] {
                smallest = right;
            }
            if smallest == pos {
                break;
            }
            self.heap_swap(pos, smallest);
            pos = smallest;
        }
    }

    /// Remove the live deadline node for `id`, if any. O(log N), no scan.
    fn heap_remove(&mut self, id: LogicalCallerId) {
        let Some(pos) = self.heap_pos_of(id) else {
            return;
        };
        let last = self.deadlines.heap.len() - 1;
        if pos != last {
            self.heap_swap(pos, last);
        }
        self.deadlines.truncate(last);
        if let Some(entry) = self.sched.get_mut(&id) {
            entry.heap_pos = None;
        }
        if pos != last && pos < self.deadlines.heap.len() {
            self.sift_up(pos);
            let moved_id = self.deadlines.heap[pos].id;
            if self.heap_pos_of(moved_id) == Some(pos) {
                self.sift_down(pos);
            }
        }
    }

    /// Whether this session has no live output path left because every leg
    /// of it was quarantined by a protocol materialization failure.
    ///
    /// A quarantined session still holds its queued output, so it must be kept
    /// out of the ready queue and the due heap: re-offering it would either
    /// rediscover the same failure forever or report a shard that always has
    /// pending work while the application has not yet retired it.
    fn session_output_quarantined(&self, id: LogicalCallerId) -> bool {
        match self.sessions.get(&id) {
            Some(CallerSession::Direct(leg)) => leg.output_faulted,
            Some(CallerSession::Group(group)) => group.legs.values().all(|leg| leg.output_faulted),
            None => false,
        }
    }

    /// Drain attributed protocol materialization failures, oldest first.
    ///
    /// Each entry names the logical session and the physical leg and carries
    /// the protocol's own error kind and reason. Every quarantined leg has
    /// exactly one record and that record lives on the leg, so this drain
    /// cannot lose one however many legs fault before it runs; entries whose
    /// session/leg has since been retired are skipped because the leg (and
    /// therefore the problem) is already gone.
    pub fn poll_output_failures(
        &mut self,
        max_events: usize,
        out: &mut Vec<ProtocolOutputFailure>,
    ) {
        out.clear();
        for _ in 0..max_events {
            let Some((id, member)) = self.protocol_failure_index.pop_front() else {
                break;
            };
            let Some(session) = self.sessions.get_mut(&id) else {
                continue;
            };
            let record = match session {
                CallerSession::Direct(leg) if member == 0 => leg.output_failure.take(),
                CallerSession::Group(group) => group
                    .legs
                    .get_mut(&member)
                    .and_then(|leg| leg.output_failure.take()),
                _ => None,
            };
            if let Some(record) = record {
                out.push(record);
            }
        }
    }

    /// Protocol-output failures still awaiting application drain. Always equal
    /// to the number of quarantined legs whose record has not been drained.
    #[must_use]
    pub fn output_failures_pending(&self) -> usize {
        self.protocol_failure_index.len()
    }

    fn enqueue_ready(&mut self, id: LogicalCallerId) {
        if self.session_output_quarantined(id) {
            return;
        }
        let entry = self.sched.entry(id).or_insert(SchedEntry {
            ready_queued: false,
            event_ready_queued: false,
            deadline_micros: None,
            heap_pos: None,
        });
        if entry.ready_queued {
            return;
        }
        entry.ready_queued = true;
        self.ready_queue.push_back(id);
    }

    fn enqueue_event_ready(&mut self, id: LogicalCallerId) {
        let entry = self.sched.entry(id).or_insert(SchedEntry {
            ready_queued: false,
            event_ready_queued: false,
            deadline_micros: None,
            heap_pos: None,
        });
        if entry.event_ready_queued {
            return;
        }
        entry.event_ready_queued = true;
        self.event_ready_queue.push_back(id);
    }

    fn pop_event_ready_visit(&mut self) -> EventReadyVisit {
        let Some(id) = self.event_ready_queue.pop_front() else {
            return EventReadyVisit::Empty;
        };
        let Some(meta) = self.sched.get_mut(&id) else {
            return EventReadyVisit::Stale;
        };
        if !meta.event_ready_queued {
            return EventReadyVisit::Stale;
        }
        meta.event_ready_queued = false;
        if !self.sessions.contains_key(&id) {
            return EventReadyVisit::Stale;
        }
        EventReadyVisit::Live(id)
    }

    fn pop_ready_visit(&mut self) -> ReadyVisit {
        let Some(id) = self.ready_queue.pop_front() else {
            return ReadyVisit::Empty;
        };
        let Some(meta) = self.sched.get_mut(&id) else {
            return ReadyVisit::Stale;
        };
        if !meta.ready_queued {
            return ReadyVisit::Stale;
        }
        meta.ready_queued = false;
        if !self.sessions.contains_key(&id) {
            return ReadyVisit::Stale;
        }
        ReadyVisit::Live(id)
    }

    fn maybe_compact_ready_queue(&mut self) {
        if self.ready_queue.len() > 64 && self.ready_queue.len() > self.sessions.len() * 4 {
            self.ready_queue.retain(|id| {
                self.sessions.contains_key(id)
                    && self.sched.get(id).is_some_and(|meta| meta.ready_queued)
            });
        }
    }

    fn maybe_compact_event_ready_queue(&mut self) {
        if self.event_ready_queue.len() > 64
            && self.event_ready_queue.len() > self.sessions.len() * 4
        {
            self.event_ready_queue.retain(|id| {
                self.sessions.contains_key(id)
                    && self
                        .sched
                        .get(id)
                        .is_some_and(|meta| meta.event_ready_queued)
            });
        }
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn sched_counters(&self) -> SchedCounters {
        self.sched_stats
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn reset_sched_counters(&mut self) {
        self.sched_stats = SchedCounters::default();
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn deadline_count(&self) -> usize {
        self.deadlines.len()
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn due_index_snapshot(&self) -> DueIndexSnapshot {
        DueIndexSnapshot {
            live: self.deadlines.len(),
            physical: self.deadlines.len(),
        }
    }

    #[cfg(any(test, feature = "bench-internals"))]
    /// Ids collected by the last `pop_due_ids` call, before
    /// `fire_due_ids` consumes them.
    pub fn bench_due_scratch(&self) -> &[LogicalCallerId] {
        &self.due_scratch
    }
    #[cfg(any(test, feature = "bench-internals"))]
    pub fn ready_queue_len(&self) -> usize {
        self.ready_queue.len()
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn event_ready_queue_len(&self) -> usize {
        self.event_ready_queue.len()
    }

    /// Add one direct caller. Its non-zero SRT Socket ID must be unique among
    /// all physical legs in this shared UDP socket.
    pub fn add_direct(&mut self, leg: CallerLeg) -> Result<LogicalCallerId, srt_proto::Error> {
        if self.sessions.len() >= self.max_callers {
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "caller table capacity reached",
            ));
        }
        let socket_id = self.validate_socket_id(&leg.connection)?;
        let id = self.allocate_logical_caller()?;
        self.sessions.insert(
            id,
            CallerSession::Direct(Box::new(CallerLegState {
                peer: leg.peer,
                connection: leg.connection,
                timers: ManualTimerStore::new(),
                pending: VecDeque::new(),
                output_faulted: false,
                output_failure: None,
            })),
        );
        self.routes.insert(socket_id, CallerRoute::Direct(id));
        self.sched.insert(
            id,
            SchedEntry {
                ready_queued: false,
                event_ready_queued: false,
                deadline_micros: None,
                heap_pos: None,
            },
        );
        self.sync_deadline(id);
        self.enqueue_ready(id);
        self.enqueue_event_ready(id);
        Ok(id)
    }

    /// Add one logical Broadcast or Backup caller. Each member needs a
    /// distinct non-zero SRT Socket ID, even when every member shares the same
    /// UDP four-tuple; Socket IDs are the SRT-layer demultiplexing key.
    pub fn add_group(
        &mut self,
        group_id: u32,
        mode: srt_proto::GroupMode,
        legs: impl IntoIterator<Item = CallerGroupLeg>,
    ) -> Result<LogicalCallerId, srt_proto::Error> {
        if self.sessions.len() >= self.max_callers {
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "caller table capacity reached",
            ));
        }
        let mut group = srt_proto::SrtGroup::new(group_id, mode)?;
        let mut caller_legs = HashMap::new();
        let mut socket_ids = HashSet::new();
        let mut leg_order = Vec::new();
        for leg in legs {
            let socket_id = self.validate_socket_id(&leg.connection)?;
            if !socket_ids.insert(socket_id) {
                return Err(srt_proto::Error::with_reason(
                    srt_proto::ErrorKind::InvalidState,
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
                        output_faulted: false,
                        output_failure: None,
                    },
                )
                .is_some()
            {
                return Err(srt_proto::Error::with_reason(
                    srt_proto::ErrorKind::InvalidState,
                    "shared caller groups require distinct member IDs",
                ));
            }
            leg_order.push(leg.member_id);
        }

        if leg_order.is_empty() {
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "shared caller groups require at least one member",
            ));
        }

        let id = self.allocate_logical_caller()?;
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
        self.sched.insert(
            id,
            SchedEntry {
                ready_queued: false,
                event_ready_queued: false,
                deadline_micros: None,
                heap_pos: None,
            },
        );
        self.sync_deadline(id);
        self.enqueue_ready(id);
        Ok(id)
    }
    fn validate_socket_id(&self, connection: &SrtConnection) -> Result<u32, srt_proto::Error> {
        let socket_id = connection.socket_id();
        if socket_id == 0 || self.routes.contains_key(&socket_id) {
            return Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "shared caller sockets require distinct non-zero SRT socket IDs",
            ));
        }
        Ok(socket_id)
    }

    fn allocate_logical_caller(&mut self) -> Result<LogicalCallerId, srt_proto::Error> {
        let raw = self.next_logical_caller;
        self.next_logical_caller = raw.checked_add(1).ok_or_else(|| {
            srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "logical caller ID space exhausted",
            )
        })?;
        Ok(LogicalCallerId(raw))
    }

    /// Feed one datagram received from the application-owned UDP socket.
    /// Unknown Socket IDs and unexpected source addresses are ignored.
    pub fn feed(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
    ) -> Result<bool, srt_proto::Error> {
        let socket_id = srt_proto::wire::peek_destination_socket_id(data)?;
        let target_id = match self.routes.get(&socket_id).copied() {
            Some(route) => match route {
                CallerRoute::Direct(id) => id,
                CallerRoute::Group { caller, .. } => caller,
            },
            None => return Ok(false),
        };
        let feed_res = match self.routes.get(&socket_id).copied().expect("checked") {
            CallerRoute::Direct(id) => {
                let Some(CallerSession::Direct(leg)) = self.sessions.get_mut(&id) else {
                    return Ok(false);
                };
                if leg.peer != peer {
                    return Ok(false);
                }
                leg.connection.feed_recv_buf(data, now)
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
                let res = group
                    .group
                    .member_mut(member_id)
                    .expect("group and caller legs are built together")
                    .connection_mut()
                    .feed_recv_buf(data, now);
                group.group.refresh_member_states();
                res
            }
        };
        self.sync_deadline(target_id);
        self.enqueue_ready(target_id);
        self.enqueue_event_ready(target_id);
        feed_res.map(|()| true)
    }

    /// Pop up to `max_due` sessions whose deadline has passed, in
    /// `(deadline, id)` order, into the table-owned due scratch. Returns
    /// the popped count; the ids stay in `due_scratch` until
    /// [`Self::fire_due_ids`] drains them. A session past the cap is left
    /// exactly where it was -- still live in the due index, still due -- so
    /// it is picked up again, unchanged, by the very next call with a
    /// `now` no earlier than this one. Zero `max_due` performs no work.
    /// The internal [`MAX_DUE_PER_VISIT`] cap bounds synchronous timer work
    /// even when an outer compatibility budget is effectively unbounded.
    fn pop_due_ids(&mut self, now: Timestamp, max_due: usize) -> usize {
        self.due_scratch.clear();
        let now_micros = now.as_micros();
        let cap = max_due.min(MAX_DUE_PER_VISIT);
        while self.due_scratch.len() < cap {
            let Some(head) = self.deadlines.peek() else {
                break;
            };
            if head.deadline_micros > now_micros {
                break;
            }
            // Exact indexed pop: root is live by construction (no stale
            // entries exist), so pop it directly.
            let node = self.indexed_pop_root();
            if let Some(meta) = self.sched.get_mut(&node.id) {
                meta.deadline_micros = None;
                meta.heap_pos = None;
            }
            if !self.sessions.contains_key(&node.id) {
                continue;
            }
            self.due_scratch.push(node.id);
        }
        self.due_scratch.len()
    }

    /// Pop the heap root and restore the heap property. The root owner's
    /// `heap_pos` is cleared by the caller (`pop_due_ids`); the node moved
    /// to the root gets its position updated here.
    fn indexed_pop_root(&mut self) -> DeadlineNode {
        let last = self.deadlines.heap.len() - 1;
        self.heap_swap(0, last);
        let node = self.deadlines.heap.pop().expect("nonempty heap");
        if !self.deadlines.heap.is_empty() {
            let moved_id = self.deadlines.heap[0].id;
            self.set_heap_pos(moved_id, 0);
            self.sift_down(0);
        }
        node
    }

    /// Whether a due session remains that this visit's `pop_due_ids` cap
    /// left unfired (P02). O(1): the heap root is always live.
    fn has_due_remaining(&self, now: Timestamp) -> bool {
        self.deadlines
            .peek()
            .is_some_and(|head| head.deadline_micros <= now.as_micros())
    }

    /// Fire the timers of every due id left in `due_scratch` by the last
    /// [`Self::pop_due_ids`], then drain the scratch.
    fn fire_due_ids(&mut self, now: Timestamp) {
        let count = self.due_scratch.len();
        for i in 0..count {
            let id = self.due_scratch[i];
            if let Some(session) = self.sessions.get_mut(&id) {
                session.fire_timers(now);
                #[cfg(any(test, feature = "bench-internals"))]
                {
                    self.sched_stats.due_callers_visited += 1;
                }
            }
            self.enqueue_ready(id);
            self.enqueue_event_ready(id);
            self.sync_deadline(id);
        }
        self.due_scratch.clear();
    }

    /// Drive all protocol timers and collect datagrams for the application to
    /// transmit through its one shared UDP socket.
    pub fn poll_outbound(
        &mut self,
        now: Timestamp,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        // Compatibility API: retain its historical drain-current-work
        // behavior, with a finite ceiling large enough for the supported
        // caller fan-in and flow/control bursts.
        let _ = self.poll_outbound_bounded(
            now,
            OutputDrainBudget::new(65_536, 65_536, 64 * 1024 * 1024),
            out,
        );
    }

    /// Fairly drain bounded work from all logical callers. Due timers are
    /// fired only for due callers before the budget is shared fairly across
    /// ready logical streams, so a busy caller cannot starve another caller's
    /// retransmission or close timer.
    /// Drain ready output into any [`DatagramSink`].
    pub fn poll_outbound_bounded_to<S: DatagramSink + ?Sized>(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
        sink: &mut S,
    ) -> OutputDrainReport {
        self.poll_outbound_bounded_to_with_visits(now, budget, sink)
            .0
    }

    pub(crate) fn poll_outbound_bounded_to_with_visits<S: DatagramSink + ?Sized>(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
        sink: &mut S,
    ) -> (OutputDrainReport, usize) {
        if budget.max_actions == 0 {
            return (
                OutputDrainReport {
                    status: if self.has_pending_output(now) {
                        OutputDrainStatus::BudgetExhausted
                    } else {
                        OutputDrainStatus::Drained
                    },
                    ..OutputDrainReport::default()
                },
                0,
            );
        }
        let due_actions = self.pop_due_ids(now, budget.max_actions);
        let due_remaining = self.has_due_remaining(now);
        self.fire_due_ids(now);
        let remaining = OutputDrainBudget::new(
            budget.max_actions.saturating_sub(due_actions),
            budget.max_packets,
            budget.max_bytes,
        );
        let (mut report, ready_visits) = self.drain_ready_bounded(now, remaining, sink);
        report.actions = report.actions.saturating_add(due_actions);
        if due_remaining && report.status == OutputDrainStatus::Drained {
            report.status = OutputDrainStatus::BudgetExhausted;
        }
        (report, due_actions.saturating_add(ready_visits))
    }

    /// Bounded drain into a [`Vec<(SocketAddr, Vec<u8>)>`].
    pub fn poll_outbound_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) -> OutputDrainReport {
        out.clear();
        self.poll_outbound_bounded_to(now, budget, out)
    }

    #[allow(dead_code)]
    pub(crate) fn poll_outbound_bounded_with_visits(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) -> (OutputDrainReport, usize) {
        out.clear();
        self.poll_outbound_bounded_to_with_visits(now, budget, out)
    }

    fn drain_ready_bounded<S: DatagramSink + ?Sized>(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
        sink_dest: &mut S,
    ) -> (OutputDrainReport, usize) {
        let mut report = OutputDrainReport::default();
        let mut failures = self.protocol_failure_scratch.take().unwrap_or_default();
        failures.clear();
        let mut sink = DrainSink {
            budget,
            report: &mut report,
            sink: sink_dest,
            failures: &mut failures,
        };
        // Set when a leg's next packet cannot fit the remaining allowance
        // (`DrainOne::Blocked`'s exceeds_bytes case in
        // drain_one_caller_leg_parts): the numeric counters below can all
        // still be under their caps at that point (e.g. one 1332-byte
        // packet leaves 668 of a 2000-byte allowance, which the next
        // 1332-byte packet cannot fit, but report.bytes is still < 2000),
        // yet real work was pushed back to `pending` and is not drained
        // (T03).
        let mut blocked_on_next_item = false;
        let mut visits = 0;
        while visits < sink.budget.max_actions {
            let visit = self.pop_ready_visit();
            let ReadyVisit::Live(id) = visit else {
                if matches!(visit, ReadyVisit::Stale) {
                    visits += 1;
                    #[cfg(any(test, feature = "bench-internals"))]
                    {
                        self.sched_stats.ready_drain_probes += 1;
                        self.sched_stats.ready_stale_visits += 1;
                    }
                    continue;
                }
                break;
            };
            visits += 1;
            match self.drain_one_ready_visit(id, now, &mut sink) {
                ReadyVisitOutcome::Continue => {}
                ReadyVisitOutcome::BudgetExhausted => break,
                ReadyVisitOutcome::Blocked => {
                    blocked_on_next_item = true;
                    break;
                }
            }
        }
        if blocked_on_next_item
            || !self.ready_queue.is_empty()
            || report.actions >= budget.max_actions
            || report.packets >= budget.max_packets
            || report.bytes >= budget.max_bytes
        {
            report.status = OutputDrainStatus::BudgetExhausted;
        }
        debug_assert!(
            failures.is_empty(),
            "every record produced in a pass is stored on its leg before the pass ends"
        );
        self.protocol_failure_scratch = Some(failures);
        (report, visits)
    }

    /// Service one ready-queue visit -- split out of
    /// [`Self::drain_ready_bounded`]'s own loop body to keep it a plain
    /// "pop, service, repeat" dispatcher.
    fn drain_one_ready_visit<S: DatagramSink + ?Sized>(
        &mut self,
        id: LogicalCallerId,
        now: Timestamp,
        sink: &mut DrainSink<'_, S>,
    ) -> ReadyVisitOutcome {
        // Disjoint field borrows: the session being drained and the failure
        // index it appends to are different fields of this table.
        let Self {
            sessions,
            protocol_failure_index,
            ..
        } = self;
        let (drain_result, timers_touched) = {
            let Some(session) = sessions.get_mut(&id) else {
                return ReadyVisitOutcome::Continue;
            };
            session.drain_one(id, now, sink, protocol_failure_index)
        };
        #[cfg(any(test, feature = "bench-internals"))]
        {
            self.sched_stats.ready_drain_probes += 1;
            if matches!(self.sessions.get(&id), Some(CallerSession::Group(_))) {
                self.sched_stats.ready_group_visits += 1;
            }
        }
        if timers_touched {
            self.sync_deadline(id);
        }
        match drain_result {
            DrainOne::Drained => {
                self.enqueue_ready(id);
                if sink.report.actions >= sink.budget.max_actions
                    || sink.report.packets >= sink.budget.max_packets
                {
                    #[cfg(any(test, feature = "bench-internals"))]
                    {
                        self.sched_stats.budget_exhausted += 1;
                    }
                    return ReadyVisitOutcome::BudgetExhausted;
                }
            }
            DrainOne::Empty => {}
            DrainOne::ProtocolFailed { leg } => {
                // The session (or every leg of it) is quarantined: its output
                // stays queued, the attributed failure is already on the
                // bounded queue, and it must not be re-enqueued as ordinary
                // work. Other sessions in this visit are unaffected, so the
                // loop simply continues.
                let _ = leg;
                #[cfg(any(test, feature = "bench-internals"))]
                {
                    self.sched_stats.protocol_failed_visits += 1;
                }
                return ReadyVisitOutcome::Continue;
            }
            DrainOne::SinkRejected => {
                // Nothing was consumed. The id must stay visible to the
                // scheduler -- dropping it out of the ready queue would hide a
                // still-queued datagram and turn a refusal into silent loss.
                // The refusal itself is already recorded on the report.
                self.enqueue_ready(id);
                #[cfg(any(test, feature = "bench-internals"))]
                {
                    self.sched_stats.budget_exhausted += 1;
                }
                return ReadyVisitOutcome::BudgetExhausted;
            }
            DrainOne::Blocked => {
                self.enqueue_ready(id);
                #[cfg(any(test, feature = "bench-internals"))]
                {
                    self.sched_stats.budget_exhausted += 1;
                }
                return ReadyVisitOutcome::Blocked;
            }
        }
        if sink.report.packets >= sink.budget.max_packets {
            #[cfg(any(test, feature = "bench-internals"))]
            {
                self.sched_stats.budget_exhausted += 1;
            }
            return ReadyVisitOutcome::BudgetExhausted;
        }
        ReadyVisitOutcome::Continue
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
        // Exact removal from the indexed heap: O(log N), no scan, no stale
        // residue. A removed-then-re-added caller gets a fresh heap node;
        // monotonic ids mean the old node can never alias the new one.
        if self
            .sched
            .get(&id)
            .is_some_and(|meta| meta.heap_pos.is_some())
        {
            self.heap_remove(id);
        }
        self.sched.remove(&id);
        self.maybe_compact_ready_queue();
        self.maybe_compact_event_ready_queue();
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

    /// The protocol's own `ConnectionState` for one direct logical caller
    /// -- unlike [`LogicalCallerState`], which folds `Induction`/
    /// `Conclusion`/`Listening`/`Closing` all into one `Connecting` value,
    /// this distinguishes a session still trying to establish from one
    /// that already connected and is now gracefully closing. `None` for a
    /// bonded group (no single state to report) or an id that no longer
    /// exists.
    #[must_use]
    pub fn raw_direct_state(&self, id: &LogicalCallerId) -> Option<srt_proto::ConnectionState> {
        match self.sessions.get(id)? {
            CallerSession::Direct(leg) => Some(leg.connection.state()),
            CallerSession::Group(_) => None,
        }
    }

    /// Drain protocol events for every direct logical caller -- the
    /// caller-side counterpart to [`crate::PeerTable::poll_events`]. The
    /// event-ready queue is populated by packet, timer, and lifecycle paths,
    /// so an idle table does not require a population scan.
    pub fn poll_events(&mut self, out: &mut Vec<CallerEvent>) {
        let _ = self.poll_events_bounded(OutputDrainBudget::default().max_actions, out);
    }

    /// Drain at most `max_events` direct caller events. Returns `true` when
    /// another event-ready caller remains queued. A zero limit is a useful
    /// probe and consumes nothing.
    pub fn poll_events_bounded(&mut self, max_events: usize, out: &mut Vec<CallerEvent>) -> bool {
        out.clear();
        if max_events == 0 {
            return self.has_pending_events();
        }
        let mut visits = 0;
        while visits < max_events && out.len() < max_events {
            let visit = self.pop_event_ready_visit();
            let EventReadyVisit::Live(id) = visit else {
                if matches!(visit, EventReadyVisit::Stale) {
                    visits += 1;
                    continue;
                }
                break;
            };
            visits += 1;
            let filled = {
                let Some(CallerSession::Direct(leg)) = self.sessions.get_mut(&id) else {
                    continue;
                };
                while out.len() < max_events {
                    let Some(event) = leg.connection.poll_event() else {
                        break;
                    };
                    out.push(CallerEvent { id, event });
                }
                out.len() == max_events
            };
            // There is no protocol-side event-count accessor. If this visit
            // filled the caller-facing budget, leave a deduplicated marker so
            // the next call probes it; an exact fill with no remaining event
            // is cleared by that next cheap probe.
            if filled {
                self.enqueue_event_ready(id);
                break;
            }
        }
        self.has_pending_events()
    }

    /// Whether any event-ready queue entry remains. A stale entry is still
    /// pending bounded maintenance and is removed by the next poll.
    #[must_use]
    pub fn has_pending_events(&self) -> bool {
        !self.event_ready_queue.is_empty()
    }

    /// Whether output or a due timer can be serviced at `now`. O(1): the
    /// heap root is always the earliest live deadline.
    #[must_use]
    pub fn has_pending_output(&self, now: Timestamp) -> bool {
        if !self.ready_queue.is_empty() {
            return true;
        }
        self.deadlines
            .peek()
            .is_some_and(|head| head.deadline_micros <= now.as_micros())
    }

    /// Whether this table has any bounded work to drive at `now`.
    #[must_use]
    pub fn has_pending_work(&self, now: Timestamp) -> bool {
        self.has_pending_output(now) || self.has_pending_events()
    }

    pub fn logical_caller_mut(&mut self, id: &LogicalCallerId) -> Option<LogicalCallerMut<'_>> {
        self.logical_caller(id)?;
        Some(LogicalCallerMut {
            table: self,
            id: *id,
        })
    }

    /// Time in microseconds until the nearest live deadline, capped at
    /// `default_micros`. O(1): reads the heap root, no scan.
    #[must_use]
    pub fn time_until_next_deadline(&self, now: Timestamp, default_micros: u64) -> u64 {
        match self.deadlines.peek() {
            None => default_micros,
            Some(head) => head
                .deadline_micros
                .saturating_sub(now.as_micros())
                .min(default_micros),
        }
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn bench_arm_timer(
        &mut self,
        id: LogicalCallerId,
        timer_id: srt_proto::TimerId,
        duration_micros: u64,
        now: Timestamp,
    ) {
        if let Some(session) = self.sessions.get_mut(&id) {
            match session {
                CallerSession::Direct(leg) => {
                    leg.timers.apply_output(
                        &ConnectionOutput::SetTimer {
                            id: timer_id,
                            duration_micros,
                        },
                        now,
                    );
                }
                CallerSession::Group(group) => {
                    if let Some(leg) = group.legs.values_mut().next() {
                        leg.timers.apply_output(
                            &ConnectionOutput::SetTimer {
                                id: timer_id,
                                duration_micros,
                            },
                            now,
                        );
                    }
                }
            }
            self.sync_deadline(id);
        }
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn bench_inject_deadline(&mut self, id: LogicalCallerId, deadline: Timestamp) {
        self.bench_arm_timer(
            id,
            srt_proto::TimerId::Ack,
            deadline.as_micros(),
            Timestamp::from_micros(0),
        );
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn bench_clear_deadline(&mut self, id: LogicalCallerId) {
        if let Some(session) = self.sessions.get_mut(&id) {
            match session {
                CallerSession::Direct(leg) => {
                    for &t in &srt_proto::TimerId::ALL {
                        leg.timers.apply_output(
                            &ConnectionOutput::ClearTimer { id: t },
                            Timestamp::default(),
                        );
                    }
                }
                CallerSession::Group(group) => {
                    for leg in group.legs.values_mut() {
                        for &t in &srt_proto::TimerId::ALL {
                            leg.timers.apply_output(
                                &ConnectionOutput::ClearTimer { id: t },
                                Timestamp::default(),
                            );
                        }
                    }
                }
            }
            self.sync_deadline(id);
        }
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn bench_ids(&self) -> Vec<LogicalCallerId> {
        self.sessions.keys().copied().collect()
    }

    /// Benchmark/test-only: the protocol's next queued output for this
    /// session, if any. Used to prove a refused acquisition consumes nothing:
    /// the identical metadata must still be queued afterwards.
    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn bench_peek_output(&self, id: &LogicalCallerId) -> Option<srt_proto::OutputMeta> {
        match self.sessions.get(id)? {
            CallerSession::Direct(leg) => leg.connection.peek_output(),
            CallerSession::Group(group) => group
                .leg_order
                .first()
                .and_then(|first| {
                    group
                        .group
                        .member(*first)
                        .map(|member| member.connection().peek_output())
                })
                .flatten(),
        }
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn bench_make_ready(&mut self, id: LogicalCallerId) {
        self.enqueue_ready(id);
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub fn bench_push_pending(
        &mut self,
        id: LogicalCallerId,
        _peer: std::net::SocketAddr,
        packet: Vec<u8>,
    ) {
        if let Some(session) = self.sessions.get_mut(&id) {
            match session {
                CallerSession::Direct(leg) => {
                    leg.pending.push_back(ConnectionOutput::SendPacket(packet));
                }
                CallerSession::Group(group) => {
                    if let Some(first) = group.leg_order.first().copied()
                        && let Some(leg) = group.legs.get_mut(&first)
                    {
                        leg.pending.push_back(ConnectionOutput::SendPacket(packet));
                    }
                }
            }
            self.enqueue_ready(id);
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    #[must_use]
    pub fn max_callers(&self) -> usize {
        self.max_callers
    }
}

impl Default for CallerTable {
    fn default() -> Self {
        Self::new()
    }
}
fn drain_one_caller_leg<S: DatagramSink + ?Sized>(
    id: LogicalCallerId,
    leg: &mut CallerLegState,
    now: Timestamp,
    sink: &mut DrainSink<'_, S>,
) -> (DrainOne, bool) {
    drain_one_caller_leg_parts(
        leg.peer,
        TxAttribution::caller(id, 0),
        None,
        now,
        &mut leg.timers,
        &mut leg.pending,
        &mut leg.connection,
        sink,
    )
}

fn drain_caller_legacy_output<S: DatagramSink + ?Sized>(
    peer: std::net::SocketAddr,
    now: Timestamp,
    timers: &mut ManualTimerStore,
    pending: &mut VecDeque<ConnectionOutput>,
    sink: &mut DrainSink<'_, S>,
) -> Option<(DrainOne, bool)> {
    let output = pending.front()?;
    match output {
        ConnectionOutput::SendPacket(packet) => {
            let wire_len = packet.len();
            let exceeds_packets = sink.report.packets >= sink.budget.max_packets;
            let exceeds_bytes = sink.report.bytes.saturating_add(wire_len) > sink.budget.max_bytes;
            if exceeds_packets || exceeds_bytes {
                return Some((DrainOne::Blocked, false));
            }
            // Reserve first: every fallible decision happens here, so a
            // refusal leaves this queued packet untouched.
            let (report, dest) = split(sink);
            let mut slot = match dest.acquire(peer, wire_len) {
                Ok(Some(slot)) => slot,
                Ok(None) => {
                    record_unavailable(report);
                    return Some((DrainOne::Blocked, false));
                }
                Err(error) => {
                    record_sink_rejection(report, &error);
                    return Some((DrainOne::SinkRejected, false));
                }
            };
            // Compatibility surface: the bytes are already materialized, so
            // this is a copy into the reserved slot, then an infallible commit.
            {
                let buf = slot.bytes_mut();
                buf[..wire_len].copy_from_slice(packet);
            }
            slot.commit(wire_len);
            pending.pop_front();
            record_pushed(report, wire_len);
            Some((DrainOne::Drained, false))
        }
        _other => {
            let output = pending.pop_front().unwrap();
            sink.report.actions += 1;
            timers.apply_output(&output, now);
            Some((DrainOne::Drained, true))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_caller_direct_meta<S: DatagramSink + ?Sized>(
    peer: std::net::SocketAddr,
    attribution: TxAttribution,
    leg: Option<u32>,
    now: Timestamp,
    timers: &mut ManualTimerStore,
    connection: &mut SrtConnection,
    meta: OutputMeta,
    sink: &mut DrainSink<'_, S>,
) -> (DrainOne, bool) {
    match meta {
        OutputMeta::Datagram { wire_len } => {
            let exceeds_packets = sink.report.packets >= sink.budget.max_packets;
            let exceeds_bytes = sink.report.bytes.saturating_add(wire_len) > sink.budget.max_bytes;
            if exceeds_packets || exceeds_bytes {
                return (DrainOne::Blocked, false);
            }
            // Reserve first: `poll_output_into` is only reached once capacity
            // is irrevocably held, so a refusal cannot consume protocol state.
            let (report, chain, dest) = split_chain(sink);
            let mut slot = match dest.acquire_target(DatagramTarget { peer, attribution }, wire_len)
            {
                Ok(Some(slot)) => slot,
                Ok(None) => {
                    record_unavailable(report);
                    return (DrainOne::Blocked, false);
                }
                Err(error) => {
                    record_sink_rejection(report, &error);
                    return (DrainOne::SinkRejected, false);
                }
            };
            let materialized = {
                let buf = slot.bytes_mut();
                match connection.poll_output_into(buf) {
                    Ok(Some(OutputInto::Datagram { len })) => Ok(len),
                    // The peeked datagram is still queued: a datagram that
                    // vanished between peek and poll, or a protocol refusal,
                    // is a real condition of this session -- never "empty".
                    Ok(_) => Err(srt_proto::Error::with_reason(
                        srt_proto::ErrorKind::InvalidState,
                        "peeked datagram output vanished before materialization",
                    )),
                    Err(error) => Err(error),
                }
            };
            match materialized {
                Ok(len) => {
                    // Infallible: the protocol output is consumed exactly once.
                    slot.commit(len);
                    record_pushed(report, len);
                    (DrainOne::Drained, false)
                }
                Err(error) => {
                    record_protocol_failure(report, chain.failures, attribution, &error);
                    (DrainOne::ProtocolFailed { leg }, false)
                }
            }
        }
        OutputMeta::SetTimer { .. } | OutputMeta::ClearTimer { .. } => {
            let mut dummy = [];
            match connection.poll_output_into(&mut dummy) {
                Ok(Some(OutputInto::SetTimer {
                    id,
                    duration_micros,
                })) => {
                    sink.report.actions += 1;
                    timers.apply_output(
                        &ConnectionOutput::SetTimer {
                            id,
                            duration_micros,
                        },
                        now,
                    );
                    (DrainOne::Drained, true)
                }
                Ok(Some(OutputInto::ClearTimer { id })) => {
                    sink.report.actions += 1;
                    timers.apply_output(&ConnectionOutput::ClearTimer { id }, now);
                    (DrainOne::Drained, true)
                }
                _ => (DrainOne::Empty, false),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_one_caller_leg_parts<S: DatagramSink + ?Sized>(
    peer: std::net::SocketAddr,
    attribution: TxAttribution,
    leg: Option<u32>,
    now: Timestamp,
    timers: &mut ManualTimerStore,
    pending: &mut VecDeque<ConnectionOutput>,
    connection: &mut SrtConnection,
    sink: &mut DrainSink<'_, S>,
) -> (DrainOne, bool) {
    if sink.report.actions >= sink.budget.max_actions {
        return (DrainOne::Blocked, false);
    }
    if let Some(res) = drain_caller_legacy_output(peer, now, timers, pending, sink) {
        return res;
    }
    let Some(meta) = connection.peek_output() else {
        return (DrainOne::Empty, false);
    };
    drain_caller_direct_meta(peer, attribution, leg, now, timers, connection, meta, sink)
}

pub(crate) fn prepend_outputs(
    pending: &mut VecDeque<ConnectionOutput>,
    outputs: impl DoubleEndedIterator<Item = ConnectionOutput>,
) {
    for output in outputs.rev() {
        pending.push_front(output);
    }
}

/// Collect protocol output for one bounded drain.
///
/// Fallible because `poll_output` is: a transactional materialization failure
/// (`InvalidState` after a queue overflow, `InvalidData` on a malformed
/// datagram) leaves the offending output queued, so it must be reported rather
/// than read as "nothing left to send".
pub(crate) fn collect_output_work(
    conn: &mut SrtConnection,
    pending: &mut VecDeque<ConnectionOutput>,
    budget: OutputDrainBudget,
) -> Result<(VecDeque<ConnectionOutput>, bool), srt_proto::Error> {
    // `max_actions == 0` performs no work. A composed owner budget can
    // legitimately reach zero after an earlier phase consumed the shared
    // allowance, and that must stop the follow-up phase rather than reopening
    // it as unlimited.
    if budget.max_actions == 0 {
        return Ok((VecDeque::new(), true));
    }
    let max_actions = budget.max_actions;
    let max_packets = budget.max_packets;
    let max_bytes = budget.max_bytes;
    let mut work = VecDeque::new();
    let mut packets = 0usize;
    let mut bytes = 0usize;

    while work.len() < max_actions {
        let output = match pending.pop_front() {
            Some(output) => output,
            None => match conn.poll_output()? {
                Some(output) => output,
                None => return Ok((work, false)),
            },
        };
        if let ConnectionOutput::SendPacket(packet) = &output {
            let exceeds_packet_cap = packets >= max_packets;
            let exceeds_byte_cap = bytes.saturating_add(packet.len()) > max_bytes;
            if exceeds_packet_cap || exceeds_byte_cap {
                pending.push_front(output);
                return Ok((work, true));
            }
            packets += 1;
            bytes = bytes.saturating_add(packet.len());
        }
        work.push_back(output);
    }

    Ok((work, true))
}

#[cfg(test)]
mod tests {
    use crate::*;
    use proptest::prelude::*;
    use srt_proto::handshake::HandshakePacket;
    use srt_proto::wire::SrtPacket;
    use srt_proto::{
        ConnectionEvent, ConnectionOptions, ConnectionOutput, ErrorKind, SrtConnection, TimerId,
        Timestamp,
    };
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    fn induction(socket_id: u32) -> Vec<u8> {
        let packet = HandshakePacket::new_induction_request(socket_id).encode(0, 0);
        let mut bytes = Vec::new();
        packet
            .encode(&mut bytes)
            .expect("packet fits configured datagram bound");
        bytes
    }

    fn next_packet(conn: &mut SrtConnection) -> Vec<u8> {
        loop {
            match conn
                .poll_output()
                .expect("exact-size output materializes")
                .expect("connection output")
            {
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

    #[test]
    fn poll_outbound_bounded_to_drains_directly_and_handles_exhaustion() {
        let mut table = CallerTable::default();
        let peer: std::net::SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let mut conn = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 0x5555,
            ..Default::default()
        });
        let now = Timestamp::from_micros(10_000);
        conn.connect(now).expect("connect");
        let leg = CallerLeg {
            peer,
            connection: conn,
        };
        let _id = table.add_direct(leg).expect("admitted");
        // Try draining with sink capacity = 0 (completely exhausted)
        let mut sink0 = TestSink {
            capacity: 0,
            packets: Vec::new(),
        };
        let report0 = table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut sink0);
        assert_eq!(sink0.packets.len(), 0);
        assert_eq!(report0.status, OutputDrainStatus::BudgetExhausted);

        // Now drain with capacity = 1
        let mut sink1 = TestSink {
            capacity: 1,
            packets: Vec::new(),
        };
        let _report1 =
            table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut sink1);
        assert_eq!(sink1.packets.len(), 1);
        assert_eq!(sink1.packets[0].0, peer);
    }

    /// A capacity-bounded recording sink shared by the drain tests.
    struct TestSink {
        capacity: usize,
        packets: Vec<(std::net::SocketAddr, Vec<u8>)>,
    }

    struct TestSlot<'a> {
        sink: &'a mut TestSink,
        peer: std::net::SocketAddr,
        buf: Vec<u8>,
    }

    impl DatagramSlot for TestSlot<'_> {
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.buf
        }

        fn commit(self, len: usize) {
            let mut buf = self.buf;
            buf.truncate(len);
            self.sink.packets.push((self.peer, buf));
        }
    }

    impl DatagramSink for TestSink {
        type Slot<'a> = TestSlot<'a>;

        fn acquire(
            &mut self,
            peer: std::net::SocketAddr,
            wire_len: usize,
        ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
            if self.packets.len() >= self.capacity {
                return Ok(None);
            }
            Ok(Some(TestSlot {
                sink: self,
                peer,
                buf: vec![0u8; wire_len],
            }))
        }
    }

    /// Adversarial sink: it reserves the requested capacity but hands the
    /// protocol a SHORTER buffer, so `poll_output_into` refuses with
    /// `insufficient_buffer` while the protocol output stays queued.
    ///
    /// That is the deterministic injection the materialization-failure
    /// contract needs: no kernel, no timing, and no dependence on which error
    /// the protocol picks. A sink that violates its own reservation contract
    /// is exactly the hostile case the table must survive.
    struct ShortBufferSink {
        acquisitions: usize,
        committed: Vec<(std::net::SocketAddr, Vec<u8>)>,
        /// Attribution offered on the most recent acquisition, so a test can
        /// prove the table passes the logical identity, not just an address.
        last_attribution: Option<crate::sink::TxAttribution>,
        short_by: usize,
    }

    struct ShortBufferSlot<'a> {
        sink: &'a mut ShortBufferSink,
        peer: std::net::SocketAddr,
        buf: Vec<u8>,
    }

    impl DatagramSlot for ShortBufferSlot<'_> {
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.buf
        }

        fn commit(self, len: usize) {
            let mut buf = self.buf;
            buf.truncate(len);
            self.sink.committed.push((self.peer, buf));
        }
    }

    impl DatagramSink for ShortBufferSink {
        type Slot<'a> = ShortBufferSlot<'a>;

        fn acquire(
            &mut self,
            peer: std::net::SocketAddr,
            wire_len: usize,
        ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
            self.acquisitions += 1;
            let len = wire_len.saturating_sub(self.short_by).max(1);
            Ok(Some(ShortBufferSlot {
                sink: self,
                peer,
                buf: vec![0u8; len],
            }))
        }

        fn acquire_target(
            &mut self,
            target: crate::sink::DatagramTarget,
            wire_len: usize,
        ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
            self.last_attribution = Some(target.attribution);
            self.acquire(target.peer, wire_len)
        }
    }

    /// A protocol materialization failure must never read as "nothing to
    /// send": the output stays queued, the failure is typed and attributed to
    /// the logical caller, and the caller is not re-offered as ordinary empty
    /// work (which would rediscover the same failure every visit).
    #[test]
    fn direct_protocol_materialization_failure_is_typed_and_attributed() {
        let mut table = CallerTable::new();
        let peer: std::net::SocketAddr = "127.0.0.1:9401".parse().unwrap();
        let now = Timestamp::from_micros(10_000);
        let leg = CallerLeg {
            peer,
            connection: caller_connection(ConnectionOptions {
                socket_id: 0x9401,
                ..ConnectionOptions::default()
            }),
        };
        let id = table.add_direct(leg).expect("admitted");

        // First visit with a hostile sink: the reservation is granted but the
        // protocol cannot materialize into it.
        let mut short = ShortBufferSink {
            acquisitions: 0,
            committed: Vec::new(),
            last_attribution: None,
            short_by: 8,
        };
        let report = table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut short);
        assert_eq!(
            report.protocol_output_failures, 1,
            "the refusal is counted, not swallowed"
        );
        assert_eq!(
            report.protocol_output_error_kind,
            Some(srt_proto::ErrorKind::InsufficientBuffer),
            "the protocol's own kind is surfaced"
        );
        assert_eq!(report.status, OutputDrainStatus::ProtocolError);
        assert!(short.committed.is_empty(), "nothing was committed");
        assert_eq!(
            short.last_attribution.and_then(|a| a.caller_id()),
            Some(id),
            "the reservation carried the logical caller identity"
        );
        // The offending output is STILL QUEUED.
        assert!(
            table.bench_peek_output(&id).is_some(),
            "a refused materialization leaves the output queued"
        );

        let mut failures = Vec::new();
        table.poll_output_failures(8, &mut failures);
        assert_eq!(failures.len(), 1, "one attributed failure is reported");
        assert_eq!(failures[0].attribution.caller_id(), Some(id));
        assert_eq!(failures[0].attribution.leg(), 0);
        assert_eq!(failures[0].kind, srt_proto::ErrorKind::InsufficientBuffer);
    }

    /// Follow-up to the test above: a quarantined caller is not rediscovered,
    /// and a healthy sibling in the same table keeps draining.
    #[test]
    fn quarantined_caller_is_not_rediscovered_and_siblings_keep_draining() {
        let mut table = CallerTable::new();
        let peer: std::net::SocketAddr = "127.0.0.1:9403".parse().unwrap();
        let now = Timestamp::from_micros(10_000);
        let id = table
            .add_direct(CallerLeg {
                peer,
                connection: caller_connection(ConnectionOptions {
                    socket_id: 0x9403,
                    ..ConnectionOptions::default()
                }),
            })
            .expect("admitted");
        let mut short = ShortBufferSink {
            acquisitions: 0,
            committed: Vec::new(),
            last_attribution: None,
            short_by: 8,
        };
        let report = table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut short);
        assert_eq!(report.protocol_output_failures, 1);
        let mut failures = Vec::new();
        table.poll_output_failures(8, &mut failures);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].attribution.caller_id(), Some(id));

        // The quarantined caller is not rediscovered: further visits neither
        // re-report nor spin, and the table stops claiming pending output.
        for _ in 0..3 {
            let mut again = ShortBufferSink {
                acquisitions: 0,
                committed: Vec::new(),
                last_attribution: None,
                short_by: 8,
            };
            let report =
                table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut again);
            assert_eq!(
                report.protocol_output_failures, 0,
                "a quarantined caller must not re-report the same failure"
            );
            assert_eq!(again.acquisitions, 0, "and must not be re-offered");
        }
        assert_eq!(table.output_failures_pending(), 0);
        assert!(
            !table.has_pending_output(now),
            "a quarantined caller is not schedulable work"
        );

        // A healthy sibling in the same table keeps draining.
        let other_peer: std::net::SocketAddr = "127.0.0.1:9402".parse().unwrap();
        let other = table
            .add_direct(CallerLeg {
                peer: other_peer,
                connection: caller_connection(ConnectionOptions {
                    socket_id: 0x9402,
                    ..ConnectionOptions::default()
                }),
            })
            .expect("admitted");
        table.bench_make_ready(other);
        let mut good = TestSink {
            capacity: 8,
            packets: Vec::new(),
        };
        let report = table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut good);
        assert_eq!(
            report.protocol_output_failures, 0,
            "the sibling's datagram materializes normally"
        );
        assert!(!good.packets.is_empty(), "the sibling kept sending");
        assert_eq!(good.packets[0].0, other_peer);
    }

    /// The same contract for a bonded caller: the failure names the exact leg,
    /// and the other leg of that group keeps working.
    #[test]
    fn bonded_protocol_materialization_failure_isolates_one_leg() {
        let mut callers = CallerTable::new();
        let group_id = srt_proto::handshake::SRTGROUP_MASK | 78;
        let first_peer: std::net::SocketAddr = "127.0.0.1:9412".parse().unwrap();
        let second_peer: std::net::SocketAddr = "127.0.0.1:9413".parse().unwrap();
        let now = Timestamp::from_micros(10_000);
        let id = callers
            .add_group(
                group_id,
                srt_proto::GroupMode::Broadcast,
                [
                    CallerGroupLeg::new(
                        1,
                        1,
                        first_peer,
                        caller_connection(ConnectionOptions {
                            socket_id: 112,
                            initial_seq: Some(1234),
                            ..ConnectionOptions::default()
                        }),
                    ),
                    CallerGroupLeg::new(
                        2,
                        1,
                        second_peer,
                        caller_connection(ConnectionOptions {
                            socket_id: 113,
                            initial_seq: Some(1234),
                            ..ConnectionOptions::default()
                        }),
                    ),
                ],
            )
            .expect("group admitted");

        // Fail the first leg only: the sink grants the reservation for the
        // first peer and shortens every buffer, then behaves for the second.
        let mut selective = SelectiveShortSink {
            failing_peer: first_peer,
            short_by: 8,
            committed: Vec::new(),
            attributions: Vec::new(),
        };
        let _ = callers.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut selective);

        let mut failures = Vec::new();
        callers.poll_output_failures(8, &mut failures);
        assert_eq!(failures.len(), 1, "exactly one leg is reported");
        assert_eq!(failures[0].attribution.caller_id(), Some(id));
        assert_eq!(
            failures[0].attribution.leg(),
            1,
            "the failing MEMBER id is the attribution, not the peer address"
        );
        assert_eq!(failures[0].kind, srt_proto::ErrorKind::InsufficientBuffer);

        // Only the failing leg is quarantined: the same visit already
        // materialized the sibling leg's datagram, on its own peer address.
        assert!(
            selective
                .committed
                .iter()
                .any(|(peer, _)| *peer == second_peer),
            "the healthy leg of the group still materializes"
        );
        assert!(
            !selective
                .committed
                .iter()
                .any(|(peer, _)| *peer == first_peer),
            "the failing leg committed nothing"
        );

        // Later visits neither re-report the quarantined leg nor stop the
        // group from being serviceable.
        let mut good = TestSink {
            capacity: 8,
            packets: Vec::new(),
        };
        let report = callers.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut good);
        assert_eq!(
            report.protocol_output_failures, 0,
            "the quarantined leg is not re-reported"
        );
        let mut more = Vec::new();
        callers.poll_output_failures(8, &mut more);
        assert!(more.is_empty(), "one failure per leg, not one per visit");
    }

    /// Sink that fails materialization for one peer only, so a bonded test can
    /// prove leg-level isolation instead of whole-group failure.
    struct SelectiveShortSink {
        failing_peer: std::net::SocketAddr,
        short_by: usize,
        committed: Vec<(std::net::SocketAddr, Vec<u8>)>,
        attributions: Vec<crate::sink::DatagramTarget>,
    }

    struct SelectiveShortSlot<'a> {
        sink: &'a mut SelectiveShortSink,
        peer: std::net::SocketAddr,
        buf: Vec<u8>,
    }

    impl DatagramSlot for SelectiveShortSlot<'_> {
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.buf
        }

        fn commit(self, len: usize) {
            let mut buf = self.buf;
            buf.truncate(len);
            self.sink.committed.push((self.peer, buf));
        }
    }

    impl DatagramSink for SelectiveShortSink {
        type Slot<'a> = SelectiveShortSlot<'a>;

        fn acquire_target(
            &mut self,
            target: crate::sink::DatagramTarget,
            wire_len: usize,
        ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
            let len = if target.peer == self.failing_peer {
                wire_len.saturating_sub(self.short_by).max(1)
            } else {
                wire_len
            };
            self.attributions.push(target);
            Ok(Some(SelectiveShortSlot {
                sink: self,
                peer: target.peer,
                buf: vec![0u8; len],
            }))
        }

        fn acquire(
            &mut self,
            peer: std::net::SocketAddr,
            wire_len: usize,
        ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
            self.acquire_target(crate::sink::DatagramTarget::unattributed(peer), wire_len)
        }
    }

    /// The successful path is unchanged: reserve, materialize, commit -- with
    /// the attribution still recorded on the sink.
    #[test]
    fn successful_materialization_still_commits_with_attribution() {
        let mut table = CallerTable::new();
        let peer: std::net::SocketAddr = "127.0.0.1:9421".parse().unwrap();
        let now = Timestamp::from_micros(10_000);
        let id = table
            .add_direct(CallerLeg {
                peer,
                connection: caller_connection(ConnectionOptions {
                    socket_id: 0x9421,
                    ..ConnectionOptions::default()
                }),
            })
            .expect("admitted");
        let mut sink = ShortBufferSink {
            acquisitions: 0,
            committed: Vec::new(),
            last_attribution: None,
            short_by: 0,
        };
        let report = table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut sink);
        assert_eq!(report.protocol_output_failures, 0);
        assert_eq!(report.status, OutputDrainStatus::Drained);
        assert_eq!(sink.committed.len(), 1, "one datagram committed");
        assert_eq!(sink.committed[0].0, peer);
        assert_eq!(
            sink.last_attribution.and_then(|a| a.caller_id()),
            Some(id),
            "attribution survives the successful path too"
        );
        assert_eq!(table.output_failures_pending(), 0);
    }

    /// Two logical callers can share one remote UDP endpoint; SRT routing
    /// distinguishes them by socket identity, not by address. The attribution
    /// that reaches the sink must therefore be the logical caller, and it must
    /// differ between them.
    #[test]
    fn attribution_distinguishes_logical_callers_sharing_one_peer_address() {
        let mut table = CallerTable::new();
        // Same address for both legs: only the socket id differs.
        let shared: std::net::SocketAddr = "127.0.0.1:9501".parse().unwrap();
        let now = Timestamp::from_micros(10_000);
        let first = table
            .add_direct(CallerLeg {
                peer: shared,
                connection: caller_connection(ConnectionOptions {
                    socket_id: 0x9501,
                    ..ConnectionOptions::default()
                }),
            })
            .expect("first admitted");
        let second = table
            .add_direct(CallerLeg {
                peer: shared,
                connection: caller_connection(ConnectionOptions {
                    socket_id: 0x9502,
                    ..ConnectionOptions::default()
                }),
            })
            .expect("second admitted");
        assert_ne!(first, second, "distinct logical callers");

        let mut sink = SelectiveShortSink {
            failing_peer: "127.0.0.1:0".parse().unwrap(),
            short_by: 0,
            committed: Vec::new(),
            attributions: Vec::new(),
        };
        table.bench_make_ready(first);
        table.bench_make_ready(second);
        let _ =
            table.poll_outbound_bounded_to(now, OutputDrainBudget::new(64, 64, 1 << 20), &mut sink);
        let mut attributed: Vec<LogicalCallerId> = sink
            .attributions
            .iter()
            .filter_map(|target| target.attribution.caller_id())
            .collect();
        attributed.sort();
        attributed.dedup();
        assert_eq!(
            attributed,
            vec![first.min(second), first.max(second)],
            "each datagram carries its own logical caller even on a shared address"
        );
        assert_eq!(
            sink.attributions
                .iter()
                .filter(|target| target.peer == shared)
                .count(),
            2,
            "both datagrams went to the same address"
        );
    }

    /// Adversarial: MORE than the old 64-entry failure queue's worth of legs
    /// fault before the application drains anything.
    ///
    /// The retirement token is the only way to identify a quarantined leg, and
    /// a quarantined leg is deliberately never re-offered or re-reported, so a
    /// lost record means a permanently invisible session. This test faults 70
    /// separately identifiable legs with nothing drained in between and
    /// requires every one of them back exactly once.
    #[test]
    fn every_quarantined_leg_stays_discoverable_past_any_queue_bound() {
        /// Comfortably past the 64-entry bound the queue used to have.
        const LEGS: usize = 70;
        const { assert!(LEGS > 64) };
        let mut table = CallerTable::new();
        let now = Timestamp::from_micros(10_000);
        let mut ids = Vec::with_capacity(LEGS);
        for i in 0..LEGS {
            let peer: std::net::SocketAddr = format!("127.0.0.1:{}", 20_000 + i)
                .parse()
                .expect("address");
            ids.push(
                table
                    .add_direct(CallerLeg {
                        peer,
                        connection: caller_connection(ConnectionOptions {
                            socket_id: 0x20_000 + i as u32,
                            ..ConnectionOptions::default()
                        }),
                    })
                    .expect("admitted"),
            );
        }

        // Every leg faults; nothing is drained until all of them have.
        let mut short = ShortBufferSink {
            acquisitions: 0,
            committed: Vec::new(),
            last_attribution: None,
            short_by: 8,
        };
        let budget = OutputDrainBudget::new(4096, 4096, 1 << 22);
        let _ = table.poll_outbound_bounded_to(now, budget, &mut short);
        let after_first = short.acquisitions;
        assert_eq!(
            after_first, LEGS,
            "every leg is offered once, then quarantined"
        );
        assert!(short.committed.is_empty(), "no leg materialized anything");
        // Later visits must not re-offer a quarantined leg.
        for _ in 0..4 {
            let _ = table.poll_outbound_bounded_to(now, budget, &mut short);
        }
        assert_eq!(
            short.acquisitions, after_first,
            "quarantined legs are never re-offered"
        );
        assert_eq!(
            table.output_failures_pending(),
            LEGS,
            "every quarantined leg has an undrained record"
        );

        // Drain everything and require exactly one record per leg.
        let mut failures = Vec::new();
        table.poll_output_failures(LEGS * 2, &mut failures);
        assert_eq!(failures.len(), LEGS, "no record was lost");
        let mut reported: Vec<LogicalCallerId> = failures
            .iter()
            .filter_map(|record| record.attribution.caller_id())
            .collect();
        reported.sort();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(
            reported, expected,
            "every failed leg is returned exactly once, in no particular order"
        );
        assert_eq!(table.output_failures_pending(), 0);

        // And no leg is left quarantined without a discoverable record: a
        // second drain finds nothing, and each id is uniquely represented.
        let mut again = Vec::new();
        table.poll_output_failures(LEGS * 2, &mut again);
        assert!(again.is_empty());

        // Siblings still progress: a healthy leg added afterwards drains fine.
        let healthy_peer: std::net::SocketAddr = "127.0.0.1:21999".parse().expect("address");
        let healthy = table
            .add_direct(CallerLeg {
                peer: healthy_peer,
                connection: caller_connection(ConnectionOptions {
                    socket_id: 0x2_1999,
                    ..ConnectionOptions::default()
                }),
            })
            .expect("admitted");
        table.bench_make_ready(healthy);
        let mut good = TestSink {
            capacity: 8,
            packets: Vec::new(),
        };
        let _ =
            table.poll_outbound_bounded_to(now, OutputDrainBudget::new(64, 64, 1 << 20), &mut good);
        assert!(
            !good.packets.is_empty(),
            "a healthy leg still drains while many legs are quarantined"
        );
    }

    /// A sink that refuses every datagram in `acquire`, so a test can prove
    /// a refusal never consumes protocol state.
    struct RefusingSink {
        accepted: Vec<(std::net::SocketAddr, Vec<u8>)>,
    }

    struct RefusingSlot<'a> {
        sink: &'a mut RefusingSink,
        peer: std::net::SocketAddr,
        buf: Vec<u8>,
    }

    impl DatagramSlot for RefusingSlot<'_> {
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.buf
        }

        fn commit(self, len: usize) {
            let mut buf = self.buf;
            buf.truncate(len);
            self.sink.accepted.push((self.peer, buf));
        }
    }

    impl DatagramSink for RefusingSink {
        type Slot<'a> = RefusingSlot<'a>;

        fn acquire(
            &mut self,
            peer: std::net::SocketAddr,
            wire_len: usize,
        ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
            let _ = (peer, wire_len);
            Err(srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidData,
                "test sink refuses every datagram",
            ))
        }
    }

    impl CallerTable {
        /// Test-only: the first direct session's queued protocol output.
        fn bench_peek_output_of_first_direct(&self) -> Option<srt_proto::OutputMeta> {
            self.bench_peek_output(&self.only_direct_id())
        }

        fn only_direct_id(&self) -> LogicalCallerId {
            self.sessions
                .keys()
                .copied()
                .next()
                .expect("a direct caller was admitted")
        }
    }

    /// Build a table with one direct caller whose induction datagram is queued,
    /// for the transactional-sink tests.
    fn table_with_one_queued_direct_caller() -> (CallerTable, Timestamp) {
        let mut table = CallerTable::default();
        let peer: std::net::SocketAddr = "127.0.0.1:9011".parse().unwrap();
        let mut conn = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 0x6001,
            ..Default::default()
        });
        let now = Timestamp::from_micros(10_000);
        conn.connect(now).expect("connect");
        table
            .add_direct(CallerLeg {
                peer,
                connection: conn,
            })
            .expect("admitted");
        (table, now)
    }

    /// Invariant 1: an exhausted sink reserves nothing and the protocol output
    /// stays untouched.
    #[test]
    fn exhausted_sink_leaves_protocol_output_pending() {
        let (mut table, now) = table_with_one_queued_direct_caller();
        assert!(table.has_pending_output(now), "induction is queued");

        let mut exhausted = TestSink {
            capacity: 0,
            packets: Vec::new(),
        };
        let report =
            table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut exhausted);
        assert!(exhausted.packets.is_empty());
        assert_eq!(report.sink_outcome, SinkOutcome::Unavailable);
        assert_eq!(report.packets, 0);
        assert!(
            table.has_pending_output(now),
            "an exhausted sink must leave the protocol datagram pending"
        );
    }

    /// Invariant 2: a refusal is typed, precedes materialization, and still
    /// consumes nothing.
    #[test]
    fn refusing_sink_consumes_nothing_and_reports_a_typed_kind() {
        let (mut table, now) = table_with_one_queued_direct_caller();
        let pending_before = table.bench_peek_output_of_first_direct();

        let mut refusing = RefusingSink {
            accepted: Vec::new(),
        };
        let report =
            table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut refusing);

        assert!(
            refusing.accepted.is_empty(),
            "a refusing sink must not receive a committed datagram"
        );
        assert_eq!(report.sink_outcome, SinkOutcome::Rejected);
        assert_eq!(report.sink_rejections, 1);
        assert_eq!(
            report.sink_error_kind,
            Some(srt_proto::ErrorKind::InvalidData)
        );
        assert_eq!(report.packets, 0);
        assert_eq!(
            table.bench_peek_output_of_first_direct(),
            pending_before,
            "a refused datagram must still be queued with identical metadata"
        );
        assert!(
            table.has_pending_output(now),
            "the refused datagram must stay visible to the scheduler"
        );
    }

    /// Invariant 3 (and 4): a successful acquisition consumes the datagram
    /// exactly once, and `commit` -- which has no error path at all -- is what
    /// transfers ownership.
    #[test]
    fn successful_acquisition_consumes_exactly_once() {
        let (mut table, now) = table_with_one_queued_direct_caller();
        let mut accepting = TestSink {
            capacity: 1,
            packets: Vec::new(),
        };

        let report =
            table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut accepting);
        assert_eq!(report.sink_outcome, SinkOutcome::Accepted);
        assert_eq!(
            accepting.packets.len(),
            1,
            "exactly one datagram is committed"
        );
        assert_eq!(report.packets, 1);

        let again =
            table.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut accepting);
        assert_eq!(
            again.packets, 0,
            "a consumed datagram must not be materialized a second time"
        );
        assert_eq!(accepting.packets.len(), 1);
    }

    /// Transactional-sink invariant 5: the bonded group path obeys the same
    /// reserve-then-commit ordering, with every leg's physical address.
    #[test]
    fn sink_acquisition_is_transactional_for_group_legs() {
        let mut callers = CallerTable::new();
        let group_id = srt_proto::handshake::SRTGROUP_MASK | 77;
        let first_peer: std::net::SocketAddr = "127.0.0.1:9012".parse().unwrap();
        let second_peer: std::net::SocketAddr = "127.0.0.1:9013".parse().unwrap();
        let now = Timestamp::from_micros(10_000);
        let _group = callers
            .add_group(
                group_id,
                srt_proto::GroupMode::Broadcast,
                [
                    CallerGroupLeg::new(
                        1,
                        1,
                        first_peer,
                        caller_connection(ConnectionOptions {
                            socket_id: 102,
                            initial_seq: Some(1234),
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
                            ..ConnectionOptions::default()
                        }),
                    ),
                ],
            )
            .expect("group admitted");

        // Exhausted: nothing consumed, both legs still pending.
        let mut exhausted = TestSink {
            capacity: 0,
            packets: Vec::new(),
        };
        let report =
            callers.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut exhausted);
        assert!(exhausted.packets.is_empty());
        assert_eq!(report.packets, 0);
        assert!(
            callers.has_pending_output(now),
            "group legs must stay pending when the sink is exhausted"
        );

        // Capacity 1: exactly one leg commits, and only that leg's address.
        let mut one = TestSink {
            capacity: 1,
            packets: Vec::new(),
        };
        let report = callers.poll_outbound_bounded_to(now, OutputDrainBudget::default(), &mut one);
        assert_eq!(one.packets.len(), 1);
        assert_eq!(report.packets, 1);
        let committed_peer = one.packets[0].0;
        assert!(
            committed_peer == first_peer || committed_peer == second_peer,
            "a committed group datagram must carry a real leg address, got {committed_peer}"
        );
    }

    /// Transactional-sink invariant 4 (explicit): an uncommitted reservation is
    /// released, and commit itself has no failure path.
    #[test]
    fn uncommitted_slot_releases_capacity_and_commit_cannot_fail() {
        let mut sink = TestSink {
            capacity: 1,
            packets: Vec::new(),
        };
        let peer: std::net::SocketAddr = "127.0.0.1:9014".parse().unwrap();
        // Acquire and drop without committing: capacity comes back.
        drop(sink.acquire(peer, 8).expect("acquire").expect("capacity"));
        assert!(sink.packets.is_empty(), "nothing is stored without commit");
        // Commit (which returns `()`) stores exactly the committed bytes.
        let mut slot = sink.acquire(peer, 8).expect("acquire").expect("capacity");
        slot.bytes_mut()[..8].copy_from_slice(b"12345678");
        slot.commit(4);
        assert_eq!(sink.packets, vec![(peer, b"1234".to_vec())]);
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
                group_extension: Some(srt_proto::handshake::GroupExtensionData {
                    group_id: srt_proto::handshake::SRTGROUP_MASK | 42,
                    group_type: srt_proto::handshake::GroupType::Broadcast,
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
    fn bonded_inputs_reject_unknown_group_type_with_bad_mode() {
        let peer = "127.0.0.1:10000".parse().expect("address");
        let mut options = AdmissionOptions::basic(0x2222, 0, true);
        options.bonded_inputs = BondedInputPolicy::Accept;
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let (mut caller, conclusion) = prepare_conclusion_with_options(
            &mut table,
            peer,
            ConnectionOptions {
                socket_id: 0x1111,
                group_extension: Some(srt_proto::handshake::GroupExtensionData {
                    group_id: srt_proto::handshake::SRTGROUP_MASK | 42,
                    group_type: srt_proto::handshake::GroupType::Unknown(3),
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
        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(2), &mut outbound);
        let (_, rejection) = outbound
            .into_iter()
            .find(|(address, _)| *address == peer)
            .expect("listener emits rejection");
        let error = caller
            .feed_recv_buf(&rejection, Timestamp::from_micros(3))
            .expect_err("caller observes rejection");
        assert!(error.reason.contains("reason=1405"));
    }

    #[test]
    #[expect(clippy::cognitive_complexity)]
    fn opted_in_bonded_inputs_share_one_logical_event_stream_and_telemetry() {
        let first = "127.0.0.1:10000".parse().expect("address");
        let second = "127.0.0.1:10001".parse().expect("address");
        let mut options = AdmissionOptions::basic(0x2222, 0, true);
        options.bonded_inputs = BondedInputPolicy::Accept;
        let telemetry = IngressTelemetry::new();
        let mut table = PeerTable::new();
        let group_id = srt_proto::handshake::SRTGROUP_MASK | 42;
        let caller_options = |socket_id, weight| ConnectionOptions {
            socket_id,
            initial_seq: Some(1234),
            stream_id: Some("publish:bonded".to_string()),
            group_extension: Some(srt_proto::handshake::GroupExtensionData {
                group_id,
                group_type: srt_proto::handshake::GroupType::Broadcast,
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
                    srt_proto::wire::SrtPacket::decode(packet),
                    Ok(srt_proto::wire::SrtPacket::Data(_))
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

        // DATA is held by the negotiated 120ms TSBPD latency. Drive the
        // peer timers past that deadline before observing logical delivery;
        // a fixed timestamp near receipt only happened to pass before TSBPD
        // capability negotiation was made symmetric.
        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(125_000), &mut outbound);
        table.poll_events(&mut events);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].representative_peer, first);
        assert!(matches!(
            &events[0].event,
            ConnectionEvent::DataReceived { payload, .. } if payload.as_ref() == b"one logical payload"
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
                .filter(|(_, packet)| matches!(srt_proto::wire::SrtPacket::decode(packet), Ok(srt_proto::wire::SrtPacket::Control(control)) if control.control_type == srt_proto::wire::ControlType::Shutdown))
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
        let group_id = srt_proto::handshake::SRTGROUP_MASK | 42;
        let caller_options = |socket_id, group_type| ConnectionOptions {
            socket_id,
            stream_id: Some("publish:bonded".to_string()),
            group_extension: Some(srt_proto::handshake::GroupExtensionData {
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
            caller_options(0x1111, srt_proto::handshake::GroupType::Broadcast),
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
            caller_options(0x2222, srt_proto::handshake::GroupType::Backup),
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
            srt_proto::GroupMode::Broadcast
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
            srt_proto::wire::SrtPacket::decode(packet),
            Ok(srt_proto::wire::SrtPacket::Data(_))
        )));
        assert!(outbound.iter().any(|(_, packet)| matches!(
            srt_proto::wire::SrtPacket::decode(packet),
            Ok(srt_proto::wire::SrtPacket::Control(control))
                if control.control_type == srt_proto::wire::ControlType::Shutdown
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
    fn caller_table_capacity_rejects_an_extra_logical_session() {
        let mut callers = CallerTable::with_max_callers(1);
        let peer = "127.0.0.1:11000".parse().expect("address");
        callers
            .add_direct(CallerLeg::new(
                peer,
                caller_connection(ConnectionOptions {
                    socket_id: 101,
                    ..ConnectionOptions::default()
                }),
            ))
            .expect("first caller is admitted");
        let error = callers
            .add_direct(CallerLeg::new(
                peer,
                caller_connection(ConnectionOptions {
                    socket_id: 102,
                    ..ConnectionOptions::default()
                }),
            ))
            .expect_err("the configured caller cap must reject the second session");
        assert!(error.to_string().contains("capacity"));
    }

    #[test]
    fn caller_table_clamps_adversarial_capacity() {
        let callers = CallerTable::with_max_callers(usize::MAX);
        assert_eq!(callers.max_callers(), MAX_CALLERS);
    }

    #[test]
    #[expect(clippy::cognitive_complexity)]
    fn caller_table_has_one_logical_api_for_direct_and_broadcast_callers() {
        let direct_peer = "127.0.0.1:11000".parse().expect("address");
        let first_peer = "127.0.0.1:11001".parse().expect("address");
        let second_peer = first_peer;
        let group_id = srt_proto::handshake::SRTGROUP_MASK | 55;
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
                srt_proto::GroupMode::Broadcast,
                [
                    CallerGroupLeg::new(
                        1,
                        1,
                        first_peer,
                        caller_connection(ConnectionOptions {
                            socket_id: 102,
                            initial_seq: Some(1234),
                            group_extension: Some(srt_proto::handshake::GroupExtensionData {
                                group_id,
                                group_type: srt_proto::handshake::GroupType::Broadcast,
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
                            group_extension: Some(srt_proto::handshake::GroupExtensionData {
                                group_id,
                                group_type: srt_proto::handshake::GroupType::Broadcast,
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
                    srt_proto::wire::SrtPacket::decode(packet),
                    Ok(srt_proto::wire::SrtPacket::Data(_))
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
            listeners.all_group_streams_have_deadlines(),
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
    #[allow(clippy::cognitive_complexity)]
    fn bonded_group_drain_never_exceeds_declared_action_packet_or_byte_budget() {
        let mut callers = CallerTable::default();
        let group_id = 999 | srt_proto::handshake::SRTGROUP_MASK;
        let first_peer: std::net::SocketAddr = "127.0.0.1:31001".parse().unwrap();
        let second_peer: std::net::SocketAddr = "127.0.0.1:31002".parse().unwrap();

        let grouped = callers
            .add_group(
                group_id,
                srt_proto::GroupMode::Broadcast,
                [
                    CallerGroupLeg::new(
                        1,
                        1,
                        first_peer,
                        caller_connection(ConnectionOptions {
                            socket_id: 202,
                            initial_seq: Some(1000),
                            group_extension: Some(srt_proto::handshake::GroupExtensionData {
                                group_id,
                                group_type: srt_proto::handshake::GroupType::Broadcast,
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
                            socket_id: 203,
                            initial_seq: Some(1000),
                            group_extension: Some(srt_proto::handshake::GroupExtensionData {
                                group_id,
                                group_type: srt_proto::handshake::GroupType::Broadcast,
                                flags: 0,
                                weight: 1,
                            }),
                            ..ConnectionOptions::default()
                        }),
                    ),
                ],
            )
            .expect("grouped caller admitted");

        let mut listeners = PeerTable::new();
        let mut options = AdmissionOptions::basic(999, 0, true);
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

        // Send 5 broadcast messages (each produces 2 physical packets, total 10 packets)
        for i in 0..5 {
            let _ = callers.logical_caller_mut(&grouped).unwrap().send(
                format!("broadcast payload {i}").as_bytes(),
                Timestamp::from_micros(100),
            );
        }

        let now = Timestamp::from_micros(100);

        // 1. Drain with max_packets = 1
        let mut out = Vec::new();
        let report =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(10, 1, 100_000), &mut out);
        assert_eq!(report.packets, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);

        // 2. Drain with max_actions = 1
        let report =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(1, 10, 100_000), &mut out);
        assert_eq!(report.actions, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);

        // 3. Drain with max_bytes = 0 (zero means zero work, never unlimited)
        let report =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(10, 10, 0), &mut out);
        assert_eq!(report.bytes, 0);
        assert_eq!(out.len(), 0);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);

        // 4. Drain with max_bytes = wire_len - 1 = 34B (smaller than 1 packet of 35B)
        let report =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(10, 10, 34), &mut out);
        assert_eq!(report.bytes, 0);
        assert_eq!(out.len(), 0);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);

        // 5. Drain with max_bytes = wire_len = 35B (fits exactly 1 packet)
        let report =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(10, 10, 35), &mut out);
        assert_eq!(report.bytes, 35);
        assert_eq!(out.len(), 1);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);

        // 6. Drain with max_bytes = 50: fits 1 packet (35B), second (35+35=70) is blocked
        let report =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(10, 10, 50), &mut out);
        assert_eq!(report.bytes, 35);
        assert_eq!(out.len(), 1);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn direct_caller_drain_never_exceeds_declared_action_packet_or_byte_budget() {
        let mut callers = CallerTable::default();
        let peer: std::net::SocketAddr = "127.0.0.1:31010".parse().unwrap();
        let id = callers
            .add_direct(CallerLeg::new(
                peer,
                caller_connection(ConnectionOptions {
                    socket_id: 301,
                    initial_seq: Some(1000),
                    ..ConnectionOptions::default()
                }),
            ))
            .expect("direct caller admitted");

        let mut listeners = PeerTable::new();
        let options = AdmissionOptions::basic(999, 0, true);
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

        // Send 5 messages (each produces 1 packet of 35 bytes: "direct payload {i}")
        for i in 0..5 {
            let _ = callers.logical_caller_mut(&id).unwrap().send(
                format!("direct payload {i}").as_bytes(),
                Timestamp::from_micros(100),
            );
        }

        let now = Timestamp::from_micros(100);
        let mut out = Vec::new();

        // 1. max_bytes = 0: drains 0 bytes, 0 packets, BudgetExhausted
        let report =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(10, 10, 0), &mut out);
        assert_eq!(report.bytes, 0);
        assert_eq!(out.len(), 0);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);

        // 2. max_bytes = wire_len - 1 = 30B (smaller than 31B payload)
        // Let's check actual wire_len of direct packet
        let report_sample =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(1, 1, 100_000), &mut out);
        let wire_len = report_sample.bytes;
        assert!(wire_len > 0);

        // Drain with max_bytes = wire_len - 1
        let report = callers.poll_outbound_bounded(
            now,
            OutputDrainBudget::new(10, 10, wire_len - 1),
            &mut out,
        );
        assert_eq!(report.bytes, 0);
        assert_eq!(out.len(), 0);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);

        // Drain with max_bytes = wire_len
        let report =
            callers.poll_outbound_bounded(now, OutputDrainBudget::new(10, 10, wire_len), &mut out);
        assert_eq!(report.bytes, wire_len);
        assert_eq!(out.len(), 1);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);

        // Drain with max_bytes = wire_len + wire_len / 2 (second packet cannot fit)
        let report = callers.poll_outbound_bounded(
            now,
            OutputDrainBudget::new(10, 10, wire_len + wire_len / 2),
            &mut out,
        );
        assert_eq!(report.bytes, wire_len);
        assert_eq!(out.len(), 1);
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
    }
    /// A05: `CallerTable::poll_events` must surface a direct caller's
    /// `Connected`, `DataReceived`, and `Disconnected` transitions -- the
    /// gap this crate had left open since A03 first noted "CallerTable has
    /// no poll_events anywhere," now closed because the Tokio facade's
    /// receive-message method genuinely needs it.
    #[test]
    fn poll_events_surfaces_a_direct_callers_full_lifecycle() {
        let peer = "127.0.0.1:11020".parse().expect("address");
        let options = AdmissionOptions::basic(0x1234, 0, false);
        let telemetry = IngressTelemetry::new();
        let mut callers = CallerTable::new();
        let id = callers
            .add_direct(CallerLeg::new(
                peer,
                caller_connection(ConnectionOptions {
                    socket_id: 55,
                    tsbpd_delay: 0,
                    ..ConnectionOptions::default()
                }),
            ))
            .expect("direct caller is admitted");

        let mut listeners = PeerTable::new();
        let mut micros: u64 = 0;
        fn pump(
            callers: &mut CallerTable,
            listeners: &mut PeerTable,
            options: &AdmissionOptions,
            telemetry: &IngressTelemetry,
            micros: &mut u64,
            rounds: u32,
        ) {
            for _ in 0..rounds {
                *micros += 10;
                pump_caller_table(
                    callers,
                    listeners,
                    options,
                    telemetry,
                    Timestamp::from_micros(*micros),
                );
            }
        }
        pump(
            &mut callers,
            &mut listeners,
            &options,
            &telemetry,
            &mut micros,
            8,
        );

        let mut events = Vec::new();
        callers.poll_events(&mut events);
        assert!(
            events.iter().any(|event| event.id == id
                && matches!(event.event, srt_proto::ConnectionEvent::Connected)),
            "a direct caller's Connected transition must be observable, got {events:?}"
        );

        micros += 10;
        callers
            .logical_caller_mut(&id)
            .expect("caller exists")
            .send(b"outbound", Timestamp::from_micros(micros))
            .expect("send");
        pump(
            &mut callers,
            &mut listeners,
            &options,
            &telemetry,
            &mut micros,
            8,
        );

        // The fake listener in `pump_caller_table` never sends anything
        // back, so drive a real reply from it directly to prove
        // DataReceived actually reaches the caller side, not just what the
        // caller itself sent. Capture the listener's own view of this
        // peer's identity via its own poll_events, since a PhysicalPeerKey
        // doesn't directly give a LogicalPeerId.
        let mut listener_events = Vec::new();
        listeners.poll_events(&mut listener_events);
        let listener_peer_id = listener_events
            .iter()
            .find(|event| event.representative_peer == peer)
            .map(|event| event.logical_peer)
            .expect("listener observed this peer's admission");
        micros += 10;
        listeners
            .logical_peer_mut(&listener_peer_id)
            .expect("logical peer exists")
            .send(b"inbound", Timestamp::from_micros(micros))
            .expect("listener sends");
        pump(
            &mut callers,
            &mut listeners,
            &options,
            &telemetry,
            &mut micros,
            8,
        );

        let mut events = Vec::new();
        callers.poll_events(&mut events);
        assert!(
            events.iter().any(|event| event.id == id
                && matches!(
                    &event.event,
                    srt_proto::ConnectionEvent::DataReceived { payload, .. }
                        if payload.as_ref() == b"inbound"
                )),
            "a direct caller's received payload must be observable via poll_events, got {events:?}"
        );

        micros += 10;
        callers
            .logical_caller_mut(&id)
            .expect("caller exists")
            .disconnect(Timestamp::from_micros(micros));
        pump(
            &mut callers,
            &mut listeners,
            &options,
            &telemetry,
            &mut micros,
            8,
        );
        let mut events = Vec::new();
        callers.poll_events(&mut events);
        assert!(
            events.iter().any(|event| event.id == id
                && matches!(
                    event.event,
                    srt_proto::ConnectionEvent::StateChanged(srt_proto::ConnectionState::Closing)
                )),
            "a direct caller's close starting must be observable via poll_events, got {events:?}"
        );
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

        // As above, receiver delivery occurs on the periodic ACK timer after
        // the negotiated TSBPD delay, not at DATA receipt time.
        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(125_000), &mut outbound);
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
            let group_id = srt_proto::handshake::SRTGROUP_MASK | group_suffix;
            let caller_options = |socket_id| ConnectionOptions {
                socket_id,
                initial_seq: Some(initial_seq),
                stream_id: Some("publish:property-group".to_string()),
                group_extension: Some(srt_proto::handshake::GroupExtensionData {
                    group_id,
                    group_type: srt_proto::handshake::GroupType::Broadcast,
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
        let mut truncated = vec![false; 2];
        let error = recvmsg_batch(-1, &mut bufs, &mut sizes, &mut addrs, &mut truncated)
            .expect_err("mismatched slices must be rejected before the syscall");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

        let mut sizes = vec![0; 2];
        let mut addrs = vec![None; 1];
        let error = recvmsg_batch(-1, &mut bufs, &mut sizes, &mut addrs, &mut truncated)
            .expect_err("mismatched address slice must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn recvmsg_batch_accepts_an_empty_batch_without_touching_the_fd() {
        assert_eq!(
            recvmsg_batch(-1, &mut [], &mut [], &mut [], &mut []).expect("empty batch is a no-op"),
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
        assert_eq!(caller.state(), srt_proto::ConnectionState::Disconnected);
        assert_eq!(listener.state(), srt_proto::ConnectionState::Listening);
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
            let mut truncated = vec![false; count];
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut received = 0usize;
            while received < count && Instant::now() < deadline {
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
        // `admit` now bounds its own half-open pruning to one entry per
        // call (finding 3/10, keeping packet admission itself bounded
        // rather than turning one receive into a table-wide sweep) --
        // both peers[0] and peers[1] are overdue at this point, so this
        // first admit only retires one of them.
        assert_eq!(table.len(), 2);
        assert_eq!(telemetry.expired_half_open.load(Ordering::Relaxed), 1);

        // A second admission call's own bounded prune drains the
        // remaining overdue half-open entry.
        let peer_four = "127.0.0.1:10003".parse().expect("address");
        let _ = table.admit(
            peer_four,
            &induction(4),
            Timestamp::from_micros(102),
            &options,
            0,
            1,
            &telemetry,
        );
        assert_eq!(table.len(), 2);
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
            srt_proto::ConnectionState::Connected
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
            srt_proto::ConnectionState::Connected
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
                        ListenerEncryptionConfig::new(
                            passphrase,
                            srt_proto::crypto::KeyLength::Aes128,
                        )
                        .expect("valid listener secret"),
                    )),
                    ..Default::default()
                })
            },
        );
        assert_eq!(result, Admit::Fed);
        assert_eq!(
            table.get(&peer).expect("listener peer").conn.state(),
            srt_proto::ConnectionState::Connected
        );

        let mut outbound = Vec::new();
        table.poll_outbound(Timestamp::from_micros(2), &mut outbound);
        for (_, packet) in outbound {
            caller
                .feed_recv_buf(&packet, Timestamp::from_micros(3))
                .expect("caller accepts KM response");
        }
        assert_eq!(caller.state(), srt_proto::ConnectionState::Connected);
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
                            srt_proto::crypto::KeyLength::Aes128,
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
            srt_proto::ConnectionState::Connected
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
            srt_proto::ConnectionState::Disconnected
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
        assert_eq!(error.kind, srt_proto::ErrorKind::HandshakeRejected);
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
        let due: Vec<_> = store
            .due_timers(Timestamp::from_micros(10_000))
            .into_iter()
            .collect();
        assert_eq!(due, vec![TimerId::Ack]);
        assert!(store.due_timers(Timestamp::from_micros(10_000)).is_empty());

        // Nak still pending.
        let due: Vec<_> = store
            .due_timers(Timestamp::from_micros(50_000))
            .into_iter()
            .collect();
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
        let due: Vec<_> = store
            .due_timers(Timestamp::from_micros(5_000))
            .into_iter()
            .collect();
        assert_eq!(due, vec![TimerId::Keepalive]);
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

    // -----------------------------------------------------------------
    // CallerTable ready / deadline scheduling invariants (exact BTreeSet)
    // -----------------------------------------------------------------

    fn new_connected_caller_connection(socket_id: u32) -> SrtConnection {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: socket_id.wrapping_add(100_000).max(1),
            ..ConnectionOptions::default()
        });
        caller.connect(Timestamp::default()).expect("connect");
        for i in 0..10 {
            let now = Timestamp::from_micros(i * 10_000);
            while let Some(output) = caller
                .poll_output()
                .expect("exact-size output materializes")
            {
                if let ConnectionOutput::SendPacket(data) = output {
                    let _ = listener.feed_recv_buf(&data, now);
                }
            }
            while let Some(output) = listener
                .poll_output()
                .expect("exact-size output materializes")
            {
                if let ConnectionOutput::SendPacket(data) = output {
                    let _ = caller.feed_recv_buf(&data, now);
                }
            }
            if caller.state() == srt_proto::ConnectionState::Connected {
                break;
            }
        }
        assert_eq!(caller.state(), srt_proto::ConnectionState::Connected);
        caller
    }

    fn mk_table(n: usize) -> CallerTable {
        let mut t = CallerTable::new();
        for i in 0..n {
            let peer = std::net::SocketAddr::from((
                [10, 0, (i / 256) as u8, (i % 256) as u8],
                4000 + (i % 1000) as u16,
            ));
            let conn = new_connected_caller_connection(1000 + i as u32);
            t.add_direct(CallerLeg {
                peer,
                connection: conn,
            })
            .unwrap();
        }
        let mut out = Vec::new();
        t.poll_outbound(Timestamp::default(), &mut out);
        t.reset_sched_counters();
        t
    }

    #[test]
    fn caller_ready_deduplication() {
        let mut table = mk_table(4);
        let id = table.bench_ids()[0];
        // Enqueue same caller 100 times via bench_make_ready
        for _ in 0..100 {
            table.bench_make_ready(id);
        }
        assert_eq!(table.ready_queue_len(), 1);

        // Poll should consume exactly one ready visit
        let mut out = Vec::new();
        let budget = crate::OutputDrainBudget::new(64, 32, 256 * 1024);
        table.poll_outbound_bounded(Timestamp::default(), budget, &mut out);
        assert_eq!(table.ready_queue_len(), 0);
    }

    #[test]
    fn caller_feed_error_drains_cleanup_and_cleans_deadline_index() {
        let mut table = CallerTable::new();
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 9000));
        let socket_id = 4242;
        let mut conn = SrtConnection::new_caller(ConnectionOptions {
            socket_id,
            ..ConnectionOptions::default()
        });
        conn.connect(Timestamp::default()).expect("start caller");
        let _id = table
            .add_direct(CallerLeg {
                peer,
                connection: conn,
            })
            .expect("add direct");

        // Drain the initial induction request packet and arm connection timers.
        let mut out = Vec::new();
        let budget = crate::OutputDrainBudget::new(64, 32, 256 * 1024);
        table.poll_outbound_bounded(Timestamp::default(), budget, &mut out);
        assert!(!out.is_empty(), "must have emitted induction request");

        // Handshake timer is now armed in the index.
        assert_eq!(table.deadline_count(), 1);
        let initial_deadline = table.time_until_next_deadline(Timestamp::default(), 10_000_000);
        assert!(
            initial_deadline < 10_000_000,
            "handshake timer should be armed"
        );
        // Fabricate a malformed induction response that triggers fail_caller_handshake.
        // Specifically, an induction response with invalid SRT magic (0 instead of SRT_MAGIC_CODE).
        let mut response = HandshakePacket::new_induction_response(socket_id, 9999, 0);
        response.extension_field = 0; // invalid magic
        let packet = response.encode(0, socket_id);
        let mut bytes = Vec::new();
        packet
            .encode(&mut bytes)
            .expect("packet fits configured datagram bound");

        // 1. feed() must return Err because the handshake failed.
        let feed_res = table.feed(peer, &bytes, Timestamp::from_micros(1000));
        assert!(
            feed_res.is_err(),
            "feed should return Err on invalid handshake magic"
        );

        // 2. Caller must be enqueued ready to drain its queued cleanup output (ClearTimer).
        assert_eq!(
            table.ready_queue_len(),
            1,
            "caller must be ready to drain cleanup"
        );

        // 3. Drain the table.
        let mut cleanup_out = Vec::new();
        table.poll_outbound_bounded(Timestamp::from_micros(1000), budget, &mut cleanup_out);

        // 4. Stale handshake deadline state must not remain in the index.
        assert_eq!(
            table.deadline_count(),
            0,
            "handshake deadline must be cleared from index"
        );
        assert_eq!(
            table.time_until_next_deadline(Timestamp::from_micros(1000), 5_000_000),
            5_000_000,
            "no live deadline should remain"
        );
    }

    #[test]
    fn caller_one_ready_among_many_visits_sparse() {
        for n in [30, 200, 1000] {
            let mut table = mk_table(n);
            let ids = table.bench_ids();
            let target = ids[0];
            let now = Timestamp::default();
            let send_res = table
                .logical_caller_mut(&target)
                .unwrap()
                .send(b"hello", now);
            assert!(
                send_res.is_ok(),
                "send must succeed on Connected caller: {:?}",
                send_res
            );
            table.reset_sched_counters();
            let mut out = Vec::new();
            let budget = crate::OutputDrainBudget::new(64, 32, 256 * 1024);
            table.poll_outbound_bounded(Timestamp::default(), budget, &mut out);
            let c = table.sched_counters();
            assert!(
                c.ready_drain_probes <= 2,
                "n={n} one_ready should visit ~1 ready caller (at most 2 probes: drained + empty), got {}",
                c.ready_drain_probes
            );
            assert_eq!(
                c.due_callers_visited, 0,
                "n={n} one_ready should have 0 due caller visits"
            );
        }
    }

    #[test]
    fn caller_one_due_among_many_visits_sparse() {
        for n in [30, 200, 1000] {
            let mut table = mk_table(n);
            let ids = table.bench_ids();
            let target = ids[0];
            // Clear all deadlines to known idle, then inject exactly one due deadline
            for id in ids.clone() {
                table.bench_clear_deadline(id);
            }
            let now = Timestamp::from_micros(5_000_000);
            table.bench_arm_timer(
                target,
                srt_proto::TimerId::Ack,
                5_000_000,
                Timestamp::from_micros(0),
            );
            table.reset_sched_counters();
            let mut out = Vec::new();
            let budget = crate::OutputDrainBudget::new(64, 32, 256 * 1024);
            table.poll_outbound_bounded(now, budget, &mut out);
            let c = table.sched_counters();
            assert_eq!(
                c.due_callers_visited, 1,
                "n={n} due_callers_visited should be 1, got {}",
                c.due_callers_visited
            );
        }
    }

    /// P02: hundreds of simultaneously due sessions must not all get their
    /// timers fired in one visit -- before this fix, `pop_due_ids` popped
    /// every session whose deadline had passed with no cap at all, so
    /// `poll_outbound_bounded`'s own budget only ever applied to the
    /// ready-drain phase that ran *after* every due session's timers had
    /// already fired.
    #[test]
    fn caller_hundreds_of_simultaneous_deadlines_are_serviced_over_several_visits() {
        const N: usize = 500;
        let mut table = mk_table(N);
        let ids = table.bench_ids();
        for id in ids.clone() {
            table.bench_clear_deadline(id);
        }
        let now = Timestamp::from_micros(1_000_000);
        for &id in &ids {
            table.bench_arm_timer(
                id,
                srt_proto::TimerId::Ack,
                1_000_000,
                Timestamp::from_micros(0),
            );
        }
        table.reset_sched_counters();

        let budget = crate::OutputDrainBudget::new(32, 32, 256 * 1024);
        let mut out = Vec::new();
        let mut total_visited = 0usize;
        let mut worst_single_visit = 0usize;
        let mut calls = 0usize;
        loop {
            let before = table.sched_counters().due_callers_visited;
            let report = table.poll_outbound_bounded(now, budget, &mut out);
            calls += 1;
            let this_visit = table.sched_counters().due_callers_visited - before;
            worst_single_visit = worst_single_visit.max(this_visit);
            total_visited += this_visit;
            assert!(
                this_visit <= budget.max_actions,
                "one visit fired {this_visit} due sessions, over the budget of {}",
                budget.max_actions
            );
            if this_visit >= budget.max_actions {
                assert_eq!(
                    report.status,
                    crate::OutputDrainStatus::BudgetExhausted,
                    "a visit that fired the maximum due sessions this budget allows must \
                     report BudgetExhausted"
                );
            }
            // Firing a due session's timers can itself queue real protocol
            // output (e.g. an ACK), which the *separate* ready-drain budget
            // may not finish draining in the same visit -- so "no more due
            // sessions to pop" does not by itself mean fully drained.
            // `Drained` is the one authoritative "nothing left at all"
            // signal from this function.
            if report.status == crate::OutputDrainStatus::Drained {
                break;
            }
            assert!(
                calls < 4 * N,
                "must make real per-visit progress, not loop forever without draining the \
                 due set"
            );
        }

        assert_eq!(
            total_visited, N,
            "every one of the {N} simultaneously due sessions must eventually be serviced, \
             none skipped and none double-fired"
        );
        assert!(
            worst_single_visit <= budget.max_actions,
            "worst observed single-visit due-session count ({worst_single_visit}) must stay \
             within the {}-action budget",
            budget.max_actions
        );
        assert!(
            calls > 1,
            "{N} due sessions against a budget of {} must take more than one visit \
             (worst single visit: {worst_single_visit}, visits taken: {calls})",
            budget.max_actions
        );
    }

    /// P02: isolates `pop_due_ids`'s cap and `has_due_remaining` from the
    /// ready-drain budget (the end-to-end
    /// `caller_hundreds_of_simultaneous_deadlines_are_serviced_over_several_visits`
    /// test above cannot cleanly isolate this: every timer handler in this
    /// codebase re-arms itself with a `SetTimer` output, so firing a due
    /// session almost always produces at least one ready-drain action too,
    /// coupling the two budgets in practice). Directly checks the index
    /// itself: capped `pop_due_ids` must leave the uncapped remainder
    /// exactly where it was, still discoverable as due.
    #[test]
    fn pop_due_ids_leaves_the_remainder_in_the_deadline_index_when_capped() {
        const N: usize = 50;
        const CAP: usize = 10;
        let mut table = mk_table(N);
        let ids = table.bench_ids();
        for id in ids.clone() {
            table.bench_clear_deadline(id);
        }
        let now = Timestamp::from_micros(1_000_000);
        for &id in &ids {
            table.bench_arm_timer(
                id,
                srt_proto::TimerId::Ack,
                1_000_000,
                Timestamp::from_micros(0),
            );
        }
        assert_eq!(table.deadline_count(), N);

        let n_popped = table.pop_due_ids(now, CAP);
        assert_eq!(n_popped, CAP, "must pop exactly the cap, not fewer or more");
        let popped: Vec<_> = table.bench_due_scratch().to_vec();
        assert_eq!(
            table.deadline_count(),
            N - CAP,
            "everything past the cap must remain in the deadline index, untouched"
        );
        assert!(
            table.has_due_remaining(now),
            "the remainder is still due at the same `now` and must be reported as such"
        );

        // Draining the rest in one more call must account for every
        // session exactly once: none left behind, none popped twice.
        let n_rest = table.pop_due_ids(now, usize::MAX);
        assert_eq!(n_rest, N - CAP);
        let rest: Vec<_> = table.bench_due_scratch().to_vec();
        let mut all_popped: Vec<_> = popped.into_iter().chain(rest).collect();
        all_popped.sort();
        let mut expected = ids;
        expected.sort();
        assert_eq!(all_popped, expected);
        assert!(!table.has_due_remaining(now));
    }

    #[test]
    fn caller_earliest_deadline_matches_scan() {
        let mut table = mk_table(20);
        // Inject staggered deadlines
        let ids = table.bench_ids();
        for (i, id) in ids.iter().enumerate() {
            let dl = Timestamp::from_micros(10_000 + i as u64 * 1_000);
            table.bench_inject_deadline(*id, dl);
        }
        let now = Timestamp::from_micros(0);
        let indexed = table.time_until_next_deadline(now, 1_000_000);
        // Reference scan over injected deadlines (they are the only ones)
        let expected = 10_000; // earliest is 10_000
        assert_eq!(indexed, expected);
    }

    #[test]
    fn caller_deadline_move_earlier_and_later() {
        let mut table = mk_table(5);
        let ids = table.bench_ids();
        let target = ids[0];
        let now = Timestamp::from_micros(0);
        for id in ids.clone() {
            table.bench_clear_deadline(id);
        }
        table.bench_inject_deadline(target, Timestamp::from_micros(100_000));
        assert_eq!(table.time_until_next_deadline(now, 999_999), 100_000);
        // move earlier
        table.bench_inject_deadline(target, Timestamp::from_micros(10_000));
        assert_eq!(table.time_until_next_deadline(now, 999_999), 10_000);
        // move later
        table.bench_inject_deadline(target, Timestamp::from_micros(200_000));
        assert_eq!(table.time_until_next_deadline(now, 999_999), 200_000);
        // ensure heap size stays bounded (exact set, no stale)
        assert!(table.deadline_count() <= 20);
    }

    #[test]
    fn caller_remove_invalidates_ready_and_deadline() {
        let mut table = mk_table(10);
        let ids = table.bench_ids();
        let target = ids[0];
        table.bench_inject_deadline(target, Timestamp::from_micros(1_000));
        table.bench_push_pending(
            target,
            std::net::SocketAddr::from(([10, 0, 0, 1], 5000)),
            vec![1; 64],
        );
        let before_deadlines = table.deadline_count();
        let before_ready = table.ready_queue_len();
        assert!(before_deadlines > 0);
        assert!(before_ready > 0);
        table.remove(target);
        // Stale entries must not fire
        let now = Timestamp::from_micros(10_000);
        let mut out = Vec::new();
        let budget = crate::OutputDrainBudget::new(64, 32, 256 * 1024);
        table.poll_outbound_bounded(now, budget, &mut out);
        // No panic, and deadline for removed id is gone
        assert!(
            table.deadline_count() < before_deadlines || table.deadline_count() <= 10,
            "deadlines should shrink after remove"
        );
        // IDs never wrap (checked_add), so a new caller cannot alias a removed one.
        let peer = std::net::SocketAddr::from(([10, 0, 0, 99], 9999));
        let conn = {
            let mut c = SrtConnection::new_caller(ConnectionOptions {
                socket_id: 99999,
                ..ConnectionOptions::default()
            });
            c.connect(Timestamp::default()).unwrap();
            c
        };
        let new_id = table
            .add_direct(CallerLeg {
                peer,
                connection: conn,
            })
            .unwrap();
        assert_ne!(
            new_id, target,
            "monotonic IDs must never alias a removed caller"
        );
        let _ = table.time_until_next_deadline(now, 999_999);
    }

    /// T03: a leg's next packet can fail to fit the remaining byte
    /// allowance while every raw counter (actions/packets/bytes) is still
    /// under its cap -- one 1332-byte wire packet (1316-byte payload +
    /// 16-byte header) leaves 668 of a 2000-byte allowance, and a second
    /// identical packet cannot fit it, but `report.bytes` (1332) is still
    /// well under `max_bytes` (2000). The old status logic only checked
    /// counters against caps, so this case silently reported `Drained`
    /// while a real packet sat pushed back in `pending`, undrained.
    #[test]
    fn caller_reports_budget_exhausted_when_the_next_packet_does_not_fit() {
        let mut table = mk_table(1);
        let id = table.bench_ids()[0];
        let now = Timestamp::default();
        let payload = vec![0xABu8; 1316];
        for _ in 0..2 {
            table
                .logical_caller_mut(&id)
                .unwrap()
                .send(&payload, now)
                .expect("send succeeds");
        }

        let mut out = Vec::new();
        // Room for exactly one 1332-byte wire packet, not two.
        let budget = crate::OutputDrainBudget::new(usize::MAX, usize::MAX, 2000);
        let report = table.poll_outbound_bounded(now, budget, &mut out);

        assert_eq!(out.len(), 1, "only the packet that fits should be emitted");
        assert_eq!(report.packets, 1);
        assert_eq!(report.bytes, 1332, "sanity: this is below max_bytes (2000)");
        assert_eq!(
            report.status,
            crate::OutputDrainStatus::BudgetExhausted,
            "a packet that couldn't fit was retained, so this pass is not fully drained"
        );
        assert!(
            table.ready_queue_len() > 0,
            "the leg with retained work must stay ready for the next poll"
        );

        // The retained second packet is still there, in order, on the next poll.
        let mut out2 = Vec::new();
        let report2 = table.poll_outbound_bounded(now, budget, &mut out2);
        assert_eq!(out2.len(), 1);
        assert_eq!(report2.status, crate::OutputDrainStatus::Drained);
    }

    #[test]
    fn caller_budget_exhaustion_preserves_pending() {
        let mut table = mk_table(2);
        let ids = table.bench_ids();
        let now = Timestamp::default();
        for id in ids.clone() {
            for _ in 0..5 {
                let res = table
                    .logical_caller_mut(&id)
                    .unwrap()
                    .send(b"payload-data-test", now);
                assert!(res.is_ok(), "send must succeed: {:?}", res);
            }
        }
        // Tiny budget: should exhaust and leave work ready for next poll
        let mut out = Vec::new();
        let tiny = crate::OutputDrainBudget::new(1, 1, 1024);
        let report = table.poll_outbound_bounded(Timestamp::default(), tiny, &mut out);
        assert_eq!(report.status, crate::OutputDrainStatus::BudgetExhausted);
        assert!(
            table.ready_queue_len() > 0,
            "pending should remain ready after budget exhaustion"
        );
        // Next poll should continue delivering
        let mut out2 = Vec::new();
        let report2 = table.poll_outbound_bounded(Timestamp::default(), tiny, &mut out2);
        assert!(!out2.is_empty() || report2.packets > 0);
    }

    #[test]
    fn caller_fairness_busy_does_not_starve() {
        let mut table = mk_table(2);
        let ids = table.bench_ids();
        let a = ids[0];
        let b = ids[1];
        let now = Timestamp::default();
        for _ in 0..10 {
            let res = table.logical_caller_mut(&a).unwrap().send(b"a", now);
            assert!(res.is_ok());
        }
        let res = table.logical_caller_mut(&b).unwrap().send(b"b", now);
        assert!(res.is_ok());
        table.reset_sched_counters();
        let mut out = Vec::new();
        // Budget allows 2 actions, should interleave rather than draining all of A's 10 before B
        let budget = crate::OutputDrainBudget::new(2, 10, 10 * 1024);
        let _ = table.poll_outbound_bounded(Timestamp::default(), budget, &mut out);
        // After bounded poll with fair requeue, both callers should have been visited (b not starved)
        let c = table.sched_counters();
        assert!(
            c.ready_drain_probes >= 2,
            "fair scheduling should visit both callers, got {}",
            c.ready_drain_probes
        );
    }
    #[test]
    fn caller_churn_bounded_memory() {
        let mut table = mk_table(100);
        for iter in 0..200 {
            let ids = table.bench_ids();
            let id = ids[iter % ids.len()];
            // reschedule via deadline inject
            table.bench_inject_deadline(id, Timestamp::from_micros(1_000_000 + iter as u64 * 100));
            if iter % 10 == 0 {
                let rm = ids[0];
                table.remove(rm);
                let peer = std::net::SocketAddr::from(([10, 1, 0, (iter % 250) as u8], 5000));
                let conn = {
                    let mut c = SrtConnection::new_caller(ConnectionOptions {
                        socket_id: 50000 + iter as u32,
                        ..ConnectionOptions::default()
                    });
                    c.connect(Timestamp::default()).unwrap();
                    c
                };
                let _ = table.add_direct(CallerLeg {
                    peer,
                    connection: conn,
                });
            }
        }
        // Exact BTreeSet should keep deadlines == live callers (or fewer), no unbounded growth
        assert!(
            table.deadline_count() <= table.len() + 2,
            "deadline index grew unbounded: {} deadlines for {} callers",
            table.deadline_count(),
            table.len()
        );
    }

    // -----------------------------------------------------------------
    // Property / differential tests for the versioned due-index
    // -----------------------------------------------------------------

    /// Reference model: a simple BTreeSet that tracks the canonical
    /// (id -> deadline_micros) mapping. Used to diff against the heap index.
    use std::collections::BTreeMap;

    fn ref_earliest_due(model: &BTreeMap<LogicalCallerId, u64>, now_us: u64) -> bool {
        model.values().any(|&d| d <= now_us)
    }

    fn ref_time_until(model: &BTreeMap<LogicalCallerId, u64>, now_us: u64, default: u64) -> u64 {
        model
            .values()
            .map(|&d| d.saturating_sub(now_us))
            .min()
            .unwrap_or(default)
            .min(default)
    }

    #[test]
    fn due_index_differential_randomised() {
        // Deterministic pseudo-random trace: insert, update, remove, query.
        let n = 80usize;
        let mut table = mk_table(n);
        let ids: Vec<_> = table.bench_ids();
        // Clear all protocol-set timers so the model starts empty.
        for &id in &ids {
            table.bench_clear_deadline(id);
        }
        let mut model: BTreeMap<LogicalCallerId, u64> = BTreeMap::new();

        let mut seed: u64 = 0xdeadbeef_cafebabe;
        let lcg = |s: u64| {
            s.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407)
        };

        for step in 0u64..5_000 {
            seed = lcg(seed);
            let now_us = step * 500;
            let now = Timestamp::from_micros(now_us);

            let op = seed % 5;
            let idx = (seed >> 16) as usize % ids.len();
            let id = ids[idx];

            match op {
                0 | 1 => {
                    // set/change deadline
                    let dl_us = now_us + (seed >> 32) % 200_000 + 1;
                    table.bench_inject_deadline(id, Timestamp::from_micros(dl_us));
                    model.insert(id, dl_us);
                }
                2 => {
                    // clear deadline
                    table.bench_clear_deadline(id);
                    model.remove(&id);
                }
                3 => {
                    // set same deadline twice (idempotent)
                    let dl_us = now_us + 50_000;
                    table.bench_inject_deadline(id, Timestamp::from_micros(dl_us));
                    table.bench_inject_deadline(id, Timestamp::from_micros(dl_us));
                    model.insert(id, dl_us);
                }
                _ => {
                    // many callers same deadline (tie semantics)
                    let dl_us = now_us + 1_000;
                    for &other in ids.iter().take(4) {
                        table.bench_inject_deadline(other, Timestamp::from_micros(dl_us));
                        model.insert(other, dl_us);
                    }
                }
            }

            // Invariant 1: deadline_count == model size
            assert_eq!(
                table.deadline_count(),
                model.len(),
                "step {step}: live count mismatch"
            );

            // Invariant 2: if model says NOT due, table must also say not due.
            // (Table may report ready_queue work the model doesn't track, so
            // we only assert in the false direction.)
            let model_due = ref_earliest_due(&model, now_us);
            if !model_due {
                assert!(
                    !table.has_pending_output(now),
                    "step {step}: table reports due work but model says none"
                );
            }

            // Invariant 3: time_until_next_deadline agrees (within 1 us for ties)
            let model_us = ref_time_until(&model, now_us, 999_999);
            let table_us = table.time_until_next_deadline(now, 999_999);
            assert_eq!(
                table_us, model_us,
                "step {step}: time_until mismatch: table={table_us} model={model_us}"
            );
        }
    }

    #[test]
    fn due_index_remove_then_readd_never_revived_by_stale() {
        // Remove a caller, re-add it, verify the removed heap node cannot
        // fire the new caller's deadline falsely. The indexed heap removes
        // the node exactly at remove() time, so no stale residue exists.
        let mut table = CallerTable::new();
        let peer = std::net::SocketAddr::from(([10, 0, 0, 1], 5000));
        let make_conn = |sid: u32| {
            let mut c = SrtConnection::new_caller(ConnectionOptions {
                socket_id: sid,
                ..ConnectionOptions::default()
            });
            c.connect(Timestamp::default()).unwrap();
            c
        };
        let id1 = table
            .add_direct(CallerLeg {
                peer,
                connection: make_conn(1001),
            })
            .unwrap();
        // Flush the initial ready/deadline state so the table is quiescent.
        let mut out = Vec::new();
        table.poll_outbound(Timestamp::default(), &mut out);
        table.bench_inject_deadline(id1, Timestamp::from_micros(1_000));
        assert_eq!(table.deadline_count(), 1);

        // Remove: heap node removed exactly, live drops to 0.
        table.remove(id1);
        assert_eq!(table.deadline_count(), 0);
        // After draining any residual ready work, no output should remain.
        let now = Timestamp::from_micros(2_000);
        table.poll_outbound(now, &mut out);
        assert!(
            !table.has_pending_output(now),
            "removed caller must not appear due"
        );

        // Add a new caller — gets a fresh monotonic id.
        let id2 = table
            .add_direct(CallerLeg {
                peer,
                connection: make_conn(1002),
            })
            .unwrap();
        assert_ne!(id1, id2, "ids must be monotonically distinct");
        // Flush id2's initial ready state, then clear its deadline.
        table.poll_outbound(now, &mut out);
        table.bench_clear_deadline(id2);
        assert_eq!(table.deadline_count(), 0);
        // No stale entry from id1 must show up as id2's deadline.
        assert!(
            !table.has_pending_output(Timestamp::from_micros(1_000)),
            "stale heap entry from removed id1 must not revive as id2 due"
        );
    }

    #[test]
    fn due_index_exact_one_node_per_caller_no_stale() {
        // Arm + re-arm the same caller 1000 times; the indexed heap must
        // hold exactly one node for it: updates are in-place key changes,
        // never stale duplicates. No rebuild machinery exists.
        let n = 1usize; // single caller: no protocol noise from others
        let mut table = mk_table(n);
        let ids = table.bench_ids();
        let id = ids[0];
        // Clear all existing deadlines so we start from a clean heap.
        table.bench_clear_deadline(id);
        let mut out = Vec::new();
        table.poll_outbound(Timestamp::default(), &mut out);

        for k in 0u64..1_000 {
            table.bench_inject_deadline(id, Timestamp::from_micros(k * 100 + 50));
        }
        let snap = table.due_index_snapshot();
        // After 1000 updates of one caller, exactly one node exists.
        assert_eq!(snap.live, 1, "only one node for one caller");
        assert_eq!(
            snap.physical, 1,
            "indexed heap has no stale entries: physical must equal live"
        );
    }

    /// One recorded scheduler op: (step, caller id, op kind, deadline arg).
    type InvariantOp = (u64, LogicalCallerId, u8, u64);

    fn invariant_trace_table() -> (CallerTable, Vec<LogicalCallerId>, Vec<InvariantOp>) {
        // Deterministic 2000-op trace shared by the three invariant tests.
        let n = 30usize;
        let mut table = mk_table(n);
        let ids: Vec<_> = table.bench_ids();
        for &id in &ids {
            table.bench_clear_deadline(id);
        }
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        let lcg = |s: u64| {
            s.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407)
        };
        let mut ops = Vec::with_capacity(2_000);
        for step in 0u64..2_000 {
            seed = lcg(seed);
            let id = ids[(seed >> 16) as usize % ids.len()];
            let op = (seed % 3) as u8;
            let arg = step * 500 + (seed >> 32) % 100_000 + 1;
            ops.push((step, id, op, arg));
        }
        (table, ids, ops)
    }

    fn apply_invariant_op(
        table: &mut CallerTable,
        step: u64,
        id: LogicalCallerId,
        op: u8,
        arg: u64,
    ) {
        match op {
            0 => {
                table.bench_inject_deadline(id, Timestamp::from_micros(arg));
            }
            1 => table.bench_clear_deadline(id),
            _ => {
                table.remove(id);
                let peer = std::net::SocketAddr::from(([10, 9, 9, 9], 5000));
                let mut c = SrtConnection::new_caller(ConnectionOptions {
                    socket_id: 90000 + (step % 1000) as u32,
                    ..ConnectionOptions::default()
                });
                c.connect(Timestamp::default()).unwrap();
                let _ = table.add_direct(CallerLeg {
                    peer,
                    connection: c,
                });
            }
        }
    }

    fn assert_heap_len_matches_sched(table: &CallerTable, step: u64) {
        let live_sched = table
            .sched
            .values()
            .filter(|e| e.deadline_micros.is_some())
            .count();
        assert_eq!(
            table.deadlines.heap.len(),
            live_sched,
            "step {step}: heap length must equal live sched count"
        );
    }

    fn assert_heap_pos_round_trip(table: &CallerTable, step: u64) {
        for (sid, entry) in table.sched.iter() {
            if let Some(pos) = entry.heap_pos {
                let node = &table.deadlines.heap[pos as usize];
                assert_eq!(node.id, *sid, "step {step}: heap_pos must name own node");
                assert_eq!(
                    Some(node.deadline_micros),
                    entry.deadline_micros,
                    "step {step}: node key must match sched deadline"
                );
            } else {
                assert!(
                    entry.deadline_micros.is_none(),
                    "step {step}: no heap_pos implies no deadline"
                );
            }
        }
    }

    fn assert_min_heap_property(table: &CallerTable, step: u64) {
        for (i, node) in table.deadlines.heap.iter().enumerate() {
            let left = i * 2 + 1;
            let right = left + 1;
            if left < table.deadlines.heap.len() {
                assert!(
                    *node <= table.deadlines.heap[left],
                    "step {step}: heap property violated at {i}"
                );
            }
            if right < table.deadlines.heap.len() {
                assert!(
                    *node <= table.deadlines.heap[right],
                    "step {step}: heap property violated at {i}"
                );
            }
        }
    }

    #[test]
    fn due_index_heap_len_matches_sched_count() {
        let (mut table, _ids, ops) = invariant_trace_table();
        for (step, id, op, arg) in ops {
            apply_invariant_op(&mut table, step, id, op, arg);
            assert_heap_len_matches_sched(&table, step);
        }
    }

    #[test]
    fn due_index_heap_pos_round_trips() {
        let (mut table, _ids, ops) = invariant_trace_table();
        for (step, id, op, arg) in ops {
            apply_invariant_op(&mut table, step, id, op, arg);
            assert_heap_pos_round_trip(&table, step);
        }
    }

    #[test]
    fn due_index_min_heap_property_holds() {
        let (mut table, _ids, ops) = invariant_trace_table();
        for (step, id, op, arg) in ops {
            apply_invariant_op(&mut table, step, id, op, arg);
            assert_min_heap_property(&table, step);
        }
    }
}
