use crate::{
    GroupConnectionStats, GroupLogicalCounters, ManualTimerStore, OutputDrainBudget,
    OutputDrainReport, OutputDrainStatus, group_connection_stats,
};
use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
use std::collections::{HashMap, HashSet, VecDeque};

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

pub(crate) fn prepend_outputs(
    pending: &mut VecDeque<ConnectionOutput>,
    outputs: impl DoubleEndedIterator<Item = ConnectionOutput>,
) {
    for output in outputs.rev() {
        pending.push_front(output);
    }
}

pub(crate) fn collect_output_work(
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
    use crate::*;
    use proptest::prelude::*;
    use shiguredo_srt::{
        ConnectionEvent, ConnectionOptions, ConnectionOutput, ErrorKind, HandshakePacket,
        SrtConnection, SrtPacket, TimerId, Timestamp,
    };
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

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
                group_extension: Some(shiguredo_srt::GroupExtensionData {
                    group_id: shiguredo_srt::SRTGROUP_MASK | 42,
                    group_type: shiguredo_srt::GroupType::Unknown(3),
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
    #[expect(clippy::cognitive_complexity)]
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
}
