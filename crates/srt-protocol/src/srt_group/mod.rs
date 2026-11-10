mod retirement;
mod send;
pub use retirement::GroupRetirement;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bytes::Bytes;

use crate::error::Error;
use crate::srt_connection::{
    ConnectionEvent, ConnectionState, GroupTime, MAX_DELIVERY_PER_VISIT, SrtConnection,
};
use crate::srt_handshake::{GroupType, SRTGROUP_MASK};
use crate::srt_packet::sequence_less_than;
use crate::time::Timestamp;

/// Hard implementation bound for one bonded group. Every group-wide scan and
/// retained per-member queue is therefore finite even for adversarial input.
pub const MAX_GROUP_MEMBERS: usize = 64;

/// How an [`SrtGroup`] distributes payload across its members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMode {
    /// Send every payload on every active member.
    Broadcast,
    /// Send each payload on one active member at a time, promoting a standby
    /// member if it fails.
    Backup,
}

impl GroupMode {
    /// Map a handshake [`GroupType`] to a `GroupMode`, or `None` if the wire
    /// type doesn't correspond to a mode this crate implements.
    pub fn from_group_type(group_type: GroupType) -> Option<Self> {
        match group_type {
            GroupType::Broadcast => Some(Self::Broadcast),
            GroupType::Backup => Some(Self::Backup),
            GroupType::Undefined | GroupType::Unknown(_) => None,
        }
    }
}

/// A group member's lifecycle state within its [`SrtGroup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMemberState {
    /// Added to the group but not yet handshake-connected.
    Pending,
    /// Connected and currently eligible to carry payload.
    Active,
    /// Connected but held in reserve (Backup mode only), promoted to
    /// [`Self::Active`] if the active member fails.
    Standby,
    /// Temporarily excluded after a send-buffer backpressure event. A
    /// connected leg is requalified once its in-flight packets drain and its
    /// send sequence can be aligned with the group again.
    Unstable,
    /// Disconnected or failed; permanently excluded from the group.
    Broken,
}

/// One deduplicated payload delivered by [`SrtGroup::poll_data`], tagged with
/// the member and sequence it arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPacket {
    /// The member the payload was received on. Origin metadata only: the
    /// payload stays deliverable after that member is removed.
    pub member_id: u32,
    /// The group-logical sequence number.
    pub sequence_number: u32,
    /// The message number, for reassembling multi-packet messages.
    pub message_number: u32,
    /// The sender's timestamp, in the units defined by the SRT wire format.
    pub timestamp: u32,
    /// F01: when the sender originally queued this message, converted into
    /// this member connection's local clock domain -- see
    /// `ConnectionEvent::DataReceived`'s field of the same name.
    pub source_time: crate::Timestamp,
    /// Number of SRT DATA packets represented by the reassembled payload.
    pub packet_count: u32,
    /// One complete message, preserving its packet chunks without flattening.
    pub payload: crate::ReceivedPayload,
}

/// Result of one bounded logical-data poll.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GroupDataPoll {
    /// The next deduplicated payload, if one was available within the visit.
    pub packet: Option<GroupPacket>,
    /// The visit reached its lifecycle-event limit. Call the bounded method
    /// again immediately before waiting for new socket input.
    pub continuation: bool,
}

/// One physical-leg event observed while driving an SRT group.
///
/// Applications normally consume [`SrtGroup::poll_data`] for the logical,
/// deduplicated stream. Transport adapters use this lower-level view to map
/// member lifecycle onto one logical connection lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupEvent {
    /// A member completed its handshake and became connected.
    MemberConnected {
        /// The member that connected.
        member_id: u32,
    },
    /// A deduplicated, in-order payload is ready for the application.
    DataReceived(GroupPacket),
    /// A member's connection reported a protocol error and was marked
    /// [`GroupMemberState::Broken`].
    MemberError {
        /// The member that errored.
        member_id: u32,
        /// The error, as reported by the member's [`SrtConnection`].
        error: String,
    },
    /// A member disconnected and was marked [`GroupMemberState::Broken`].
    MemberDisconnected {
        /// The member that disconnected.
        member_id: u32,
        /// Why the member disconnected.
        reason: String,
    },
}

/// A caller-side group leg whose handshake response carried a different
/// *receiving group* identity than the group is bound to.
///
/// A bonded group has exactly one remote receiving group: the first member
/// whose response carries a GROUP extension binds the group to that
/// extension's group ID (the responder's mirror-group ID), and every later
/// member must report the same ID. This is libsrt's own rule (`CUDT::
/// interpretGroup`, `SRT_REJ_GROUP`: "group membership responded for peer
/// $X but the current socket's group has already a peer $Y"). It is a
/// property of the handshake, never of the destination address: several
/// addresses can belong to one receiver, and one address never proves it.
///
/// This is a configuration fault, distinct from a leg that is merely
/// unreachable or slow (which stays a normal degraded bond).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerGroupCollision {
    /// The leg that answered from a different receiving group. It is marked
    /// [`GroupMemberState::Broken`] and disconnected.
    pub member_id: u32,
    /// The receiving-group ID this group is bound to.
    pub expected_peer_group_id: u32,
    /// The receiving-group ID the leg reported.
    pub actual_peer_group_id: u32,
}

/// One physical leg of an [`SrtGroup`]: a socket-level [`SrtConnection`] plus
/// its group membership metadata.
pub struct SrtGroupMember {
    id: u32,
    weight: u16,
    state: GroupMemberState,
    connection: SrtConnection,
    /// This member's receiving-group identity has been admitted (bound or
    /// matched). Set once its handshake completes, whatever its state label:
    /// a Backup leg is labelled Standby before it is connected.
    peer_group_admitted: bool,
    /// Sequences of the group's pending payloads this member holds a receive
    /// reservation for, and the packets they span.
    reserved: BTreeSet<u32>,
    reserved_packets: u32,
}

impl SrtGroupMember {
    /// This member's group-member ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// This member's weight, used to break ties when [`GroupMode::Backup`]
    /// promotes a standby member.
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// This member's current lifecycle state.
    pub fn state(&self) -> GroupMemberState {
        self.state
    }

    /// The member's underlying protocol connection.
    pub fn connection(&self) -> &SrtConnection {
        &self.connection
    }

    /// The member's underlying protocol connection, mutably.
    pub fn connection_mut(&mut self) -> &mut SrtConnection {
        &mut self.connection
    }
}

/// A bonded SRT group: a set of physical [`SrtGroupMember`] connections
/// driven as one logical, deduplicated stream.
///
/// Applications add members as their handshakes complete, then send and
/// receive through the group rather than through individual members. See
/// [`GroupMode`] for how payload is distributed/deduplicated across members.
pub struct SrtGroup {
    group_id: u32,
    mode: GroupMode,
    members: Vec<SrtGroupMember>,
    next_send_sequence: Option<u32>,
    next_receive_sequence: Option<u32>,
    /// First member's fixed TX origin and the logical receiver's current clock.
    /// Membership changes can advance its wrap phase, never select its drift.
    time: Option<GroupTime>,
    /// Newest clock phase observed on accepted unique DATA, retained even if
    /// its producer is removed. Published only when logical DATA progresses.
    collected_time: Option<GroupTime>,
    /// A bounded event collection stopped before reaching all queued work.
    receive_continuation: bool,
    /// Complete payloads waiting behind a sequence gap, by sequence. Each is
    /// either in its member's `reserved` (that member holds a receive
    /// reservation for it) or in `owned`.
    pending: BTreeMap<u32, GroupPacket>,
    events: std::collections::VecDeque<GroupEvent>,
    next_event_member: usize,
    /// The remote receiving group this group is bound to, set by the first
    /// member whose handshake response carried a GROUP extension.
    peer_group_id: Option<u32>,
    /// Members that answered from another receiving group, awaiting
    /// [`Self::poll_peer_group_collision`]. At most one per member.
    collisions: std::collections::VecDeque<PeerGroupCollision>,
    /// Sequences of pending payloads no member holds a reservation for: their
    /// member was removed, which returned the reservation then. Delivering or
    /// retiring them releases nothing, even into a new member with that ID.
    owned: BTreeSet<u32>,
    /// Packets the `owned` payloads span.
    owned_packets: u32,
    /// Backup mode: what the carrier sent and its peer has not acknowledged,
    /// oldest first, so a standby that takes over replays it before new
    /// payload. Bounded by [`MAX_BACKUP_HISTORY`].
    backup_history: VecDeque<(u32, Bytes, Timestamp)>,
    /// The member that carried the last Backup send.
    backup_carrier: Option<u32>,
    /// The carrier has unacknowledged packets older than the history holds
    /// (the bound evicted them): a takeover would leave a hole, so it is
    /// refused.
    backup_history_gap: bool,
    /// Packets the receive side skipped because no member delivered them
    /// before a later sequence was released.
    skipped_receive_packets: u64,
}

/// Floor of a Backup carrier's stability timeout (libsrt's `SRT_TMIN`).
pub const BACKUP_MIN_STABILITY_TIMEOUT_MICROS: u64 = 60_000;

/// Most unacknowledged Backup sends kept for a takeover replay: half the
/// output queue, so a replay plus its live traffic never overflows the new
/// leg's queue (an overflow disconnects it).
pub const MAX_BACKUP_HISTORY: usize = crate::srt_connection::MAX_OUTPUT_QUEUE_ACTIONS / 2;

impl SrtGroup {
    /// Create an empty group. `group_id` must carry [`SRTGROUP_MASK`], as it
    /// does on the wire.
    pub fn new(group_id: u32, mode: GroupMode) -> Result<Self, Error> {
        if group_id & SRTGROUP_MASK == 0 {
            return Err(Error::invalid_state("group ID is missing SRTGROUP_MASK"));
        }
        Ok(Self {
            group_id,
            mode,
            members: Vec::new(),
            next_send_sequence: None,
            next_receive_sequence: None,
            time: None,
            collected_time: None,
            receive_continuation: false,
            pending: BTreeMap::new(),
            events: std::collections::VecDeque::new(),
            next_event_member: 0,
            peer_group_id: None,
            collisions: std::collections::VecDeque::new(),
            owned: BTreeSet::new(),
            owned_packets: 0,
            backup_history: VecDeque::new(),
            backup_carrier: None,
            backup_history_gap: false,
            skipped_receive_packets: 0,
        })
    }

    /// How long a Backup member may hold unacknowledged data without hearing
    /// from its peer before a connected standby takes over:
    /// `max(60 ms, 2·SRTT + 4·RTTVar)` from its own RTT estimate, as libsrt.
    pub fn backup_stability_timeout_micros(&self, member_id: u32) -> Option<u64> {
        let (srtt, rttvar) = self
            .member(member_id)?
            .connection
            .sender_buffer()?
            .rtt_estimate_micros();
        let dynamic = 2 * u64::from(srtt) + 4 * u64::from(rttvar);
        Some(dynamic.max(BACKUP_MIN_STABILITY_TIMEOUT_MICROS))
    }

    /// The remote receiving-group ID this group is bound to, once a member
    /// whose response carried a GROUP extension has connected.
    pub fn peer_group_id(&self) -> Option<u32> {
        self.peer_group_id
    }

    /// Pop one peer-group collision. The offending member's connection is
    /// disconnected now (it is already [`GroupMemberState::Broken`]), so the
    /// remote receiver is told to drop the leg.
    pub fn poll_peer_group_collision(&mut self, now: Timestamp) -> Option<PeerGroupCollision> {
        let collision = self.collisions.pop_front()?;
        if let Some(member) = self.member_mut(collision.member_id) {
            member.connection.disconnect(now);
        }
        Some(collision)
    }

    /// A member may have released DATA before the group consumer polls it.
    /// Membership changes retain only strictly newer wrap phases from that
    /// physical progress; equal-phase drift belongs to logical DATA delivery.
    fn refresh_receive_epoch(&mut self) {
        let Some(time) = &mut self.time else {
            return;
        };
        if let Some(collected) = self.collected_time {
            time.advance_receive_epoch(collected);
        }
        for member in &self.members {
            if member.peer_group_admitted
                && let Some(advanced) = member.connection.group_time()
            {
                time.advance_receive_epoch(advanced);
            }
        }
    }

    /// Bind the group to, or check the member against, the remote receiving
    /// group named by the member's handshake response. Returns `false` (and
    /// records the collision) when the member reports a different one. A
    /// member that sent GROUP never connects without a GROUP response (its
    /// handshake refuses it, as libsrt's `SRT_REJ_GROUP` does); a member that
    /// sent none has no identity to check.
    fn admit_peer_group(&mut self, index: usize) -> bool {
        // As in libsrt, the first connected member fixes the receive base
        // before TLPKTDROP can make a later packet look like the prefix.
        if self.next_receive_sequence.is_none() {
            self.next_receive_sequence = self.members[index].connection.peer_initial_sequence();
        }
        let actual = self.members[index]
            .connection
            .peer_group_extension()
            .map(|extension| extension.group_id);
        let admitted = match (self.peer_group_id, actual) {
            (_, None) => true,
            (None, Some(actual)) => {
                self.peer_group_id = Some(actual);
                true
            }
            (Some(expected), Some(actual)) if expected == actual => true,
            (Some(expected), Some(actual)) => {
                self.members[index].state = GroupMemberState::Broken;
                self.collisions.push_back(PeerGroupCollision {
                    member_id: self.members[index].id,
                    expected_peer_group_id: expected,
                    actual_peer_group_id: actual,
                });
                false
            }
        };
        if admitted {
            self.refresh_receive_epoch();
            self.members[index].peer_group_admitted = true;
            // libsrt synchronizeWithGroup/applyGroupTime: late members inherit
            // the logical clock, not an idle physical leg's stale wrap epoch.
            let time = self
                .time
                .or_else(|| self.members[index].connection.group_time());
            if let Some(time) = time {
                self.members[index].connection.inherit_group_time(time);
                self.time = Some(time);
                self.collected_time.get_or_insert(time);
            }
        }
        admitted
    }

    /// This group's ID, as carried on the wire.
    pub fn group_id(&self) -> u32 {
        self.group_id
    }

    /// This group's mode.
    pub fn mode(&self) -> GroupMode {
        self.mode
    }

    /// This group's members, in the order they were added.
    pub fn members(&self) -> &[SrtGroupMember] {
        &self.members
    }

    /// Look up one member by ID.
    pub fn member(&self, member_id: u32) -> Option<&SrtGroupMember> {
        self.members.iter().find(|member| member.id == member_id)
    }

    /// Look up one member by ID, mutably.
    pub fn member_mut(&mut self, member_id: u32) -> Option<&mut SrtGroupMember> {
        self.members
            .iter_mut()
            .find(|member| member.id == member_id)
    }

    /// Add a new physical leg to the group. Its initial state depends on
    /// [`GroupMode`] and whether its connection is already established; a
    /// not-yet-connected member starts [`GroupMemberState::Pending`].
    pub fn add_member(
        &mut self,
        member_id: u32,
        weight: u16,
        mut connection: SrtConnection,
    ) -> Result<(), Error> {
        if self.members.len() >= MAX_GROUP_MEMBERS {
            return Err(Error::invalid_state("group member limit reached"));
        }
        if self.member(member_id).is_some() {
            return Err(Error::invalid_state("duplicate group member ID"));
        }
        self.refresh_receive_epoch();
        let connected = connection.state() == ConnectionState::Connected;
        if !connected && let Some(time) = self.time {
            connection.inherit_group_time(time);
        }
        let state = match self.mode {
            GroupMode::Broadcast => connected.then_some(GroupMemberState::Active),
            GroupMode::Backup => {
                if connected && !self.has_active_member() {
                    Some(GroupMemberState::Active)
                } else {
                    Some(GroupMemberState::Standby)
                }
            }
        }
        .unwrap_or(GroupMemberState::Pending);

        self.members.push(SrtGroupMember {
            id: member_id,
            weight,
            state,
            connection,
            peer_group_admitted: false,
            reserved: BTreeSet::new(),
            reserved_packets: 0,
        });
        // A pending leg has no sender buffer until its handshake completes.
        // `refresh_pending_states` aligns it at that transition; attempting
        // it here would reject a legitimate late-joining group member.
        if connected {
            let index = self.members.len() - 1;
            if self.admit_peer_group(index) {
                self.align_member_sequence(member_id)?;
            }
        }
        Ok(())
    }

    /// Force one member to [`GroupMemberState::Broken`]. Returns `false` if
    /// `member_id` isn't a member of this group.
    pub fn mark_member_broken(&mut self, member_id: u32) -> bool {
        let Some(member) = self.member_mut(member_id) else {
            return false;
        };
        member.state = GroupMemberState::Broken;
        true
    }

    /// Remove one member from the group without returning its connection.
    /// Use [`Self::remove_member_connection`] when the caller still owns the
    /// leg's socket/timers and needs the protocol core back.
    ///
    /// Complete payloads already collected from the member stay pending and
    /// are delivered in order like any other.
    pub fn remove_member(&mut self, member_id: u32) -> bool {
        self.remove_member_connection(member_id).is_some()
    }

    /// Remove a member and return its protocol core to the transport that
    /// owns the socket and timers for that leg.
    ///
    /// Complete payloads already collected from the member stay pending and
    /// are delivered in order like any other; their receive reservation is
    /// returned to the connection here, once. Incomplete messages are still
    /// the connection's own and never reach the group.
    pub fn remove_member_connection(&mut self, member_id: u32) -> Option<SrtConnection> {
        let index = self
            .members
            .iter()
            .position(|member| member.id == member_id)?;
        self.refresh_receive_epoch();
        let mut member = self.members.remove(index);
        self.next_event_member = self
            .next_event_member
            .min(self.members.len().saturating_sub(1));
        // The payloads this member reserved become the group's own. Merging
        // the smaller index into the larger costs at most the smaller one's
        // entries; nothing else is walked.
        self.owned_packets = self.owned_packets.saturating_add(member.reserved_packets);
        if self.owned.len() < member.reserved.len() {
            std::mem::swap(&mut self.owned, &mut member.reserved);
        }
        self.owned.extend(std::mem::take(&mut member.reserved));
        member
            .connection
            .release_data_reservation(member.reserved_packets);
        self.bound_group_owned_pending(member.connection.receive_window_packets());
        Some(member.connection)
    }

    /// Keep group-owned payloads within the largest member receive window.
    ///
    /// They are charged to no member window, so without this, member churn
    /// behind a gap that never fills could retain them without bound. One
    /// removal never exceeds it (a member holds at most its own window); the
    /// payloads farthest from delivery are retired first, touching only the
    /// ones retired.
    fn bound_group_owned_pending(&mut self, removed_window: u32) {
        let limit = self
            .members
            .iter()
            .map(|member| member.connection.receive_window_packets())
            .fold(removed_window, u32::max);
        if self.owned_packets <= limit {
            return;
        }
        let base = self
            .next_receive_sequence
            .or_else(|| self.oldest_pending())
            .unwrap_or_default();
        // Farthest first: sequences that wrapped below `base`, then those
        // from `base` up, each walked down.
        for (low, high) in [(0, base), (base, u32::MAX)] {
            while self.owned_packets > limit {
                let Some(&sequence) = self.owned.range(low..high).next_back() else {
                    break;
                };
                self.owned.remove(&sequence);
                let retired = self.pending.remove(&sequence);
                debug_assert!(retired.is_some(), "owned sequence {sequence} is pending");
                let count = retired.map_or(0, |packet| packet.packet_count);
                debug_assert!(self.owned_packets >= count);
                self.owned_packets = self.owned_packets.saturating_sub(count);
            }
        }
    }

    /// Refresh member lifecycle labels after an owner has driven each
    /// underlying connection. This makes completed handshakes visible as
    /// `Active` or `Standby` without requiring an attempted payload send.
    ///
    /// Runtime adapters should call this at the end of each bounded I/O pass;
    /// applications that drive member connections directly may call it before
    /// inspecting [`Self::members`].
    pub fn refresh_member_states(&mut self) {
        self.refresh_states();
    }

    /// Begin an orderly close of every physical member while retaining the
    /// logical group until normal transport teardown completes.
    pub fn disconnect(&mut self, now: Timestamp) {
        for member in &mut self.members {
            member.connection.disconnect(now);
        }
    }

    /// Packets the receive side skipped because no member delivered them
    /// before a later sequence was released: lost on every link.
    pub fn skipped_receive_packets(&self) -> u64 {
        self.skipped_receive_packets
    }

    /// Whether collected receive work remains: payloads, member-lifecycle
    /// events, or a bounded collection that needs another visit. This does
    /// not inspect uncollected physical connection queues; poll events until
    /// they report no event before using it to finish logical teardown.
    pub fn has_pending_data(&self) -> bool {
        !self.pending.is_empty() || !self.events.is_empty() || self.receive_continuation
    }

    /// Whether the last event poll exhausted its bounded collection before
    /// proving the physical queues empty. Unlike [`Self::has_pending_data`],
    /// this requests immediate service, not waiting for a gap's deadline.
    pub fn has_receive_continuation(&self) -> bool {
        self.receive_continuation
    }

    /// The oldest pending sequence, in wrapping order, in two ordered
    /// lookups. Pending sequences span less than half the sequence space,
    /// so either none lies half a space above the numerically first and that
    /// one is oldest, or the span wraps and the first of those above is.
    fn oldest_pending(&self) -> Option<u32> {
        count_work!(PendingKeysVisited);
        let (&first, _) = self.pending.first_key_value()?;
        count_work!(PendingKeysVisited);
        let wrapped = self
            .pending
            .range(first.saturating_add(SEQUENCE_HALF_SPACE)..)
            .next()
            .map(|(&sequence, _)| sequence);
        Some(wrapped.unwrap_or(first))
    }

    /// Remove the pending payloads stored at the interior sequences of a
    /// delivered message, `first..first + count`, visiting only those
    /// present: at most two ordered ranges across a wrap.
    fn remove_pending_within(&mut self, first: u32, count: u32) {
        if count == 0 {
            return;
        }
        let last = first.wrapping_add(count - 1) & SEQUENCE_MASK;
        let ranges = if first <= last {
            [(first, last), (1, 0)]
        } else {
            [(first, SEQUENCE_MASK), (0, last)]
        };
        for (low, high) in ranges {
            while let Some(sequence) = (low <= high)
                .then(|| self.pending.range(low..=high).next().map(|(&key, _)| key))
                .flatten()
            {
                count_work!(PendingKeysVisited);
                if let Some(stale) = self.pending.remove(&sequence) {
                    self.release_pending_reservation(&stale);
                }
            }
        }
    }

    /// Whether TLPKTDROP has given up, at `now`, on every sequence before the
    /// oldest pending one: that packet's give-up point on the member that
    /// delivered it has passed, and no older sequence's comes later.
    fn gap_given_up(&self, now: Timestamp) -> bool {
        let Some(packet) = self
            .oldest_pending()
            .and_then(|sequence| self.pending.get(&sequence))
        else {
            return false;
        };
        // Terminal cores cannot recover a missing packet. The caller still
        // has to drain their queued events before actually skipping it.
        if self
            .members
            .iter()
            .all(|member| member.connection.state() == ConnectionState::Disconnected)
        {
            return true;
        }
        self.members
            .iter()
            .find(|member| member.id == packet.member_id)
            .or_else(|| self.members.first())
            .and_then(|member| member.connection.gives_up_at(packet.source_time))
            .is_some_and(|at| now >= at)
    }

    /// The sequence to deliver next: `next`, or -- once members have given
    /// up on the gap before the oldest pending payload -- that payload,
    /// counting the skip. A member's release of `next` may still be queued,
    /// so collect those first; a lifecycle event collected on the way breaks.
    fn skip_given_up_gap(
        &mut self,
        next: u32,
        now: Timestamp,
        budget: &mut usize,
    ) -> std::ops::ControlFlow<GroupEvent, u32> {
        use std::ops::ControlFlow::{Break, Continue};
        if self.pending.contains_key(&next) || self.receive_continuation || !self.gap_given_up(now)
        {
            return Continue(next);
        }
        let mut exhausted = true;
        for _ in 0..MAX_GROUP_MEMBERS {
            if self.receive_continuation
                || self.pending.contains_key(&next)
                || !self.collect_one_event(now, budget)
            {
                exhausted = false;
                break;
            }
        }
        self.receive_continuation |= exhausted && !self.pending.contains_key(&next);
        if let Some(event) = self.events.pop_front() {
            return Break(event);
        }
        // A queued sibling may still hold the missing prefix. A full visit
        // is not proof of an empty queue, even after physical termination.
        if self.receive_continuation {
            return Continue(next);
        }
        match self.oldest_pending() {
            Some(oldest) if !self.pending.contains_key(&next) => {
                let skipped = oldest.wrapping_sub(next) & 0x7FFF_FFFF;
                self.skipped_receive_packets = self
                    .skipped_receive_packets
                    .saturating_add(u64::from(skipped));
                Continue(oldest)
            }
            _ => Continue(next),
        }
    }

    /// Return the next deduplicated, in-order payload, discarding any
    /// member-lifecycle events along the way. Applications that need to know
    /// whether the bounded lifecycle drain left more work should use
    /// [`Self::poll_data_bounded`] instead.
    pub fn poll_data(&mut self, now: Timestamp) -> Option<GroupPacket> {
        self.poll_data_bounded(now, MAX_GROUP_MEMBERS).packet
    }

    /// Return the next deduplicated payload after at most `max_events`
    /// lifecycle-event visits. The limit is clamped to [`MAX_GROUP_MEMBERS`]
    /// so a caller cannot turn a single poll into an unbounded scan.
    pub fn poll_data_bounded(&mut self, now: Timestamp, max_events: usize) -> GroupDataPoll {
        let limit = max_events.min(MAX_GROUP_MEMBERS);
        if limit == 0 {
            return GroupDataPoll {
                packet: None,
                continuation: self.has_pending_data(),
            };
        }
        for _ in 0..limit {
            let Some(event) = self.poll_event(now) else {
                return GroupDataPoll {
                    packet: None,
                    continuation: self.receive_continuation,
                };
            };
            match event {
                GroupEvent::DataReceived(packet) => {
                    return GroupDataPoll {
                        packet: Some(packet),
                        continuation: false,
                    };
                }
                GroupEvent::MemberConnected { .. }
                | GroupEvent::MemberError { .. }
                | GroupEvent::MemberDisconnected { .. } => {}
            }
        }
        GroupDataPoll {
            packet: None,
            continuation: true,
        }
    }

    /// Return the next member-lifecycle event or deduplicated group payload.
    pub fn poll_event(&mut self, now: Timestamp) -> Option<GroupEvent> {
        self.receive_continuation = false;
        self.refresh_pending_states();
        let mut delivery_budget = MAX_DELIVERY_PER_VISIT;
        for visit in 0..MAX_GROUP_MEMBERS {
            if let Some(event) = self.events.pop_front() {
                return Some(event);
            }
            if !self.collect_one_event(now, &mut delivery_budget) {
                break;
            }
            self.receive_continuation |= visit + 1 == MAX_GROUP_MEMBERS && self.pending.is_empty();
            if let Some(event) = self.events.pop_front() {
                return Some(event);
            }
            if self.receive_continuation || !self.pending.is_empty() {
                break;
            }
        }
        self.refresh_states();

        if let Some(event) = self.events.pop_front() {
            return Some(event);
        }

        let next = self
            .next_receive_sequence
            .or_else(|| self.oldest_pending())?;
        let next = match self.skip_given_up_gap(next, now, &mut delivery_budget) {
            std::ops::ControlFlow::Continue(next) => next,
            std::ops::ControlFlow::Break(event) => return Some(event),
        };
        self.next_receive_sequence = Some(next);
        let packet = self.pending.remove(&next)?;
        let following = next.wrapping_add(packet.packet_count) & 0x7FFF_FFFF;
        self.next_receive_sequence = Some(following);
        self.release_pending_reservation(&packet);
        self.remove_pending_within(
            next.wrapping_add(1) & SEQUENCE_MASK,
            packet.packet_count.saturating_sub(1),
        );
        self.advance_member_receive_prefix(following, now);
        Some(GroupEvent::DataReceived(packet))
    }

    fn advance_member_receive_prefix(&mut self, following: u32, now: Timestamp) {
        if let (Some(time), Some(collected)) = (&mut self.time, self.collected_time) {
            time.update_receive(collected);
        }
        for member in &mut self.members {
            if let Some(time) = self.time
                && (member.peer_group_admitted || member.state != GroupMemberState::Broken)
            {
                member.connection.inherit_group_time(time);
            }
            member.connection.advance_receive_sequence(following, now);
            // Advancing the prefix can release queued DATA and finish a wrap.
            // Only a newer phase can replace the logical producer's drift.
            if member.peer_group_admitted
                && let (Some(time), Some(advanced)) =
                    (&mut self.time, member.connection.group_time())
            {
                time.advance_receive_epoch(advanced);
            }
        }
        // No idle member may receive its first post-wrap packet in an old
        // epoch. An already-ahead physical receiver never rewinds on inherit.
        let Some(time) = self.time else {
            return;
        };
        for member in &mut self.members {
            if member.peer_group_admitted || member.state != GroupMemberState::Broken {
                member.connection.inherit_group_time(time);
            }
        }
    }

    fn collect_one_event(&mut self, now: Timestamp, budget: &mut usize) -> bool {
        let len = self.members.len();
        if len == 0 {
            return false;
        }
        for offset in 0..len {
            let index = (self.next_event_member + offset) % len;
            let (event, continuation) = self.members[index]
                .connection
                .poll_event_for_group(now, budget);
            self.receive_continuation |= continuation;
            let Some(event) = event else {
                if continuation {
                    self.next_event_member = (index + 1) % len;
                    return false;
                }
                continue;
            };
            let member_id = self.members[index].id;
            self.next_event_member = (index + 1) % len;
            self.collect_member_event(index, member_id, event);
            return true;
        }
        false
    }

    fn collect_member_event(&mut self, index: usize, member_id: u32, event: ConnectionEvent) {
        match event {
            ConnectionEvent::Connected => {
                self.events
                    .push_back(GroupEvent::MemberConnected { member_id });
            }
            // Accept DATA regardless of the member's local Active/Standby
            // label. Sequence deduplication is the authority because peers can
            // independently choose different active legs during handshakes.
            ConnectionEvent::DataReceived {
                sequence_number,
                message_number,
                timestamp,
                source_time,
                payload,
                packet_count,
            } => {
                let packet = GroupPacket {
                    member_id,
                    sequence_number,
                    message_number,
                    timestamp,
                    source_time,
                    payload,
                    packet_count,
                };
                if !self.retain_group_packet(index, packet) {
                    self.members[index]
                        .connection
                        .release_data_reservation(packet_count);
                }
            }
            ConnectionEvent::Error(error) => {
                self.events
                    .push_back(GroupEvent::MemberError { member_id, error });
                self.members[index].state = GroupMemberState::Broken;
                if self.mode == GroupMode::Backup {
                    self.promote_backup_member();
                }
            }
            ConnectionEvent::Disconnected { reason } => {
                self.events.push_back(GroupEvent::MemberDisconnected {
                    member_id,
                    reason: reason.to_string(),
                });
                self.members[index].state = GroupMemberState::Broken;
                if self.mode == GroupMode::Backup {
                    self.promote_backup_member();
                }
            }
            _ => {}
        }
    }

    fn retain_group_packet(&mut self, index: usize, packet: GroupPacket) -> bool {
        if self
            .next_receive_sequence
            .is_some_and(|next| sequence_less_than(packet.sequence_number, next))
        {
            return false;
        }
        let std::collections::btree_map::Entry::Vacant(entry) =
            self.pending.entry(packet.sequence_number)
        else {
            return false;
        };
        let member = &mut self.members[index];
        member.reserved.insert(packet.sequence_number);
        member.reserved_packets = member.reserved_packets.saturating_add(packet.packet_count);
        entry.insert(packet);
        if let Some(time) = member.connection.group_time() {
            if let Some(collected) = &mut self.collected_time {
                collected.update_receive(time);
            } else {
                self.collected_time = Some(time);
            }
        }
        true
    }

    fn refresh_states(&mut self) {
        self.refresh_pending_states();
        for member in &mut self.members {
            if member.state != GroupMemberState::Broken
                && member.connection.state() == ConnectionState::Disconnected
            {
                member.state = GroupMemberState::Broken;
            }
        }
        self.requalify_unstable_members();
        if self.mode == GroupMode::Backup && !self.has_active_member() {
            self.promote_backup_member();
        }
    }

    /// Return a delivered or retired payload's reservation to the member
    /// holding it. A group-owned payload holds none: that reservation was
    /// returned when its member was removed.
    fn release_pending_reservation(&mut self, packet: &GroupPacket) {
        let count = packet.packet_count;
        if self.owned.remove(&packet.sequence_number) {
            debug_assert!(self.owned_packets >= count);
            self.owned_packets = self.owned_packets.saturating_sub(count);
            return;
        }
        let Some(member) = self.member_mut(packet.member_id) else {
            debug_assert!(false, "a pending payload is owned or reserved");
            return;
        };
        let reserved = member.reserved.remove(&packet.sequence_number);
        debug_assert!(reserved, "a member's pending payload is in its index");
        debug_assert!(member.reserved_packets >= count);
        member.reserved_packets = member.reserved_packets.saturating_sub(count);
        member.connection.release_data_reservation(count);
    }

    /// Admit the receiving-group identity of every member whose handshake has
    /// completed since the last look, whatever its state label.
    fn admit_connected_peer_groups(&mut self) {
        for index in 0..self.members.len() {
            let member = &self.members[index];
            if !member.peer_group_admitted
                && member.state != GroupMemberState::Broken
                && member.connection.state() == ConnectionState::Connected
            {
                self.admit_peer_group(index);
            }
        }
    }

    fn refresh_pending_states(&mut self) {
        self.admit_connected_peer_groups();
        for index in 0..self.members.len() {
            let ready = {
                let member = &self.members[index];
                member.state == GroupMemberState::Pending
                    && member.connection.state() == ConnectionState::Connected
            };
            if !ready {
                continue;
            }

            let member_id = self.members[index].id;
            if self.align_member_sequence(member_id).is_err() {
                continue;
            }
            self.members[index].state = if self.mode == GroupMode::Broadcast {
                GroupMemberState::Active
            } else {
                GroupMemberState::Standby
            };
        }
        if self.mode == GroupMode::Backup && !self.has_active_member() {
            self.promote_backup_member();
        }
    }

    fn align_member_sequence(&mut self, member_id: u32) -> Result<(), Error> {
        let sequence_number = self.next_send_sequence.or_else(|| {
            self.members
                .iter()
                .filter(|member| {
                    member.id != member_id
                        && member.connection.state() == ConnectionState::Connected
                })
                .find_map(|member| member.connection.next_sequence_number())
        });
        let Some(sequence_number) = sequence_number else {
            return Ok(());
        };
        let Some(member) = self.member_mut(member_id) else {
            return Err(Error::invalid_state("unknown group member"));
        };
        if member.connection.next_sequence_number() != Some(sequence_number) {
            member
                .connection
                .synchronize_send_sequence(sequence_number)?;
        }
        Ok(())
    }

    fn requalify_unstable_members(&mut self) {
        for index in 0..self.members.len() {
            if self.members[index].state != GroupMemberState::Unstable
                || self.members[index].connection.state() != ConnectionState::Connected
                || !self.members[index].connection.can_send()
            {
                continue;
            }

            let member_id = self.members[index].id;
            if self.align_member_sequence(member_id).is_ok() {
                self.members[index].state =
                    if self.mode == GroupMode::Broadcast || !self.has_active_member() {
                        GroupMemberState::Active
                    } else {
                        GroupMemberState::Standby
                    };
            }
        }
    }

    fn active_indices(&self) -> Vec<usize> {
        self.members
            .iter()
            .enumerate()
            .filter(|(_, member)| {
                member.state == GroupMemberState::Active
                    && member.connection.state() == ConnectionState::Connected
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn has_active_member(&self) -> bool {
        !self.active_indices().is_empty()
    }

    fn promote_backup_member(&mut self) {
        let Some((index, _)) = self
            .members
            .iter()
            .enumerate()
            .filter(|(_, member)| {
                member.state == GroupMemberState::Standby
                    && member.connection.state() == ConnectionState::Connected
            })
            .max_by_key(|(_, member)| (member.weight, std::cmp::Reverse(member.id)))
        else {
            return;
        };
        self.members[index].state = GroupMemberState::Active;
    }
}

/// The 31-bit sequence space's mask, and half of the space: the farthest
/// apart two comparable sequences can be.
const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
const SEQUENCE_HALF_SPACE: u32 = 0x4000_0000;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::WorkCounters;

    #[test]
    fn bounded_data_poll_reports_lifecycle_continuation() {
        let mut group = SrtGroup::new(SRTGROUP_MASK, GroupMode::Broadcast).unwrap();
        for member_id in 0..=MAX_GROUP_MEMBERS as u32 {
            group
                .events
                .push_back(GroupEvent::MemberConnected { member_id });
        }

        let first = group.poll_data_bounded(Timestamp::default(), MAX_GROUP_MEMBERS);
        assert!(first.packet.is_none());
        assert!(first.continuation);

        let second = group.poll_data_bounded(Timestamp::default(), MAX_GROUP_MEMBERS);
        assert!(second.packet.is_none());
        assert!(!second.continuation);
    }

    /// A pending payload at `sequence_number` spanning `packet_count`
    /// packets, owned by the group.
    fn pending_packet(group: &mut SrtGroup, sequence_number: u32, packet_count: u32) {
        group.pending.insert(
            sequence_number,
            GroupPacket {
                member_id: 0,
                sequence_number,
                message_number: 1,
                timestamp: 0,
                source_time: Timestamp::default(),
                packet_count,
                payload: bytes::Bytes::from_static(b"x").into(),
            },
        );
        group.owned.insert(sequence_number);
        group.owned_packets += packet_count;
    }

    /// The group windows the pending-work test compares.
    const PENDING_BACKLOGS: [u32; 3] = [32, 8_192, 65_536];

    /// Pending keys one head lookup or one delivery may visit.
    const PENDING_KEY_LIMIT: u64 = 8;

    /// F13: finding the oldest pending payload and delivering a
    /// multi-packet one cost the same whatever the backlog behind it or the
    /// packets it spans, across a sequence wrap.
    #[test]
    fn pending_head_and_fragment_delivery_work_is_backlog_independent() {
        let mut results = Vec::new();
        for backlog in PENDING_BACKLOGS {
            // A backlog that wraps: the oldest key is numerically largest.
            let mut group = SrtGroup::new(SRTGROUP_MASK, GroupMode::Broadcast).unwrap();
            let oldest = SEQUENCE_MASK - 3;
            for offset in 0..backlog {
                pending_packet(&mut group, oldest.wrapping_add(offset) & SEQUENCE_MASK, 1);
            }
            let (head, head_work) = WorkCounters::measure(|| group.oldest_pending());
            assert_eq!(head, Some(oldest));

            // One message spanning the backlog, two stale fragments inside.
            let mut group = SrtGroup::new(SRTGROUP_MASK, GroupMode::Broadcast).unwrap();
            pending_packet(&mut group, oldest, backlog);
            for offset in [1, backlog - 1] {
                pending_packet(&mut group, oldest.wrapping_add(offset) & SEQUENCE_MASK, 1);
            }
            let (event, delivery_work) =
                WorkCounters::measure(|| group.poll_event(Timestamp::default()));
            assert!(matches!(event, Some(GroupEvent::DataReceived(_))));
            assert!(group.pending.is_empty(), "interior fragments are gone");
            results.push((backlog, head_work, delivery_work));
        }
        for (backlog, head, delivery) in &results {
            eprintln!(
                "backlog {backlog}: head keys {} delivery keys {}",
                head.pending_keys_visited, delivery.pending_keys_visited
            );
        }
        for (backlog, head, delivery) in results {
            assert!(
                head.pending_keys_visited <= PENDING_KEY_LIMIT
                    && delivery.pending_keys_visited <= PENDING_KEY_LIMIT,
                "backlog {backlog}: head {head:?} delivery {delivery:?}"
            );
        }
    }
}
