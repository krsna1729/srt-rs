use std::collections::BTreeMap;

use bytes::Bytes;

use crate::error::Error;
use crate::srt_connection::{ConnectionEvent, ConnectionState, SrtConnection};
use crate::srt_handshake::{GroupType, SRTGROUP_MASK};
use crate::srt_packet::sequence_less_than;
use crate::time::Timestamp;

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
    /// The member the payload was received on.
    pub member_id: u32,
    /// The group-logical sequence number.
    pub sequence_number: u32,
    /// The message number, for reassembling multi-packet messages.
    pub message_number: u32,
    /// The sender's timestamp, in the units defined by the SRT wire format.
    pub timestamp: u32,
    /// Number of SRT DATA packets represented by the reassembled payload.
    pub packet_count: u32,
    /// Reference-counted payload bytes.
    pub payload: Bytes,
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

/// One physical leg of an [`SrtGroup`]: a socket-level [`SrtConnection`] plus
/// its group membership metadata.
pub struct SrtGroupMember {
    id: u32,
    weight: u16,
    state: GroupMemberState,
    connection: SrtConnection,
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
    pending: BTreeMap<u32, GroupPacket>,
    events: std::collections::VecDeque<GroupEvent>,
}

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
            pending: BTreeMap::new(),
            events: std::collections::VecDeque::new(),
        })
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
        connection: SrtConnection,
    ) -> Result<(), Error> {
        if self.member(member_id).is_some() {
            return Err(Error::invalid_state("duplicate group member ID"));
        }
        let connected = connection.state() == ConnectionState::Connected;
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
        });
        // A pending leg has no sender buffer until its handshake completes.
        // `refresh_pending_states` aligns it at that transition; attempting
        // it here would reject a legitimate late-joining group member.
        if connected {
            self.align_member_sequence(member_id)?;
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
    pub fn remove_member(&mut self, member_id: u32) -> bool {
        let Some(index) = self
            .members
            .iter()
            .position(|member| member.id == member_id)
        else {
            return false;
        };
        self.purge_member_pending(member_id);
        self.members.remove(index);
        true
    }

    /// Remove a member and return its protocol core to the transport that
    /// owns the socket and timers for that leg.
    pub fn remove_member_connection(&mut self, member_id: u32) -> Option<SrtConnection> {
        let index = self
            .members
            .iter()
            .position(|member| member.id == member_id)?;
        let reserved_packets = self.purge_member_pending(member_id);
        self.members[index]
            .connection
            .release_data_reservation(reserved_packets);
        Some(self.members.remove(index).connection)
    }

    fn purge_member_pending(&mut self, member_id: u32) -> u32 {
        let mut packet_count = 0u32;
        self.pending.retain(|_, packet| {
            if packet.member_id != member_id {
                return true;
            }
            packet_count = packet_count.saturating_add(packet.packet_count);
            false
        });
        packet_count
    }

    /// Send one payload through the group per its [`GroupMode`]. Returns the
    /// number of members it was actually sent on.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, Error> {
        self.send_shared(Bytes::copy_from_slice(payload), now)
    }

    /// Send shared payload data across group members. Uses reference-counted
    /// `Bytes` to avoid deep-copying the payload for each leg.
    pub fn send_shared(&mut self, payload: Bytes, now: Timestamp) -> Result<usize, Error> {
        self.refresh_states();
        match self.mode {
            GroupMode::Broadcast => self.send_broadcast(payload, now),
            GroupMode::Backup => self.send_backup(payload, now),
        }
    }

    /// Whether at least one active member can accept the next logical send.
    ///
    /// Broadcast attempts every active leg, but its logical send succeeds as
    /// soon as any member accepts the payload. A member whose sender window
    /// is full becomes temporarily unstable; once its in-flight packets drain
    /// it is sequence-aligned and automatically rejoins the active set. Backup
    /// promotes a standby member while an unstable leg requalifies.
    pub fn can_send(&mut self) -> bool {
        self.refresh_states();
        let active = self.active_indices();
        match self.mode {
            GroupMode::Broadcast => active
                .iter()
                .any(|&index| self.members[index].connection.can_send()),
            GroupMode::Backup => active
                .first()
                .is_some_and(|&index| self.members[index].connection.can_send()),
        }
    }

    pub fn can_send_with_pacing(&mut self, now: Timestamp) -> bool {
        self.refresh_states();
        let active = self.active_indices();
        match self.mode {
            GroupMode::Broadcast => active
                .iter()
                .any(|&index| self.members[index].connection.can_send_with_pacing(now)),
            GroupMode::Backup => active
                .first()
                .is_some_and(|&index| self.members[index].connection.can_send_with_pacing(now)),
        }
    }

    pub fn time_until_send(&self, now: Timestamp) -> u64 {
        self.members
            .iter()
            .filter(|m| {
                matches!(
                    m.state,
                    GroupMemberState::Active | GroupMemberState::Standby
                )
            })
            .map(|m| m.connection.time_until_send(now))
            .min()
            .unwrap_or(100_000)
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

    /// Return the next deduplicated, in-order payload, discarding any
    /// member-lifecycle events along the way. Applications that need those
    /// events too should use [`Self::poll_event`] instead.
    pub fn poll_data(&mut self, now: Timestamp) -> Option<GroupPacket> {
        loop {
            match self.poll_event(now)? {
                GroupEvent::DataReceived(packet) => return Some(packet),
                GroupEvent::MemberConnected { .. }
                | GroupEvent::MemberError { .. }
                | GroupEvent::MemberDisconnected { .. } => {}
            }
        }
    }

    /// Return the next member-lifecycle event or deduplicated group payload.
    pub fn poll_event(&mut self, now: Timestamp) -> Option<GroupEvent> {
        self.refresh_pending_states();
        self.collect_events();
        self.refresh_states();

        if let Some(event) = self.events.pop_front() {
            return Some(event);
        }

        let next = self.next_receive_sequence.or_else(|| {
            self.pending.keys().copied().reduce(|left, right| {
                if sequence_less_than(right, left) {
                    right
                } else {
                    left
                }
            })
        })?;
        self.next_receive_sequence = Some(next);
        let packet = self.pending.remove(&next)?;
        let following = next.wrapping_add(packet.packet_count) & 0x7FFF_FFFF;
        self.next_receive_sequence = Some(following);
        self.release_member_data_reservation(packet.member_id, packet.packet_count);
        for offset in 1..packet.packet_count {
            let stale_sequence = next.wrapping_add(offset) & 0x7FFF_FFFF;
            if let Some(stale) = self.pending.remove(&stale_sequence) {
                self.release_member_data_reservation(stale.member_id, stale.packet_count);
            }
        }
        for member in &mut self.members {
            member.connection.advance_receive_sequence(following, now);
        }
        Some(GroupEvent::DataReceived(packet))
    }

    fn send_broadcast(&mut self, payload: Bytes, now: Timestamp) -> Result<usize, Error> {
        let active = self.active_indices();
        if active.is_empty() {
            return Err(Error::invalid_state("no active Broadcast group members"));
        }
        let sequence_number = self.sequence_for_send(&active)?;
        let mut sent = 0;
        for index in active {
            let sent_on_member = self.members[index].connection.can_send()
                && self.members[index]
                    .connection
                    .send_shared_with_sequence(payload.clone(), sequence_number, now)
                    .is_ok();
            if sent_on_member {
                sent += 1;
            } else {
                self.mark_send_failure(index);
            }
        }
        if sent == 0 {
            return Err(Error::invalid_state("all Broadcast group members failed"));
        }
        self.next_send_sequence = Some(sequence_number.wrapping_add(1) & 0x7FFF_FFFF);
        Ok(sent)
    }

    fn send_backup(&mut self, payload: Bytes, now: Timestamp) -> Result<usize, Error> {
        let mut active = self.active_indices().into_iter().next();
        if active.is_none() {
            self.promote_backup_member();
            active = self.active_indices().into_iter().next();
        }
        let Some(index) = active else {
            return Err(Error::invalid_state("no active Backup group members"));
        };

        if self.next_send_sequence.is_some() {
            let member_id = self.members[index].id;
            self.align_member_sequence(member_id)?;
        }
        let sequence_number = self.sequence_for_send(&[index])?;
        if !self.members[index].connection.can_send()
            || self.members[index]
                .connection
                .send_shared_with_sequence(payload.clone(), sequence_number, now)
                .is_err()
        {
            self.mark_send_failure(index);
            self.promote_backup_member();
            let Some(index) = self.active_indices().into_iter().next() else {
                return Err(Error::invalid_state("all Backup group members failed"));
            };
            self.align_member_sequence(self.members[index].id)?;
            self.members[index]
                .connection
                .send_shared_with_sequence(payload, sequence_number, now)
                .map_err(|_| Error::invalid_state("Backup promotion send failed"))?;
        }
        self.next_send_sequence = Some(sequence_number.wrapping_add(1) & 0x7FFF_FFFF);
        Ok(1)
    }

    fn sequence_for_send(&self, active: &[usize]) -> Result<u32, Error> {
        let sequence_number = self
            .next_send_sequence
            .or_else(|| {
                active
                    .first()
                    .and_then(|&index| self.members[index].connection.next_sequence_number())
            })
            .ok_or_else(|| Error::invalid_state("group member is not connected"))?;
        if active.iter().any(|&index| {
            self.members[index].connection.next_sequence_number() != Some(sequence_number)
        }) {
            return Err(Error::invalid_state("group member sequence mismatch"));
        }
        Ok(sequence_number)
    }

    fn collect_events(&mut self) {
        for index in 0..self.members.len() {
            while let Some((member_id, event)) = {
                let member = &mut self.members[index];
                member
                    .connection
                    .poll_event_for_group()
                    .map(|event| (member.id, event))
            } {
                self.collect_member_event(index, member_id, event);
            }
        }
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
                payload,
                packet_count,
            } => {
                let packet = GroupPacket {
                    member_id,
                    sequence_number,
                    message_number,
                    timestamp,
                    payload,
                    packet_count,
                };
                if !self.retain_group_packet(packet) {
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
                self.events
                    .push_back(GroupEvent::MemberDisconnected { member_id, reason });
                self.members[index].state = GroupMemberState::Broken;
                if self.mode == GroupMode::Backup {
                    self.promote_backup_member();
                }
            }
            _ => {}
        }
    }

    fn retain_group_packet(&mut self, packet: GroupPacket) -> bool {
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
        entry.insert(packet);
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

    fn release_member_data_reservation(&mut self, member_id: u32, packet_count: u32) {
        if let Some(member) = self.member_mut(member_id) {
            member.connection.release_data_reservation(packet_count);
        }
    }

    fn refresh_pending_states(&mut self) {
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

    fn mark_send_failure(&mut self, index: usize) {
        let member = &mut self.members[index];
        member.state = if member.connection.state() == ConnectionState::Connected
            && !member.connection.can_send()
        {
            GroupMemberState::Unstable
        } else {
            GroupMemberState::Broken
        };
    }

    fn requalify_unstable_members(&mut self) {
        for index in 0..self.members.len() {
            if self.members[index].state != GroupMemberState::Unstable
                || self.members[index].connection.state() != ConnectionState::Connected
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
