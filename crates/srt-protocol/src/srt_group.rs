use std::collections::BTreeMap;

use crate::error::Error;
use crate::srt_connection::{ConnectionEvent, ConnectionState, SrtConnection};
use crate::srt_handshake::{GroupType, SRTGROUP_MASK};
use crate::srt_packet::sequence_less_than;
use crate::time::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMode {
    Broadcast,
    Backup,
}

impl GroupMode {
    pub fn from_group_type(group_type: GroupType) -> Option<Self> {
        match group_type {
            GroupType::Broadcast => Some(Self::Broadcast),
            GroupType::Backup => Some(Self::Backup),
            GroupType::Undefined => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupMemberState {
    Pending,
    Active,
    Standby,
    Broken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPacket {
    pub member_id: u32,
    pub sequence_number: u32,
    pub message_number: u32,
    pub timestamp: u32,
    pub payload: Vec<u8>,
}

pub struct SrtGroupMember {
    id: u32,
    weight: u16,
    state: GroupMemberState,
    connection: SrtConnection,
}

impl SrtGroupMember {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }

    pub fn state(&self) -> GroupMemberState {
        self.state
    }

    pub fn connection(&self) -> &SrtConnection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut SrtConnection {
        &mut self.connection
    }
}

pub struct SrtGroup {
    group_id: u32,
    mode: GroupMode,
    members: Vec<SrtGroupMember>,
    next_send_sequence: Option<u32>,
    next_receive_sequence: Option<u32>,
    pending: BTreeMap<u32, GroupPacket>,
}

impl SrtGroup {
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
        })
    }

    pub fn group_id(&self) -> u32 {
        self.group_id
    }

    pub fn mode(&self) -> GroupMode {
        self.mode
    }

    pub fn members(&self) -> &[SrtGroupMember] {
        &self.members
    }

    pub fn member(&self, member_id: u32) -> Option<&SrtGroupMember> {
        self.members.iter().find(|member| member.id == member_id)
    }

    pub fn member_mut(&mut self, member_id: u32) -> Option<&mut SrtGroupMember> {
        self.members
            .iter_mut()
            .find(|member| member.id == member_id)
    }

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
        self.align_member_sequence(member_id)?;
        Ok(())
    }

    pub fn mark_member_broken(&mut self, member_id: u32) -> bool {
        let Some(member) = self.member_mut(member_id) else {
            return false;
        };
        member.state = GroupMemberState::Broken;
        true
    }

    pub fn remove_member(&mut self, member_id: u32) -> bool {
        let Some(index) = self
            .members
            .iter()
            .position(|member| member.id == member_id)
        else {
            return false;
        };
        self.members.remove(index);
        true
    }

    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, Error> {
        self.refresh_states();
        match self.mode {
            GroupMode::Broadcast => self.send_broadcast(payload, now),
            GroupMode::Backup => self.send_backup(payload, now),
        }
    }

    pub fn poll_data(&mut self, now: Timestamp) -> Option<GroupPacket> {
        self.refresh_pending_states();
        self.collect_events();
        self.refresh_states();

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
        let following = next.wrapping_add(1) & 0x7FFF_FFFF;
        self.next_receive_sequence = Some(following);
        for member in &mut self.members {
            member.connection.advance_receive_sequence(following, now);
        }
        Some(packet)
    }

    fn send_broadcast(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, Error> {
        let active = self.active_indices();
        if active.is_empty() {
            return Err(Error::invalid_state("no active Broadcast group members"));
        }
        let sequence_number = self.sequence_for_send(&active)?;
        if active
            .iter()
            .any(|&index| !self.members[index].connection.can_send())
        {
            return Err(Error::invalid_state("Broadcast group send buffer is full"));
        }

        let mut sent = 0;
        for index in active {
            if self.members[index]
                .connection
                .send_with_sequence(payload, sequence_number, now)
                .is_ok()
            {
                sent += 1;
            } else {
                self.members[index].state = GroupMemberState::Broken;
            }
        }
        if sent == 0 {
            return Err(Error::invalid_state("all Broadcast group members failed"));
        }
        self.next_send_sequence = Some(sequence_number.wrapping_add(1) & 0x7FFF_FFFF);
        Ok(sent)
    }

    fn send_backup(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, Error> {
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
                .send_with_sequence(payload, sequence_number, now)
                .is_err()
        {
            self.members[index].state = GroupMemberState::Broken;
            self.promote_backup_member();
            let Some(index) = self.active_indices().into_iter().next() else {
                return Err(Error::invalid_state("all Backup group members failed"));
            };
            self.align_member_sequence(self.members[index].id)?;
            self.members[index]
                .connection
                .send_with_sequence(payload, sequence_number, now)
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
            while let Some((member_id, accept_data, event)) = {
                let member = &mut self.members[index];
                let accept_data =
                    self.mode == GroupMode::Broadcast || member.state == GroupMemberState::Active;
                member
                    .connection
                    .poll_event()
                    .map(|event| (member.id, accept_data, event))
            } {
                match event {
                    ConnectionEvent::DataReceived {
                        sequence_number,
                        message_number,
                        timestamp,
                        payload,
                    } if accept_data
                        && self
                            .next_receive_sequence
                            .is_none_or(|next| !sequence_less_than(sequence_number, next)) =>
                    {
                        self.pending.entry(sequence_number).or_insert(GroupPacket {
                            member_id,
                            sequence_number,
                            message_number,
                            timestamp,
                            payload,
                        });
                    }
                    ConnectionEvent::Disconnected { .. } | ConnectionEvent::Error(_) => {
                        self.members[index].state = GroupMemberState::Broken;
                        if self.mode == GroupMode::Backup {
                            self.promote_backup_member();
                        }
                    }
                    _ => {}
                }
            }
        }
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
        if self.mode == GroupMode::Backup && !self.has_active_member() {
            self.promote_backup_member();
        }
    }

    fn refresh_pending_states(&mut self) {
        for member in &mut self.members {
            if member.state == GroupMemberState::Pending
                && member.connection.state() == ConnectionState::Connected
            {
                member.state = if self.mode == GroupMode::Broadcast {
                    GroupMemberState::Active
                } else {
                    GroupMemberState::Standby
                };
            }
        }
        if self.mode == GroupMode::Backup && !self.has_active_member() {
            self.promote_backup_member();
        }
    }

    fn align_member_sequence(&mut self, member_id: u32) -> Result<(), Error> {
        let Some(sequence_number) = self.next_send_sequence else {
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
