//! The send side of a bonded group: fanning one logical payload out over
//! its members per [`GroupMode`], and the member health a failed send
//! reports.

use bytes::Bytes;

use super::{GroupMemberState, GroupMode, MAX_BACKUP_HISTORY, SrtGroup};
use crate::error::Error;
use crate::srt_connection::ConnectionState;
use crate::srt_packet::sequence_less_than;
use crate::time::Timestamp;

impl SrtGroup {
    /// Send one payload through the group per its [`GroupMode`]. Returns the
    /// number of members it was actually sent on.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, Error> {
        self.refresh_states();
        self.validate_payload_size(payload.len())?;
        self.send_mode(Bytes::copy_from_slice(payload), now)
    }

    /// Send shared payload data across group members. Uses reference-counted
    /// `Bytes` to avoid deep-copying the payload for each leg.
    pub fn send_shared(&mut self, payload: Bytes, now: Timestamp) -> Result<usize, Error> {
        self.refresh_states();
        self.validate_payload_size(payload.len())?;
        self.send_mode(payload, now)
    }

    fn validate_payload_size(&self, payload_len: usize) -> Result<(), Error> {
        // Reject an oversized payload once, here, before the per-member fan-out.
        // `send_broadcast`/`send_backup` route a member connection's rejection
        // through `mark_send_failure`, which has no way to tell "this payload
        // is too large for every leg" apart from an actual member health
        // problem -- since the window is open, it would score as `Broken`
        // (permanent, no requalify path) and, for a same-size payload,
        // deterministically do that to every active member. There is no
        // group-level fragmenting send to fall back to (`send`/`send_shared`
        // are the only group entry points), so this must be the caller's
        // error, not the group's.
        if let Some(&first) = self.active_indices().first() {
            let limit = self.members[first].connection.effective_max_payload_size();
            if payload_len > limit {
                return Err(Error::invalid_state(
                    "payload exceeds the maximum single-packet size for this group",
                ));
            }
        }
        Ok(())
    }

    fn send_mode(&mut self, payload: Bytes, now: Timestamp) -> Result<usize, Error> {
        match self.mode {
            GroupMode::Broadcast => self.send_broadcast(payload, now),
            GroupMode::Backup => self.send_backup(payload, now),
        }
    }

    /// Whether the group can accept the next logical send, including takeover.
    ///
    /// Broadcast attempts every active leg, but its logical send succeeds as
    /// soon as any member accepts the payload. A member whose sender window
    /// is full becomes temporarily unstable; once its in-flight packets drain
    /// it is sequence-aligned and automatically rejoins the active set. Backup
    /// promotes a standby member while an unstable leg requalifies.
    pub fn can_send(&mut self) -> bool {
        self.refresh_states();
        if self.mode == GroupMode::Backup {
            return self.backup_send_ready(None);
        }
        let active = self.active_indices();
        match self.mode {
            GroupMode::Broadcast => active
                .iter()
                .any(|&index| self.members[index].connection.can_send()),
            GroupMode::Backup => unreachable!("Backup readiness handled above"),
        }
    }

    pub fn can_send_with_pacing(&mut self, now: Timestamp) -> bool {
        self.refresh_states();
        if self.mode == GroupMode::Backup {
            self.demote_stale_backup_carrier(now);
            if !self.has_active_member() {
                self.promote_backup_member();
            }
            return self.backup_send_ready(Some(now));
        }
        let active = self.active_indices();
        match self.mode {
            GroupMode::Broadcast => active
                .iter()
                .any(|&index| self.members[index].connection.can_send_with_pacing(now)),
            GroupMode::Backup => unreachable!("Backup readiness handled above"),
        }
    }

    /// Readiness includes the same pressure takeover that `send_backup`
    /// attempts. Merely waiting for a full active window must not hide a
    /// standby able to replay the complete retained flight plus a new packet.
    fn backup_send_ready(&mut self, now: Option<Timestamp>) -> bool {
        if let Some(carrier) = self
            .backup_carrier
            .and_then(|id| self.members.iter().position(|member| member.id == id))
        {
            self.trim_backup_history(carrier);
        }
        let Some(index) = self.members.iter().position(|member| {
            member.state == GroupMemberState::Active
                && member.connection.state() == ConnectionState::Connected
        }) else {
            return false;
        };
        if self.members[index].connection.can_send() {
            return self.backup_member_ready(index, now);
        }
        // Match `promote_backup_member`'s priority, rather than advertising
        // a lower-priority leg that the actual send would not choose.
        self.members
            .iter()
            .enumerate()
            .filter(|(_, member)| {
                member.state == GroupMemberState::Standby
                    && member.connection.state() == ConnectionState::Connected
            })
            .max_by_key(|(_, member)| (member.weight, std::cmp::Reverse(member.id)))
            .is_some_and(|(index, _)| self.backup_member_ready(index, now))
    }

    fn backup_member_ready(&self, index: usize, now: Option<Timestamp>) -> bool {
        let member = &self.members[index];
        let connection = &member.connection;
        if !now.map_or_else(
            || connection.can_send(),
            |now| connection.can_send_with_pacing(now),
        ) {
            return false;
        }
        let Some(sender) = connection.sender_buffer() else {
            return false;
        };
        let takes_over = self.backup_carrier.is_some_and(|id| id != member.id);
        let replay = if takes_over {
            self.backup_history.len()
        } else {
            0
        };
        let sequence = self
            .backup_history
            .front()
            .filter(|_| takes_over)
            .map(|&(sequence, _, _)| sequence)
            .or(self.next_send_sequence);
        (!takes_over || replay == 0 || !self.backup_history_gap)
            && (sender.remaining_window_packets() as usize) > replay
            && sequence.is_none_or(|sequence| {
                connection.next_sequence_number() == Some(sequence) || sender.is_empty()
            })
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

    /// One Backup send. A carrier that stopped hearing from its peer is
    /// demoted first; a member that takes over from another carrier replays
    /// the unacknowledged flight before the new payload, so the receiver
    /// gets no hole; a takeover that cannot replay all of it is refused.
    fn send_backup(&mut self, payload: Bytes, now: Timestamp) -> Result<usize, Error> {
        self.demote_stale_backup_carrier(now);
        let mut active = self.active_indices().into_iter().next();
        if active.is_none() {
            self.promote_backup_member();
            active = self.active_indices().into_iter().next();
        }
        let Some(mut index) = active else {
            return Err(Error::invalid_state("no active Backup group members"));
        };

        self.take_over_backup_flight(index, now)?;
        let sequence_number = self.sequence_for_send(&[index])?;
        if !self.members[index].connection.can_send()
            || self.members[index]
                .connection
                .send_shared_with_sequence(payload.clone(), sequence_number, now)
                .is_err()
        {
            self.mark_send_failure(index);
            self.promote_backup_member();
            let Some(promoted) = self.active_indices().into_iter().next() else {
                return Err(Error::invalid_state("all Backup group members failed"));
            };
            index = promoted;
            self.take_over_backup_flight(index, now)?;
            self.members[index]
                .connection
                .send_shared_with_sequence(payload.clone(), sequence_number, now)
                .map_err(|_| Error::invalid_state("Backup promotion send failed"))?;
        }
        self.next_send_sequence = Some(sequence_number.wrapping_add(1) & 0x7FFF_FFFF);
        self.record_backup_send(index, sequence_number, payload, now);
        Ok(1)
    }

    /// Demote the Backup carrier to [`GroupMemberState::Unstable`] when it
    /// holds unacknowledged data and has heard nothing from its peer for
    /// longer than [`Self::backup_stability_timeout_micros`], and a connected
    /// standby can take over. Its connection stays up; it requalifies once
    /// its flight drains.
    fn demote_stale_backup_carrier(&mut self, now: Timestamp) {
        let Some(index) = self.members.iter().position(|member| {
            member.state == GroupMemberState::Active
                && member.connection.state() == ConnectionState::Connected
        }) else {
            return;
        };
        let standby = self.members.iter().any(|member| {
            member.state == GroupMemberState::Standby
                && member.connection.state() == ConnectionState::Connected
        });
        if !standby {
            return;
        }
        let Some(timeout) = self.backup_stability_timeout_micros(self.members[index].id) else {
            return;
        };
        let connection = &self.members[index].connection;
        let Some(sender) = connection.sender_buffer() else {
            return;
        };
        if !sender.has_outstanding_submitted_data() {
            return;
        }
        let Some(admitted) = sender.oldest_packet_time() else {
            return;
        };
        let heard = connection
            .last_recv_time()
            .map_or(admitted, |received| received.max(admitted));
        if now.saturating_sub(heard) > timeout {
            self.members[index].state = GroupMemberState::Unstable;
        }
    }

    /// Prepare the member at `index` to carry the next Backup send: the
    /// previous carrier's still unacknowledged flight is replayed onto it,
    /// at the same sequences, when it takes over; otherwise it is aligned to
    /// the group sequence.
    fn take_over_backup_flight(&mut self, index: usize, now: Timestamp) -> Result<(), Error> {
        let member_id = self.members[index].id;
        let carrier = self
            .backup_carrier
            .filter(|&carrier| carrier != member_id)
            .and_then(|carrier| self.members.iter().position(|member| member.id == carrier));
        if let Some(carrier) = carrier {
            // ACKs that arrived since the carrier's last send.
            self.trim_backup_history(carrier);
        }
        let takes_over = self
            .backup_carrier
            .is_some_and(|carrier| carrier != member_id);
        let Some(&(first, _, _)) = self.backup_history.front().filter(|_| takes_over) else {
            return if self.next_send_sequence.is_some() {
                self.align_member_sequence(member_id)
            } else {
                Ok(())
            };
        };
        let refused =
            || Error::invalid_state("Backup failover cannot replay the unacknowledged interval");
        if self.backup_history_gap {
            return Err(refused());
        }
        let connection = &mut self.members[index].connection;
        if connection.next_sequence_number() != Some(first) {
            connection
                .synchronize_send_sequence(first)
                .map_err(|_| refused())?;
        }
        let room = connection
            .sender_buffer()
            .map_or(0, |sender| sender.remaining_window_packets());
        if (room as usize) <= self.backup_history.len() {
            return Err(refused());
        }
        for (sequence, payload, source_time) in &self.backup_history {
            connection
                .send_shared_with_sequence_at(payload.clone(), *sequence, *source_time, now)
                .map_err(|_| refused())?;
        }
        Ok(())
    }

    /// Keep a sent payload until its carrier's peer acknowledges it.
    fn record_backup_send(&mut self, index: usize, sequence: u32, payload: Bytes, now: Timestamp) {
        self.backup_carrier = Some(self.members[index].id);
        if self.backup_history.len() >= MAX_BACKUP_HISTORY {
            self.backup_history.pop_front();
        }
        self.backup_history.push_back((sequence, payload, now));
        self.trim_backup_history(index);
    }

    /// Drop what the carrier at `index` has had acknowledged, and note
    /// whether the history still reaches back to its oldest unacknowledged
    /// sequence (the bound may have evicted older ones).
    fn trim_backup_history(&mut self, index: usize) {
        let Some(oldest) = self.members[index]
            .connection
            .sender_buffer()
            .map(|sender| sender.oldest_unacked_sequence())
        else {
            return;
        };
        while self
            .backup_history
            .front()
            .is_some_and(|&(front, _, _)| sequence_less_than(front, oldest))
        {
            self.backup_history.pop_front();
        }
        self.backup_history_gap = self
            .backup_history
            .front()
            .is_some_and(|&(front, _, _)| sequence_less_than(oldest, front));
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
}
