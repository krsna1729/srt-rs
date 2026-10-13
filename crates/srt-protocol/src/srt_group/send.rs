//! The send side of a bonded group: fanning one logical payload out over
//! its members per [`GroupMode`], and the member health a failed send
//! reports.

use bytes::Bytes;

use super::{GroupMemberState, GroupMode, SrtGroup};
use crate::error::Error;
use crate::srt_connection::ConnectionState;
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
