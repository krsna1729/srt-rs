use super::{GroupEvent, SrtGroup};
use crate::{ConnectionRetirement, PayloadRetirement};

/// Terminal group storage, including member reservation indexes and cores.
/// The transport retains all admission/memory credit until this is complete.
#[must_use]
pub struct GroupRetirement {
    group: SrtGroup,
    connection: Option<ConnectionRetirement>,
    payload: PayloadRetirement,
}

impl SrtGroup {
    /// Relinquish the entire group's authority without merging or destroying
    /// member reservation indexes, pending messages, or connection windows.
    pub fn into_retirement(self) -> GroupRetirement {
        GroupRetirement {
            group: self,
            connection: None,
            payload: PayloadRetirement::default(),
        }
    }
}

impl GroupRetirement {
    /// Release at most `max_actions` chunks, index entries, events or member
    /// transitions. Zero performs no work. No member-removal merge is needed
    /// because a terminal group will never deliver or admit another message.
    pub fn reclaim(&mut self, max_actions: usize) -> usize {
        let mut used = 0;
        while used < max_actions {
            if !self.payload.is_complete() {
                used += self.payload.reclaim(max_actions - used);
            } else if let Some(connection) = self.connection.as_mut() {
                used += connection.reclaim(max_actions - used);
                if connection.is_complete() && used < max_actions {
                    self.connection = None;
                    used += 1;
                }
            } else if let Some((_, packet)) = self.group.pending.pop_first() {
                self.payload = packet.payload.retire();
                used += 1;
            } else if let Some(event) = self.group.events.pop_front() {
                if let GroupEvent::DataReceived(packet) = event {
                    self.payload = packet.payload.retire();
                }
                used += 1;
            } else if self.group.owned.pop_first().is_some() {
                used += 1;
            } else if let Some(member) = self.group.members.last_mut() {
                if member.reserved.pop_first().is_none() {
                    let member = self.group.members.pop().expect("member retained");
                    self.connection = Some(member.connection.into_retirement());
                }
                used += 1;
            } else if self.group.collisions.pop_front().is_some() {
                used += 1;
            } else {
                break;
            }
        }
        used
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.payload.is_complete()
            && self.connection.is_none()
            && self.group.pending.is_empty()
            && self.group.events.is_empty()
            && self.group.owned.is_empty()
            && self.group.members.is_empty()
            && self.group.collisions.is_empty()
    }
}
