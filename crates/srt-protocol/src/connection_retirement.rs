use super::{ConnectionEvent, ConnectionState, SrtConnection};
use crate::PayloadRetirement;

/// A terminal connection's retained storage, reclaimed on its owning thread.
///
/// No protocol input, output or timer may be serviced after this cutover.
/// The transport must retain the connection's admission/memory reservation
/// until `is_complete` is true. Dropping an incomplete cursor is synchronous;
/// Owner paths must drive it to completion with finite per-turn budgets.
#[must_use]
pub struct ConnectionRetirement {
    connection: SrtConnection,
    payload: PayloadRetirement,
    sender_empty: bool,
    receiver_empty: bool,
}

impl SrtConnection {
    /// Relinquish protocol authority without destroying retained packet storage.
    pub fn into_retirement(mut self) -> ConnectionRetirement {
        self.state = ConnectionState::Disconnected;
        self.clear_config_secrets();
        self.assembler.begin_retirement();
        let sender_empty = self
            .sender
            .as_mut()
            .is_none_or(|sender| sender.reclaim_terminal(0).1);
        let receiver_empty = self
            .receiver
            .as_mut()
            .is_none_or(|receiver| receiver.reclaim_terminal(0).1);
        ConnectionRetirement {
            connection: self,
            payload: PayloadRetirement::default(),
            sender_empty,
            receiver_empty,
        }
    }
}

impl ConnectionRetirement {
    /// Release at most `max_actions` retained packet chunks, queued events,
    /// queued outputs or bounded NAK descriptors. Zero performs no work.
    /// Fixed-size empty window directories and crypto state leave at completion.
    pub fn reclaim(&mut self, max_actions: usize) -> usize {
        let mut used = 0;
        while used < max_actions {
            if !self.payload.is_complete() {
                used += self.payload.reclaim(max_actions - used);
            } else if let Some(event) = self.connection.event_queue.pop_front() {
                if let ConnectionEvent::DataReceived { payload, .. } = event {
                    self.payload = payload.retire();
                }
                used += 1;
            } else if self.connection.assembler.has_retired() {
                used += self
                    .connection
                    .assembler
                    .reclaim_retired(max_actions - used);
            } else if !self.receiver_empty {
                let (released, complete) = self
                    .connection
                    .receiver
                    .as_mut()
                    .expect("nonempty receiver retained")
                    .reclaim_terminal(max_actions - used);
                used += released;
                self.receiver_empty = complete;
            } else if !self.sender_empty {
                let (released, complete) = self
                    .connection
                    .sender
                    .as_mut()
                    .expect("nonempty sender retained")
                    .reclaim_terminal(max_actions - used);
                used += released;
                self.sender_empty = complete;
            } else if self.connection.output_queue.pop_front().is_some()
                || self.connection.periodic_nak_packets.pop().is_some()
            {
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
            && self.connection.event_queue.is_empty()
            && !self.connection.assembler.has_retired()
            && self.receiver_empty
            && self.sender_empty
            && self.connection.output_queue.is_empty()
            && self.connection.periodic_nak_packets.is_empty()
    }
}
