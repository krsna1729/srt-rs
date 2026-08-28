use crate::srt_packet::{DataPacket, PacketPosition};

pub(crate) struct AssembledMessage {
    pub payload: Vec<u8>,
    pub message_number: u32,
    pub timestamp: u32,
    pub first_sequence_number: u32,
}

struct PartialMessage {
    message_number: u32,
    first_sequence_number: u32,
    next_expected_seq: u32,
    fragments: Vec<Vec<u8>>,
    timestamp: u32,
}

pub(crate) struct MessageAssembler {
    pending: Option<PartialMessage>,
}

impl MessageAssembler {
    pub fn new() -> Self {
        Self { pending: None }
    }

    pub fn feed(&mut self, packet: DataPacket) -> Option<AssembledMessage> {
        match packet.position {
            PacketPosition::Single => {
                self.pending = None;
                Some(AssembledMessage {
                    first_sequence_number: packet.sequence_number,
                    message_number: packet.message_number,
                    timestamp: packet.timestamp,
                    payload: packet.payload,
                })
            }
            PacketPosition::First => {
                let next_seq = packet.sequence_number.wrapping_add(1) & 0x7FFF_FFFF;
                self.pending = Some(PartialMessage {
                    message_number: packet.message_number,
                    first_sequence_number: packet.sequence_number,
                    next_expected_seq: next_seq,
                    fragments: vec![packet.payload],
                    timestamp: packet.timestamp,
                });
                None
            }
            PacketPosition::Middle => {
                let matched = self.pending.as_ref().is_some_and(|p| {
                    p.message_number == packet.message_number
                        && p.next_expected_seq == packet.sequence_number
                });
                if matched {
                    let partial = self.pending.as_mut().unwrap();
                    partial.fragments.push(packet.payload);
                    partial.next_expected_seq =
                        packet.sequence_number.wrapping_add(1) & 0x7FFF_FFFF;
                    None
                } else {
                    self.pending = None;
                    None
                }
            }
            PacketPosition::Last => {
                let matched = self.pending.as_ref().is_some_and(|p| {
                    p.message_number == packet.message_number
                        && p.next_expected_seq == packet.sequence_number
                });
                if matched {
                    let mut partial = self.pending.take().unwrap();
                    partial.fragments.push(packet.payload);
                    let total_len: usize = partial.fragments.iter().map(|f| f.len()).sum();
                    let mut payload = Vec::with_capacity(total_len);
                    for frag in partial.fragments {
                        payload.extend_from_slice(&frag);
                    }
                    Some(AssembledMessage {
                        payload,
                        message_number: partial.message_number,
                        timestamp: partial.timestamp,
                        first_sequence_number: partial.first_sequence_number,
                    })
                } else {
                    self.pending = None;
                    None
                }
            }
        }
    }

    pub fn drop_message(&mut self, message_number: u32) {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.message_number == message_number)
        {
            self.pending = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_packet(seq: u32, msg: u32, position: PacketPosition, payload: Vec<u8>) -> DataPacket {
        DataPacket {
            sequence_number: seq,
            position,
            order_flag: true,
            encryption_flag: 0,
            retransmitted: false,
            message_number: msg,
            timestamp: 1000,
            dest_socket_id: 1,
            payload,
        }
    }

    #[test]
    fn single_packet_passes_through() {
        let mut asm = MessageAssembler::new();
        let pkt = data_packet(0, 0, PacketPosition::Single, vec![1, 2, 3]);
        let msg = asm.feed(pkt).expect("Single should emit immediately");
        assert_eq!(msg.payload, vec![1, 2, 3]);
        assert_eq!(msg.message_number, 0);
        assert_eq!(msg.first_sequence_number, 0);
    }

    #[test]
    fn two_packet_message_reassembles() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(data_packet(10, 5, PacketPosition::First, vec![1, 2]))
                .is_none()
        );
        let msg = asm
            .feed(data_packet(11, 5, PacketPosition::Last, vec![3, 4]))
            .expect("Last should complete the message");
        assert_eq!(msg.payload, vec![1, 2, 3, 4]);
        assert_eq!(msg.message_number, 5);
        assert_eq!(msg.first_sequence_number, 10);
    }

    #[test]
    fn three_packet_message_reassembles() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(data_packet(0, 1, PacketPosition::First, vec![10]))
                .is_none()
        );
        assert!(
            asm.feed(data_packet(1, 1, PacketPosition::Middle, vec![20]))
                .is_none()
        );
        let msg = asm
            .feed(data_packet(2, 1, PacketPosition::Last, vec![30]))
            .expect("Last completes");
        assert_eq!(msg.payload, vec![10, 20, 30]);
    }

    #[test]
    fn incomplete_message_dropped_on_new_first() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(data_packet(0, 1, PacketPosition::First, vec![1]))
                .is_none()
        );
        // New First for a different message drops the pending one.
        assert!(
            asm.feed(data_packet(2, 2, PacketPosition::First, vec![10]))
                .is_none()
        );
        let msg = asm
            .feed(data_packet(3, 2, PacketPosition::Last, vec![20]))
            .expect("second message completes");
        assert_eq!(msg.payload, vec![10, 20]);
        assert_eq!(msg.message_number, 2);
    }

    #[test]
    fn gap_in_sequence_drops_partial() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(data_packet(0, 1, PacketPosition::First, vec![1]))
                .is_none()
        );
        // seq 1 is missing — seq 2 Middle doesn't match next_expected_seq.
        assert!(
            asm.feed(data_packet(2, 1, PacketPosition::Middle, vec![3]))
                .is_none()
        );
        // Partial should be dropped.
        assert!(asm.pending.is_none());
    }

    #[test]
    fn drop_message_purges_partial() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(data_packet(0, 7, PacketPosition::First, vec![1]))
                .is_none()
        );
        assert!(asm.pending.is_some());
        asm.drop_message(7);
        assert!(asm.pending.is_none());
    }

    #[test]
    fn drop_message_ignores_different_number() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(data_packet(0, 7, PacketPosition::First, vec![1]))
                .is_none()
        );
        asm.drop_message(99);
        assert!(asm.pending.is_some());
    }

    #[test]
    fn message_number_wrap() {
        let mut asm = MessageAssembler::new();
        let msg_num = 0x03FF_FFFF; // max 26-bit value
        assert!(
            asm.feed(data_packet(0, msg_num, PacketPosition::First, vec![1]))
                .is_none()
        );
        let msg = asm
            .feed(data_packet(1, msg_num, PacketPosition::Last, vec![2]))
            .expect("completes");
        assert_eq!(msg.message_number, msg_num);
        assert_eq!(msg.payload, vec![1, 2]);
    }

    #[test]
    fn single_drops_pending_partial() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(data_packet(0, 1, PacketPosition::First, vec![1]))
                .is_none()
        );
        let msg = asm
            .feed(data_packet(2, 2, PacketPosition::Single, vec![99]))
            .expect("Single emits");
        assert_eq!(msg.payload, vec![99]);
        assert!(asm.pending.is_none());
    }

    #[test]
    fn wrong_message_number_on_middle_drops_partial() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(data_packet(0, 1, PacketPosition::First, vec![1]))
                .is_none()
        );
        assert!(
            asm.feed(data_packet(1, 2, PacketPosition::Middle, vec![2]))
                .is_none()
        );
        assert!(asm.pending.is_none());
    }

    #[test]
    fn sequence_number_wraps_at_31_bit_boundary() {
        let mut asm = MessageAssembler::new();
        let max_seq = 0x7FFF_FFFE;
        assert!(
            asm.feed(data_packet(max_seq, 1, PacketPosition::First, vec![1]))
                .is_none()
        );
        // Next seq wraps to max_seq + 1 = 0x7FFF_FFFF
        assert!(
            asm.feed(data_packet(0x7FFF_FFFF, 1, PacketPosition::Middle, vec![2]))
                .is_none()
        );
        // Next wraps to 0
        let msg = asm
            .feed(data_packet(0, 1, PacketPosition::Last, vec![3]))
            .expect("completes across wrap");
        assert_eq!(msg.payload, vec![1, 2, 3]);
        assert_eq!(msg.first_sequence_number, max_seq);
    }
}
