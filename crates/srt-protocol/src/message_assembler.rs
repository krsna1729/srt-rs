use crate::Timestamp;
use crate::received_payload::{PayloadPages, PayloadRetirement, ReceivedPayload};
use crate::srt_packet::{DataPacket, PacketPosition, sequence_less_than};

pub(crate) struct AssembledMessage {
    pub payload: ReceivedPayload,
    pub message_number: u32,
    pub timestamp: u32,
    /// F01: the first fragment's source time (see
    /// `ReceiverBuffer::last_source_time`), carried through reassembly
    /// unchanged -- the same way `timestamp` already is.
    pub source_time: Timestamp,
    pub first_sequence_number: u32,
    pub packet_count: u32,
}

struct PartialMessage {
    message_number: u32,
    first_sequence_number: u32,
    next_expected_seq: u32,
    fragments: PayloadPages,
    timestamp: u32,
    source_time: Timestamp,
}

pub(crate) struct MessageAssembler {
    // Allocate fragmentation state only after First, not for every connection.
    pending: Option<Box<PartialMessage>>,
    retired: std::collections::VecDeque<PayloadRetirement>,
    retired_packets: u32,
}

impl MessageAssembler {
    pub fn new() -> Self {
        Self {
            pending: None,
            retired: std::collections::VecDeque::new(),
            retired_packets: 0,
        }
    }

    /// `source_time` is this specific packet's own source time (F01),
    /// already resolved by the receiver at pop time -- only the value from
    /// the `Single`/`First` fragment is ever retained; later fragments'
    /// values are ignored, matching how `timestamp` is already handled.
    pub fn feed(&mut self, packet: DataPacket, source_time: Timestamp) -> Option<AssembledMessage> {
        match packet.position {
            PacketPosition::Single => {
                self.discard_pending();
                Some(AssembledMessage {
                    first_sequence_number: packet.sequence_number,
                    message_number: packet.message_number,
                    timestamp: packet.timestamp,
                    source_time,
                    payload: packet.payload.into(),
                    packet_count: 1,
                })
            }
            PacketPosition::First => {
                self.discard_pending();
                let next_seq = packet.sequence_number.wrapping_add(1) & 0x7FFF_FFFF;
                let mut fragments = PayloadPages::default();
                fragments.push(packet.payload);
                self.pending = Some(Box::new(PartialMessage {
                    message_number: packet.message_number,
                    first_sequence_number: packet.sequence_number,
                    next_expected_seq: next_seq,
                    fragments,
                    timestamp: packet.timestamp,
                    source_time,
                }));
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
                    self.discard_pending();
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
                    let packet_count = partial.fragments.chunk_count() as u32;
                    Some(AssembledMessage {
                        payload: partial.fragments.finish(),
                        message_number: partial.message_number,
                        timestamp: partial.timestamp,
                        source_time: partial.source_time,
                        first_sequence_number: partial.first_sequence_number,
                        packet_count,
                    })
                } else {
                    self.discard_pending();
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
            self.discard_pending();
        }
    }

    pub fn pending_packet_count(&self) -> u32 {
        self.retired_packets.saturating_add(
            self.pending
                .as_ref()
                .map_or(0, |partial| partial.fragments.chunk_count() as u32),
        )
    }

    pub fn discard_before(&mut self, sequence_number: u32) {
        if self.pending.as_ref().is_some_and(|partial| {
            sequence_less_than(partial.first_sequence_number, sequence_number)
        }) {
            self.discard_pending();
        }
    }

    fn discard_pending(&mut self) {
        if let Some(partial) = self.pending.take() {
            self.retired_packets += partial.fragments.chunk_count() as u32;
            self.retired.push_back(partial.fragments.into_retirement());
        }
    }

    pub(crate) fn has_retired(&self) -> bool {
        !self.retired.is_empty()
    }

    pub(crate) fn reclaim_retired(&mut self, max_packets: usize) -> usize {
        let mut released = 0;
        while released < max_packets {
            let Some(retired) = self.retired.front_mut() else {
                break;
            };
            let before = retired.remaining_chunks();
            released += retired.reclaim(max_packets - released);
            self.retired_packets -= (before - retired.remaining_chunks()) as u32;
            if retired.is_complete() {
                self.retired.pop_front();
            }
        }
        released
    }

    pub(crate) fn begin_retirement(&mut self) {
        self.discard_pending();
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
            payload: payload.into(),
        }
    }

    #[test]
    fn single_packet_passes_through() {
        let mut asm = MessageAssembler::new();
        let pkt = data_packet(0, 0, PacketPosition::Single, vec![1, 2, 3]);
        let msg = asm
            .feed(pkt, Timestamp::from_micros(0))
            .expect("Single should emit immediately");
        assert!(msg.payload.eq(&[1, 2, 3][..]));
        assert_eq!(msg.message_number, 0);
        assert_eq!(msg.first_sequence_number, 0);
        assert_eq!(msg.packet_count, 1);
    }

    #[test]
    fn two_packet_message_reassembles() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(
                data_packet(10, 5, PacketPosition::First, vec![1, 2]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        let msg = asm
            .feed(
                data_packet(11, 5, PacketPosition::Last, vec![3, 4]),
                Timestamp::from_micros(0),
            )
            .expect("Last should complete the message");
        assert!(msg.payload.eq(&[1, 2, 3, 4][..]));
        assert_eq!(msg.message_number, 5);
        assert_eq!(msg.first_sequence_number, 10);
        assert_eq!(msg.packet_count, 2);
    }

    /// F01: a reassembled multi-fragment message must report the FIRST
    /// fragment's source time, not the last fragment's (which would
    /// silently understate age by however long reassembly took) and not
    /// the moment reassembly completed.
    #[test]
    fn multi_fragment_message_retains_the_first_fragments_source_time() {
        let mut asm = MessageAssembler::new();
        let first_source_time = Timestamp::from_micros(1_000_000);
        let last_source_time = Timestamp::from_micros(9_000_000);
        assert!(
            asm.feed(
                data_packet(10, 5, PacketPosition::First, vec![1, 2]),
                first_source_time
            )
            .is_none()
        );
        let msg = asm
            .feed(
                data_packet(11, 5, PacketPosition::Last, vec![3, 4]),
                last_source_time,
            )
            .expect("Last should complete the message");
        assert_eq!(
            msg.source_time, first_source_time,
            "must retain the first fragment's source time, not the last fragment's"
        );
    }

    #[test]
    fn three_packet_message_reassembles() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(
                data_packet(0, 1, PacketPosition::First, vec![10]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        assert!(
            asm.feed(
                data_packet(1, 1, PacketPosition::Middle, vec![20]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        let msg = asm
            .feed(
                data_packet(2, 1, PacketPosition::Last, vec![30]),
                Timestamp::from_micros(0),
            )
            .expect("Last completes");
        assert!(msg.payload.eq(&[10, 20, 30][..]));
        assert_eq!(msg.packet_count, 3);
    }

    #[test]
    fn incomplete_message_dropped_on_new_first() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(
                data_packet(0, 1, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        // New First for a different message drops the pending one.
        assert!(
            asm.feed(
                data_packet(2, 2, PacketPosition::First, vec![10]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        let msg = asm
            .feed(
                data_packet(3, 2, PacketPosition::Last, vec![20]),
                Timestamp::from_micros(0),
            )
            .expect("second message completes");
        assert!(msg.payload.eq(&[10, 20][..]));
        assert_eq!(msg.message_number, 2);
    }

    #[test]
    fn gap_in_sequence_drops_partial() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(
                data_packet(0, 1, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        // seq 1 is missing — seq 2 Middle doesn't match next_expected_seq.
        assert!(
            asm.feed(
                data_packet(2, 1, PacketPosition::Middle, vec![3]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        // Partial should be dropped.
        assert!(asm.pending.is_none());
    }

    #[test]
    fn drop_message_purges_partial() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(
                data_packet(0, 7, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
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
            asm.feed(
                data_packet(0, 7, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        asm.drop_message(99);
        assert!(asm.pending.is_some());
    }

    #[test]
    fn obsolete_partial_retains_credit_until_bounded_reclamation() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(
                data_packet(0x7fff_fffe, 7, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );

        asm.discard_before(0x7fff_fffe);
        assert_eq!(asm.pending_packet_count(), 1);

        asm.discard_before(1);
        assert_eq!(asm.pending_packet_count(), 1);
        assert_eq!(asm.reclaim_retired(0), 0);
        assert_eq!(asm.pending_packet_count(), 1);
        assert_eq!(asm.reclaim_retired(1), 1);
        assert_eq!(asm.pending_packet_count(), 0);
        assert!(
            asm.feed(
                data_packet(0x7fff_ffff, 7, PacketPosition::Last, vec![2]),
                Timestamp::from_micros(0),
            )
            .is_none(),
            "discarded partial must not regain delivery authority"
        );
    }

    #[test]
    fn message_number_wrap() {
        let mut asm = MessageAssembler::new();
        let msg_num = 0x03FF_FFFF; // max 26-bit value
        assert!(
            asm.feed(
                data_packet(0, msg_num, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        let msg = asm
            .feed(
                data_packet(1, msg_num, PacketPosition::Last, vec![2]),
                Timestamp::from_micros(0),
            )
            .expect("completes");
        assert_eq!(msg.message_number, msg_num);
        assert!(msg.payload.eq(&[1, 2][..]));
    }

    #[test]
    fn single_drops_pending_partial() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(
                data_packet(0, 1, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        let msg = asm
            .feed(
                data_packet(2, 2, PacketPosition::Single, vec![99]),
                Timestamp::from_micros(0),
            )
            .expect("Single emits");
        assert!(msg.payload.eq(&[99][..]));
        assert!(asm.pending.is_none());
    }

    #[test]
    fn wrong_message_number_on_middle_drops_partial() {
        let mut asm = MessageAssembler::new();
        assert!(
            asm.feed(
                data_packet(0, 1, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        assert!(
            asm.feed(
                data_packet(1, 2, PacketPosition::Middle, vec![2]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        assert!(asm.pending.is_none());
    }

    #[test]
    fn sequence_number_wraps_at_31_bit_boundary() {
        let mut asm = MessageAssembler::new();
        let max_seq = 0x7FFF_FFFE;
        assert!(
            asm.feed(
                data_packet(max_seq, 1, PacketPosition::First, vec![1]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        // Next seq wraps to max_seq + 1 = 0x7FFF_FFFF
        assert!(
            asm.feed(
                data_packet(0x7FFF_FFFF, 1, PacketPosition::Middle, vec![2]),
                Timestamp::from_micros(0)
            )
            .is_none()
        );
        // Next wraps to 0
        let msg = asm
            .feed(
                data_packet(0, 1, PacketPosition::Last, vec![3]),
                Timestamp::from_micros(0),
            )
            .expect("completes across wrap");
        assert!(msg.payload.eq(&[1, 2, 3][..]));
        assert_eq!(msg.first_sequence_number, max_seq);
    }

    fn assert_original_max_message_chunks(message: &AssembledMessage, pointers: &[*const u8]) {
        for (index, chunk) in message.payload.chunks().enumerate() {
            assert_eq!(
                chunk.as_ptr(),
                pointers[index],
                "packet data must not be copied"
            );
            if index == 64 {
                assert!(chunk.is_empty());
            } else {
                assert_eq!(chunk.as_ref(), &[index as u8]);
            }
        }
    }

    #[test]
    fn maximum_message_keeps_empty_chunks_order_and_source_time_across_wrap() {
        let mut asm = MessageAssembler::new();
        let count = crate::srt_handshake::MAX_FLOW_WINDOW as usize;
        let first_seq = 0x7fff_8000u32;
        let first_source = Timestamp::from_micros(123);
        let mut pointers = Vec::with_capacity(count);
        let mut message = None;
        for index in 0..count {
            let position = if index == 0 {
                PacketPosition::First
            } else if index == count - 1 {
                PacketPosition::Last
            } else {
                PacketPosition::Middle
            };
            let mut packet = data_packet(
                first_seq.wrapping_add(index as u32) & 0x7fff_ffff,
                9,
                position,
                if index == 64 {
                    Vec::new()
                } else {
                    vec![index as u8]
                },
            );
            packet.timestamp = index as u32 + 1000;
            pointers.push(packet.payload.as_ptr());
            message = asm.feed(
                packet,
                if index == 0 {
                    first_source
                } else {
                    Timestamp::from_micros(999)
                },
            );
            if index != count - 1 {
                assert!(message.is_none());
            }
        }
        let message = message.expect("the last fragment completes exactly one message");
        assert_eq!(message.packet_count, count as u32);
        assert_eq!(message.first_sequence_number, first_seq);
        assert_eq!(message.message_number, 9);
        assert_eq!(message.timestamp, 1000);
        assert_eq!(message.source_time, first_source);
        assert_eq!(message.payload.len(), count - 1);
        assert_eq!(message.payload.chunk_count(), count);
        assert_original_max_message_chunks(&message, &pointers);
    }
}
