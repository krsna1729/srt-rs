//! The srt-proto side: `ReceiverBuffer` driven with the same packets and
//! times, observed only through its public (and `test-support`) API.

use srt_proto::receiver::ReceiverBuffer;
use srt_proto::wire::{DataPacket, PacketPosition};
use srt_proto::{Bytes, Timestamp};

use crate::model::{Admission, Delivered, Packet, Profile, Receiver, SeqRange, Snapshot};

/// srt-proto's receive buffer under the scenario profile.
pub struct SrtRsReceiver {
    buffer: ReceiverBuffer,
    profile: Profile,
}

impl SrtRsReceiver {
    /// A receiver for `profile`, its TSBPD time base and window taken from it.
    #[must_use]
    pub fn new(profile: Profile) -> Self {
        let buffer = ReceiverBuffer::with_buffer_size(
            profile.initial_seq,
            profile.latency_ms,
            Timestamp::from_micros(profile.time_base_us),
            i64::try_from(profile.time_base_us).expect("time base within the signed clock"),
            profile.capacity,
        );
        Self { buffer, profile }
    }

    fn ranges(ranges: impl IntoIterator<Item = srt_proto::receiver::LossRange>) -> Vec<SeqRange> {
        ranges
            .into_iter()
            .map(|range| SeqRange {
                first: range.first_seq,
                last: range.last_seq,
            })
            .collect()
    }
}

impl Receiver for SrtRsReceiver {
    fn insert(&mut self, packet: &Packet, now_us: u64) -> Admission {
        let before = self.buffer.stats();
        let data = DataPacket {
            sequence_number: packet.seq,
            position: PacketPosition::Single,
            order_flag: packet.order_flag,
            encryption_flag: 0,
            retransmitted: packet.retransmitted,
            message_number: packet.msgno,
            timestamp: packet.timestamp,
            dest_socket_id: 0,
            payload: Bytes::copy_from_slice(&packet.payload),
        };
        let _ = self.buffer.receive(data, Timestamp::from_micros(now_us));
        let after = self.buffer.stats();
        if after.total_received > before.total_received {
            Admission::Accepted
        } else if after.total_duplicates > before.total_duplicates {
            Admission::Old
        } else {
            Admission::NoRoom
        }
    }

    fn read(&mut self, now_us: u64) -> Option<Delivered> {
        let (packet, source_time) = self
            .buffer
            .pop_ready_with_source_time(Timestamp::from_micros(now_us))?;
        Some(Delivered {
            seq: packet.sequence_number,
            msgno: packet.message_number,
            play_time_us: source_time.as_micros() + self.profile.latency_us(),
            payload: packet.payload.to_vec(),
        })
    }

    fn service(&mut self, now_us: u64) -> Vec<SeqRange> {
        // The connection calls drop_too_late only with TLPKTDROP enabled
        // (`SrtConnection::service_receive_deadlines`).
        if !self.profile.tlpktdrop {
            return Vec::new();
        }
        Self::ranges(self.buffer.drop_too_late(Timestamp::from_micros(now_us)))
    }

    fn snapshot(&self, now_us: u64) -> Snapshot {
        let losses = self
            .buffer
            .generate_periodic_nak()
            .map(|nak| Self::ranges(nak.loss_ranges))
            .unwrap_or_default();
        Snapshot {
            ready: self
                .buffer
                .deliverable_sequence(Timestamp::from_micros(now_us))
                .is_some(),
            ack_seq: self.buffer.expected_sequence(),
            losses,
        }
    }
}
