#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{DataPacket, PacketPosition, ReceiverBuffer, Timestamp};

const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
// Keep individual fuzz executions cheap enough for sanitizer builds. Full
// 8192-position windows are covered by deterministic unit/property/benchmark
// cases; 256 positions still exercise every transition and 31-bit wrap.
const FUZZ_WINDOW: u32 = 256;

fn packet(sequence_number: u32, timestamp: u32, retransmitted: bool) -> DataPacket {
    DataPacket {
        sequence_number,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0,
        retransmitted,
        message_number: sequence_number & 0x03FF_FFFF,
        timestamp,
        dest_socket_id: 1,
        payload: Vec::new().into(),
    }
}

// Exercise classification-frontier transitions directly. The connection-feed
// target covers the wire path; this target can cheaply explore much longer
// receive/recovery/DROPREQ/forced-advance sequences, including 31-bit wrap.
fuzz_target!(|data: &[u8]| {
    let Some(initial_bytes) = data.get(..4) else {
        return;
    };
    let initial = u32::from_le_bytes(initial_bytes.try_into().unwrap()) & SEQUENCE_MASK;
    let mut receiver = ReceiverBuffer::new(initial, 120, Timestamp::default(), 0);
    receiver.set_tsbpd_enabled(false);
    let mut now_us = 1u64;

    for action in data[4..].chunks_exact(5) {
        let opcode = action[0];
        let raw = u16::from_le_bytes([action[1], action[2]]);
        let offset = u32::from(raw) % FUZZ_WINDOW;
        let seq = initial.wrapping_add(offset) & SEQUENCE_MASK;
        now_us = now_us.saturating_add(u64::from(action[3]) + 1);
        let now = Timestamp::from_micros(now_us);

        match opcode % 7 {
            0 => {
                let _ = receiver.receive(packet(seq, now_us as u32, false), now);
            }
            1 => {
                let drop_offset = if action[4] & 0x80 == 0 {
                    offset
                } else {
                    8_192 + offset
                };
                let seq = initial.wrapping_add(drop_offset) & SEQUENCE_MASK;
                let distance = u32::from(action[4]) % FUZZ_WINDOW;
                let last = seq.wrapping_add(distance) & SEQUENCE_MASK;
                let _ = receiver.drop_range(seq, last);
            }
            2 => receiver.advance_expected_sequence(seq),
            3 => {
                while receiver.pop_ready(now).is_some() {}
            }
            4 => {
                let _ = receiver.drop_too_late(Timestamp::from_micros(
                    now_us.saturating_add(2_000_000),
                ));
            }
            5 => {
                if let Some(nak) = receiver.generate_periodic_nak() {
                    assert!(nak.loss_list.windows(2).all(|pair| pair[0] < pair[1]));
                    assert!(receiver.stats().total_lost >= nak.loss_list.len() as u64);
                    assert!(nak.loss_list.iter().all(|&loss| {
                        loss.wrapping_sub(receiver.expected_sequence()) & SEQUENCE_MASK < 8_192
                    }));
                }
            }
            _ => {
                let retransmitted = action[4] & 1 != 0;
                let packet = packet(seq, now_us as u32, retransmitted);
                let _ = receiver.receive(packet.clone(), now);
                let _ = receiver.receive(packet, now);
            }
        }
    }
});
