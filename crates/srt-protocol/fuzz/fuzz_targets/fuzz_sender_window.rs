#![no_main]

//! Focused fuzzing for the sender window's loss-report and drop semantics.
//!
//! The actions are the ones the protocol actually performs -- push, submit,
//! cumulative ACK, advertised receive window, NAK, TLPKTDROP, retransmit,
//! sequence resynchronization -- driven with fuzzer-chosen arguments, so the
//! transactional NAK validation and the TLPKTDROP tombstone bookkeeping are
//! explored across sequence wrap, dense ranges, repeated reports and
//! all-tombstone windows.
//!
//! Invariants:
//!
//! * the retained span never exceeds the negotiated window (bounded memory);
//! * live flight never exceeds the retained span, and is exactly the retained
//!   span minus the tombstones that are still unacknowledged;
//! * a tombstoned sequence is never DATA-retransmitted;
//! * a retransmission always names a position that was actually pushed;
//! * payload accounting is bounded by what was pushed, and is exactly zero
//!   once every retained position is a tombstone.

use libfuzzer_sys::fuzz_target;
use srt_proto::Timestamp;
use srt_proto::receiver::LossRange;
use srt_proto::sender::SenderBuffer;

const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
const HALF_RANGE: u32 = 0x4000_0000;
const WINDOW: u32 = 64;

/// Whether `sequence` lies behind `ack_seq` in 31-bit circular order.
fn behind(sequence: u32, ack_seq: u32) -> bool {
    ack_seq.wrapping_sub(sequence) & SEQUENCE_MASK != 0
        && (ack_seq.wrapping_sub(sequence) & SEQUENCE_MASK) < HALF_RANGE
}

fuzz_target!(|data: &[u8]| {
    let Some(initial_bytes) = data.get(..4) else {
        return;
    };
    let initial_seq = u32::from_le_bytes(initial_bytes.try_into().unwrap()) & SEQUENCE_MASK;
    let mut sender = SenderBuffer::new(initial_seq, WINDOW, 10);
    // Positions whose media has been dropped and not yet acknowledged.
    let mut tombstones: Vec<u32> = Vec::new();
    let mut pushed: Vec<u32> = Vec::new();
    let mut payload_bytes_pushed = 0u64;
    // Mirrors the sender's own cumulative position, so the tracker can tell an
    // effective ACK (which retires the prefix) from a stale or impossible one
    // (which the sender ignores).
    let mut oldest_unacked = initial_seq;
    let mut now_us = 1_000u64;

    for action in data[4..].chunks(9) {
        let op = action[0] % 9;
        let first = u32::from_le_bytes([
            action.get(1).copied().unwrap_or_default(),
            action.get(2).copied().unwrap_or_default(),
            action.get(3).copied().unwrap_or_default(),
            action.get(4).copied().unwrap_or_default(),
        ]) & SEQUENCE_MASK;
        let second = u32::from_le_bytes([
            action.get(5).copied().unwrap_or_default(),
            action.get(6).copied().unwrap_or_default(),
            action.get(7).copied().unwrap_or_default(),
            action.get(8).copied().unwrap_or_default(),
        ]) & SEQUENCE_MASK;
        now_us = now_us.saturating_add(u64::from(action[0]) * 1_000);
        let now = Timestamp::from_micros(now_us);

        match op {
            0 | 1 => {
                let next = sender.next_sequence_number();
                let payload = vec![
                    action[0];
                    1 + usize::from(action.get(1).copied().unwrap_or_default() % 8)
                ];
                let payload_len = payload.len() as u64;
                if let Some((header, _)) = sender.push(payload, 1, 1, now) {
                    assert_eq!(header.sequence_number, next);
                    if sender.retained_span() == 1 {
                        // The window was empty, so the sender resumes from here.
                        oldest_unacked = next;
                    }
                    // A real sender marks the datagram submitted once the
                    // transport has materialized it; that is the boundary of
                    // what a loss report may name.
                    sender.note_data_submitted(header.sequence_number);
                    pushed.push(next);
                    payload_bytes_pushed += payload_len;
                }
            }
            2 => {
                let span = sender.retained_span();
                let distance = first.wrapping_sub(oldest_unacked) & SEQUENCE_MASK;
                sender.handle_ack(first);
                // Only an ACK the sender actually acted on retires anything:
                // the same rule its own `discard_acked` applies.
                if distance != 0 && distance <= span {
                    oldest_unacked = first;
                    tombstones.retain(|&sequence| !behind(sequence, first));
                    pushed.retain(|&sequence| !behind(sequence, first));
                }
            }
            3 => {
                sender.set_peer_window(first, second % (WINDOW * 2));
            }
            4 | 5 => {
                let span = u32::from(action.get(1).copied().unwrap_or_default() % 96);
                let report = [LossRange {
                    first_seq: first,
                    last_seq: first.wrapping_add(span) & SEQUENCE_MASK,
                }];
                let answered = sender.handle_nak_ranges(&report);
                assert!(
                    answered.len() <= 16,
                    "one report cannot be amplified into unbounded DROPREQ batches"
                );
                for message in answered {
                    // A repeated DROPREQ always names a position this sender
                    // had already given up.
                    assert!(
                        tombstones.contains(&message.first_seq),
                        "DROPREQ for a position that was never dropped"
                    );
                }
            }
            6 => {
                for message in sender.drop_expired(Timestamp::from_micros(now_us + 2_000_000)) {
                    let mut current = message.first_seq;
                    loop {
                        if !tombstones.contains(&current) {
                            tombstones.push(current);
                        }
                        if current == message.last_seq {
                            break;
                        }
                        current = current.wrapping_add(1) & SEQUENCE_MASK;
                    }
                }
            }
            7 => {
                if let Some((header, payload)) = sender.pop_retransmit(1) {
                    assert!(
                        !tombstones.contains(&header.sequence_number),
                        "a tombstone was DATA-retransmitted"
                    );
                    assert!(
                        pushed.contains(&header.sequence_number),
                        "a retransmission named a position that was never pushed"
                    );
                    assert!(!payload.is_empty(), "live media is retained");
                }
            }
            _ => {
                // A wrapped dense report, and a message admission check: both
                // are bounded queries that must agree with the retained state.
                let wrapped = [LossRange {
                    first_seq: second,
                    last_seq: first.wrapping_sub(1) & SEQUENCE_MASK,
                }];
                let _ = sender.handle_nak_ranges(&wrapped);
                let _ = sender.can_send_message((second % 8) as usize + 1);
            }
        }

        // Invariants that must hold after every action.
        let retained = sender.retained_span();
        let live = sender.packets_in_flight();
        assert!(retained <= WINDOW, "retained span exceeded the window");
        assert!(live <= retained, "flight exceeded the retained span");
        // Every unacknowledged tombstone, and only those, is excluded from the
        // live count: nothing but a cumulative ACK retires a retained
        // position, and the tracked set is pruned by exactly that ACK.
        assert!(
            tombstones.len() as u32 <= retained,
            "tracked tombstones exceed the retained span"
        );
        assert_eq!(
            live,
            retained - tombstones.len() as u32,
            "tombstone accounting diverged"
        );
        let stats = sender.stats();
        assert_eq!(stats.packets_in_buffer, retained);
        assert_eq!(stats.packets_in_flight, live);
        assert!(stats.payload_bytes_in_buffer <= payload_bytes_pushed);
        if retained == 0 {
            assert_eq!(stats.payload_bytes_in_buffer, 0);
            assert_eq!(live, 0);
        }
    }
});
