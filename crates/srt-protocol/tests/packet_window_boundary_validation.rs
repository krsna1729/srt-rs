//! Deterministic boundary and correctness validation for packet windows.
//!
//! Tests edge cases across 63/64/65, 127/128/129, 8191/8192/8193, and 65535/65536
//! window boundaries, unaligned initial sequence numbers, 31-bit sequence wrap,
//! page-aligned ACK retirement, and NAK intersection across page boundaries.

use shiguredo_srt::{LossRange, SenderBuffer, Timestamp};

const PAYLOAD: &[u8] = &[42u8; 1316];

fn ts() -> Timestamp {
    Timestamp::from_micros(1000)
}

#[test]
fn sender_window_boundary_capacities_and_push_limits() {
    for &boundary in &[63, 64, 65, 127, 128, 129, 8191, 8192, 8193, 65535, 65536] {
        let mut sender = SenderBuffer::new(0, boundary, 120);
        sender.set_congestion_window(boundary);

        for _ in 0..boundary {
            assert!(
                sender.push(PAYLOAD.to_vec(), 0, 1, ts()).is_some(),
                "failed pushing to boundary {boundary}"
            );
        }
        assert_eq!(sender.packets_in_flight(), boundary);

        // Next push must fail closed due to window capacity
        assert!(sender.push(PAYLOAD.to_vec(), 0, 1, ts()).is_none());

        // ACK all packets -> in flight returns to 0
        sender.handle_ack(boundary);
        assert_eq!(sender.packets_in_flight(), 0);
        assert!(sender.is_empty());
    }
}

#[test]
fn unaligned_initial_sequence_and_partial_page_ack() {
    for &initial_seq in &[17, 39, 63, 127, 8191, 0x7fff_ffe0] {
        let mut sender = SenderBuffer::new(initial_seq, 256, 120);
        sender.set_congestion_window(256);

        // Push 100 packets starting from unaligned initial_seq
        for _ in 0..100 {
            assert!(sender.push(PAYLOAD.to_vec(), 0, 1, ts()).is_some());
        }
        assert_eq!(sender.packets_in_flight(), 100);

        // 1. Partial unaligned ACK: advance 37 packets
        let ack1 = (initial_seq + 37) & 0x7fff_ffff;
        sender.handle_ack(ack1);
        assert_eq!(sender.packets_in_flight(), 63);

        // 2. Aligned page boundary ACK: advance next 63 packets
        let ack2 = (initial_seq + 100) & 0x7fff_ffff;
        sender.handle_ack(ack2);
        assert_eq!(sender.packets_in_flight(), 0);
        assert!(sender.is_empty());
    }
}

#[test]
fn nak_crossing_page_boundary_and_sequence_wrap() {
    // 1. NAK crossing a 64-slot page boundary (60..70)
    let mut sender = SenderBuffer::new(0, 256, 120);
    sender.set_congestion_window(256);
    for _ in 0..128 {
        sender.push(PAYLOAD.to_vec(), 0, 1, ts()).unwrap();
    }

    let page_crossing_range = [LossRange {
        first_seq: 60,
        last_seq: 70,
    }];
    sender.handle_nak_ranges(&page_crossing_range);
    assert_eq!(sender.stats().packets_in_loss_list, 11);

    // Pop and verify retransmit packets are in order
    for expected in 60..=70 {
        let (header, _) = sender.pop_retransmit(1400).expect("pop retransmit");
        assert_eq!(header.sequence_number, expected);
    }
    assert_eq!(sender.stats().packets_in_loss_list, 0);

    // 2. NAK crossing 31-bit sequence wrap (0x7fff_fff8 .. 5)
    let wrap_initial = 0x7fff_fff0;
    let mut wrap_sender = SenderBuffer::new(wrap_initial, 256, 120);
    wrap_sender.set_congestion_window(256);
    for _ in 0..32 {
        wrap_sender.push(PAYLOAD.to_vec(), 0, 1, ts()).unwrap();
    }

    let wrap_loss_range = [LossRange {
        first_seq: 0x7fff_fff8,
        last_seq: 5,
    }];
    wrap_sender.handle_nak_ranges(&wrap_loss_range);
    assert_eq!(wrap_sender.stats().packets_in_loss_list, 14);

    let mut popped = Vec::new();
    while let Some((hdr, _)) = wrap_sender.pop_retransmit(1400) {
        popped.push(hdr.sequence_number);
    }
    assert_eq!(popped.len(), 14);
    assert_eq!(popped[0], 0x7fff_fff8);
    assert_eq!(*popped.last().unwrap(), 5);
}

#[test]
fn retransmit_queue_entry_survives_physical_page_reuse_and_rejects_stale_alias() {
    let mut sender = SenderBuffer::new(0, 128, 120);
    sender.set_congestion_window(128);

    // Fill page 0 (0..64)
    for _ in 0..64 {
        sender.push(PAYLOAD.to_vec(), 0, 1, ts()).unwrap();
    }
    // NAK seq 10 on page 0
    sender.handle_nak(&[10]);
    assert!(sender.has_retransmit());

    // ACK 0..64 without popping retransmit 10 (e.g. recovered via FEC)
    sender.handle_ack(64);
    assert_eq!(sender.packets_in_flight(), 0);

    // Now fill page 1 (64..128) and physically reuse slot 10 on page 1 (seq 74)
    for _ in 64..128 {
        sender.push(PAYLOAD.to_vec(), 0, 1, ts()).unwrap();
    }
    assert_eq!(sender.packets_in_flight(), 64);

    // Stale sequence 10 must NOT alias to seq 74
    assert!(!sender.has_retransmit() || sender.pop_retransmit(1400).is_none());
}
