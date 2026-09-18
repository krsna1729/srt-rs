//! Integration and scale verification for the direct paged `SenderPacketWindow`.

use srt_proto::Timestamp;
use srt_proto::receiver::LossRange;
use srt_proto::sender::SenderBuffer;

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

/// Push a packet and mark its datagram transmitted.
///
/// A peer's loss report is only credible for positions that reached the wire,
/// so the loss-report path rejects reports naming positions this sender
/// accepted but never transmitted.
fn push_transmitted(sender: &mut SenderBuffer, byte: u8) {
    let (header, _) = sender.push(vec![byte], 1, 1, ts(1000)).expect("admitted");
    sender.note_data_submitted(header.sequence_number);
}

/// Apply a peer's cumulative ACK together with the receive window that ACK
/// advertises.
///
/// In the boundary model the cumulative ACK retires the acknowledged flight
/// but grants no new credit of its own: only the advertised window end moves,
/// so a test that keeps sending across an ACK has to be the peer that
/// advertises one.
fn ack_with_window(sender: &mut SenderBuffer, ack_seq: u32, window: u32) {
    sender.handle_ack(ack_seq);
    sender.set_peer_window(ack_seq, window);
}

#[test]
fn sender_packet_window_monotonic_push_ack_and_wrap() {
    const MASK: u32 = 0x7FFF_FFFF;
    let start_seq = MASK - 2;
    let mut sender = SenderBuffer::new(start_seq, 256, 120);

    // Push packets across sequence wrap: MASK - 2, MASK - 1, MASK, 0, 1.
    for i in 0..5 {
        let (header, payload) = sender.push(vec![i as u8; 100], 1, 1, ts(1000)).unwrap();
        let expected_seq = start_seq.wrapping_add(i) & MASK;
        assert_eq!(header.sequence_number, expected_seq);
        assert_eq!(payload.len(), 100);
    }
    assert_eq!(sender.packets_in_flight(), 5);
    assert!(sender.allocated_pages() >= 1);

    // ACK first 3 packets (MASK - 2, MASK - 1, MASK).
    // New ack_seq is 0.
    sender.handle_ack(0);
    assert_eq!(sender.packets_in_flight(), 2);

    // ACK remaining 2 packets (0, 1).
    // New ack_seq is 2.
    sender.handle_ack(2);
    assert_eq!(sender.packets_in_flight(), 0);
    assert!(sender.is_empty());
    assert_eq!(sender.allocated_pages(), 0);
}

#[test]
fn sender_nak_range_intersection_and_duplicate_suppression() {
    let mut sender = SenderBuffer::new(0, 256, 120);

    for seq in 0..10 {
        let (header, _) = sender.push(vec![seq as u8], 1, 1, ts(1000)).unwrap();
        sender.note_data_submitted(header.sequence_number);
    }
    assert_eq!(sender.packets_in_flight(), 10);
    assert!(!sender.has_retransmit());

    // NAK packets 3..=7.
    sender.handle_nak_ranges(&[LossRange {
        first_seq: 3,
        last_seq: 7,
    }]);
    assert!(sender.has_retransmit());
    assert_eq!(sender.stats().packets_in_loss_list, 5);

    // Duplicate NAK must not re-increment loss list count.
    sender.handle_nak_ranges(&[LossRange {
        first_seq: 3,
        last_seq: 5,
    }]);
    assert_eq!(sender.stats().packets_in_loss_list, 5);

    // Pop retransmits in order.
    for expected in 3..=7 {
        let (header, _) = sender.pop_retransmit(1).expect("retransmit packet");
        assert_eq!(header.sequence_number, expected);
        assert!(header.retransmitted);
    }
    assert!(!sender.has_retransmit());
    assert_eq!(sender.stats().packets_in_loss_list, 0);
}

#[test]
fn sender_tlpktdrop_retires_entire_message_across_wrap() {
    const MASK: u32 = 0x7FFF_FFFF;
    let start_seq = MASK - 1;
    let mut sender = SenderBuffer::new(start_seq, 256, 10);

    // Push a multi-fragment message spanning across 31-bit wrap.
    let big_payload = vec![0xAB; 3_000]; // 3 fragments of 1000 bytes each
    let packets = sender.push_message(&big_payload, 1_000, 1, 1, ts(1_000));
    assert_eq!(packets.len(), 3);
    assert_eq!(packets[0].0.sequence_number, MASK - 1);
    assert_eq!(packets[1].0.sequence_number, MASK);
    assert_eq!(packets[2].0.sequence_number, 0);

    // Expire message (now is past 1s threshold): the whole fragmented message
    // is given up at once, media released, identity kept until the ACK.
    let dropped = sender.drop_expired(ts(2_000_000));
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].first_seq, MASK - 1);
    assert_eq!(dropped[0].last_seq, 0);
    assert_eq!(sender.packets_in_flight(), 0, "no live packets left");
    assert_eq!(sender.retained_span(), 3, "three tombstones remain");
    assert!(!sender.is_empty());
    // The three tombstones sit at 0x7FFF_FFFE, 0x7FFF_FFFF and 0, which is a
    // page boundary in the physical window: two pages, not three.
    assert_eq!(sender.allocated_pages(), 2, "the identity needs its pages");
    assert_eq!(sender.stats().payload_bytes_in_buffer, 0, "media released");
}

/// The tombstone left by a message that was given up across the wrap still
/// expands back to the whole message range when the peer repeats the NAK, and
/// only the cumulative ACK reclaims it.
#[test]
fn a_repeated_nak_expands_a_wrapped_dropped_message_and_the_ack_reclaims_it() {
    const MASK: u32 = 0x7FFF_FFFF;
    let mut sender = SenderBuffer::new(MASK - 1, 256, 10);
    sender.push_message(&[0xAB; 3_000], 1_000, 1, 1, ts(1_000));
    sender.drop_expired(ts(2_000_000));

    let repeated = sender.handle_nak_ranges(&[LossRange {
        first_seq: MASK,
        last_seq: 0,
    }]);
    assert_eq!(repeated.len(), 1);
    assert_eq!(repeated[0].first_seq, MASK - 1);
    assert_eq!(repeated[0].last_seq, 0);

    // The cumulative ACK is what reclaims the pages.
    ack_with_window(&mut sender, 1, 256);
    assert!(sender.is_empty());
    assert_eq!(sender.allocated_pages(), 0);
}

#[test]
#[cfg_attr(miri, ignore = "resource-scale evidence is covered outside Miri")]
fn sender_scale_1_30_200_1000_allocates_and_reclaims_pages() {
    fn rss_bytes() -> Option<usize> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: usize = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4096)
    }

    for &conns in &[1, 30, 200, 1_000] {
        let idle_rss = rss_bytes();
        let mut senders: Vec<SenderBuffer> = (0..conns)
            .map(|_| SenderBuffer::new(0, 8_192, 120))
            .collect();

        // Baseline directory floor: conns * 1,040 bytes.
        let empty_heap: usize = senders.iter().map(|s| s.sender_window_heap_bytes()).sum();
        assert_eq!(empty_heap, conns * 1_040);
        for s in &senders {
            assert_eq!(s.allocated_pages(), 0);
        }

        // Burst: each connection sends 128 packets (filling exactly 2 pages per connection).
        let now = ts(1_000);
        for s in &mut senders {
            for _ in 0..128 {
                s.push(vec![0x42; 64], 1, 1, now).unwrap();
            }
        }
        let burst_heap: usize = senders.iter().map(|s| s.sender_window_heap_bytes()).sum();
        let burst_rss = rss_bytes();
        assert!(burst_heap > empty_heap);
        for s in &senders {
            assert_eq!(s.allocated_pages(), 2);
        }

        // Cumulative ACK: acknowledge all 128 packets.
        for s in &mut senders {
            s.handle_ack(128);
        }

        // All pages eagerly reclaimed; heap returns exactly to directory floor.
        let post_ack_heap: usize = senders.iter().map(|s| s.sender_window_heap_bytes()).sum();
        let post_ack_rss = rss_bytes();
        assert_eq!(post_ack_heap, empty_heap);
        for s in &senders {
            assert_eq!(s.allocated_pages(), 0);
            assert!(s.is_empty());
        }

        eprintln!(
            "[{conns} senders] owned heap: empty={empty_heap} B, burst-128pkts={burst_heap} B, post-ack={post_ack_heap} B | RSS: idle={idle_rss:?}, burst={burst_rss:?}, post-ack={post_ack_rss:?}"
        );
    }
}

#[test]
fn out_of_window_and_high_bit_ack_rejected_without_desync() {
    let mut sender = SenderBuffer::new(0, 64, 120);
    sender.push(vec![0x42], 1, 1, ts(1000)).unwrap();
    assert_eq!(sender.packets_in_flight(), 1);

    // Peer sends out-of-window ACK 65 (distance 65 > in_flight_span 1).
    sender.handle_ack(65);
    assert_eq!(sender.packets_in_flight(), 1);

    // Peer sends invalid 32-bit ACK with high bit set.
    sender.handle_ack(0x8000_0001);
    assert_eq!(sender.packets_in_flight(), 1);

    // Duplicate/stale ACK 0 is ignored.
    sender.handle_ack(0);
    assert_eq!(sender.packets_in_flight(), 1);

    // Legitimate ACK 1 correctly retires packet 0.
    sender.handle_ack(1);
    assert_eq!(sender.packets_in_flight(), 0);
    assert!(sender.is_empty());
}

#[test]
fn physical_slot_reuse_does_not_alias_stale_retransmit_entry() {
    // With flow_window = 64, directory capacity is 64.
    // Sequence 0 and sequence 64 share the exact same physical slot index (0 in page 0).
    let mut sender = SenderBuffer::new(0, 64, 120);

    // 1. Send packet 0 and NAK it (queued for retransmit).
    push_transmitted(&mut sender, 0);
    sender.handle_nak_ranges(&[LossRange {
        first_seq: 0,
        last_seq: 0,
    }]);
    assert!(sender.has_retransmit());

    // 2. ACK packet 0 without retransmitting (e.g. peer recovered via FEC).
    // Sequence 0 in loss_list becomes stale.
    ack_with_window(&mut sender, 1, 64);
    assert_eq!(sender.packets_in_flight(), 0);

    // 3. Advance to sequence 64 and send it.
    for seq in 1..64 {
        push_transmitted(&mut sender, seq);
    }
    ack_with_window(&mut sender, 64, 64);
    assert_eq!(sender.packets_in_flight(), 0);

    // 4. Send packet 64 (physically reuses slot 0).
    push_transmitted(&mut sender, 64);
    assert_eq!(sender.packets_in_flight(), 1);

    // 5. NAK packet 64 -> physical slot 0 has retransmit_queued bit set for seq 64.
    sender.handle_nak_ranges(&[LossRange {
        first_seq: 64,
        last_seq: 64,
    }]);
    assert!(sender.has_retransmit());

    // 6. Pop retransmit must yield sequence 64, NOT sequence 0.
    let (header, _) = sender.pop_retransmit(1).expect("retransmit packet");
    assert_eq!(header.sequence_number, 64);
    assert!(!sender.has_retransmit());
}

#[test]
fn tlpktdrop_cycles_stay_bounded_and_the_ack_reclaims_them() {
    // Latency 10ms -> TLPKTDROP threshold is 1s (1_000_000 us).
    let mut sender = SenderBuffer::new(0, 64, 10);

    // Cycle packets: push -> NAK -> TLPKTDROP -> ACK. Each drop leaves a
    // tombstone that occupies window span until the peer's cumulative ACK
    // retires it, so the window never grows and never fills permanently --
    // the same bounded-memory contract the media-removing version had, now
    // with the identity retained in between.
    let drop_time = ts(2_000_000);

    for _ in 0..1_050 {
        let seq = sender.next_sequence_number();
        push_transmitted(&mut sender, 1);
        sender.handle_nak_ranges(&[LossRange {
            first_seq: seq,
            last_seq: seq,
        }]);
        assert!(sender.has_retransmit());
        let dropped = sender.drop_expired(drop_time);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].first_seq, seq);
        // The dropped position is answered by DROPREQ from now on, not by a
        // retransmission, and it still holds window span.
        assert!(!sender.has_retransmit());
        assert_eq!(sender.retained_span(), 1);
        assert_eq!(sender.packets_in_flight(), 0);

        // The peer's cumulative ACK retires the tombstone (and the stale
        // retransmit entry with it), and its advertised window reopens
        // credit for the next cycle.
        ack_with_window(&mut sender, seq.wrapping_add(1) & 0x7FFF_FFFF, 64);
        assert!(sender.is_empty());
        assert_eq!(sender.stats().packets_in_loss_list, 0);
    }

    assert_eq!(
        sender.allocated_pages(),
        0,
        "pages are reclaimed each cycle"
    );
}
