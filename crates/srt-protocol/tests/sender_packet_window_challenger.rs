//! Integration and scale verification for the direct paged `SenderPacketWindow`.

use shiguredo_srt::{SenderBuffer, Timestamp};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

#[test]
fn sender_packet_window_monotonic_push_ack_and_wrap() {
    const MASK: u32 = 0x7FFF_FFFF;
    let start_seq = MASK - 2;
    let mut sender = SenderBuffer::new(start_seq, 256, 120);
    sender.set_congestion_window(256);

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
    sender.set_congestion_window(256);

    for seq in 0..10 {
        sender.push(vec![seq as u8], 1, 1, ts(1000)).unwrap();
    }
    assert_eq!(sender.packets_in_flight(), 10);
    assert!(!sender.has_retransmit());

    // NAK packets 3..=7.
    sender.handle_nak(&(3..=7).collect::<Vec<_>>());
    assert!(sender.has_retransmit());
    assert_eq!(sender.stats().packets_in_loss_list, 5);

    // Duplicate NAK must not re-increment loss list count.
    sender.handle_nak(&(3..=5).collect::<Vec<_>>());
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
    sender.set_congestion_window(256);

    // Push a multi-fragment message spanning across 31-bit wrap.
    let big_payload = vec![0xAB; 3_000]; // 3 fragments of 1000 bytes each
    let packets = sender.push_message(&big_payload, 1_000, 1, 1, ts(1_000));
    assert_eq!(packets.len(), 3);
    assert_eq!(packets[0].0.sequence_number, MASK - 1);
    assert_eq!(packets[1].0.sequence_number, MASK);
    assert_eq!(packets[2].0.sequence_number, 0);

    // Expire message (now is past 1s threshold).
    let dropped = sender.drop_expired(ts(2_000_000));
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].first_seq, MASK - 1);
    assert_eq!(dropped[0].last_seq, 0);
    assert_eq!(sender.packets_in_flight(), 0);
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
            .map(|_| {
                let mut s = SenderBuffer::new(0, 8_192, 120);
                s.set_congestion_window(256);
                s
            })
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
    sender.set_congestion_window(64);

    // 1. Send packet 0 and NAK it (queued for retransmit).
    sender.push(vec![0], 1, 1, ts(1000)).unwrap();
    sender.handle_nak(&[0]);
    assert!(sender.has_retransmit());

    // 2. ACK packet 0 without retransmitting (e.g. peer recovered via FEC).
    // Sequence 0 in loss_list becomes stale.
    sender.handle_ack(1);
    assert_eq!(sender.packets_in_flight(), 0);

    // 3. Advance to sequence 64 and send it.
    for seq in 1..64 {
        sender.push(vec![seq as u8], 1, 1, ts(1000)).unwrap();
    }
    sender.handle_ack(64);
    assert_eq!(sender.packets_in_flight(), 0);

    // 4. Send packet 64 (physically reuses slot 0).
    sender.push(vec![64], 1, 1, ts(1000)).unwrap();
    assert_eq!(sender.packets_in_flight(), 1);

    // 5. NAK packet 64 -> physical slot 0 has retransmit_queued bit set for seq 64.
    sender.handle_nak(&[64]);
    assert!(sender.has_retransmit());

    // 6. Pop retransmit must yield sequence 64, NOT sequence 0.
    let (header, _) = sender.pop_retransmit(1).expect("retransmit packet");
    assert_eq!(header.sequence_number, 64);
    assert!(!sender.has_retransmit());
}

#[test]
fn tlpktdrop_stale_retransmits_compacts_at_threshold() {
    // Latency 10ms -> TLPKTDROP threshold is 1s (1_000_000 us).
    let mut sender = SenderBuffer::new(0, 64, 10);
    sender.set_congestion_window(64);

    // Cycle packets: push -> NAK -> TLPKTDROP before retransmit.
    // Each drop should increment stale_retransmits because was_retransmit_queued is true.
    // After 1,024 stale entries, compaction should purge the loss_list.
    let now = ts(1_000);
    let drop_time = ts(2_000_000);

    for _ in 0..1_050 {
        let seq = sender.next_sequence_number();
        sender.push(vec![1], 1, 1, now).unwrap();
        sender.handle_nak(&[seq]);
        assert!(sender.has_retransmit());
        let dropped = sender.drop_expired(drop_time);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].first_seq, seq);
    }

    // Compaction must have triggered at 1,024, keeping loss_list bounded.
    assert!(!sender.has_retransmit());
    assert!(sender.is_empty());
    assert_eq!(sender.stats().packets_in_loss_list, 0);
}
