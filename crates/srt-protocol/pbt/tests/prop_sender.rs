//! Property-based tests for SRT SenderBuffer

use proptest::prelude::*;
use shiguredo_srt::{SenderBuffer, Timestamp};
use std::collections::HashSet;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_sender_buffer_new(
        initial_seq in 0u32..0x7FFF_FFFFu32,
        flow_window in 1u32..10000u32,
        latency_ms in 0u16..1000u16,
    ) {
        let buf = SenderBuffer::new(initial_seq, flow_window, latency_ms);
        prop_assert_eq!(buf.next_sequence_number(), initial_seq);
        prop_assert!(buf.can_send());
        prop_assert!(buf.is_empty());
        prop_assert_eq!(buf.packets_in_flight(), 0);
    }

    #[test]
    fn test_sender_buffer_push_increments_seq(
        initial_seq in 0u32..0x7FFF_FF00u32,
        payload_len in 1usize..1000usize,
    ) {
        let mut buf = SenderBuffer::new(initial_seq, 8192, 120);
        let now = Timestamp::from_micros(0);
        let payload = vec![0u8; payload_len];

        let packet = buf.push(payload.clone(), 100, 12345, now);
        prop_assert!(packet.is_some());
        let (hdr, payload_bytes) = packet.expect("送信パケットは Some になる想定");
        prop_assert_eq!(hdr.sequence_number, initial_seq);
        prop_assert_eq!(payload_bytes.len(), payload_len);
        prop_assert_eq!(buf.next_sequence_number(), (initial_seq + 1) & 0x7FFF_FFFF);
        prop_assert_eq!(buf.packets_in_flight(), 1);
    }

    #[test]
    fn test_sender_buffer_push_multiple(
        initial_seq in 0u32..0x7FFF_FF00u32,
        count in 1usize..16usize, // 初期 congestion_window は 16
    ) {
        let mut buf = SenderBuffer::new(initial_seq, 8192, 120);
        let now = Timestamp::from_micros(0);

        for i in 0..count {
            let packet = buf.push(vec![i as u8], 100, 12345, now);
            prop_assert!(packet.is_some());
        }

        prop_assert_eq!(buf.packets_in_flight(), count as u32);
        prop_assert_eq!(
            buf.next_sequence_number(),
            (initial_seq.wrapping_add(count as u32)) & 0x7FFF_FFFF
        );
    }

    #[test]
    fn test_sender_buffer_ack_clears_packets(
        initial_seq in 0u32..0x7FFF_FF00u32,
        count in 1usize..16usize, // 初期 congestion_window は 16
        ack_count in 0usize..16usize,
    ) {
        let mut buf = SenderBuffer::new(initial_seq, 8192, 120);
        let now = Timestamp::from_micros(0);

        // パケットを送信
        for i in 0..count {
            buf.push(vec![i as u8], 100, 12345, now);
        }

        // ACK を処理
        let ack_seq = initial_seq.wrapping_add(ack_count.min(count) as u32) & 0x7FFF_FFFF;
        buf.handle_ack(ack_seq);

        let expected_remaining = count.saturating_sub(ack_count);
        prop_assert_eq!(buf.packets_in_flight(), expected_remaining as u32);
    }

    #[test]
    fn test_sender_buffer_nak_adds_to_loss_list(
        initial_seq in 0u32..0x7FFF_FF00u32,
    ) {
        let mut buf = SenderBuffer::new(initial_seq, 8192, 120);
        let now = Timestamp::from_micros(0);

        // 3 パケット送信
        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);

        prop_assert!(!buf.has_retransmit());

        // 中間のパケットを NAK
        let lost_seq = (initial_seq + 1) & 0x7FFF_FFFF;
        buf.handle_nak(&[lost_seq]);

        prop_assert!(buf.has_retransmit());
    }

    #[test]
    fn retransmit_queue_matches_unique_retained_reference_model(
        initial_seq in 0u32..0x7FFF_FFE0u32,
        reports in prop::collection::vec(prop::collection::vec(0u8..48, 0..48), 0..24),
    ) {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
        let mut sender = SenderBuffer::new(initial_seq, 32, 120);
        for _ in 0..32 {
            sender.push(vec![1], 1, 1, Timestamp::default());
        }

        let mut seen = HashSet::new();
        let mut expected = Vec::new();
        for report in reports {
            let sequences = report
                .into_iter()
                .map(|offset| initial_seq.wrapping_add(u32::from(offset)) & SEQUENCE_MASK)
                .collect::<Vec<_>>();
            sender.handle_nak(&sequences);
            for sequence in sequences {
                let offset = sequence.wrapping_sub(initial_seq) & SEQUENCE_MASK;
                if offset < 32 && seen.insert(sequence) {
                    expected.push(sequence);
                }
            }
        }

        let actual = std::iter::from_fn(|| sender.pop_retransmit(1))
            .map(|(header, _)| header.sequence_number)
            .collect::<Vec<_>>();
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn test_sender_buffer_retransmit(
        initial_seq in 0u32..0x7FFF_FF00u32,
    ) {
        let mut buf = SenderBuffer::new(initial_seq, 8192, 120);
        let now = Timestamp::from_micros(0);

        // 3 パケット送信
        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);

        // 中間のパケットを NAK
        let lost_seq = (initial_seq + 1) & 0x7FFF_FFFF;
        buf.handle_nak(&[lost_seq]);

        // 再送パケットを取得
        let retransmit = buf.pop_retransmit(1);
        prop_assert!(retransmit.is_some());
        let (hdr, _payload) = retransmit.expect("再送パケットは Some になる想定");
        prop_assert_eq!(hdr.sequence_number, lost_seq);
        prop_assert!(hdr.retransmitted);

        // 再送後は loss_list が空
        prop_assert!(!buf.has_retransmit());
    }

    #[test]
    fn test_sender_buffer_flow_window(
        flow_window in 1u32..16u32, // 初期 congestion_window は 16
    ) {
        let mut buf = SenderBuffer::new(0, flow_window, 120);
        buf.set_congestion_window(1000); // フローウィンドウテスト用に増やす
        let now = Timestamp::from_micros(0);

        // フローウィンドウ分のパケットを送信
        for i in 0..flow_window {
            let packet = buf.push(vec![i as u8], 100, 1, now);
            prop_assert!(packet.is_some());
        }

        // これ以上は送信不可
        prop_assert!(!buf.can_send());
        let packet = buf.push(vec![0], 100, 1, now);
        prop_assert!(packet.is_none());
    }

    #[test]
    fn test_sender_buffer_congestion_window(
        cwnd in 1u32..50u32,
    ) {
        let mut buf = SenderBuffer::new(0, 8192, 120);
        buf.set_congestion_window(cwnd);
        let now = Timestamp::from_micros(0);

        // 輻輳ウィンドウ分のパケットを送信
        for i in 0..cwnd {
            let packet = buf.push(vec![i as u8], 100, 1, now);
            prop_assert!(packet.is_some());
        }

        // これ以上は送信不可
        prop_assert!(!buf.can_send());
    }

    #[test]
    fn test_sender_buffer_pacing(
        period in 100u64..10000u64,
    ) {
        let mut buf = SenderBuffer::new(0, 8192, 120);
        buf.set_packet_send_period(period);

        // 送信時刻を記録
        let send_time = Timestamp::from_micros(0);
        buf.record_send_time(send_time);

        // 直後は送信不可
        let half_period = Timestamp::from_micros(period / 2);
        prop_assert!(!buf.can_send_with_pacing(half_period));
        prop_assert!(buf.time_until_send(half_period) > 0);

        // period 経過後は送信可能
        let after_period = Timestamp::from_micros(period);
        prop_assert!(buf.can_send_with_pacing(after_period));
        prop_assert_eq!(buf.time_until_send(after_period), 0);
    }

    #[test]
    fn test_sender_buffer_stats(
        count in 1usize..16usize, // 初期 congestion_window は 16
    ) {
        let mut buf = SenderBuffer::new(0, 8192, 120);
        let now = Timestamp::from_micros(0);

        for i in 0..count {
            buf.push(vec![i as u8; 100], 100, 1, now);
        }

        let stats = buf.stats();
        prop_assert_eq!(stats.packets_in_buffer, count as u32);
        prop_assert_eq!(stats.total_sent, count as u64);
        prop_assert_eq!(stats.total_bytes_sent, (count * 100) as u64);
    }

    #[test]
    fn test_sender_buffer_drop_expired(
        latency_ms in 10u16..1000u16,
    ) {
        let mut buf = SenderBuffer::new(0, 8192, latency_ms);
        let send_time = Timestamp::from_micros(0);

        // パケットを送信
        buf.push(vec![1], 100, 1, send_time);
        buf.push(vec![2], 100, 1, send_time);

        // 新閾値: max(latency_us * 125 / 100, 1_000_000)
        let latency_us = latency_ms as u64 * 1000;
        let threshold = (latency_us * 125 / 100).max(1_000_000);

        // 閾値経過前は drop されない
        let before_expire = Timestamp::from_micros(threshold.saturating_sub(1000));
        let dropped = buf.drop_expired(before_expire);
        prop_assert!(dropped.is_empty());

        // 閾値経過後は drop される
        let after_expire = Timestamp::from_micros(threshold + 1000);
        let dropped = buf.drop_expired(after_expire);
        prop_assert_eq!(dropped.len(), 2);
    }

    #[test]
    fn test_sender_buffer_message_split(
        payload_size in 1usize..1500usize, // congestion_window に収まるように
        max_payload in 100usize..500usize,
    ) {
        let mut buf = SenderBuffer::new(0, 8192, 120);
        buf.set_congestion_window(1000); // 大きなメッセージ用に増やす
        let now = Timestamp::from_micros(0);
        let payload = vec![0u8; payload_size];

        let packets = buf.push_message(&payload, max_payload, 100, 1, now);

        let expected_count = payload_size.div_ceil(max_payload);
        prop_assert_eq!(packets.len(), expected_count);

        // 全ペイロードが含まれているか確認
        let total_bytes: usize = packets.iter().map(|(_, b)| b.len()).sum();
        prop_assert_eq!(total_bytes, payload_size);
    }

    #[test]
    fn test_sender_buffer_oldest_packet_time(
        initial_seq in 0u32..0x7FFF_FF00u32,
    ) {
        let mut buf = SenderBuffer::new(initial_seq, 8192, 120);

        // 空の場合は None
        prop_assert!(buf.oldest_packet_time().is_none());

        // パケットを追加
        let t1 = Timestamp::from_micros(1000);
        buf.push(vec![1], 100, 1, t1);

        let t2 = Timestamp::from_micros(2000);
        buf.push(vec![2], 100, 1, t2);

        // 最古のパケット時刻を取得
        let oldest = buf.oldest_packet_time();
        prop_assert!(oldest.is_some());
        prop_assert_eq!(
            oldest.expect("最古パケット時刻は Some になる想定")
                .as_micros(),
            1000
        );
    }

    #[test]
    fn test_sequence_wraparound(
        offset in 0u32..5u32, // 初期 congestion_window は 16
    ) {
        // シーケンス番号のラップアラウンドをテスト
        let initial_seq = 0x7FFF_FFFF - offset;
        let mut buf = SenderBuffer::new(initial_seq, 8192, 120);
        buf.set_congestion_window(100); // ラップアラウンドテスト用に増やす
        let now = Timestamp::from_micros(0);

        // ラップアラウンドを超えてパケットを送信
        for _ in 0..(offset + 10) {
            buf.push(vec![0], 100, 1, now);
        }

        // シーケンス番号が正しくラップアラウンド
        let expected = ((initial_seq as u64 + offset as u64 + 10) & 0x7FFF_FFFF) as u32;
        prop_assert_eq!(buf.next_sequence_number(), expected);
    }

    #[test]
    fn prop_sender_differential_state_machine(
        initial_seq in 0u32..0x7FFF_FFFFu32,
        window_size in 64u32..256u32,
        operations in prop::collection::vec(0u8..8u8, 1..60),
    ) {
        const MASK: u32 = 0x7FFF_FFFF;
        let mut buf = SenderBuffer::new(initial_seq, window_size, 10);
        buf.set_congestion_window(window_size);

        let mut model_packets = std::collections::BTreeMap::new();
        let mut model_queue = std::collections::VecDeque::new();
        let mut model_retransmit_set = std::collections::HashSet::new();
        let mut model_oldest_unacked = initial_seq & MASK;
        let mut model_next_seq = initial_seq & MASK;

        let mut current_time_us = 1_000u64;

        for op in operations {
            current_time_us += 1_000;
            let now = Timestamp::from_micros(current_time_us);

            match op {
                0 => {
                    // Push 1..4 packets if capacity allows
                    let count = 1 + (current_time_us as usize % 4);
                    for _ in 0..count {
                        if model_packets.len() < window_size as usize {
                            let seq = model_next_seq;
                            let (header, _) = buf.push(vec![1, 2, 3], 1, 1, now).expect("push succeeds");
                            prop_assert_eq!(header.sequence_number, seq);
                            model_packets.insert(seq, now);
                            model_next_seq = model_next_seq.wrapping_add(1) & MASK;
                        }
                    }
                }
                1 => {
                    // Valid cumulative ACK advancing by 1..=in_flight
                    if !model_packets.is_empty() {
                        let in_flight = model_packets.len();
                        let advance = 1 + (current_time_us as usize % in_flight);
                        let ack_seq = model_oldest_unacked.wrapping_add(advance as u32) & MASK;
                        buf.handle_ack(ack_seq);

                        // Retire prefix in model
                        let mut cur = model_oldest_unacked;
                        while cur != ack_seq {
                            model_packets.remove(&cur);
                            model_retransmit_set.remove(&cur);
                            cur = cur.wrapping_add(1) & MASK;
                        }
                        model_oldest_unacked = ack_seq;
                    }
                }
                2 => {
                    // Stale / duplicate ACK (behind oldest_unacked or high bit set)
                    let stale_ack = if current_time_us.is_multiple_of(2) {
                        model_oldest_unacked.wrapping_sub(1) & MASK
                    } else {
                        model_oldest_unacked | 0x8000_0000
                    };
                    buf.handle_ack(stale_ack);
                }
                3 => {
                    // Future / out-of-window ACK (strictly ahead of next_seq)
                    let future_ack = model_next_seq.wrapping_add(1 + (current_time_us as u32 % 50)) & MASK;
                    buf.handle_ack(future_ack);
                }
                4 => {
                    // NAK a random sequence in the in-flight span
                    if !model_packets.is_empty() {
                        let in_flight = model_packets.len();
                        let offset = (current_time_us as usize % in_flight) as u32;
                        let nak_seq = model_oldest_unacked.wrapping_add(offset) & MASK;
                        buf.handle_nak(&[nak_seq]);
                        if model_packets.contains_key(&nak_seq) && model_retransmit_set.insert(nak_seq) {
                            model_queue.push_back(nak_seq);
                        }
                    }
                }
                5 => {
                    // Duplicate NAK on already queued or non-existent sequence
                    let dup_seq = model_oldest_unacked;
                    buf.handle_nak(&[dup_seq]);
                    if model_packets.contains_key(&dup_seq) && model_retransmit_set.insert(dup_seq) {
                        model_queue.push_back(dup_seq);
                    }
                }
                6 => {
                    // Pop retransmit
                    if buf.has_retransmit() {
                        let popped = buf.pop_retransmit(1);
                        prop_assert!(popped.is_some());
                        let seq = popped.unwrap().0.sequence_number;

                        // Find matching entry in model
                        let mut found = false;
                        while let Some(q_seq) = model_queue.pop_front() {
                            if model_retransmit_set.remove(&q_seq) {
                                prop_assert_eq!(seq, q_seq);
                                found = true;
                                break;
                            }
                        }
                        prop_assert!(found);
                    }
                }
                7 => {
                    // TLPKTDROP (advance time past 1s threshold)
                    let drop_time = Timestamp::from_micros(current_time_us + 2_000_000);
                    let dropped = buf.drop_expired(drop_time);
                    for msg in dropped {
                        let mut cur = msg.first_seq;
                        loop {
                            model_packets.remove(&cur);
                            model_retransmit_set.remove(&cur);
                            if cur == msg.last_seq {
                                break;
                            }
                            cur = cur.wrapping_add(1) & MASK;
                        }
                        if (model_next_seq.wrapping_sub(cur.wrapping_add(1) & MASK) & MASK) <= window_size {
                            model_oldest_unacked = cur.wrapping_add(1) & MASK;
                        }
                    }
                    if model_packets.is_empty() {
                        model_oldest_unacked = model_next_seq;
                    }
                }
                _ => unreachable!(),
            }

            // Assert invariants after each operation
            prop_assert_eq!(buf.packets_in_flight() as usize, model_packets.len());
            prop_assert_eq!(buf.is_empty(), model_packets.is_empty());
            prop_assert_eq!(buf.next_sequence_number(), model_next_seq);
            prop_assert_eq!(buf.has_retransmit(), !model_retransmit_set.is_empty());
            prop_assert_eq!(buf.stats().packets_in_loss_list as usize, model_retransmit_set.len());
            prop_assert_eq!(buf.oldest_packet_time().is_some(), !model_packets.is_empty());
        }
    }
}
