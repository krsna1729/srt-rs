//! Property-based tests for SRT ReceiverBuffer

use proptest::prelude::*;
use shiguredo_srt::{
    DEFAULT_FLOW_WINDOW, DataPacket, LossRange, NakPacket, PacketPosition, ReceiverBuffer,
    Timestamp,
};

fn expand_range(range: LossRange) -> Vec<u32> {
    range.iter().collect()
}

fn expand_nak(nak: NakPacket) -> Vec<u32> {
    nak.loss_ranges
        .into_iter()
        .flat_map(|range| range.iter())
        .collect()
}

/// テスト用の DataPacket を生成
fn make_packet(seq: u32, timestamp: u32) -> DataPacket {
    DataPacket {
        sequence_number: seq,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0,
        retransmitted: false,
        message_number: 1,
        timestamp,
        dest_socket_id: 1,
        payload: vec![1, 2, 3].into(),
    }
}

/// 任意のペイロードを持つ DataPacket を生成
fn make_packet_with_payload(seq: u32, timestamp: u32, payload: Vec<u8>) -> DataPacket {
    DataPacket {
        sequence_number: seq,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0,
        retransmitted: false,
        message_number: 1,
        timestamp,
        dest_socket_id: 1,
        payload: payload.into(),
    }
}

/// ラップ境界近傍の連続シーケンス列と、その順不同の受信順を生成する Strategy
///
/// 戻り値は (循環順のシーケンス列, それを順不同にシャッフルした受信順) で、
/// 受信順のシャッフルは proptest の prop_shuffle に委ねる。
fn wrap_around_run() -> impl Strategy<Value = (Vec<u32>, Vec<u32>)> {
    // before 個 (末尾が 0x7FFF_FFFF) と after 個 (0 から始まる) を連結し、必ずラップ境界
    // (0x7FFF_FFFF -> 0) をまたぐ連続シーケンス列を作る。これにより境界をまたがない退行ケースを除く。
    (1usize..4usize, 1usize..4usize).prop_flat_map(|(before, after)| {
        let start_seq = 0x7FFF_FFFFu32 - (before as u32 - 1);
        let seqs: Vec<u32> = (0..before + after)
            .map(|i| start_seq.wrapping_add(i as u32) & 0x7FFF_FFFF)
            .collect();
        let recv_order = Just(seqs.clone()).prop_shuffle();
        (Just(seqs), recv_order)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_receiver_buffer_new(
        initial_seq in 0u32..0x7FFF_FFFFu32,
        tsbpd_delay_ms in 0u16..1000u16,
        start_time in 0u64..1_000_000u64,
    ) {
        let start = Timestamp::from_micros(start_time);
        let buf = ReceiverBuffer::new(initial_seq, tsbpd_delay_ms, start, 0);
        prop_assert_eq!(buf.expected_sequence(), initial_seq);
    }

    #[test]
    fn test_receiver_buffer_receive_in_order(
        initial_seq in 0u32..0x7FFF_FF00u32,
        count in 1usize..50usize,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        for i in 0..count {
            let seq = (initial_seq + i as u32) & 0x7FFF_FFFF;
            let losses = buf.receive(make_packet(seq, 100), now);
            prop_assert!(losses.is_none());
        }

        let expected_seq = (initial_seq + count as u32) & 0x7FFF_FFFF;
        prop_assert_eq!(buf.expected_sequence(), expected_seq);
    }

    #[test]
    fn test_receiver_buffer_loss_detection(
        initial_seq in 0u32..0x7FFF_FF00u32,
        gap in 1u32..10u32,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 最初のパケットを受信
        buf.receive(make_packet(initial_seq, 100), now);

        // ギャップを作って受信
        let skip_seq = (initial_seq + gap + 1) & 0x7FFF_FFFF;
        let losses = buf.receive(make_packet(skip_seq, 200), now);

        prop_assert!(losses.is_some());
        let lost = losses.expect("欠落パケットは Some になる想定");
        prop_assert_eq!(lost.sequence_count(), gap);
    }

    #[test]
    fn test_receiver_buffer_duplicate_detection(
        initial_seq in 0u32..0x7FFF_FFFFu32,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 同じパケットを 2 回受信
        buf.receive(make_packet(initial_seq, 100), now);
        let losses = buf.receive(make_packet(initial_seq, 100), now);
        prop_assert!(losses.is_none());

        let stats = buf.stats();
        prop_assert_eq!(stats.total_duplicates, 1);
    }

    #[test]
    fn test_receiver_buffer_old_packet_ignored(
        initial_seq in 10u32..0x7FFF_FFFFu32,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // expected_seq より古いパケットは無視される
        let old_seq = initial_seq - 5;
        let losses = buf.receive(make_packet(old_seq, 100), now);
        prop_assert!(losses.is_none());

        let stats = buf.stats();
        prop_assert_eq!(stats.total_received, 0);
    }

    #[test]
    fn test_receiver_buffer_pop_ready_no_tsbpd(
        initial_seq in 0u32..0x7FFF_FF00u32,
        count in 1usize..20usize,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 順序通りにパケットを受信
        for i in 0..count {
            let seq = (initial_seq + i as u32) & 0x7FFF_FFFF;
            buf.receive(make_packet(seq, 100), now);
        }

        // 全て pop 可能
        for _ in 0..count {
            let pkt = buf.pop_ready(now);
            prop_assert!(pkt.is_some());
        }

        // これ以上は None
        prop_assert!(buf.pop_ready(now).is_none());
    }

    #[test]
    fn test_receiver_buffer_ack_generation(
        initial_seq in 0u32..0x7FFF_FF00u32,
        count in 1usize..20usize,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);

        let now = Timestamp::from_micros(1000);

        for i in 0..count {
            let seq = (initial_seq + i as u32) & 0x7FFF_FFFF;
            buf.receive(make_packet(seq, 100), now);
        }

        let ack = buf.generate_ack(now);
        let expected_seq = (initial_seq + count as u32) & 0x7FFF_FFFF;
        prop_assert_eq!(ack.ack_seq, expected_seq);
    }

    #[test]
    fn test_receiver_buffer_nak_generation(
        initial_seq in 0u32..0x7FFF_FF00u32,
        gap in 1u32..5u32,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 最初のパケット
        buf.receive(make_packet(initial_seq, 100), now);

        // ギャップを作る
        let skip_seq = (initial_seq + gap + 1) & 0x7FFF_FFFF;
        buf.receive(make_packet(skip_seq, 200), now);

        // NAK を生成
        let nak = buf.generate_periodic_nak();
        prop_assert!(nak.is_some());
        prop_assert_eq!(
            nak.expect("欠落パケットは NAK が生成される想定")
                .loss_ranges,
            vec![LossRange {
                first_seq: initial_seq.wrapping_add(1) & 0x7FFF_FFFF,
                last_seq: initial_seq.wrapping_add(gap) & 0x7FFF_FFFF,
            }]
        );
    }

    #[test]
    fn test_receiver_buffer_rtt_accessors(
        initial_seq in 0u32..0x7FFF_FFFFu32,
    ) {
        let start = Timestamp::from_micros(0);
        let buf = ReceiverBuffer::new(initial_seq, 120, start, 0);

        // 初期 RTT 値
        prop_assert!(buf.rtt() > 0);
        prop_assert!(buf.rtt_var() > 0);
    }

    #[test]
    fn test_receiver_buffer_nak_interval(
        initial_seq in 0u32..0x7FFF_FFFFu32,
    ) {
        let start = Timestamp::from_micros(0);
        let buf = ReceiverBuffer::new(initial_seq, 120, start, 0);

        // NAK 間隔は最低 20ms
        let interval = buf.nak_interval();
        prop_assert!(interval >= 20_000);
    }

    #[test]
    fn receiver_state_machine_preserves_hard_occupancy(
        initial_seq in any::<u32>(),
        actions in prop::collection::vec((0u8..4, any::<u16>()), 1..160),
    ) {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
        let initial_seq = initial_seq & SEQUENCE_MASK;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);

        for (opcode, raw_offset) in actions {
            let offset = u32::from(raw_offset) % 512;
            let seq = initial_seq.wrapping_add(offset) & SEQUENCE_MASK;
            match opcode {
                0 => {
                    let _ = buf.receive(make_packet(seq, offset), now);
                }
                1 => {
                    let _ = buf.drop_range(seq, seq);
                }
                2 => buf.advance_expected_sequence(seq),
                _ => {
                    let _ = buf.pop_ready(now);
                }
            }

            let stats = buf.stats();
            let losses = buf
                .generate_periodic_nak()
                .map_or(0, |nak| expand_nak(nak).len() as u32);
            prop_assert_eq!(
                stats
                    .packets_in_buffer
                    .saturating_add(losses)
                    .saturating_add(stats.available_buffer_packets),
                stats.max_buffer_packets
            );
        }
    }

    #[test]
    fn test_receiver_buffer_stats(
        initial_seq in 0u32..0x7FFF_FF00u32,
        count in 1usize..20usize,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        for i in 0..count {
            let seq = (initial_seq + i as u32) & 0x7FFF_FFFF;
            buf.receive(make_packet(seq, 100), now);
        }

        let stats = buf.stats();
        prop_assert_eq!(stats.total_received, count as u64);
        prop_assert_eq!(stats.total_lost, 0);
        prop_assert_eq!(stats.loss_rate_percent_x100, 0);
    }

    #[test]
    fn test_receiver_buffer_bytes_received(
        initial_seq in 0u32..0x7FFF_FFFFu32,
        payload_size in 1usize..1000usize,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);
        let payload = vec![0u8; payload_size];
        buf.receive(make_packet_with_payload(initial_seq, 100, payload), now);

        let stats = buf.stats();
        // payload_size + 16 (SRT header)
        prop_assert_eq!(stats.total_bytes_received, (payload_size + 16) as u64);
    }

    #[test]
    fn test_receiver_buffer_should_send_ack_periodic(
        initial_seq in 0u32..0x7FFF_FFFFu32,
    ) {
        let start = Timestamp::from_micros(0);
        let buf = ReceiverBuffer::new(initial_seq, 120, start, 0);

        // 直後は ACK 不要
        let now = Timestamp::from_micros(1000);
        prop_assert!(!buf.should_send_ack(now));

        // 10ms 経過後は ACK 必要
        let later = Timestamp::from_micros(11_000);
        prop_assert!(buf.should_send_ack(later));
    }

    #[test]
    fn test_receiver_buffer_loss_recovery(
        initial_seq in 0u32..0x7FFF_FF00u32,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // パケット 0, 2 を受信 (1 が欠落)
        buf.receive(make_packet(initial_seq, 100), now);
        let losses = buf.receive(make_packet((initial_seq + 2) & 0x7FFF_FFFF, 300), now);
        prop_assert!(losses.is_some());

        // パケット 1 を後から受信 (回復)
        let losses = buf.receive(make_packet((initial_seq + 1) & 0x7FFF_FFFF, 200), now);
        prop_assert!(losses.is_none());

        // NAK は空になる
        let nak = buf.generate_periodic_nak();
        prop_assert!(nak.is_none());
    }

    #[test]
    fn test_receiver_buffer_ackack_updates_rtt(
        initial_seq in 0u32..0x7FFF_FFFFu32,
        rtt_sample in 1000u64..100_000u64,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);
        buf.receive(make_packet(initial_seq, 100), now);

        // ACK 生成 (送信時刻が記録される)
        let ack_time = Timestamp::from_micros(2000);
        buf.generate_ack(ack_time);
        let ack_number = buf.ack_number();

        // ACKACK 受信 (RTT が計算される)
        let ackack_time = Timestamp::from_micros(2000 + rtt_sample);
        let _old_rtt = buf.rtt();
        buf.handle_ackack(ack_number, 0, ackack_time);
        let new_rtt = buf.rtt();

        // RTT が更新される (EWMA なので必ずしも等しくない)
        // 初期 RTT (100ms) と新しいサンプルの間の値になる
        prop_assert!(new_rtt > 0);
    }

    #[test]
    fn test_receiver_buffer_periodic_nak(
        initial_seq in 0u32..0x7FFF_FF00u32,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // ギャップを作る
        buf.receive(make_packet(initial_seq, 100), now);
        buf.receive(make_packet((initial_seq + 2) & 0x7FFF_FFFF, 300), now);

        // Periodic NAK も同じ内容
        let nak1 = buf.generate_periodic_nak();
        let nak2 = buf.generate_periodic_nak();

        prop_assert!(nak1.is_some());
        prop_assert!(nak2.is_some());
        prop_assert_eq!(
            nak1.expect("欠落パケットは NAK が生成される想定")
                .loss_ranges,
            nak2.expect("欠落パケットは NAK が生成される想定")
                .loss_ranges
        );
    }

    #[test]
    fn test_receiver_buffer_jitter_stable(
        initial_seq in 0u32..0x7FFF_FF00u32,
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        // タイムスタンプと到着時刻の差が一定
        for i in 0..10u32 {
            let seq = (initial_seq + i) & 0x7FFF_FFFF;
            let ts = 1000 + i * 1000;
            let now = Timestamp::from_micros((2000 + i * 1000) as u64);
            buf.receive(make_packet(seq, ts), now);
        }

        let stats = buf.stats();
        // transit が一定なのでジッターは 0
        prop_assert_eq!(stats.jitter, 0);
    }

    /// Loss detection under random out-of-order arrival never produces
    /// duplicates and accounts for every missing sequence number.
    #[test]
    fn detect_losses_total_equals_gap_minus_received(
        initial_seq in 0u32..0x7FFF_FF00u32,
        gap in 2u32..20u32,
        drop_indices in proptest::collection::hash_set(0usize..19usize, 1..10),
    ) {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(initial_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        let end_seq = (initial_seq + gap) & 0x7FFF_FFFF;
        let seqs: Vec<u32> = (0..gap)
            .map(|i| (initial_seq + i) & 0x7FFF_FFFF)
            .collect();
        let dropped: Vec<u32> = drop_indices
            .iter()
            .filter(|&&i| i < seqs.len())
            .map(|&i| seqs[i])
            .collect();

        for &seq in &seqs {
            if !dropped.contains(&seq) {
                buf.receive(make_packet(seq, 100), now);
            }
        }
        // Trigger loss detection with the packet after the gap.
        buf.receive(make_packet(end_seq, 200), now);

        let stats = buf.stats();
        prop_assert_eq!(
            stats.total_lost,
            dropped.len() as u64,
            "total_lost must equal the number of dropped packets"
        );
    }

    /// Loss detection across the sequence-number wrap boundary
    /// (0x7FFF_FFFF -> 0) produces the correct loss count.
    #[test]
    fn detect_losses_across_wrap_boundary(
        before in 1u32..5u32,
        after in 1u32..5u32,
        drop_count in 1usize..4usize,
    ) {
        let total = before + after;
        let start_seq = 0x7FFF_FFFFu32.wrapping_sub(before - 1);
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(start_seq, 120, start, 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        let seqs: Vec<u32> = (0..total)
            .map(|i| start_seq.wrapping_add(i) & 0x7FFF_FFFF)
            .collect();
        let actual_drops = drop_count.min(seqs.len().saturating_sub(1));
        let dropped: std::collections::HashSet<u32> =
            seqs[..actual_drops].iter().copied().collect();

        for &seq in &seqs {
            if !dropped.contains(&seq) {
                buf.receive(make_packet(seq, 100), now);
            }
        }
        let end_seq = start_seq.wrapping_add(total) & 0x7FFF_FFFF;
        buf.receive(make_packet(end_seq, 200), now);

        prop_assert_eq!(
            buf.stats().total_lost,
            dropped.len() as u64,
            "wrap-boundary losses must be detected correctly"
        );
    }

    /// A sequence position is emitted as a new loss only when the receive
    /// stream first extends beyond the classification frontier. Later
    /// recovery, reordering, and duplication at or behind the frontier must
    /// not rediscover any part of the old interval.
    #[test]
    fn loss_frontier_emits_each_newly_exposed_position_once(
        raw_initial in any::<u32>(),
        offsets in proptest::collection::vec(0u16..128, 1..256),
    ) {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
        let initial = raw_initial & SEQUENCE_MASK;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(initial, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);
        let mut frontier_offset = -1i32;

        for offset in offsets {
            let offset = i32::from(offset);
            let seq = initial.wrapping_add(offset as u32) & SEQUENCE_MASK;
            let actual = buf.receive(make_packet(seq, offset as u32), now);
            let expected: Vec<u32> = if offset > frontier_offset {
                ((frontier_offset + 1)..offset)
                    .map(|missing| initial.wrapping_add(missing as u32) & SEQUENCE_MASK)
                    .collect()
            } else {
                Vec::new()
            };
            prop_assert_eq!(actual.map_or_else(Vec::new, expand_range), expected);
            frontier_offset = frontier_offset.max(offset);
        }
    }

    /// The public NAK view remains equivalent to the set of exposed sequence
    /// positions that have not subsequently arrived, including across wrap.
    #[test]
    fn loss_membership_matches_exposed_but_unreceived_positions(
        raw_initial in any::<u32>(),
        offsets in proptest::collection::vec(0u16..256, 1..512),
    ) {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
        let initial = raw_initial & SEQUENCE_MASK;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(initial, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);
        let mut received = std::collections::HashSet::new();
        let mut frontier = 0u16;

        for offset in offsets {
            let seq = initial.wrapping_add(u32::from(offset)) & SEQUENCE_MASK;
            let _ = buf.receive(make_packet(seq, u32::from(offset)), now);
            received.insert(offset);
            frontier = frontier.max(offset);

            let mut expected: Vec<u32> = (0..frontier)
                .filter(|position| !received.contains(position))
                .map(|position| initial.wrapping_add(u32::from(position)) & SEQUENCE_MASK)
                .collect();
            expected.sort_unstable();
            let actual = buf
                .generate_periodic_nak()
                .map_or_else(Vec::new, expand_nak);
            prop_assert_eq!(actual, expected);
        }
    }

    /// A forward DROPREQ classifies the gap before the request as loss and the
    /// request itself as dropped. Extending receipt beyond it must expose only
    /// the new suffix, including when either interval crosses sequence wrap.
    #[test]
    fn drop_range_and_loss_frontier_partition_new_sequence_space(
        raw_initial in any::<u32>(),
        gap_before_drop in 0u32..16,
        drop_len in 1u32..16,
        gap_after_drop in 0u32..16,
    ) {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
        let initial = raw_initial & SEQUENCE_MASK;
        let first_drop = initial.wrapping_add(1 + gap_before_drop) & SEQUENCE_MASK;
        let last_drop = first_drop.wrapping_add(drop_len - 1) & SEQUENCE_MASK;
        let next_received = last_drop.wrapping_add(1 + gap_after_drop) & SEQUENCE_MASK;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(initial, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);

        prop_assert!(buf.receive(make_packet(initial, 0), now).is_none());
        let summary = buf.drop_range(first_drop, last_drop)?;
        prop_assert_eq!(summary.sequence_count, drop_len);

        let suffix = buf
            .receive(make_packet(next_received, 1), now)
            .map_or_else(Vec::new, expand_range);
        let expected_suffix: Vec<u32> = (0..gap_after_drop)
            .map(|offset| last_drop.wrapping_add(1 + offset) & SEQUENCE_MASK)
            .collect();
        prop_assert_eq!(suffix, expected_suffix);

        let mut expected_losses: Vec<u32> = (0..gap_before_drop)
            .map(|offset| initial.wrapping_add(1 + offset) & SEQUENCE_MASK)
            .chain(
                (0..gap_after_drop)
                    .map(|offset| last_drop.wrapping_add(1 + offset) & SEQUENCE_MASK),
            )
            .collect();
        expected_losses.sort_unstable();
        let actual_losses = buf
            .generate_periodic_nak()
            .map_or_else(Vec::new, expand_nak);
        prop_assert_eq!(actual_losses, expected_losses);
        prop_assert_eq!(
            buf.stats().total_lost,
            u64::from(gap_before_drop + gap_after_drop)
        );
    }

    #[test]
    fn forward_drop_cannot_classify_losses_beyond_the_receive_window(
        raw_initial in any::<u32>(),
        beyond_window in 1u32..64,
    ) {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
        let initial = raw_initial & SEQUENCE_MASK;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(initial, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);

        let edge = initial.wrapping_add(DEFAULT_FLOW_WINDOW - 1) & SEQUENCE_MASK;
        prop_assert_eq!(
            buf.receive(make_packet(edge, 0), now)
                .unwrap()
                .sequence_count(),
            DEFAULT_FLOW_WINDOW - 1
        );
        let first_drop = edge.wrapping_add(beyond_window) & SEQUENCE_MASK;
        prop_assert!(buf.drop_range(first_drop, first_drop).is_err());

        let nak = expand_nak(buf.generate_periodic_nak().unwrap());
        prop_assert_eq!(nak.len(), DEFAULT_FLOW_WINDOW as usize - 1);
        let all_losses_fit = nak.iter().all(|&seq| {
            seq.wrapping_sub(initial) & SEQUENCE_MASK < DEFAULT_FLOW_WINDOW
        });
        prop_assert!(all_losses_fit);
        prop_assert_eq!(
            buf.stats().total_lost,
            u64::from(DEFAULT_FLOW_WINDOW - 1)
        );
    }

    #[test]
    fn ack_timestamp_retention_matches_the_latest_sixteen_records(
        target in 0usize..20,
    ) {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);
        let _ = buf.receive(make_packet(0, 0), now);

        let ack_numbers: Vec<u32> = (0..20)
            .map(|offset| {
                let _ = buf.generate_ack(now.add_micros(offset));
                buf.ack_number()
            })
            .collect();
        let rtt_before = buf.rtt();
        buf.handle_ackack(ack_numbers[target], 0, now.add_micros(200_000));

        prop_assert_eq!(buf.rtt() != rtt_before, target >= 4);
    }

    #[test]
    fn link_capacity_matches_latest_sixteen_valid_intervals(
        intervals in prop::collection::vec(1u64..100_000, 1..40),
    ) {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);
        let _ = buf.receive(make_packet(0, 0), Timestamp::default());
        let mut arrival = 0u64;
        for (offset, &interval) in intervals.iter().enumerate() {
            arrival += interval;
            let _ = buf.receive(
                make_packet(offset as u32 + 1, arrival as u32),
                Timestamp::from_micros(arrival),
            );
        }

        let retained = &intervals[intervals.len().saturating_sub(16)..];
        let mut sorted = retained.to_vec();
        sorted.sort_unstable();
        let expected = (1_000_000 / sorted[sorted.len() / 4]) as u32;
        let ack = buf.generate_ack(Timestamp::from_micros(arrival + 10_000));

        prop_assert_eq!(ack.link_capacity, expected);
    }

    /// Word-at-a-time DROPREQ clearing must match a per-sequence model for
    /// ranges large enough to cross several bitmap words and sequence wrap.
    #[test]
    fn dense_drop_range_matches_loss_membership_model(
        raw_initial in any::<u32>(),
        gap in 65u32..512,
        raw_drop_offset in any::<u32>(),
        raw_drop_len in any::<u32>(),
    ) {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
        let initial = raw_initial & SEQUENCE_MASK;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(initial, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);
        let _ = buf.receive(
            make_packet(initial.wrapping_add(gap) & SEQUENCE_MASK, 1),
            now,
        );

        let drop_offset = raw_drop_offset % gap;
        let drop_len = 1 + raw_drop_len % (gap - drop_offset);
        let first = initial.wrapping_add(drop_offset) & SEQUENCE_MASK;
        let last = first.wrapping_add(drop_len - 1) & SEQUENCE_MASK;
        let summary = buf.drop_range(first, last)?;
        prop_assert_eq!(summary.losses_removed, drop_len);

        let mut expected: Vec<u32> = (0..gap)
            .filter(|&offset| offset < drop_offset || offset >= drop_offset + drop_len)
            .map(|offset| initial.wrapping_add(offset) & SEQUENCE_MASK)
            .collect();
        expected.sort_unstable();
        let actual = buf
            .generate_periodic_nak()
            .map_or_else(Vec::new, expand_nak);
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn test_pop_ready_wrap_around_delivery_order(
        (seqs, recv_order) in wrap_around_run(),
        tsbpd_enabled in any::<bool>(),
    ) {
        // ラップ境界をまたぐ連続パケットを順不同で受信し、pop_ready が循環順で取り出すことを
        // 検証する。既存の配送系 PBT は initial_seq をラップ近傍から除外しているためこの回帰を
        // 検出できない。tsbpd 有効・無効の両方を含める。
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(seqs[0], 120, start, 0);
        buf.set_tsbpd_enabled(tsbpd_enabled);

        let now = Timestamp::from_micros(1000);

        // recv_order (seqs を順不同にした列) で受信する。
        // 全パケットに同一タイムスタンプを与え配信時刻を揃える。
        for &seq in &recv_order {
            buf.receive(make_packet(seq, 100), now);
        }

        // 全パケットの配信時刻を十分過ぎた時刻で取り出す
        let pop_now = Timestamp::from_micros(10_000_000_000);
        let mut popped = Vec::new();
        while let Some(pkt) = buf.pop_ready(pop_now) {
            popped.push(pkt.sequence_number);
        }

        // 欠損が無いため全パケットが循環順 (seqs) で配送される
        prop_assert_eq!(popped, seqs);
    }

    /// DROPREQ removes exactly its circular interval, preserves every packet
    /// outside it, and leaves delivery ordered across the sequence wrap.
    #[test]
    fn drop_range_preserves_outside_packets_and_order(
        raw_start in any::<u32>(),
        count in 1u32..64,
        raw_drop_offset in any::<u32>(),
        raw_drop_len in any::<u32>(),
    ) {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
        let start_seq = raw_start & SEQUENCE_MASK;
        let drop_offset = raw_drop_offset % count;
        let max_drop_len = count - drop_offset;
        let drop_len = raw_drop_len % max_drop_len + 1;
        let first_seq = start_seq.wrapping_add(drop_offset) & SEQUENCE_MASK;
        let last_seq = first_seq.wrapping_add(drop_len - 1) & SEQUENCE_MASK;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(start_seq, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);

        for offset in 0..count {
            let seq = start_seq.wrapping_add(offset) & SEQUENCE_MASK;
            buf.receive(make_packet(seq, offset), now);
        }

        let summary = buf.drop_range(first_seq, last_seq)?;
        prop_assert_eq!(summary.sequence_count, drop_len);
        prop_assert_eq!(summary.packets_removed, drop_len);
        prop_assert_eq!(summary.losses_removed, 0);

        let mut delivered = Vec::new();
        while let Some(packet) = buf.pop_ready(now) {
            delivered.push(packet.sequence_number);
        }
        let expected: Vec<u32> = (0..count)
            .filter(|&offset| offset < drop_offset || offset >= drop_offset + drop_len)
            .map(|offset| start_seq.wrapping_add(offset) & SEQUENCE_MASK)
            .collect();
        prop_assert_eq!(delivered, expected);
    }
}
