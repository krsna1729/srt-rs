use srt_proto::group::GroupPacket;
use srt_proto::wire::{ControlPacket, ControlType, SrtPacket};
use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMemberState, GroupMode,
    SrtConnection, SrtGroup, TimerId, Timestamp,
};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

#[test]
fn group_member_limit_is_enforced() {
    let mut group = SrtGroup::new(0x4000_0100, GroupMode::Broadcast).unwrap();
    for member_id in 0..srt_proto::MAX_GROUP_MEMBERS as u32 {
        group
            .add_member(
                member_id,
                1,
                SrtConnection::new_caller(ConnectionOptions::default()),
            )
            .unwrap();
    }
    let result = group.add_member(
        srt_proto::MAX_GROUP_MEMBERS as u32,
        1,
        SrtConnection::new_caller(ConnectionOptions::default()),
    );
    assert!(result.is_err());
    assert_eq!(group.members().len(), srt_proto::MAX_GROUP_MEMBERS);
}

fn transfer(caller: &mut SrtConnection, listener: &mut SrtConnection, now: Timestamp) {
    while let Some(output) = caller.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(packet) = output {
            listener
                .feed_recv_buf(&packet, now)
                .expect("packet should decode");
        }
    }
}

fn establish_pair() -> (SrtConnection, SrtConnection) {
    establish_pair_with_options(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    })
}

fn establish_pair_with_options(options: ConnectionOptions) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        ..options.clone()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        tsbpd_delay: 0,
        ..options
    });
    caller.connect(ts(0)).expect("caller should connect");
    for round in 0..10 {
        transfer(&mut caller, &mut listener, ts(round * 10_000));
        while let Some(output) = listener.poll_output().unwrap() {
            if let ConnectionOutput::SendPacket(packet) = output {
                caller
                    .feed_recv_buf(&packet, ts(round * 10_000))
                    .expect("response should decode");
            }
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, listener);
        }
    }
    panic!("pair did not connect");
}

fn packets_from(connection: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while let Some(output) = connection.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(packet) = output {
            packets.push(packet);
        }
    }
    packets
}

fn transfer_to_group_member(
    source: &mut SrtConnection,
    group: &mut SrtGroup,
    member_id: u32,
    now: Timestamp,
) {
    for packet in packets_from(source) {
        group
            .member_mut(member_id)
            .expect("group member")
            .connection_mut()
            .feed_recv_buf(&packet, now)
            .expect("packet should decode");
    }
}

#[test]
fn broadcast_sends_one_sequence_to_every_active_member() {
    let (mut caller_a, mut listener_a) = establish_pair();
    let (mut caller_b, mut listener_b) = establish_pair();
    caller_a.synchronize_send_sequence(100).unwrap();
    caller_b.synchronize_send_sequence(200).unwrap();
    let mut group = SrtGroup::new(0x4000_0001, GroupMode::Broadcast).unwrap();
    group.add_member(1, 100, caller_a).unwrap();
    group.add_member(2, 100, caller_b).unwrap();

    assert_eq!(group.send(b"broadcast", ts(100_000)).unwrap(), 2);
    let packets_a = packets_from(group.member_mut(1).unwrap().connection_mut());
    let packets_b = packets_from(group.member_mut(2).unwrap().connection_mut());
    assert_eq!(packets_a.len(), 1);
    assert_eq!(packets_b.len(), 1);

    let sequence_a = match SrtPacket::decode(&packets_a[0]).unwrap() {
        SrtPacket::Data(packet) => packet.sequence_number,
        SrtPacket::Control(_) => panic!("broadcast send should produce data"),
    };
    let sequence_b = match SrtPacket::decode(&packets_b[0]).unwrap() {
        SrtPacket::Data(packet) => packet.sequence_number,
        SrtPacket::Control(_) => panic!("broadcast send should produce data"),
    };
    assert_eq!(sequence_a, sequence_b);
    listener_a
        .feed_recv_buf(&packets_a[0], ts(100_000))
        .unwrap();
    listener_b
        .feed_recv_buf(&packets_b[0], ts(100_000))
        .unwrap();
}

#[test]
fn aligned_group_member_retransmits_after_sequence_jump() {
    let options = ConnectionOptions {
        initial_seq: Some(0),
        flow_window_packets: 32,
        receive_buffer_packets: 32,
        ..ConnectionOptions::default()
    };
    let (mut leader, _) = establish_pair_with_options(options.clone());
    let (joining, _) = establish_pair_with_options(options);
    leader.synchronize_send_sequence(1_000).unwrap();

    let mut group = SrtGroup::new(0x4000_0018, GroupMode::Broadcast).unwrap();
    group.add_member(1, 1, leader).unwrap();
    group.add_member(2, 1, joining).unwrap();
    group.send(b"aligned", ts(100_000)).unwrap();
    packets_from(group.member_mut(1).unwrap().connection_mut());
    let sent = packets_from(group.member_mut(2).unwrap().connection_mut());
    assert_eq!(data_sequence(&sent[0]), 1_000);

    let member = group.member_mut(2).unwrap().connection_mut();
    let mut nak = ControlPacket::new(ControlType::Nak, 0, member.socket_id());
    nak.control_info.extend_from_slice(&1_000u32.to_be_bytes());
    let mut encoded = Vec::new();
    nak.encode(&mut encoded)
        .expect("packet fits configured datagram bound");
    member.feed_recv_buf(&encoded, ts(101_000)).unwrap();

    let retransmitted = packets_from(member)
        .into_iter()
        .filter_map(|packet| SrtPacket::decode(&packet).ok())
        .find_map(|packet| match packet {
            SrtPacket::Data(packet) if packet.retransmitted => Some(packet.sequence_number),
            _ => None,
        });
    assert_eq!(retransmitted, Some(1_000));
}

#[test]
fn broadcast_backpressure_requalifies_the_recovered_leg() {
    let constrained = ConnectionOptions {
        flow_window_packets: 3,
        ..Default::default()
    };
    let (caller_a, mut listener_a) = establish_pair_with_options(constrained);
    let (caller_b, _) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0015, GroupMode::Broadcast).unwrap();
    group.add_member(1, 1, caller_a).unwrap();
    group.add_member(2, 1, caller_b).unwrap();

    let mut stalled_packets = Vec::new();
    while group.member(1).unwrap().connection().can_send() {
        assert_eq!(group.send(b"fill", ts(100_000)).unwrap(), 2);
        stalled_packets.extend(packets_from(group.member_mut(1).unwrap().connection_mut()));
        let _ = packets_from(group.member_mut(2).unwrap().connection_mut());
    }

    assert!(group.member(2).unwrap().connection().can_send());
    assert!(group.can_send());
    assert_eq!(group.send(b"continue", ts(101_000)).unwrap(), 1);
    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Unstable);
    assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Active);

    for packet in stalled_packets {
        listener_a.feed_recv_buf(&packet, ts(102_000)).unwrap();
        while listener_a.poll_event().is_some() {}
    }
    // The first stalled packet already sent a DATA-path Full ACK at 102 ms;
    // like libsrt's `checkACKTimer`, the next Full ACK (carrying the final
    // position) is due one ACK interval later.
    listener_a.handle_timer(TimerId::Ack, ts(112_000)).unwrap();
    transfer(
        &mut listener_a,
        group.member_mut(1).unwrap().connection_mut(),
        ts(112_000),
    );

    assert!(group.can_send());
    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Active);
    assert_eq!(group.send(b"rejoined", ts(113_000)).unwrap(), 2);
}

#[test]
fn broadcast_receive_deduplicates_and_advances_other_links() {
    let (mut source_a, listener_a) = establish_pair();
    let (mut source_b, listener_b) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0002, GroupMode::Broadcast).unwrap();
    group.add_member(1, 100, listener_a).unwrap();
    group.add_member(2, 100, listener_b).unwrap();

    // Both sources send "hello" — each to its own listener. The group
    // deduplicates and delivers only one copy.
    source_a.send(b"hello", ts(100_000)).unwrap();
    let pkt_a = packets_from(&mut source_a).pop().unwrap();
    source_b.send(b"hello", ts(100_000)).unwrap();
    let pkt_b = packets_from(&mut source_b).pop().unwrap();

    group
        .member_mut(1)
        .unwrap()
        .connection_mut()
        .feed_recv_buf(&pkt_a, ts(100_000))
        .unwrap();
    group
        .member_mut(2)
        .unwrap()
        .connection_mut()
        .feed_recv_buf(&pkt_b, ts(100_000))
        .unwrap();

    let delivered = group.poll_data(ts(120_000)).unwrap();
    assert_eq!(delivered.payload.as_ref(), b"hello");
    // Second copy is deduplicated — only one delivery.
    assert!(group.poll_data(ts(120_000)).is_none());
    assert_eq!(
        group
            .member(1)
            .unwrap()
            .connection()
            .receiver_stats()
            .unwrap()
            .available_buffer_packets,
        8_192
    );
    assert_eq!(
        group
            .member(2)
            .unwrap()
            .connection()
            .receiver_stats()
            .unwrap()
            .available_buffer_packets,
        8_192
    );
}

#[test]
fn fragmented_group_message_advances_by_every_reassembled_packet() {
    const SEQUENCE_MASK: u32 = 0x7fff_ffff;

    for initial_seq in [100, SEQUENCE_MASK - 1] {
        let options = ConnectionOptions {
            initial_seq: Some(initial_seq),
            tsbpd_delay: 0,
            ..ConnectionOptions::default()
        };
        let (mut source, listener) = establish_pair_with_options(options);
        let mut group = SrtGroup::new(0x4000_0019, GroupMode::Backup).unwrap();
        group.add_member(1, 1, listener).unwrap();

        let fragmented = vec![0x5a; 3_000];
        source.send_message(&fragmented, ts(100_000)).unwrap();
        source.send(b"following", ts(100_001)).unwrap();
        for packet in packets_from(&mut source) {
            group
                .member_mut(1)
                .unwrap()
                .connection_mut()
                .feed_recv_buf(&packet, ts(110_000))
                .unwrap();
        }

        let first = group.poll_data(ts(120_000)).unwrap();
        assert_eq!(first.sequence_number, initial_seq);
        assert_eq!(first.packet_count, 3);
        assert_eq!(first.payload.as_ref(), fragmented);

        let following = group.poll_data(ts(120_000)).unwrap();
        assert_eq!(
            following.sequence_number,
            initial_seq.wrapping_add(3) & SEQUENCE_MASK
        );
        assert_eq!(following.packet_count, 1);
        assert_eq!(following.payload.as_ref(), b"following");
    }
}

#[test]
fn group_pending_payloads_remain_charged_to_the_member_window() {
    const WINDOW: u32 = 32;
    let options = ConnectionOptions {
        initial_seq: Some(0),
        tsbpd_delay: 0,
        flow_window_packets: WINDOW,
        receive_buffer_packets: WINDOW,
        delivery_queue_packets: WINDOW,
        ..ConnectionOptions::default()
    };
    let (mut source, listener) = establish_pair_with_options(options);
    let mut group = SrtGroup::new(0x4000_001a, GroupMode::Backup).unwrap();
    group.add_member(1, 1, listener).unwrap();

    for sequence_number in 0..WINDOW {
        source.send(&[sequence_number as u8], ts(100_000)).unwrap();
    }
    for packet in packets_from(&mut source) {
        group
            .member_mut(1)
            .unwrap()
            .connection_mut()
            .feed_recv_buf(&packet, ts(110_000))
            .unwrap();
    }

    assert_eq!(group.poll_data(ts(120_000)).unwrap().sequence_number, 0);
    assert_eq!(
        group
            .member(1)
            .unwrap()
            .connection()
            .receiver_stats()
            .unwrap()
            .available_buffer_packets,
        1
    );

    for expected in 1..WINDOW {
        assert_eq!(
            group.poll_data(ts(120_000)).unwrap().sequence_number,
            expected
        );
    }
    assert_eq!(
        group
            .member(1)
            .unwrap()
            .connection()
            .receiver_stats()
            .unwrap()
            .available_buffer_packets,
        WINDOW
    );
}

#[test]
fn group_catch_up_discards_obsolete_partial_member_message() {
    const WINDOW: u32 = 32;
    let options = ConnectionOptions {
        initial_seq: Some(100),
        tsbpd_delay: 0,
        flow_window_packets: WINDOW,
        receive_buffer_packets: WINDOW,
        ..ConnectionOptions::default()
    };
    let (mut source_a, listener_a) = establish_pair_with_options(options.clone());
    let (mut source_b, listener_b) = establish_pair_with_options(options);
    let mut group = SrtGroup::new(0x4000_001b, GroupMode::Broadcast).unwrap();
    group.add_member(1, 1, listener_a).unwrap();
    group.add_member(2, 1, listener_b).unwrap();

    let fragmented = vec![0x33; 3_000];
    source_a.send_message(&fragmented, ts(100_000)).unwrap();
    source_b.send_message(&fragmented, ts(100_000)).unwrap();
    for packet in packets_from(&mut source_a) {
        group
            .member_mut(1)
            .unwrap()
            .connection_mut()
            .feed_recv_buf(&packet, ts(110_000))
            .unwrap();
    }
    let first_fragment = packets_from(&mut source_b).remove(0);
    group
        .member_mut(2)
        .unwrap()
        .connection_mut()
        .feed_recv_buf(&first_fragment, ts(110_000))
        .unwrap();

    let delivered = group.poll_data(ts(120_000)).unwrap();
    assert_eq!(delivered.packet_count, 3);
    assert_eq!(delivered.payload.as_ref(), fragmented);
    assert_eq!(
        group
            .member(2)
            .unwrap()
            .connection()
            .receiver_stats()
            .unwrap()
            .available_buffer_packets,
        WINDOW
    );
}

#[test]
fn fragmented_group_delivery_releases_already_pending_overlaps() {
    const WINDOW: u32 = 32;
    let options_a = ConnectionOptions {
        initial_seq: Some(100),
        tsbpd_delay: 0,
        flow_window_packets: WINDOW,
        receive_buffer_packets: WINDOW,
        ..ConnectionOptions::default()
    };
    let options_b = ConnectionOptions {
        initial_seq: Some(101),
        ..options_a.clone()
    };
    let (mut source_a, listener_a) = establish_pair_with_options(options_a);
    let (mut source_b, listener_b) = establish_pair_with_options(options_b);
    let mut group = SrtGroup::new(0x4000_001c, GroupMode::Broadcast).unwrap();
    group.add_member(1, 1, listener_a).unwrap();
    group.add_member(2, 1, listener_b).unwrap();

    source_a
        .send_message(&vec![0x44; 3_000], ts(100_000))
        .unwrap();
    source_b.send(b"overlap-101", ts(100_000)).unwrap();
    source_b.send(b"overlap-102", ts(100_001)).unwrap();
    for packet in packets_from(&mut source_a) {
        group
            .member_mut(1)
            .unwrap()
            .connection_mut()
            .feed_recv_buf(&packet, ts(110_000))
            .unwrap();
    }
    for packet in packets_from(&mut source_b) {
        group
            .member_mut(2)
            .unwrap()
            .connection_mut()
            .feed_recv_buf(&packet, ts(110_000))
            .unwrap();
    }

    assert_eq!(group.poll_data(ts(120_000)).unwrap().packet_count, 3);
    assert!(group.poll_data(ts(120_000)).is_none());
    assert_eq!(
        group
            .member(2)
            .unwrap()
            .connection()
            .receiver_stats()
            .unwrap()
            .available_buffer_packets,
        WINDOW
    );
}

#[test]
fn backup_promotion_preserves_group_sequence() {
    let (caller_a, _listener_a) = establish_pair();
    let (caller_b, _listener_b) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0003, GroupMode::Backup).unwrap();
    group.add_member(1, 100, caller_a).unwrap();
    group.add_member(2, 1, caller_b).unwrap();

    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Active);
    assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Standby);
    group.send(b"primary", ts(100_000)).unwrap();
    let primary_packet = packets_from(group.member_mut(1).unwrap().connection_mut())
        .pop()
        .unwrap();
    assert_eq!(data_sequence(&primary_packet), 0);

    assert!(group.mark_member_broken(1));
    group.send(b"backup", ts(110_000)).unwrap();
    let backup_packet = packets_from(group.member_mut(2).unwrap().connection_mut())
        .pop()
        .unwrap();
    assert_eq!(data_sequence(&backup_packet), 1);
    assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Active);
}

#[test]
fn backup_backpressure_promotes_a_standby_leg() {
    let options = ConnectionOptions {
        flow_window_packets: 3,
        ..Default::default()
    };
    let (primary, _) = establish_pair_with_options(options.clone());
    let (backup, _) = establish_pair_with_options(options);
    let mut group = SrtGroup::new(0x4000_0016, GroupMode::Backup).unwrap();
    group.add_member(1, 100, primary).unwrap();
    group.add_member(2, 1, backup).unwrap();

    while group.member(1).unwrap().connection().can_send() {
        assert_eq!(group.send(b"fill", ts(100_000)).unwrap(), 1);
        let _ = packets_from(group.member_mut(1).unwrap().connection_mut());
    }

    assert!(!group.can_send());
    assert_eq!(group.send(b"fail over", ts(101_000)).unwrap(), 1);
    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Unstable);
    assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Active);
}

#[test]
fn backup_delivers_standby_payload_arriving_with_active_shutdown() {
    let (mut caller_a, listener_a) = establish_pair();
    let (mut caller_b, listener_b) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0004, GroupMode::Backup).unwrap();
    group.add_member(1, 100, listener_a).unwrap();
    group.add_member(2, 1, listener_b).unwrap();

    caller_a.send(b"primary", ts(100_000)).unwrap();
    let primary_packet = packets_from(&mut caller_a).pop().unwrap();
    caller_a.disconnect(ts(101_000));
    let shutdown_packet = packets_from(&mut caller_a)
        .into_iter()
        .find(|packet| {
            matches!(
                SrtPacket::decode(packet),
                Ok(SrtPacket::Control(control)) if control.control_type == ControlType::Shutdown
            )
        })
        .expect("active member should emit shutdown");

    caller_b.synchronize_send_sequence(1).unwrap();
    caller_b.send(b"backup", ts(102_000)).unwrap();
    let backup_packet = packets_from(&mut caller_b).pop().unwrap();

    group
        .member_mut(1)
        .unwrap()
        .connection_mut()
        .feed_recv_buf(&primary_packet, ts(102_000))
        .unwrap();
    group
        .member_mut(1)
        .unwrap()
        .connection_mut()
        .feed_recv_buf(&shutdown_packet, ts(102_000))
        .unwrap();
    group
        .member_mut(2)
        .unwrap()
        .connection_mut()
        .feed_recv_buf(&backup_packet, ts(102_000))
        .unwrap();

    assert_eq!(
        group.poll_data(ts(103_000)).unwrap().payload.as_ref(),
        b"primary"
    );
    assert_eq!(
        group.poll_data(ts(103_000)).unwrap().payload.as_ref(),
        b"backup"
    );
    assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Active);
}

fn data_sequence(packet: &[u8]) -> u32 {
    match SrtPacket::decode(packet).unwrap() {
        SrtPacket::Data(packet) => packet.sequence_number,
        SrtPacket::Control(_) => panic!("expected data packet"),
    }
}

#[test]
fn group_rejects_invalid_and_duplicate_ids() {
    assert!(SrtGroup::new(1, GroupMode::Broadcast).is_err());
    let (caller_a, _) = establish_pair();
    let (caller_b, _) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0010, GroupMode::Broadcast).unwrap();
    group.add_member(7, 1, caller_a).unwrap();
    assert!(group.add_member(7, 2, caller_b).is_err());
    assert_eq!(group.members().len(), 1);
}

#[test]
fn backup_removal_promotes_highest_weight_with_stable_tie_break() {
    let (primary, _) = establish_pair();
    let (standby_high_id, _) = establish_pair();
    let (standby_low_id, _) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0011, GroupMode::Backup).unwrap();
    group.add_member(9, 1, primary).unwrap();
    group.add_member(5, 100, standby_high_id).unwrap();
    group.add_member(3, 100, standby_low_id).unwrap();

    assert!(group.remove_member(9));
    assert!(!group.remove_member(9));
    assert_eq!(group.send(b"failover", ts(100_000)).unwrap(), 1);
    assert_eq!(group.member(3).unwrap().state(), GroupMemberState::Active);
    assert_eq!(group.member(5).unwrap().state(), GroupMemberState::Standby);
}

const REMOVAL_WINDOW: u32 = 32;

fn removal_options(initial_seq: u32) -> ConnectionOptions {
    ConnectionOptions {
        initial_seq: Some(initial_seq),
        tsbpd_delay: 0,
        flow_window_packets: REMOVAL_WINDOW,
        receive_buffer_packets: REMOVAL_WINDOW,
        ..ConnectionOptions::default()
    }
}

fn available_window(connection: &SrtConnection) -> u32 {
    connection
        .receiver_stats()
        .expect("connected member has a receiver")
        .available_buffer_packets
}

fn member_window(group: &SrtGroup, member_id: u32) -> u32 {
    available_window(group.member(member_id).expect("group member").connection())
}

/// A group whose logical stream waits at sequence 101: member 2 delivered
/// 100 and will later fill the gap.
fn group_waiting_at_101(group_id: u32) -> (SrtGroup, SrtConnection) {
    let (mut gap_source, gap_member) = establish_pair_with_options(removal_options(100));
    let mut group = SrtGroup::new(group_id, GroupMode::Broadcast).unwrap();
    group.add_member(2, 1, gap_member).unwrap();
    gap_source.send(b"start", ts(100_000)).unwrap();
    transfer_to_group_member(&mut gap_source, &mut group, 2, ts(110_000));
    assert_eq!(
        next_data(&mut group, ts(120_000)).unwrap().sequence_number,
        100
    );
    (group, gap_source)
}

/// The next logical payload. One `poll_data` visit collects member events
/// round-robin and may return before reaching the member that holds the
/// next sequence, so poll once per possible member before calling it absent.
fn next_data(group: &mut SrtGroup, now: Timestamp) -> Option<GroupPacket> {
    (0..=srt_proto::MAX_GROUP_MEMBERS).find_map(|_| group.poll_data(now))
}

/// Feed only the DATA packets whose sequence is in `sequences`.
fn transfer_sequences_to_group_member(
    source: &mut SrtConnection,
    group: &mut SrtGroup,
    member_id: u32,
    sequences: std::ops::RangeInclusive<u32>,
    now: Timestamp,
) {
    for packet in packets_from(source) {
        if matches!(SrtPacket::decode(&packet), Ok(SrtPacket::Data(data)) if sequences.contains(&data.sequence_number))
        {
            group
                .member_mut(member_id)
                .expect("group member")
                .connection_mut()
                .feed_recv_buf(&packet, now)
                .expect("packet should decode");
        }
    }
}

/// A complete payload the group already collected from a member belongs to
/// the group. Removing that member -- by either API -- must not lose it: it
/// is delivered once, in order, after the gap fills. An incomplete message
/// on the removed leg never becomes deliverable, and the removed leg's
/// reservation is released exactly once, at detach, so a later poll cannot
/// release it again into a member that reuses the ID.
#[test]
fn removed_member_complete_pending_payload_is_delivered_once_in_order() {
    for return_connection in [false, true] {
        let (mut group, mut gap_source) = group_waiting_at_101(0x4000_001d);
        let (mut ahead_source, ahead_member) = establish_pair_with_options(removal_options(102));
        group.add_member(1, 1, ahead_member).unwrap();

        // Member 1 holds complete 102 behind the gap, plus only the first
        // fragment of a 103..=105 message.
        ahead_source.send(b"held", ts(120_001)).unwrap();
        ahead_source
            .send_message(&[0x66; 3_000], ts(120_002))
            .unwrap();
        transfer_sequences_to_group_member(
            &mut ahead_source,
            &mut group,
            1,
            102..=103,
            ts(120_002),
        );
        assert!(next_data(&mut group, ts(120_002)).is_none());
        assert_eq!(member_window(&group, 1), REMOVAL_WINDOW - 2);

        if return_connection {
            let removed = group.remove_member_connection(1).unwrap();
            // The held payload's reservation came back; the incomplete
            // fragment is still the leg's own.
            assert_eq!(available_window(&removed), REMOVAL_WINDOW - 1);
        } else {
            assert!(group.remove_member(1));
        }
        let (_replacement_source, replacement) = establish_pair_with_options(removal_options(106));
        group.add_member(1, 1, replacement).unwrap();

        gap_source.send(b"fill", ts(130_000)).unwrap();
        transfer_to_group_member(&mut gap_source, &mut group, 2, ts(130_000));
        let filled = next_data(&mut group, ts(140_000)).unwrap();
        assert_eq!(
            (filled.sequence_number, filled.payload.as_ref()),
            (101, &b"fill"[..])
        );
        let held = next_data(&mut group, ts(140_000))
            .expect("the removed member's complete payload survives removal");
        assert_eq!(
            (held.sequence_number, held.member_id, held.packet_count),
            (102, 1, 1)
        );
        assert_eq!(held.payload.as_ref(), b"held");
        assert!(next_data(&mut group, ts(140_000)).is_none());
        assert!(next_data(&mut group, ts(150_000)).is_none());
        assert_eq!(member_window(&group, 1), REMOVAL_WINDOW);
        assert_eq!(member_window(&group, 2), REMOVAL_WINDOW);
    }
}

/// A group-owned payload overlapped by a longer delivered message is
/// retired by the ordinary poll rule, and releases nothing: its reservation
/// already went back when its member was removed.
#[test]
fn removed_member_pending_overlap_retires_without_a_second_release() {
    let (mut group, mut gap_source) = group_waiting_at_101(0x4000_001f);
    let (mut single_source, single_member) = establish_pair_with_options(removal_options(103));
    let (mut long_source, long_member) = establish_pair_with_options(removal_options(102));
    group.add_member(1, 1, single_member).unwrap();
    group.add_member(3, 1, long_member).unwrap();

    single_source.send(b"overlap-103", ts(120_001)).unwrap();
    transfer_to_group_member(&mut single_source, &mut group, 1, ts(120_001));
    long_source
        .send_message(&[0x77; 3_000], ts(120_001))
        .unwrap();
    transfer_to_group_member(&mut long_source, &mut group, 3, ts(120_001));
    assert!(next_data(&mut group, ts(120_001)).is_none());

    assert!(group.remove_member(1));
    let (_replacement_source, replacement) = establish_pair_with_options(removal_options(106));
    group.add_member(1, 1, replacement).unwrap();

    gap_source.send(b"fill", ts(130_000)).unwrap();
    transfer_to_group_member(&mut gap_source, &mut group, 2, ts(130_000));
    assert_eq!(
        next_data(&mut group, ts(140_000)).unwrap().sequence_number,
        101
    );
    let long = next_data(&mut group, ts(140_000)).unwrap();
    assert_eq!((long.sequence_number, long.packet_count), (102, 3));
    assert!(next_data(&mut group, ts(140_000)).is_none());
    assert_eq!(member_window(&group, 1), REMOVAL_WINDOW);
    assert_eq!(member_window(&group, 3), REMOVAL_WINDOW);
}

/// Payloads the group keeps for removed members are charged to no member
/// window, so member churn cannot grow them past the largest member
/// receive window. The ones nearest delivery are kept.
#[test]
fn member_churn_cannot_accumulate_uncharged_pending_payloads() {
    const CHURNED: u32 = REMOVAL_WINDOW + 8;
    let (mut group, mut gap_source) = group_waiting_at_101(0x4000_001e);

    for offset in 0..CHURNED {
        let sequence = 102 + offset;
        let (mut source, member) = establish_pair_with_options(removal_options(sequence));
        group.add_member(1, 1, member).unwrap();
        source.send(&sequence.to_be_bytes(), ts(120_001)).unwrap();
        transfer_to_group_member(&mut source, &mut group, 1, ts(120_001));
        assert!(next_data(&mut group, ts(120_001)).is_none());
        assert!(group.remove_member(1));
    }

    gap_source.send(b"close gap", ts(130_000)).unwrap();
    transfer_to_group_member(&mut gap_source, &mut group, 2, ts(130_000));
    for expected in 101..102 + REMOVAL_WINDOW {
        let packet = next_data(&mut group, ts(140_000)).unwrap();
        assert_eq!(packet.sequence_number, expected);
        if expected > 101 {
            assert_eq!(packet.payload.as_ref(), expected.to_be_bytes());
        }
    }
    assert!(next_data(&mut group, ts(140_000)).is_none());
    assert_eq!(member_window(&group, 2), REMOVAL_WINDOW);
}

#[test]
fn group_with_no_healthy_members_fails_without_panicking() {
    let (member, _) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0012, GroupMode::Backup).unwrap();
    group.add_member(1, 1, member).unwrap();
    assert!(group.mark_member_broken(1));
    assert!(!group.mark_member_broken(99));
    assert!(group.send(b"unroutable", ts(100_000)).is_err());
}

#[test]
fn group_send_sequence_wraps_at_srt_sequence_boundary() {
    let (mut member, _) = establish_pair();
    member.synchronize_send_sequence(0x7fff_ffff).unwrap();
    let mut group = SrtGroup::new(0x4000_0013, GroupMode::Backup).unwrap();
    group.add_member(1, 1, member).unwrap();

    group.send(b"last", ts(100_000)).unwrap();
    let last = packets_from(group.member_mut(1).unwrap().connection_mut())
        .pop()
        .unwrap();
    group.send(b"wrapped", ts(101_000)).unwrap();
    let wrapped = packets_from(group.member_mut(1).unwrap().connection_mut())
        .pop()
        .unwrap();
    assert_eq!(data_sequence(&last), 0x7fff_ffff);
    assert_eq!(data_sequence(&wrapped), 0);
}

#[test]
fn pending_member_becomes_active_after_handshake() {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    });
    let listener = SrtConnection::new_listener(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    });
    let mut group = SrtGroup::new(0x4000_0014, GroupMode::Broadcast).unwrap();
    group.add_member(1, 1, listener).unwrap();
    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Pending);

    caller.connect(ts(0)).unwrap();
    for round in 0..10 {
        let now = ts(round * 10_000);
        transfer(
            &mut caller,
            group.member_mut(1).unwrap().connection_mut(),
            now,
        );
        while let Some(output) = group
            .member_mut(1)
            .unwrap()
            .connection_mut()
            .poll_output()
            .unwrap()
        {
            if let ConnectionOutput::SendPacket(packet) = output {
                caller.feed_recv_buf(&packet, now).unwrap();
            }
        }
        if caller.state() == ConnectionState::Connected
            && group.member(1).unwrap().connection().state() == ConnectionState::Connected
        {
            break;
        }
    }
    group.send(b"activated", ts(100_000)).unwrap();
    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Active);
}

#[test]
fn late_pending_member_waits_for_handshake_before_sequence_alignment() {
    let (active, _) = establish_pair();
    let pending = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    });
    let mut group = SrtGroup::new(0x4000_0017, GroupMode::Broadcast).unwrap();
    group.add_member(1, 1, active).unwrap();

    // A newly added caller has no sender buffer until its handshake completes.
    // Adding it to an already active group must retain it as Pending rather
    // than attempting sequence alignment against that absent buffer.
    group.add_member(2, 1, pending).unwrap();
    assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Pending);
}
