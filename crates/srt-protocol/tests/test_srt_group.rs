use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, ControlType, GroupMemberState, GroupMode,
    SrtConnection, SrtGroup, SrtPacket, TimerId, Timestamp,
};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn transfer(caller: &mut SrtConnection, listener: &mut SrtConnection, now: Timestamp) {
    while let Some(output) = caller.poll_output() {
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
        while let Some(output) = listener.poll_output() {
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
    while let Some(output) = connection.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            packets.push(packet);
        }
    }
    packets
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
    listener_a.handle_timer(TimerId::Ack, ts(103_000)).unwrap();
    transfer(
        &mut listener_a,
        group.member_mut(1).unwrap().connection_mut(),
        ts(103_000),
    );

    assert!(group.can_send());
    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Active);
    assert_eq!(group.send(b"rejoined", ts(104_000)).unwrap(), 2);
}

#[test]
fn broadcast_receive_deduplicates_and_advances_other_links() {
    let (mut source, listener_a) = establish_pair();
    let (_, listener_b) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0002, GroupMode::Broadcast).unwrap();
    group.add_member(1, 100, listener_a).unwrap();
    group.add_member(2, 100, listener_b).unwrap();

    source.send(b"first", ts(100_000)).unwrap();
    let first = packets_from(&mut source).pop().unwrap();
    source.send(b"second", ts(110_000)).unwrap();
    let second = packets_from(&mut source).pop().unwrap();

    group
        .member_mut(1)
        .unwrap()
        .connection_mut()
        .feed_recv_buf(&first, ts(100_000))
        .unwrap();
    group
        .member_mut(2)
        .unwrap()
        .connection_mut()
        .feed_recv_buf(&second, ts(110_000))
        .unwrap();

    let delivered_first = group.poll_data(ts(120_000)).unwrap();
    assert_eq!(delivered_first.payload, b"first");
    let delivered_second = group.poll_data(ts(120_000)).unwrap();
    assert_eq!(delivered_second.payload, b"second");
    assert!(group.poll_data(ts(120_000)).is_none());
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

    assert_eq!(group.poll_data(ts(103_000)).unwrap().payload, b"primary");
    assert_eq!(group.poll_data(ts(103_000)).unwrap().payload, b"backup");
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
        while let Some(output) = group.member_mut(1).unwrap().connection_mut().poll_output() {
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
