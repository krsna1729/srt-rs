use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, ControlType, GroupMemberState, GroupMode,
    SrtConnection, SrtGroup, SrtPacket, Timestamp,
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
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
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
    let (caller_a, mut listener_a) = establish_pair();
    let (caller_b, mut listener_b) = establish_pair();
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
