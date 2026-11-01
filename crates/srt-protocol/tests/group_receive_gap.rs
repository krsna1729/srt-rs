//! A sequence every group member lost must not stall the receiving group.

use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMode, SrtConnection, SrtGroup,
    TimerId, Timestamp,
};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
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

/// A connected pair that keeps `options`' TSBPD latency.
fn connect_pair(options: ConnectionOptions) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(options.clone());
    let mut listener = SrtConnection::new_listener(options);
    caller.connect(ts(0)).expect("caller connects");
    for round in 0..10 {
        let now = ts(round * 10_000);
        for packet in packets_from(&mut caller) {
            listener.feed_recv_buf(&packet, now).expect("decodes");
        }
        for packet in packets_from(&mut listener) {
            caller.feed_recv_buf(&packet, now).expect("decodes");
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, listener);
        }
    }
    panic!("pair did not connect");
}

/// Both links lose the same sequence. Each member's TLPKTDROP gives up on it
/// and releases the next packet; the group must then deliver that packet, in
/// order, and count the one sequence it skipped.
#[test]
fn group_receiver_skips_a_sequence_every_member_lost() {
    let options = ConnectionOptions {
        tsbpd_delay: 100,
        ..Default::default()
    };
    let mut group = SrtGroup::new(0x4000_0050, GroupMode::Broadcast).unwrap();
    let mut sources = Vec::new();
    for member_id in [1, 2] {
        let (source, listener) = connect_pair(options.clone());
        group.add_member(member_id, 1, listener).unwrap();
        sources.push((member_id, source));
    }

    let sent = ts(200_000);
    for (member_id, source) in &mut sources {
        let mut packets = Vec::new();
        for payload in [&b"zero"[..], b"one", b"two"] {
            source.send(payload, sent).unwrap();
            packets.extend(packets_from(source));
        }
        packets.remove(1); // "one" is lost on every link
        let member = group.member_mut(*member_id).unwrap().connection_mut();
        for packet in packets {
            member.feed_recv_buf(&packet, sent).unwrap();
        }
    }
    // Past each member's drop point: the deadline plus srt-rs's 1 s minimum.
    let late = ts(2_000_000);
    for member_id in [1, 2] {
        let member = group.member_mut(member_id).unwrap().connection_mut();
        member.handle_timer(TimerId::Ack, late).unwrap();
        let _ = packets_from(member);
    }

    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| group.poll_data(late))
        .map(|packet| {
            packet
                .payload
                .chunks()
                .flat_map(|chunk| chunk.to_vec())
                .collect()
        })
        .collect();
    assert_eq!(delivered, [b"zero".to_vec(), b"two".to_vec()]);
    assert_eq!(group.skipped_receive_packets(), 1);
}

/// Only one link loses the sequence. The group may see that link release
/// the next packet first, but it must still deliver the other link's copy
/// rather than skip it.
#[test]
fn group_receiver_takes_a_sequence_another_member_still_holds() {
    let options = ConnectionOptions {
        tsbpd_delay: 100,
        ..Default::default()
    };
    let mut group = SrtGroup::new(0x4000_0051, GroupMode::Broadcast).unwrap();
    let mut sources = Vec::new();
    for member_id in [1, 2] {
        let (source, listener) = connect_pair(options.clone());
        group.add_member(member_id, 1, listener).unwrap();
        sources.push((member_id, source));
    }

    let sent = ts(200_000);
    for (member_id, source) in &mut sources {
        let mut packets = Vec::new();
        for payload in [&b"zero"[..], b"one", b"two"] {
            source.send(payload, sent).unwrap();
            packets.extend(packets_from(source));
        }
        if *member_id == 1 {
            packets.remove(1); // only link 1 loses "one"
        }
        let member = group.member_mut(*member_id).unwrap().connection_mut();
        for packet in packets {
            member.feed_recv_buf(&packet, sent).unwrap();
        }
    }
    let late = ts(2_000_000);
    for member_id in [1, 2] {
        let member = group.member_mut(member_id).unwrap().connection_mut();
        member.handle_timer(TimerId::Ack, late).unwrap();
        let _ = packets_from(member);
    }

    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| group.poll_data(late))
        .map(|packet| {
            packet
                .payload
                .chunks()
                .flat_map(|chunk| chunk.to_vec())
                .collect()
        })
        .collect();
    assert_eq!(
        delivered,
        [b"zero".to_vec(), b"one".to_vec(), b"two".to_vec()]
    );
    assert_eq!(group.skipped_receive_packets(), 0);
}
