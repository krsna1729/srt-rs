//! Backup-mode retirement-prefix challenger.
//!
//! One old active leg's flight arrives after a standby leg has advanced the
//! group's retirement prefix, and the old leg then returns with the next
//! sequence. The group must deduplicate the retired sequence, keep delivering
//! contiguously across the 31-bit wrap, accept the returning leg without
//! fabricating an acknowledgment, and leave member states unchanged.
//!
//! The scenario is the composition the per-case group tests do not cover:
//! `broadcast_receive_deduplicates_and_advances_other_links` deduplicates
//! without a second delivery path,
//! `backup_promotion_preserves_group_sequence` promotes without an old flight
//! arriving afterwards, and `aligned_group_member_retransmits_after_sequence_jump`
//! aligns a leg without the group prefix having moved.

use srt_proto::wire::SrtPacket;
use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMemberState, GroupMode,
    SrtConnection, SrtGroup, Timestamp,
};

/// Three sequences before the wrap, so the scenario delivers across it.
const SEQUENCE_MASK: u32 = 0x7fff_ffff;
const BASE: u32 = SEQUENCE_MASK - 1;

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

/// Connected caller/listener pair, driven by real handshake packets.
fn establish_pair(options: ConnectionOptions) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        ..options.clone()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 2,
        syn_cookie: Some(7),
        tsbpd_delay: 0,
        ..options
    });
    caller.connect(ts(0)).expect("caller should connect");
    for round in 0..10 {
        for packet in packets_from(&mut caller) {
            listener
                .feed_recv_buf(&packet, ts(round * 10_000))
                .expect("request should decode");
        }
        for packet in packets_from(&mut listener) {
            caller
                .feed_recv_buf(&packet, ts(round * 10_000))
                .expect("response should decode");
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

fn data_sequence(packet: &[u8]) -> u32 {
    match SrtPacket::decode(packet).unwrap() {
        SrtPacket::Data(packet) => packet.sequence_number,
        SrtPacket::Control(_) => panic!("expected data packet"),
    }
}

fn feed(group: &mut SrtGroup, member_id: u32, packet: &[u8], now: Timestamp) {
    group
        .member_mut(member_id)
        .expect("group member")
        .connection_mut()
        .feed_recv_buf(packet, now)
        .expect("packet should decode");
}

/// Return the member's control packets to the source, so the member's
/// acknowledgments really retire the source's flight.
fn return_control(source: &mut SrtConnection, member: &mut SrtConnection, now: Timestamp) {
    for packet in packets_from(member) {
        source
            .feed_recv_buf(&packet, now)
            .expect("control should decode");
    }
}

fn available_buffer_packets(group: &SrtGroup, member_id: u32) -> u32 {
    group
        .member(member_id)
        .expect("group member")
        .connection()
        .receiver_stats()
        .expect("receiver stats")
        .available_buffer_packets
}

/// A backup group whose retirement prefix has moved three sequences, the last
/// of which crosses the wrap: the active leg delivered `first`, the standby
/// advanced one further, and the returning leg delivered the sequence after
/// that. `first` is therefore retired, and `source_a` is the old flight's leg.
struct PrefixFixture {
    group: SrtGroup,
    source_a: SrtConnection,
    first: Vec<u8>,
}

/// The same group one delivery earlier: only the active leg has sent, its
/// packet is delivered and acknowledged, and the standby has sent nothing.
struct FirstDelivery {
    group: SrtGroup,
    source_a: SrtConnection,
    source_b: SrtConnection,
    first: Vec<u8>,
}

fn group_after_the_active_legs_first_delivery() -> FirstDelivery {
    let options = ConnectionOptions {
        initial_seq: Some(BASE),
        ..ConnectionOptions::default()
    };
    let (mut source_a, listener_a) = establish_pair(options.clone());
    let (source_b, listener_b) = establish_pair(options);
    let mut group = SrtGroup::new(0x4000_0021, GroupMode::Backup).unwrap();
    group.add_member(1, 100, listener_a).unwrap();
    group.add_member(2, 1, listener_b).unwrap();
    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Active);
    assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Standby);

    // The active leg's first packet is delivered, so the retirement prefix sits
    // one sequence past it and every member cursor advanced with it.
    source_a.send(b"first", ts(100_000)).unwrap();
    let first = packets_from(&mut source_a).pop().unwrap();
    assert_eq!(data_sequence(&first), BASE);
    feed(&mut group, 1, &first, ts(101_000));
    let delivered = group.poll_data(ts(101_000)).expect("first is delivered");
    assert_eq!(delivered.member_id, 1);
    assert_eq!(delivered.sequence_number, BASE);
    assert!(delivered.payload.eq(&b"first"[..]));
    assert!(group.poll_data(ts(101_000)).is_none());
    return_control(
        &mut source_a,
        group.member_mut(1).unwrap().connection_mut(),
        ts(101_500),
    );
    assert_eq!(
        source_a.sender_stats().unwrap().packets_in_buffer,
        0,
        "a delivered sequence retires the peer's flight"
    );

    FirstDelivery {
        group,
        source_a,
        source_b,
        first,
    }
}

fn advanced_prefix_group() -> PrefixFixture {
    let FirstDelivery {
        mut group,
        mut source_a,
        mut source_b,
        first,
    } = group_after_the_active_legs_first_delivery();

    // The standby leg advances the prefix with the very next sequence, which is
    // what a promoted leg sends, and the leg after that crosses the wrap.
    source_b
        .synchronize_send_sequence(BASE.wrapping_add(1) & SEQUENCE_MASK)
        .unwrap();
    source_b.send(b"second", ts(102_000)).unwrap();
    let second = packets_from(&mut source_b).pop().unwrap();
    assert_eq!(data_sequence(&second), BASE.wrapping_add(1) & SEQUENCE_MASK);
    feed(&mut group, 2, &second, ts(102_500));
    let delivered = group
        .poll_data(ts(102_500))
        .expect("the standby advances the prefix");
    assert_eq!(delivered.member_id, 2);
    assert!(delivered.payload.eq(&b"second"[..]));

    source_a
        .synchronize_send_sequence(BASE.wrapping_add(2) & SEQUENCE_MASK)
        .unwrap();
    source_a.send(b"third", ts(104_000)).unwrap();
    let third = packets_from(&mut source_a).pop().unwrap();
    assert_eq!(data_sequence(&third), BASE.wrapping_add(2) & SEQUENCE_MASK);
    feed(&mut group, 1, &third, ts(104_500));
    let delivered = group
        .poll_data(ts(104_500))
        .expect("the returning leg is accepted");
    assert_eq!(delivered.member_id, 1);
    assert_eq!(
        delivered.sequence_number,
        BASE.wrapping_add(2) & SEQUENCE_MASK
    );
    assert!(delivered.payload.eq(&b"third"[..]));
    assert!(group.poll_data(ts(104_500)).is_none());
    return_control(
        &mut source_a,
        group.member_mut(1).unwrap().connection_mut(),
        ts(104_800),
    );
    PrefixFixture {
        group,
        source_a,
        first,
    }
}

#[test]
fn a_retired_flight_does_not_redeliver_or_fabricate_an_acknowledgment() {
    let PrefixFixture {
        mut group,
        mut source_a,
        first,
    } = advanced_prefix_group();

    // The old flight arrives late: the same sequence again, on the leg that
    // first delivered it. The prefix already retired it, so it is dropped
    // rather than delivered twice, and no acknowledgment is fabricated for a
    // sequence the group never delivered.
    feed(&mut group, 1, &first, ts(103_000));
    assert!(
        group.poll_data(ts(103_000)).is_none(),
        "a retired sequence is not delivered twice"
    );
    return_control(
        &mut source_a,
        group.member_mut(1).unwrap().connection_mut(),
        ts(103_500),
    );
    assert!(
        source_a.send(b"fourth", ts(105_000)).is_ok(),
        "the returning leg stays writable"
    );

    // Retirement authority moved without changing the topology: the leg that
    // advanced the prefix is still the standby, and the active leg is still
    // selectable.
    assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Active);
    assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Standby);
}

#[test]
fn a_late_leg_cannot_reopen_a_retired_sequence() {
    let PrefixFixture {
        mut group, first, ..
    } = advanced_prefix_group();

    // The same stale copy on the standby, which never received it at all:
    // delivery advanced every member's cursor, not just the delivering one, so
    // the standby has nothing left to deliver and nothing new to reserve.
    let standby_capacity = available_buffer_packets(&group, 2);
    feed(&mut group, 2, &first, ts(103_200));
    assert!(
        group.poll_data(ts(103_200)).is_none(),
        "the standby leg does not deliver the retired sequence either"
    );
    assert_eq!(
        available_buffer_packets(&group, 2),
        standby_capacity,
        "a retired sequence reserves no window on a leg that never delivered it"
    );

    // A leg that joins after the prefix advanced carries no receive cursor of
    // its own at the group position, so the group's own retirement prefix is
    // what returns the reservation instead of holding it.
    let (_, listener_c) = establish_pair(ConnectionOptions {
        initial_seq: Some(BASE),
        ..ConnectionOptions::default()
    });
    group.add_member(3, 1, listener_c).unwrap();
    let late_capacity = available_buffer_packets(&group, 3);
    feed(&mut group, 3, &first, ts(105_000));
    assert!(
        group.poll_data(ts(105_000)).is_none(),
        "a late leg cannot reopen a retired sequence"
    );
    assert_eq!(
        available_buffer_packets(&group, 3),
        late_capacity,
        "the group returns the retired sequence's reservation instead of holding it"
    );
}
