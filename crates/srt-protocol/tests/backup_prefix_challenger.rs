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

use srt_proto::group::GroupEvent;
use srt_proto::wire::{ControlType, SrtPacket};
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

/// Return control packets to the source, so the member's acknowledgments really
/// retire the source's flight.
fn return_packets(source: &mut SrtConnection, packets: Vec<Vec<u8>>, now: Timestamp) {
    for packet in packets {
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

/// The sequence numbers acknowledged by the given control packets. The first
/// four bytes of an ACK's control information are the acknowledged sequence
/// number (`send_ack`).
fn acknowledged_sequences(packets: &[Vec<u8>]) -> Vec<u32> {
    let mut acknowledged = Vec::new();
    for packet in packets {
        if let Ok(SrtPacket::Control(control)) = SrtPacket::decode(packet)
            && control.control_type == ControlType::Ack
            && control.control_info.len() >= 4
        {
            acknowledged.push(u32::from_be_bytes([
                control.control_info[0],
                control.control_info[1],
                control.control_info[2],
                control.control_info[3],
            ]));
        }
    }
    acknowledged
}

/// The group's retirement prefix after the three deliveries of the fixture: the
/// sequence one past the wrap.
fn prefix() -> u32 {
    BASE.wrapping_add(3) & SEQUENCE_MASK
}

/// Whether `sequence` lies past `prefix` in the 31-bit sequence comparison
/// space, so a prefix-relative assertion uses the same wrap the protocol does.
fn sequence_past(sequence: u32, prefix: u32) -> bool {
    /// Half the 31-bit sequence space: the point where "ahead" becomes
    /// "behind" in the protocol's own comparison.
    const HALF_SEQUENCE_SPACE: u32 = 1 << 30;
    let ahead = sequence.wrapping_sub(prefix) & SEQUENCE_MASK;
    ahead != 0 && ahead < HALF_SEQUENCE_SPACE
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
    let packets = packets_from(group.member_mut(1).unwrap().connection_mut());
    assert!(
        acknowledged_sequences(&packets).contains(&(BASE.wrapping_add(1) & SEQUENCE_MASK)),
        "the delivering leg acknowledges the sequence it delivered"
    );
    return_packets(&mut source_a, packets, ts(101_500));
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
    source_b.send(b"second", ts(120_000)).unwrap();
    let second = packets_from(&mut source_b).pop().unwrap();
    assert_eq!(data_sequence(&second), BASE.wrapping_add(1) & SEQUENCE_MASK);
    feed(&mut group, 2, &second, ts(120_500));
    let delivered = group
        .poll_data(ts(120_500))
        .expect("the standby advances the prefix");
    assert_eq!(delivered.member_id, 2);
    assert!(delivered.payload.eq(&b"second"[..]));

    source_a
        .synchronize_send_sequence(BASE.wrapping_add(2) & SEQUENCE_MASK)
        .unwrap();
    source_a.send(b"third", ts(140_000)).unwrap();
    let third = packets_from(&mut source_a).pop().unwrap();
    assert_eq!(data_sequence(&third), BASE.wrapping_add(2) & SEQUENCE_MASK);
    feed(&mut group, 1, &third, ts(140_500));
    let delivered = group
        .poll_data(ts(140_500))
        .expect("the returning leg is accepted");
    assert_eq!(delivered.member_id, 1);
    assert_eq!(
        delivered.sequence_number,
        BASE.wrapping_add(2) & SEQUENCE_MASK
    );
    assert!(delivered.payload.eq(&b"third"[..]));
    assert!(group.poll_data(ts(140_500)).is_none());
    let packets = packets_from(group.member_mut(1).unwrap().connection_mut());
    let acknowledged = acknowledged_sequences(&packets);
    assert!(
        acknowledged.contains(&prefix()),
        "the returning leg acknowledges the moved prefix, got {acknowledged:?}"
    );
    for sequence in &acknowledged {
        assert!(
            !sequence_past(*sequence, prefix()),
            "an acknowledgment for {sequence} runs past the delivered prefix"
        );
    }
    return_packets(&mut source_a, packets, ts(140_800));
    PrefixFixture {
        group,
        source_a,
        first,
    }
}

#[test]
fn a_stale_flight_copy_is_not_delivered_again_or_acknowledged_past_the_prefix() {
    let PrefixFixture {
        mut group,
        mut source_a,
        first,
    } = advanced_prefix_group();
    let prefix = prefix();

    // The old flight arrives late: the same sequence again, on the leg that
    // first delivered it. That leg's own receive cursor already covers the
    // sequence, so it is dropped inside the connection; what this asserts is
    // the end-to-end property, that the duplicate produces neither a delivery
    // nor an acknowledgment past what the group really delivered. The group's
    // own prefix guard is exercised by the late-leg test below.
    feed(&mut group, 1, &first, ts(160_000));
    assert!(
        group.poll_data(ts(160_000)).is_none(),
        "a retired sequence is not delivered twice"
    );
    let packets = packets_from(group.member_mut(1).unwrap().connection_mut());
    for sequence in acknowledged_sequences(&packets) {
        assert!(
            !sequence_past(sequence, prefix),
            "an acknowledgment for {sequence} runs past the delivered prefix {prefix}"
        );
    }
    return_packets(&mut source_a, packets, ts(160_100));
    assert!(
        source_a.send(b"fourth", ts(160_200)).is_ok(),
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

    // The same stale copy on the standby, which never received it at all. The
    // delivery fan-out already moved that leg's cursor past the sequence, so
    // this pins that the fan-out reached it: the standby has nothing left to
    // deliver and nothing new to reserve.
    let standby_capacity = available_buffer_packets(&group, 2);
    feed(&mut group, 2, &first, ts(180_000));
    assert!(
        group.poll_data(ts(180_000)).is_none(),
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
    feed(&mut group, 3, &first, ts(200_000));
    assert!(
        group.poll_data(ts(200_000)).is_none(),
        "a late leg cannot reopen a retired sequence"
    );
    assert_eq!(
        available_buffer_packets(&group, 3),
        late_capacity,
        "the group returns the retired sequence's reservation instead of holding it"
    );
}

#[test]
fn a_second_legs_copy_of_a_pending_sequence_returns_its_reservation() {
    // Head-of-line blocking, not the retirement prefix: both legs deliver a
    // sequence above the group's prefix while the sequence at the prefix is
    // still missing, so both copies really sit in the pending table at once and
    // the second one meets the table's own uniqueness guard.
    let PrefixFixture {
        mut group,
        mut source_a,
        ..
    } = advanced_prefix_group();
    let missing = prefix();
    let late = missing.wrapping_add(2) & SEQUENCE_MASK;

    let mut sources = Vec::new();
    for member_id in 3..=4 {
        let (source, listener) = establish_pair(ConnectionOptions {
            initial_seq: Some(late),
            ..ConnectionOptions::default()
        });
        group.add_member(member_id, 1, listener).unwrap();
        sources.push(source);
    }
    let mut copies = Vec::new();
    for source in sources.iter_mut() {
        source.send(b"pending", ts(200_000)).unwrap();
        let packet = packets_from(source).pop().unwrap();
        assert_eq!(data_sequence(&packet), late);
        copies.push(packet);
    }

    let full_third = available_buffer_packets(&group, 3);
    let full_fourth = available_buffer_packets(&group, 4);
    feed(&mut group, 3, &copies[0], ts(200_000));
    feed(&mut group, 4, &copies[1], ts(200_000));
    assert!(
        group.poll_data(ts(200_000)).is_none(),
        "the sequence at the group prefix is missing, so nothing is delivered yet"
    );
    // Precondition: each leg is holding exactly one slot, the first as the
    // group's pending copy and the second because its copy is not collected
    // from the member's event queue yet.
    assert_eq!(available_buffer_packets(&group, 3), full_third - 1);
    assert_eq!(available_buffer_packets(&group, 4), full_fourth - 1);

    // Unblock the head on the active leg, whose cursor sits at the group
    // prefix: the pending copy is then delivered and its reservation returns.
    source_a.synchronize_send_sequence(missing).unwrap();
    for _ in 0..2 {
        source_a.send(b"head", ts(201_000)).unwrap();
        let packet = packets_from(&mut source_a).pop().unwrap();
        feed(&mut group, 1, &packet, ts(201_000));
    }
    let mut delivered = Vec::new();
    for _ in 0..8 {
        if let Some(GroupEvent::DataReceived(packet)) = group.poll_event(ts(202_000)) {
            delivered.push(packet.sequence_number);
        }
    }
    assert_eq!(
        delivered,
        vec![missing, missing.wrapping_add(1) & SEQUENCE_MASK, late],
        "head, middle and the pending copy are delivered in order"
    );
    assert_eq!(
        available_buffer_packets(&group, 3),
        full_third,
        "the pending leg returns to full once its copy is delivered"
    );
    assert_eq!(
        available_buffer_packets(&group, 4),
        full_fourth,
        "the rejected duplicate keeps no reservation at all"
    );
}
