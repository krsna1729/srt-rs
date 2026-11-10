//! Backup-mode member-state challengers.
//!
//! The fixture below drives the composition the per-case group tests do not
//! cover: the active leg's sender window fills, the failover promotes the
//! standby and continues the group cursor on the promoted leg, and the stalled
//! leg must drain its flight before it becomes eligible again.

use srt_proto::wire::SrtPacket;
use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMemberState, GroupMode,
    SrtConnection, SrtGroup, TimerId, Timestamp,
};

/// The group's 31-bit sequence space.
const SEQUENCE_MASK: u32 = 0x7fff_ffff;

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

/// A connected caller/listener pair, driven by real handshake packets.
fn establish_pair(options: ConnectionOptions) -> (SrtConnection, SrtConnection) {
    establish_pair_at(
        ConnectionOptions {
            tsbpd_delay: 0,
            ..options
        },
        0,
    )
}

fn establish_pair_at(options: ConnectionOptions, start: u64) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(options.clone());
    let mut listener = SrtConnection::new_listener(options);
    caller.connect(ts(start)).expect("caller should connect");
    for _ in 0..10 {
        for packet in packets_from(&mut caller) {
            listener
                .feed_recv_buf(&packet, ts(start))
                .expect("request should decode");
        }
        for packet in packets_from(&mut listener) {
            caller
                .feed_recv_buf(&packet, ts(start))
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

/// Every DATA sequence a connection produced, in output order, ignoring
/// control traffic. No DATA packet is folded away, so a repeated sequence or a
/// replayed older flight stays visible.
fn data_sequences(connection: &mut SrtConnection) -> Vec<u32> {
    packets_from(connection)
        .into_iter()
        .filter_map(|packet| match SrtPacket::decode(&packet) {
            Ok(SrtPacket::Data(data)) => Some(data.sequence_number),
            _ => None,
        })
        .collect()
}

fn feed_into_group(group: &mut SrtGroup, member_id: u32, packets: Vec<Vec<u8>>, now: Timestamp) {
    for packet in packets {
        group
            .member_mut(member_id)
            .expect("group member")
            .connection_mut()
            .feed_recv_buf(&packet, now)
            .expect("packet should decode");
    }
}

/// A Backup group after the active leg's window filled and the standby took
/// over: the stalled leg is Unstable with its whole flight parked, and the
/// promoted leg is Active and has carried the cursor the stalled leg could not
/// send.
struct Failover {
    group: SrtGroup,
    listener: SrtConnection,
    stalled: Vec<Vec<u8>>,
    cursor: u32,
    /// Packets the stalled leg still holds in its sender buffer.
    parked: u32,
}

fn stall_and_fail_over() -> Failover {
    let constrained = ConnectionOptions {
        flow_window_packets: 3,
        ..Default::default()
    };
    let (caller_a, listener_a) = establish_pair(constrained);
    let (caller_b, _) = establish_pair(ConnectionOptions::default());
    let mut group = SrtGroup::new(0x4000_0017, GroupMode::Backup).expect("group");
    group.add_member(1, 100, caller_a).expect("first member");
    group.add_member(2, 1, caller_b).expect("second member");
    assert_eq!(
        group.member(1).expect("first member").state(),
        GroupMemberState::Active
    );
    assert_eq!(
        group.member(2).expect("second member").state(),
        GroupMemberState::Standby
    );

    // Fill the active leg's sender window, so it cannot take another payload.
    let mut stalled = Vec::new();
    while group
        .member(1)
        .expect("first member")
        .connection()
        .can_send()
    {
        assert_eq!(group.send(b"fill", ts(100_000)).expect("group sends"), 1);
        stalled.extend(packets_from(
            group.member_mut(1).expect("first member").connection_mut(),
        ));
    }
    let cursor = group
        .member(1)
        .expect("first member")
        .connection()
        .next_sequence_number()
        .expect("a connected leg holds a sequence cursor");
    let parked = group
        .member(1)
        .expect("first member")
        .connection()
        .sender_stats()
        .expect("a connected sender reports stats")
        .packets_in_buffer;
    assert!(parked > 0, "the stalled flight is parked, not dropped");
    assert!(
        group.can_send(),
        "a roomy standby makes the full active window ready for takeover"
    );
    assert_eq!(
        group.member(1).expect("first member").state(),
        GroupMemberState::Active,
        "a full window alone does not relabel the leg; a failed send does"
    );

    // The next payload fails on the stalled leg, which promotes the standby and
    // continues the group cursor on it.
    assert_eq!(
        group.send(b"fail over", ts(101_000)).expect("group sends"),
        1
    );
    assert_eq!(
        group.member(1).expect("first member").state(),
        GroupMemberState::Unstable
    );
    assert_eq!(
        group.member(2).expect("second member").state(),
        GroupMemberState::Active
    );
    let flight: Vec<u32> = (1..=parked)
        .rev()
        .map(|back| cursor.wrapping_sub(back) & SEQUENCE_MASK)
        .chain([cursor])
        .collect();
    assert_eq!(
        data_sequences(group.member_mut(2).expect("second member").connection_mut()),
        flight,
        "the promoted leg replays the stalled flight, then carries the cursor once"
    );

    Failover {
        group,
        listener: listener_a,
        stalled,
        cursor,
        parked,
    }
}

impl Failover {
    /// Acknowledge the parked flight, which is what makes the stalled leg
    /// eligible again.
    ///
    /// The first stalled packet already sent a DATA-path Full ACK at 102 ms;
    /// like libsrt's `checkACKTimer`, the next Full ACK (carrying the final
    /// position) is due one ACK interval later.
    fn acknowledge_stalled_flight(&mut self) {
        for packet in std::mem::take(&mut self.stalled) {
            self.listener
                .feed_recv_buf(&packet, ts(102_000))
                .expect("data decodes");
            while self.listener.poll_event().is_some() {}
        }
        self.listener
            .handle_timer(TimerId::Ack, ts(112_000))
            .expect("ack timer");
        let packets = packets_from(&mut self.listener);
        feed_into_group(&mut self.group, 1, packets, ts(112_000));
    }

    /// The cursor the group sends with next, once the failover has carried the
    /// stalled leg's cursor on the promoted leg.
    fn next_cursor(&self) -> u32 {
        self.cursor.wrapping_add(1) & SEQUENCE_MASK
    }
}

#[test]
fn a_recovered_backup_leg_is_eligible_but_not_authoritative() {
    let mut failover = stall_and_fail_over();

    // Lifecycle: pressure leaves the connection and group membership intact.
    assert_eq!(
        failover
            .group
            .member(1)
            .expect("first member")
            .connection()
            .state(),
        ConnectionState::Connected
    );
    assert_eq!(failover.group.members().len(), 2);

    // Pressure: the buffered packet count is unchanged across failover.
    assert_eq!(
        failover
            .group
            .member(1)
            .expect("first member")
            .connection()
            .sender_stats()
            .expect("a connected sender reports stats")
            .packets_in_buffer,
        failover.parked,
        "the stalled flight remains buffered"
    );

    // Synchronization: the failed send leaves the stalled leg's cursor intact.
    assert_eq!(
        failover
            .group
            .member(1)
            .expect("first member")
            .connection()
            .next_sequence_number(),
        Some(failover.cursor)
    );

    // Still outstanding: a state refresh alone must not requalify the leg.
    assert!(failover.group.can_send());
    assert_eq!(
        failover.group.member(1).expect("first member").state(),
        GroupMemberState::Unstable,
        "an outstanding flight keeps the leg out of the eligible set"
    );

    failover.acknowledge_stalled_flight();
    assert!(failover.group.can_send());
    assert_eq!(
        failover.group.member(1).expect("first member").state(),
        GroupMemberState::Standby,
        "a recovered leg is eligible again, not authoritative"
    );
    assert_eq!(
        failover.group.member(2).expect("second member").state(),
        GroupMemberState::Active
    );
    assert_eq!(
        failover
            .group
            .member(1)
            .expect("first member")
            .connection()
            .next_sequence_number(),
        Some(failover.next_cursor()),
        "re-qualification realigns the recovered leg with the group cursor"
    );

    // The promoted leg keeps sending, exactly once, and the recovered leg
    // carries nothing.
    assert_eq!(
        failover
            .group
            .send(b"still backup", ts(113_000))
            .expect("group sends"),
        1
    );
    assert_eq!(
        data_sequences(
            failover
                .group
                .member_mut(2)
                .expect("second member")
                .connection_mut()
        ),
        vec![failover.next_cursor()]
    );
    assert!(
        data_sequences(
            failover
                .group
                .member_mut(1)
                .expect("first member")
                .connection_mut()
        )
        .is_empty(),
        "no second leg carries"
    );
}

/// The real consumer calls send only after readiness, including when a silent
/// carrier's full window would otherwise hide the standby until inactivity.
#[test]
fn guarded_backup_readiness_takes_over_a_full_window_before_inactivity() {
    for paced in [false, true] {
        let (primary, _) = establish_pair(ConnectionOptions {
            flow_window_packets: 3,
            ..Default::default()
        });
        let (standby, _) = establish_pair(ConnectionOptions::default());
        let mut group = SrtGroup::new(0x4000_0060, GroupMode::Backup).unwrap();
        group.add_member(1, 100, primary).unwrap();
        group.add_member(2, 1, standby).unwrap();
        let mut original = Vec::new();
        while group.member(1).unwrap().connection().can_send() {
            assert!(group.can_send());
            group.send(b"prefix", ts(100_000)).unwrap();
            original.extend(data_sequences(
                group.member_mut(1).unwrap().connection_mut(),
            ));
        }
        assert!(!original.is_empty());
        let next = group
            .member(1)
            .unwrap()
            .connection()
            .next_sequence_number()
            .unwrap();
        let takeover = ts(100_000 + group.backup_stability_timeout_micros(1).unwrap() + 1);
        assert!(takeover < ts(1_000_000), "well before normal inactivity");
        let ready = if paced {
            group.can_send_with_pacing(takeover)
        } else {
            group.can_send()
        };
        let mut sent = false;
        if ready {
            group.send(b"after", takeover).unwrap();
            sent = true;
        }
        assert!(
            sent,
            "guarded send must reach the viable standby; paced={paced}"
        );
        original.push(next);
        assert_eq!(
            data_sequences(group.member_mut(2).unwrap().connection_mut()),
            original,
            "the complete flight precedes the new packet; paced={paced}"
        );
        assert_eq!(group.member(1).unwrap().state(), GroupMemberState::Unstable);
        assert_eq!(group.member(2).unwrap().state(), GroupMemberState::Active);
        assert_eq!(
            group.member(1).unwrap().connection().state(),
            ConnectionState::Connected,
            "takeover must not require ordinary disconnect"
        );
    }
}

/// A late member inherits the group's clock even when its own handshake
/// started after the retained DATA. Replay keeps source instants and spacing.
#[test]
fn backup_replay_preserves_source_time_and_tsbpd_spacing_across_leg_origins() {
    late_backup_replay(false, false);
}

#[test]
fn backup_pending_member_inherits_group_time_before_first_data() {
    late_backup_replay(false, true);
}

#[test]
fn backup_replacement_inherits_group_time_after_last_member_removed() {
    late_backup_replay(true, false);
}

fn late_backup_replay(remove_primary: bool, pending: bool) {
    let options = ConnectionOptions {
        tsbpd_delay: 120,
        ..Default::default()
    };
    let (primary, primary_listener) = establish_pair_at(options.clone(), 0);
    let mut sender = SrtGroup::new(0x4000_0061, GroupMode::Backup).unwrap();
    sender.add_member(1, 100, primary).unwrap();
    let mut receiver = SrtGroup::new(0x4000_0062, GroupMode::Backup).unwrap();
    receiver.add_member(1, 100, primary_listener).unwrap();
    assert!(receiver.poll_data(ts(90_000)).is_none());

    sender.send(b"p0", ts(100_000)).unwrap();
    sender.send(b"p1", ts(130_000)).unwrap();
    let original: Vec<(u32, u32)> = packets_from(sender.member_mut(1).unwrap().connection_mut())
        .iter()
        .filter_map(|packet| match SrtPacket::decode(packet) {
            Ok(SrtPacket::Data(data)) => Some((data.sequence_number, data.timestamp)),
            _ => None,
        })
        .collect();
    assert_eq!(original.len(), 2);
    if remove_primary {
        assert!(sender.remove_member(1));
        assert!(receiver.remove_member(1));
    }
    // Both retained sources predate this member's independent handshake.
    if pending {
        add_pending_backup_members(&mut sender, &mut receiver, options);
    } else {
        let (standby, listener) = establish_pair_at(options, 140_000);
        sender.add_member(2, 1, standby).unwrap();
        receiver.add_member(2, 1, listener).unwrap();
    }
    assert!(receiver.poll_data(ts(140_000)).is_none());
    // Lose both primary packets and all ACKs; take over while both original
    // playback deadlines are still in the future.
    sender.mark_member_broken(1);
    assert!(sender.can_send());
    sender.send(b"p2", ts(160_000)).unwrap();
    let takeover = packets_from(sender.member_mut(2).unwrap().connection_mut());
    let replay: Vec<(u32, u32)> = takeover
        .iter()
        .filter_map(|packet| match SrtPacket::decode(packet) {
            Ok(SrtPacket::Data(data)) => Some((data.sequence_number, data.timestamp)),
            _ => None,
        })
        .collect();
    assert_eq!(replay.len(), 3);
    assert_eq!(
        replay[0], original[0],
        "the group has one wire timestamp origin"
    );
    assert_eq!(replay[1], original[1]);
    feed_into_group(&mut receiver, 2, takeover, ts(160_000));

    assert_backup_replay_deadlines(&mut receiver);
}

fn assert_backup_replay_deadlines(receiver: &mut SrtGroup) {
    for (at, source, payload) in [
        (220_000, 100_000, &b"p0"[..]),
        (250_000, 130_000, &b"p1"[..]),
        (280_000, 160_000, &b"p2"[..]),
    ] {
        let member = receiver.member_mut(2).unwrap().connection_mut();
        member.handle_timer(TimerId::Ack, ts(at - 1)).unwrap();
        let _ = packets_from(member);
        assert!(
            receiver.poll_data(ts(at - 1)).is_none(),
            "not due before {at}"
        );
        let member = receiver.member_mut(2).unwrap().connection_mut();
        member.handle_timer(TimerId::Ack, ts(at)).unwrap();
        let _ = packets_from(member);
        let packet = receiver
            .poll_data(ts(at))
            .expect("original playback deadline");
        assert!(packet.payload.eq(payload));
        assert_eq!(packet.source_time, ts(source));
    }
    assert!(receiver.poll_data(ts(400_000)).is_none());
}

fn add_pending_backup_members(
    sender: &mut SrtGroup,
    receiver: &mut SrtGroup,
    options: ConnectionOptions,
) {
    let mut standby = SrtConnection::new_caller(options.clone());
    standby.connect(ts(140_000)).unwrap();
    sender.add_member(2, 1, standby).unwrap();
    receiver
        .add_member(2, 1, SrtConnection::new_listener(options))
        .unwrap();
    for _ in 0..10 {
        let packets = packets_from(sender.member_mut(2).unwrap().connection_mut());
        feed_into_group(receiver, 2, packets, ts(140_000));
        let packets = packets_from(receiver.member_mut(2).unwrap().connection_mut());
        feed_into_group(sender, 2, packets, ts(140_000));
        if sender.member(2).unwrap().connection().state() == ConnectionState::Connected
            && receiver.member(2).unwrap().connection().state() == ConnectionState::Connected
        {
            break;
        }
    }
    assert_eq!(
        sender.member(2).unwrap().connection().state(),
        ConnectionState::Connected
    );
    assert_eq!(
        receiver.member(2).unwrap().connection().state(),
        ConnectionState::Connected
    );
}

#[test]
fn group_clock_rollover_does_not_follow_an_idle_connected_member() {
    group_receive_clock_rollover(false, false);
}

#[test]
fn group_clock_rollover_survives_advancing_member_removed_before_idle_member() {
    group_receive_clock_rollover(true, false);
}

#[test]
fn group_clock_rollover_survives_queued_data_before_logical_delivery() {
    group_receive_clock_rollover(false, true);
}

fn group_receive_clock_rollover(remove_all: bool, queued: bool) {
    const WRAP: u64 = 1u64 << 32;
    let options = ConnectionOptions {
        initial_seq: Some(0),
        tsbpd_delay: 120,
        ..Default::default()
    };
    let (_, idle) = establish_pair_at(options.clone(), 0);
    let (source, advancing) = establish_pair_at(options.clone(), 0);
    let mut sender = SrtGroup::new(0x4000_0070, GroupMode::Broadcast).unwrap();
    sender.add_member(2, 1, source).unwrap();
    let mut receiver = SrtGroup::new(0x4000_0071, GroupMode::Broadcast).unwrap();
    receiver.add_member(1, 1, idle).unwrap();
    receiver.add_member(2, 1, advancing).unwrap();
    assert!(receiver.poll_data(ts(0)).is_none());
    stage_clock_rollover_prefix(
        &mut sender,
        &mut receiver,
        [WRAP - 1_000_000, WRAP + 30_000_000],
        queued,
    );
    assert_eq!(
        receiver.member(1).unwrap().connection().state(),
        ConnectionState::Connected
    );
    if remove_all {
        assert!(receiver.remove_member(2));
        assert!(receiver.remove_member(1));
    }
    assert!(sender.remove_member(2));
    let joined = WRAP + 31_000_000;
    let (source, member) = establish_pair_at(options, joined);
    sender.add_member(3, 1, source).unwrap();
    receiver.add_member(3, 1, member).unwrap();
    if !queued {
        assert!(receiver.poll_data(ts(joined)).is_none());
    }
    let source = WRAP + 32_000_000;
    sender.send(b"new carrier", ts(source)).unwrap();
    let packets = packets_from(sender.member_mut(3).unwrap().connection_mut());
    feed_into_group(&mut receiver, 3, packets, ts(source));
    // C receives before logical polling can publish B's read-ahead epoch.
    // Admission must already have installed the right receive clock.
    if queued {
        for old_source in [WRAP - 1_000_000, WRAP + 30_000_000] {
            let packet = receiver.poll_data(ts(source)).expect("queued old DATA");
            assert_eq!(packet.source_time, ts(old_source));
        }
    }
    assert!(
        receiver.poll_data(ts(source)).is_none(),
        "new leg cannot use the pre-wrap epoch"
    );
    assert_new_carrier_deadline(&mut receiver, source);
}

fn stage_clock_rollover_prefix(
    sender: &mut SrtGroup,
    receiver: &mut SrtGroup,
    sources: [u64; 2],
    queued: bool,
) {
    for source in sources {
        sender.send(b"old carrier", ts(source)).unwrap();
        let packets = packets_from(sender.member_mut(2).unwrap().connection_mut());
        feed_into_group(receiver, 2, packets, ts(source));
        let due = source + 120_000;
        let member = receiver.member_mut(2).unwrap().connection_mut();
        member.handle_timer(TimerId::Ack, ts(due)).unwrap();
        let _ = packets_from(member);
        if !queued {
            let packet = receiver.poll_data(ts(due)).expect("old carrier's due DATA");
            assert_eq!(packet.source_time, ts(source));
        }
    }
}

fn assert_new_carrier_deadline(receiver: &mut SrtGroup, source: u64) {
    let due = source + 120_000;
    let member = receiver.member_mut(3).unwrap().connection_mut();
    member.handle_timer(TimerId::Ack, ts(due - 1)).unwrap();
    let _ = packets_from(member);
    assert!(receiver.poll_data(ts(due - 1)).is_none());
    let member = receiver.member_mut(3).unwrap().connection_mut();
    member.handle_timer(TimerId::Ack, ts(due)).unwrap();
    let _ = packets_from(member);
    let packet = receiver
        .poll_data(ts(due))
        .expect("new carrier's original deadline");
    assert_eq!(packet.source_time, ts(source));
    assert!(packet.payload.eq(&b"new carrier"[..]));
}

#[test]
fn group_clock_rollover_retains_collected_data_after_its_producer_is_removed() {
    const WRAP: u64 = 1u64 << 32;
    let options = ConnectionOptions {
        initial_seq: Some(0),
        tsbpd_delay: 120,
        ..Default::default()
    };
    let (mut idle_source, idle) = establish_pair_at(options.clone(), 0);
    let (source, advancing) = establish_pair_at(options.clone(), 0);
    let mut sender = SrtGroup::new(0x4000_0072, GroupMode::Broadcast).unwrap();
    sender.add_member(2, 1, source).unwrap();
    let mut receiver = SrtGroup::new(0x4000_0073, GroupMode::Broadcast).unwrap();
    receiver.add_member(1, 1, idle).unwrap();
    receiver.add_member(2, 1, advancing).unwrap();
    assert!(receiver.poll_data(ts(0)).is_none());

    let before = WRAP - 1_000_000;
    sender.send(b"before wrap", ts(before)).unwrap();
    let packets = packets_from(sender.member_mut(2).unwrap().connection_mut());
    feed_into_group(&mut receiver, 2, packets, ts(before));
    let member = receiver.member_mut(2).unwrap().connection_mut();
    member
        .handle_timer(TimerId::Ack, ts(before + 120_000))
        .unwrap();
    let _ = packets_from(member);
    assert_eq!(
        receiver
            .poll_data(ts(before + 120_000))
            .unwrap()
            .source_time,
        ts(before)
    );

    sender.send(b"lost sequence one", ts(WRAP)).unwrap();
    let _ = packets_from(sender.member_mut(2).unwrap().connection_mut());
    let source = WRAP + 30_000_000;
    sender.send(b"collected sequence two", ts(source)).unwrap();
    // The physical receiver has already retired one; the logical group still
    // waits for its sibling before giving up that gap.
    receiver
        .member_mut(2)
        .unwrap()
        .connection_mut()
        .advance_receive_sequence(2, ts(source));
    let packets = packets_from(sender.member_mut(2).unwrap().connection_mut());
    feed_into_group(&mut receiver, 2, packets, ts(source));
    let due = source + 120_000;
    let member = receiver.member_mut(2).unwrap().connection_mut();
    member.handle_timer(TimerId::Ack, ts(due)).unwrap();
    let _ = packets_from(member);

    // The sibling's terminal event interrupts gap retirement after sequence
    // two is collected, but before it is logically delivered.
    receiver
        .member_mut(1)
        .unwrap()
        .connection_mut()
        .disconnect(ts(due));
    idle_source
        .handle_timer(TimerId::Keepalive, ts(due))
        .unwrap();
    feed_into_group(&mut receiver, 1, packets_from(&mut idle_source), ts(due));
    assert!(matches!(
        receiver.poll_event(ts(due)),
        Some(srt_proto::GroupEvent::MemberDisconnected { member_id: 1, .. })
    ));
    assert!(receiver.has_pending_data());
    assert!(receiver.remove_member(2));
    assert!(receiver.remove_member(1));
    let packet = receiver
        .poll_data(ts(due))
        .expect("group-owned collected DATA");
    assert_eq!(packet.sequence_number, 2);
    assert_eq!(packet.source_time, ts(source));

    assert!(sender.remove_member(2));
    let joined = WRAP + 31_000_000;
    let (source, member) = establish_pair_at(options, joined);
    sender.add_member(3, 1, source).unwrap();
    receiver.add_member(3, 1, member).unwrap();
    assert!(receiver.poll_data(ts(joined)).is_none());
    let source = WRAP + 32_000_000;
    sender.send(b"replacement", ts(source)).unwrap();
    let packets = packets_from(sender.member_mut(3).unwrap().connection_mut());
    feed_into_group(&mut receiver, 3, packets, ts(source));
    assert!(receiver.poll_data(ts(source)).is_none());
    let due = source + 120_000;
    let member = receiver.member_mut(3).unwrap().connection_mut();
    member.handle_timer(TimerId::Ack, ts(due)).unwrap();
    let _ = packets_from(member);
    let packet = receiver
        .poll_data(ts(due))
        .expect("replacement's original deadline");
    assert_eq!(packet.source_time, ts(source));
}

#[test]
fn group_clock_rollover_does_not_retime_a_members_raw_pre_wrap_tail() {
    raw_pre_wrap_tail(true, 1);
}

#[test]
fn group_collection_recovers_raw_tail_without_a_physical_timer_turn() {
    raw_pre_wrap_tail(false, 1);
}

#[test]
fn group_collection_continues_a_raw_fragmented_tail_beyond_one_visit() {
    raw_pre_wrap_tail(false, 65);
}

fn raw_pre_wrap_tail(manual_service: bool, fragments: usize) {
    const WRAP: u64 = 1u64 << 32;
    let options = ConnectionOptions {
        initial_seq: Some(0),
        tsbpd_delay: 120,
        ..Default::default()
    };
    let (source_a, member_a) = establish_pair_at(
        ConnectionOptions {
            delivery_queue_packets: 1,
            ..options.clone()
        },
        0,
    );
    let (source_b, member_b) = establish_pair_at(options, 0);
    let mut sender = SrtGroup::new(0x4000_0074, GroupMode::Broadcast).unwrap();
    sender.add_member(2, 1, source_b).unwrap();
    sender.add_member(1, 1, source_a).unwrap();
    let mut receiver = SrtGroup::new(0x4000_0075, GroupMode::Broadcast).unwrap();
    // B is collected first; A's duplicate zero fills its application queue.
    receiver.add_member(2, 1, member_b).unwrap();
    receiver.add_member(1, 1, member_a).unwrap();
    assert!(receiver.poll_data(ts(0)).is_none());
    let zero = WRAP - 2_000_000;
    seed_raw_wrap_prefix(&mut sender, &mut receiver, zero);
    let one = WRAP - 1_000_000;
    let source_a = sender.member_mut(1).unwrap().connection_mut();
    let payload = if fragments == 1 {
        b"one".to_vec()
    } else {
        vec![0x42; fragments * source_a.effective_max_payload_size()]
    };
    source_a.send_message(&payload, ts(one)).unwrap();
    let packets = packets_from(sender.member_mut(1).unwrap().connection_mut());
    feed_into_group(&mut receiver, 1, packets, ts(one));
    let source_b = sender.member_mut(2).unwrap().connection_mut();
    for _ in 0..fragments {
        source_b.send(b"lost on B", ts(one)).unwrap();
    }
    let _ = packets_from(source_b);
    let two = WRAP + 30_000_000;
    sender
        .member_mut(2)
        .unwrap()
        .connection_mut()
        .send(b"two", ts(two))
        .unwrap();
    let following = fragments as u32 + 1;
    receiver
        .member_mut(2)
        .unwrap()
        .connection_mut()
        .advance_receive_sequence(following, ts(two));
    let packets = packets_from(sender.member_mut(2).unwrap().connection_mut());
    feed_into_group(&mut receiver, 2, packets, ts(two));
    let now = two + 120_000;
    let member = receiver.member_mut(2).unwrap().connection_mut();
    member.handle_timer(TimerId::Ack, ts(now)).unwrap();
    let _ = packets_from(member);
    assert_eq!(receiver.poll_data(ts(now)).unwrap().sequence_number, 0);

    if manual_service {
        service_raw_pre_wrap_tail(&mut receiver, now);
    }
    let (packet, continuations) = collect_raw_group_tail(&mut receiver, fragments, now);
    assert_eq!(packet.sequence_number, 1);
    assert_eq!(packet.source_time, ts(one));
    assert_eq!(packet.packet_count, fragments as u32);
    assert!(packet.payload.eq(payload.as_slice()));
    if fragments > 64 {
        assert!(
            continuations > 0,
            "partial assembly must yield bounded continuation"
        );
    }
    let packet = receiver.poll_data(ts(now)).expect("post-wrap successor");
    assert_eq!(packet.sequence_number, following);
    assert_eq!(packet.source_time, ts(two));
    assert_eq!(receiver.skipped_receive_packets(), 0);
}

fn seed_raw_wrap_prefix(sender: &mut SrtGroup, receiver: &mut SrtGroup, zero: u64) {
    sender.send(b"zero", ts(zero)).unwrap();
    for id in [2, 1] {
        let packets = packets_from(sender.member_mut(id).unwrap().connection_mut());
        feed_into_group(receiver, id, packets, ts(zero));
        let member = receiver.member_mut(id).unwrap().connection_mut();
        member
            .handle_timer(TimerId::Ack, ts(zero + 120_000))
            .unwrap();
        let _ = packets_from(member);
    }
}

fn service_raw_pre_wrap_tail(receiver: &mut SrtGroup, now: u64) {
    // Isolate clock inheritance from the group-specific refill path.
    let member = receiver.member_mut(1).unwrap().connection_mut();
    assert!(matches!(
        member.poll_event(),
        Some(srt_proto::ConnectionEvent::DataReceived {
            sequence_number: 0,
            ..
        })
    ));
    member.handle_timer(TimerId::Ack, ts(now)).unwrap();
    let _ = packets_from(member);
}

fn collect_raw_group_tail(
    receiver: &mut SrtGroup,
    fragments: usize,
    now: u64,
) -> (srt_proto::group::GroupPacket, usize) {
    let mut continuations = 0;
    let mut recovered = None;
    for _ in 0..fragments + 4 {
        let result = receiver.poll_data_bounded(ts(now), 1);
        if let Some(packet) = result.packet {
            recovered = Some(packet);
            break;
        }
        assert!(
            result.continuation,
            "due raw work is not an empty-queue proof"
        );
        continuations += 1;
    }
    (
        recovered.expect("recoverable raw pre-wrap tail"),
        continuations,
    )
}
