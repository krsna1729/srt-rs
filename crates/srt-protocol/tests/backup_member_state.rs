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
        !group.can_send(),
        "the active leg's full window is the only leg Backup sends on"
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
    assert_eq!(
        data_sequences(group.member_mut(2).expect("second member").connection_mut()),
        vec![cursor],
        "the promoted leg carries the cursor the stalled leg could not send, once"
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

/// The member-state axes are independent signals. A stalled leg is under
/// pressure, not broken: pressure neither dissolves its connection and
/// membership, nor the flight it could not send, nor its own send cursor,
/// while the group's authority sits on the leg that can send.
#[test]
fn pressure_stays_separate_from_lifecycle_authority_and_cursor() {
    let failover = stall_and_fail_over();

    // Lifecycle: connected, still a member.
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

    // Pressure: the parked flight is intact, packet for packet.
    assert_eq!(
        failover
            .group
            .member(1)
            .expect("first member")
            .connection()
            .sender_stats()
            .expect("a connected sender reports stats")
            .packets_in_buffer,
        failover.parked
    );

    // Authority: exactly one leg carries, and it is the promoted one.
    assert_eq!(
        failover
            .group
            .members()
            .iter()
            .filter(|member| member.state() == GroupMemberState::Active)
            .count(),
        1
    );
    assert_eq!(
        failover.group.member(2).expect("second member").state(),
        GroupMemberState::Active
    );

    // Synchronization: the send that failed on the stalled leg did not move
    // that leg's own cursor.
    assert_eq!(
        failover
            .group
            .member(1)
            .expect("first member")
            .connection()
            .next_sequence_number(),
        Some(failover.cursor)
    );
}
