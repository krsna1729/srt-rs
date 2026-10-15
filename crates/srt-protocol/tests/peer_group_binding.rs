//! Receiving-group binding for a caller-side group.
//!
//! A bonded group has exactly one remote receiving group. The first member
//! whose handshake response carries a GROUP extension binds the group to that
//! ID, every later member must report the same one, a response without the
//! extension is admitted without binding, and a mismatch breaks only that
//! member. The binding is a property of the group, not of the leg that set it,
//! so it outlives that leg: a replacement with the same ID is admitted.

use srt_proto::handshake::{GroupExtensionData, GroupType};
use srt_proto::wire::{ControlPacket, ControlType, SrtPacket};
use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMemberState, GroupMode,
    SrtConnection, SrtGroup, Timestamp,
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

/// The caller side of a connected pair whose listener answers from `group_id`,
/// or from no receiving group at all.
fn member_pair(group_id: Option<u32>) -> SrtConnection {
    let local_extension = GroupExtensionData {
        group_id: 0x4000_0031,
        group_type: GroupType::Broadcast,
        flags: 0,
        weight: 1,
    };
    let listener_extension = group_id.map(|group_id| GroupExtensionData {
        group_id,
        group_type: GroupType::Broadcast,
        flags: 0,
        weight: 100,
    });
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        // The listener answers with its own extension only when the caller
        // sent one, so the caller always carries its local group here.
        group_extension: Some(local_extension),
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        tsbpd_delay: 0,
        group_extension: listener_extension,
        ..Default::default()
    });
    caller.connect(ts(0)).expect("caller connects");
    for round in 0..10 {
        for packet in packets_from(&mut caller) {
            listener
                .feed_recv_buf(&packet, ts(round * 10_000))
                .expect("request decodes");
        }
        for packet in packets_from(&mut listener) {
            caller
                .feed_recv_buf(&packet, ts(round * 10_000))
                .expect("response decodes");
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            assert_eq!(
                caller
                    .peer_group_extension()
                    .map(|extension| extension.group_id),
                group_id,
                "the leg reports the receiving group the listener answers from"
            );
            return caller;
        }
    }
    panic!("pair did not connect");
}

fn group() -> SrtGroup {
    SrtGroup::new(0x4000_0031, GroupMode::Broadcast).expect("group")
}

#[test]
fn the_first_group_report_binds_and_a_matching_leg_is_admitted() {
    let mut group = group();
    group
        .add_member(1, 1, member_pair(Some(0x4000_2002)))
        .expect("first member");
    assert!(group.can_send(), "a refresh admits the connected members");
    assert_eq!(
        group.peer_group_id(),
        Some(0x4000_2002),
        "the first report binds the group"
    );

    group
        .add_member(2, 1, member_pair(Some(0x4000_2002)))
        .expect("second member");
    assert!(group.can_send());
    assert_eq!(group.peer_group_id(), Some(0x4000_2002));
    assert_eq!(
        group.member(2).expect("second member").state(),
        GroupMemberState::Active,
        "a leg reporting the bound group is admitted"
    );
    assert!(
        group.poll_peer_group_collision(ts(300_000)).is_none(),
        "the same receiving group is not a collision"
    );
}

#[test]
fn a_leg_without_a_group_report_is_admitted_without_binding() {
    let mut group = group();
    group
        .add_member(1, 1, member_pair(None))
        .expect("first member");
    assert!(group.can_send());
    assert_eq!(
        group.peer_group_id(),
        None,
        "a response without a GROUP extension carries no identity to bind"
    );
    assert_eq!(
        group.member(1).expect("first member").state(),
        GroupMemberState::Active
    );

    // The next member to report an identity binds the group for every later
    // one, no matter that an earlier leg was admitted first.
    group
        .add_member(2, 1, member_pair(Some(0x4000_2002)))
        .expect("second member");
    assert!(group.can_send());
    assert_eq!(group.peer_group_id(), Some(0x4000_2002));
    assert_eq!(
        group.member(2).expect("second member").state(),
        GroupMemberState::Active
    );
}

#[test]
fn a_leg_from_another_receiving_group_breaks_only_itself() {
    let mut group = group();
    group
        .add_member(1, 1, member_pair(Some(0x4000_2002)))
        .expect("first member");
    group
        .add_member(2, 1, member_pair(Some(0x4000_3003)))
        .expect("second member");
    assert!(group.can_send());

    assert_eq!(
        group.peer_group_id(),
        Some(0x4000_2002),
        "the binding is not replaced by the mismatching leg"
    );
    assert_eq!(
        group.member(1).expect("first member").state(),
        GroupMemberState::Active,
        "the matching leg keeps carrying"
    );
    assert_eq!(
        group.member(2).expect("second member").state(),
        GroupMemberState::Broken,
        "only the offending leg breaks"
    );

    let collision = group
        .poll_peer_group_collision(ts(300_000))
        .expect("the collision is reported once");
    assert_eq!(collision.member_id, 2);
    assert_eq!(collision.expected_peer_group_id, 0x4000_2002);
    assert_eq!(collision.actual_peer_group_id, 0x4000_3003);
    assert_eq!(
        group.member(2).expect("second member").connection().state(),
        ConnectionState::Closing,
        "reporting the collision tells the receiver to drop the leg"
    );
    let closing = packets_from(group.member_mut(2).expect("second member").connection_mut());
    assert!(
        closing.iter().any(|packet| matches!(
            SrtPacket::decode(packet),
            Ok(SrtPacket::Control(ControlPacket {
                control_type: ControlType::Shutdown,
                ..
            }))
        )),
        "the drop is a graceful shutdown on the wire"
    );
    assert!(
        group.poll_peer_group_collision(ts(301_000)).is_none(),
        "one report per offending leg"
    );
    assert!(group.can_send(), "the survivable leg keeps sending");
}

#[test]
fn a_replacement_leg_keeps_the_binding_of_a_failed_holder() {
    let mut group = group();
    group
        .add_member(1, 1, member_pair(Some(0x4000_2002)))
        .expect("first member");
    assert!(group.can_send());
    assert!(group.mark_member_broken(1), "the holder is marked broken");

    group
        .add_member(2, 1, member_pair(Some(0x4000_2002)))
        .expect("replacement member");
    assert!(group.can_send());
    assert_eq!(
        group.peer_group_id(),
        Some(0x4000_2002),
        "the failed holder does not release or own the binding"
    );
    assert_eq!(
        group.member(2).expect("replacement member").state(),
        GroupMemberState::Active
    );

    group
        .add_member(3, 1, member_pair(Some(0x4000_3003)))
        .expect("third member");
    assert!(group.can_send());
    assert_eq!(
        group.member(3).expect("third member").state(),
        GroupMemberState::Broken,
        "a different receiving group is still refused after a holder failed"
    );
}
