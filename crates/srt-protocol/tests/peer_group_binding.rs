//! Receiving-group binding for a caller-side group.
//!
//! A bonded group has exactly one remote receiving group. The first member
//! whose handshake response carries a GROUP extension binds the group to that
//! ID, every later member must report the same one, a response without the
//! extension is admitted without binding, and a mismatch breaks only that
//! member. The binding is a property of the group, not of the leg that set it,
//! and it is never released: a failed holder does not let a different
//! receiving group in.
//!
//! Legs are added before their handshake completes, as the transport adds
//! them, so admission is the state refresh's job (`refresh_pending_states` ->
//! `admit_connected_peer_groups`), not `add_member`'s.

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

/// A leg before the group sees it: the caller side is what the group will
/// hold, and the listener side answers from `group_id`, or from no receiving
/// group at all.
struct PendingLeg {
    caller: SrtConnection,
    listener: SrtConnection,
}

impl PendingLeg {
    fn new(group_id: Option<u32>) -> Self {
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
        caller.connect(ts(0)).expect("caller starts its handshake");
        let listener = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            group_extension: listener_extension,
            ..Default::default()
        });
        Self { caller, listener }
    }

    /// Add this leg and drive its handshake inside `group`, as the transport
    /// does: the group holds the caller side, the listener answers it.
    fn join(self, group: &mut SrtGroup, member_id: u32) {
        let Self {
            caller,
            mut listener,
        } = self;
        group
            .add_member(member_id, 1, caller)
            .expect("member admitted");
        for round in 0..10 {
            let now = ts(round * 10_000);
            let member = group.member_mut(member_id).expect("member");
            for packet in packets_from(member.connection_mut()) {
                listener
                    .feed_recv_buf(&packet, now)
                    .expect("request decodes");
            }
            for packet in packets_from(&mut listener) {
                group
                    .member_mut(member_id)
                    .expect("member")
                    .connection_mut()
                    .feed_recv_buf(&packet, now)
                    .expect("response decodes");
            }
            if group
                .member(member_id)
                .expect("member")
                .connection()
                .state()
                == ConnectionState::Connected
            {
                return;
            }
        }
        panic!("leg did not connect");
    }
}

fn group() -> SrtGroup {
    SrtGroup::new(0x4000_0031, GroupMode::Broadcast).expect("group")
}

#[test]
fn the_first_group_report_binds_and_a_matching_leg_is_admitted() {
    let mut group = group();
    PendingLeg::new(Some(0x4000_2002)).join(&mut group, 1);
    assert_eq!(
        group.peer_group_id(),
        None,
        "a leg that is connected but not yet looked at has not bound anything"
    );

    assert!(group.can_send(), "a refresh admits the connected leg");
    assert_eq!(
        group.peer_group_id(),
        Some(0x4000_2002),
        "the first report binds the group"
    );

    PendingLeg::new(Some(0x4000_2002)).join(&mut group, 2);
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
    PendingLeg::new(None).join(&mut group, 1);
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
    PendingLeg::new(Some(0x4000_2002)).join(&mut group, 2);
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
    PendingLeg::new(Some(0x4000_2002)).join(&mut group, 1);
    PendingLeg::new(Some(0x4000_3003)).join(&mut group, 2);
    assert_eq!(
        group.peer_group_id(),
        None,
        "neither leg has been looked at yet"
    );

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
fn a_failed_holder_does_not_release_the_binding() {
    let mut group = group();
    PendingLeg::new(Some(0x4000_2002)).join(&mut group, 1);
    assert!(group.can_send());
    assert!(group.mark_member_broken(1), "the holder is marked broken");
    assert_eq!(
        group.peer_group_id(),
        Some(0x4000_2002),
        "the binding is not released with the leg that set it"
    );

    // A different receiving group is refused while the binding stands, before
    // any same-ID replacement exists: a released binding would have let this
    // leg bind the group instead.
    PendingLeg::new(Some(0x4000_3003)).join(&mut group, 2);
    // A refresh is what looks at a newly connected leg, whether or not any leg
    // can send: both legs are broken by the time this one is refused.
    let _ = group.can_send();
    assert_eq!(
        group.member(2).expect("second member").state(),
        GroupMemberState::Broken,
        "a different receiving group is still refused"
    );
    assert_eq!(
        group.peer_group_id(),
        Some(0x4000_2002),
        "the refusal leaves the binding alone"
    );
    assert_eq!(
        group
            .poll_peer_group_collision(ts(300_000))
            .expect("the refusal is reported")
            .member_id,
        2
    );

    // The same receiving group is welcome again.
    PendingLeg::new(Some(0x4000_2002)).join(&mut group, 3);
    assert!(group.can_send());
    assert_eq!(
        group.member(3).expect("third member").state(),
        GroupMemberState::Active,
        "a replacement reporting the same group is admitted"
    );
    assert_eq!(group.peer_group_id(), Some(0x4000_2002));
}
