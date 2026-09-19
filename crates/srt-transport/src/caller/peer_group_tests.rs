//! Bonded-caller receiving-group identity, on the runtime-neutral core.
//!
//! libsrt's rule (`CUDT::interpretGroup`): the first leg whose response
//! carries a GROUP extension binds the caller's group to that extension's
//! group ID (the responder's mirror group); a later leg naming a different
//! one is rejected with `SRT_REJ_GROUP`. Addresses never decide it.

use crate::*;
use srt_proto::handshake::{GroupExtensionData, GroupType, SRTGROUP_MASK};
use srt_proto::{ConnectionOptions, GroupMode, PeerGroupCollision, SrtConnection, Timestamp};
use std::net::SocketAddr;

const CALLER_GROUP: u32 = SRTGROUP_MASK | 0x55;

struct Receiver {
    table: PeerTable,
    /// The mirror-group ID this receiver returns in CONCLUSION; `None`
    /// answers without any GROUP extension.
    mirror: Option<u32>,
}

impl Receiver {
    fn new(mirror: u32) -> Self {
        Self {
            table: PeerTable::new(),
            mirror: Some(SRTGROUP_MASK | mirror),
        }
    }

    fn without_identity() -> Self {
        Self {
            table: PeerTable::new(),
            mirror: None,
        }
    }
}

fn group_type(mode: GroupMode) -> GroupType {
    match mode {
        GroupMode::Broadcast => GroupType::Broadcast,
        GroupMode::Backup => GroupType::Backup,
    }
}

fn leg(member_id: u32, socket_id: u32, peer: SocketAddr, mode: GroupMode) -> CallerGroupLeg {
    let mut connection = SrtConnection::new_caller(ConnectionOptions {
        socket_id,
        initial_seq: Some(1234),
        group_extension: Some(GroupExtensionData {
            group_id: CALLER_GROUP,
            group_type: group_type(mode),
            flags: 0,
            weight: 1,
        }),
        ..ConnectionOptions::default()
    });
    connection
        .connect(Timestamp::default())
        .expect("caller starts handshake");
    CallerGroupLeg::new(member_id, 1, peer, connection)
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Drive the caller against receivers reachable at `routes` (destination
/// address -> receiver index). Destinations with no route are unreachable:
/// their datagrams vanish.
fn pump(
    callers: &mut CallerTable,
    receivers: &mut [Receiver],
    routes: &[(SocketAddr, usize)],
    rounds: std::ops::Range<u64>,
) {
    let mut options = AdmissionOptions::basic(900, 0, true);
    options.bonded_inputs = BondedInputPolicy::Accept;
    let telemetry = IngressTelemetry::new();
    for round in rounds {
        let now = Timestamp::from_micros(round * 50_000);
        let mut outbound = Vec::new();
        callers.poll_outbound(now, &mut outbound);
        for (peer, packet) in outbound.drain(..) {
            let Some((_, index)) = routes.iter().find(|(address, _)| *address == peer) else {
                continue;
            };
            let mirror = receivers[*index].mirror;
            receivers[*index].table.admit_with_connection_hook(
                peer,
                &packet,
                now,
                &options,
                0,
                1,
                &telemetry,
                |request, connection| {
                    if let (Some(mirror), Some(group)) =
                        (mirror, request.handshake.get_group_extension())
                    {
                        // A real receiver answers with its own mirror group.
                        connection.set_group_extension(GroupExtensionData {
                            group_id: mirror,
                            ..group
                        });
                    }
                    AdmissionResolution::Accept
                },
            );
        }
        for receiver in receivers.iter_mut() {
            let mut replies = Vec::new();
            receiver.table.poll_outbound(now, &mut replies);
            for (peer, packet) in replies {
                if routes.iter().any(|(address, _)| *address == peer) {
                    let _ = callers.feed(peer, &packet, now);
                }
            }
        }
    }
}

fn group_of(callers: &CallerTable, id: LogicalCallerId) -> Box<GroupConnectionStats> {
    match callers.logical_caller(&id).expect("caller").stats() {
        Some(LogicalCallerStats::Group(stats)) => stats,
        _ => panic!("group stats"),
    }
}

fn faults(callers: &mut CallerTable) -> Vec<CallerGroupFault> {
    let mut out = Vec::new();
    callers.poll_group_faults(8, &mut out);
    out
}

fn two_leg_caller(a: SocketAddr, b: SocketAddr) -> (CallerTable, LogicalCallerId) {
    two_leg_caller_in(a, b, GroupMode::Broadcast)
}

fn two_leg_caller_in(
    a: SocketAddr,
    b: SocketAddr,
    mode: GroupMode,
) -> (CallerTable, LogicalCallerId) {
    let mut callers = CallerTable::new();
    let id = add_two_legs(&mut callers, a, b, mode);
    (callers, id)
}

fn add_two_legs(
    callers: &mut CallerTable,
    a: SocketAddr,
    b: SocketAddr,
    mode: GroupMode,
) -> LogicalCallerId {
    callers
        .add_group(
            CALLER_GROUP,
            mode,
            [leg(1, 102, a, mode), leg(2, 103, b, mode)],
        )
        .expect("group admitted")
}

/// One receiver reachable at two endpoints is ONE receiving group: both legs
/// connect and nothing collides, whatever the addresses look like.
#[test]
fn two_endpoints_of_one_receiver_form_one_valid_group() {
    let (a, b) = (addr(11001), addr(11002));
    let (mut callers, id) = two_leg_caller(a, b);
    let mut receivers = [Receiver::new(0x7001)];
    pump(&mut callers, &mut receivers, &[(a, 0), (b, 0)], 0..12);
    assert_eq!(group_of(&callers, id).aggregate.active_legs, 2);
    assert!(faults(&mut callers).is_empty());
}

/// Two independent receivers (different mirror groups) are not one bond: the
/// leg that connects second is broken and reported, attributably.
#[test]
fn independent_receivers_collide_on_the_second_leg() {
    let (a, b) = (addr(11001), addr(11002));
    let (mut callers, id) = two_leg_caller(a, b);
    let mut receivers = [Receiver::new(0x7001), Receiver::new(0x7002)];
    // Leg A completes alone first, then leg B.
    pump(&mut callers, &mut receivers, &[(a, 0)], 0..8);
    assert_eq!(group_of(&callers, id).aggregate.active_legs, 1);
    pump(&mut callers, &mut receivers, &[(a, 0), (b, 1)], 8..24);

    let found = faults(&mut callers);
    assert_eq!(found.len(), 1, "exactly one collision: {found:?}");
    assert_eq!(found[0].id, id);
    assert_eq!(found[0].peer, b);
    assert_eq!(
        found[0].collision,
        PeerGroupCollision {
            member_id: 2,
            expected_peer_group_id: SRTGROUP_MASK | 0x7001,
            actual_peer_group_id: SRTGROUP_MASK | 0x7002,
        }
    );
    assert_eq!(
        group_of(&callers, id).aggregate.active_legs,
        1,
        "the colliding leg never becomes an active member"
    );
}

/// Connection order does not change the verdict: whichever leg connects
/// first defines the group, and the other one collides.
#[test]
fn reversed_connection_order_reaches_the_same_verdict() {
    let (a, b) = (addr(11001), addr(11002));
    let (mut callers, id) = two_leg_caller(a, b);
    let mut receivers = [Receiver::new(0x7001), Receiver::new(0x7002)];
    pump(&mut callers, &mut receivers, &[(b, 1)], 0..8);
    pump(&mut callers, &mut receivers, &[(a, 0), (b, 1)], 8..24);

    let found = faults(&mut callers);
    assert_eq!(found.len(), 1, "exactly one collision: {found:?}");
    assert_eq!(found[0].id, id);
    assert_eq!(found[0].peer, a);
    assert_eq!(found[0].collision.member_id, 1);
    assert_eq!(
        found[0].collision.expected_peer_group_id,
        SRTGROUP_MASK | 0x7002
    );
    assert_eq!(
        found[0].collision.actual_peer_group_id,
        SRTGROUP_MASK | 0x7001
    );
}

/// A Broadcast leg that is merely unreachable is a normal degraded bond,
/// never a collision.
#[test]
fn an_unreachable_broadcast_leg_is_degradation_not_collision() {
    let (a, b) = (addr(11001), addr(11002));
    let (mut callers, id) = two_leg_caller(a, b);
    let mut receivers = [Receiver::new(0x7001)];
    pump(&mut callers, &mut receivers, &[(a, 0)], 0..40);
    assert_eq!(group_of(&callers, id).aggregate.active_legs, 1);
    assert!(faults(&mut callers).is_empty());
    assert_eq!(callers.group_faults_pending(), 0);
}

/// A response with no GROUP extension carries no identity and binds nothing,
/// as in libsrt: it neither collides nor blocks a later identified leg.
#[test]
fn a_response_without_group_identity_is_not_checked() {
    let (a, b) = (addr(11001), addr(11002));
    let (mut callers, id) = two_leg_caller(a, b);
    // Leg A's receiver names no group; leg B's names one. Neither collides.
    let mut receivers = [Receiver::without_identity(), Receiver::new(0x7002)];
    pump(&mut callers, &mut receivers, &[(a, 0), (b, 1)], 0..12);
    assert_eq!(group_of(&callers, id).aggregate.active_legs, 2);
    assert!(faults(&mut callers).is_empty());
}

/// The receiving-group invariant does not depend on the group mode: a Backup
/// bond whose standby leg answers from another receiving group collides too.
#[test]
fn backup_mode_collides_on_independent_receivers() {
    let (a, b) = (addr(11001), addr(11002));
    let (mut callers, id) = two_leg_caller_in(a, b, GroupMode::Backup);
    let mut receivers = [Receiver::new(0x7001), Receiver::new(0x7002)];
    pump(&mut callers, &mut receivers, &[(a, 0)], 0..8);
    pump(&mut callers, &mut receivers, &[(a, 0), (b, 1)], 8..24);

    let found = faults(&mut callers);
    assert_eq!(found.len(), 1, "exactly one collision: {found:?}");
    assert_eq!(found[0].id, id);
    assert_eq!(found[0].peer, b);
    assert_eq!(found[0].collision.member_id, 2);
    let stats = group_of(&callers, id);
    assert_eq!(stats.aggregate.active_legs, 1, "only the first leg carries");
}

/// Backup with two endpoints of one receiver is a valid bond, and an
/// unreachable backup leg is degradation, not a collision.
#[test]
fn backup_mode_accepts_one_receiver_and_tolerates_an_unreachable_leg() {
    let (a, b) = (addr(11001), addr(11002));
    let (mut callers, _) = two_leg_caller_in(a, b, GroupMode::Backup);
    let mut receivers = [Receiver::new(0x7001)];
    pump(&mut callers, &mut receivers, &[(a, 0), (b, 0)], 0..12);
    assert!(faults(&mut callers).is_empty());

    let (mut degraded, id) = two_leg_caller_in(a, b, GroupMode::Backup);
    let mut receivers = [Receiver::new(0x7001)];
    pump(&mut degraded, &mut receivers, &[(a, 0)], 0..40);
    assert!(faults(&mut degraded).is_empty());
    assert_eq!(degraded.group_faults_pending(), 0);
    assert!(group_of(&degraded, id).aggregate.active_legs >= 1);
}

/// Several offending legs of one logical caller raise ONE application-level
/// fault (its first); the others are still broken but stay silent.
#[test]
fn one_logical_caller_retains_a_single_fault() {
    let (a, b, c) = (addr(11001), addr(11002), addr(11003));
    let mut callers = CallerTable::new();
    let id = callers
        .add_group(
            CALLER_GROUP,
            GroupMode::Broadcast,
            [
                leg(1, 102, a, GroupMode::Broadcast),
                leg(2, 103, b, GroupMode::Broadcast),
                leg(3, 104, c, GroupMode::Broadcast),
            ],
        )
        .expect("group admitted");
    let mut receivers = [
        Receiver::new(0x7001),
        Receiver::new(0x7002),
        Receiver::new(0x7003),
    ];
    pump(&mut callers, &mut receivers, &[(a, 0)], 0..8);
    pump(
        &mut callers,
        &mut receivers,
        &[(a, 0), (b, 1), (c, 2)],
        8..24,
    );

    assert_eq!(callers.group_faults_pending(), 1, "one retained fault");
    let found = faults(&mut callers);
    assert_eq!(found.len(), 1, "one fault for the caller: {found:?}");
    assert_eq!(found[0].id, id);
    assert_eq!(callers.group_faults_pending(), 0);
    assert_eq!(group_of(&callers, id).aggregate.active_legs, 1);
}

/// Churn: a caller collides, is retired WITHOUT anyone draining the fault,
/// and a new one takes its place, over and over. Retained fault state stays
/// bounded by the live callers and is reclaimed with each retired caller.
#[test]
fn undrained_faults_are_reclaimed_with_their_caller_under_churn() {
    let (a, b) = (addr(11001), addr(11002));
    let mut callers = CallerTable::with_max_callers(2);
    for round in 0..64 {
        let id = add_two_legs(&mut callers, a, b, GroupMode::Broadcast);
        let mut receivers = [Receiver::new(0x7001), Receiver::new(0x7002)];
        pump(&mut callers, &mut receivers, &[(a, 0)], 0..8);
        pump(&mut callers, &mut receivers, &[(a, 0), (b, 1)], 8..24);
        assert_eq!(
            callers.group_faults_pending(),
            1,
            "round {round}: exactly this caller's fault is retained"
        );
        assert!(callers.remove(id).is_some());
        assert_eq!(
            callers.group_faults_pending(),
            0,
            "round {round}: removing the caller reclaims its undrained fault"
        );
    }
    assert!(
        faults(&mut callers).is_empty(),
        "nothing stale is delivered"
    );
    assert!(callers.is_empty());
}
