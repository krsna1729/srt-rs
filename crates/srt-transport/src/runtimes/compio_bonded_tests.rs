//! Production bonded-caller attach on the Compio [`Owner`]: `connect_bonded`.
//!
//! These tests drive the Owner's public surface only (`connect_bonded`,
//! `logical_caller*`, `remove_caller`, `poll_*`, `service`, `shutdown_and_drain`).
//! Group state transitions are never poked through the caller table; the
//! table is inspected read-only where a test has to prove reclamation.

use super::*;
use crate::caller::{LogicalCallerState, LogicalCallerStats, RemovedLogicalCaller};
use crate::{BondedCallerConfig, CallerConfig, GroupConfig, PoolEvent, PoolOutcome};
use srt_proto::GroupMemberState;
use srt_proto::handshake::GroupType;
use std::net::SocketAddr;
use std::time::Duration;

fn shared_leg(remote: SocketAddr) -> CallerConfig {
    CallerConfig::builder(remote)
        .ownership(crate::SocketOwnership::Shared)
        .build()
        .expect("caller config")
}

fn shared_leg_with_id(remote: SocketAddr, socket_id: u32) -> CallerConfig {
    let mut session = crate::SessionConfig::default();
    session.set_socket_id(socket_id);
    CallerConfig::builder(remote)
        .ownership(crate::SocketOwnership::Shared)
        .session(session)
        .build()
        .expect("caller config")
}

fn bonded(group: u32, group_type: GroupType, legs: &[(SocketAddr, u16)]) -> BondedCallerConfig {
    legs.iter().fold(
        BondedCallerConfig::new(GroupConfig::new(group, group_type)),
        |config, (remote, weight)| config.leg(shared_leg(*remote), *weight),
    )
}

/// An address nothing listens on; datagrams to it are simply never answered.
fn dead_peer() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.local_addr().expect("addr")
}

/// An Owner whose listener accepts bonded publishers, so a bonded caller
/// created on the SAME owner has a real peer to handshake with.
fn owner_with_bonded_listener(tx_capacity: usize) -> (Owner, SocketAddr) {
    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    let addr = std_sock.local_addr().expect("listener addr");
    let sock = compio::net::UdpSocket::from_std(std_sock).expect("adopt listener");
    let config = crate::ListenerConfig::builder(addr)
        .bonded_inputs(crate::BondedInputPolicy::Accept)
        .build()
        .expect("listener config");
    let side = ListenerSide::new(sock, &config).expect("listener side");
    (Owner::new(tx_capacity).with_listener(side), addr)
}

fn group_stats(owner: &Owner, id: &crate::LogicalCallerId) -> Box<crate::GroupConnectionStats> {
    match owner
        .logical_caller(id)
        .expect("logical caller")
        .stats()
        .expect("stats")
    {
        LogicalCallerStats::Group(stats) => stats,
        LogicalCallerStats::Direct(_) => panic!("expected a bonded caller"),
    }
}

/// Serve the owner until `done` is true or the round budget runs out.
async fn drive_until(
    owner: &mut Owner,
    start_micros: u64,
    rounds: u64,
    mut done: impl FnMut(&mut Owner) -> bool,
) -> u64 {
    let budget = OwnerServiceBudget::default();
    let mut now = start_micros;
    for round in 0..rounds {
        now = start_micros + round * 5_000;
        let _ = owner.service(Timestamp::from_micros(now), budget).await;
        owner.wait_for_activity(Duration::from_millis(1)).await;
        if done(owner) {
            return now;
        }
    }
    now
}

fn all_legs_established(owner: &Owner, id: &crate::LogicalCallerId, legs: usize) -> bool {
    let stats = group_stats(owner, id);
    stats
        .legs
        .iter()
        .filter(|leg| {
            matches!(
                leg.state,
                GroupMemberState::Active | GroupMemberState::Standby
            )
        })
        .count()
        == legs
}

fn admitted(outcome: PoolOutcome) -> crate::LogicalCallerId {
    match outcome {
        PoolOutcome::Admitted(id) => id,
        other => panic!("expected immediate admission, got {other:?}"),
    }
}

#[test]
fn direct_connect_is_unchanged_by_the_bonded_path() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let id = admitted(
            owner
                .connect(&shared_leg(dead_peer()), Timestamp::from_micros(0))
                .expect("direct connect"),
        );
        let caller = owner.logical_caller(&id).expect("direct caller");
        assert!(matches!(
            caller.stats(),
            Some(LogicalCallerStats::Direct(_))
        ));
        assert_eq!(caller.state(), Some(LogicalCallerState::Connecting));
        assert_eq!(owner.caller_pool_stats().expect("stats").in_flight, 1);
    });
}

#[test]
fn bonded_connect_admits_one_logical_caller_immediately() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let config = bonded(
            7,
            GroupType::Broadcast,
            &[(dead_peer(), 1), (dead_peer(), 1)],
        );
        let id = admitted(
            owner
                .connect_bonded(&config, Timestamp::from_micros(0))
                .expect("bonded connect"),
        );

        let stats = group_stats(&owner, &id);
        assert_eq!(stats.mode, srt_proto::GroupMode::Broadcast);
        assert_eq!(stats.legs.len(), 2);
        assert_eq!(
            owner.logical_caller(&id).and_then(|caller| caller.state()),
            Some(LogicalCallerState::Connecting)
        );
        // One logical caller, one permit, whatever the leg count.
        let pool = owner.caller_pool_stats().expect("pool stats");
        assert_eq!(pool.in_flight, 1);
        assert_eq!(pool.started, 1);
        assert_eq!(owner.caller().expect("caller side").table().len(), 1);
    });
}

#[test]
fn bonded_connect_starts_the_handshake_on_every_leg() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let peers = [dead_peer(), dead_peer(), dead_peer()];
        let config = bonded(
            11,
            GroupType::Backup,
            &[(peers[0], 3), (peers[1], 2), (peers[2], 1)],
        );
        let id = admitted(
            owner
                .connect_bonded(&config, Timestamp::from_micros(0))
                .expect("bonded connect"),
        );
        let stats = group_stats(&owner, &id);
        let ids: Vec<u32> = stats.legs.iter().map(|leg| leg.member_id).collect();
        assert_eq!(ids, vec![1, 2, 3], "distinct member IDs in leg order");
        let weights: Vec<u16> = stats.legs.iter().map(|leg| leg.weight).collect();
        assert_eq!(weights, vec![3, 2, 1], "configured weights are preserved");
        // No peer has answered, so no leg may be delivering yet (an
        // unconnected Backup leg parks as Standby, a Broadcast one Pending).
        assert!(
            stats
                .legs
                .iter()
                .all(|leg| leg.state != GroupMemberState::Active)
        );
    });
}

fn set_pool(owner: &mut Owner, max_in_flight: usize, deadline: Duration) {
    owner
        .set_caller_pool_policy(
            std::num::NonZeroUsize::new(max_in_flight).expect("non-zero"),
            deadline,
        )
        .expect("pool policy");
}

fn pool_events(owner: &mut Owner) -> Vec<PoolEvent> {
    let mut events = Vec::new();
    owner.poll_caller_pool_events(&mut events);
    events
}

/// One group takes ONE queue slot and, once admitted, ONE permit; the request
/// ID it was queued under is the one its admission is reported with.
#[test]
fn queued_bonded_request_keeps_its_id_and_its_deadline_starts_at_admission() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        set_pool(&mut owner, 1, Duration::from_millis(50));
        let first = admitted(
            owner
                .connect(&shared_leg(dead_peer()), Timestamp::from_micros(0))
                .expect("first"),
        );
        let config = bonded(3, GroupType::Broadcast, &[(dead_peer(), 1), (dead_peer(), 1)]);
        let request_id = match owner
            .connect_bonded(&config, Timestamp::from_micros(0))
            .expect("bonded")
        {
            PoolOutcome::Queued(id) => id,
            other => panic!("the permit is taken, expected Queued, got {other:?}"),
        };
        let stats = owner.caller_pool_stats().expect("stats");
        assert_eq!((stats.in_flight, stats.queued), (1, 1));
        assert_eq!(owner.caller().expect("side").table().len(), 1, "not admitted yet");
        assert!(pool_events(&mut owner).iter().any(
            |event| matches!(event, PoolEvent::Queued { request_id: id } if *id == request_id)
        ));

        // Free the permit at t=40ms; the queued group is admitted then.
        drop(owner.remove_caller(first).expect("remove first"));
        let _ = owner
            .service(Timestamp::from_micros(40_000), OwnerServiceBudget::default())
            .await;
        let events = pool_events(&mut owner);
        let admissions: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                PoolEvent::Admitted {
                    request_id: id,
                    caller_id,
                } if *id == request_id => Some(*caller_id),
                _ => None,
            })
            .collect();
        assert_eq!(admissions.len(), 1, "exactly one admission: {events:?}");
        let group_id = admissions[0];
        assert_eq!(group_stats(&owner, &group_id).legs.len(), 2);

        // 60ms is past the deadline had it started when the request was
        // queued (0 + 50ms), but not one that starts at admission (40 + 50).
        let _ = owner
            .service(Timestamp::from_micros(60_000), OwnerServiceBudget::default())
            .await;
        assert!(
            !pool_events(&mut owner)
                .iter()
                .any(|event| matches!(event, PoolEvent::Expired { .. })),
            "queue wait must not count against the attempt deadline"
        );
        let _ = owner
            .service(Timestamp::from_micros(100_000), OwnerServiceBudget::default())
            .await;
        assert!(pool_events(&mut owner).iter().any(|event| matches!(
            event,
            PoolEvent::Expired { request_id: id, caller_id } if *id == request_id && *caller_id == group_id
        )));
    });
}

#[test]
fn full_pool_refuses_a_bonded_request_without_retaining_it() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        set_pool(&mut owner, 1, Duration::from_secs(10));
        let _first = admitted(
            owner
                .connect(&shared_leg(dead_peer()), Timestamp::from_micros(0))
                .expect("first"),
        );
        let config = bonded(4, GroupType::Backup, &[(dead_peer(), 1), (dead_peer(), 2)]);
        assert!(matches!(
            owner.connect_bonded(&config, Timestamp::from_micros(0)),
            Ok(PoolOutcome::Queued(_))
        ));
        let before = owner.caller_pool_stats().expect("stats");
        assert_eq!(
            owner
                .connect_bonded(&config, Timestamp::from_micros(0))
                .expect("full"),
            PoolOutcome::Full
        );
        let after = owner.caller_pool_stats().expect("stats");
        assert_eq!(
            (after.in_flight, after.queued),
            (before.in_flight, before.queued)
        );
        assert_eq!(after.started, before.started, "nothing was admitted");
        assert_eq!(owner.caller().expect("side").table().len(), 1);
    });
}

/// The whole group is retired as one logical caller and every route it held
/// is reclaimed: the same explicit socket IDs can be admitted again.
#[test]
fn bonded_attempt_deadline_retires_the_whole_group() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        set_pool(&mut owner, 4, Duration::from_millis(10));
        let make = || {
            BondedCallerConfig::new(GroupConfig::new(5, GroupType::Broadcast))
                .leg(shared_leg_with_id(dead_peer(), 0x5101), 1)
                .leg(shared_leg_with_id(dead_peer(), 0x5102), 1)
        };
        let id = admitted(
            owner
                .connect_bonded(&make(), Timestamp::from_micros(0))
                .expect("bonded"),
        );
        // Explicit IDs are unique per table: the same request cannot coexist.
        assert!(
            owner
                .connect_bonded(&make(), Timestamp::from_micros(0))
                .is_err(),
            "duplicate socket IDs are refused, leaving the first group intact"
        );
        assert_eq!(owner.caller().expect("side").table().len(), 1);

        let _ = owner
            .service(
                Timestamp::from_micros(20_000),
                OwnerServiceBudget::default(),
            )
            .await;
        let events = pool_events(&mut owner);
        assert!(
            events.iter().any(|event| matches!(
                event,
                PoolEvent::Expired { caller_id, .. } if *caller_id == id
            )),
            "{events:?}"
        );
        assert!(owner.logical_caller(&id).is_none(), "the group is gone");
        let stats = owner.caller_pool_stats().expect("stats");
        assert_eq!((stats.in_flight, stats.expired), (0, 1));
        assert_eq!(owner.caller().expect("side").table().len(), 0);
        assert_eq!(
            owner.time_until_next_deadline(Timestamp::from_micros(20_000), 7_000_000),
            7_000_000,
            "no pool deadline or protocol timer is left behind"
        );
        // Routes reclaimed: the identical legs are admissible again.
        assert!(matches!(
            owner.connect_bonded(&make(), Timestamp::from_micros(30_000)),
            Ok(PoolOutcome::Admitted(_))
        ));
    });
}

#[test]
fn remove_caller_reclaims_every_leg_route_and_deadline() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        set_pool(&mut owner, 4, Duration::from_secs(30));
        let make = || {
            BondedCallerConfig::new(GroupConfig::new(6, GroupType::Backup))
                .leg(shared_leg_with_id(dead_peer(), 0x6101), 2)
                .leg(shared_leg_with_id(dead_peer(), 0x6102), 1)
                .leg(shared_leg_with_id(dead_peer(), 0x6103), 1)
        };
        let id = admitted(
            owner
                .connect_bonded(&make(), Timestamp::from_micros(0))
                .expect("bonded"),
        );
        let removed = owner.remove_caller(id).expect("group removed");
        match removed {
            RemovedLogicalCaller::Group(legs) => assert_eq!(legs.len(), 3),
            RemovedLogicalCaller::Direct(_) => panic!("expected a group"),
        }
        assert!(owner.logical_caller(&id).is_none());
        assert_eq!(owner.caller_pool_stats().expect("stats").in_flight, 0);
        assert_eq!(owner.caller().expect("side").table().len(), 0);
        assert_eq!(
            owner.time_until_next_deadline(Timestamp::from_micros(1), 9_000_000),
            9_000_000
        );
        assert!(matches!(
            owner.connect_bonded(&make(), Timestamp::from_micros(2)),
            Ok(PoolOutcome::Admitted(_))
        ));
    });
}

/// Zero legs and more than `MAX_GROUP_MEMBERS` are refused before anything is
/// created; exactly the maximum is admitted as one caller.
#[test]
fn bonded_leg_count_is_bounded_by_the_protocol_limit() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let empty = BondedCallerConfig::new(GroupConfig::new(8, GroupType::Broadcast));
        assert!(
            owner
                .connect_bonded(&empty, Timestamp::from_micros(0))
                .is_err()
        );

        let peer = dead_peer();
        let too_many: Vec<_> = (0..=srt_proto::MAX_GROUP_MEMBERS)
            .map(|_| (peer, 1))
            .collect();
        let over = bonded(8, GroupType::Broadcast, &too_many);
        assert!(
            owner
                .connect_bonded(&over, Timestamp::from_micros(0))
                .is_err()
        );
        assert!(
            owner.caller().is_none(),
            "no side, group or leg was created"
        );
        assert!(owner.caller_pool_stats().is_none());

        let exact = bonded(
            8,
            GroupType::Broadcast,
            &too_many[..srt_proto::MAX_GROUP_MEMBERS],
        );
        let id = admitted(
            owner
                .connect_bonded(&exact, Timestamp::from_micros(0))
                .expect("exactly the maximum"),
        );
        assert_eq!(
            group_stats(&owner, &id).legs.len(),
            srt_proto::MAX_GROUP_MEMBERS
        );
        assert_eq!(owner.caller_pool_stats().expect("stats").in_flight, 1);
    });
}

/// A rejected group leaves the Owner exactly as configurable as before: no
/// side, no permit, no frozen wire ceiling or pool policy.
#[test]
fn rejected_bonded_attach_is_transactional() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let exclusive = CallerConfig::builder(dead_peer())
            .build()
            .expect("exclusive leg");
        let bad = BondedCallerConfig::new(GroupConfig::new(9, GroupType::Broadcast))
            .leg(shared_leg(dead_peer()), 1)
            .leg(exclusive, 1);
        assert!(
            owner
                .connect_bonded(&bad, Timestamp::from_micros(0))
                .is_err()
        );

        let v6: SocketAddr = "[::1]:9".parse().expect("v6");
        let mixed = bonded(9, GroupType::Broadcast, &[(dead_peer(), 1), (v6, 1)]);
        let error = owner
            .connect_bonded(&mixed, Timestamp::from_micros(0))
            .expect_err("mixed address families share no socket");
        assert!(error.to_string().contains("address family"), "{error}");

        assert!(owner.caller().is_none(), "no caller side was attached");
        assert!(owner.caller_pool_stats().is_none());
        owner
            .set_wire_ceiling(4096)
            .expect("configuration is still open after refusals");
        set_pool(&mut owner, 2, Duration::from_secs(1));
        assert!(matches!(
            owner.connect_bonded(
                &bonded(9, GroupType::Broadcast, &[(dead_peer(), 1)]),
                Timestamp::from_micros(0)
            ),
            Ok(PoolOutcome::Admitted(_))
        ));
    });
}

/// Direct callers and a bonded caller live behind the one caller UDP socket,
/// and adding legs adds no socket handle or task: the only task population is
/// the Owner's fixed TX lanes, which are already running before the group.
#[test]
fn bonded_and_direct_callers_share_one_socket_at_fixed_runtime_cost() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(64);
        set_pool(&mut owner, 8, Duration::from_secs(30));
        let d1 = admitted(
            owner
                .connect(&shared_leg(dead_peer()), Timestamp::from_micros(0))
                .expect("direct 1"),
        );
        let d2 = admitted(
            owner
                .connect(&shared_leg(dead_peer()), Timestamp::from_micros(0))
                .expect("direct 2"),
        );
        // Start the lanes with direct traffic first, so the lane count below
        // is the settled fixed population rather than lazy startup.
        let _ = owner
            .service(Timestamp::from_micros(500), OwnerServiceBudget::default())
            .await;
        owner.wait_for_activity(Duration::from_millis(5)).await;
        let _ = owner
            .service(Timestamp::from_micros(600), OwnerServiceBudget::default())
            .await;
        let lanes_before = owner.tx_engine.lanes.len();
        assert!(lanes_before > 0, "TX lanes are running");
        let (refs, addr) = {
            let side = owner.caller().expect("side");
            (
                Rc::strong_count(&side.sock),
                side.sock.local_addr().expect("addr"),
            )
        };

        let peers: Vec<_> = (0..srt_proto::MAX_GROUP_MEMBERS)
            .map(|_| (dead_peer(), 1))
            .collect();
        let config = bonded(12, GroupType::Broadcast, &peers);
        let group = admitted(
            owner
                .connect_bonded(&config, Timestamp::from_micros(1_000))
                .expect("64-leg group"),
        );
        assert_eq!(
            Rc::strong_count(&owner.caller().expect("side").sock),
            refs,
            "attaching 64 legs took no socket handle"
        );
        let _ = owner
            .service(Timestamp::from_micros(2_000), OwnerServiceBudget::default())
            .await;

        let side = owner.caller().expect("side");
        assert_eq!(
            side.sock.local_addr().expect("addr"),
            addr,
            "still the one socket"
        );
        // While datagrams are in flight each send holds a handle, so the
        // count is bounded by the fixed TX pool, never by the leg count.
        assert!(
            Rc::strong_count(&side.sock) <= refs + owner.tx_pool().capacity(),
            "socket handles are bounded by TX capacity, not by legs"
        );
        assert_eq!(
            owner.tx_engine.lanes.len(),
            lanes_before,
            "64 legs added no TX lane or other task"
        );
        for id in [d1, d2, group] {
            assert!(
                owner.logical_caller(&id).is_some(),
                "direct and bonded callers all resolve as logical callers"
            );
        }
        assert_eq!(side.table().len(), 3);
        assert_eq!(owner.caller_pool_stats().expect("stats").in_flight, 3);
    });
}

/// Broadcast: one logical send is offered to every established leg by the
/// existing group core, and the peer receives it.
#[test]
fn broadcast_send_reaches_every_established_leg() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let (mut owner, listener) = owner_with_bonded_listener(64);
        let config = bonded(21, GroupType::Broadcast, &[(listener, 1), (listener, 1)]);
        let id = admitted(
            owner
                .connect_bonded(&config, Timestamp::from_micros(1_000))
                .expect("bonded"),
        );
        let mut now = drive_until(&mut owner, 10_000, 400, |owner| {
            all_legs_established(owner, &id, 2)
        })
        .await;
        assert!(all_legs_established(&owner, &id, 2), "both legs handshook");
        assert_eq!(group_stats(&owner, &id).aggregate.active_legs, 2);
        // Establishment resolves the attempt: the group's one permit is
        // released, exactly as for a connected direct caller.
        let _ = owner
            .service(
                Timestamp::from_micros(now + 5_000),
                OwnerServiceBudget::default(),
            )
            .await;
        assert_eq!(owner.caller_pool_stats().expect("stats").in_flight, 0);

        let payload = Bytes::from_static(b"one logical payload, every broadcast leg");
        now += 10_000;
        owner
            .logical_caller_mut(&id)
            .expect("group")
            .send_shared(payload.clone(), Timestamp::from_micros(now))
            .expect("send");
        let mut received = 0;
        drive_until(&mut owner, now + 5_000, 400, |owner| {
            let mut events = Vec::new();
            owner.poll_listener_events(&mut events);
            received += events
                .iter()
                .filter(|event| matches!(&event.event,
                    srt_proto::ConnectionEvent::DataReceived { payload: got, .. } if *got == payload))
                .count();
            received > 0
                && group_stats(owner, &id)
                    .legs
                    .iter()
                    .all(|leg| leg.connection.sender.is_some_and(|s| s.total_data_packets_sent >= 1))
        })
        .await;
        let stats = group_stats(&owner, &id);
        for leg in &stats.legs {
            assert!(
                leg.connection.sender.is_some_and(|s| s.total_data_packets_sent >= 1),
                "leg {} was offered the payload",
                leg.member_id
            );
        }
        assert_eq!(stats.aggregate.logical_payloads_sent, 1, "one logical send");
        assert!(stats.aggregate.wire_unique_packets_sent >= 2, "duplicated on the wire");
        assert!(received >= 1, "the listener received the payload");
    });
}

/// Backup: a connected leg carries the payload while an unreachable
/// higher-weight sibling never delivers; only one leg is offered the data.
#[test]
fn backup_send_uses_the_established_leg_only() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let (mut owner, listener) = owner_with_bonded_listener(64);
        let config = bonded(22, GroupType::Backup, &[(dead_peer(), 10), (listener, 1)]);
        let id = admitted(
            owner
                .connect_bonded(&config, Timestamp::from_micros(1_000))
                .expect("bonded"),
        );
        let mut now = drive_until(&mut owner, 10_000, 400, |owner| {
            owner.logical_caller(&id).and_then(|c| c.state()) == Some(LogicalCallerState::Connected)
        })
        .await;
        assert_eq!(
            owner.logical_caller(&id).and_then(|c| c.state()),
            Some(LogicalCallerState::Connected),
            "the reachable leg alone connects the group"
        );

        let payload = Bytes::from_static(b"backup payload over the leg that works");
        now += 10_000;
        owner
            .logical_caller_mut(&id)
            .expect("group")
            .send_shared(payload.clone(), Timestamp::from_micros(now))
            .expect("send over the surviving leg");
        let mut received = false;
        drive_until(&mut owner, now + 5_000, 400, |owner| {
            let mut events = Vec::new();
            owner.poll_listener_events(&mut events);
            received |= events.iter().any(|event| {
                matches!(&event.event,
                srt_proto::ConnectionEvent::DataReceived { payload: got, .. } if *got == payload)
            });
            received
        })
        .await;
        assert!(received, "the payload arrived through the working leg");
        let stats = group_stats(&owner, &id);
        assert_eq!(stats.aggregate.logical_payloads_sent, 1);
        let carriers = stats
            .legs
            .iter()
            .filter(|leg| {
                leg.connection
                    .sender
                    .is_some_and(|s| s.total_data_packets_sent >= 1)
            })
            .count();
        assert_eq!(carriers, 1, "Backup offers the payload to a single leg");
        let dead = stats
            .legs
            .iter()
            .find(|leg| leg.member_id == 1)
            .expect("leg 1");
        assert!(
            dead.connection
                .sender
                .is_none_or(|s| s.total_data_packets_sent == 0)
        );
    });
}

/// A live bonded caller does not weaken the Owner's shutdown invariants.
#[test]
fn shutdown_with_a_live_bonded_caller_is_quiescent() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let (mut owner, listener) = owner_with_bonded_listener(16);
        let config = bonded(23, GroupType::Broadcast, &[(listener, 1), (listener, 1)]);
        let id = admitted(
            owner
                .connect_bonded(&config, Timestamp::from_micros(1_000))
                .expect("bonded"),
        );
        drive_until(&mut owner, 10_000, 400, |owner| {
            all_legs_established(owner, &id, 2)
        })
        .await;
        assert!(all_legs_established(&owner, &id, 2));

        let drained = owner.shutdown_and_drain(Duration::from_millis(500)).await;
        assert!(drained, "teardown reaches quiescence");
        assert_eq!(owner.tx_in_flight(), 0);
        assert_eq!(owner.tx_pool().free_count(), owner.tx_pool().capacity());
        assert!(owner.quiescence_invariants_hold());
    });
}

/// A peer-local TX failure is attributed to the logical group AND the
/// physical leg, and does not fault the Owner.
#[test]
fn bonded_tx_failure_is_attributed_to_group_and_leg() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let config = bonded(
            31,
            GroupType::Broadcast,
            &[(dead_peer(), 1), (dead_peer(), 1)],
        );
        let id = admitted(
            owner
                .connect_bonded(&config, Timestamp::from_micros(0))
                .expect("bonded"),
        );
        // Real group handshake datagrams go out through the Owner first.
        let report = owner
            .service(
                Timestamp::from_micros(1_000),
                OwnerServiceBudget {
                    max_completions: 0,
                    ..Default::default()
                },
            )
            .await;
        assert!(
            report.tx_packets_submitted >= 2,
            "both legs submitted a handshake"
        );

        let leg = 2;
        let token = TxAttribution::caller(id, leg);
        let peer = dead_peer();
        {
            let engine = &mut owner.tx_engine;
            let lane_index = engine
                .lanes
                .iter()
                .position(|lane| lane.state.borrow().completion.is_none())
                .unwrap_or(0);
            engine.completed_lanes.borrow_mut().clear();
            let lane = &engine.lanes[lane_index];
            lane.state.borrow_mut().completion = Some(TxCompletion {
                meta: InFlightMeta {
                    peer,
                    expected_len: 20,
                    attribution: token,
                },
                res: Err(io::Error::from_raw_os_error(libc::EHOSTUNREACH)),
                buf: vec![0u8; DEFAULT_TX_SLOT_SIZE],
            });
            engine.completed_lanes.borrow_mut().push_back(lane_index);
        }
        let _ = owner
            .service(Timestamp::from_micros(2_000), OwnerServiceBudget::default())
            .await;
        assert!(
            owner.is_operational(),
            "one failed leg does not fault the Owner"
        );
        let mut failures = Vec::new();
        owner.poll_tx_failures(8, &mut failures);
        let failure = failures
            .iter()
            .find(|failure| failure.attribution == token)
            .expect("the group leg failure is reported");
        assert_eq!(failure.attribution.caller_id(), Some(id));
        assert_eq!(failure.attribution.leg(), leg);
        assert_eq!(failure.class, TxFailureClass::PeerLocal);
        assert!(
            owner.logical_caller(&id).is_some(),
            "the application still resolves the group and decides its fate"
        );
    });
}

/// Two legs with the SAME explicit SRT socket ID: configuration prepares,
/// the candidate socket and side are built, and only the table's
/// `add_group` refuses them. That is a genuine post-side-construction
/// failure reachable through public configuration.
fn duplicate_socket_id_group(group: u32) -> BondedCallerConfig {
    BondedCallerConfig::new(GroupConfig::new(group, GroupType::Broadcast))
        .leg(shared_leg_with_id(dead_peer(), 0x0D01), 1)
        .leg(shared_leg_with_id(dead_peer(), 0x0D01), 1)
}

fn assert_owner_untouched(owner: &Owner) {
    assert!(owner.caller().is_none(), "no caller side was committed");
    assert_eq!(owner.rx_mode(), None, "no receive datapath was claimed");
    assert!(
        !owner.sessions_started,
        "a refused attach starts no session"
    );
    assert!(owner.caller_pool_stats().is_none(), "no pool exists");
    assert!(
        owner.rx_stats().caller.is_none(),
        "no receive consumer exists"
    );
}

/// The first caller attach commits completely or changes nothing, even when
/// the request fails after the candidate side was built.
#[test]
fn failed_first_bonded_admission_leaves_the_owner_untouched() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let error = owner
            .connect_bonded(&duplicate_socket_id_group(41), Timestamp::from_micros(0))
            .expect_err("duplicate socket IDs are refused by the table");
        assert!(error.to_string().contains("distinct"), "{error}");
        assert_owner_untouched(&owner);

        // Configuration is not frozen by the refusal...
        owner
            .set_rx_substrate(ManagedRxSubstrate::NotIoUring)
            .expect("substrate still declarable");
        set_pool(&mut owner, 3, Duration::from_secs(9));
        owner
            .set_wire_ceiling(4096)
            .expect("wire ceiling still settable");

        // ...and a valid request becomes the genuine first caller.
        let id = admitted(
            owner
                .connect_bonded(
                    &bonded(
                        42,
                        GroupType::Broadcast,
                        &[(dead_peer(), 1), (dead_peer(), 1)],
                    ),
                    Timestamp::from_micros(0),
                )
                .expect("valid group"),
        );
        assert!(owner.caller().is_some());
        assert_eq!(owner.rx_mode(), Some(OwnerRxMode::RawReadiness));
        assert!(owner.sessions_started);
        let pool = owner.caller_pool_stats().expect("pool");
        assert_eq!(
            (pool.started, pool.in_flight),
            (1, 1),
            "the first admission"
        );
        assert_eq!(owner.caller().expect("side").table().len(), 1);
        assert!(owner.logical_caller(&id).is_some());
    });
}

/// Same rule under a required managed receive: the failed attach leaves no
/// consumer or lease behind, and the valid retry is the first caller that
/// starts the consumer (only where the host can run one).
#[test]
fn failed_first_admission_under_managed_rx_starts_no_consumer() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    let capable = runtime
        .block_on(async { runtime.driver_type().is_iouring() && runtime.buffer_pool().is_ok() });
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        owner.set_rx_mode_policy(RxModePolicy::ManagedRequired);
        owner
            .set_rx_substrate(ManagedRxSubstrate::Available)
            .expect("declare substrate");

        let error = owner
            .connect_bonded(&duplicate_socket_id_group(43), Timestamp::from_micros(0))
            .expect_err("refused after the candidate side was built");
        assert!(error.to_string().contains("distinct"), "{error}");
        assert_owner_untouched(&owner);
        // No side exists, so no consumer task, staged completion or
        // provided-buffer lease can; the TX pool is whole as well.
        assert_eq!(owner.tx_in_flight(), 0);
        assert_eq!(owner.tx_pool().free_count(), owner.tx_pool().capacity());
        // Still configurable, and the same rule holds for a direct attempt
        // refused before side construction.
        owner
            .set_rx_substrate(ManagedRxSubstrate::Available)
            .expect("substrate still declarable");

        if !capable {
            // No consumer can run on this kernel; the negative half above is
            // the whole claim here.
            return;
        }
        let id = admitted(
            owner
                .connect_bonded(
                    &bonded(
                        44,
                        GroupType::Broadcast,
                        &[(dead_peer(), 1), (dead_peer(), 1)],
                    ),
                    Timestamp::from_micros(0),
                )
                .expect("valid group"),
        );
        assert_eq!(owner.rx_mode(), Some(OwnerRxMode::ManagedMultishot));
        let ring = owner
            .caller()
            .expect("side")
            .rx
            .ring
            .as_ref()
            .expect("managed ring")
            .clone();
        assert!(
            ring.borrow().task.is_some(),
            "the consumer runs after commit"
        );
        assert!(owner.logical_caller(&id).is_some());
        assert!(
            owner.shutdown_and_drain(Duration::from_secs(5)).await,
            "the consumer stops through the awaited cancel"
        );
        assert!(owner.quiescence_invariants_hold());
    });
}

/// Construction alone never starts a managed consumer; `start_managed_rx`
/// does, once. A candidate side dropped after a failed admission therefore
/// never owned a live receive.
#[test]
fn caller_side_construction_starts_no_managed_task() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let sock = compio::net::UdpSocket::from_std(std_sock).expect("adopt");
        let transport = crate::TransportConfig {
            ownership: crate::SocketOwnership::Shared,
            ..crate::TransportConfig::default()
        }
        .resolve(crate::RuntimeFlavor::Compio.capabilities())
        .expect("shared transport");
        let mut side = OwnerCallerSide::from_parts_with_rx_mode(
            sock,
            std::num::NonZeroUsize::MIN,
            Duration::from_secs(1),
            transport,
            None,
            crate::ConnectConfig::default(),
            OwnerRxMode::ManagedMultishot,
            managed_rx_buffer_len(1500),
        )
        .expect("candidate side");
        let ring = side
            .rx
            .ring
            .as_ref()
            .expect("managed ring configured")
            .clone();
        assert!(
            ring.borrow().task.is_none(),
            "construction spawns no consumer"
        );
        assert!(
            side.rx.quiescent(),
            "a never-started candidate holds nothing"
        );

        side.start_managed_rx(managed_rx_buffer_len(1500));
        assert!(ring.borrow().task.is_some(), "the commit step starts it");
        // Starting twice is a no-op, and the awaited stop is what releases it.
        side.start_managed_rx(managed_rx_buffer_len(1500));
        assert!(side.rx.stop_and_join(Duration::from_secs(5)).await);
        assert!(side.rx.quiescent());
    });
}

/// A first direct connect follows the same rule: side, receive mode and
/// started-session flag are committed together, after admission. (No legal
/// public direct configuration fails between side construction and
/// admission, so there is no direct counterpart to the duplicate-ID case.)
#[test]
fn first_direct_connect_commits_side_mode_and_session_together() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        assert_owner_untouched(&owner);
        let id = admitted(
            owner
                .connect(&shared_leg(dead_peer()), Timestamp::from_micros(0))
                .expect("direct connect"),
        );
        assert!(owner.caller().is_some());
        assert_eq!(owner.rx_mode(), Some(OwnerRxMode::RawReadiness));
        assert!(owner.sessions_started);
        assert!(owner.logical_caller(&id).is_some());
        assert_eq!(owner.caller_pool_stats().expect("pool").started, 1);
    });
}
