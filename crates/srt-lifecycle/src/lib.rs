#![forbid(unsafe_code)]
//! Runtime-neutral SRT admission and worker-affinity policy.
//!
//! This crate deliberately stops at the lifecycle boundary. It owns the
//! logical identity and assignment invariants that must be shared by a
//! listener and its workers, but it does not own live or external resources
//! such as sockets, clocks, threads, event loops, media delivery, or
//! authorization. It may own policy bookkeeping such as routing maps and
//! counters.
//!
//! The rule, as a test for anything proposed for this crate:
//!
//! > **It takes values and returns decisions. It owns policy bookkeeping, but
//! > never live protocol, socket, clock, or runtime resources.**
//!
//! Time arrives as a parameter ([`is_terminal`]), never read from a
//! clock. Wire bytes are decoded by `shiguredo_srt::handshake::peek_handshake` and
//! only *interpreted* here. Anything holding a live `SrtConnection`, a
//! timer store, or a file descriptor belongs in `srt-transport` --
//! which is where the admission peer table lives, calling back into the
//! policy defined here.
//!
//! ```text
//!   decisions (this crate)        things (srt-transport)
//!   ──────────────────────        ──────────────────────
//!   WorkerRouter                  PeerTable / AdmissionPeer
//!   decide_promotion()            ManualTimerStore
//!   cookie_for_worker()           Handoff / WorkerMessage
//!   is_terminal()                 IngressTelemetry
//!   handshake_identity()          per-runtime Conn
//! ```

pub mod cookie;
pub mod identity;
pub mod promotion;
pub mod routing;
pub mod terminal;
pub mod wire;

pub use cookie::*;
pub use identity::*;
pub use promotion::*;
pub use routing::*;
pub use terminal::*;

#[cfg(test)]
mod promotion_tests {
    use super::*;
    use shiguredo_srt::handshake::{GroupExtensionData, GroupType};

    const MODES: [Promotion; 4] = [
        Promotion::Never,
        Promotion::Relocate,
        Promotion::Bonded,
        Promotion::All,
    ];

    fn affinity(group_id: u32) -> GroupAffinity {
        GroupAffinity {
            group_id,
            stream_id: None,
            extension: GroupExtensionData {
                group_id,
                group_type: GroupType::Broadcast,
                flags: 0,
                weight: 0,
            },
        }
    }

    /// Run one decision against a router in a known state: `seed_owner`
    /// pre-assigns the group to a chosen worker, so the bonded case is
    /// deterministic instead of depending on selection order.
    fn decide(
        mode: Promotion,
        group: Option<GroupAffinity>,
        worker_index: usize,
        seed_owner: Option<usize>,
    ) -> PromotionDecision {
        let mut router: WorkerRouter<u32> = WorkerRouter::new(4);
        if let (Some(group), Some(owner)) = (group.clone(), seed_owner) {
            // Anchor the group on `owner`. Round-robin hands out workers
            // in order, so walk it forward with unbonded keys until the
            // next pick is `owner`, then register the group with a real
            // tuple. Re-assigning one key would just return its existing
            // worker and never move the group anywhere.
            for i in 0..owner {
                router.assign(8_000 + i as u32, None, RoutingMode::RoundRobin);
            }
            router.assign(9_000, Some(group), RoutingMode::RoundRobin);
        }
        decide_promotion(
            mode,
            1u32,
            group,
            worker_index,
            &mut router,
            RoutingMode::LeastTuples,
            true,
        )
    }

    #[test]
    fn never_promotes_nothing_bonded_or_not() {
        for group in [None, Some(affinity(7))] {
            for worker in 0..4 {
                assert_eq!(
                    decide(Promotion::Never, group.clone(), worker, Some(2)),
                    PromotionDecision::StayOnListener,
                    "Never must not promote (group={group:?}, worker={worker})"
                );
            }
        }
    }

    #[test]
    fn unbonded_promotes_only_under_all() {
        for mode in MODES {
            let decision = decide(mode, None, 0, None);
            let expected = if mode == Promotion::All {
                PromotionDecision::PromoteHere
            } else {
                PromotionDecision::StayOnListener
            };
            assert_eq!(decision, expected, "unbonded under {mode:?}");
        }
    }

    #[test]
    fn shared_udp_tuple_never_promotes() {
        let mut router: WorkerRouter<u32> = WorkerRouter::new(4);
        for mode in MODES {
            assert_eq!(
                decide_promotion(
                    mode,
                    1u32,
                    None,
                    0,
                    &mut router,
                    RoutingMode::LeastTuples,
                    false,
                ),
                PromotionDecision::StayOnListener,
                "unbonded shared tuple under {mode:?}"
            );
            assert_eq!(
                decide_promotion(
                    mode,
                    2u32,
                    Some(affinity(7)),
                    0,
                    &mut router,
                    RoutingMode::LeastTuples,
                    false,
                ),
                PromotionDecision::StayOnListener,
                "bonded shared tuple under {mode:?}"
            );
        }
    }

    #[test]
    fn shared_udp_tuple_reuseport_single_stays_unconnected() {
        for workers in [0, 1, 4, 64] {
            assert_eq!(
                plan_reuseport_single(workers, false),
                ReuseportSinglePlan::UnconnectedListener,
                "workers={workers}"
            );
        }
        assert_eq!(
            plan_reuseport_single(4, true),
            ReuseportSinglePlan::ConnectedWorkers(4)
        );
        assert_eq!(
            plan_reuseport_single(0, true),
            ReuseportSinglePlan::ConnectedWorkers(1)
        );
    }

    #[test]
    fn a_leg_on_another_worker_always_relocates_except_under_never() {
        // Seed the group onto worker 3, then decide as worker 0.
        for mode in [Promotion::Relocate, Promotion::Bonded, Promotion::All] {
            assert_eq!(
                decide(mode, Some(affinity(11)), 0, Some(3)),
                PromotionDecision::RelocateTo(3),
                "off-owner leg under {mode:?} must relocate"
            );
        }
    }

    #[test]
    fn a_leg_already_on_its_owner_promotes_only_under_bonded_or_all() {
        // Seed the group onto worker 0 and decide as worker 0.
        for mode in MODES {
            let decision = decide(mode, Some(affinity(12)), 0, Some(0));
            let expected = match mode {
                Promotion::Bonded | Promotion::All => PromotionDecision::PromoteHere,
                _ => PromotionDecision::StayOnListener,
            };
            assert_eq!(decision, expected, "on-owner leg under {mode:?}");
        }
    }

    #[test]
    fn relocation_never_targets_the_deciding_worker() {
        for worker in 0..4 {
            for owner in 0..4 {
                for mode in MODES {
                    if let PromotionDecision::RelocateTo(target) =
                        decide(mode, Some(affinity(20 + owner as u32)), worker, Some(owner))
                    {
                        assert_ne!(
                            target, worker,
                            "relocating to self is a no-op that would drop the connection"
                        );
                    }
                }
            }
        }
    }

    /// The contract the six hand-written copies were each supposed to
    /// uphold and which nothing could check across all of them: the set
    /// of promoted connections only grows as the mode widens.
    #[test]
    fn promotion_sets_nest_monotonically() {
        for group in [None, Some(affinity(31))] {
            for worker in 0..4 {
                for owner in 0..4 {
                    let seed = group.as_ref().map(|_| owner);
                    let promoted: Vec<bool> = MODES
                        .iter()
                        .map(|&m| decide(m, group.clone(), worker, seed).promotes())
                        .collect();
                    for window in promoted.windows(2) {
                        assert!(
                            !window[0] || window[1],
                            "promotion is not monotonic across modes                              (group={group:?}, worker={worker}, owner={owner}): {promoted:?}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod cookie_tests {
    use super::*;

    #[test]
    fn cookie_round_trips_the_owning_worker() {
        for workers in [1usize, 2, 4, 17, 64, 256] {
            for worker in 0..workers {
                let cookie = cookie_for_worker(worker, 0xDEAD_BE00);
                assert_eq!(
                    worker_from_cookie(cookie, workers),
                    Some(worker),
                    "worker {worker} of {workers} did not survive the cookie round trip"
                );
            }
        }
    }

    #[test]
    fn cookie_keeps_peer_entropy_outside_the_index_byte() {
        // Two peers on the same worker must still get distinct cookies,
        // or the cookie stops being per-connection at all.
        let a = cookie_for_worker(3, 0x1111_1100);
        let b = cookie_for_worker(3, 0x2222_2200);
        assert_ne!(a, b);
        assert_eq!(a & 0xFF, 3);
        assert_eq!(b & 0xFF, 3);
    }

    #[test]
    fn cookie_index_beyond_worker_count_is_not_routable() {
        // A cookie this listener never issued (or one from a previous
        // run with more workers) must not route to a nonexistent worker.
        let cookie = cookie_for_worker(9, 0);
        assert_eq!(worker_from_cookie(cookie, 4), None);
    }

    #[test]
    fn cookie_routing_is_declined_for_unsupported_worker_counts() {
        assert_eq!(worker_from_cookie(0, 0), None);
        assert_eq!(worker_from_cookie(0, MAX_COOKIE_WORKERS + 1), None);
        // Exactly at the limit is still fine.
        assert_eq!(
            worker_from_cookie(cookie_for_worker(255, 0), 256),
            Some(255)
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use super::*;
    use shiguredo_srt::handshake::{GroupExtensionData, GroupType, SRTGROUP_MASK};

    #[test]
    fn is_terminal_never_connected_waits_for_connect_window() {
        let now = Instant::now();
        let connect_deadline = now + Duration::from_secs(5);
        assert!(!is_terminal(
            false,
            None,
            now,
            now,
            connect_deadline,
            Duration::from_secs(10)
        ));
        assert!(is_terminal(
            false,
            None,
            now,
            connect_deadline,
            connect_deadline,
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn is_terminal_connected_and_streaming_is_not_terminal() {
        let now = Instant::now();
        let stream_deadline = now + Duration::from_secs(10);
        assert!(!is_terminal(
            true,
            Some(stream_deadline),
            now,
            now,
            now,
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn is_terminal_disconnected_is_terminal_even_before_its_deadline() {
        let now = Instant::now();
        let stream_deadline = now + Duration::from_secs(10);
        assert!(is_terminal(
            false, // live connected flag flipped false
            Some(stream_deadline),
            now,
            now,
            now,
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn is_terminal_past_stream_deadline_is_terminal() {
        let now = Instant::now();
        let stream_deadline = now;
        assert!(is_terminal(
            true,
            Some(stream_deadline),
            now,
            now,
            now,
            Duration::from_secs(10)
        ));
    }

    #[test]
    fn is_terminal_idle_past_grace_is_terminal_even_before_stream_deadline() {
        let now = Instant::now();
        let stream_deadline = now + Duration::from_secs(60);
        let last_data_at = now;
        let idle_grace = Duration::from_secs(10);
        assert!(!is_terminal(
            true,
            Some(stream_deadline),
            last_data_at,
            now + Duration::from_secs(9),
            now,
            idle_grace
        ));
        assert!(is_terminal(
            true,
            Some(stream_deadline),
            last_data_at,
            now + Duration::from_secs(10),
            now,
            idle_grace
        ));
    }

    fn group(stream_id: Option<&str>) -> GroupAffinity {
        GroupAffinity {
            group_id: SRTGROUP_MASK | 0x42,
            stream_id: stream_id.map(str::to_owned),
            extension: GroupExtensionData {
                group_id: SRTGROUP_MASK | 0x42,
                group_type: GroupType::Broadcast,
                flags: 0,
                weight: 7,
            },
        }
    }

    #[test]
    fn group_affinity_survives_member_disconnect_and_reuses_worker() {
        let mut router = WorkerRouter::new(4);
        let first = SocketAddr::from(([127, 0, 0, 1], 20_001));
        let second = SocketAddr::from(([192, 0, 2, 1], 20_002));
        let third = SocketAddr::from(([198, 51, 100, 1], 20_003));
        let affinity = group(Some("publish:camera\0"));

        let first_worker = router.assign(first, Some(affinity.clone()), RoutingMode::RoundRobin);
        let second_worker = router.assign(second, Some(affinity.clone()), RoutingMode::LeastTuples);
        assert_eq!(second_worker, first_worker);
        assert_eq!(router.release(&first), None);

        let third_worker = router.assign(third, Some(affinity.clone()), RoutingMode::RoundRobin);
        assert_eq!(third_worker, second_worker);
        assert_eq!(router.release(&second), None);
        assert_eq!(router.release(&third), Some(affinity.logical_key()));
        assert_eq!(router.active_tuple_count(), 0);
        assert_eq!(router.active_group_count(), 0);
    }

    #[test]
    fn stream_id_is_part_of_logical_group_identity() {
        let mut router = WorkerRouter::new(2);
        let first = SocketAddr::from(([127, 0, 0, 1], 21_001));
        let second = SocketAddr::from(([127, 0, 0, 1], 21_002));
        let first_worker = router.assign(first, Some(group(Some("one"))), RoutingMode::RoundRobin);
        let second_worker =
            router.assign(second, Some(group(Some("two"))), RoutingMode::RoundRobin);
        assert_ne!(first_worker, second_worker);
    }

    #[test]
    fn worker_count_never_reaches_zero_or_exceeds_budget() {
        assert_eq!(worker_count(0, 8), 1);
        assert_eq!(worker_count(2, 8), 2);
        assert_eq!(worker_count(99, 4), 4);
        assert_eq!(worker_count(99, 0), 1);
    }

    #[test]
    fn conclusion_identity_exposes_stream_without_group_metadata() {
        let mut handshake =
            shiguredo_srt::handshake::HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        handshake.add_sid_extension("publish:camera");
        let mut packet = Vec::new();
        handshake
            .encode(0, 0)
            .encode(&mut packet)
            .expect("packet fits configured datagram bound");

        let identity = super::wire::handshake_identity(&packet).expect("handshake identity");
        assert!(identity.is_conclusion);
        assert_eq!(identity.stream_id.as_deref(), Some("publish:camera"));
        assert!(identity.group.is_none());
    }
}

/// `WorkerRouter` invariants, checked against random sequences of
/// assign/release ops rather than fixed scenarios. The property under test
/// throughout is the crate's whole reason to exist: once a logical group
/// has an owner, every physical leg of that group must land on the same
/// worker, no matter the interleaving of assigns and releases across other
/// keys and groups.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use shiguredo_srt::handshake::{GroupExtensionData, GroupType};
    use std::collections::{HashMap, HashSet};

    fn affinity(group_id: u8) -> GroupAffinity {
        GroupAffinity {
            group_id: group_id as u32,
            stream_id: None,
            extension: GroupExtensionData {
                group_id: group_id as u32,
                group_type: GroupType::Broadcast,
                flags: 0,
                weight: 0,
            },
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Assign {
            key: u8,
            group_id: Option<u8>,
            round_robin: bool,
        },
        Release {
            key: u8,
        },
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0u8..6, proptest::option::of(0u8..3), any::<bool>()).prop_map(
                |(key, group_id, round_robin)| Op::Assign {
                    key,
                    group_id,
                    round_robin,
                }
            ),
            (0u8..6).prop_map(|key| Op::Release { key }),
        ]
    }

    proptest! {
        #[test]
        fn worker_router_upholds_invariants(
            ops in proptest::collection::vec(op_strategy(), 1..200),
            worker_count in 1usize..5,
        ) {
            let mut router: WorkerRouter<u8> = WorkerRouter::new(worker_count);
            // Shadow model, checked against the router's own counters at
            // the end and used to compute the expected outcome of each op
            // as we go.
            let mut tuple_worker: HashMap<u8, usize> = HashMap::new();
            let mut tuple_group: HashMap<u8, u8> = HashMap::new();
            let mut group_worker: HashMap<u8, usize> = HashMap::new();
            let mut group_members: HashMap<u8, HashSet<u8>> = HashMap::new();

            for op in ops {
                match op {
                    Op::Assign { key, group_id, round_robin } => {
                        let mode = if round_robin {
                            RoutingMode::RoundRobin
                        } else {
                            RoutingMode::LeastTuples
                        };
                        let worker = router.assign(key, group_id.map(affinity), mode);
                        prop_assert!(worker < worker_count);

                        let is_new_tuple = !tuple_worker.contains_key(&key);
                        if is_new_tuple {
                            // New tuple joining an already-owned group must
                            // land on that group's existing owner, never a
                            // freshly scheduled worker.
                            if let Some(gid) = group_id
                                && let Some(&owner) = group_worker.get(&gid)
                            {
                                prop_assert_eq!(worker, owner);
                            }
                            tuple_worker.insert(key, worker);
                        } else {
                            // An already-owned tuple's worker never moves,
                            // regardless of what group (if any) is passed
                            // on a later assign for the same key.
                            prop_assert_eq!(worker, tuple_worker[&key]);
                        }

                        // First time this key is associated with a group
                        // (mirrors `register_group`'s own idempotency
                        // guard): record it.
                        if let Some(gid) = group_id
                            && !tuple_group.contains_key(&key)
                        {
                            group_worker.entry(gid).or_insert(worker);
                            tuple_group.insert(key, gid);
                            group_members.entry(gid).or_default().insert(key);
                        }
                    }
                    Op::Release { key } => {
                        let existed = tuple_worker.remove(&key).is_some();
                        let released_group = router.release(&key);

                        if !existed {
                            prop_assert_eq!(released_group, None);
                            continue;
                        }
                        match tuple_group.remove(&key) {
                            None => prop_assert_eq!(released_group, None),
                            Some(gid) => {
                                let now_empty = {
                                    let members =
                                        group_members.get_mut(&gid).expect("group was tracked");
                                    members.remove(&key);
                                    members.is_empty()
                                };
                                if now_empty {
                                    group_members.remove(&gid);
                                    group_worker.remove(&gid);
                                    prop_assert!(released_group.is_some());
                                } else {
                                    prop_assert_eq!(released_group, None);
                                }
                            }
                        }
                    }
                }
            }

            prop_assert_eq!(router.active_tuple_count(), tuple_worker.len());
            prop_assert_eq!(router.active_group_count(), group_worker.len());
        }

        #[test]
        fn shared_tuple_never_creates_a_socket(
            mode in prop_oneof![
                Just(Promotion::Never),
                Just(Promotion::Relocate),
                Just(Promotion::Bonded),
                Just(Promotion::All)
            ],
            workers in 1usize..8,
            worker in 0usize..8,
            has_group in any::<bool>(),
            seed_other in any::<bool>(),
            requested in 0usize..16,
        ) {
            let mut router = WorkerRouter::new(workers);
            let group = has_group.then(|| affinity(1));
            if seed_other && has_group {
                router.assign(99u32, group.clone(), RoutingMode::RoundRobin);
            }
            let decision = decide_promotion(
                mode,
                1u32,
                group,
                worker % workers,
                &mut router,
                RoutingMode::LeastTuples,
                false,
            );
            prop_assert!(!decision.promotes());
            prop_assert_eq!(decision, PromotionDecision::StayOnListener);
            prop_assert_eq!(
                plan_reuseport_single(requested, false),
                ReuseportSinglePlan::UnconnectedListener
            );
            prop_assert_eq!(
                plan_reuseport_single(requested, true),
                ReuseportSinglePlan::ConnectedWorkers(requested.max(1))
            );
        }
    }
}
