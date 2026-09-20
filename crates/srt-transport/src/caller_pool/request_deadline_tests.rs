//! Per-request attempt deadlines and exact, bounded pool maintenance.

use super::*;
use crate::{CallerConfig, RuntimeFlavor};
use std::net::SocketAddr;

fn remote(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn request(port: u16, deadline: Duration) -> PreparedCaller {
    request_with_handshake(port, deadline, Duration::from_secs(30))
}

/// A request whose protocol handshake gives up after `handshake` while the
/// pool's attempt deadline is `deadline`: the handshake timer firing is what
/// resolves it (to Disconnected) before its attempt deadline.
fn request_with_handshake(port: u16, deadline: Duration, handshake: Duration) -> PreparedCaller {
    CallerConfig::builder(remote(port))
        .ownership(crate::SocketOwnership::Shared)
        .connect_deadline(deadline)
        .configure_session(|session| {
            session.handshake.retry_interval = handshake.min(session.handshake.retry_interval);
            session.handshake.timeout = handshake;
        })
        .build()
        .expect("caller config")
        .prepare(RuntimeFlavor::Compio)
        .expect("prepared caller")
}

fn group_request(group: u32, ports: &[u16], deadline: Duration) -> PreparedBondedCaller {
    let mut config = crate::BondedCallerConfig::new(crate::GroupConfig::new(
        group,
        srt_proto::handshake::GroupType::Broadcast,
    ));
    for port in ports {
        let leg = CallerConfig::builder(remote(*port))
            .ownership(crate::SocketOwnership::Shared)
            .connect_deadline(deadline)
            .build()
            .expect("leg config");
        config = config.leg(leg, 1);
    }
    config
        .prepare(RuntimeFlavor::Compio)
        .expect("prepared group")
}

fn ms(millis: u64) -> Timestamp {
    Timestamp::from_micros(millis * 1_000)
}

fn admitted(outcome: PoolOutcome) -> LogicalCallerId {
    match outcome {
        PoolOutcome::Admitted(id) => id,
        other => panic!("expected admission, got {other:?}"),
    }
}

/// Fire due protocol timers (what a service visit's output drain does).
fn fire_timers(pool: &mut CallerPool, at: Timestamp) {
    let mut out = Vec::new();
    // The first drain arms each caller's protocol timers (relative to `at`);
    // a second, later drain fires the ones that have run out.
    pool.poll_outbound(at, &mut out);
    pool.poll_outbound(Timestamp::from_micros(at.as_micros() + 100_000), &mut out);
}

fn expired(pool: &mut CallerPool, at: Timestamp) -> Vec<LogicalCallerId> {
    let mut retired = Vec::new();
    pool.maintain(at, usize::MAX >> 1, Some(&mut retired));
    retired
}

/// A. Different request deadlines share one pool: each expires on its own.
#[test]
fn requests_in_one_pool_expire_at_their_own_deadlines() {
    let mut pool = CallerPool::new(NonZeroUsize::new(4).unwrap());
    let a = admitted(
        pool.connect(request(1, Duration::from_millis(100)), ms(0))
            .unwrap(),
    );
    let b = admitted(
        pool.connect(request(2, Duration::from_secs(1)), ms(0))
            .unwrap(),
    );
    assert_eq!(expired(&mut pool, ms(200)), vec![a]);
    assert!(pool.logical_caller(&b).is_some(), "B is still establishing");
    assert_eq!(pool.stats().in_flight, 1);
    assert_eq!(expired(&mut pool, ms(1_000)), vec![b]);
}

/// B. The clock of a queued request starts at ADMISSION, with its own
/// duration: queue wait never counts.
#[test]
fn a_queued_request_gets_a_fresh_window_of_its_own_length() {
    let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap());
    let a = admitted(
        pool.connect(request(1, Duration::from_millis(500)), ms(0))
            .unwrap(),
    );
    let PoolOutcome::Queued(_) = pool
        .connect(request(2, Duration::from_millis(50)), ms(0))
        .unwrap()
    else {
        panic!("B queues behind A");
    };
    // B waits 200 ms (4x its own deadline) without expiring: it has no clock.
    assert!(expired(&mut pool, ms(200)).is_empty());
    assert_eq!(pool.stats().queued, 1);
    assert!(pool.remove(a).is_some());
    let mut retired = Vec::new();
    let work = pool.maintain(ms(200), 8, Some(&mut retired));
    assert_eq!(work.admitted, 1, "B is admitted at t=200ms");
    assert!(retired.is_empty());
    assert!(expired(&mut pool, ms(249)).is_empty(), "fresh 50 ms window");
    assert_eq!(expired(&mut pool, ms(251)).len(), 1, "expires at 250 ms");
}

/// The parking example: the earliest ADMITTED deadline decides; a queued
/// request has none until it is admitted.
#[test]
fn next_deadline_reflects_request_specific_admitted_deadlines() {
    let mut pool = CallerPool::new(NonZeroUsize::new(2).unwrap());
    let _a = admitted(
        pool.connect(request(1, Duration::from_millis(100)), ms(0))
            .unwrap(),
    );
    let _b = admitted(
        pool.connect(request(2, Duration::from_secs(5)), ms(0))
            .unwrap(),
    );
    assert!(matches!(
        pool.connect(request(3, Duration::from_millis(50)), ms(0))
            .unwrap(),
        PoolOutcome::Queued(_)
    ));
    let big = 10_000_000;
    // The pool's own deadline is the earliest admitted one (100 ms). The
    // table's protocol timers only ever fire sooner, never later.
    let park = pool.time_until_next_deadline(ms(0), big);
    assert!(park <= 100_000, "parks no later than A's deadline ({park})");
    assert_eq!(pool.earliest_deadline_micros, Some(100_000));
    // A expires at 200 ms; C (queued, 50 ms) is admitted THEN and expires at
    // 250 ms, not at 50 ms.
    let mut retired = Vec::new();
    let work = pool.maintain(ms(200), 8, Some(&mut retired));
    assert_eq!((work.expired, work.admitted), (1, 1));
    assert_eq!(pool.earliest_deadline_micros, Some(250_000));
    assert_eq!(pool.stats().queued, 0);
}

/// D/E. A bonded logical caller has ONE deadline, running from admission.
#[test]
fn a_bonded_request_expires_once_and_its_clock_starts_at_admission() {
    let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap());
    let first = admitted(
        pool.connect(request(1, Duration::from_secs(60)), ms(0))
            .unwrap(),
    );
    assert!(matches!(
        pool.connect_group(
            group_request(9, &[11, 12], Duration::from_millis(250)),
            ms(0)
        )
        .unwrap(),
        PoolOutcome::Queued(_)
    ));
    assert!(pool.remove(first).is_some());
    let mut retired = Vec::new();
    assert_eq!(pool.maintain(ms(1_000), 8, Some(&mut retired)).admitted, 1);
    assert!(
        expired(&mut pool, ms(1_249)).is_empty(),
        "queue wait is free"
    );
    let gone = expired(&mut pool, ms(1_251));
    assert_eq!(gone.len(), 1, "the whole group retires as one request");
    assert_eq!(pool.table().len(), 0);
}

/// F. Legs that disagree on the deadline are refused, transactionally.
#[test]
fn bonded_legs_with_different_deadlines_are_refused_without_state() {
    // Preparation refuses the configuration outright...
    let mut config = crate::BondedCallerConfig::new(crate::GroupConfig::new(
        7,
        srt_proto::handshake::GroupType::Broadcast,
    ));
    for (port, deadline) in [(1_u16, Duration::from_secs(1)), (2, Duration::from_secs(2))] {
        config = config.leg(
            CallerConfig::builder(remote(port))
                .ownership(crate::SocketOwnership::Shared)
                .connect_deadline(deadline)
                .build()
                .expect("leg"),
            1,
        );
    }
    assert!(config.prepare(RuntimeFlavor::Compio).is_err());

    // ...and a hand-built prepared request is refused by the pool before
    // anything is queued or admitted.
    let mut prepared = group_request(8, &[21, 22], Duration::from_secs(1));
    prepared.legs[1].caller.connect.attempt_deadline = Duration::from_secs(2);
    let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap());
    assert!(pool.connect_group(prepared, ms(0)).is_err());
    let stats = pool.stats();
    assert_eq!((stats.in_flight, stats.queued, stats.started), (0, 0, 0));
    assert_eq!(pool.table().len(), 0);
}

/// An attempt that stops establishing frees its permit at the next pass, not
/// at its original deadline, so a queued request is admitted promptly.
#[test]
fn a_resolved_attempt_frees_its_permit_promptly() {
    let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap());
    let _a = admitted(
        pool.connect(
            request_with_handshake(1, Duration::from_secs(60), Duration::from_millis(5)),
            ms(0),
        )
        .unwrap(),
    );
    assert!(matches!(
        pool.connect(request(2, Duration::from_secs(60)), ms(0))
            .unwrap(),
        PoolOutcome::Queued(_)
    ));
    assert!(
        !pool.has_pending_work(ms(1)),
        "nothing resolved, nothing due"
    );
    // A's protocol handshake timer fires long before its 60 s attempt deadline.
    fire_timers(&mut pool, ms(10));
    assert!(
        pool.has_pending_work(ms(10)),
        "the resolution is pending work"
    );
    let work = pool.maintain(ms(10), 8, None);
    assert_eq!((work.resolved, work.admitted), (1, 1), "{work:?}");
    assert_eq!(pool.stats().in_flight, 1, "B took the freed permit");
    assert!(!pool.has_pending_work(ms(10)));
}

/// High fan-out: future, unresolved attempts are not maintenance work.
#[test]
fn future_attempts_cost_nothing_and_work_is_proportional_to_the_subset() {
    const N: usize = 1024;
    let mut pool = CallerPool::new(NonZeroUsize::new(N).unwrap());
    let mut ids = Vec::new();
    for index in 0..N {
        let port = 20_000 + u16::try_from(index).unwrap();
        ids.push(admitted(
            pool.connect(request(port, Duration::from_secs(30)), ms(0))
                .unwrap(),
        ));
    }
    let before = pool.table().status_probes();
    let work = pool.maintain(ms(10), 16, None);
    assert_eq!(
        work,
        PoolMaintenance::default(),
        "no due, no resolved: zero work"
    );
    assert_eq!(
        pool.table().status_probes(),
        before,
        "not one of {N} attempts was even inspected"
    );
    assert!(!pool.has_pending_work(ms(10)));

    // Resolve 8 by protocol timeout among 1024 long ones: work is exactly
    // those 8, and not one attempt is probed for status.
    let mut pool = CallerPool::new(NonZeroUsize::new(N).unwrap());
    for index in 0..N {
        let handshake = if index < 8 {
            Duration::from_millis(5)
        } else {
            Duration::from_secs(30)
        };
        let port = 20_000 + u16::try_from(index).unwrap();
        admitted(
            pool.connect(
                request_with_handshake(port, Duration::from_secs(30), handshake),
                ms(0),
            )
            .unwrap(),
        );
    }
    fire_timers(&mut pool, ms(20));
    let before = pool.table().status_probes();
    let work = pool.maintain(ms(20), 4096, None);
    assert_eq!(work.resolved, 8, "{work:?}");
    assert_eq!(pool.table().status_probes(), before, "resolution is exact");

    // Due subset: 8 more short requests among the long ones. Only the due 8
    // are examined -- one probe each -- not the whole population.
    let mut pool = CallerPool::new(NonZeroUsize::new(N).unwrap());
    for index in 0..N {
        let deadline = if index < 8 {
            Duration::from_millis(10)
        } else {
            Duration::from_secs(30)
        };
        let port = 20_000 + u16::try_from(index).unwrap();
        admitted(pool.connect(request(port, deadline), ms(0)).unwrap());
    }
    let before = pool.table().status_probes();
    let work = pool.maintain(ms(50), 4096, None);
    assert_eq!(work.expired, 8);
    assert_eq!(
        pool.table().status_probes() - before,
        8,
        "probes are proportional to the due subset, not to {N}"
    );
}

/// The maintenance budget is a hard bound and each unit is real work.
#[test]
fn a_tiny_maintenance_budget_progresses_every_phase_across_passes() {
    let mut pool = CallerPool::with_queue_capacity(NonZeroUsize::new(2).unwrap(), 8);
    // A is due at 10 ms; B resolves by handshake timeout at 5 ms; three wait.
    let _a = admitted(
        pool.connect(request(1, Duration::from_millis(10)), ms(0))
            .unwrap(),
    );
    let _b = admitted(
        pool.connect(
            request_with_handshake(2, Duration::from_secs(60), Duration::from_millis(5)),
            ms(0),
        )
        .unwrap(),
    );
    for port in [3, 4, 5] {
        assert!(matches!(
            pool.connect(request(port, Duration::from_secs(60)), ms(0))
                .unwrap(),
            PoolOutcome::Queued(_)
        ));
    }
    fire_timers(&mut pool, ms(20));
    let (mut resolved, mut expired_count, mut admitted_count) = (0, 0, 0);
    let mut passes = 0;
    while pool.has_pending_work(ms(20)) {
        let work = pool.maintain(ms(20), 1, None);
        assert_eq!(work.actions(), 1, "budget of one is a hard bound: {work:?}");
        resolved += work.resolved;
        expired_count += work.expired;
        admitted_count += work.admitted;
        passes += 1;
        assert!(passes < 16, "maintenance must converge");
    }
    assert_eq!(
        (resolved, expired_count, admitted_count),
        (1, 1, 2),
        "resolved cleanup, due expiry and queued admission all progressed"
    );
    assert!(passes >= 4, "one action per pass: {passes}");
    let stats = pool.stats();
    assert_eq!((stats.in_flight, stats.queued), (2, 1));
}

/// Churn: resolve/retire without draining never grows the index, and a stale
/// id can never resolve a later caller.
#[test]
fn resolution_index_is_bounded_and_reclaimed_under_churn() {
    let mut pool = CallerPool::new(NonZeroUsize::new(4).unwrap());
    for round in 0..200_u16 {
        let id = admitted(
            pool.connect(
                request_with_handshake(
                    30_000 + round,
                    Duration::from_secs(60),
                    Duration::from_millis(5),
                ),
                ms(0),
            )
            .unwrap(),
        );
        fire_timers(&mut pool, ms(10));
        assert_eq!(pool.table().resolved_attempts_pending(), 1, "round {round}");
        // Retire it WITHOUT running maintenance: the signal must go with it.
        assert!(pool.remove(id).is_some());
        assert_eq!(
            pool.table().resolved_attempts_pending(),
            0,
            "round {round}: removal reclaims the unconsumed signal"
        );
        // A new caller never inherits the old id's resolution.
        let fresh = admitted(
            pool.connect(request(40_000 + round, Duration::from_secs(60)), ms(1))
                .unwrap(),
        );
        assert_eq!(pool.table().resolved_attempts_pending(), 0);
        assert_eq!(pool.maintain(ms(1), 8, None), PoolMaintenance::default());
        assert!(pool.remove(fresh).is_some());
    }
    assert!(pool.table().is_empty());
    assert_eq!(pool.stats().in_flight, 0);
}
