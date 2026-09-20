//! Owner-level pool semantics: capacity is shared, deadlines are per request,
//! and lifecycle maintenance and protocol TX have independent finite budgets.

use super::*;
use crate::{BondedCallerConfig, CallerConfig, GroupConfig, PoolEvent, PoolOutcome};
use srt_proto::handshake::GroupType;
use std::net::SocketAddr;
use std::time::Duration;

/// An address nothing answers on.
fn dead_peer() -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket.local_addr().expect("addr")
}

fn leg(remote: SocketAddr, deadline: Duration) -> CallerConfig {
    CallerConfig::builder(remote)
        .ownership(crate::SocketOwnership::Shared)
        .connect_deadline(deadline)
        .build()
        .expect("caller config")
}

fn admitted(outcome: PoolOutcome) -> crate::LogicalCallerId {
    match outcome {
        PoolOutcome::Admitted(id) => id,
        other => panic!("expected admission, got {other:?}"),
    }
}

fn pool_events(owner: &mut Owner) -> Vec<PoolEvent> {
    let mut events = Vec::new();
    owner.poll_caller_pool_events(&mut events);
    events
}

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

/// Owner-wide capacity does not rewrite a request's deadline: with capacity 4
/// and a 30 ms request, the attempt expires at 30 ms -- not at any Owner
/// default -- and a second request with a longer deadline keeps its own.
#[test]
fn owner_capacity_never_rewrites_a_request_deadline() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        owner
            .set_caller_pool_capacity(std::num::NonZeroUsize::new(4).unwrap())
            .expect("capacity");
        let short = admitted(
            owner
                .connect(&leg(dead_peer(), Duration::from_millis(30)), ts(0))
                .expect("short"),
        );
        let long = admitted(
            owner
                .connect(&leg(dead_peer(), Duration::from_secs(5)), ts(0))
                .expect("a different deadline is a compatible shared caller"),
        );
        let _ = owner
            .service(ts(29_000), OwnerServiceBudget::default())
            .await;
        assert!(owner.logical_caller(&short).is_some(), "not yet due");
        let _ = owner
            .service(ts(31_000), OwnerServiceBudget::default())
            .await;
        assert!(owner.logical_caller(&short).is_none(), "expired at 30 ms");
        assert!(
            owner.logical_caller(&long).is_some(),
            "the 5 s request lives"
        );
        assert!(pool_events(&mut owner).iter().any(
            |event| matches!(event, PoolEvent::Expired { caller_id, .. } if *caller_id == short)
        ));
    });
}

/// Capacity is the one thing shared callers must agree on.
#[test]
fn shared_callers_may_differ_in_deadline_but_not_in_capacity() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let a = leg(dead_peer(), Duration::from_secs(1));
        admitted(owner.connect(&a, ts(0)).expect("first fixes the capacity"));
        let mut other = leg(dead_peer(), Duration::from_secs(1));
        other.connect.max_in_flight = std::num::NonZeroUsize::new(7).unwrap();
        assert!(
            owner.connect(&other, ts(0)).is_err(),
            "a different pool capacity is a different pool"
        );
    });
}

/// A bonded request whose legs disagree on the attempt deadline is refused
/// outright: no side, no session, nothing frozen.
#[test]
fn bonded_legs_with_different_deadlines_are_refused_transactionally() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        let config = BondedCallerConfig::new(GroupConfig::new(11, GroupType::Broadcast))
            .leg(leg(dead_peer(), Duration::from_secs(1)), 1)
            .leg(leg(dead_peer(), Duration::from_secs(2)), 1);
        assert!(owner.connect_bonded(&config, ts(0)).is_err());
        assert!(owner.caller().is_none(), "no caller side was created");
        assert!(owner.caller_pool_stats().is_none());
        // The owner is untouched: a valid request still attaches.
        let ok = BondedCallerConfig::new(GroupConfig::new(12, GroupType::Broadcast))
            .leg(leg(dead_peer(), Duration::from_secs(1)), 1)
            .leg(leg(dead_peer(), Duration::from_secs(1)), 1);
        admitted(owner.connect_bonded(&ok, ts(0)).expect("valid bond"));
    });
}

/// STARVATION REGRESSION. Many admitted attempts with deadlines far in the
/// future, a small FIXED budget, and no park between visits: maintenance must
/// not consume the action allowance merely by looking at future attempts, so
/// protocol TX makes progress and the handshakes leave.
#[test]
fn future_attempts_do_not_starve_handshake_tx_under_a_tiny_fixed_budget() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        const ATTEMPTS: usize = 64;
        let mut owner = Owner::new(16);
        owner
            .set_caller_pool_capacity(std::num::NonZeroUsize::new(ATTEMPTS).unwrap())
            .expect("capacity");
        for _ in 0..ATTEMPTS {
            admitted(
                owner
                    .connect(&leg(dead_peer(), Duration::from_secs(60)), ts(0))
                    .expect("admit"),
            );
        }
        // Small and independent of the fan-out: 4 output actions, 1 maintenance.
        let budget = OwnerServiceBudget {
            max_actions: 4,
            max_maintenance_actions: 1,
            ..OwnerServiceBudget::default()
        };
        let mut submitted = 0;
        for visit in 0..40 {
            let report = owner.service(ts(1_000 + visit * 10), budget).await;
            submitted += report.tx_packets_submitted;
            assert!(report.actions <= 4, "TX actions are bounded: {report:?}");
            assert_eq!(report.maintenance_actions, 0, "no due, no resolved: free");
        }
        assert!(
            submitted >= 16,
            "handshake TX made progress under a 4-action budget: {submitted}"
        );
    });
}

/// TINY BUDGETS ON BOTH AXES. Maintenance = 1 and TX = 1 with an expiry, a
/// queued admission and handshake output all pending: each visit does at most
/// one of each, and over a bounded run every phase progresses.
#[test]
fn tiny_budgets_let_maintenance_and_tx_both_make_progress() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(16);
        owner
            .set_caller_pool_capacity(std::num::NonZeroUsize::new(2).unwrap())
            .expect("capacity");
        // Two attempts due at 20 ms; two queued behind them.
        for _ in 0..2 {
            admitted(
                owner
                    .connect(&leg(dead_peer(), Duration::from_millis(20)), ts(0))
                    .expect("admit"),
            );
        }
        for _ in 0..2 {
            assert!(matches!(
                owner
                    .connect(&leg(dead_peer(), Duration::from_secs(60)), ts(0))
                    .expect("queue"),
                PoolOutcome::Queued(_)
            ));
        }
        let budget = OwnerServiceBudget {
            max_actions: 1,
            max_maintenance_actions: 1,
            ..OwnerServiceBudget::default()
        };
        let (mut tx, mut maintenance) = (0, 0);
        for visit in 0..40 {
            let report = owner.service(ts(30_000 + visit * 10), budget).await;
            assert!(report.actions <= 1 && report.maintenance_actions <= 1);
            tx += report.tx_packets_submitted;
            maintenance += report.maintenance_actions;
        }
        let stats = owner.caller_pool_stats().expect("pool");
        assert_eq!(stats.expired, 2, "both due attempts were retired");
        assert_eq!((stats.in_flight, stats.queued), (2, 0), "queue admitted");
        assert_eq!(maintenance, 4, "2 expiries + 2 admissions, one per visit");
        assert!(tx > 0, "handshake TX progressed alongside maintenance");
    });
}

/// `work_remaining` is truthful about pool work: true while a queued request
/// has a free permit, false once it has been admitted -- and never true merely
/// because TX is in flight.
#[test]
fn pending_work_includes_runnable_pool_work() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let mut owner = Owner::new(8);
        owner
            .set_caller_pool_capacity(std::num::NonZeroUsize::new(1).unwrap())
            .expect("capacity");
        let first = admitted(
            owner
                .connect(&leg(dead_peer(), Duration::from_secs(60)), ts(0))
                .expect("first"),
        );
        assert!(matches!(
            owner
                .connect(&leg(dead_peer(), Duration::from_secs(60)), ts(0))
                .expect("queued"),
            PoolOutcome::Queued(_)
        ));
        // Drain the initial handshake output so only pool work could remain.
        for visit in 0..8 {
            let _ = owner
                .service(ts(1_000 + visit * 10), OwnerServiceBudget::default())
                .await;
        }
        assert!(
            !owner.has_pending_work(ts(2_000)),
            "queued request with NO free permit is not runnable"
        );
        drop(owner.remove_caller(first).expect("remove"));
        assert!(
            owner.has_pending_work(ts(2_000)),
            "a queued request with a free permit is runnable pool work"
        );
        let report = owner
            .service(ts(2_010), OwnerServiceBudget::default())
            .await;
        assert_eq!(report.maintenance_actions, 1, "the admission");
    });
}

// ---------------------------------------------------------------------------
// Fair maintenance: caller-pool and listener idle reclaim share one finite
// `max_maintenance_actions` allowance with alternating priority.
// ---------------------------------------------------------------------------

const IDLE_TIMEOUT: Duration = Duration::from_millis(200);

/// An Owner with a listener whose idle timeout is short, plus `peers`
/// established sessions (the Owner's own callers connected to its own
/// listener) that are then abandoned without a shutdown, leaving `peers`
/// listener-side peers that only go idle. Returns the owner and the synthetic
/// time of the last datagram.
async fn owner_with_idle_peers(peers: usize) -> (Owner, u64) {
    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    let addr = std_sock.local_addr().expect("listener addr");
    let sock = compio::net::UdpSocket::from_std(std_sock).expect("adopt listener");
    let config = crate::ListenerConfig::builder(addr)
        .configure_admission(|admission| admission.idle_timeout = IDLE_TIMEOUT)
        .build()
        .expect("listener config");
    let side = ListenerSide::new(sock, &config).expect("listener side");
    let mut owner = Owner::new(16).with_listener(side);
    owner
        .set_caller_pool_capacity(std::num::NonZeroUsize::new(8).unwrap())
        .expect("capacity");
    let ids: Vec<_> = (0..peers)
        .map(|_| {
            admitted(
                owner
                    .connect(&leg(addr, Duration::from_secs(60)), ts(0))
                    .expect("connect to the own listener"),
            )
        })
        .collect();
    let mut now = 0;
    for round in 0..600_u64 {
        now = round * 5_000;
        let _ = owner.service(ts(now), OwnerServiceBudget::default()).await;
        owner.wait_for_activity(Duration::from_millis(1)).await;
        let connected = ids.iter().all(|id| {
            owner.logical_caller(id).and_then(|c| c.state())
                == Some(crate::LogicalCallerState::Connected)
        });
        if connected && owner.listener().expect("listener").table.len() >= peers {
            break;
        }
    }
    for id in ids {
        drop(owner.remove_caller(id).expect("abandon the caller"));
    }
    assert!(
        owner.listener().expect("listener").table.len() >= peers,
        "the listener holds {peers} established peers"
    );
    (owner, now)
}

fn idle_due(owner: &Owner, at: u64) -> bool {
    let listener = owner.listener().expect("listener");
    listener.table.has_idle_due(ts(at), IDLE_TIMEOUT)
}

/// Caller-pool maintenance that stays runnable across many visits: `n`
/// admitted attempts that are due at `at`, plus `n` queued behind them.
fn queue_caller_work(owner: &mut Owner, n: usize, admitted_at: u64) {
    for _ in 0..n {
        admitted(
            owner
                .connect(
                    &leg(dead_peer(), Duration::from_millis(10)),
                    ts(admitted_at),
                )
                .expect("admit"),
        );
    }
    for _ in 0..n {
        assert!(matches!(
            owner
                .connect(&leg(dead_peer(), Duration::from_secs(60)), ts(admitted_at))
                .expect("queue"),
            PoolOutcome::Queued(_)
        ));
    }
}

/// With ONE maintenance action per visit, continuously runnable caller
/// maintenance must not postpone a due listener idle peer (and vice versa).
#[test]
fn maintenance_alternates_between_caller_and_listener() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let (mut owner, last) = owner_with_idle_peers(1).await;
        let start = last + 1_000_000; // far past the 200 ms idle timeout
        queue_caller_work(&mut owner, 8, last);
        assert!(idle_due(&owner, start), "the idle peer is due");
        let budget = OwnerServiceBudget {
            max_maintenance_actions: 1,
            ..OwnerServiceBudget::default()
        };
        let mut listener_visit = None;
        let mut caller_actions_before_listener = 0;
        for visit in 0..40_u64 {
            let queued = owner.caller_pool_stats().expect("pool").queued;
            let report = owner.service(ts(start + visit * 100), budget).await;
            assert!(report.maintenance_actions <= 1, "{report:?}");
            if listener_visit.is_none() && !idle_due(&owner, start + visit * 100) {
                listener_visit = Some(visit);
                assert!(queued > 0, "the caller still had queued work");
            }
            if listener_visit.is_none() {
                caller_actions_before_listener += report.maintenance_actions;
            }
        }
        let visit = listener_visit.expect("the idle peer was reclaimed");
        assert!(
            visit <= 2,
            "reclaimed within alternation, not after the caller: {visit}"
        );
        assert!(
            caller_actions_before_listener >= 1 || visit == 0,
            "the caller progressed on the visits the listener did not take"
        );
        let stats = owner.caller_pool_stats().expect("pool");
        assert!(
            stats.expired >= 1 && stats.started > 8,
            "caller work progressed too"
        );
    });
}

/// No reserved split: an uncontended side may use the whole allowance.
#[test]
fn an_uncontended_side_uses_the_full_maintenance_budget() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        // Only caller maintenance runnable.
        let mut owner = Owner::new(16);
        owner
            .set_caller_pool_capacity(std::num::NonZeroUsize::new(8).unwrap())
            .expect("capacity");
        queue_caller_work(&mut owner, 8, 0);
        let budget = OwnerServiceBudget {
            max_maintenance_actions: 4,
            ..OwnerServiceBudget::default()
        };
        let report = owner.service(ts(1_000_000), budget).await;
        assert_eq!(report.maintenance_actions, 4, "caller used all four");

        // Only listener maintenance runnable.
        let (mut owner, last) = owner_with_idle_peers(3).await;
        let start = last + 1_000_000;
        let wide = OwnerServiceBudget {
            max_maintenance_actions: 8,
            ..OwnerServiceBudget::default()
        };
        let report = owner.service(ts(start), wide).await;
        assert!(
            (3..=8).contains(&report.maintenance_actions),
            "the listener alone used the allowance it needed: {report:?}"
        );
        assert!(!idle_due(&owner, start), "all three idle peers reclaimed");
        // With a budget of exactly 3 it may spend all of it: nothing is
        // reserved for the idle caller side.
        let (mut owner, last) = owner_with_idle_peers(3).await;
        let three = OwnerServiceBudget {
            max_maintenance_actions: 3,
            ..OwnerServiceBudget::default()
        };
        let report = owner.service(ts(last + 1_000_000), three).await;
        assert_eq!(report.maintenance_actions, 3, "no reserved caller share");
    });
}
