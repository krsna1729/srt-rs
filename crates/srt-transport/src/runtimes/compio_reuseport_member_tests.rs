//! Owner-level tests for multi-Owner listeners: `owner_plans` splits the
//! configured topology into one plan per Owner, `Owner::listen_planned`
//! attaches each, and SYN-cookie routing forwards CONCLUSIONs the kernel
//! delivers to the wrong reuseport member.

use super::*;
use crate::caller::LogicalCallerState;
use crate::{CallerConfig, PoolOutcome};
use std::net::SocketAddr;

fn owner_plans(
    config: &crate::ListenerConfig,
) -> Result<Vec<crate::OwnerListenerPlan>, crate::RuntimeBuildError> {
    crate::owner_plans(config, crate::RuntimeFlavor::Compio)
}
use std::time::Duration;

fn free_port() -> u16 {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe");
    probe.local_addr().expect("probe addr").port()
}

fn config(
    port: u16,
    topology: crate::ListenerTopology,
    promotion: crate::PromotionPolicy,
) -> crate::ListenerConfig {
    crate::ListenerConfig::builder(SocketAddr::from(([127, 0, 0, 1], port)))
        .topology(topology)
        .configure_transport(|transport| transport.promotion = promotion)
        .build()
        .expect("listener config")
}

fn count(n: usize) -> crate::WorkerCount {
    crate::WorkerCount::Count(std::num::NonZeroUsize::new(n).expect("count"))
}

fn reuseport(port: u16, members: usize) -> crate::ListenerConfig {
    config(
        port,
        crate::ListenerTopology::ReusePortMulti {
            acceptors: count(members),
        },
        crate::PromotionPolicy::Never,
    )
}

fn attach(plan: &OwnerListenerPlan) -> Owner {
    let mut owner = Owner::new(64);
    owner.listen_planned(plan, None).expect("listen_planned");
    owner
}

fn caller(remote: SocketAddr) -> (Owner, crate::LogicalCallerId) {
    let mut config = CallerConfig::builder(remote)
        .ownership(crate::SocketOwnership::Shared)
        .build()
        .expect("caller config");
    // No handshake retry inside the test: a stranded CONCLUSION can only be
    // rescued by forwarding, never by a fresh INDUCTION.
    config.session.handshake.retry_interval = Duration::from_secs(60);
    config.session.handshake.timeout = Duration::from_secs(120);
    let mut owner = Owner::new(64);
    match owner
        .connect(&config, Timestamp::from_micros(0))
        .expect("connect")
    {
        PoolOutcome::Admitted(id) => (owner, id),
        other => panic!("expected admission, got {other:?}"),
    }
}

fn connected(callers: &[(Owner, crate::LogicalCallerId)]) -> usize {
    callers
        .iter()
        .filter(|(owner, id)| {
            owner.logical_caller(id).and_then(|c| c.state()) == Some(LogicalCallerState::Connected)
        })
        .count()
}

/// Service every Owner, then route forwarded CONCLUSIONs between members the
/// way an application's inter-thread bridge would.
async fn pump_round(
    members: &mut [Owner],
    callers: &mut [(Owner, crate::LogicalCallerId)],
    now: u64,
    forwarded: &mut usize,
) {
    let budget = OwnerServiceBudget::default();
    let at = Timestamp::from_micros(now);
    for owner in members.iter_mut() {
        let _ = owner.service(at, budget).await;
    }
    for (owner, _) in callers.iter_mut() {
        let _ = owner.service(at, budget).await;
    }
    let mut forwards = Vec::new();
    for owner in members.iter_mut() {
        owner.poll_listener_forwards(&mut forwards);
    }
    *forwarded += forwards.len();
    for handshake in forwards {
        members[handshake.to].inject_listener_handshake(handshake.peer, &handshake.data, at);
    }
    for owner in members.iter_mut() {
        owner.wait_for_activity(Duration::from_micros(200)).await;
    }
}

/// Callers send INDUCTION to a one-member group; binding the second member
/// rehashes the port, so some CONCLUSIONs land on a member holding no state.
/// Cookie routing forwards them, and every caller still connects.
#[test]
fn conclusions_rehashed_to_another_member_are_forwarded_and_connect() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let port = free_port();
        let remote = SocketAddr::from(([127, 0, 0, 1], port));
        let plans = owner_plans(&reuseport(port, 2)).expect("plans");
        assert_eq!(plans.len(), 2);

        let mut members = vec![attach(&plans[0])];
        let mut callers: Vec<_> = (0..16).map(|_| caller(remote)).collect();
        let mut forwarded = 0;
        let mut now = 1_000;
        // INDUCTION and its response only, so member 0 issues every cookie
        // and no CONCLUSION is sent before member 1 joins: callers send their
        // INDUCTION once, then only member 0 runs until it has replied.
        let budget = OwnerServiceBudget::default();
        for (owner, _) in callers.iter_mut() {
            let _ = owner.service(Timestamp::from_micros(now), budget).await;
        }
        for _ in 0..20 {
            members[0]
                .wait_for_activity(Duration::from_micros(500))
                .await;
            let _ = members[0]
                .service(Timestamp::from_micros(now), budget)
                .await;
        }
        now += 5_000;
        members.push(attach(&plans[1]));

        for _ in 0..400 {
            pump_round(&mut members, &mut callers, now, &mut forwarded).await;
            now += 5_000;
            if connected(&callers) == callers.len() {
                break;
            }
        }
        assert_eq!(connected(&callers), callers.len(), "every caller connects");
        assert!(
            forwarded > 0,
            "the rehash sent some CONCLUSIONs to member 1"
        );
        assert_eq!(members[1].listener_forwards_dropped(), 0);
    });
}

#[test]
fn shared_pool_owners_each_serve_their_own_port() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let base = free_port();
        let plans = owner_plans(&config(
            base,
            crate::ListenerTopology::SharedPool {
                listeners: count(2),
            },
            crate::PromotionPolicy::Never,
        ))
        .expect("shared-pool plans");
        let mut owners: Vec<_> = plans.iter().map(attach).collect();
        let mut callers: Vec<_> = plans.iter().map(|plan| caller(plan.bind())).collect();
        let mut forwarded = 0;
        let mut now = 1_000;
        for _ in 0..400 {
            pump_round(&mut owners, &mut callers, now, &mut forwarded).await;
            now += 5_000;
            if connected(&callers) == callers.len() {
                break;
            }
        }
        assert_eq!(connected(&callers), 2);
        assert_eq!(
            forwarded, 0,
            "a shared pool has no reuseport group to rehash"
        );
    });
}

#[test]
fn plain_listen_stays_per_port_only() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        assert!(Owner::new(8).listen(&reuseport(free_port(), 2)).is_err());
    });
}
