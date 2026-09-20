//! Owner-level tests for the resolved listener admission policy
//! (`Owner::listen_with_resolver`): per-StreamID crypto/latency/authorization,
//! Reject, bounded Defer, resolver-invocation bounds, and the listener-owned
//! receiving-group identity. Every case drives real UDP sockets through Owner
//! RX with synthetic timestamps; nothing calls `PeerTable` directly except the
//! bounded-TTL prune, which mirrors the existing caller-table Defer test.

use super::*;
use crate::caller::LogicalCallerState;
use crate::{
    AdmissionResolution, BondedCallerConfig, CallerConfig, GroupConfig, ListenerAdmissionResolver,
    ListenerEncryptionConfig, ListenerPeerPolicy, PolicyOverride, PoolOutcome, RejectionReason,
};
use srt_proto::handshake::GroupType;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const PASS_A: &str = "passphrase-for-stream-a";
const PASS_B: &str = "passphrase-for-stream-b";

fn stream_id_of(request: &crate::AdmissionRequest) -> String {
    request
        .claimed_identity
        .stream_id
        .clone()
        .unwrap_or_default()
}

fn policy(latency_ms: u64, pass: &str, key: srt_proto::crypto::KeyLength) -> ListenerPeerPolicy {
    ListenerPeerPolicy {
        latency: PolicyOverride::Set(Duration::from_millis(latency_ms)),
        encryption: PolicyOverride::Set(Some(
            ListenerEncryptionConfig::new(pass, key).expect("passphrase"),
        )),
        ..ListenerPeerPolicy::default()
    }
}

fn group_policy(group_id: u32, mode: GroupType) -> ListenerPeerPolicy {
    ListenerPeerPolicy {
        group: PolicyOverride::Set(Some(GroupConfig::new(group_id, mode))),
        ..ListenerPeerPolicy::default()
    }
}

fn listener_owner(resolver: ListenerAdmissionResolver, bonded: bool) -> (Owner, SocketAddr) {
    let mut builder = crate::ListenerConfig::builder("127.0.0.1:0".parse().unwrap())
        .topology(crate::ListenerTopology::PerPort)
        .configure_transport(|transport| transport.promotion = crate::PromotionPolicy::Never);
    if bonded {
        builder = builder.bonded_inputs(crate::BondedInputPolicy::Accept);
    }
    let config = builder.build().expect("listener config");
    let mut owner = Owner::new(64);
    owner
        .listen_with_resolver(&config, resolver)
        .expect("listen_with_resolver");
    let addr = owner.listener_local_addr().expect("listener addr");
    (owner, addr)
}

fn caller_config(
    remote: SocketAddr,
    stream_id: &str,
    pass: Option<(&str, srt_proto::crypto::KeyLength)>,
) -> CallerConfig {
    let mut session = crate::SessionConfig::default();
    session.set_stream_id(Some(stream_id.to_owned()));
    session
        .set_latency(Duration::from_millis(20))
        .expect("caller latency");
    if let Some((pass, key)) = pass {
        session.set_encryption(Some(crate::EncryptionConfig::new(pass).key_length(key)));
    }
    CallerConfig::builder(remote)
        .ownership(crate::SocketOwnership::Shared)
        .session(session)
        .build()
        .expect("caller config")
}

fn leg(remote: SocketAddr) -> CallerConfig {
    CallerConfig::builder(remote)
        .ownership(crate::SocketOwnership::Shared)
        .build()
        .expect("leg config")
}

fn admitted(outcome: PoolOutcome) -> crate::LogicalCallerId {
    match outcome {
        PoolOutcome::Admitted(id) => id,
        other => panic!("expected admission, got {other:?}"),
    }
}

fn state(owner: &Owner, id: &crate::LogicalCallerId) -> Option<LogicalCallerState> {
    owner.logical_caller(id).and_then(|c| c.state())
}

fn established(owner: &Owner) -> usize {
    owner
        .listener
        .as_ref()
        .expect("listener")
        .table
        .established_count()
}

/// Serve every owner on one synthetic clock until `done` or the rounds run out.
async fn pump(
    owners: &mut [&mut Owner],
    start_micros: u64,
    rounds: u64,
    mut done: impl FnMut(&mut [&mut Owner], u64) -> bool,
) -> u64 {
    let budget = OwnerServiceBudget::default();
    let mut now = start_micros;
    for round in 0..rounds {
        now = start_micros + round * 5_000;
        for owner in owners.iter_mut() {
            let _ = owner.service(Timestamp::from_micros(now), budget).await;
        }
        for owner in owners.iter_mut() {
            owner.wait_for_activity(Duration::from_micros(300)).await;
        }
        if done(owners, now) {
            return now;
        }
    }
    now
}

fn counting(
    calls: &Arc<AtomicUsize>,
    resolve: impl Fn(&crate::AdmissionRequest, &str) -> AdmissionResolution + Send + Sync + 'static,
) -> ListenerAdmissionResolver {
    let calls = Arc::clone(calls);
    ListenerAdmissionResolver::new(move |request| {
        calls.fetch_add(1, Ordering::SeqCst);
        resolve(request, &stream_id_of(request))
    })
}

fn stream_resolver(calls: &Arc<AtomicUsize>) -> ListenerAdmissionResolver {
    counting(calls, |_, stream| match stream {
        "cam/a" => AdmissionResolution::Configure(policy(
            400,
            PASS_A,
            srt_proto::crypto::KeyLength::Aes128,
        )),
        "cam/b" => {
            AdmissionResolution::Configure(policy(60, PASS_B, srt_proto::crypto::KeyLength::Aes256))
        }
        "cam/deny" => AdmissionResolution::Reject {
            reason: RejectionReason::FORBIDDEN,
        },
        "cam/defer" => AdmissionResolution::Defer,
        _ => AdmissionResolution::Reject {
            reason: RejectionReason::NOT_FOUND,
        },
    })
}

/// Connect one direct caller (own Owner, own socket) and return the time it
/// reached Connected, if it did.
async fn connect_direct(
    listener: &mut Owner,
    addr: SocketAddr,
    stream: &str,
    pass: Option<(&str, srt_proto::crypto::KeyLength)>,
    rounds: u64,
) -> (Owner, crate::LogicalCallerId, Option<u64>) {
    let mut caller = Owner::new(64);
    let id = admitted(
        caller
            .connect(
                &caller_config(addr, stream, pass),
                Timestamp::from_micros(0),
            )
            .expect("connect"),
    );
    let mut connected_at = None;
    pump(
        &mut [listener, &mut caller],
        1_000,
        rounds,
        |owners, now| {
            if state(owners[1], &id) == Some(LogicalCallerState::Connected) {
                connected_at = Some(now);
                true
            } else {
                false
            }
        },
    )
    .await;
    (caller, id, connected_at)
}

/// First synthetic time the listener sees `payload` after `send_at`.
async fn deliver(
    listener: &mut Owner,
    caller: &mut Owner,
    id: &crate::LogicalCallerId,
    send_at: u64,
    payload: &'static [u8],
) -> Option<u64> {
    caller
        .logical_caller_mut(id)
        .expect("caller")
        .send_shared(Bytes::from_static(payload), Timestamp::from_micros(send_at))
        .expect("send");
    let mut arrived = None;
    pump(&mut [listener, caller], send_at, 400, |owners, now| {
        let mut events = Vec::new();
        owners[0].poll_listener_events(&mut events);
        if events.iter().any(|e| {
            matches!(&e.event,
                srt_proto::ConnectionEvent::DataReceived { payload: got, .. } if got[..] == *payload)
        }) {
            arrived = Some(now);
        }
        arrived.is_some()
    })
    .await;
    arrived
}

/// Two StreamIDs, two cached policies, through Owner RX: each gets its own
/// key length and latency; a wrong credential for either is refused.
#[test]
fn per_streamid_crypto_and_latency_apply_through_owner_rx() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let (mut listener, addr) = listener_owner(stream_resolver(&calls), false);

        let (mut a, a_id, a_up) = connect_direct(
            &mut listener,
            addr,
            "cam/a",
            Some((PASS_A, srt_proto::crypto::KeyLength::Aes128)),
            200,
        )
        .await;
        let a_up = a_up.expect("stream a connects with its credential");
        let (mut b, b_id, b_up) = connect_direct(
            &mut listener,
            addr,
            "cam/b",
            Some((PASS_B, srt_proto::crypto::KeyLength::Aes256)),
            200,
        )
        .await;
        let b_up = b_up.expect("stream b connects with its credential");

        // Latency: the negotiated TSBPD delay is the max of caller (20 ms) and
        // the resolved policy, so a=400 ms and b=60 ms hold data differently.
        let a_sent = a_up + 10_000;
        let a_arrived = deliver(&mut listener, &mut a, &a_id, a_sent, b"payload-a")
            .await
            .expect("a payload arrives");
        let b_sent = b_up + 10_000;
        let b_arrived = deliver(&mut listener, &mut b, &b_id, b_sent, b"payload-b")
            .await
            .expect("b payload arrives");
        assert!(
            a_arrived - a_sent >= 380_000,
            "stream a is held for its 400 ms policy latency, got {} us",
            a_arrived - a_sent
        );
        assert!(
            b_arrived - b_sent < 250_000,
            "stream b is held for its 60 ms policy latency, got {} us",
            b_arrived - b_sent
        );

        // Wrong credential for the SAME StreamID: refused, never Connected.
        let (_bad, _bad_id, bad_up) = connect_direct(
            &mut listener,
            addr,
            "cam/a",
            Some((
                "not-the-right-passphrase",
                srt_proto::crypto::KeyLength::Aes128,
            )),
            150,
        )
        .await;
        assert!(bad_up.is_none(), "a wrong credential must not connect");
        assert_eq!(
            established(&listener),
            2,
            "only the two correctly credentialed publishers are established"
        );
    });
}

/// Reject: the caller is refused, nothing is established, and the rejection
/// is counted.
#[test]
fn resolver_reject_refuses_the_publisher() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let (mut listener, addr) = listener_owner(stream_resolver(&calls), false);
        let (_caller, _id, up) = connect_direct(&mut listener, addr, "cam/deny", None, 150).await;
        assert!(up.is_none(), "a rejected StreamID never connects");
        let snapshot = listener.listener_telemetry().expect("telemetry");
        assert!(snapshot.policy_rejections >= 1, "{snapshot:?}");
        assert_eq!(established(&listener), 0);
        assert!(calls.load(Ordering::SeqCst) >= 1);
    });
}

/// Defer: the half-open peer is left untouched and is still bounded by the
/// original hard half-open expiry.
#[test]
fn resolver_defer_is_bounded_by_the_half_open_ttl() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let (mut listener, addr) = listener_owner(stream_resolver(&calls), false);
        let (_caller, _id, up) = connect_direct(&mut listener, addr, "cam/defer", None, 100).await;
        assert!(up.is_none(), "a deferred StreamID does not connect");
        let snapshot = listener.listener_telemetry().expect("telemetry");
        assert!(snapshot.policy_deferred >= 1, "{snapshot:?}");
        let side = listener.listener.as_mut().expect("listener");
        assert_eq!(side.table.established_count(), 0);
        assert_eq!(side.table.len(), 1, "the deferred peer stays half-open");
        // Far beyond any half-open timeout: the entry is reclaimed, not leaked.
        let pruned = side
            .table
            .prune_half_open(Timestamp::from_micros(10 * 60 * 1_000_000));
        assert_eq!(pruned, 1);
        assert_eq!(side.table.len(), 0);
    });
}

/// The resolver runs for handshake admission only: a burst of DATA, ACK, NAK
/// and timer traffic on an established publisher never calls it again.
#[test]
fn resolver_is_not_invoked_for_data_ack_nak_or_timers() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let (mut listener, addr) = listener_owner(stream_resolver(&calls), false);
        let (mut caller, id, up) = connect_direct(
            &mut listener,
            addr,
            "cam/b",
            Some((PASS_B, srt_proto::crypto::KeyLength::Aes256)),
            200,
        )
        .await;
        let mut now = up.expect("connects");
        let admission_calls = calls.load(Ordering::SeqCst);
        assert!(admission_calls >= 1);
        for i in 0..40u64 {
            now += 10_000;
            caller
                .logical_caller_mut(&id)
                .expect("caller")
                .send_shared(
                    Bytes::from(vec![i as u8; 1_000]),
                    Timestamp::from_micros(now),
                )
                .expect("send");
            now = pump(&mut [&mut listener, &mut caller], now, 6, |_, _| false).await;
        }
        // Idle stretch: keepalives / ACK timers only.
        pump(
            &mut [&mut listener, &mut caller],
            now + 5_000,
            300,
            |_, _| false,
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            admission_calls,
            "no resolver call after admission"
        );
    });
}

/// A resolver-less `listen` is unchanged: same admission, no resolver stored.
#[test]
fn listen_without_a_resolver_stores_none() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let config = crate::ListenerConfig::builder("127.0.0.1:0".parse().unwrap())
            .topology(crate::ListenerTopology::PerPort)
            .configure_transport(|t| t.promotion = crate::PromotionPolicy::Never)
            .build()
            .expect("config");
        let accept = || ListenerAdmissionResolver::new(|_| AdmissionResolution::Accept);
        let mut plain = Owner::new(8);
        plain.listen(&config).expect("listen");
        assert!(plain.listener.as_ref().expect("side").resolver.is_none());
        let mut resolved = Owner::new(8);
        resolved
            .listen_with_resolver(&config, accept())
            .expect("listen_with_resolver");
        assert!(resolved.listener.as_ref().expect("side").resolver.is_some());
        // A second listener on the same owner is refused.
        assert!(resolved.listen_with_resolver(&config, accept()).is_err());
    });
}

/// Common-helper guard: every listener admission site in the Compio Owner
/// goes through `admit_listener_datagram`; none calls the table directly.
#[test]
fn every_compio_listener_admission_site_uses_the_one_helper() {
    let source = include_str!("compio.rs");
    let production = source
        .split("#[cfg(test)]\n#[path")
        .next()
        .expect("production section");
    assert_eq!(
        production.matches("admit_with_listener_resolver(").count(),
        1,
        "exactly one table admission call, inside the helper"
    );
    assert!(
        production.matches("admit_listener_datagram(").count() >= 4,
        "the helper definition plus the two readiness sites and the managed site"
    );
    assert!(
        !production.contains(".table.admit("),
        "no listener site may bypass the resolver helper"
    );
}

/// Drive a bonded caller with `caller_group` at one listener per entry of
/// `receiver_groups`; returns (faults, established-per-listener, connected).
async fn bonded_run(
    mode: GroupType,
    caller_group: u32,
    receiver_groups: [u32; 2],
    rounds: u64,
) -> (Vec<crate::CallerGroupFault>, Vec<usize>, bool) {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut listeners = Vec::new();
    let mut addrs = Vec::new();
    for receiver in receiver_groups {
        let (owner, addr) = listener_owner(
            counting(&calls, move |_, _| {
                AdmissionResolution::Configure(group_policy(receiver, mode))
            }),
            true,
        );
        listeners.push(owner);
        addrs.push(addr);
    }
    let mut caller = Owner::new(64);
    let config = BondedCallerConfig::new(GroupConfig::new(caller_group, mode))
        .leg(leg(addrs[0]), 2)
        .leg(leg(addrs[1]), 1);
    let id = admitted(
        caller
            .connect_bonded(&config, Timestamp::from_micros(0))
            .expect("bonded"),
    );
    let mut faults = Vec::new();
    let (l1, l2) = listeners.split_at_mut(1);
    pump(
        &mut [&mut l1[0], &mut l2[0], &mut caller],
        1_000,
        rounds,
        |owners, _| {
            let mut found = Vec::new();
            owners[2].poll_caller_group_faults(8, &mut found);
            faults.extend(found);
            !faults.is_empty()
                || (state(owners[2], &id) == Some(LogicalCallerState::Connected)
                    && established(owners[0]) >= 1
                    && established(owners[1]) >= 1)
        },
    )
    .await;
    let established_per = listeners.iter().map(established).collect();
    let connected = state(&caller, &id) == Some(LogicalCallerState::Connected);
    (faults, established_per, connected)
}

/// The same receiving-group id advertised by every leg's listener is ONE
/// receiving group: the bond connects and no fault is raised, in both modes.
#[test]
fn same_receiver_group_id_across_legs_is_one_bond() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        for mode in [GroupType::Broadcast, GroupType::Backup] {
            let (faults, established, connected) = bonded_run(mode, 7, [0x4242, 0x4242], 300).await;
            assert!(faults.is_empty(), "{mode:?}: {faults:?}");
            assert!(connected, "{mode:?}: the bond connects");
            assert_eq!(established, vec![1, 1], "{mode:?}: both legs are admitted");
        }
    });
}

/// Independent receivers that advertise different ids are a caller-side
/// collision, and the ids in the fault are the receivers' -- never the
/// caller's own group id.
#[test]
fn independent_receiver_group_ids_collide_on_the_caller() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        for mode in [GroupType::Broadcast, GroupType::Backup] {
            let (faults, _, _) = bonded_run(mode, 7, [0x1111, 0x2222], 300).await;
            assert_eq!(
                faults.len(),
                1,
                "{mode:?}: exactly one collision, got {faults:?}"
            );
            let ids = [
                faults[0].collision.expected_peer_group_id,
                faults[0].collision.actual_peer_group_id,
            ];
            let receivers = [
                GroupConfig::new(0x1111, mode).group_id,
                GroupConfig::new(0x2222, mode).group_id,
            ];
            assert!(
                receivers.contains(&ids[0]) && receivers.contains(&ids[1]) && ids[0] != ids[1],
                "{mode:?}: collision carries the receivers' ids, got {ids:x?}"
            );
            assert!(
                !ids.contains(&GroupConfig::new(7, mode).group_id),
                "{mode:?}: the caller's own id is never advertised back"
            );
        }
    });
}

/// A direct caller never receives a GROUP response, even from a listener
/// whose policy carries a receiving group: it connects and no group fault can
/// arise.
#[test]
fn direct_callers_never_get_a_group_response() {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime builds");
    runtime.block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let (mut listener, addr) = listener_owner(
            counting(&calls, |_, _| {
                AdmissionResolution::Configure(group_policy(0x5151, GroupType::Broadcast))
            }),
            true,
        );
        let (mut caller, id, up) = connect_direct(&mut listener, addr, "cam/any", None, 200).await;
        assert!(
            up.is_some(),
            "a direct caller connects to a group-advertising listener"
        );
        let mut faults = Vec::new();
        caller.poll_caller_group_faults(8, &mut faults);
        assert!(faults.is_empty());
        assert!(matches!(
            caller.logical_caller(&id).and_then(|c| c.stats()),
            Some(crate::caller::LogicalCallerStats::Direct(_))
        ));
    });
}
