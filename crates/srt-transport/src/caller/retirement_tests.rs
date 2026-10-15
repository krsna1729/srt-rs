use super::tests::{
    finish_conclusion, new_connected_caller_connection, next_packet,
    prepare_conclusion_with_options,
};
use crate::*;
use bytes::Bytes;
use srt_proto::{ConnectionOptions, SrtConnection, Timestamp};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct TrackedDatagram {
    bytes: Vec<u8>,
    freed: Arc<AtomicUsize>,
}
impl AsRef<[u8]> for TrackedDatagram {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for TrackedDatagram {
    fn drop(&mut self) {
        self.freed.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
#[expect(
    clippy::cognitive_complexity,
    reason = "One direct/group lifecycle trace checks routing, capacity and physical destruction"
)]
fn direct_and_group_callers_unroute_now_but_hold_capacity_until_physical_completion() {
    for grouped in [false, true] {
        let mut table = CallerTable::with_max_callers(1);
        let peer = "127.0.0.1:19001".parse().unwrap();
        let connection = new_connected_caller_connection(101);
        let id = if grouped {
            table
                .add_group(
                    srt_proto::handshake::SRTGROUP_MASK | 9,
                    srt_proto::GroupMode::Broadcast,
                    [CallerGroupLeg::new(1, 1, peer, connection)],
                )
                .unwrap()
        } else {
            table.add_direct(CallerLeg::new(peer, connection)).unwrap()
        };
        let freed = Arc::new(AtomicUsize::new(0));
        let now = Timestamp::from_micros(1_000_000);
        for _ in 0..130 {
            let payload = Bytes::from_owner(TrackedDatagram {
                bytes: vec![0x42],
                freed: Arc::clone(&freed),
            });
            table
                .logical_caller_mut(&id)
                .unwrap()
                .send_shared(payload, now)
                .unwrap();
        }
        let mut wire = Vec::new();
        for _ in 0..10 {
            table.poll_outbound(now, &mut wire);
            if wire.is_empty() {
                break;
            }
        }
        assert_eq!(freed.load(Ordering::SeqCst), 0);
        assert!(table.retire(id));
        assert!(table.logical_caller(&id).is_none());
        assert_eq!(freed.load(Ordering::SeqCst), 0);
        assert_eq!(table.reclaim_retired(0), 0);
        assert_eq!(table.retirements_pending(), 1);
        assert!(!table.retire(id), "logical retirement is exactly once");
        let replacement = || CallerLeg::new(peer, new_connected_caller_connection(102));
        assert!(table.add_direct(replacement()).is_err());
        assert!(
            table
                .add_group(
                    srt_proto::handshake::SRTGROUP_MASK | 10,
                    srt_proto::GroupMode::Broadcast,
                    [CallerGroupLeg::new(
                        2,
                        1,
                        peer,
                        new_connected_caller_connection(103)
                    )],
                )
                .is_err()
        );
        for _ in 0..4096 {
            if table.retirements_pending() == 0 {
                break;
            }
            let before = freed.load(Ordering::SeqCst);
            assert_eq!(table.reclaim_retired(1), 1);
            assert!(freed.load(Ordering::SeqCst) <= before + 1);
        }
        assert_eq!(freed.load(Ordering::SeqCst), 130);
        assert_eq!(table.retirements_pending(), 0);
        assert!(table.add_direct(replacement()).is_ok());
    }
}

#[test]
#[expect(
    clippy::cognitive_complexity,
    reason = "One admission lifecycle trace checks receive totals, late packets and held physical credit"
)]
fn peer_retirement_keeps_window_credit_and_monotonic_totals_until_storage_is_gone() {
    let options = AdmissionOptions::basic(0x3335, 0, false);
    let telemetry = IngressTelemetry::new();
    let mut table = PeerTable::with_config(PeerTableConfig {
        max_peers: 1,
        max_half_open_peers: 1,
        max_established_peers: 1,
        ..PeerTableConfig::default()
    });
    let peer = "127.0.0.1:19002".parse().unwrap();
    let (mut caller, conclusion) = prepare_conclusion_with_options(
        &mut table,
        peer,
        ConnectionOptions {
            socket_id: 0x4446,
            ..Default::default()
        },
        &options,
        &telemetry,
    );
    finish_conclusion(
        &mut table,
        peer,
        &mut caller,
        &conclusion,
        &options,
        &telemetry,
    );
    let mut events = Vec::new();
    table.poll_events(&mut events);
    let id = events
        .iter()
        .find(|event| matches!(event.event, srt_proto::ConnectionEvent::Connected))
        .expect("established peer")
        .logical_peer;
    let held = table.reserved_window_memory_bytes();
    let freed = Arc::new(AtomicUsize::new(0));
    let mut first_wire = Vec::new();
    for index in 0..130 {
        caller.send(b"x", Timestamp::from_micros(4)).unwrap();
        let wire = next_packet(&mut caller);
        if index == 0 {
            first_wire = wire.clone();
        }
        let datagram = Bytes::from_owner(TrackedDatagram {
            bytes: wire,
            freed: Arc::clone(&freed),
        });
        assert_eq!(
            table.admit_bytes_with_listener_resolver(
                None,
                peer,
                datagram,
                Timestamp::from_micros(5),
                &options,
                0,
                1,
                &telemetry
            ),
            Admit::Fed
        );
    }
    assert_eq!(
        table.admit(
            peer,
            &first_wire,
            Timestamp::from_micros(6),
            &options,
            0,
            1,
            &telemetry
        ),
        Admit::Fed
    );
    let totals = table.receiver_totals();
    assert_eq!(totals.duplicates, 1);
    assert!(table.retire(id));
    assert!(table.logical_peer(&id).is_none());
    assert_eq!(freed.load(Ordering::SeqCst), 0);
    assert_eq!(table.reserved_window_memory_bytes(), held);
    assert_eq!(table.receiver_totals(), totals);
    assert_eq!(table.reclaim_retired(0), 0);
    assert!(matches!(
        table.admit(
            peer,
            &first_wire,
            Timestamp::from_micros(7),
            &options,
            0,
            1,
            &telemetry
        ),
        Admit::Dropped(_)
    ));
    let mut second = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x4447,
        ..Default::default()
    });
    second.connect(Timestamp::default()).unwrap();
    let induction = next_packet(&mut second);
    let second_peer = "127.0.0.1:19003".parse().unwrap();
    assert!(matches!(
        table.admit(
            second_peer,
            &induction,
            Timestamp::from_micros(8),
            &options,
            0,
            1,
            &telemetry
        ),
        Admit::Dropped(_)
    ));
    for _ in 0..4096 {
        if table.retirements_pending() == 0 {
            break;
        }
        let before = freed.load(Ordering::SeqCst);
        assert_eq!(table.reclaim_retired(1), 1);
        assert!(freed.load(Ordering::SeqCst) <= before + 1);
        assert_eq!(table.receiver_totals(), totals);
    }
    assert_eq!(freed.load(Ordering::SeqCst), 130);
    assert_eq!(table.retirements_pending(), 0);
    assert_eq!(table.reserved_window_memory_bytes(), 0);
    assert_eq!(
        table.admit(
            second_peer,
            &induction,
            Timestamp::from_micros(9),
            &options,
            0,
            1,
            &telemetry
        ),
        Admit::Fed
    );
}
