use std::sync::Arc;
use std::thread;

use srt_transport::{Handoff, IngressTelemetry};

fn assert_send<T: Send>() {}
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn cross_thread_transport_contracts_remain_explicit() {
    assert_send::<Handoff>();
    assert_send_sync::<IngressTelemetry>();
}

#[test]
fn telemetry_is_lossless_under_concurrent_updates() {
    let telemetry = Arc::new(IngressTelemetry::new());
    let threads = 8;
    let increments = 10_000;
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let telemetry = Arc::clone(&telemetry);
            thread::spawn(move || {
                for _ in 0..increments {
                    telemetry.record_cookie_routed();
                    telemetry.record_source_capacity_drop();
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("telemetry worker");
    }
    let snapshot = telemetry.snapshot();
    assert_eq!(snapshot.cookie_routed, threads * increments);
    assert_eq!(snapshot.source_capacity_drops, threads * increments);
    assert_eq!(snapshot.total_capacity_drops(), threads * increments);
}
