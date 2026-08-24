use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{HandshakePacket, Timestamp};
use srt_transport::{AdmissionOptions, DueIndex, IngressTelemetry, PeerTable, PeerTableConfig};

fn induction(socket_id: u32) -> Vec<u8> {
    let packet = HandshakePacket::new_induction_request(socket_id).encode(0, 0);
    let mut bytes = Vec::new();
    packet.encode(&mut bytes);
    bytes
}

fn bench_invalid_admission(c: &mut Criterion) {
    let options = AdmissionOptions {
        socket_id: 7,
        tsbpd_delay: 120,
        cookie_routing: true,
    };
    let telemetry = IngressTelemetry::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 10_000));
    let mut group = c.benchmark_group("admission_hardening");
    group.throughput(Throughput::Elements(1));
    group.bench_function("invalid_datagram_no_allocation", |b| {
        b.iter_batched(
            PeerTable::new,
            |mut table| {
                black_box(table.admit(
                    peer,
                    black_box(&[0u8; 64]),
                    Timestamp::default(),
                    &options,
                    0,
                    1,
                    &telemetry,
                ));
                assert!(table.is_empty());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_bounded_capacity(c: &mut Criterion) {
    let options = AdmissionOptions {
        socket_id: 7,
        tsbpd_delay: 120,
        cookie_routing: true,
    };
    let telemetry = IngressTelemetry::new();
    let packet = induction(1);
    c.bench_function("admission_capacity_rejection", |b| {
        b.iter_batched(
            || {
                let mut table = PeerTable::with_config(PeerTableConfig {
                    max_peers: 1,
                    half_open_timeout: Duration::from_secs(10),
                });
                let _ = table.admit(
                    SocketAddr::from(([127, 0, 0, 1], 10_000)),
                    &packet,
                    Timestamp::default(),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                table
            },
            |mut table| {
                black_box(table.admit(
                    SocketAddr::from(([127, 0, 0, 1], 10_001)),
                    &packet,
                    Timestamp::from_micros(1),
                    &options,
                    0,
                    1,
                    &telemetry,
                ));
                assert_eq!(table.len(), 1);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_due_index_churn(c: &mut Criterion) {
    c.bench_function("due_index_replace_and_expire_4096", |b| {
        b.iter(|| {
            let mut index = DueIndex::default();
            for key in 0..4096u32 {
                index.set(key, Timestamp::from_micros(u64::from(key)));
                index.set(key, Timestamp::from_micros(u64::from(key) + 4096));
            }
            let mut due = Vec::new();
            index.pop_due(Timestamp::from_micros(8192), &mut due);
            black_box(due);
        });
    });
}

criterion_group!(
    benches,
    bench_invalid_admission,
    bench_bounded_capacity,
    bench_due_index_churn
);
criterion_main!(benches);
