//! Receiver packet window scale and cache footprint validation benchmarks.
//!
//! Evaluates production ReceiverBuffer round-robined across 1, 30, 200, and 1,000 independent
//! receiver working sets competing for CPU cache under healthy, in-order, immediately deliverable traffic.

use std::hint::black_box;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{DataPacket, ReceiverBuffer, Timestamp};

const PAYLOAD: &[u8] = &[7u8; 1316];

fn data_packet(seq: u32, timestamp: Timestamp) -> DataPacket {
    DataPacket::new(
        seq,
        1,
        timestamp.as_micros() as u32,
        1,
        Bytes::from_static(PAYLOAD),
    )
}

fn bench_receiver_cache_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("receiver_cache_scale");

    for &num_receivers in &[1, 30, 200, 1000] {
        group.throughput(Throughput::Elements(num_receivers as u64));

        // Healthy In-Order Receive and Delivery (dominant production fast path)
        // Timed iteration round-robins one packet through each receiver and drains it immediately.
        group.bench_with_input(
            BenchmarkId::new("healthy_in_order", num_receivers),
            &num_receivers,
            |b, &num_receivers| {
                let mut receivers: Vec<_> = (0..num_receivers)
                    .map(|_| {
                        let mut r = ReceiverBuffer::new(0, 0, Timestamp::default(), 0);
                        r.set_tsbpd_enabled(false);
                        r
                    })
                    .collect();
                let mut seq = 0u32;
                let mut now_us = 10_000u64;

                b.iter(|| {
                    let now = Timestamp::from_micros(now_us);
                    let pkt = data_packet(seq, now);

                    for r in &mut receivers {
                        black_box(r.receive(black_box(pkt.clone()), now));
                        let popped = r.pop_ready(now);
                        debug_assert!(popped.is_some());
                        black_box(popped);
                    }
                    seq = (seq + 1) & 0x7fff_ffff;
                    now_us += 10;
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_receiver_cache_scale);
criterion_main!(benches);
