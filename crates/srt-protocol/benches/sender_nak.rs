//! Inbound NAK queueing and retransmission benchmarks.
//!
//! Excludes setup and teardown from the timed region using `iter_batched_ref`
//! to prevent destructor overhead of populated sender buffers from contaminating
//! retransmission membership and queueing measurements.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{LossRange, SenderBuffer, Timestamp};

const PACKETS: u32 = 8_192;

fn populated_sender(count: u32) -> SenderBuffer {
    let mut sender = SenderBuffer::new(0, count, 120);
    sender.set_congestion_window(count);
    for _ in 0..count {
        assert!(
            sender
                .push(vec![1; 1316], 0, 1, Timestamp::default())
                .is_some()
        );
    }
    sender
}

fn bench_sender_nak_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_nak");
    group.throughput(Throughput::Elements(PACKETS as u64));

    let expanded_losses = (0..PACKETS).collect::<Vec<_>>();
    let dense_range = [LossRange {
        first_seq: 0,
        last_seq: PACKETS - 1,
    }];

    // 1. Expanded Unique Loss List
    group.bench_function("expanded_unique_8192", |b| {
        b.iter_batched_ref(
            || populated_sender(PACKETS),
            |sender| {
                sender.handle_nak(black_box(&expanded_losses));
                black_box(sender.has_retransmit());
            },
            BatchSize::SmallInput,
        );
    });

    // 2. Compact Dense Unique Range
    group.bench_function("compact_dense_unique_8192", |b| {
        b.iter_batched_ref(
            || populated_sender(PACKETS),
            |sender| {
                sender.handle_nak_ranges(black_box(&dense_range));
                black_box(sender.has_retransmit());
            },
            BatchSize::SmallInput,
        );
    });

    // 3. Expanded Duplicate Loss List
    group.bench_function("expanded_duplicate_8192", |b| {
        b.iter_batched_ref(
            || {
                let mut sender = populated_sender(PACKETS);
                sender.handle_nak(&expanded_losses);
                sender
            },
            |sender| {
                sender.handle_nak(black_box(&expanded_losses));
                black_box(sender.has_retransmit());
            },
            BatchSize::SmallInput,
        );
    });

    // 4. Compact Duplicate Range
    group.bench_function("compact_duplicate_8192", |b| {
        b.iter_batched_ref(
            || {
                let mut sender = populated_sender(PACKETS);
                sender.handle_nak_ranges(&dense_range);
                sender
            },
            |sender| {
                sender.handle_nak_ranges(black_box(&dense_range));
                black_box(sender.has_retransmit());
            },
            BatchSize::SmallInput,
        );
    });

    // 5. Pop / Drain Retransmits After a Dense Compact NAK
    group.bench_function("drain_retransmits_after_dense_nak", |b| {
        b.iter_batched_ref(
            || {
                let mut sender = populated_sender(PACKETS);
                sender.handle_nak_ranges(&dense_range);
                sender
            },
            |sender| {
                let mut drained = 0;
                while let Some((hdr, _)) = sender.pop_retransmit(1400) {
                    black_box(hdr);
                    drained += 1;
                }
                black_box(drained)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_sender_nak_scale);
criterion_main!(benches);
