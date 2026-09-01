//! Inbound NAK queueing benchmarks.
//!
//! Setup is excluded so the measurements isolate retained-packet
//! intersection and retransmit duplicate suppression.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{LossRange, SenderBuffer, Timestamp};
use std::hint::black_box;

const PACKETS: u32 = 8_192;

fn populated_sender() -> SenderBuffer {
    let mut sender = SenderBuffer::new(0, PACKETS, 120);
    for _ in 0..PACKETS {
        assert!(sender.push(vec![1], 1, 1, Timestamp::default()).is_some());
    }
    sender
}

fn benches(c: &mut Criterion) {
    let losses = (0..PACKETS).collect::<Vec<_>>();
    let dense = [LossRange {
        first_seq: 0,
        last_seq: PACKETS - 1,
    }];
    let mut group = c.benchmark_group("sender_nak");
    group.throughput(Throughput::Elements(PACKETS as u64));

    group.bench_function("expanded_unique_8192", |b| {
        b.iter_batched(
            populated_sender,
            |mut sender| {
                sender.handle_nak(black_box(&losses));
                black_box(sender.stats().packets_in_loss_list)
            },
            BatchSize::LargeInput,
        );
    });
    group.bench_function("compact_dense_unique_8192", |b| {
        b.iter_batched(
            populated_sender,
            |mut sender| {
                sender.handle_nak_ranges(black_box(&dense));
                black_box(sender.stats().packets_in_loss_list)
            },
            BatchSize::LargeInput,
        );
    });
    group.bench_function("expanded_duplicate_8192", |b| {
        b.iter_batched(
            || {
                let mut sender = populated_sender();
                sender.handle_nak(&losses);
                sender
            },
            |mut sender| {
                sender.handle_nak(black_box(&losses));
                black_box(sender.stats().packets_in_loss_list)
            },
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(sender_nak, benches);
criterion_main!(sender_nak);
