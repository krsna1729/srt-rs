//! Inbound NAK queueing and retransmission benchmarks.
//!
//! Excludes setup and teardown from the timed region using `iter_batched_ref`
//! to prevent destructor overhead of populated sender buffers from contaminating
//! retransmission membership and queueing measurements.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use srt_proto::Timestamp;
use srt_proto::receiver::LossRange;
use srt_proto::sender::SenderBuffer;

const PACKETS: u32 = 8_192;

fn populated_sender(count: u32) -> SenderBuffer {
    let mut sender = SenderBuffer::new(0, count, 120);
    for _ in 0..count {
        let (header, _) = sender
            .push(vec![1; 1316], 0, 1, Timestamp::default())
            .expect("the negotiated window admits the flight");
        // A loss report is only credible for positions that reached the wire.
        sender.note_data_submitted(header.sequence_number);
    }
    sender
}

/// Expand a loss list into the single-sequence ranges a NAK carries.
fn loss_ranges(sequences: &[u32]) -> Vec<LossRange> {
    sequences
        .iter()
        .map(|&sequence| LossRange {
            first_seq: sequence,
            last_seq: sequence,
        })
        .collect()
}

fn bench_sender_nak_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_nak");
    group.throughput(Throughput::Elements(PACKETS as u64));

    let expanded_losses = (0..PACKETS).collect::<Vec<_>>();
    let expanded_ranges = loss_ranges(&expanded_losses);
    let dense_range = [LossRange {
        first_seq: 0,
        last_seq: PACKETS - 1,
    }];

    // 1. Expanded Unique Loss List
    group.bench_function("expanded_unique_8192", |b| {
        b.iter_batched_ref(
            || populated_sender(PACKETS),
            |sender| {
                let _ = sender.handle_nak_ranges(black_box(&expanded_ranges));
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
                let _ = sender.handle_nak_ranges(black_box(&dense_range));
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
                let _ = sender.handle_nak_ranges(&expanded_ranges);
                sender
            },
            |sender| {
                let _ = sender.handle_nak_ranges(black_box(&expanded_ranges));
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
                let _ = sender.handle_nak_ranges(&dense_range);
                sender
            },
            |sender| {
                let _ = sender.handle_nak_ranges(black_box(&dense_range));
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
                let _ = sender.handle_nak_ranges(&dense_range);
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
