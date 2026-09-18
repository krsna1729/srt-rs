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

/// Tombstone discovery during NAK validation: proves the O(1)-amortized
/// cost per distinct tombstoned run holds at scale, for both a NAK naming
/// many one-packet dropped messages and one naming a single heavily
/// fragmented dropped message. See `srt_sender::tests::
/// a_nak_spanning_one_huge_fragmented_tombstone_walks_the_run_once` and
/// `..._many_one_packet_tombstones_walks_each_run_once` for the
/// deterministic (operation-counted) regression this benchmark
/// complements.
fn bench_sender_nak_tombstones(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_nak_tombstones");
    const TOMBSTONES: u32 = 8_192;
    group.throughput(Throughput::Elements(TOMBSTONES as u64));

    let many_one_packet = |messages: u32| -> SenderBuffer {
        let mut sender = SenderBuffer::new(0, messages + 64, 10);
        for _ in 0..messages {
            let (header, _) = sender
                .push(vec![1], 1, 1, Timestamp::default())
                .expect("admitted");
            sender.note_data_submitted(header.sequence_number);
        }
        let _ = sender.drop_expired(Timestamp::from_micros(1_000_001));
        sender
    };
    let dense_range = [LossRange {
        first_seq: 0,
        last_seq: TOMBSTONES - 1,
    }];

    group.bench_function("many_one_packet_tombstones", |b| {
        b.iter_batched_ref(
            || many_one_packet(TOMBSTONES),
            |sender| {
                black_box(sender.handle_nak_ranges(black_box(&dense_range)).ok());
            },
            BatchSize::SmallInput,
        );
    });

    let one_giant_fragmented_tombstone = || -> SenderBuffer {
        let mut sender = SenderBuffer::new(0, TOMBSTONES + 64, 10);
        let payload = vec![0u8; TOMBSTONES as usize];
        for (header, _) in sender.push_message(&payload, 1, 1, 1, Timestamp::default()) {
            sender.note_data_submitted(header.sequence_number);
        }
        let _ = sender.drop_expired(Timestamp::from_micros(1_000_001));
        sender
    };

    group.bench_function("one_giant_fragmented_tombstone", |b| {
        b.iter_batched_ref(
            one_giant_fragmented_tombstone,
            |sender| {
                black_box(sender.handle_nak_ranges(black_box(&dense_range)).ok());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_sender_nak_scale, bench_sender_nak_tombstones);
criterion_main!(benches);
