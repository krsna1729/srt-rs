//! Private challenger against the receiver's current `BTreeMap` packet store.

#[path = "../challengers/receiver_packet_window.rs"]
mod receiver_packet_window;

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use receiver_packet_window::ReceiverPacketWindow;

const WINDOW: u32 = 8_192;
const PAYLOAD: [u64; 7] = [0x42; 7];

fn btree_successor(map: &BTreeMap<u32, [u64; 7]>, sequence: u32) -> Option<u32> {
    let next = sequence.wrapping_add(1) & 0x7fff_ffff;
    map.range(next..)
        .next()
        .or_else(|| map.first_key_value())
        .map(|(&sequence, _)| sequence)
}

fn dense_btree() -> BTreeMap<u32, [u64; 7]> {
    (0..WINDOW).map(|sequence| (sequence, PAYLOAD)).collect()
}

fn dense_paged() -> ReceiverPacketWindow<[u64; 7]> {
    let mut window = ReceiverPacketWindow::new(WINDOW);
    for sequence in 0..WINDOW {
        window.insert(sequence, PAYLOAD).unwrap();
    }
    window
}

fn sparse_btree() -> BTreeMap<u32, [u64; 7]> {
    (0..WINDOW)
        .step_by(64)
        .map(|sequence| (sequence, PAYLOAD))
        .collect()
}

fn sparse_paged() -> ReceiverPacketWindow<[u64; 7]> {
    let mut window = ReceiverPacketWindow::new(WINDOW);
    for sequence in (0..WINDOW).step_by(64) {
        window.insert(sequence, PAYLOAD).unwrap();
    }
    window
}

fn benchmark_point_operations(c: &mut Criterion) {
    let queries: Vec<u32> = (0..WINDOW).map(|sequence| sequence ^ 31).collect();
    let btree = dense_btree();
    let paged = dense_paged();
    let mut group = c.benchmark_group("receiver_packet_window/point");
    group.throughput(Throughput::Elements(WINDOW.into()));

    group.bench_function("btree_lookup_dense", |b| {
        b.iter(|| {
            for sequence in &queries {
                black_box(btree.get(black_box(sequence)));
            }
        });
    });
    group.bench_function("paged_lookup_dense", |b| {
        b.iter(|| {
            for sequence in &queries {
                black_box(paged.get(black_box(*sequence)));
            }
        });
    });
    group.bench_function("btree_insert_dense", |b| {
        b.iter_batched(
            BTreeMap::new,
            |mut map| {
                for sequence in 0..WINDOW {
                    map.insert(sequence, PAYLOAD);
                }
                black_box(map);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("paged_insert_dense", |b| {
        b.iter_batched(
            || ReceiverPacketWindow::new(WINDOW),
            |mut window| {
                for sequence in 0..WINDOW {
                    window.insert(sequence, PAYLOAD).unwrap();
                }
                black_box(window);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn benchmark_ordered_operations(c: &mut Criterion) {
    let queries: Vec<u32> = (0..WINDOW).map(|sequence| sequence ^ 127).collect();
    let btree = sparse_btree();
    let paged = sparse_paged();
    let mut group = c.benchmark_group("receiver_packet_window/successor");
    group.throughput(Throughput::Elements(WINDOW.into()));

    group.bench_function("btree_successor_sparse", |b| {
        b.iter(|| {
            for sequence in &queries {
                black_box(btree_successor(&btree, black_box(*sequence)));
            }
        });
    });
    group.bench_function("paged_successor_sparse", |b| {
        b.iter(|| {
            for sequence in &queries {
                black_box(paged.successor_after(black_box(*sequence)));
            }
        });
    });
    group.finish();

    let mut group = c.benchmark_group("receiver_packet_window/sparse_drain");
    group.throughput(Throughput::Elements(u64::from(WINDOW / 64)));
    group.bench_function("btree", |b| {
        b.iter_batched(
            sparse_btree,
            |mut map| {
                let mut sequence = 0x7fff_ffff;
                while let Some(next) = btree_successor(&map, sequence) {
                    map.remove(&next);
                    sequence = next;
                }
                black_box(map);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("paged", |b| {
        b.iter_batched(
            sparse_paged,
            |mut window| {
                let mut sequence = 0x7fff_ffff;
                while let Some(next) = window.successor_after(sequence) {
                    window.remove(next);
                    sequence = next;
                }
                black_box(window);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn benchmark_range_retirement(c: &mut Criterion) {
    let first = WINDOW / 4;
    let last = WINDOW * 3 / 4 - 1;
    let mut group = c.benchmark_group("receiver_packet_window/range_retirement");
    group.throughput(Throughput::Elements(u64::from(last - first + 1)));
    group.bench_function("btree_dense", |b| {
        b.iter_batched(
            dense_btree,
            |mut map| {
                while let Some(sequence) = map.range(first..=last).next().map(|(&seq, _)| seq) {
                    map.remove(&sequence);
                }
                black_box(map);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("paged_dense", |b| {
        b.iter_batched(
            dense_paged,
            |mut window| {
                black_box(window.remove_range(first, last));
                black_box(window);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_point_operations,
    benchmark_ordered_operations,
    benchmark_range_retirement
);
criterion_main!(benches);
