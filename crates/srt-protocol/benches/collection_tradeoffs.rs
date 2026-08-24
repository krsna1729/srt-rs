//! Microbenchmarks for the protocol collections whose choices are not
//! interchangeable. These do not replace the end-to-end packet benches: they
//! isolate the operation that selected each representation so a future change
//! has a reproducible comparison point.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::hint::black_box;

const WINDOW: u32 = 512;
const LOOKUPS: u32 = 4_096;

fn benchmark_loss_membership(c: &mut Criterion) {
    let keys: Vec<u32> = (0..WINDOW).step_by(3).collect();
    let queries: Vec<u32> = (0..LOOKUPS).map(|key| key % (WINDOW * 2)).collect();
    let fx_set: FxHashSet<u32> = keys.iter().copied().collect();
    let std_set: HashSet<u32> = keys.iter().copied().collect();
    let mut group = c.benchmark_group("collection_tradeoffs/loss_membership");
    group.throughput(Throughput::Elements(LOOKUPS.into()));

    group.bench_function("fxhashset_u32", |b| {
        b.iter(|| {
            for query in &queries {
                black_box(black_box(&fx_set).contains(black_box(query)));
            }
        });
    });
    group.bench_function("std_hashset_u32", |b| {
        b.iter(|| {
            for query in &queries {
                black_box(black_box(&std_set).contains(black_box(query)));
            }
        });
    });
    group.finish();
}

fn btree_successor(map: &BTreeMap<u32, ()>, key: u32) -> Option<u32> {
    map.range(key..)
        .next()
        .or_else(|| map.first_key_value())
        .map(|(&sequence, _)| sequence)
}

fn hash_successor(map: &FxHashMap<u32, ()>, key: u32) -> Option<u32> {
    map.keys()
        .filter(|&&sequence| sequence >= key)
        .min()
        .or_else(|| map.keys().min())
        .copied()
}

fn benchmark_ordered_successor(c: &mut Criterion) {
    let btree: BTreeMap<u32, ()> = (0..WINDOW).map(|key| (key * 3, ())).collect();
    let hash: FxHashMap<u32, ()> = btree.keys().copied().map(|key| (key, ())).collect();
    let queries: Vec<u32> = (0..LOOKUPS).map(|key| key * 2).collect();
    let mut group = c.benchmark_group("collection_tradeoffs/ordered_successor");
    group.throughput(Throughput::Elements(LOOKUPS.into()));

    group.bench_function("btreemap_range", |b| {
        b.iter(|| {
            for query in &queries {
                black_box(btree_successor(&btree, black_box(*query)));
            }
        });
    });
    group.bench_function("fxhashmap_scan", |b| {
        b.iter(|| {
            for query in &queries {
                black_box(hash_successor(&hash, black_box(*query)));
            }
        });
    });
    group.finish();
}

fn benchmark_fifo_retransmit(c: &mut Criterion) {
    let initial: Vec<u32> = (0..WINDOW).collect();
    let mut group = c.benchmark_group("collection_tradeoffs/fifo_retransmit");
    group.throughput(Throughput::Elements(LOOKUPS.into()));

    group.bench_function("vecdeque_pop_front", |b| {
        b.iter_batched(
            || VecDeque::from(initial.clone()),
            |mut queue| {
                for replacement in WINDOW..WINDOW + LOOKUPS {
                    let _ = black_box(queue.pop_front());
                    queue.push_back(replacement);
                }
                black_box(queue);
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("vec_remove_zero", |b| {
        b.iter_batched(
            || initial.clone(),
            |mut queue| {
                for replacement in WINDOW..WINDOW + LOOKUPS {
                    let _ = black_box(queue.remove(0));
                    queue.push(replacement);
                }
                black_box(queue);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_loss_membership,
    benchmark_ordered_successor,
    benchmark_fifo_retransmit
);
criterion_main!(benches);
