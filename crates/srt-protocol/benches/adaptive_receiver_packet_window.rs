//! Occupancy and transition matrix for the adaptive receiver challenger.

#[path = "../challengers/adaptive_receiver_packet_window.rs"]
mod adaptive_receiver_packet_window;

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Duration;

use adaptive_receiver_packet_window::AdaptiveReceiverPacketWindow;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const WINDOW: u32 = 8_192;
const PAGE_SLOTS: u32 = 64;
const PAGE_COUNT: u32 = WINDOW / PAGE_SLOTS;
const OCCUPANCIES: [u32; 7] = [1, 2, 4, 8, 16, 32, 64];
const VALUE: [u64; 7] = [0x42; 7];

fn sequences(occupancy: u32) -> Vec<u32> {
    (0..PAGE_COUNT)
        .flat_map(|page| (0..occupancy).map(move |slot| page * PAGE_SLOTS + slot))
        .collect()
}

fn btree(occupancy: u32) -> BTreeMap<u32, [u64; 7]> {
    sequences(occupancy)
        .into_iter()
        .map(|sequence| (sequence, VALUE))
        .collect()
}

fn adaptive<const N: usize>(
    occupancy: u32,
    demote_at: usize,
) -> AdaptiveReceiverPacketWindow<[u64; 7], N> {
    let mut window = AdaptiveReceiverPacketWindow::new(WINDOW, demote_at);
    for sequence in sequences(occupancy) {
        window.insert(sequence, VALUE).unwrap();
    }
    window
}

fn settle_with_points<const N: usize>(
    window: &mut AdaptiveReceiverPacketWindow<[u64; 7], N>,
    occupancy: u32,
) {
    for page in 0..PAGE_COUNT {
        for slot in occupancy..=N as u32 {
            window.remove(page * PAGE_SLOTS + slot);
        }
    }
}

fn settle_with_ranges<const N: usize>(
    window: &mut AdaptiveReceiverPacketWindow<[u64; 7], N>,
    occupancy: u32,
) {
    for page in 0..PAGE_COUNT {
        window
            .remove_range(page * PAGE_SLOTS + occupancy, page * PAGE_SLOTS + N as u32)
            .unwrap();
    }
}

fn promoted_then_settled<const N: usize>(
    demote_at: usize,
    occupancy: u32,
) -> AdaptiveReceiverPacketWindow<[u64; 7], N> {
    let mut window = adaptive::<N>(N as u32 + 1, demote_at);
    settle_with_points(&mut window, occupancy);
    window
}

fn btree_successor(map: &BTreeMap<u32, [u64; 7]>, sequence: u32) -> Option<u32> {
    let next = sequence.wrapping_add(1) & 0x7fff_ffff;
    map.range(next..)
        .next()
        .or_else(|| map.first_key_value())
        .map(|(&sequence, _)| sequence)
}

fn matrix_config(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(250));
    group.measurement_time(Duration::from_millis(750));
}

fn benchmark_occupancy_matrix(c: &mut Criterion) {
    for occupancy in OCCUPANCIES {
        let keys = sequences(occupancy);
        let elements = keys.len() as u64;

        let mut group = c.benchmark_group(format!("adaptive_receiver/insert/{occupancy}_per_page"));
        matrix_config(&mut group);
        group.throughput(Throughput::Elements(elements));
        group.bench_function("btree", |b| {
            b.iter(|| {
                let mut map = BTreeMap::new();
                for &sequence in &keys {
                    map.insert(sequence, VALUE);
                }
                black_box(map);
            });
        });
        group.bench_function("adaptive4", |b| {
            b.iter(|| {
                let mut window = AdaptiveReceiverPacketWindow::<_, 4>::new(WINDOW, 1);
                for &sequence in &keys {
                    window.insert(sequence, VALUE).unwrap();
                }
                black_box(window);
            });
        });
        group.bench_function("adaptive8_demote4", |b| {
            b.iter(|| {
                let mut window = AdaptiveReceiverPacketWindow::<_, 8>::new(WINDOW, 4);
                for &sequence in &keys {
                    window.insert(sequence, VALUE).unwrap();
                }
                black_box(window);
            });
        });
        group.finish();

        let map = btree(occupancy);
        let window4 = adaptive::<4>(occupancy, 1);
        let candidate = adaptive::<8>(occupancy, 4);
        let mut group = c.benchmark_group(format!("adaptive_receiver/lookup/{occupancy}_per_page"));
        matrix_config(&mut group);
        group.throughput(Throughput::Elements(elements));
        group.bench_function("btree", |b| {
            b.iter(|| {
                for sequence in &keys {
                    black_box(map.get(black_box(sequence)));
                }
            });
        });
        group.bench_function("adaptive4", |b| {
            b.iter(|| {
                for sequence in &keys {
                    black_box(window4.get(black_box(*sequence)));
                }
            });
        });
        group.bench_function("adaptive8_demote4", |b| {
            b.iter(|| {
                for sequence in &keys {
                    black_box(candidate.get(black_box(*sequence)));
                }
            });
        });
        group.finish();

        let mut group =
            c.benchmark_group(format!("adaptive_receiver/successor/{occupancy}_per_page"));
        matrix_config(&mut group);
        group.throughput(Throughput::Elements(elements));
        group.bench_function("btree", |b| {
            b.iter(|| {
                for sequence in &keys {
                    black_box(btree_successor(&map, black_box(*sequence)));
                }
            });
        });
        group.bench_function("adaptive4", |b| {
            b.iter(|| {
                for sequence in &keys {
                    black_box(window4.successor_after(black_box(*sequence)));
                }
            });
        });
        group.bench_function("adaptive8_demote4", |b| {
            b.iter(|| {
                for sequence in &keys {
                    black_box(candidate.successor_after(black_box(*sequence)));
                }
            });
        });
        group.finish();

        let remove_count = keys.len().div_ceil(2) as u64;
        let mut group = c.benchmark_group(format!("adaptive_receiver/remove/{occupancy}_per_page"));
        matrix_config(&mut group);
        group.throughput(Throughput::Elements(remove_count));
        group.bench_function("btree", |b| {
            b.iter_batched(
                || btree(occupancy),
                |mut map| {
                    for sequence in keys.iter().step_by(2) {
                        black_box(map.remove(sequence));
                    }
                    black_box(map);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function("adaptive4", |b| {
            b.iter_batched(
                || adaptive::<4>(occupancy, 1),
                |mut window| {
                    for sequence in keys.iter().step_by(2) {
                        black_box(window.remove(*sequence));
                    }
                    black_box(window);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function("adaptive8_demote4", |b| {
            b.iter_batched(
                || adaptive::<8>(occupancy, 4),
                |mut window| {
                    for sequence in keys.iter().step_by(2) {
                        black_box(window.remove(*sequence));
                    }
                    black_box(window);
                },
                BatchSize::SmallInput,
            );
        });
        group.finish();

        let first = WINDOW / 4;
        let last = WINDOW * 3 / 4 - 1;
        let range_elements = u64::from(occupancy) * u64::from(PAGE_COUNT / 2);
        let mut group = c.benchmark_group(format!(
            "adaptive_receiver/range_retirement/{occupancy}_per_page"
        ));
        matrix_config(&mut group);
        group.throughput(Throughput::Elements(range_elements));
        group.bench_function("btree", |b| {
            b.iter_batched(
                || btree(occupancy),
                |mut map| {
                    while let Some(sequence) = map
                        .range(first..=last)
                        .next()
                        .map(|(&sequence, _)| sequence)
                    {
                        map.remove(&sequence);
                    }
                    black_box(map);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function("adaptive4", |b| {
            b.iter_batched(
                || adaptive::<4>(occupancy, 1),
                |mut window| {
                    black_box(window.remove_range(first, last));
                    black_box(window);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function("adaptive8_demote4", |b| {
            b.iter_batched(
                || adaptive::<8>(occupancy, 4),
                |mut window| {
                    black_box(window.remove_range(first, last));
                    black_box(window);
                },
                BatchSize::SmallInput,
            );
        });
        group.finish();

        let mut group = c.benchmark_group(format!("adaptive_receiver/drain/{occupancy}_per_page"));
        matrix_config(&mut group);
        group.throughput(Throughput::Elements(elements));
        group.bench_function("btree", |b| {
            b.iter_batched(
                || btree(occupancy),
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
        group.bench_function("adaptive4", |b| {
            b.iter_batched(
                || adaptive::<4>(occupancy, 1),
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
        group.bench_function("adaptive8_demote4", |b| {
            b.iter_batched(
                || adaptive::<8>(occupancy, 4),
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
}

fn benchmark_demotion_policy(c: &mut Criterion) {
    fn cycle<const N: usize>(window: &mut AdaptiveReceiverPacketWindow<[u64; 7], N>, low: usize) {
        for _ in 0..1_000 {
            for sequence in low as u32..=N as u32 {
                window.insert(sequence, VALUE).unwrap();
            }
            for sequence in (low as u32..=N as u32).rev() {
                window.remove(sequence);
            }
        }
    }

    fn bench_cycle<const N: usize>(c: &mut Criterion, demote_at: usize, low: usize) {
        let mut group = c.benchmark_group(format!(
            "adaptive_receiver/churn/N{N}_demote{demote_at}_{low}_to_{}",
            N + 1
        ));
        matrix_config(&mut group);
        group.throughput(Throughput::Elements((2_000 * (N + 1 - low)) as u64));
        group.bench_function(BenchmarkId::new("cycles", low), |b| {
            b.iter_batched(
                || adaptive::<N>(low as u32, demote_at),
                |mut window| {
                    cycle(&mut window, low);
                    black_box(window);
                },
                BatchSize::SmallInput,
            );
        });
        group.finish();
    }

    for low in 1..=4 {
        bench_cycle::<4>(c, low, low);
    }
    for low in [4, 5, 8] {
        bench_cycle::<8>(c, 4, low);
    }
}

fn benchmark_history_policy<const N: usize>(c: &mut Criterion, demote_at: usize) {
    for occupancy in 1..=4 {
        let elements = (N + 1 - occupancy) as u64 * u64::from(PAGE_COUNT);
        let mut group = c.benchmark_group(format!(
            "adaptive_receiver/history/N{N}_demote{demote_at}_settle{occupancy}"
        ));
        matrix_config(&mut group);
        group.throughput(Throughput::Elements(elements));
        group.bench_function("point_remove", |b| {
            b.iter_batched(
                || adaptive::<N>(N as u32 + 1, demote_at),
                |mut window| {
                    settle_with_points(&mut window, occupancy as u32);
                    black_box(window);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function("range_retirement", |b| {
            b.iter_batched(
                || adaptive::<N>(N as u32 + 1, demote_at),
                |mut window| {
                    settle_with_ranges(&mut window, occupancy as u32);
                    black_box(window);
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function("repromotion", |b| {
            b.iter_batched(
                || promoted_then_settled::<N>(demote_at, occupancy as u32),
                |mut window| {
                    for page in 0..PAGE_COUNT {
                        for slot in occupancy as u32..=N as u32 {
                            window.insert(page * PAGE_SLOTS + slot, VALUE).unwrap();
                        }
                    }
                    black_box(window);
                },
                BatchSize::SmallInput,
            );
        });
        group.finish();
    }
}

fn benchmark_history_matrix(c: &mut Criterion) {
    for demote_at in 1..=4 {
        benchmark_history_policy::<4>(c, demote_at);
    }
    for demote_at in [1, 4] {
        benchmark_history_policy::<8>(c, demote_at);
    }
}

criterion_group!(
    benches,
    benchmark_occupancy_matrix,
    benchmark_demotion_policy,
    benchmark_history_matrix
);
criterion_main!(benches);
