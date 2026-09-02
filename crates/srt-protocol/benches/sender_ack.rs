use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{SenderBuffer, Timestamp};

const PAYLOAD_SIZE: usize = 1316;

fn fill_window(buf: &mut SenderBuffer, count: u32) {
    let now = Timestamp::from_micros(0);
    for _ in 0..count {
        buf.push(vec![0u8; PAYLOAD_SIZE], 0, 1, now);
    }
}

fn bench_ack_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_ack");

    // Windows required by local://paste-8.md: 64, 256, 1024, 4096, 8192, plus boundary 8191, 8193.
    let windows = [64, 256, 1024, 4096, 8191, 8192, 8193];

    for &window in &windows {
        group.throughput(Throughput::Elements(1));

        for &initial_seq in &[0u32, 17u32] {
            let align_label = if initial_seq == 0 {
                "aligned"
            } else {
                "unaligned"
            };

            // 1. ACK one packet
            let ack_one_seq = (initial_seq + 1) & 0x7fff_ffff;
            group.bench_with_input(
                BenchmarkId::new(format!("advance_one_{align_label}"), window),
                &window,
                |b, &window| {
                    b.iter_batched_ref(
                        || {
                            let mut buf = SenderBuffer::new(initial_seq, window, 120);
                            buf.set_congestion_window(window);
                            fill_window(&mut buf, window);
                            debug_assert_eq!(buf.packets_in_flight(), window);
                            buf
                        },
                        |buf| {
                            buf.handle_ack(ack_one_seq);
                            black_box(buf.packets_in_flight());
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );

            // 2. ACK half the window
            let ack_half_seq = (initial_seq + window / 2) & 0x7fff_ffff;
            group.bench_with_input(
                BenchmarkId::new(format!("advance_half_{align_label}"), window),
                &window,
                |b, &window| {
                    b.iter_batched_ref(
                        || {
                            let mut buf = SenderBuffer::new(initial_seq, window, 120);
                            buf.set_congestion_window(window);
                            fill_window(&mut buf, window);
                            debug_assert_eq!(buf.packets_in_flight(), window);
                            buf
                        },
                        |buf| {
                            buf.handle_ack(ack_half_seq);
                            black_box(buf.packets_in_flight());
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );

            // 3. ACK full window
            let ack_full_seq = (initial_seq + window) & 0x7fff_ffff;
            group.bench_with_input(
                BenchmarkId::new(format!("advance_full_{align_label}"), window),
                &window,
                |b, &window| {
                    b.iter_batched_ref(
                        || {
                            let mut buf = SenderBuffer::new(initial_seq, window, 120);
                            buf.set_congestion_window(window);
                            fill_window(&mut buf, window);
                            debug_assert_eq!(buf.packets_in_flight(), window);
                            buf
                        },
                        |buf| {
                            buf.handle_ack(ack_full_seq);
                            black_box(buf.packets_in_flight());
                        },
                        criterion::BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_ack_scale);
criterion_main!(benches);
