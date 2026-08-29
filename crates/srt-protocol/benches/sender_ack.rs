use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{SenderBuffer, Timestamp};

const PAYLOAD_SIZE: usize = 1316;

fn fill_window(buf: &mut SenderBuffer, count: u32) {
    let now = Timestamp::from_micros(0);
    for _ in 0..count {
        buf.push(vec![0u8; PAYLOAD_SIZE], 0, 1, now);
    }
}

fn bench_ack(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_ack");

    for &window in &[64, 256, 1024, 4096] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("advance_one", window),
            &window,
            |b, &window| {
                b.iter_batched(
                    || {
                        let mut buf = SenderBuffer::new(0, 8192, 120);
                        buf.set_congestion_window(8192);
                        fill_window(&mut buf, window);
                        buf
                    },
                    |mut buf| {
                        buf.handle_ack(1);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("advance_half", window),
            &window,
            |b, &window| {
                b.iter_batched(
                    || {
                        let mut buf = SenderBuffer::new(0, 8192, 120);
                        buf.set_congestion_window(8192);
                        fill_window(&mut buf, window);
                        buf
                    },
                    |mut buf| {
                        buf.handle_ack(window / 2);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_ack);
criterion_main!(benches);
