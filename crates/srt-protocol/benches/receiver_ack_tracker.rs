use criterion::{Criterion, criterion_group, criterion_main};
use shiguredo_srt::{ReceiverBuffer, Timestamp};
use std::hint::black_box;

fn bench_receiver_ack_tracker(c: &mut Criterion) {
    let mut receiver = ReceiverBuffer::new(0, 120, Timestamp::default(), 0);
    receiver.set_tsbpd_enabled(false);
    let mut tick = 1u64;
    let mut group = c.benchmark_group("receiver_ack_tracker");
    group.sample_size(30);

    group.bench_function("full_ack", |b| {
        b.iter(|| {
            tick += 1;
            black_box(receiver.generate_ack(Timestamp::from_micros(tick)))
        });
    });
    group.finish();
}

criterion_group!(benches, bench_receiver_ack_tracker);
criterion_main!(benches);
