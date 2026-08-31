use criterion::{Criterion, criterion_group, criterion_main};
use shiguredo_srt::{ReceiverBuffer, Timestamp};
use std::hint::black_box;

fn receiver_with_acks(count: u32) -> (ReceiverBuffer, u32) {
    let mut receiver = ReceiverBuffer::new(0, 120, Timestamp::default(), 0);
    receiver.set_tsbpd_enabled(false);
    let mut first_ack = 0;
    for tick in 1..=count {
        black_box(receiver.generate_ack(Timestamp::from_micros(u64::from(tick))));
        if tick == 1 {
            first_ack = receiver.ack_number();
        }
    }
    (receiver, first_ack)
}

fn bench_receiver_ackack_lookup(c: &mut Criterion) {
    let (mut retained_receiver, retained_ack) = receiver_with_acks(1);
    let (mut stale_receiver, stale_ack) = receiver_with_acks(17);
    let mut now = 1_000u64;
    let mut group = c.benchmark_group("receiver_ackack_lookup");
    group.sample_size(30);

    group.bench_function("retained_hit", |b| {
        b.iter(|| {
            now += 1;
            retained_receiver.handle_ackack(
                black_box(retained_ack),
                0,
                Timestamp::from_micros(now),
            );
            black_box(retained_receiver.rtt())
        });
    });

    group.bench_function("stale_miss", |b| {
        b.iter(|| {
            now += 1;
            stale_receiver.handle_ackack(black_box(stale_ack), 0, Timestamp::from_micros(now));
            black_box(stale_receiver.rtt())
        });
    });
    group.finish();
}

criterion_group!(benches, bench_receiver_ackack_lookup);
criterion_main!(benches);
