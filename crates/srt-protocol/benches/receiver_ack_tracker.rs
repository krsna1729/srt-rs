use criterion::{Criterion, criterion_group, criterion_main};
use shiguredo_srt::{DataPacket, PacketPosition, ReceiverBuffer, Timestamp};
use std::hint::black_box;

fn packet(sequence_number: u32, timestamp: u32) -> DataPacket {
    DataPacket {
        sequence_number,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0,
        retransmitted: false,
        message_number: sequence_number,
        timestamp,
        dest_socket_id: 1,
        payload: bytes::Bytes::new(),
    }
}

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

fn bench_receiver_link_capacity(c: &mut Criterion) {
    let mut receiver = ReceiverBuffer::new(0, 120, Timestamp::default(), 0);
    receiver.set_tsbpd_enabled(false);
    let intervals = [
        37u64, 11, 29, 17, 43, 13, 31, 19, 47, 23, 41, 7, 53, 5, 59, 3,
    ];
    let mut arrival = 1u64;
    let _ = receiver.receive(packet(0, 0), Timestamp::from_micros(arrival));
    for (sequence_number, interval) in (1..=16).zip(intervals) {
        arrival += interval;
        let _ = receiver.receive(
            packet(sequence_number, arrival as u32),
            Timestamp::from_micros(arrival),
        );
    }

    let mut tick = 1_000u64;
    let mut group = c.benchmark_group("receiver_link_capacity");
    group.sample_size(30);
    group.bench_function("full_ack_16_samples", |b| {
        b.iter(|| {
            tick += 1;
            black_box(receiver.generate_ack(Timestamp::from_micros(tick)))
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_receiver_ack_tracker,
    bench_receiver_link_capacity
);
criterion_main!(benches);
