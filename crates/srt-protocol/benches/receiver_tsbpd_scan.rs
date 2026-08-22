use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{DataPacket, ReceiverBuffer, Timestamp};

const PACKET_COUNT: u32 = 8192;
const PACKET_INTERVAL_US: u64 = 1_316;
const PAYLOAD_SIZE: usize = 1_316;
const TSBPD_DELAY_MS: u16 = 250;

fn run_tsbpd(tsbpd_delay_ms: u16) {
    let mut receiver = ReceiverBuffer::new(0, tsbpd_delay_ms, Timestamp::from_micros(0), 0);

    for sequence_number in 0..PACKET_COUNT {
        let now_us = (sequence_number as u64 + 1) * PACKET_INTERVAL_US;
        let packet = DataPacket::new(
            sequence_number,
            sequence_number,
            now_us as u32,
            1,
            vec![0x42; PAYLOAD_SIZE],
        );

        black_box(receiver.receive(packet, Timestamp::from_micros(now_us)));
        black_box(receiver.pop_ready(Timestamp::from_micros(now_us)));
    }

    let drain_time = Timestamp::from_micros(
        (PACKET_COUNT as u64 + 1) * PACKET_INTERVAL_US + u64::from(tsbpd_delay_ms) * 1_000,
    );
    while black_box(receiver.pop_ready(drain_time)).is_some() {}
    black_box(receiver.stats());
}

fn bench_buffered_tsbpd(c: &mut Criterion) {
    let mut group = c.benchmark_group("receiver_tsbpd_scan");
    group.throughput(Throughput::Elements(PACKET_COUNT as u64));
    group.sample_size(30);
    group.bench_function("zero_loss_empty_window", |b| {
        b.iter(|| run_tsbpd(0));
    });
    group.bench_function("zero_loss_250ms_buffered_window", |b| {
        b.iter(|| run_tsbpd(TSBPD_DELAY_MS));
    });
    group.finish();
}

criterion_group!(benches, bench_buffered_tsbpd);
criterion_main!(benches);
