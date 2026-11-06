use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use srt_proto::Timestamp;
use srt_proto::receiver::ReceiverBuffer;
use srt_proto::wire::DataPacket;

const PACKET_COUNT: u32 = 8192;
const PACKET_INTERVAL_US: u64 = 1_316;
const PAYLOAD_SIZE: usize = 1_316;
const TSBPD_DELAY_MS: u16 = 250;

/// Receive one packet per interval and pop it with a single call: the head is
/// due exactly when it is popped, so this measures the deliverable fast path.
fn run_tsbpd(tsbpd_delay_ms: u16) {
    let mut receiver = ReceiverBuffer::new(0, tsbpd_delay_ms, Timestamp::from_micros(0), 0);

    for sequence_number in 0..PACKET_COUNT {
        let now_us = (sequence_number as u64 + 1) * PACKET_INTERVAL_US;
        let packet = DataPacket::new(
            sequence_number,
            sequence_number,
            now_us as u32,
            1,
            vec![0x42; PAYLOAD_SIZE].into(),
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

/// What a connection does: after each DATA packet, drain until `pop_ready`
/// returns `None`. With a buffered window the head is not due yet on most
/// calls, so this measures the not-deliverable path the drain always ends on.
fn run_tsbpd_drain(tsbpd_delay_ms: u16) {
    let mut receiver = ReceiverBuffer::new(0, tsbpd_delay_ms, Timestamp::from_micros(0), 0);

    for sequence_number in 0..PACKET_COUNT {
        let now_us = (sequence_number as u64 + 1) * PACKET_INTERVAL_US;
        let now = Timestamp::from_micros(now_us);
        let packet = DataPacket::new(
            sequence_number,
            sequence_number,
            now_us as u32,
            1,
            vec![0x42; PAYLOAD_SIZE].into(),
        );

        black_box(receiver.receive(packet, now));
        while black_box(receiver.pop_ready(now)).is_some() {}
    }
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
    group.bench_function("zero_loss_250ms_drain_per_packet", |b| {
        b.iter(|| run_tsbpd_drain(TSBPD_DELAY_MS));
    });
    group.finish();
}

/// Repeated rejected DATA still asks whether retained data is deliverable.
/// Keep an unchanged descending-timestamp window outside the timed loop.
fn bench_blocked_head(c: &mut Criterion) {
    let mut group = c.benchmark_group("receiver_tsbpd_blocked_head");
    group.sample_size(30);
    for window in [8192, 65_536] {
        let mut receiver =
            ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, window);
        for sequence in 0..window {
            receiver.receive(
                DataPacket::new(
                    sequence,
                    sequence,
                    100_000_000 - sequence,
                    1,
                    bytes::Bytes::from_static(b"x"),
                ),
                Timestamp::from_micros(1),
            );
        }
        assert_eq!(receiver.stats().packets_in_buffer, window);
        assert!(receiver.pop_ready(Timestamp::from_micros(2)).is_none());
        group.bench_function(window.to_string(), |b| {
            b.iter(|| black_box(receiver.pop_ready(black_box(Timestamp::from_micros(2)))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_buffered_tsbpd, bench_blocked_head);
criterion_main!(benches);
