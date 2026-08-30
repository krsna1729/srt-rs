//! Benchmark for upstream shiguredo/srt-rs issues 0055/0073, applied to
//! this crate's `ReceiverBuffer`: `loss_list` was `Vec<u32>` with O(n)
//! `contains`/`retain` on the per-packet hot path, and
//! `find_deliverable_seq`'s `has_gap` check did an O(loss_list) scan for
//! *every* candidate packet on *every* `pop_ready()` call -- O(packets x
//! loss_list) overall. Fixed by switching to `HashSet<u32>` plus an O(1)
//! circular-order-minimum cache (`loss_list_min`), recomputed in
//! O(loss_list) only on the rare case the cached minimum itself is removed.
//!
//! Unlike `core_packet_loop.rs` (deliberately zero-loss, since it targets a
//! different question), this benchmark exists specifically to exercise
//! `loss_list` under sustained loss -- the fix is invisible when
//! `loss_list` is empty, which is exactly why re-running the zero-loss
//! benches after the fix showed no measurable change (see the session that
//! added this file: that null result was a benchmark-selection gap, not
//! evidence the fix doesn't matter).
//!
//! Scenario: ~14% of packets are withheld on first send (simulating loss),
//! accumulating in `loss_list` until a batch of ~50 are "recovered"
//! (simulating retransmission catching up) -- a realistic scattered-loss
//! pattern, not a hand-picked pathological case. `pop_ready()` is drained
//! after every receive, matching how a real connection's message loop
//! calls it.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{DataPacket, PacketPosition, ReceiverBuffer, Timestamp};
use std::hint::black_box;

const TOTAL_PACKETS: u32 = 5000;
/// Roughly 1/7 (~14%) of packets are initially withheld -- a realistic
/// sustained loss rate for a degraded link, not a worst-case burst.
const LOSS_STRIDE: u32 = 7;
const PAYLOAD_SIZE: usize = 1316;

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn make_packet(seq: u32, timestamp: u32) -> DataPacket {
    DataPacket {
        sequence_number: seq,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0,
        retransmitted: false,
        message_number: seq & 0x03FF_FFFF,
        timestamp,
        dest_socket_id: 1,
        payload: vec![0x42u8; PAYLOAD_SIZE].into(),
    }
}

/// Withheld packets are "retransmitted" (delivered late, out of send
/// order) once `recovery_batch` have accumulated, matching a real
/// NAK/retransmit round-trip lag rather than instant recovery. Larger
/// values simulate more severe/bursty loss, growing `loss_list` further
/// before it drains -- this is the O(N) vs O(N x loss_list) axis.
fn run_lossy_receive_scenario(recovery_batch: usize) {
    let mut buf = ReceiverBuffer::new(0, 120, ts(0), 0);
    // TSBPD disabled: isolates loss-list mechanics (the thing under test)
    // from TSBPD delivery-time gating, which would otherwise also block
    // pop_ready() and muddy the comparison.
    buf.set_tsbpd_enabled(false);

    let mut held_back: Vec<u32> = Vec::new();
    let mut now_us = 0u64;

    for seq in 0..TOTAL_PACKETS {
        now_us += 1_000;
        if seq % LOSS_STRIDE == 0 {
            held_back.push(seq);
        } else {
            let _ = buf.receive(black_box(make_packet(seq, now_us as u32)), ts(now_us));
        }

        if held_back.len() >= recovery_batch || seq == TOTAL_PACKETS - 1 {
            for &held_seq in &held_back {
                let _ = buf.receive(black_box(make_packet(held_seq, now_us as u32)), ts(now_us));
            }
            held_back.clear();
        }

        while black_box(buf.pop_ready(ts(now_us))).is_some() {}
    }
}

fn bench_lossy_receive(c: &mut Criterion) {
    let mut group = c.benchmark_group("receiver_loss_scan");
    group.throughput(Throughput::Elements(TOTAL_PACKETS as u64));
    group.sample_size(30);
    // 50: realistic scattered loss (moderate loss_list, ~14% loss rate
    // with retransmit-speed recovery). 500: severe/bursty loss where
    // recovery lags far behind -- loss_list grows an order of magnitude
    // larger before draining, showing how the gap between O(N) and
    // O(N x loss_list) widens as conditions worsen.
    for &recovery_batch in &[50usize, 500usize] {
        group.bench_function(
            format!("scattered_loss_5000pkts/recovery_batch_{recovery_batch}"),
            |b| {
                b.iter(|| run_lossy_receive_scenario(recovery_batch));
            },
        );
    }
    group.finish();
}

/// Burst regime: one contiguous run of `burst_len` packets is lost, then
/// `post_burst` in-order packets arrive while the burst is still missing.
/// This is the overload shape the 2026-08-21 8 Mbps x 1200-connection
/// flamegraphs showed: a lagging connection accumulates large gaps, and
/// the old per-sequence walk paid O(gap) on every subsequent packet --
/// positive-feedback collapse. The scattered cases above never exercise
/// this (every gap there is 1 packet).
fn run_burst_receive_scenario(burst_len: u32, post_burst: u32) {
    let mut buf = ReceiverBuffer::new(0, 120, ts(0), 0);
    buf.set_tsbpd_enabled(false);
    let mut now_us = 0u64;
    let total = burst_len + post_burst;
    // Post-burst packets arrive first (burst is in flight, lost).
    // Then the burst is delivered as late retransmission.
    for seq in burst_len..total {
        now_us += 1_000;
        let _ = buf.receive(black_box(make_packet(seq, now_us as u32)), ts(now_us));
        while black_box(buf.pop_ready(ts(now_us))).is_some() {}
    }
    for seq in 0..burst_len {
        now_us += 1_000;
        let _ = buf.receive(black_box(make_packet(seq, now_us as u32)), ts(now_us));
        while black_box(buf.pop_ready(ts(now_us))).is_some() {}
    }
}

fn bench_burst_receive(c: &mut Criterion) {
    let mut group = c.benchmark_group("receiver_loss_scan");
    group.sample_size(30);
    // 100-packet burst with 500 post-burst packets: old walk re-scanned
    // ~100 entries per post-burst packet (50k probes); new walk discovers
    // the burst once.
    for &(burst_len, post_burst) in &[(100u32, 500u32), (1000u32, 2000u32)] {
        group.throughput(Throughput::Elements((burst_len + post_burst) as u64));
        group.bench_function(
            format!("burst_loss/burst{burst_len}_post{post_burst}"),
            |b| {
                b.iter(|| run_burst_receive_scenario(burst_len, post_burst));
            },
        );
    }
    group.finish();
}

fn receiver_with_dense_loss(initial_seq: u32, last_seq: u32) -> ReceiverBuffer {
    let mut receiver = ReceiverBuffer::new(initial_seq, 120, ts(0), 0);
    receiver.set_tsbpd_enabled(false);
    let _ = receiver.receive(make_packet(last_seq, 1), ts(1));
    receiver
}

fn receiver_with_mixed_state() -> ReceiverBuffer {
    let mut receiver = ReceiverBuffer::new(0, 120, ts(0), 0);
    receiver.set_tsbpd_enabled(false);
    for seq in (1..8192).step_by(2) {
        let _ = receiver.receive(make_packet(seq, seq), ts(u64::from(seq) + 1));
    }
    receiver
}

fn receiver_with_future_tsbpd_packets(packet_count: u32) -> ReceiverBuffer {
    let mut receiver = ReceiverBuffer::new(0, 120, ts(0), 0);
    for seq in 0..packet_count {
        let mut packet = make_packet(seq, 1_000_000_000 + seq);
        packet.payload = Vec::new().into();
        let _ = receiver.receive(packet, ts(1));
    }
    receiver
}

/// Maximum legal DROPREQ coverage. Setup is excluded so these cases isolate
/// the in-place range mutation for empty, dense-loss, mixed, and wrapped state.
fn bench_drop_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("receiver_drop_range");
    group.throughput(Throughput::Elements(8192));
    group.sample_size(30);

    group.bench_function("max_legal/empty", |b| {
        b.iter_batched(
            || ReceiverBuffer::new(0, 120, ts(0), 0),
            |mut receiver| black_box(receiver.drop_range(0, 8191)).unwrap(),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("max_legal/dense_loss", |b| {
        b.iter_batched(
            || receiver_with_dense_loss(0, 8191),
            |mut receiver| black_box(receiver.drop_range(0, 8191)).unwrap(),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("max_legal/mixed_packets_and_losses", |b| {
        b.iter_batched(
            receiver_with_mixed_state,
            |mut receiver| black_box(receiver.drop_range(0, 8191)).unwrap(),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("max_legal/wrap_crossing", |b| {
        b.iter_batched(
            || receiver_with_dense_loss(0x7FFF_F000, 0x0FFF),
            |mut receiver| black_box(receiver.drop_range(0x7FFF_F000, 0x0FFF)).unwrap(),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// A tiny DROPREQ must not become slower in proportion to unrelated packets
/// retained behind future TSBPD delivery times. Setup is excluded and empty
/// payloads keep this focused on ordered-map removal and hint repair.
fn bench_drop_range_locality(c: &mut Criterion) {
    let mut group = c.benchmark_group("receiver_drop_range_locality");
    group.throughput(Throughput::Elements(1));
    group.sample_size(20);

    for &packet_count in &[8192u32, 32_768u32] {
        group.bench_function(format!("single_sequence/retained_{packet_count}"), |b| {
            b.iter_batched(
                || receiver_with_future_tsbpd_packets(packet_count),
                |mut receiver| {
                    black_box(receiver.drop_range(0, 0)).unwrap();
                    receiver
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_lossy_receive,
    bench_burst_receive,
    bench_drop_range,
    bench_drop_range_locality
);
criterion_main!(benches);
