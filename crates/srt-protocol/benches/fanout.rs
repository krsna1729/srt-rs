//! Fan-out benchmark: one upstream sender → N downstream connections.
//!
//! Measures per-packet CPU cost of a restreaming proxy that receives one
//! stream and re-sends to N subscribers. Compares `send(&[u8])` (deep copy
//! per downstream) against `send_shared(Bytes)` (refcount bump per
//! downstream).

use bytes::Bytes;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection, TimerId, Timestamp,
};
use std::hint::black_box;

const PAYLOAD_SIZE: usize = 1316;
const PACKETS_PER_BATCH: u64 = 16;
const ACK_EVERY_N: u64 = 8;
const FANOUT_SIZES: &[usize] = &[1, 10, 100, 500, 1000];

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn drain_sent(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    while let Some(out) = conn.poll_output() {
        if let ConnectionOutput::SendPacket(data) = out {
            sent.push(data);
        }
    }
    sent
}

fn connection_options() -> ConnectionOptions {
    ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    }
}

fn setup_connected_pair() -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(connection_options());
    let mut listener = SrtConnection::new_listener(connection_options());
    caller.connect(ts(0)).expect("connect");

    for i in 0..10u64 {
        let now = ts(i * 10_000);
        for data in drain_sent(&mut caller) {
            let _ = listener.feed_recv_buf(&data, now);
        }
        for data in drain_sent(&mut listener) {
            let _ = caller.feed_recv_buf(&data, now);
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, listener);
        }
    }
    panic!("connection not established");
}

struct FanoutRig {
    upstream_caller: SrtConnection,
    upstream_listener: SrtConnection,
    downstream: Vec<(SrtConnection, SrtConnection)>,
}

fn setup_fanout(n: usize) -> FanoutRig {
    let (upstream_caller, upstream_listener) = setup_connected_pair();
    let downstream: Vec<_> = (0..n).map(|_| setup_connected_pair()).collect();
    FanoutRig {
        upstream_caller,
        upstream_listener,
        downstream,
    }
}

fn ack_round_trips(rig: &mut FanoutRig, now: Timestamp) {
    let _ = rig.upstream_listener.handle_timer(TimerId::Ack, now);
    for data in drain_sent(&mut rig.upstream_listener) {
        let _ = rig.upstream_caller.feed_recv_buf(&data, now);
    }
    for (caller, listener) in &mut rig.downstream {
        let _ = listener.handle_timer(TimerId::Ack, now);
        for data in drain_sent(listener) {
            let _ = caller.feed_recv_buf(&data, now);
        }
    }
}

fn upstream_recv(rig: &mut FanoutRig, now: Timestamp) -> Vec<u8> {
    let payload = [0x42u8; PAYLOAD_SIZE];
    rig.upstream_caller
        .send(black_box(&payload), now)
        .expect("upstream send");
    for data in drain_sent(&mut rig.upstream_caller) {
        rig.upstream_listener
            .feed_recv_buf(black_box(&data), now)
            .expect("upstream recv");
    }
    let mut received = None;
    while let Some(event) = rig.upstream_listener.poll_event() {
        if let shiguredo_srt::ConnectionEvent::DataReceived { payload, .. } = event {
            received = Some(payload);
        }
    }
    received.expect("should receive data")
}

fn deliver_downstream(caller: &mut SrtConnection, listener: &mut SrtConnection, now: Timestamp) {
    for data in drain_sent(caller) {
        listener
            .feed_recv_buf(black_box(&data), now)
            .expect("downstream recv");
    }
    while listener.poll_event().is_some() {}
}

fn run_fanout_send(rig: &mut FanoutRig, batch_size: u64) {
    let mut now_us = 20_000u64;
    for i in 0..batch_size {
        let now = ts(now_us);
        let rx_payload = upstream_recv(rig, now);

        for (caller, listener) in &mut rig.downstream {
            caller
                .send(black_box(&rx_payload), now)
                .expect("downstream send");
            deliver_downstream(caller, listener, now);
        }

        if (i + 1) % ACK_EVERY_N == 0 {
            ack_round_trips(rig, now);
        }
        now_us += 1_000;
    }
}

fn run_fanout_send_shared(rig: &mut FanoutRig, batch_size: u64) {
    let mut now_us = 20_000u64;
    for i in 0..batch_size {
        let now = ts(now_us);
        let rx_payload = upstream_recv(rig, now);
        let shared = Bytes::from(rx_payload);

        for (caller, listener) in &mut rig.downstream {
            caller
                .send_shared(black_box(shared.clone()), now)
                .expect("downstream send_shared");
            deliver_downstream(caller, listener, now);
        }

        if (i + 1) % ACK_EVERY_N == 0 {
            ack_round_trips(rig, now);
        }
        now_us += 1_000;
    }
}

fn bench_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout");
    for &n in FANOUT_SIZES {
        group.throughput(Throughput::Elements(PACKETS_PER_BATCH * n as u64));
        group.bench_with_input(BenchmarkId::new("send", n), &n, |b, &n| {
            b.iter_batched(
                || setup_fanout(n),
                |mut rig| run_fanout_send(&mut rig, PACKETS_PER_BATCH),
                BatchSize::LargeInput,
            );
        });
        group.bench_with_input(BenchmarkId::new("send_shared", n), &n, |b, &n| {
            b.iter_batched(
                || setup_fanout(n),
                |mut rig| run_fanout_send_shared(&mut rig, PACKETS_PER_BATCH),
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fanout);
criterion_main!(benches);
