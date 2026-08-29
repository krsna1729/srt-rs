//! Fan-out benchmark: one upstream sender → N downstream connections.
//!
//! Measures per-packet CPU cost of a restreaming proxy that receives one
//! stream and re-sends to N subscribers. The hot-path copy amplification
//! is: for each incoming packet, the proxy calls `send(&payload)` on N
//! downstream connections, each of which does `payload.to_vec()` +
//! `clone().into_boxed_slice()` + `encode(extend_from_slice)`.
//!
//! This benchmark quantifies whether `Box<[u8]>` deep-copy fan-out is a
//! scaling bottleneck and gates the decision to introduce `Bytes`/shared
//! payloads into the protocol crate.

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

fn run_fanout_batch(rig: &mut FanoutRig, batch_size: u64) {
    let payload = [0x42u8; PAYLOAD_SIZE];
    let mut now_us = 20_000u64;

    for i in 0..batch_size {
        let now = ts(now_us);

        // Upstream: sender sends one packet
        rig.upstream_caller
            .send(black_box(&payload), now)
            .expect("upstream send");

        // Upstream: deliver to upstream listener (the proxy's receive side)
        for data in drain_sent(&mut rig.upstream_caller) {
            rig.upstream_listener
                .feed_recv_buf(black_box(&data), now)
                .expect("upstream recv");
        }

        // Proxy: extract the received payload
        let mut received_payload = None;
        while let Some(event) = rig.upstream_listener.poll_event() {
            if let shiguredo_srt::ConnectionEvent::DataReceived { payload, .. } = event {
                received_payload = Some(payload);
            }
        }
        let rx_payload = received_payload.expect("should receive data");

        // Fan-out: send the same payload to all N downstream connections
        for (downstream_caller, downstream_listener) in &mut rig.downstream {
            downstream_caller
                .send(black_box(&rx_payload), now)
                .expect("downstream send");

            // Deliver to downstream listener (simulates the subscriber receiving)
            for data in drain_sent(downstream_caller) {
                downstream_listener
                    .feed_recv_buf(black_box(&data), now)
                    .expect("downstream recv");
            }
            while downstream_listener.poll_event().is_some() {}
        }

        // ACK round-trips to keep windows open
        if (i + 1) % ACK_EVERY_N == 0 {
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

        now_us += 1_000;
    }
}

fn bench_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout");
    for &n in FANOUT_SIZES {
        group.throughput(Throughput::Elements(PACKETS_PER_BATCH * n as u64));
        group.bench_with_input(BenchmarkId::new("plain_fanout", n), &n, |b, &n| {
            b.iter_batched(
                || setup_fanout(n),
                |mut rig| run_fanout_batch(&mut rig, PACKETS_PER_BATCH),
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fanout);
criterion_main!(benches);
