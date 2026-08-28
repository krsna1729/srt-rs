use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection, TimerId, Timestamp,
};
use std::hint::black_box;

const BATCH_SIZE: u64 = 16;
const ACK_EVERY_N: u64 = 8;

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

fn setup_connected_pair() -> (SrtConnection, SrtConnection) {
    let opts = ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    };
    let mut caller = SrtConnection::new_caller(opts.clone());
    let mut listener = SrtConnection::new_listener(opts);

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
            while caller.poll_event().is_some() {}
            while listener.poll_event().is_some() {}
            return (caller, listener);
        }
    }
    panic!("connection not established");
}

fn run_message_batch(
    caller: &mut SrtConnection,
    listener: &mut SrtConnection,
    payload: &[u8],
    batch_size: u64,
) {
    let mut now_us = 20_000u64;
    for i in 0..batch_size {
        let now = ts(now_us);
        caller
            .send_message(black_box(payload), now)
            .expect("send_message");
        for data in drain_sent(caller) {
            listener.feed_recv_buf(black_box(&data), now).expect("feed");
        }
        while listener.poll_event().is_some() {}

        if (i + 1) % ACK_EVERY_N == 0 {
            let _ = listener.handle_timer(TimerId::Ack, now);
            for data in drain_sent(listener) {
                let _ = caller.feed_recv_buf(&data, now);
            }
        }
        now_us += 1_000;
    }
}

fn bench_reassembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("reassembly_overhead");

    // Single packet (assembler passthrough cost).
    let single_payload = vec![0x42u8; 1000];
    group.throughput(Throughput::Elements(BATCH_SIZE));
    group.bench_with_input(
        BenchmarkId::new("single_packet", BATCH_SIZE),
        &BATCH_SIZE,
        |b, &batch_size| {
            b.iter_batched(
                setup_connected_pair,
                |(mut caller, mut listener)| {
                    run_message_batch(&mut caller, &mut listener, &single_payload, batch_size)
                },
                BatchSize::SmallInput,
            );
        },
    );

    // 2-fragment message (~2600 bytes).
    let two_frag_payload = vec![0x42u8; 2600];
    group.bench_with_input(
        BenchmarkId::new("2_fragment", BATCH_SIZE),
        &BATCH_SIZE,
        |b, &batch_size| {
            b.iter_batched(
                setup_connected_pair,
                |(mut caller, mut listener)| {
                    run_message_batch(&mut caller, &mut listener, &two_frag_payload, batch_size)
                },
                BatchSize::SmallInput,
            );
        },
    );

    // 8-fragment message (~10KB).
    let eight_frag_payload = vec![0x42u8; 10_000];
    group.bench_with_input(
        BenchmarkId::new("8_fragment", BATCH_SIZE),
        &BATCH_SIZE,
        |b, &batch_size| {
            b.iter_batched(
                setup_connected_pair,
                |(mut caller, mut listener)| {
                    run_message_batch(&mut caller, &mut listener, &eight_frag_payload, batch_size)
                },
                BatchSize::SmallInput,
            );
        },
    );

    group.finish();
}

criterion_group!(benches, bench_reassembly);
criterion_main!(benches);
