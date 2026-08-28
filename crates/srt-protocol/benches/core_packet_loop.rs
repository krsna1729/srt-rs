//! Core-only per-packet CPU cost benchmark, no I/O in the way.
//!
//! This is the primary technical kill-switch benchmark for
//! "is a clean-sheet Rust protocol layer cheaper per packet than libsrt's,
//! in a pure micro-benchmark with no I/O in the way." Because
//! `SrtConnection` is sans-I/O, this measures
//! genuine protocol-layer cost (packetization, sequence/ACK bookkeeping,
//! buffer management, and -- in the encrypted variant -- AES-CTR) with
//! zero syscalls anywhere in the timed region: no sockets, no threads, no
//! kernel involvement at all. Compare against libsrt's own per-packet cost
//! via `benches/srt_ingest_latency.rs` (the application crate) and the
//! isolated C throughput floor in `test/native/srt-scaling/`.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{
    CipherMode, ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection, TimerId,
    Timestamp,
};
use std::hint::black_box;

/// SRT live-mode payload ceiling (`SRT_LIVE_MAX_PLSIZE` minus headers,
/// matches this repo's `MAX_SRT_MESSAGE_PAYLOAD` in
/// `src/media/srt/egress_engine.rs` in the application using this crate).
const PAYLOAD_SIZE: usize = 1316;

/// Batch sizes measured per run. 1 isolates true single-packet cost (no
/// amortization across a batch -- confirms the steady-state number isn't a
/// batching artifact); 8 matches libsrt's own `benches/srt_ingest_latency.rs`
/// `PACKETS_PER_ITER` for a direct comparison; 64 is the original
/// steady-state batch. All stay well under `DEFAULT_FLOW_WINDOW` (8192) --
/// each batch starts from a freshly (but realistically) established
/// connection with zero packets in flight.
const BATCH_SIZES: &[u64] = &[1, 8, 16, 24, 32, 64];

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

/// Drain every queued output and hand back only the `SendPacket` bytes, in
/// order. `poll_output()` pops a `VecDeque` front regardless of variant, so
/// a `while let Some(ConnectionOutput::SendPacket(data)) = conn.poll_output()`
/// filter silently drops (and stops the loop at) the first `SetTimer`/
/// `ClearTimer` entry it meets -- orphaning any `SendPacket`s still queued
/// behind it. Matches the drain pattern `crates/srt-bench/src/driver.rs`
/// already uses for exactly this reason.
fn drain_sent(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    while let Some(out) = conn.poll_output() {
        if let ConnectionOutput::SendPacket(data) = out {
            sent.push(data);
        }
    }
    sent
}

fn connection_options_with_mode(
    passphrase: Option<&str>,
    cipher_mode: CipherMode,
) -> ConnectionOptions {
    ConnectionOptions {
        tsbpd_delay: 0,
        passphrase: passphrase.map(str::to_string),
        crypto_salt: passphrase.map(|_| [0x11u8; 16]),
        crypto_sek: passphrase.map(|_| vec![0x22u8; 16]),
        cipher_mode,
        ..Default::default()
    }
}

fn connection_options(passphrase: Option<&str>) -> ConnectionOptions {
    connection_options_with_mode(passphrase, CipherMode::Ctr)
}

/// Establish a connected caller/listener pair via the sans-I/O handshake
/// state machine directly (no sockets) -- mirrors
/// `tests/test_srt_connection.rs`'s `establish_connection` helper.
fn setup_connected_pair(passphrase: Option<&str>) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(connection_options(passphrase));
    let mut listener = SrtConnection::new_listener(connection_options(passphrase));

    caller.connect(ts(0)).expect("connect() should succeed");

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
    panic!(
        "connection not established: caller={:?} listener={:?}",
        caller.state(),
        listener.state()
    );
}

/// How often (in packets) to drive an ACK round-trip. `SenderBuffer`'s
/// congestion window starts at a small fixed value (16 packets,
/// `srt_sender.rs`) and only grows via ACK feedback -- without any ACK
/// processing at all, `send()` blocks on a full window well before
/// `PACKETS_PER_BATCH` sends. Real SRT paces ACKs on a ~10ms timer, not
/// per-packet; ACKing more often here is a deliberate benchmark
/// simplification to keep the window open, and is itself part of the
/// realistic steady-state cost this benchmark measures (ACK generation,
/// parsing, and in-flight-packet bookkeeping are real per-connection
/// costs, not free).
const ACK_EVERY_N_PACKETS: u64 = 8;

/// One full send -> packetize -> deliver -> decode(+decrypt) -> buffer
/// cycle, periodically interleaved with an ACK round-trip to keep the
/// congestion window open. This is the steady-state unit of work Phase 4's
/// kill-switch criterion measures.
fn run_batch(caller: &mut SrtConnection, listener: &mut SrtConnection, batch_size: u64) {
    let payload = [0x42u8; PAYLOAD_SIZE];
    let mut now_us = 20_000u64;
    for i in 0..batch_size {
        let now = ts(now_us);
        caller
            .send(black_box(&payload), now)
            .expect("send should succeed within the flow/congestion window");
        for data in drain_sent(caller) {
            listener
                .feed_recv_buf(black_box(&data), now)
                .expect("feed_recv_buf should decode a well-formed data packet");
        }
        // Drain DataReceived (and any other) events -- matches a real
        // application consuming the connection's output, and keeps the
        // event queue from growing across the batch.
        while listener.poll_event().is_some() {}

        if (i + 1) % ACK_EVERY_N_PACKETS == 0 {
            let _ = listener.handle_timer(TimerId::Ack, now);
            for data in drain_sent(listener) {
                let _ = caller.feed_recv_buf(&data, now);
            }
        }

        // Fixed synthetic pacing step, not tied to any real bitrate --
        // this benchmark measures per-packet CPU cost, not throughput
        // pacing behavior.
        now_us += 1_000;
    }
}

fn bench_plain(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_packet_loop");
    for &batch_size in BATCH_SIZES {
        group.throughput(Throughput::Elements(batch_size));
        group.bench_with_input(
            BenchmarkId::new("plain_send_recv", batch_size),
            &batch_size,
            |b, &batch_size| {
                b.iter_batched(
                    || setup_connected_pair(None),
                    |(mut caller, mut listener)| run_batch(&mut caller, &mut listener, batch_size),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_encrypted(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_packet_loop");
    for &batch_size in BATCH_SIZES {
        group.throughput(Throughput::Elements(batch_size));
        group.bench_with_input(
            BenchmarkId::new("aes128_send_recv", batch_size),
            &batch_size,
            |b, &batch_size| {
                b.iter_batched(
                    || setup_connected_pair(Some("bench-passphrase")),
                    |(mut caller, mut listener)| run_batch(&mut caller, &mut listener, batch_size),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn setup_connected_pair_gcm(passphrase: Option<&str>) -> (SrtConnection, SrtConnection) {
    let caller_opts = connection_options_with_mode(passphrase, CipherMode::Gcm);
    let listener_opts = connection_options_with_mode(passphrase, CipherMode::Gcm);
    let mut caller = SrtConnection::new_caller(caller_opts);
    let mut listener = SrtConnection::new_listener(listener_opts);

    caller.connect(ts(0)).expect("connect() should succeed");

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
    panic!(
        "GCM connection not established: caller={:?} listener={:?}",
        caller.state(),
        listener.state()
    );
}

fn bench_encrypted_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("core_packet_loop");
    for &batch_size in BATCH_SIZES {
        group.throughput(Throughput::Elements(batch_size));
        group.bench_with_input(
            BenchmarkId::new("aes128_gcm_send_recv", batch_size),
            &batch_size,
            |b, &batch_size| {
                b.iter_batched(
                    || setup_connected_pair_gcm(Some("bench-passphrase")),
                    |(mut caller, mut listener)| run_batch(&mut caller, &mut listener, batch_size),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_plain, bench_encrypted, bench_encrypted_gcm);
criterion_main!(benches);
