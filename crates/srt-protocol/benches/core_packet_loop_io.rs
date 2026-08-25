//! Real-loopback-UDP companion to `core_packet_loop.rs`.
//!
//! `core_packet_loop.rs` deliberately has zero syscalls, which makes its
//! numbers *not* directly comparable to `benches/srt_ingest_latency.rs`
//! (the application crate) -- that bench's numbers are dominated by real
//! loopback UDP syscalls and libsrt's own internal worker threads, which
//! `core_packet_loop.rs` has no equivalent of. This bench adds that same
//! kind of overhead on top of the Rust Core (two real OS threads, real
//! `UdpSocket` traffic on loopback, no in-process byte-passing) so the two
//! codebases can be compared on equal footing: Core-plus-a-minimal-driver
//! vs. libsrt-plus-its-own-driver, both paying real socket cost.
//!
//! Matches `srt_ingest_latency.rs`'s own structure directly: same
//! `b.iter_custom` shape reusing one persistent connection across all
//! measured iterations of a sample. `PACKETS_PER_ITER_VALUES` includes 1 to
//! isolate true single-packet cost -- each `iter_custom` sample still pays
//! one connection-setup + driver-thread-spawn cost regardless of this value,
//! so a batch of 1 also checks whether that fixed per-sample overhead is
//! hiding in the amortized larger-batch numbers.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection, TimerId,
    Timestamp,
};
use std::hint::black_box;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const PAYLOAD_SIZE: usize = 1316;
/// 1 isolates true single-packet cost; 8 matches libsrt's own
/// `benches/srt_ingest_latency.rs` `PACKETS_PER_ITER` for direct comparison.
const PACKETS_PER_ITER_VALUES: &[u64] = &[1, 8];
/// How often the listener's background driver thread fires the ACK timer
/// while idle -- matches the ~10ms cadence `core_packet_loop.rs` and real
/// SRT both use (see that file's `ACK_EVERY_N_PACKETS` doc comment).
const SOCKET_POLL_TIMEOUT: Duration = Duration::from_millis(10);

fn connection_options(passphrase: Option<&str>) -> ConnectionOptions {
    ConnectionOptions {
        tsbpd_delay: 0,
        passphrase: passphrase.map(str::to_string),
        crypto_salt: passphrase.map(|_| [0x11u8; 16]),
        crypto_sek: passphrase.map(|_| vec![0x22u8; 16]),
        ..Default::default()
    }
}

fn drain_sent(conn: &mut SrtConnection, sock: &UdpSocket) {
    while let Some(out) = conn.poll_output() {
        if let ConnectionOutput::SendPacket(data) = out {
            let _ = sock.send(&data);
        }
    }
}

fn bind_connected_pair() -> (UdpSocket, UdpSocket) {
    let a = UdpSocket::bind("127.0.0.1:0").expect("bind a");
    let b = UdpSocket::bind("127.0.0.1:0").expect("bind b");
    a.connect(b.local_addr().unwrap()).expect("connect a->b");
    b.connect(a.local_addr().unwrap()).expect("connect b->a");
    (a, b)
}

fn now_ts(start: Instant) -> Timestamp {
    Timestamp::from_micros(start.elapsed().as_micros() as u64)
}

/// Establish a connected caller/listener pair over real loopback UDP
/// sockets (handshake bytes actually go through the kernel), outside any
/// timed region -- mirrors `srt_ingest_latency.rs::make_srt_pair` excluding
/// its connection setup from the measured time.
fn setup_connected_pair_io(
    passphrase: Option<&str>,
) -> (SrtConnection, UdpSocket, SrtConnection, UdpSocket, Instant) {
    let mut caller = SrtConnection::new_caller(connection_options(passphrase));
    let mut listener = SrtConnection::new_listener(connection_options(passphrase));
    let (caller_sock, listener_sock) = bind_connected_pair();
    caller_sock
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    listener_sock
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let start = Instant::now();

    caller
        .connect(now_ts(start))
        .expect("connect() should succeed");
    drain_sent(&mut caller, &caller_sock);

    let mut buf = [0u8; 2048];
    for _ in 0..200 {
        if let Ok(n) = listener_sock.recv(&mut buf) {
            let _ = listener.feed_recv_buf(&buf[..n], now_ts(start));
            drain_sent(&mut listener, &listener_sock);
        }
        if let Ok(n) = caller_sock.recv(&mut buf) {
            let _ = caller.feed_recv_buf(&buf[..n], now_ts(start));
            drain_sent(&mut caller, &caller_sock);
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, caller_sock, listener, listener_sock, start);
        }
    }
    panic!(
        "connection not established over UDP loopback: caller={:?} listener={:?}",
        caller.state(),
        listener.state()
    );
}

/// Background driver for the listener side: decodes inbound DATA packets,
/// counts delivered payloads, and fires the ACK timer on a fixed cadence
/// while idle -- the minimal stand-in for what a real Driver's timer wheel
/// and recv loop would do in a production application.
fn run_listener_driver(
    mut listener: SrtConnection,
    listener_sock: UdpSocket,
    start: Instant,
    received: &AtomicU64,
    stop: &AtomicBool,
) {
    listener_sock
        .set_read_timeout(Some(SOCKET_POLL_TIMEOUT))
        .unwrap();
    let mut buf = [0u8; 2048];
    loop {
        match listener_sock.recv(&mut buf) {
            Ok(n) => {
                let now = now_ts(start);
                if listener.feed_recv_buf(&buf[..n], now).is_ok() {
                    while let Some(ev) = listener.poll_event() {
                        if matches!(ev, ConnectionEvent::DataReceived { .. }) {
                            received.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                drain_sent(&mut listener, &listener_sock);
            }
            Err(_) => {
                let now = now_ts(start);
                let _ = listener.handle_timer(TimerId::Ack, now);
                drain_sent(&mut listener, &listener_sock);
            }
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
    }
}

fn bench_round_trip(c: &mut Criterion, label: &str, passphrase: Option<&str>) {
    let mut group = c.benchmark_group("core_packet_loop_io");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(30);

    for &packets_per_iter in PACKETS_PER_ITER_VALUES {
        group.throughput(Throughput::Bytes(PAYLOAD_SIZE as u64 * packets_per_iter));
        group.bench_with_input(
            BenchmarkId::new(label, packets_per_iter),
            &packets_per_iter,
            |b, &packets_per_iter| {
                b.iter_custom(|iters| {
                    let (mut caller, caller_sock, listener, listener_sock, start) =
                        setup_connected_pair_io(passphrase);
                    caller_sock
                        .set_read_timeout(Some(SOCKET_POLL_TIMEOUT))
                        .unwrap();

                    let total_packets = iters * packets_per_iter;
                    let received = AtomicU64::new(0);
                    let stop = AtomicBool::new(false);

                    thread::scope(|s| {
                        let received_ref = &received;
                        let stop_ref = &stop;
                        s.spawn(move || {
                            run_listener_driver(
                                listener,
                                listener_sock,
                                start,
                                received_ref,
                                stop_ref,
                            )
                        });

                        let payload = [0x42u8; PAYLOAD_SIZE];
                        let send_start = Instant::now();
                        let mut buf = [0u8; 2048];
                        for _ in 0..total_packets {
                            loop {
                                if caller.can_send() {
                                    break;
                                }
                                if let Ok(n) = caller_sock.recv(&mut buf) {
                                    let now = now_ts(start);
                                    let _ = caller.feed_recv_buf(&buf[..n], now);
                                    drain_sent(&mut caller, &caller_sock);
                                }
                            }
                            let now = now_ts(start);
                            caller
                                .send(black_box(&payload), now)
                                .expect("send should succeed once can_send() is true");
                            drain_sent(&mut caller, &caller_sock);
                        }
                        while received_ref.load(Ordering::Relaxed) < total_packets {
                            if let Ok(n) = caller_sock.recv(&mut buf) {
                                let now = now_ts(start);
                                let _ = caller.feed_recv_buf(&buf[..n], now);
                                drain_sent(&mut caller, &caller_sock);
                            }
                        }
                        let elapsed = send_start.elapsed();
                        stop_ref.store(true, Ordering::Relaxed);
                        elapsed
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_plain(c: &mut Criterion) {
    bench_round_trip(c, "plain_send_recv", None);
}

fn bench_encrypted(c: &mut Criterion) {
    bench_round_trip(c, "aes128_send_recv", Some("bench-passphrase"));
}

criterion_group!(benches, bench_plain, bench_encrypted);
criterion_main!(benches);
