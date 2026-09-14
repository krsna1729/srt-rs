//! Decision-quality SRT crypto fanout benchmark.
//!
//! Measures two different questions:
//!
//! 1. `primitive/*`:
//!    Cached RustCrypto/SRT crypto cost while round-robin cycling through
//!    1/10/100/600/1000 independent CryptoContexts with distinct key material.
//!    This exposes key-schedule/cache-locality effects hidden by a one-context
//!    microbenchmark.
//!
//! 2. `srt_tx/*`:
//!    The current real SrtConnection egress path for the same fanouts:
//!    send_shared(Bytes)
//!    -> sender bookkeeping / packetization
//!    -> SRT header
//!    -> encryption
//!    -> ConnectionOutput::SendPacket(Vec<u8>)
//!    Receive/ACK work needed to keep the sender windows healthy is performed
//!    OUTSIDE the timed region, so this is an egress-side measurement.
//!
//! Setup/handshake/PBKDF2 are not timed.
//!
//! Run:
//!   env -u RUSTFLAGS cargo bench -p srt-proto --bench crypto_fanout_x86
//!
//! Optional filtering examples:
//!   ... -- primitive
//!   ... -- srt_tx
//!   ... -- 'srt_tx/ctr128/1000'
//!
//! On x86_64 the benchmark prints detected crypto/vector CPU features.

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use srt_proto::crypto::{CipherMode, CryptoContext, KeyLength};
use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection, TimerId, Timestamp,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

const PAYLOAD_SIZE: usize = 1316;
const FANOUTS: &[usize] = &[1, 10, 100, 600, 1000];
const ACK_EVERY_ROUNDS: u64 = 8;

// Keep the whole suite practical while still producing stable enough
// decision-making numbers. Criterion's CLI can override these globally.
const SAMPLE_SIZE: usize = 30;
const WARMUP_SECS: u64 = 2;
const MEASUREMENT_SECS: u64 = 3;

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

#[cfg(target_arch = "x86_64")]
fn print_cpu_features() {
    let model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|line| line.strip_prefix("model name\t: ").map(str::to_owned))
        })
        .unwrap_or_else(|| "unknown".to_owned());

    eprintln!("\n=== SRT crypto fanout characterization ===");
    eprintln!("CPU: {model}");
    eprintln!("payload: {PAYLOAD_SIZE} bytes");
    eprintln!("fanouts: {FANOUTS:?}");
    eprintln!("aes:          {}", std::is_x86_feature_detected!("aes"));
    eprintln!(
        "pclmulqdq:    {}",
        std::is_x86_feature_detected!("pclmulqdq")
    );
    eprintln!("avx2:         {}", std::is_x86_feature_detected!("avx2"));
    eprintln!("vaes:         {}", std::is_x86_feature_detected!("vaes"));
    eprintln!(
        "vpclmulqdq:   {}",
        std::is_x86_feature_detected!("vpclmulqdq")
    );
    eprintln!("avx512f:      {}", std::is_x86_feature_detected!("avx512f"));
    eprintln!();
}

#[cfg(not(target_arch = "x86_64"))]
fn print_cpu_features() {
    eprintln!(
        "\ncrypto_fanout_x86 is intended primarily for x86_64; running on {}",
        std::env::consts::ARCH
    );
}

#[derive(Clone, Copy, Debug)]
enum CipherSpec {
    Plain,
    Ctr128,
    Ctr256,
    Gcm128,
    Gcm256,
}

impl CipherSpec {
    fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Ctr128 => "ctr128",
            Self::Ctr256 => "ctr256",
            Self::Gcm128 => "gcm128",
            Self::Gcm256 => "gcm256",
        }
    }

    fn mode(self) -> CipherMode {
        match self {
            Self::Plain | Self::Ctr128 | Self::Ctr256 => CipherMode::Ctr,
            Self::Gcm128 | Self::Gcm256 => CipherMode::Gcm,
        }
    }

    fn key_length(self) -> KeyLength {
        match self {
            Self::Plain | Self::Ctr128 | Self::Gcm128 => KeyLength::Aes128,
            Self::Ctr256 | Self::Gcm256 => KeyLength::Aes256,
        }
    }

    fn encrypted(self) -> bool {
        !matches!(self, Self::Plain)
    }
}

const CRYPTO_SPECS: &[CipherSpec] = &[
    CipherSpec::Ctr128,
    CipherSpec::Ctr256,
    CipherSpec::Gcm128,
    CipherSpec::Gcm256,
];

const SRT_SPECS: &[CipherSpec] = &[
    CipherSpec::Plain,
    CipherSpec::Ctr128,
    CipherSpec::Ctr256,
    CipherSpec::Gcm128,
    CipherSpec::Gcm256,
];

fn unique_salt(i: usize) -> [u8; 16] {
    let mut salt = [0u8; 16];
    let x = i as u64;
    salt[..8].copy_from_slice(&x.to_le_bytes());
    salt[8..].copy_from_slice(&(x.rotate_left(23) ^ 0x9e37_79b9_7f4a_7c15).to_le_bytes());
    salt
}

fn unique_sek(i: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x = (i as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(0xa5a5_5a5a_dead_beef);

    for (j, b) in out.iter_mut().enumerate() {
        // Deterministic per-context key material. This is benchmark material,
        // not production key generation.
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x as u8) ^ (j as u8).wrapping_mul(31);
    }
    out
}

fn make_crypto_context(spec: CipherSpec, i: usize) -> CryptoContext {
    debug_assert!(spec.encrypted());
    CryptoContext::new_sender(
        "bench-passphrase",
        spec.key_length(),
        unique_salt(i),
        &unique_sek(i, spec.key_length().len()),
        spec.mode(),
    )
    .expect("CryptoContext::new_sender")
}

struct PrimitiveRig {
    contexts: Vec<CryptoContext>,
    payloads: Vec<Vec<u8>>,
    packet_indices: Vec<u32>,
    aad: Vec<[u8; 16]>,
}

impl PrimitiveRig {
    fn new(spec: CipherSpec, fanout: usize) -> Self {
        let contexts = (0..fanout).map(|i| make_crypto_context(spec, i)).collect();

        let payloads = (0..fanout)
            .map(|i| vec![0x42u8 ^ (i as u8); PAYLOAD_SIZE])
            .collect();

        let packet_indices = vec![1u32; fanout];

        let aad = (0..fanout)
            .map(|i| {
                let mut h = [0u8; 16];
                h[..8].copy_from_slice(&(i as u64).to_le_bytes());
                h[8..].copy_from_slice(&(!(i as u64)).to_le_bytes());
                h
            })
            .collect();

        Self {
            contexts,
            payloads,
            packet_indices,
            aad,
        }
    }

    fn round(&mut self, spec: CipherSpec) {
        match spec {
            CipherSpec::Ctr128 | CipherSpec::Ctr256 => {
                for i in 0..self.contexts.len() {
                    let idx = self.packet_indices[i];
                    self.packet_indices[i] = idx.wrapping_add(1);

                    let key_flag = self.contexts[i]
                        .encrypt(idx, black_box(self.payloads[i].as_mut_slice()))
                        .expect("CTR encrypt");
                    black_box(key_flag);
                }
            }
            CipherSpec::Gcm128 | CipherSpec::Gcm256 => {
                for i in 0..self.contexts.len() {
                    let idx = self.packet_indices[i];
                    self.packet_indices[i] = idx.wrapping_add(1);

                    let out = self.contexts[i]
                        .encrypt_gcm_detached(
                            idx,
                            black_box(&self.aad[i]),
                            black_box(self.payloads[i].as_mut_slice()),
                        )
                        .expect("GCM encrypt");
                    black_box(out);
                }
            }
            CipherSpec::Plain => unreachable!(),
        }
    }
}

fn bench_primitive_multi_context(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitive");
    group.sample_size(SAMPLE_SIZE);
    group.warm_up_time(Duration::from_secs(WARMUP_SECS));
    group.measurement_time(Duration::from_secs(MEASUREMENT_SECS));

    for &spec in CRYPTO_SPECS {
        for &fanout in FANOUTS {
            let mut rig = PrimitiveRig::new(spec, fanout);

            // One Criterion "iteration" is one packet per context.
            group.throughput(Throughput::Elements(fanout as u64));
            group.bench_with_input(
                BenchmarkId::new(spec.name(), fanout),
                &fanout,
                |b, &_fanout| {
                    b.iter(|| rig.round(spec));
                },
            );
        }
    }

    group.finish();
}

fn connection_options(spec: CipherSpec, i: usize) -> ConnectionOptions {
    let mut options = ConnectionOptions {
        tsbpd_delay: 0,
        cipher_mode: spec.mode(),
        key_length: spec.key_length(),
        ..Default::default()
    };

    if spec.encrypted() {
        options.passphrase = Some(format!("bench-passphrase-{i:06}"));
        options.crypto_salt = Some(unique_salt(i));
        options.crypto_sek = Some(unique_sek(i, spec.key_length().len()));
    }

    options
}

/// Consume every output action, returning packet Vecs only.
///
/// Important: `poll_output()` ordering also includes timer actions, so we must
/// keep polling after non-packet actions rather than stopping at the first one.
fn drain_packets(conn: &mut SrtConnection, dst: &mut Vec<Vec<u8>>) {
    dst.clear();
    while let Some(out) = conn.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = out {
            dst.push(packet);
        }
    }
}

fn setup_connected_pair(spec: CipherSpec, i: usize) -> (SrtConnection, SrtConnection) {
    let caller_options = connection_options(spec, i);
    let listener_options = connection_options(spec, i);

    let mut caller = SrtConnection::new_caller(caller_options);
    let mut listener = SrtConnection::new_listener(listener_options);

    caller.connect(ts(0)).expect("caller connect");

    let mut a_to_b = Vec::with_capacity(8);
    let mut b_to_a = Vec::with_capacity(8);

    for step in 0..32u64 {
        let now = ts(step * 10_000);

        drain_packets(&mut caller, &mut a_to_b);
        for packet in &a_to_b {
            listener
                .feed_recv_buf(packet, now)
                .expect("listener handshake receive");
        }

        drain_packets(&mut listener, &mut b_to_a);
        for packet in &b_to_a {
            caller
                .feed_recv_buf(packet, now)
                .expect("caller handshake receive");
        }

        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            // Consume any immediately queued timer/control actions so timed
            // steady state does not inherit setup noise.
            a_to_b.clear();
            b_to_a.clear();
            drain_packets(&mut caller, &mut a_to_b);
            for packet in &a_to_b {
                listener
                    .feed_recv_buf(packet, now)
                    .expect("listener final handshake receive");
            }
            drain_packets(&mut listener, &mut b_to_a);
            for packet in &b_to_a {
                caller
                    .feed_recv_buf(packet, now)
                    .expect("caller final handshake receive");
            }
            return (caller, listener);
        }
    }

    panic!(
        "connection {i} not established for {}: caller={:?} listener={:?}",
        spec.name(),
        caller.state(),
        listener.state()
    );
}

struct SrtTxRig {
    callers: Vec<SrtConnection>,
    listeners: Vec<SrtConnection>,
    // Per-connection packet storage. The outer/inner containers are reused.
    // The actual packet Vec allocation inside ConnectionOutput is part of the
    // CURRENT SRT TX path and therefore deliberately remains timed.
    wires: Vec<Vec<Vec<u8>>>,
    ack_wires: Vec<Vec<Vec<u8>>>,
    ackack_wires: Vec<Vec<Vec<u8>>>,
    shared_payload: Bytes,
    round: u64,
    now_us: u64,
}

impl SrtTxRig {
    fn new(spec: CipherSpec, fanout: usize) -> Self {
        let mut callers = Vec::with_capacity(fanout);
        let mut listeners = Vec::with_capacity(fanout);

        for i in 0..fanout {
            let (caller, listener) = setup_connected_pair(spec, i);
            callers.push(caller);
            listeners.push(listener);
        }

        let wires = (0..fanout).map(|_| Vec::with_capacity(2)).collect();
        let ack_wires = (0..fanout).map(|_| Vec::with_capacity(4)).collect();
        let ackack_wires = (0..fanout).map(|_| Vec::with_capacity(4)).collect();

        Self {
            callers,
            listeners,
            wires,
            ack_wires,
            ackack_wires,
            shared_payload: Bytes::from(vec![0x42u8; PAYLOAD_SIZE]),
            round: 0,
            now_us: 1_000_000,
        }
    }

    /// Time only current caller-side egress:
    ///
    /// shared Bytes clone -> send_shared -> sender/protocol -> encrypt ->
    /// ConnectionOutput::SendPacket(Vec<u8>) -> poll_output drain.
    ///
    /// Delivery/decrypt/ACK are done after the timer stops.
    #[allow(clippy::cognitive_complexity)]
    fn timed_tx_round(&mut self) -> Duration {
        let now = ts(self.now_us);

        let start = Instant::now();

        for i in 0..self.callers.len() {
            self.wires[i].clear();

            self.callers[i]
                .send_shared(black_box(self.shared_payload.clone()), now)
                .expect("send_shared");

            while let Some(out) = self.callers[i].poll_output() {
                if let ConnectionOutput::SendPacket(packet) = out {
                    self.wires[i].push(packet);
                }
            }
        }

        let elapsed = start.elapsed();

        // Everything below is deliberately outside the measured TX region.
        for i in 0..self.listeners.len() {
            for packet in &self.wires[i] {
                self.listeners[i]
                    .feed_recv_buf(black_box(packet), now)
                    .expect("listener DATA receive");
            }

            while self.listeners[i].poll_event().is_some() {}
        }

        self.round += 1;

        // Drive receiver -> sender control traffic OUTSIDE the timed region.
        //
        // The previous version only delivered ACK to the caller. A full SRT
        // ACK exchange also produces ACKACK back to the receiver. If ACKACK is
        // never drained/delivered, the long-running benchmark eventually stops
        // making forward acknowledgement progress and the caller's retained
        // send window fills. Short fresh-connection benchmarks hide this.
        //
        // We also drain any immediately generated receiver control packets
        // every round (e.g. light ACK / KM response), while firing the full
        // ACK timer at the same 8-packet cadence used by the repository's
        // existing core_packet_loop benchmark.
        for i in 0..self.listeners.len() {
            if self.round.is_multiple_of(ACK_EVERY_ROUNDS) {
                let _ = self.listeners[i].handle_timer(TimerId::Ack, now);
            }

            self.ack_wires[i].clear();
            while let Some(out) = self.listeners[i].poll_output() {
                if let ConnectionOutput::SendPacket(packet) = out {
                    self.ack_wires[i].push(packet);
                }
            }

            for packet in &self.ack_wires[i] {
                self.callers[i]
                    .feed_recv_buf(packet, now)
                    .expect("caller control receive");
            }

            // ACK processing can queue ACKACK (and key-management control).
            // Deliver it back so the receiver's ACK state also advances.
            self.ackack_wires[i].clear();
            while let Some(out) = self.callers[i].poll_output() {
                if let ConnectionOutput::SendPacket(packet) = out {
                    self.ackack_wires[i].push(packet);
                }
            }

            for packet in &self.ackack_wires[i] {
                self.listeners[i]
                    .feed_recv_buf(packet, now)
                    .expect("listener ACKACK/control receive");
            }

            while self.callers[i].poll_event().is_some() {}
            while self.listeners[i].poll_event().is_some() {}
        }

        // ~1 packet/ms is close to the intended 8 Mbps / 1316-byte pacing
        // scale and keeps the synthetic clock moving across ACK periods.
        self.now_us = self.now_us.saturating_add(1_000);
        elapsed
    }
}

fn bench_real_srt_tx(c: &mut Criterion) {
    let mut group = c.benchmark_group("srt_tx");
    group.sample_size(SAMPLE_SIZE);
    group.warm_up_time(Duration::from_secs(WARMUP_SECS));
    group.measurement_time(Duration::from_secs(MEASUREMENT_SECS));

    for &spec in SRT_SPECS {
        for &fanout in FANOUTS {
            eprintln!(
                "setting up srt_tx/{}/{} independent connections...",
                spec.name(),
                fanout
            );
            let mut rig = SrtTxRig::new(spec, fanout);

            // One Criterion iteration is one DATA send per logical destination.
            group.throughput(Throughput::Elements(fanout as u64));

            group.bench_with_input(
                BenchmarkId::new(spec.name(), fanout),
                &fanout,
                |b, &_fanout| {
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            total += rig.timed_tx_round();
                        }
                        total
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_all(c: &mut Criterion) {
    print_cpu_features();
    bench_primitive_multi_context(c);
    bench_real_srt_tx(c);
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
