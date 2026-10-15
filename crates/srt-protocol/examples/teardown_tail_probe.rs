//! Teardown-tail probe: how long a terminal SRT connection takes to hand its
//! retained packet storage back, measured phase by phase on real connection
//! paths.
//!
//! Restored measurement harness for the owner-local retirement contract (see
//! `crates/srt-protocol/README.md` and
//! `docs/production-progress.md` "Segmented payload retirement and its
//! measurement limits"). The case names and the TSV header are the ones the
//! deleted probe used, so old and new tables stay comparable.
//!
//! Phases, measured separately for every sample:
//!
//! - `detach`: `SrtConnection::into_retirement()`.
//! - `reclaim`: repeated `ConnectionRetirement::reclaim(budget)` visits until
//!   `is_complete()`.
//! - `final-drop`: the last Rust drop, after completion.
//! - `none`: the whole lifecycle of one sample (the three phases summed),
//!   which is what the previous probe's single `phase=none` row reported.
//!
//! `step_wall_max_us` / `step_cpu_max_us` are the largest single visit or
//! phase step: the bound that matters, because no single lifecycle step may do
//! window-scale work.
//!
//! ```text
//! taskset -c 2 teardown_tail_probe <case|all> <samples> [budget]
//! taskset -c 2 teardown_tail_probe <samples> [budget]          # all cases
//! ```
//!
//! Clocks: wall time is `std::time::Instant` (`CLOCK_MONOTONIC`); thread CPU
//! time is `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`. Each phase boundary and
//! each reclaim visit reads each clock once, so the per-visit overhead is part
//! of the phase totals. TSV goes to stdout; shape/legend lines go to stderr.

use std::io::Write;
use std::time::Instant;

use srt_proto::wire::{DataPacket, PacketPosition};
use srt_proto::{
    Bytes, ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection,
    Timestamp,
};

/// Payload of one DATA packet in the recorded matrix (libsrt's live default).
const DEFAULT_PAYLOAD: usize = 1_316;
/// Default reclaim action budget per visit.
const DEFAULT_BUDGET: usize = 64;
/// Samples per case when the CLI omits the count.
const DEFAULT_SAMPLES: usize = 20;
/// The matrix's floor: fewer samples cannot support p50/p95/p99.
const MIN_SAMPLES: usize = 10;
/// Equal to `srt_proto::handshake::MAX_FLOW_WINDOW`: the window every
/// full-window case fills.
const WINDOW_PACKETS: u32 = 65_536;
/// The fragment count every 65,536-packet case retains.
const WINDOW_CHUNKS: u32 = WINDOW_PACKETS;
/// Messages x fragments of the `app-4096-fragment16` cases.
const APP_MESSAGES: u32 = 4_096;
const APP_FRAGMENTS: u32 = 16;
/// Passphrase fixture of the original probe.
const PASSPHRASE: &str = "teardown-probe-password";
const PAYLOAD_BYTE: u8 = 0x42;
/// TSBPD delay of the cases that must hold packets undelivered.
const TSBPD_FUTURE_MS: u16 = 60_000;
/// TSBPD delay of the cases that need immediate delivery.
const TSBPD_IMMEDIATE_MS: u16 = 0;
/// TSBPD delay of the cases where delivery timing is irrelevant.
const TSBPD_DEFAULT_MS: u16 = 120;
/// Injected fixtures feed every packet at one instant; the pair handshakes at
/// timestamp zero, so this stays inside the first TSBPD window.
const START_US: u64 = 20_000;
/// Feed instant of the injected (receive-side) fixtures. The listener's TSBPD
/// time base is its conclusion time minus the peer's handshake timestamp, so a
/// synthetic stream fed at this instant with [`INJECT_TIMESTAMP`] is due
/// immediately even though the handshake may take up to 90 ms of fixture time.
const INJECT_US: u64 = 10_000_000;
/// Session-relative timestamp the injected stream carries. A message's
/// fragments share one timestamp, which is the first-fragment source time.
const INJECT_TIMESTAMP: u32 = 0;
const HANDSHAKE_ROUND_US: u64 = 10_000;
/// Hard stop for a retirement that never completes.
const MAX_VISITS: usize = 1_000_000;

const HEADER: &str = "case\tn\twall_p50_us\twall_p95_us\twall_p99_us\twall_max_us\t\
cpu_p50_us\tcpu_p95_us\tcpu_p99_us\tcpu_max_us\tstep_wall_max_us\tstep_cpu_max_us\tphase\tvisits";

const PHASES: [&str; 3] = ["detach", "reclaim", "final-drop"];

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Case {
    EmptyPlain,
    Tx8192Plain,
    Tx65536Plain,
    Rx65536Future,
    App65536Single,
    App4096Fragment16,
    Partial65536Fragments,
    Tx65536Encrypted,
    Rx65536FutureEncrypted,
    App4096Fragment16Encrypted,
    AppOne82MiBMessage,
}

impl Case {
    const ALL: [Case; 11] = [
        Case::EmptyPlain,
        Case::Tx8192Plain,
        Case::Tx65536Plain,
        Case::Rx65536Future,
        Case::App65536Single,
        Case::App4096Fragment16,
        Case::Partial65536Fragments,
        Case::Tx65536Encrypted,
        Case::Rx65536FutureEncrypted,
        Case::App4096Fragment16Encrypted,
        Case::AppOne82MiBMessage,
    ];

    fn name(self) -> &'static str {
        match self {
            Case::EmptyPlain => "empty-plain",
            Case::Tx8192Plain => "tx-8192-plain",
            Case::Tx65536Plain => "tx-65536-plain",
            Case::Rx65536Future => "rx-65536-future",
            Case::App65536Single => "app-65536-single",
            Case::App4096Fragment16 => "app-4096-fragment16",
            Case::Partial65536Fragments => "partial-65536-fragments",
            Case::Tx65536Encrypted => "tx-65536-encrypted",
            Case::Rx65536FutureEncrypted => "rx-65536-future-encrypted",
            Case::App4096Fragment16Encrypted => "app-4096-fragment16-encrypted",
            Case::AppOne82MiBMessage => "app-one-82MiB-message",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|case| case.name() == name)
    }
}

// ---------------------------------------------------------------------------
// clocks
// ---------------------------------------------------------------------------

/// One boundary reading: wall nanoseconds and thread-CPU nanoseconds since the
/// process origin.
#[derive(Clone, Copy)]
struct Reading {
    wall_ns: u64,
    cpu_ns: u64,
}

struct Clocks {
    wall_origin: Instant,
    cpu_origin: u64,
}

impl Clocks {
    fn new() -> Self {
        Self {
            wall_origin: Instant::now(),
            cpu_origin: cpu_nanos(),
        }
    }

    fn read(&self) -> Reading {
        let wall_ns = u64::try_from(Instant::now().duration_since(self.wall_origin).as_nanos())
            .unwrap_or(u64::MAX);
        Reading {
            wall_ns,
            cpu_ns: cpu_nanos().saturating_sub(self.cpu_origin),
        }
    }
}

const CLOCK_NOTE: &str = "wall=CLOCK_MONOTONIC(ca) cpu=CLOCK_THREAD_CPUTIME_ID";

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn cpu_nanos() -> u64 {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    unsafe extern "C" {
        fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
    }

    /// `CLOCK_THREAD_CPUTIME_ID` on Linux.
    const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` writes through a valid pointer to a live
    // `Timespec` and returns a status code the check below handles.
    let rc = unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime(CLOCK_THREAD_CPUTIME_ID)");
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// Non-Linux hosts have no thread-CPU clock in `std`; the CPU columns then
/// mirror the wall clock and `main` says so on stderr.
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn cpu_nanos() -> u64 {
    use std::sync::LazyLock;
    static ORIGIN: LazyLock<Instant> = LazyLock::new(Instant::now);
    u64::try_from(Instant::now().duration_since(*ORIGIN).as_nanos()).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// measurements
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct Phase {
    wall_ns: u64,
    cpu_ns: u64,
    step_wall_ns: u64,
    step_cpu_ns: u64,
    visits: usize,
    actions: usize,
}

/// What one sample retains, and what its retirement must then visit.
struct Shape {
    /// Human-readable retention description, printed per case.
    detail: String,
    /// Retained packet slots: the retirement visits at least this many.
    min_actions: usize,
    /// Upper bound for the cases that must keep the work O(1).
    max_actions: usize,
}

#[derive(Default)]
struct Accum {
    wall_ns: Vec<u64>,
    cpu_ns: Vec<u64>,
    step_wall_ns: u64,
    step_cpu_ns: u64,
    visits: usize,
    actions_min: Option<usize>,
    actions_max: usize,
}

impl Accum {
    fn add(&mut self, phase: &Phase) {
        self.wall_ns.push(phase.wall_ns);
        self.cpu_ns.push(phase.cpu_ns);
        self.step_wall_ns = self.step_wall_ns.max(phase.step_wall_ns);
        self.step_cpu_ns = self.step_cpu_ns.max(phase.step_cpu_ns);
        self.visits = self.visits.max(phase.visits);
        self.actions_min = Some(
            self.actions_min
                .map_or(phase.actions, |m| m.min(phase.actions)),
        );
        self.actions_max = self.actions_max.max(phase.actions);
    }

    fn row(&self, case: &str, phase: &str, samples: usize) -> String {
        let wall = micros(&self.wall_ns);
        let cpu = micros(&self.cpu_ns);
        format!(
            "{case}\t{samples}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{:.3}\t{phase}\t{}",
            percentile(&wall, 50),
            percentile(&wall, 95),
            percentile(&wall, 99),
            wall.last().copied().unwrap_or(0.0),
            percentile(&cpu, 50),
            percentile(&cpu, 95),
            percentile(&cpu, 99),
            cpu.last().copied().unwrap_or(0.0),
            ns_to_us(self.step_wall_ns),
            ns_to_us(self.step_cpu_ns),
            self.visits,
        )
    }
}

struct Sample {
    phases: [Phase; 3],
}

impl Sample {
    /// The whole lifecycle of this sample as one step.
    fn total(&self) -> Phase {
        let mut total = Phase {
            visits: 1 + self.phases[1].visits + 1,
            ..Phase::default()
        };
        for phase in &self.phases {
            total.wall_ns += phase.wall_ns;
            total.cpu_ns += phase.cpu_ns;
            total.step_wall_ns = total.step_wall_ns.max(phase.step_wall_ns);
            total.step_cpu_ns = total.step_cpu_ns.max(phase.step_cpu_ns);
            total.actions += phase.actions;
        }
        total
    }
}

fn ns_to_us(ns: u64) -> f64 {
    ns as f64 / 1_000.0
}

/// Microsecond samples, sorted ascending (so `last` is the maximum).
fn micros(samples: &[u64]) -> Vec<f64> {
    let mut us: Vec<f64> = samples.iter().copied().map(ns_to_us).collect();
    us.sort_by(f64::total_cmp);
    us
}

/// Nearest-rank percentile: no interpolation, so every reported number is one
/// of the observed samples.
fn percentile(sorted: &[f64], percent: usize) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (percent * sorted.len()).div_ceil(100).max(1) - 1;
    sorted[rank.min(sorted.len() - 1)]
}

/// Time `detach`, every `reclaim` visit, and the final drop of one fixture.
fn measure(conn: SrtConnection, budget: usize, shape: &Shape, clocks: &Clocks) -> Sample {
    let start = clocks.read();
    let mut retirement = conn.into_retirement();
    let after_detach = clocks.read();
    let detach = Phase {
        wall_ns: after_detach.wall_ns - start.wall_ns,
        cpu_ns: after_detach.cpu_ns - start.cpu_ns,
        step_wall_ns: after_detach.wall_ns - start.wall_ns,
        step_cpu_ns: after_detach.cpu_ns - start.cpu_ns,
        visits: 1,
        actions: 0,
    };

    let mut reclaim = Phase::default();
    loop {
        let before = clocks.read();
        let used = retirement.reclaim(budget);
        let after = clocks.read();
        let (wall_ns, cpu_ns) = (after.wall_ns - before.wall_ns, after.cpu_ns - before.cpu_ns);
        reclaim.visits += 1;
        reclaim.actions += used;
        reclaim.wall_ns += wall_ns;
        reclaim.cpu_ns += cpu_ns;
        reclaim.step_wall_ns = reclaim.step_wall_ns.max(wall_ns);
        reclaim.step_cpu_ns = reclaim.step_cpu_ns.max(cpu_ns);

        let complete = retirement.is_complete();
        assert!(
            used <= budget && (used > 0 || complete),
            "used <= budget && (used > 0 || retired.is_complete())"
        );
        if complete {
            break;
        }
        assert!(used > 0 && used <= budget, "used > 0 && used <= budget");
        assert!(reclaim.visits < MAX_VISITS, "retirement must progress");
    }

    let before_drop = clocks.read();
    assert!(
        retirement.is_complete(),
        "retirement must be complete before the final drop"
    );
    assert!(
        reclaim.actions >= shape.min_actions,
        "retirement visited {} packet slots, expected at least {}",
        reclaim.actions,
        shape.min_actions
    );
    assert!(
        reclaim.actions <= shape.max_actions,
        "retirement visited {} packet slots, expected at most {}",
        reclaim.actions,
        shape.max_actions
    );
    drop(retirement);
    let after_drop = clocks.read();
    let final_drop = Phase {
        wall_ns: after_drop.wall_ns - before_drop.wall_ns,
        cpu_ns: after_drop.cpu_ns - before_drop.cpu_ns,
        step_wall_ns: after_drop.wall_ns - before_drop.wall_ns,
        step_cpu_ns: after_drop.cpu_ns - before_drop.cpu_ns,
        visits: 1,
        actions: 0,
    };

    Sample {
        phases: [detach, reclaim, final_drop],
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn options(encrypted: bool, tsbpd_delay: u16) -> ConnectionOptions {
    ConnectionOptions {
        tsbpd_delay,
        flow_window_packets: WINDOW_PACKETS,
        receive_buffer_packets: WINDOW_PACKETS,
        delivery_queue_packets: WINDOW_PACKETS,
        passphrase: encrypted.then(|| PASSPHRASE.to_string()),
        ..Default::default()
    }
}

/// A real caller/listener pair: real handshake, real state machine, no socket.
fn pair(encrypted: bool, tsbpd_delay: u16) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(options(encrypted, tsbpd_delay));
    let mut listener = SrtConnection::new_listener(options(encrypted, tsbpd_delay));
    caller.connect(ts(0)).expect("connect");
    for round in 0..10u64 {
        let now = ts(round * HANDSHAKE_ROUND_US);
        transfer(&mut caller, &mut listener, now);
        transfer(&mut listener, &mut caller, now);
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            while caller.poll_event().is_some() {}
            while listener.poll_event().is_some() {}
            return (caller, listener);
        }
    }
    panic!("handshake did not establish");
}

/// Move every datagram `from` queued into `to`. Timer actions are dropped: the
/// fixture drives the state machine explicitly, so it needs no timer store.
fn transfer(from: &mut SrtConnection, to: &mut SrtConnection, now: Timestamp) -> usize {
    let mut moved = 0;
    while let Some(output) = from.poll_output().expect("poll_output") {
        if let ConnectionOutput::SendPacket(datagram) = output {
            to.feed_recv_buf(&datagram, now).expect("feed_recv_buf");
            moved += 1;
        }
    }
    moved
}

/// Drain and discard queued output (ACK/NAK/timer actions) so no peer retains
/// wire bytes that are not part of the case's shape.
fn drain_outputs(conn: &mut SrtConnection) -> usize {
    let mut drained = 0;
    while let Some(output) = conn.poll_output().expect("poll_output") {
        drained += usize::from(matches!(output, ConnectionOutput::SendPacket(_)));
    }
    drained
}

fn sender_packets(conn: &SrtConnection) -> u32 {
    conn.sender_stats().expect("sender stats").packets_in_buffer
}

fn receiver_packets(conn: &SrtConnection) -> u32 {
    conn.receiver_stats()
        .expect("receiver stats")
        .packets_in_buffer
}

/// Push `count` single-packet messages through the real caller send path, into
/// the real listener receive path, without acknowledging anything back.
fn send_singles(caller: &mut SrtConnection, listener: &mut SrtConnection, count: u32) {
    let payload = vec![PAYLOAD_BYTE; DEFAULT_PAYLOAD];
    let now = ts(START_US);
    for _ in 0..count {
        caller.send(&payload, now).expect("send");
        assert!(transfer(caller, listener, now) >= 1, "one DATA datagram");
        drain_outputs(listener);
    }
}

/// Push `messages` fragmented messages of `fragments` packets each through the
/// real `send_message` path, so the receiver reassembles each one.
fn send_messages(
    caller: &mut SrtConnection,
    listener: &mut SrtConnection,
    messages: u32,
    fragment_size: usize,
    fragments: u32,
) {
    let message = vec![PAYLOAD_BYTE; fragment_size * fragments as usize];
    let now = ts(START_US);
    for _ in 0..messages {
        caller.send_message(&message, now).expect("send_message");
        let moved = transfer(caller, listener, now);
        assert!(
            moved >= fragments as usize,
            "one message materialized all {fragments} fragments (moved {moved})"
        );
        drain_outputs(listener);
    }
}

/// The listener's expected first DATA sequence: the peer's initial sequence.
fn peer_sequence(caller: &SrtConnection) -> u32 {
    caller.next_sequence_number().expect("caller sender buffer")
}

/// Feed one synthetic fragment stream into a real, handshake-established
/// listener, through the public wire encoding and the real `feed_recv_buf`
/// path.
///
/// The caller's own `send_message` path cannot build a 65,536-fragment message
/// on this revision: one call queues every fragment datagram at once, which
/// exceeds the connection's `MAX_OUTPUT_QUEUE_ACTIONS` (8,192) and fails the
/// send. The recorded prototype's rows for those two shapes were built the same
/// way its notes describe ("partial messages have no Last fragment"), through
/// the wire format rather than the caller's connection state.
fn inject_fragments(listener: &mut SrtConnection, seq0: u32, fragments: u32, last: bool) {
    let chunk = vec![PAYLOAD_BYTE; DEFAULT_PAYLOAD];
    let now = ts(INJECT_US);
    let timestamp = INJECT_TIMESTAMP;
    let dest_socket_id = listener.socket_id();
    let mut datagram = Vec::with_capacity(16 + DEFAULT_PAYLOAD);
    for index in 0..fragments {
        let position = if index == 0 {
            PacketPosition::First
        } else if last && index + 1 == fragments {
            PacketPosition::Last
        } else {
            PacketPosition::Middle
        };
        let mut packet = DataPacket::new(
            seq0.wrapping_add(index),
            0,
            timestamp,
            dest_socket_id,
            Bytes::copy_from_slice(&chunk),
        );
        packet.position = position;
        datagram.clear();
        packet.encode(&mut datagram).expect("encode DATA");
        listener
            .feed_recv_buf(&datagram, now)
            .expect("feed_recv_buf");
    }
}

fn shape(detail: String, min_actions: usize) -> Shape {
    Shape {
        detail,
        min_actions,
        max_actions: usize::MAX,
    }
}

fn fixture(case: Case) -> (SrtConnection, Shape) {
    match case {
        Case::EmptyPlain => fixture_empty(),
        Case::Tx8192Plain => fixture_tx(false, 8_192),
        Case::Tx65536Plain => fixture_tx(false, WINDOW_CHUNKS),
        Case::Tx65536Encrypted => fixture_tx(true, WINDOW_CHUNKS),
        Case::Rx65536Future => fixture_future_rx(false),
        Case::Rx65536FutureEncrypted => fixture_future_rx(true),
        Case::App65536Single => fixture_app_single(),
        Case::App4096Fragment16 => fixture_app_fragments(false),
        Case::App4096Fragment16Encrypted => fixture_app_fragments(true),
        Case::Partial65536Fragments => fixture_incomplete_message(),
        Case::AppOne82MiBMessage => fixture_large_message(),
    }
}

fn cipher_prefix(encrypted: bool) -> &'static str {
    if encrypted { "AES-CTR: " } else { "" }
}

fn fixture_empty() -> (SrtConnection, Shape) {
    let (caller, listener) = pair(false, TSBPD_DEFAULT_MS);
    assert_eq!(sender_packets(&caller), 0);
    assert_eq!(receiver_packets(&listener), 0);
    drop(caller);
    (
        listener,
        Shape {
            detail: format!("no data; both {WINDOW_PACKETS}-packet windows allocated and empty"),
            min_actions: 0,
            max_actions: 64,
        },
    )
}

/// Caller-side retention: `count` packets in the send buffer, never acknowledged.
fn fixture_tx(encrypted: bool, count: u32) -> (SrtConnection, Shape) {
    let (mut caller, mut listener) = pair(encrypted, TSBPD_DEFAULT_MS);
    send_singles(&mut caller, &mut listener, count);
    let stats = caller.sender_stats().expect("sender stats");
    assert_eq!(stats.packets_in_buffer, count, "unacknowledged packets");
    drop(listener);
    let detail = format!(
        "{}caller send buffer retains {} packets ({} payload bytes) of {DEFAULT_PAYLOAD} B, nothing acknowledged",
        cipher_prefix(encrypted),
        stats.packets_in_buffer,
        stats.payload_bytes_in_buffer
    );
    (caller, shape(detail, count as usize))
}

/// Listener-side retention: the receive buffer holds a full window that TSBPD
/// has not released yet.
fn fixture_future_rx(encrypted: bool) -> (SrtConnection, Shape) {
    let (mut caller, mut listener) = pair(encrypted, TSBPD_FUTURE_MS);
    send_singles(&mut caller, &mut listener, WINDOW_CHUNKS);
    let stats = listener.receiver_stats().expect("receiver stats");
    assert_eq!(
        stats.packets_in_buffer, WINDOW_CHUNKS,
        "buffered, undelivered"
    );
    assert_eq!(stats.total_received, WINDOW_CHUNKS as u64);
    assert!(listener.poll_event().is_none(), "60 s playout delay holds");
    drop(caller);
    let detail = format!(
        "{}receive buffer holds {} of {} accepted packets undelivered (TSBPD {TSBPD_FUTURE_MS} ms, no time advance)",
        cipher_prefix(encrypted),
        stats.packets_in_buffer,
        stats.total_received
    );
    (listener, shape(detail, WINDOW_CHUNKS as usize))
}

/// Application backlog: a full window of single-packet messages delivered but
/// never polled.
fn fixture_app_single() -> (SrtConnection, Shape) {
    let (mut caller, mut listener) = pair(false, TSBPD_IMMEDIATE_MS);
    send_singles(&mut caller, &mut listener, WINDOW_CHUNKS);
    let stats = listener.receiver_stats().expect("receiver stats");
    assert_eq!(stats.total_received, WINDOW_CHUNKS as u64);
    assert_eq!(
        stats.packets_in_buffer, 0,
        "every packet moved into the application queue"
    );
    drop(caller);
    let detail = format!(
        "{WINDOW_CHUNKS} single-packet messages of {DEFAULT_PAYLOAD} B delivered to the unpolled application event queue ({WINDOW_CHUNKS} events, {WINDOW_CHUNKS} packet credits)"
    );
    (listener, shape(detail, WINDOW_CHUNKS as usize))
}

/// Application backlog of fragments: 4096 messages x 16 fragments, delivered
/// and never polled.
fn fixture_app_fragments(encrypted: bool) -> (SrtConnection, Shape) {
    let (mut caller, mut listener) = pair(encrypted, TSBPD_IMMEDIATE_MS);
    let fragment = caller.effective_max_payload_size();
    send_messages(
        &mut caller,
        &mut listener,
        APP_MESSAGES,
        fragment,
        APP_FRAGMENTS,
    );
    let stats = listener.receiver_stats().expect("receiver stats");
    let packets = u64::from(APP_MESSAGES) * u64::from(APP_FRAGMENTS);
    assert_eq!(stats.total_received, packets);
    assert_eq!(stats.packets_in_buffer, 0);
    drop(caller);
    let detail = format!(
        "{}application event queue holds {APP_MESSAGES} messages x {APP_FRAGMENTS} fragments of {fragment} B ({packets} packet credits); receiver buffer empty",
        cipher_prefix(encrypted)
    );
    (listener, shape(detail, packets as usize))
}

/// One incomplete message: fragments without a Last, so the assembler keeps a
/// single pending partial holding the whole stream.
fn fixture_incomplete_message() -> (SrtConnection, Shape) {
    let (caller, mut listener) = pair(false, TSBPD_IMMEDIATE_MS);
    let seq0 = peer_sequence(&caller);
    inject_fragments(&mut listener, seq0, WINDOW_CHUNKS, false);
    let stats = listener.receiver_stats().expect("receiver stats");
    assert_eq!(
        stats.total_received, WINDOW_CHUNKS as u64,
        "all fragments accepted"
    );
    assert_eq!(stats.total_lost, 0, "in-order stream infers no loss");
    assert_eq!(
        stats.packets_in_buffer, 0,
        "fragments moved into the pending partial"
    );
    assert!(
        listener.poll_event().is_none(),
        "incomplete message must not be delivered"
    );
    drop(caller);
    let detail = format!(
        "one incomplete {WINDOW_CHUNKS}-fragment message ({DEFAULT_PAYLOAD} B chunks, first sequence {seq0}, no Last fragment) held by the assembler's single pending partial"
    );
    (listener, shape(detail, WINDOW_CHUNKS as usize))
}

/// One complete message of a full window: 65,536 chunks, delivered and never
/// polled.
fn fixture_large_message() -> (SrtConnection, Shape) {
    let (caller, mut listener) = pair(false, TSBPD_IMMEDIATE_MS);
    let seq0 = peer_sequence(&caller);
    inject_fragments(&mut listener, seq0, WINDOW_CHUNKS, true);
    let stats = listener.receiver_stats().expect("receiver stats");
    let bytes = WINDOW_CHUNKS as u64 * DEFAULT_PAYLOAD as u64;
    assert_eq!(stats.total_received, WINDOW_CHUNKS as u64);
    assert_eq!(stats.total_lost, 0);
    assert_eq!(
        stats.packets_in_buffer, 0,
        "the whole message left the receiver buffer"
    );
    drop(caller);
    let detail = format!(
        "one complete {WINDOW_CHUNKS}-chunk message ({bytes} B, {DEFAULT_PAYLOAD} B chunks, first sequence {seq0}) delivered to the unpolled application event queue"
    );
    (listener, shape(detail, WINDOW_CHUNKS as usize))
}

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------

fn run_case(case: Case, samples: usize, budget: usize, clocks: &Clocks) -> String {
    // Warm up on one complete, untimed fixture/teardown cycle before timing.
    let (conn, shape) = fixture(case);
    let _warmup = measure(conn, budget, &shape, clocks);

    let mut phases: [Accum; 3] = Default::default();
    let mut total = Accum::default();
    let mut actions = (usize::MAX, 0usize);
    let mut visits = (usize::MAX, 0usize);
    for _ in 0..samples {
        let (conn, sample_shape) = fixture(case);
        let sample = measure(conn, budget, &sample_shape, clocks);
        for (accum, phase) in phases.iter_mut().zip(sample.phases.iter()) {
            accum.add(phase);
        }
        total.add(&sample.total());
        let reclaim = sample.phases[1];
        actions = (
            actions.0.min(reclaim.actions),
            actions.1.max(reclaim.actions),
        );
        visits = (visits.0.min(reclaim.visits), visits.1.max(reclaim.visits));
    }

    for (label, accum) in PHASES.iter().zip(phases.iter()) {
        println!("{}", accum.row(case.name(), label, samples));
    }
    println!("{}", total.row(case.name(), "none", samples));
    eprintln!(
        "# budget={budget} {} reclaim: visits={}..{} actions={}..{}",
        case.name(),
        visits.0,
        visits.1,
        actions.0,
        actions.1
    );
    shape.detail
}

/// Metadata-only sub-probe: consume the 82 MiB message's chunks through the
/// public cursor, then retire the consumed metadata under the same budget.
fn consumed_probe(samples: usize, budget: usize, clocks: &Clocks) {
    let mut phases: [Accum; 3] = Default::default();
    let mut total = Accum::default();
    for sample in 1..=samples {
        let (mut listener, _) = fixture(Case::AppOne82MiBMessage);
        let payload = loop {
            match listener.poll_event() {
                Some(ConnectionEvent::DataReceived { payload, .. }) => break payload,
                Some(_) => continue,
                None => panic!("completed large message missing"),
            }
        };
        drop(listener);
        let expected = WINDOW_CHUNKS as u64 * DEFAULT_PAYLOAD as u64;
        assert_eq!(payload.chunk_count(), WINDOW_CHUNKS as usize, "chunk count");
        assert_eq!(payload.len() as u64, expected, "message bytes");
        assert!(
            payload
                .chunks()
                .flat_map(|chunk| chunk.iter())
                .all(|byte| *byte == PAYLOAD_BYTE),
            "payload bytes"
        );

        let mut chunks = payload.into_chunks();
        let mut consumed = 0usize;
        for chunk in chunks.by_ref() {
            consumed += chunk.len();
        }
        assert_eq!(consumed as u64, expected, "consumed bytes");

        let start = clocks.read();
        let mut retirement = chunks.retire();
        let after_detach = clocks.read();
        let detach = Phase {
            wall_ns: after_detach.wall_ns - start.wall_ns,
            cpu_ns: after_detach.cpu_ns - start.cpu_ns,
            step_wall_ns: after_detach.wall_ns - start.wall_ns,
            step_cpu_ns: after_detach.cpu_ns - start.cpu_ns,
            visits: 1,
            actions: 0,
        };
        let mut reclaim = Phase::default();
        loop {
            let before = clocks.read();
            let used = retirement.reclaim(budget);
            let after = clocks.read();
            let (wall_ns, cpu_ns) = (after.wall_ns - before.wall_ns, after.cpu_ns - before.cpu_ns);
            reclaim.visits += 1;
            reclaim.actions += used;
            reclaim.wall_ns += wall_ns;
            reclaim.cpu_ns += cpu_ns;
            reclaim.step_wall_ns = reclaim.step_wall_ns.max(wall_ns);
            reclaim.step_cpu_ns = reclaim.step_cpu_ns.max(cpu_ns);
            let complete = retirement.is_complete();
            assert!(used > 0 || complete, "retirement must progress");
            if complete {
                break;
            }
        }
        let before_drop = clocks.read();
        drop(retirement);
        let after_drop = clocks.read();
        let final_drop = Phase {
            wall_ns: after_drop.wall_ns - before_drop.wall_ns,
            cpu_ns: after_drop.cpu_ns - before_drop.cpu_ns,
            step_wall_ns: after_drop.wall_ns - before_drop.wall_ns,
            step_cpu_ns: after_drop.cpu_ns - before_drop.cpu_ns,
            visits: 1,
            actions: 0,
        };
        let measured = Sample {
            phases: [detach, reclaim, final_drop],
        };
        for (label, phase) in PHASES.iter().zip(measured.phases.iter()) {
            eprintln!(
                "consumed-82MiB n={sample} budget={budget} phase={label} wall_us={:.3} cpu_us={:.3} step_wall_us={:.3} step_cpu_us={:.3} visits={} actions={}",
                ns_to_us(phase.wall_ns),
                ns_to_us(phase.cpu_ns),
                ns_to_us(phase.step_wall_ns),
                ns_to_us(phase.step_cpu_ns),
                phase.visits,
                phase.actions,
            );
        }
        for (accum, phase) in phases.iter_mut().zip(measured.phases.iter()) {
            accum.add(phase);
        }
        total.add(&measured.total());
    }
    for (label, accum) in PHASES.iter().zip(phases.iter()) {
        let wall = micros(&accum.wall_ns);
        let cpu = micros(&accum.cpu_ns);
        eprintln!(
            "consumed-82MiB-summary budget={budget} phase={label} n={samples} wall_p50_us={:.3} wall_max_us={:.3} cpu_p50_us={:.3} cpu_max_us={:.3} step_wall_max_us={:.3} step_cpu_max_us={:.3} visits={}",
            percentile(&wall, 50),
            wall.last().copied().unwrap_or(0.0),
            percentile(&cpu, 50),
            cpu.last().copied().unwrap_or(0.0),
            ns_to_us(accum.step_wall_ns),
            ns_to_us(accum.step_cpu_ns),
            accum.visits,
        );
    }
    let wall = micros(&total.wall_ns);
    eprintln!(
        "consumed-82MiB-summary budget={budget} phase=none n={samples} wall_p50_us={:.3} wall_max_us={:.3} step_wall_max_us={:.3}",
        percentile(&wall, 50),
        wall.last().copied().unwrap_or(0.0),
        ns_to_us(total.step_wall_ns),
    );
}

fn parse_args(args: &[String]) -> (Vec<Case>, usize, usize) {
    let (selected, rest) = match args.first().map(String::as_str) {
        Some("all") => (Case::ALL.to_vec(), &args[1..]),
        Some(name) => match Case::from_name(name) {
            Some(case) => (vec![case], &args[1..]),
            None => (Case::ALL.to_vec(), args),
        },
        None => (Case::ALL.to_vec(), args),
    };
    let samples = rest
        .first()
        .map(|value| value.parse().expect("samples must be a number"))
        .unwrap_or(DEFAULT_SAMPLES);
    let budget = rest
        .get(1)
        .map(|value| value.parse().expect("budget must be a number"))
        .unwrap_or(DEFAULT_BUDGET);
    (selected, samples, budget)
}

fn print_usage() {
    eprintln!("usage: teardown_tail_probe <case|all> <samples> [budget]");
    eprintln!("       teardown_tail_probe <samples> [budget]");
    eprintln!("samples >= {MIN_SAMPLES}, budget defaults to {DEFAULT_BUDGET}");
    eprintln!("cases:");
    for case in Case::ALL {
        eprintln!("  {}", case.name());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_usage();
        return;
    }
    let (cases, samples, budget) = parse_args(&args);
    assert!(samples >= MIN_SAMPLES, "samples >= 10");
    assert!(budget > 0, "budget.is_none_or(|budget| budget > 0)");

    let clocks = Clocks::new();
    eprintln!(
        "# teardown_tail_probe samples={samples} budget={budget} cases={}",
        cases.len()
    );
    eprintln!("# {CLOCK_NOTE}; payload {DEFAULT_PAYLOAD} B; flow window {WINDOW_PACKETS} packets");
    eprintln!("# phase=detach is into_retirement(); phase=reclaim is every reclaim(budget) visit;");
    eprintln!(
        "# phase=final-drop is the drop after completion; phase=none is all three per sample"
    );
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    eprintln!("# no thread-CPU clock on this host: cpu columns mirror the wall clock");
    println!("{HEADER}");
    let _ = std::io::stdout().flush();

    for &case in &cases {
        let detail = run_case(case, samples, budget, &clocks);
        eprintln!("# shape {}: {detail}", case.name());
        let _ = std::io::stdout().flush();
    }

    if cases.contains(&Case::AppOne82MiBMessage) {
        consumed_probe(samples, budget, &clocks);
    }
}
