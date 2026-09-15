//! Allocator-instrumented steady-state measurement of CallerTable scheduling.
//!
//! Two measurement classes:
//! A. Full steady-state service (deadline update + ready cycling + bounded
//!    output drain + timer movement), including payload admission.
//! B. Scheduler-isolated service (deadline remove/reinsert + ready cycling +
//!    bounded drain into a no-allocation sink, no payload send). Class B is
//!    the only valid basis for claims about the BTreeSet deadline structure
//!    itself; class A mixes scheduler cost with sender/protocol allocation.
//!
//! Scenarios: 1 logical caller, 600 logical callers, 600 bonded groups
//! (x 2 legs = 1200 physical legs).
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use srt_proto::handshake::SRTGROUP_MASK;
use srt_proto::{ConnectionOptions, ConnectionOutput, SrtConnection, Timestamp};
use srt_transport::advanced::caller::{CallerGroupLeg, CallerLeg, CallerTable, LogicalCallerId};
use srt_transport::advanced::driver::OutputDrainBudget;

struct CountingAllocator;
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: CountingAllocator forwards all allocations and deallocations directly to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: Delegating to the standard system allocator with the valid layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegating to the standard system allocator with matching ptr and layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn make_peer(idx: usize) -> SocketAddr {
    SocketAddr::from((
        [10, 0, (idx / 256) as u8, (idx % 256) as u8],
        5000 + (idx % 1000) as u16,
    ))
}

fn new_connected_caller_connection(socket_id: u32) -> SrtConnection {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id,
        ..ConnectionOptions::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: socket_id.wrapping_add(100_000).max(1),
        ..ConnectionOptions::default()
    });
    caller.connect(Timestamp::default()).expect("connect");
    for i in 0..10 {
        let now = Timestamp::from_micros(i * 10_000);
        while let Some(output) = caller.poll_output() {
            if let ConnectionOutput::SendPacket(data) = output {
                let _ = listener.feed_recv_buf(&data, now);
            }
        }
        while let Some(output) = listener.poll_output() {
            if let ConnectionOutput::SendPacket(data) = output {
                let _ = caller.feed_recv_buf(&data, now);
            }
        }
        if caller.state() == srt_proto::ConnectionState::Connected {
            break;
        }
    }
    assert_eq!(caller.state(), srt_proto::ConnectionState::Connected);
    caller
}

fn build_direct_table(n: usize) -> (CallerTable, Vec<LogicalCallerId>) {
    let mut table = CallerTable::new();
    let mut ids = Vec::with_capacity(n);
    let mut out = Vec::new();
    for i in 0..n {
        let peer = make_peer(i);
        let conn = new_connected_caller_connection(1000 + i as u32);
        let id = table
            .add_direct(CallerLeg {
                peer,
                connection: conn,
            })
            .expect("add_direct");
        ids.push(id);
    }
    table.poll_outbound(Timestamp::default(), &mut out);
    (table, ids)
}

fn build_bonded_table(group_count: usize) -> (CallerTable, Vec<LogicalCallerId>) {
    let mut table = CallerTable::new();
    let mut ids = Vec::with_capacity(group_count);
    let mut out = Vec::new();
    for i in 0..group_count {
        let gid = SRTGROUP_MASK | (1000 + i as u32);
        let legs = (0..2).map(|j| {
            let peer = make_peer(i * 10 + j);
            let conn = new_connected_caller_connection(300_000 + (i * 10 + j) as u32);
            CallerGroupLeg {
                member_id: j as u32,
                weight: 1,
                peer,
                connection: conn,
            }
        });
        let id = table
            .add_group(gid, srt_proto::GroupMode::Broadcast, legs)
            .unwrap();
        ids.push(id);
    }
    table.poll_outbound(Timestamp::default(), &mut out);
    (table, ids)
}

#[allow(dead_code)]
struct BenchmarkResults {
    scenario: &'static str,
    iterations: usize,
    allocs_per_op: f64,
    bytes_per_op: f64,
    mean_cpu_ns: f64,
    p50_cpu_ns: u64,
    p95_cpu_ns: u64,
    p99_cpu_ns: u64,
}

fn run_steady_state_measurement(
    scenario: &'static str,
    mut table: CallerTable,
    ids: Vec<LogicalCallerId>,
    iterations: usize,
) -> BenchmarkResults {
    let budget = OutputDrainBudget::new(64, 32, 256 * 1024);
    let mut out = Vec::new();
    let mut durations_ns = Vec::with_capacity(iterations);

    // Warmup
    let mut now = Timestamp::from_micros(1_000_000);
    for i in 0..500 {
        now = Timestamp::from_micros(now.as_micros() + 100);
        let target_id = ids[i % ids.len()];
        table.bench_arm_timer(target_id, srt_proto::TimerId::Ack, 100, now);
        let _ = table.time_until_next_deadline(now, 100_000);
        let mut m = table.logical_caller_mut(&target_id).expect("exists");
        let _ = m.send(b"steady-state-warmup-data", now);
        let _ = table.poll_outbound_bounded(now, budget, &mut out);
    }

    // Reset allocation accounting
    ALLOC_COUNT.store(0, Ordering::SeqCst);
    ALLOC_BYTES.store(0, Ordering::SeqCst);

    for i in 0..iterations {
        now = Timestamp::from_micros(now.as_micros() + 100);
        let target_id = ids[i % ids.len()];

        let t0 = Instant::now();

        // 1. Deadline update / timer movement
        table.bench_arm_timer(target_id, srt_proto::TimerId::Ack, 100, now);
        let _ = table.time_until_next_deadline(now, 100_000);

        // 2. Ready cycling
        let mut m = table.logical_caller_mut(&target_id).expect("exists");
        let _ = m.send(b"steady-state-payload-data", now);

        // 3. Bounded output drain
        let _ = table.poll_outbound_bounded(now, budget, &mut out);

        let elapsed_ns = t0.elapsed().as_nanos() as u64;
        durations_ns.push(elapsed_ns);
    }

    let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);
    let total_bytes = ALLOC_BYTES.load(Ordering::SeqCst);

    durations_ns.sort_unstable();
    let mean_cpu_ns = durations_ns.iter().sum::<u64>() as f64 / iterations as f64;
    let p50_cpu_ns = durations_ns[iterations * 50 / 100];
    let p95_cpu_ns = durations_ns[iterations * 95 / 100];
    let p99_cpu_ns = durations_ns[iterations * 99 / 100];

    BenchmarkResults {
        scenario,
        iterations,
        allocs_per_op: total_allocs as f64 / iterations as f64,
        bytes_per_op: total_bytes as f64 / iterations as f64,
        mean_cpu_ns,
        p50_cpu_ns,
        p95_cpu_ns,
        p99_cpu_ns,
    }
}

/// Scheduler-isolated measurement: deadline remove/reinsert, ready cycling,
/// and bounded drain into a no-allocation sink. No payload is admitted, so the
/// sender, protocol packetization, and wire encoding paths contribute zero
/// allocations by construction; whatever remains is the scheduler structure.
struct ScratchSink {
    scratch: [u8; 2048],
    wire_len: usize,
}

impl ScratchSink {
    fn new() -> Self {
        Self {
            scratch: [0u8; 2048],
            wire_len: 0,
        }
    }
}

impl srt_transport::DatagramSink for ScratchSink {
    fn push_datagram<F>(
        &mut self,
        _peer: SocketAddr,
        wire_len: usize,
        fill: F,
    ) -> Result<srt_transport::PushResult, srt_proto::Error>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, srt_proto::Error>,
    {
        if wire_len > self.scratch.len() {
            return Ok(srt_transport::PushResult::Exhausted);
        }
        let len = fill(&mut self.scratch[..wire_len])?;
        self.wire_len = len;
        Ok(srt_transport::PushResult::Pushed { len })
    }
}

fn run_scheduler_isolated_measurement(
    scenario: &'static str,
    mut table: CallerTable,
    ids: Vec<LogicalCallerId>,
    iterations: usize,
) -> BenchmarkResults {
    let mut durations_ns = Vec::with_capacity(iterations);
    let mut now = Timestamp::from_micros(1_000_000);

    for i in 0..500 {
        now = Timestamp::from_micros(now.as_micros() + 100);
        let target_id = ids[i % ids.len()];
        table.bench_arm_timer(target_id, srt_proto::TimerId::Ack, 100, now);
        let _ = table.time_until_next_deadline(now, 100_000);
        table.bench_make_ready(target_id);
        let mut sink = ScratchSink::new();
        let _ = table.poll_outbound_bounded_to(
            now,
            OutputDrainBudget::new(64, 32, 256 * 1024),
            &mut sink,
        );
    }

    ALLOC_COUNT.store(0, Ordering::SeqCst);
    ALLOC_BYTES.store(0, Ordering::SeqCst);

    for i in 0..iterations {
        now = Timestamp::from_micros(now.as_micros() + 100);
        let target_id = ids[i % ids.len()];
        let t0 = Instant::now();
        table.bench_arm_timer(target_id, srt_proto::TimerId::Ack, 100, now);
        let _ = table.time_until_next_deadline(now, 100_000);
        table.bench_make_ready(target_id);
        let mut sink = ScratchSink::new();
        let _ = table.poll_outbound_bounded_to(
            now,
            OutputDrainBudget::new(64, 32, 256 * 1024),
            &mut sink,
        );
        durations_ns.push(t0.elapsed().as_nanos() as u64);
    }

    let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);
    let total_bytes = ALLOC_BYTES.load(Ordering::SeqCst);
    durations_ns.sort_unstable();
    let mean_cpu_ns = durations_ns.iter().sum::<u64>() as f64 / iterations as f64;
    BenchmarkResults {
        scenario,
        iterations,
        allocs_per_op: total_allocs as f64 / iterations as f64,
        bytes_per_op: total_bytes as f64 / iterations as f64,
        mean_cpu_ns,
        p50_cpu_ns: durations_ns[iterations * 50 / 100],
        p95_cpu_ns: durations_ns[iterations * 95 / 100],
        p99_cpu_ns: durations_ns[iterations * 99 / 100],
    }
}

fn main() {
    println!("=== CALLER TABLE SCHEDULER ALLOCATOR & DEADLINE MEASUREMENT ===");
    println!(
        "Warmed steady-state: deadline update + ready cycling + bounded drain + timer movement"
    );
    println!("Iterations: 10,000 per scenario\n");

    const ITERS: usize = 10_000;

    // 1. 1 logical caller
    let (t1, ids1) = build_direct_table(1);
    let res1 = run_steady_state_measurement("1 logical caller", t1, ids1, ITERS);

    // 2. 600 logical callers
    let (t600, ids600) = build_direct_table(600);
    let res600 = run_steady_state_measurement("600 logical callers", t600, ids600, ITERS);

    // 3. Representative bonded 1200-leg case (600 groups x 2 legs)
    let (t1200, ids1200) = build_bonded_table(600);
    let res1200 = run_steady_state_measurement(
        "600 bonded groups (1200 physical legs)",
        t1200,
        ids1200,
        ITERS,
    );

    println!(
        "{:<45} | {:>10} | {:>10} | {:>12} | {:>10} | {:>10} | {:>10}",
        "Scenario", "Allocs/op", "Bytes/op", "Mean CPU ns", "P50 ns", "P95 ns", "P99 ns"
    );
    println!(
        "{:-<45}-+-{:-<10}-+-{:-<10}-+-{:-<12}-+-{:-<10}-+-{:-<10}-+-{:-<10}",
        "", "", "", "", "", "", ""
    );

    for res in [&res1, &res600, &res1200] {
        println!(
            "{:<45} | {:>10.3} | {:>10.1} | {:>12.1} | {:>10} | {:>10} | {:>10}",
            res.scenario,
            res.allocs_per_op,
            res.bytes_per_op,
            res.mean_cpu_ns,
            res.p50_cpu_ns,
            res.p95_cpu_ns,
            res.p99_cpu_ns
        );
    }
    println!();

    println!("=== CLASS B: SCHEDULER-ISOLATED (no payload send) ===");
    let (s1, sids1) = build_direct_table(1);
    let iso1 = run_scheduler_isolated_measurement("isolated: 1 logical caller", s1, sids1, ITERS);
    let (s600, sids600) = build_direct_table(600);
    let iso600 =
        run_scheduler_isolated_measurement("isolated: 600 logical callers", s600, sids600, ITERS);
    let (s1200, sids1200) = build_bonded_table(600);
    let iso1200 = run_scheduler_isolated_measurement(
        "isolated: 600 bonded groups (1200 legs)",
        s1200,
        sids1200,
        ITERS,
    );
    for res in [&iso1, &iso600, &iso1200] {
        println!(
            "{:<45} | {:>10.3} | {:>10.1} | {:>12.1} | {:>10} | {:>10} | {:>10}",
            res.scenario,
            res.allocs_per_op,
            res.bytes_per_op,
            res.mean_cpu_ns,
            res.p50_cpu_ns,
            res.p95_cpu_ns,
            res.p99_cpu_ns
        );
    }
    println!();
    println!(
        "Class A mixes scheduler + sender/protocol allocation. Only class B isolates the BTreeSet deadline structure."
    );
}
