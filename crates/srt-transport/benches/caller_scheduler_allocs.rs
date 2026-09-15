//! Allocator-instrumented steady-state measurement of CallerTable scheduling.
//!
//! Measures allocation churn, bytes allocated, and service visit latency
//! across:
//! 1. 1 logical caller
//! 2. 600 logical callers
//! 3. 600 bonded callers (x 2 legs = 1200 physical legs)
//!
//! In steady state, measuring repeated:
//! - deadline update
//! - ready cycling
//! - bounded output drain
//! - timer movement

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
}
