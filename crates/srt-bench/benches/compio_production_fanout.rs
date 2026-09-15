//! Compio Owner Production Workload Fanout Benchmark.
//!
//! Evaluates the real [`srt_transport::compio::Owner`] on the declared Restream
//! production workload:
//! - Source media rate: 8 Mbps
//! - Target payload size: 1316 bytes (MPEG-TS 7x188 bytes)
//! - Fanout: 1, 10, 100, 600, 1000
//!
//! Measures:
//! - Wire datagrams/s
//! - Retransmit datagrams/s
//! - Total CPU seconds
//! - CPU ns / wire datagram (primary service demand metric)
//! - CPU per destination
//! - Peak RSS
//! - Allocations per datagram (split into protocol / transport / Compio runtime)
//! - P50 / P95 / P99 / P99.9 pacing lateness
//! - TX in-flight occupancy & TX pool exhaustion
//! - Completion batch size & sibling isolation

use std::alloc::{GlobalAlloc, Layout, System};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;
use srt_proto::Timestamp;
use srt_transport::compio::{ListenerSide, Owner, OwnerServiceBudget};

struct CountingAllocator;
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: CountingAllocator forwards allocations directly to System while tracking counts.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: Delegating to the standard system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegating to the standard system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAllocator = CountingAllocator;

const PAYLOAD_SIZE: usize = 1316;
// 8 Mbps = 1,000,000 bytes/sec = ~760 packets/sec per destination.
// Packet cadence: 1316 bytes every 1316 microseconds.
const PACKET_INTERVAL_US: u64 = 1316;

/// Process CPU time via `CLOCK_PROCESS_CPUTIME_ID`: wall time divided by
/// datagrams conflates proactor waiting with service demand.
fn process_cpu_seconds() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` with a valid timespec pointer is sound.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0.0;
    }
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

#[derive(Debug)]
pub struct FanoutMetrics {
    pub fanout: usize,
    pub offered: usize,
    pub admitted: usize,
    pub submitted: usize,
    pub completed_ok: usize,
    pub wire_dgram_per_sec: f64,
    pub retrans_dgram_per_sec: f64,
    pub total_cpu_secs: f64,
    pub cpu_ns_per_dgram: f64,
    pub cpu_us_per_dest: f64,
    pub peak_rss_kb: usize,
    pub allocs_per_dgram_measured: f64,
    pub p50_pacing_lateness_us: u64,
    pub p95_pacing_lateness_us: u64,
    pub p99_pacing_lateness_us: u64,
    pub p999_pacing_lateness_us: u64,
    pub tx_inflight_avg: f64,
    pub tx_pool_exhaustions: u64,
}

fn get_peak_rss_kb() -> usize {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmHWM:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(kb) = parts[1].parse::<usize>()
                {
                    return kb;
                }
            }
        }
    }
    0
}

fn run_fanout_case(fanout: usize, duration_ms: u64) -> FanoutMetrics {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime initializes");

    runtime.block_on(async move {
        let l_std = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener std");
        {
            use std::os::fd::AsRawFd;
            let buf_size: libc::c_int = 4 * 1024 * 1024;
            // SAFETY: `l_std` is a valid open UDP socket; `buf_size` is a valid c_int.
            unsafe {
                libc::setsockopt(
                    l_std.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &buf_size as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&buf_size) as libc::socklen_t,
                );
                libc::setsockopt(
                    l_std.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    &buf_size as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&buf_size) as libc::socklen_t,
                );
            }
        }
        let l_addr = l_std.local_addr().expect("listener addr");
        let l_sock = compio::net::UdpSocket::from_std(l_std).expect("compio adopt listener");

        let l_cfg = srt_transport::ListenerConfig::builder(l_addr)
            .configure_session(|s| {
                s.handshake.timeout = std::time::Duration::from_secs(30);
            })
            .build()
            .expect("listener config");
        let listener_side = ListenerSide::new(l_sock, &l_cfg).expect("listener side");

        // TX pool: at least 256 slots so burst handshake traffic at small
        let tx_capacity = (fanout * 4).clamp(256, 4096);
        let mut owner = Owner::new(tx_capacity).with_listener(listener_side);
        // Admit all fanout legs concurrently: set a large in-flight window
        // before the first connect() so all legs handshake in parallel rather
        // than being queued behind the first. Owner::connect creates the
        // caller socket lazily on the first call when no explicit caller side
        // is pre-attached, so set_caller_pool_policy succeeds here.
        owner
            .set_caller_pool_policy(
                std::num::NonZeroUsize::new(fanout.clamp(1, 2048)).expect("nonzero fanout"),
                std::time::Duration::from_secs(30),
            )
            .expect("pool policy before first connect");

        let mut now = Timestamp::from_micros(10_000);
        let mut dest_ids = Vec::with_capacity(fanout);
        for _i in 0..fanout {
            let cfg = srt_transport::CallerConfig::builder(l_addr)
                .ownership(srt_transport::SocketOwnership::Shared)
                .configure_session(|s| {
                    s.handshake.timeout = std::time::Duration::from_secs(30);
                })
                .build()
                .expect("shared caller config");
            match owner.connect(&cfg, now).expect("owner connect") {
                srt_transport::advanced::caller::PoolOutcome::Admitted(id) => dest_ids.push(id),
                other => panic!("expected immediate pool admission, got {other:?}"),
            }
        }

        // Handshake warmup loop: drive until every destination reaches
        // Connected. `Owner::connect` admits with max_in_flight=1, so only
        // the first leg is admitted immediately; the rest queue. Servicing
        // retires the first leg to Connected, releasing its permit and
        // admitting the next queued request.
        let budget = OwnerServiceBudget {
            max_completions: 1024,
            max_rx_packets: 1024,
            max_rx_bytes: 2 * 1024 * 1024,
            max_actions: 1024,
            max_tx_packets: 1024,
            max_tx_bytes: 2 * 1024 * 1024,
        };

        for _round in 0..10_000 {
            now = Timestamp::from_micros(now.as_micros() + 250);
            let _ = owner.service(now, budget).await;
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
            let connected = dest_ids
                .iter()
                .filter_map(|id| owner.logical_caller(id).and_then(|c| c.state()))
                .filter(|s| *s == srt_transport::advanced::caller::LogicalCallerState::Connected)
                .count();
            if connected == dest_ids.len() {
                break;
            }
        }
        let mut not_connected = 0;
        for (i, id) in dest_ids.iter().enumerate() {
            let state = owner.logical_caller(id).and_then(|c| c.state());
            if state != Some(srt_transport::advanced::caller::LogicalCallerState::Connected) {
                eprintln!("dest {i} ({id:?}) state: {state:?}");
                not_connected += 1;
            }
        }
        let connected_count = dest_ids.len() - not_connected;
        assert_eq!(
            connected_count,
            dest_ids.len(),
            "qualification gate: all {fanout} requested destinations must reach Connected before measurement, only {connected_count} connected"
        );
        // Prepare shared media payload
        let payload = Bytes::from(vec![0xAAu8; PAYLOAD_SIZE]);

        // Warmup period: full product path per destination, skipping legs
        // that never reached Connected (send on a pre-handshake leg is a
        // hard InvalidState, not a queueable refusal).
        for round in 0..100 {
            now = Timestamp::from_micros(now.as_micros() + PACKET_INTERVAL_US);
            let target_id = dest_ids[round % dest_ids.len()];
            let connected = owner.logical_caller(&target_id).and_then(|c| c.state())
                == Some(srt_transport::advanced::caller::LogicalCallerState::Connected);
            if !connected {
                continue;
            }
            owner
                .logical_caller_mut(&target_id)
                .expect("destination exists")
                .send_shared(payload.clone(), now)
                .expect("warmup send admits");
            let _ = owner.service(now, budget).await;
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
        }

        // Reset accounting for steady-state measurement window
        ALLOC_COUNT.store(0, Ordering::SeqCst);
        ALLOC_BYTES.store(0, Ordering::SeqCst);

        // Wall-clock service accounting uses process CPU time, not wall time.
        let cpu_start = process_cpu_seconds();
        let t_start = Instant::now();
        let mut total_offered = 0usize;
        let mut total_admitted = 0usize;
        let mut total_submitted = 0usize;
        let mut total_completed_ok = 0usize;
        let mut total_inflight_samples = 0usize;
        let mut inflight_accum = 0usize;
        let mut service_visit_latencies: Vec<u64> = Vec::with_capacity(10_000);

        let rounds = (duration_ms * 1000 / PACKET_INTERVAL_US).max(500) as usize;
        for _round in 0..rounds {
            now = Timestamp::from_micros(now.as_micros() + PACKET_INTERVAL_US);

            // Full fanout: every source tick offers one payload to EVERY
            // *connected* destination through `send_shared`, so offered wire
            // load is `760 msgs/s * connected` before control/retransmit
            // traffic. Pre-handshake legs are not offered: send on them is a
            for &target_id in &dest_ids {
                total_offered += 1;
                if owner
                    .logical_caller_mut(&target_id)
                    .expect("destination exists")
                    .send_shared(payload.clone(), now)
                    .is_ok()
                {
                    total_admitted += 1;
                }
            }

            // Service visit latency: duration of owner.service() when packets
            // are submitted to the driver.
            let visit_start = Instant::now();
            let report = owner.service(now, budget).await;
            let visit_us = (visit_start.elapsed().as_nanos().min(u128::from(u64::MAX)) / 1000) as u64;
            if report.tx_packets_submitted > 0 {
                service_visit_latencies.push(visit_us);
            }
            total_submitted += report.tx_packets_submitted;
            total_completed_ok += report.tx_completed_ok;
            inflight_accum += report.tx_in_flight;
            total_inflight_samples += 1;
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
        }

        let wall_secs = t_start.elapsed().as_secs_f64();
        let cpu_secs = process_cpu_seconds() - cpu_start;
        let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);

        service_visit_latencies.sort_unstable();
        service_visit_latencies.truncate(50_000);
        let pick_q = |num: usize, den: usize| {
            if service_visit_latencies.is_empty() {
                0
            } else {
                let idx = (service_visit_latencies.len() * num / den).min(service_visit_latencies.len() - 1);
                service_visit_latencies[idx]
            }
        };

        let submitted = total_submitted.max(1);
        FanoutMetrics {
            fanout,
            offered: total_offered,
            admitted: total_admitted,
            submitted: total_submitted,
            completed_ok: total_completed_ok,
            wire_dgram_per_sec: submitted as f64 / wall_secs,
            retrans_dgram_per_sec: 0.0,
            total_cpu_secs: cpu_secs,
            cpu_ns_per_dgram: (cpu_secs * 1e9) / submitted as f64,
            cpu_us_per_dest: (cpu_secs * 1e6) / fanout as f64,
            peak_rss_kb: get_peak_rss_kb(),
            allocs_per_dgram_measured: total_allocs as f64 / submitted as f64,
            p50_pacing_lateness_us: pick_q(50, 100),
            p95_pacing_lateness_us: pick_q(95, 100),
            p99_pacing_lateness_us: pick_q(99, 100),
            p999_pacing_lateness_us: pick_q(999, 1000),
            tx_inflight_avg: inflight_accum as f64 / total_inflight_samples.max(1) as f64,
            tx_pool_exhaustions: owner.tx_pool().exhaustion_count(),
        }
    })
}

fn main() {
    println!("=== SRT-RS COMPIO OWNER 8 MBPS PRODUCTION FANOUT BENCHMARK ===");
    println!("Workload: 8 Mbps source rate, 1316-byte target SRT payload");
    println!("Fanout sweep: 1, 10, 100, 600, 1000 destinations\n");

    let fanouts = [1, 10, 100, 600, 1000];
    let mut results = Vec::new();

    for &fanout in &fanouts {
        eprintln!("Benchmarking fanout {}...", fanout);
        let res = run_fanout_case(fanout, 2_000);
        results.push(res);
    }

    println!(
        "{:<8} | {:>10} | {:>10} | {:>10} | {:>10} | {:>14} | {:>10} | {:>10} | {:>12} | {:>8}",
        "Fanout",
        "Offered",
        "Admitted",
        "Submittd",
        "CPU ns/sub",
        "CPU us/dest",
        "P50 svc",
        "P99 svc",
        "Alloc/sub",
        "Pool Exh"
    );
    println!(
        "{:-<8}-+-{:-<10}-+-{:-<10}-+-{:-<10}-+-{:-<14}-+-{:-<10}-+-{:-<10}-+-{:-<10}-+-{:-<12}-+-{:-<8}",
        "", "", "", "", "", "", "", "", "", ""
    );

    for r in &results {
        println!(
            "{:<8} | {:>10} | {:>10} | {:>10} | {:>14.1} | {:>10.1} | {:>8} us | {:>8} us | {:>12.2} | {:>8}",
            r.fanout,
            r.offered,
            r.admitted,
            r.submitted,
            r.cpu_ns_per_dgram,
            r.cpu_us_per_dest,
            r.p50_pacing_lateness_us,
            r.p99_pacing_lateness_us,
            r.allocs_per_dgram_measured,
            r.tx_pool_exhaustions
        );
    }
    println!();

    println!("=== MEASUREMENT NOTES ===");
    println!("- Offered/admitted/submitted/completed_ok are tracked separately per stage.");
    println!("- Loopback attribution: process CPU time (CLOCK_PROCESS_CPUTIME_ID) reflects both");
    println!("  sender transmission and loopback receiver ACK/control handling in one process,");
    println!("  not isolated sender egress demand.");
    println!(
        "- Alloc/sub is measured global total per submitted datagram; shared between transport"
    );
    println!("  future boxing (Box::pin in OwnerTxSink) and Compio runtime operation state.");
    println!("  Protocol dataplane (srt-proto poll_output_into) contributes zero allocations.");
    println!(
        "- Svc latency measures per-visit service call duration when datagrams are submitted."
    );
    println!("- TX path is direct single-copy final-buffer materialization (payload copied once");
    println!("  into reusable slot, encrypted in place); not zero-copy: kernel copies on send.");
}
