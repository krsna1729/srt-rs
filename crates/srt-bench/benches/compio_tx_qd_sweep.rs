//! TX lane queue-depth sweep: smallest QD at the throughput/latency knee.
//!
//! Design assumption under test: Q (kernel TX concurrency) << F (destinations).
//! Sweeps TX lanes {16, 32, 64, 128, 256, 512} x fanout {1, 10, 100, 600}.
//! Reports submitted datagrams, CPU ns/datagram, p50/p99 service latency.
//! Selects the smallest QD whose submitted count is within 5% of the max
//! for that fanout row.

use std::time::Instant;

use bytes::Bytes;
use srt_proto::Timestamp;
use srt_transport::compio::{ListenerSide, Owner, OwnerServiceBudget};

const PAYLOAD_SIZE: usize = 1316;
const PACKET_INTERVAL_US: u64 = 1316;

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

struct QdCell {
    lanes: usize,
    fanout: usize,
    submitted: usize,
    cpu_ns_per_dgram: f64,
    p50_us: u64,
    p99_us: u64,
}

fn run_cell(lanes: usize, fanout: usize, duration_ms: u64) -> QdCell {
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
        let mut owner = Owner::new(lanes).with_listener(listener_side);
        owner
            .set_caller_pool_capacity(
                std::num::NonZeroUsize::new(fanout.clamp(1, 2048)).expect("nonzero"),
            )
            .expect("pool capacity");

        let mut now = Timestamp::from_micros(10_000);
        let mut dest_ids = Vec::with_capacity(fanout);
        for _ in 0..fanout {
            let cfg = srt_transport::CallerConfig::builder(l_addr)
                .ownership(srt_transport::SocketOwnership::Shared)
                .connect_deadline(std::time::Duration::from_secs(30))
                .configure_session(|s| {
                    s.handshake.timeout = std::time::Duration::from_secs(30);
                })
                .build()
                .expect("shared caller config");
            match owner.connect(&cfg, now).expect("owner connect") {
                srt_transport::advanced::caller::PoolOutcome::Admitted(id) => dest_ids.push(id),
                other => panic!("expected admission, got {other:?}"),
            }
        }
        let budget = OwnerServiceBudget {
            max_completions: 1024,
            max_rx_packets: 1024,
            max_rx_bytes: 2 * 1024 * 1024,
            max_actions: 1024,
            max_maintenance_actions: 1024,
            max_tx_packets: 1024,
            max_tx_bytes: 2 * 1024 * 1024,
        };
        for _ in 0..10_000 {
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
        let payload = Bytes::from(vec![0xAAu8; PAYLOAD_SIZE]);
        for round in 0..100 {
            now = Timestamp::from_micros(now.as_micros() + PACKET_INTERVAL_US);
            let target = dest_ids[round % dest_ids.len()];
            if owner.logical_caller(&target).and_then(|c| c.state())
                != Some(srt_transport::advanced::caller::LogicalCallerState::Connected)
            {
                continue;
            }
            let _ = owner
                .logical_caller_mut(&target)
                .expect("dest")
                .send_shared(payload.clone(), now);
            let _ = owner.service(now, budget).await;
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
        }

        let cpu_start = process_cpu_seconds();
        let t_start = Instant::now();
        let mut submitted = 0usize;
        let mut latencies: Vec<u64> = Vec::with_capacity(10_000);
        let duration = std::time::Duration::from_millis(duration_ms);
        let mut next_tick = 0u64;
        while t_start.elapsed() < duration {
            let elapsed_us = t_start.elapsed().as_micros() as u64;
            while elapsed_us >= next_tick {
                next_tick += PACKET_INTERVAL_US;
                now = Timestamp::from_micros(now.as_micros() + PACKET_INTERVAL_US);
                for &id in &dest_ids {
                    let _ = owner
                        .logical_caller_mut(&id)
                        .expect("dest")
                        .send_shared(payload.clone(), now);
                }
            }
            let vs = Instant::now();
            let report = owner.service(now, budget).await;
            let vus = (vs.elapsed().as_nanos().min(u128::from(u64::MAX)) / 1000) as u64;
            if report.tx_packets_submitted > 0 {
                latencies.push(vus);
            }
            submitted += report.tx_packets_submitted;
            if !report.work_remaining {
                owner
                    .wait_for_activity(std::time::Duration::from_micros(200))
                    .await;
            }
        }
        let cpu_secs = process_cpu_seconds() - cpu_start;
        latencies.sort_unstable();
        let q = |n: usize, d: usize| {
            if latencies.is_empty() {
                0
            } else {
                latencies[(latencies.len() * n / d).min(latencies.len() - 1)]
            }
        };
        QdCell {
            lanes,
            fanout,
            submitted,
            cpu_ns_per_dgram: if submitted == 0 {
                0.0
            } else {
                cpu_secs * 1e9 / submitted as f64
            },
            p50_us: q(50, 100),
            p99_us: q(99, 100),
        }
    })
}

fn main() {
    println!("=== COMPIO TX LANE QD SWEEP ===");
    println!("lanes x fanout; submitted datagrams + CPU ns/dgram + p50/p99 svc latency\n");
    let lanes = [16, 32, 64, 128, 256, 512];
    let fanouts = [1, 10, 100, 600];
    println!(
        "{:<8} | {:<8} | {:>10} | {:>12} | {:>8} | {:>8}",
        "Lanes", "Fanout", "Submitted", "CPU ns/sub", "P50 svc", "P99 svc"
    );
    println!(
        "{:-<8}-+-{:-<8}-+-{:-<10}-+-{:-<12}-+-{:-<8}-+-{:-<8}",
        "", "", "", "", "", ""
    );
    let mut rows: Vec<QdCell> = Vec::new();
    for &l in &lanes {
        for &f in &fanouts {
            eprintln!("cell lanes={l} fanout={f}...");
            let c = run_cell(l, f, 2_000);
            println!(
                "{:<8} | {:<8} | {:>10} | {:>12.1} | {:>6} us | {:>6} us",
                c.lanes, c.fanout, c.submitted, c.cpu_ns_per_dgram, c.p50_us, c.p99_us
            );
            rows.push(c);
        }
    }
    println!();
    println!("=== KNEE SELECTION (smallest QD within 5% of row max) ===");
    for &f in &fanouts {
        let row: Vec<&QdCell> = rows.iter().filter(|c| c.fanout == f).collect();
        let max_sub = row.iter().map(|c| c.submitted).max().unwrap_or(1).max(1);
        let knee = row
            .iter()
            .find(|c| c.submitted * 100 >= max_sub * 95)
            .map(|c| c.lanes)
            .unwrap_or(*lanes.last().unwrap());
        println!("fanout {f}: max_submitted={max_sub} knee_lanes={knee}");
    }
}
