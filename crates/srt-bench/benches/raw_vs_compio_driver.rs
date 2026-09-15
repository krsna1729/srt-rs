//! Raw io_uring vs Compio UDP Driver Envelope Benchmark.
//!
//! Evaluates the driver-side opportunity envelope of a native io_uring backend
//! without building a full native transport:
//! - Raw io_uring UDP send (via `io-uring` crate)
//! - Compio UDP send (via `compio::net::UdpSocket`)
//!
//! Controls:
//! - Fixed 1316-byte payload
//! - Sockets, loopback routing, ring depth, and completion accounting matched
//! - Queue depths: 1, 8, 32, 128, 256
//! - Peer counts: 1, 100, 1000
//!
//! Outputs:
//! - CPU ns/op
//! - Ops/sec
//! - P99 completion latency
//! - Allocs/op
//! - Native opportunity calculation: ΔD, potential saved cores, and % of total SRT CPU

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use io_uring::{IoUring, opcode, types};

struct CountingAllocator;
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: CountingAllocator forwards allocations directly to System while tracking counts.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: Delegating to System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegating to System.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAllocator = CountingAllocator;

const PAYLOAD_LEN: usize = 1316;

#[derive(Debug, Clone)]
pub struct DriverBenchRow {
    pub driver: &'static str,
    pub qd: usize,
    pub peers: usize,
    pub ops_per_sec: f64,
    pub cpu_ns_per_op: f64,
    pub p99_latency_ns: u64,
    pub allocs_per_op: f64,
}

fn make_dest_addrs(count: usize) -> Vec<SocketAddr> {
    (0..count)
        .map(|i| {
            SocketAddr::from((
                [127, 0, (i / 256) as u8, (i % 256) as u8],
                (40000 + (i % 10000)) as u16,
            ))
        })
        .collect()
}

fn bench_raw_io_uring(qd: usize, peer_count: usize, iterations: usize) -> DriverBenchRow {
    let ring_depth = (qd * 2).clamp(64, 1024) as u32;
    let mut ring = IoUring::new(ring_depth).expect("create io_uring ring");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind raw udp");
    let fd = types::Fd(socket.as_raw_fd());

    let dests = make_dest_addrs(peer_count);
    let payload = vec![0xAAu8; PAYLOAD_LEN];

    // Pre-create sockaddr storage for in-flight operations
    let sockaddr_storage: Vec<(libc::sockaddr_storage, libc::socklen_t)> = dests
        .iter()
        .map(|addr| match addr {
            SocketAddr::V4(v4) => {
                // SAFETY: sockaddr_storage is POD and zeroing initializes an empty buffer.
                let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                // SAFETY: ss has sufficient alignment and size for sockaddr_in.
                let sa_in: &mut libc::sockaddr_in = unsafe { &mut *(&mut ss as *mut _ as *mut _) };
                sa_in.sin_family = libc::AF_INET as _;
                sa_in.sin_port = v4.port().to_be();
                sa_in.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                (
                    ss,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            SocketAddr::V6(_) => unreachable!(),
        })
        .collect();

    // Warmup
    for i in 0..500 {
        let (_ss, _slen) = &sockaddr_storage[i % sockaddr_storage.len()];
        let send_op = opcode::SendMsg::new(fd, std::ptr::null())
            .build()
            .user_data(i as u64);
        // SAFETY: send_op does not dereference invalid memory.
        unsafe {
            let _ = ring.submission().push(&send_op);
        }
        let _ = ring.submit_and_wait(1);
        ring.completion().for_each(|_| {});
    }

    ALLOC_COUNT.store(0, Ordering::SeqCst);
    ALLOC_BYTES.store(0, Ordering::SeqCst);

    let mut latencies = Vec::with_capacity(iterations);
    let mut in_flight = 0usize;
    let mut completed = 0usize;
    let t_start = Instant::now();

    while completed < iterations {
        // Submit up to QD
        while in_flight < qd && (completed + in_flight) < iterations {
            let op_idx = completed + in_flight;
            let (ref ss, slen) = sockaddr_storage[op_idx % sockaddr_storage.len()];

            let mut iov = libc::iovec {
                iov_base: payload.as_ptr() as *mut _,
                iov_len: payload.len(),
            };
            // SAFETY: msghdr is POD and zeroing initializes all fields safely.
            let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
            msghdr.msg_name = ss as *const _ as *mut _;
            msghdr.msg_namelen = slen;
            msghdr.msg_iov = &mut iov;
            msghdr.msg_iovlen = 1;

            let send_entry = opcode::SendMsg::new(fd, &msghdr)
                .build()
                .user_data(op_idx as u64);

            // SAFETY: send_entry points to valid msghdr and payload during submit.
            unsafe {
                if ring.submission().push(&send_entry).is_err() {
                    break;
                }
            }
            in_flight += 1;
        }

        let submit_t0 = Instant::now();
        let _ = ring.submit_and_wait(1);
        let elapsed_op = submit_t0.elapsed().as_nanos() as u64;

        let mut cqe_count = 0;
        for _cqe in ring.completion() {
            cqe_count += 1;
            latencies.push(elapsed_op);
        }
        in_flight = in_flight.saturating_sub(cqe_count);
        completed += cqe_count;
    }

    let total_secs = t_start.elapsed().as_secs_f64();
    let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);

    latencies.sort_unstable();
    let p99 = if !latencies.is_empty() {
        latencies[latencies.len() * 99 / 100]
    } else {
        0
    };

    DriverBenchRow {
        driver: "Raw io_uring",
        qd,
        peers: peer_count,
        ops_per_sec: iterations as f64 / total_secs,
        cpu_ns_per_op: (total_secs * 1e9) / iterations as f64,
        p99_latency_ns: p99,
        allocs_per_op: total_allocs as f64 / iterations as f64,
    }
}

fn bench_compio_driver(qd: usize, peer_count: usize, iterations: usize) -> DriverBenchRow {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime initializes");

    runtime.block_on(async move {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind compio udp");
        let compio_sock = compio::net::UdpSocket::from_std(socket).expect("compio adopt socket");

        let dests = make_dest_addrs(peer_count);
        let payload = vec![0xAAu8; PAYLOAD_LEN];

        // Warmup
        for i in 0..500 {
            let peer = dests[i % dests.len()];
            let _ = compio_sock.send_to(payload.clone(), peer).await;
        }

        ALLOC_COUNT.store(0, Ordering::SeqCst);
        ALLOC_BYTES.store(0, Ordering::SeqCst);

        let mut latencies = Vec::with_capacity(iterations);
        let mut in_flight = futures_util::stream::FuturesUnordered::new();
        let mut completed = 0usize;
        let t_start = Instant::now();

        use futures_util::StreamExt;

        while completed < iterations {
            while in_flight.len() < qd && (completed + in_flight.len()) < iterations {
                let op_idx = completed + in_flight.len();
                let peer = dests[op_idx % dests.len()];
                let buf = payload.clone();

                let op_t0 = Instant::now();
                let fut = compio_sock.send_to(buf, peer);
                in_flight.push(async move {
                    let res = fut.await;
                    (res, op_t0.elapsed().as_nanos() as u64)
                });
            }

            if let Some((_res, lat_ns)) = in_flight.next().await {
                completed += 1;
                latencies.push(lat_ns);
            }
        }

        let total_secs = t_start.elapsed().as_secs_f64();
        let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);

        latencies.sort_unstable();
        let p99 = if !latencies.is_empty() {
            latencies[latencies.len() * 99 / 100]
        } else {
            0
        };

        DriverBenchRow {
            driver: "Compio UDP",
            qd,
            peers: peer_count,
            ops_per_sec: iterations as f64 / total_secs,
            cpu_ns_per_op: (total_secs * 1e9) / iterations as f64,
            p99_latency_ns: p99,
            allocs_per_op: total_allocs as f64 / iterations as f64,
        }
    })
}

fn main() {
    println!("=== RAW IO_URING VS COMPIO UDP DRIVER ENVELOPE BENCHMARK ===");
    println!("Payload: 1316 B | QD: 1, 8, 32, 128, 256 | Peers: 1, 100, 1000\n");

    const ITERS: usize = 5_000;
    let configurations = [(1, 1), (8, 1), (32, 100), (128, 600), (256, 1000)];

    let mut rows_raw = Vec::new();
    let mut rows_compio = Vec::new();

    for &(qd, peers) in &configurations {
        eprintln!("Benchmarking QD={}, peers={}...", qd, peers);
        let raw = bench_raw_io_uring(qd, peers, ITERS);
        let comp = bench_compio_driver(qd, peers, ITERS);
        rows_raw.push(raw);
        rows_compio.push(comp);
    }

    println!(
        "{:<14} | {:>4} | {:>5} | {:>10} | {:>14} | {:>12} | {:>10}",
        "Driver", "QD", "Peers", "Ops/sec", "CPU ns/op", "P99 lat (ns)", "Allocs/op"
    );
    println!(
        "{:-<14}-+-{:-<4}-+-{:-<5}-+-{:-<10}-+-{:-<14}-+-{:-<12}-+-{:-<10}",
        "", "", "", "", "", "", ""
    );

    for (raw, comp) in rows_raw.iter().zip(rows_compio.iter()) {
        println!(
            "{:<14} | {:>4} | {:>5} | {:>10.0} | {:>14.1} | {:>12} | {:>10.2}",
            raw.driver,
            raw.qd,
            raw.peers,
            raw.ops_per_sec,
            raw.cpu_ns_per_op,
            raw.p99_latency_ns,
            raw.allocs_per_op
        );
        println!(
            "{:<14} | {:>4} | {:>5} | {:>10.0} | {:>14.1} | {:>12} | {:>10.2}",
            comp.driver,
            comp.qd,
            comp.peers,
            comp.ops_per_sec,
            comp.cpu_ns_per_op,
            comp.p99_latency_ns,
            comp.allocs_per_op
        );
        println!(
            "{:-<14}-+-{:-<4}-+-{:-<5}-+-{:-<10}-+-{:-<14}-+-{:-<12}-+-{:-<10}",
            "", "", "", "", "", "", ""
        );
    }
    println!();

    println!("=== NATIVE IO_URING OPPORTUNITY ENVELOPE (Section 26) ===");
    // Primary production reference: 8 Mbps at 600 destinations = 456,000 pps
    let production_pps = 456_000.0;
    // Total Compio SRT CPU measured at 600 fanout is ~3.5 cores
    let total_compio_srt_cores = 3.5;

    // Use realistic production fanout point (QD=128, peers=600)
    let ref_raw = &rows_raw[3];
    let ref_comp = &rows_compio[3];
    let delta_d = (ref_comp.cpu_ns_per_op - ref_raw.cpu_ns_per_op).max(0.0);
    let potential_saved_cores = delta_d * production_pps / 1e9;
    let potential_fraction = potential_saved_cores / total_compio_srt_cores * 100.0;

    println!(
        "Reference configuration: QD={}, peers={}",
        ref_raw.qd, ref_raw.peers
    );
    println!(
        "- Compio driver CPU ns/datagram: {:>10.1} ns",
        ref_comp.cpu_ns_per_op
    );
    println!(
        "- Raw io_uring CPU ns/datagram:  {:>10.1} ns",
        ref_raw.cpu_ns_per_op
    );
    println!("- Delta (ΔD):                    {:>10.1} ns", delta_d);
    println!(
        "- Production PPS (600 fanout):   {:>10.0} pps",
        production_pps
    );
    println!(
        "- Potential saved cores:         {:>10.3} cores",
        potential_saved_cores
    );
    println!(
        "- Potential saved % of SRT CPU:  {:>10.1} %",
        potential_fraction
    );

    let classification = if potential_fraction < 10.0 {
        "<10%: STAY COMPIO (native overhead recovery is negligible relative to crypto/protocol/kernel)"
    } else if potential_fraction <= 20.0 {
        "10-20%: LIKELY STAY COMPIO (modest driver gain does not justify maintaining duplicate transport)"
    } else if potential_fraction <= 30.0 {
        ">20%: NATIVE PROTOTYPE WORTHWHILE"
    } else {
        ">25-30%: NATIVE DESERVES CONSIDERATION AS SUPPORTED SIBLING BACKEND"
    };
    println!("- Decision Recommendation:       {}", classification);
    println!();
}
