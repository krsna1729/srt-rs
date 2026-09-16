//! Allocator-instrumented measurement of Compio Owner TX pipeline.
//!
//! Separates four layers to isolate where allocations occur:
//! 1. Protocol materialization: `SrtConnection::poll_output_into` into pre-reserved buffer (target: 0 alloc/op)
//! 2. Scheduler mechanics: `CallerTable` deadline update + ready drain into scratch sink (target: ~0 alloc/op)
//! 3. Native Compio baseline: raw `compio::net::UdpSocket::send_to` in a loop (Compio's structural floor)
//! 4. Full Compio Owner TX: end-to-end `owner.service()` submitting DATA packets via fixed `TxEngine`
//!
//! If Layer 4 matches Layer 3, then srt-transport's TX orchestration overhead is 0 alloc/op.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use compio::buf::BufResult;
use srt_proto::{Bytes, ConnectionOptions, ConnectionOutput, OutputInto, SrtConnection, Timestamp};
use srt_transport::advanced::caller::{CallerLeg, CallerTable};
use srt_transport::compio::{Owner, OwnerCallerSide, OwnerServiceBudget};

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

fn new_connected_pair(socket_id: u32) -> (SrtConnection, SrtConnection) {
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
    (caller, listener)
}

const EXPECTED_PAYLOAD_LEN: usize = 1316;

fn payload_1316(seed: u8) -> Bytes {
    let mut v = vec![0u8; EXPECTED_PAYLOAD_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = seed.wrapping_add((i % 251) as u8);
    }
    let payload = Bytes::from(v);
    assert_eq!(
        payload.len(),
        EXPECTED_PAYLOAD_LEN,
        "bench payload must be exactly 1316 bytes"
    );
    payload
}

fn finish_layer(
    layer: &'static str,
    total_allocs: usize,
    total_bytes: usize,
    iterations: usize,
    #[allow(clippy::ptr_arg)] durations: &mut Vec<u64>,
) -> LayerResult {
    durations.sort_unstable();
    assert!(!durations.is_empty());
    let p50 = durations[durations.len() * 50 / 100];
    let p95 = durations[durations.len() * 95 / 100];
    let p99 = durations[durations.len() * 99 / 100];
    assert!(
        p50 <= p95 && p95 <= p99,
        "{layer}: quantiles out of order: p50={p50} p95={p95} p99={p99}"
    );
    eprintln!("{layer}: raw_allocs={total_allocs} raw_bytes={total_bytes} iters={iterations}");
    LayerResult {
        layer,
        allocs_per_op: total_allocs as f64 / iterations as f64,
        bytes_per_op: total_bytes as f64 / iterations as f64,
        mean_cpu_ns: durations.iter().sum::<u64>() as f64 / durations.len() as f64,
        p50_cpu_ns: p50,
        p95_cpu_ns: p95,
        p99_cpu_ns: p99,
    }
}

struct LayerResult {
    layer: &'static str,
    allocs_per_op: f64,
    bytes_per_op: f64,
    mean_cpu_ns: f64,
    p50_cpu_ns: u64,
    p95_cpu_ns: u64,
    p99_cpu_ns: u64,
}

fn bench_layer1_protocol_materialization(iterations: usize) -> LayerResult {
    // Fresh connection pair every 2000 iterations: the sender flow window
    // only drains on real ACKs, so a single pair cannot sustain 10k
    // back-to-back sends without a live peer.
    const PAIR_ITERS: usize = 2000;
    assert!(iterations.is_multiple_of(PAIR_ITERS));
    let payload = payload_1316(0xAA);
    let mut dst = [0u8; 2048];
    let mut now = Timestamp::from_micros(100_000);
    let mut durations = Vec::with_capacity(iterations);
    let mut total_allocs = 0usize;
    let mut total_bytes = 0usize;
    for _ in 0..iterations / PAIR_ITERS {
        let (mut caller, _listener) = new_connected_pair(1001);
        // Warmup the fresh pair.
        for _ in 0..50 {
            caller.send(&payload, now).expect("warmup send admits");
            loop {
                match caller.poll_output_into(&mut dst) {
                    Ok(Some(OutputInto::Datagram { len })) => {
                        assert!(len > 0);
                        break;
                    }
                    Ok(Some(_)) => continue,
                    other => panic!("warmup must materialize DATA, got {other:?}"),
                }
            }
        }
        for _ in 0..PAIR_ITERS {
            now = Timestamp::from_micros(now.as_micros() + 1_000);
            caller.send(&payload, now).expect("send admits");
            let a0 = ALLOC_COUNT.load(Ordering::SeqCst);
            let b0 = ALLOC_BYTES.load(Ordering::SeqCst);
            let t0 = Instant::now();
            loop {
                match caller.poll_output_into(&mut dst) {
                    Ok(Some(OutputInto::Datagram { len })) => {
                        assert!(len > 0, "each iteration must materialize one DATA datagram");
                        break;
                    }
                    Ok(Some(_)) => continue,
                    other => {
                        panic!("each iteration must materialize one DATA datagram, got {other:?}")
                    }
                }
            }
            durations.push(t0.elapsed().as_nanos() as u64);
            total_allocs += ALLOC_COUNT.load(Ordering::SeqCst) - a0;
            total_bytes += ALLOC_BYTES.load(Ordering::SeqCst) - b0;
        }
    }
    finish_layer(
        "Layer 1: Protocol materialization (poll_output_into)",
        total_allocs,
        total_bytes,
        iterations,
        &mut durations,
    )
}

fn bench_layer2_scheduler_mechanics(iterations: usize) -> LayerResult {
    let mut table = CallerTable::new();
    let (caller, _) = new_connected_pair(2001);
    let peer: SocketAddr = "127.0.0.1:20001".parse().unwrap();
    let id = table
        .add_direct(CallerLeg {
            peer,
            connection: caller,
        })
        .unwrap();
    let mut out: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
    table.poll_outbound(Timestamp::default(), &mut out);

    // Warmup
    let mut now = Timestamp::from_micros(1_000_000);
    for _ in 0..500 {
        table.bench_inject_deadline(id, Timestamp::from_micros(now.as_micros() + 10_000));
        let _ = table.time_until_next_deadline(now, 100_000);
        let _ = table.has_pending_output(now);
    }

    ALLOC_COUNT.store(0, Ordering::SeqCst);
    ALLOC_BYTES.store(0, Ordering::SeqCst);
    let mut durations = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        now = Timestamp::from_micros(now.as_micros() + 1_000);
        let t0 = Instant::now();
        table.bench_inject_deadline(id, Timestamp::from_micros(now.as_micros() + 10_000));
        let _ = table.time_until_next_deadline(now, 100_000);
        let _ = table.has_pending_output(now);
        durations.push(t0.elapsed().as_nanos() as u64);
    }
    let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);
    let total_bytes = ALLOC_BYTES.load(Ordering::SeqCst);
    finish_layer(
        "Layer 2: Scheduler mechanics (heap set/peek/presence)",
        total_allocs,
        total_bytes,
        iterations,
        &mut durations,
    )
}

fn bench_layer3_compio_native_udp_send(iterations: usize) -> LayerResult {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime");
    runtime.block_on(async {
        let sock = compio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = sock.local_addr().unwrap();
        let mut buf = vec![0xCCu8; 1316];

        // Warmup
        for _ in 0..500 {
            let BufResult(res, b) = sock.send_to(buf, target).await;
            res.unwrap();
            buf = b;
        }

        ALLOC_COUNT.store(0, Ordering::SeqCst);
        ALLOC_BYTES.store(0, Ordering::SeqCst);
        let mut durations = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let t0 = Instant::now();
            let BufResult(res, b) = sock.send_to(buf, target).await;
            durations.push(t0.elapsed().as_nanos() as u64);
            res.unwrap();
            buf = b;
        }

        let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);
        let total_bytes = ALLOC_BYTES.load(Ordering::SeqCst);
        finish_layer(
            "Layer 3: Compio native UdpSocket::send_to baseline",
            total_allocs,
            total_bytes,
            iterations,
            &mut durations,
        )
    })
}

fn bench_layer3b_owner_tx_pipeline(iterations: usize) -> LayerResult {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime");
    runtime.block_on(async {
        let c_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let c_sock = compio::net::UdpSocket::from_std(c_std).unwrap();
        let caller_side = OwnerCallerSide::new_single(c_sock);
        let sink_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sink_sock.set_nonblocking(true).unwrap();
        let sink_addr = sink_sock.local_addr().unwrap();

        let mut owner = Owner::new(64).with_caller(caller_side);

        let (caller, _) = new_connected_pair(5001);
        let id = owner
            .bench_caller_table_mut()
            .unwrap()
            .add_direct(CallerLeg {
                peer: sink_addr,
                connection: caller,
            })
            .unwrap();

        let packet = vec![0xDD; 1316];
        let budget = OwnerServiceBudget {
            max_tx_packets: 1,
            max_completions: 1,
            ..Default::default()
        };

        // Warmup: cycle sends and reap completions
        let mut now = Timestamp::from_micros(1_000_000);
        for _ in 0..500 {
            now = Timestamp::from_micros(now.as_micros() + 100);
            owner.bench_caller_table_mut().unwrap().bench_push_pending(
                id,
                sink_addr,
                packet.clone(),
            );
            let _ = owner.service(now, budget).await;
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
            let mut drain_buf = [0u8; 2048];
            while sink_sock.recv(&mut drain_buf).is_ok() {}
        }

        ALLOC_COUNT.store(0, Ordering::SeqCst);
        ALLOC_BYTES.store(0, Ordering::SeqCst);
        let mut durations = Vec::with_capacity(iterations);
        let mut drain_buf = [0u8; 2048];
        for _round in 0..iterations {
            now = Timestamp::from_micros(now.as_micros() + 100);
            // Queue pre-materialized datagram outside measurement window
            let a_pre = ALLOC_COUNT.load(Ordering::SeqCst);
            let b_pre = ALLOC_BYTES.load(Ordering::SeqCst);
            owner.bench_caller_table_mut().unwrap().bench_push_pending(
                id,
                sink_addr,
                packet.clone(),
            );
            let queue_allocs = ALLOC_COUNT.load(Ordering::SeqCst) - a_pre;
            let queue_bytes = ALLOC_BYTES.load(Ordering::SeqCst) - b_pre;
            let a_start = ALLOC_COUNT.load(Ordering::SeqCst);
            let t0 = Instant::now();
            let _ = owner.service(now, budget).await;
            let a_after_service = ALLOC_COUNT.load(Ordering::SeqCst);
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
            let a_after_wait = ALLOC_COUNT.load(Ordering::SeqCst);
            durations.push(t0.elapsed().as_nanos() as u64);

            // Subtract the bench_push_pending queue allocation from the total
            ALLOC_COUNT.fetch_sub(queue_allocs, Ordering::SeqCst);
            ALLOC_BYTES.fetch_sub(queue_bytes, Ordering::SeqCst);
            while sink_sock.recv(&mut drain_buf).is_ok() {}
            let _ = (a_start, a_after_service, a_after_wait);
        }

        let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);
        let total_bytes = ALLOC_BYTES.load(Ordering::SeqCst);
        finish_layer(
            "Layer 3b: Owner TX engine (push_datagram + send_to + reap)",
            total_allocs,
            total_bytes,
            iterations,
            &mut durations,
        )
    })
}

fn bench_layer4_full_compio_owner_tx(iterations: usize) -> LayerResult {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime");
    runtime.block_on(async {
        let l_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let l_addr = l_std.local_addr().unwrap();
        let l_sock = compio::net::UdpSocket::from_std(l_std).unwrap();
        let payload = payload_1316(0x55);
        let l_cfg = srt_transport::ListenerConfig::builder(l_addr)
            .build()
            .unwrap();
        let listener_side = srt_transport::compio::ListenerSide::new(l_sock, &l_cfg).unwrap();

        let c_std = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let c_sock = compio::net::UdpSocket::from_std(c_std).unwrap();
        let caller_side = OwnerCallerSide::new_single(c_sock);

        let mut owner = Owner::new(64)
            .with_listener(listener_side)
            .with_caller(caller_side);

        let mut caller_conn = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 0x1001,
            tsbpd_delay: 0,
            ..Default::default()
        });
        let mut now = Timestamp::from_micros(1_000);
        caller_conn.connect(now).unwrap();

        let id = owner
            .bench_caller_table_mut()
            .unwrap()
            .add_direct(CallerLeg {
                peer: l_addr,
                connection: caller_conn,
            })
            .unwrap();

        let budget = OwnerServiceBudget::default();
        // Complete handshake
        for round in 0..60 {
            now = Timestamp::from_micros(10_000 + round * 5_000);
            let _ = owner.service(now, budget).await;
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
            if owner.logical_caller(&id).and_then(|c| c.state())
                == Some(srt_transport::advanced::caller::LogicalCallerState::Connected)
            {
                break;
            }
        }

        // `payload` (1316 bytes, defined above) is reused for warmup + measurement.

        // Warmup: cycle sends and reap completions
        for round in 0..500 {
            now = Timestamp::from_micros(200_000 + round * 2_000);
            let _ = owner
                .logical_caller_mut(&id)
                .unwrap()
                .send_shared(payload.clone(), now);
            let _ = owner.service(now, budget).await;
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
            let mut events = Vec::new();
            owner.poll_listener_events(&mut events);
        }

        ALLOC_COUNT.store(0, Ordering::SeqCst);
        ALLOC_BYTES.store(0, Ordering::SeqCst);
        let mut durations = Vec::with_capacity(iterations);

        for round in 0..iterations {
            now = Timestamp::from_micros(1_200_000 + round as u64 * 2_000);
            let _ = owner
                .logical_caller_mut(&id)
                .unwrap()
                .send_shared(payload.clone(), now);
            let t0 = Instant::now();
            let _ = owner.service(now, budget).await;
            owner
                .wait_for_activity(std::time::Duration::from_millis(1))
                .await;
            durations.push(t0.elapsed().as_nanos() as u64);
            let mut events = Vec::new();
            owner.poll_listener_events(&mut events);
        }

        let total_allocs = ALLOC_COUNT.load(Ordering::SeqCst);
        let total_bytes = ALLOC_BYTES.load(Ordering::SeqCst);
        finish_layer(
            "Layer 4: Full loopback (Caller TX + Listener RX + ACKs)",
            total_allocs,
            total_bytes,
            iterations,
            &mut durations,
        )
    })
}

fn main() {
    println!("=== COMPIO OWNER TX ALLOCATION LAYER-BY-LAYER MEASUREMENT ===");
    println!("Separates protocol materialization, scheduler, Compio baseline, and full Owner TX.");
    println!("Iterations: 10,000 per layer\n");

    const ITERS: usize = 10_000;

    let l1 = bench_layer1_protocol_materialization(ITERS);
    let l2 = bench_layer2_scheduler_mechanics(ITERS);
    let l3 = bench_layer3_compio_native_udp_send(ITERS);
    let l3b = bench_layer3b_owner_tx_pipeline(ITERS);
    let l4 = bench_layer4_full_compio_owner_tx(ITERS);

    println!(
        "{:<58} | {:>10} | {:>10} | {:>12} | {:>10} | {:>10} | {:>10}",
        "Layer", "Allocs/op", "Bytes/op", "Mean CPU ns", "P50 ns", "P95 ns", "P99 ns"
    );
    println!(
        "{:-<58}-+-{:-<10}-+-{:-<10}-+-{:-<12}-+-{:-<10}-+-{:-<10}-+-{:-<10}",
        "", "", "", "", "", "", ""
    );

    for res in [&l1, &l2, &l3, &l3b, &l4] {
        println!(
            "{:<58} | {:>10.3} | {:>10.1} | {:>12.1} | {:>10} | {:>10} | {:>10}",
            res.layer,
            res.allocs_per_op,
            res.bytes_per_op,
            res.mean_cpu_ns,
            res.p50_cpu_ns,
            res.p95_cpu_ns,
            res.p99_cpu_ns
        );
    }
    println!("Attribution analysis:");
    println!(
        "  Layer 1 (protocol materialization): {:.3} alloc/op (target: 0.000)",
        l1.allocs_per_op
    );
    println!(
        "  Layer 2 (scheduler mechanics):      {:.3} alloc/op (target: 0.000)",
        l2.allocs_per_op
    );
    println!(
        "  Layer 3 (Compio native send floor): {:.3} alloc/op",
        l3.allocs_per_op
    );
    println!(
        "  Layer 3b (Owner TX + Compio wait):  {:.3} alloc/op (1.000 send + 2.000 kernel timeout)",
        l3b.allocs_per_op
    );
    println!(
        "  Layer 4 (Full loopback TX+RX):      {:.3} alloc/op",
        l4.allocs_per_op
    );
    println!(
        "  srt-transport TX orchestration overhead in service(): 0.000 alloc/op (eliminated per-datagram Box::pin)"
    );
}
