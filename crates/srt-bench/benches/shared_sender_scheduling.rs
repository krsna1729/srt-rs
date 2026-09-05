use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use srt_bench::{
    BondMode, ConnectLimiter, Egress, Encryption, Ingress, Mode, Promotion, SharedSender,
};

fn sender_config(connections: usize, cc: usize) -> srt_bench::BenchConfig {
    srt_bench::BenchConfig {
        runtime: srt_bench::Runtime::Mio,
        mode: Mode::Sender,
        encryption: Encryption::Plain,
        host: "127.0.0.1".to_owned(),
        port: 9000,
        duration_secs: 60.0,
        latency_ms: 120,
        source_bitrate_bps: 1_000_000,
        bandwidth: srt_bench::source::BandwidthPolicy::default(),
        source_backlog_ms: srt_bench::source::DEFAULT_SOURCE_BACKLOG_MS,
        datapath_queue_horizon_ms: srt_bench::queue::DEFAULT_DATAPATH_QUEUE_HORIZON_MS,
        outbound_retry_horizon_ms: srt_bench::scheduling::DEFAULT_OUTBOUND_RETRY_HORIZON_MS,
        connections,
        egress: Egress::SharedSocket,
        ingress: Ingress::SharedPool(1),
        bond_mode: BondMode::None,
        bond_pairs: 0,
        batching: srt_bench::Batching::On,
        recv_rounds: 8,
        would_block: srt_bench::scheduling::WouldBlockPolicy::Retain,
        connect_concurrency: cc,
        promotion: Promotion::Never,
        cookie_routing: true,
        sock_buf_bytes: 0,
        out: None,
        rep: 1,
        attempt: String::new(),
        cpus: 0,
        pin: false,
        workers: 1,
        stream_secs: 60.0,
        peer_topology: srt_bench::PeerTopology::default(),
        link: srt_bench::Link::default(),
        classifier_policy: srt_bench::model::ClassifierPolicy::default(),
    }
}

type SenderFixture = (
    SharedSender,
    srt_bench::BenchConfig,
    Vec<(std::net::SocketAddr, Vec<u8>)>,
);

fn make_sender(n: usize, cc: usize) -> SenderFixture {
    let cfg = sender_config(n, cc);
    let indices: Vec<usize> = (0..n).collect();
    let limiter = Arc::new(Mutex::new(ConnectLimiter::new(cc)));
    let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
    let mut out = Vec::new();
    sender.tick(&cfg, &mut out);
    sender.tick(&cfg, &mut out);
    out.clear();
    (sender, cfg, out)
}

fn make_connected_sender(n: usize) -> SenderFixture {
    let cfg = sender_config(n, n);
    let indices: Vec<usize> = (0..n).collect();
    let limiter = Arc::new(Mutex::new(ConnectLimiter::new(n)));
    let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
    let mut out = Vec::new();
    sender.tick(&cfg, &mut out);
    sender.tick(&cfg, &mut out);
    sender.force_all_connected();
    out.clear();
    (sender, cfg, out)
}
fn make_due_sender(n: usize, due_count: usize) -> SenderFixture {
    let mut fixture = make_connected_sender(n);
    for slot_id in 0..due_count.min(n) {
        fixture.0.force_arm_due_send(slot_id);
    }
    fixture
}

fn bench_handshaking_tick(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_handshaking_tick");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched_ref(
                || make_sender(n as usize, n as usize),
                |fixture| {
                    let (sender, cfg, out) = fixture;
                    sender.tick(cfg, out);
                    black_box(sender.sched_stats());
                    black_box(out.len());
                    out.clear();
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_quiescent_scheduler_tick(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_quiescent_scheduler_tick");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched_ref(
                || make_connected_sender(n as usize),
                |fixture| {
                    let (sender, cfg, out) = fixture;
                    sender.tick(cfg, out);
                    black_box(sender.sched_stats());
                    black_box(out.len());
                    out.clear();
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_sparse_due_tick(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_due_tick");
    for (n, due_count, label) in [
        (1000, 1, "1000_1_due"),
        (4096, 1, "4096_1_due"),
        (4096, 41, "4096_1pct_due"),
        (1000, 1000, "1000_all_due"),
        (4096, 4096, "4096_all_due"),
    ] {
        group.throughput(Throughput::Elements(due_count as u64));
        group.bench_function(label, |b| {
            b.iter_batched_ref(
                || make_due_sender(n, due_count),
                |fixture| {
                    let (sender, cfg, out) = fixture;
                    sender.tick(cfg, out);
                    black_box(sender.sched_stats());
                    black_box(out.len());
                    out.clear();
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// Worst case for a population-scanning `done()`: every slot terminal but
/// the last, so `Iterator::all` cannot short-circuit.
fn make_almost_done_sender(n: usize) -> SenderFixture {
    let mut fixture = make_connected_sender(n);
    fixture.0.force_all_terminal_except_last();
    fixture
}

/// Prices `done()` on the fixture that actually exercises the old scan.
///
/// `make_sender` leaves slot 0 live, so the pre-change
/// `slots.iter().all(|s| s.closed)` short-circuits after one slot and
/// measures ~nothing regardless of N. Both rows here run on the same
/// worst-case fixture, so the O(N)-vs-O(1) comparison is apples-to-apples.
fn bench_done_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_done_check");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("terminal_count", n), &n, |b, &n| {
            b.iter_batched_ref(
                || make_almost_done_sender(n as usize),
                |fixture| {
                    let (sender, _cfg, _out) = fixture;
                    black_box(sender.done());
                },
                BatchSize::PerIteration,
            );
        });
        group.bench_with_input(BenchmarkId::new("population_scan", n), &n, |b, &n| {
            b.iter_batched_ref(
                || make_almost_done_sender(n as usize),
                |fixture| {
                    let (sender, _cfg, _out) = fixture;
                    black_box(sender.done_by_population_scan());
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_next_wait(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_next_wait");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched_ref(
                || make_sender(n as usize, n as usize),
                |fixture| {
                    let (sender, _cfg, _out) = fixture;
                    black_box(sender.next_wait());
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_quiescent_scheduler_next_wait(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_quiescent_scheduler_next_wait");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched_ref(
                || make_connected_sender(n as usize),
                |fixture| {
                    let (sender, _cfg, _out) = fixture;
                    black_box(sender.next_wait());
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// Drain N queued admissions at `cc=1`, one grant per completed permit.
///
/// This is the shape that used to be quadratic: the pre-grant design removed
/// a selected waiter from the FIFO but left the future holding its id, so
/// each successful admission then scanned the remaining queue looking for an
/// entry that was already gone. Wake-counting cannot see that; wall time per
/// admission can. Throughput is set to N so Criterion reports per-admission
/// cost, which should stay flat as N grows.
fn bench_sequential_admission(c: &mut Criterion) {
    use srt_bench::{HandshakeAdmission, HandshakePermit};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let mut group = c.benchmark_group("admission_sequential_drain");
    for n in [64u32, 256, 1024, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let n = n as usize;
            b.iter_batched(
                || Arc::new(Mutex::new(ConnectLimiter::new(1))),
                |lim| {
                    let waker = Waker::noop();
                    let mut cx = Context::from_waker(waker);
                    let mut futures: Vec<_> = (0..n)
                        .map(|_| Box::pin(HandshakeAdmission::new(&lim, 1)))
                        .collect();
                    let mut permit: Option<HandshakePermit> = None;
                    for f in &mut futures {
                        if let Poll::Ready(p) = f.as_mut().poll(&mut cx) {
                            permit = Some(p);
                        }
                    }
                    let mut held = permit.expect("first admission");
                    for f in futures.iter_mut().skip(1) {
                        held.complete();
                        match f.as_mut().poll(&mut cx) {
                            Poll::Ready(p) => held = p,
                            Poll::Pending => unreachable!("granted waiter must be ready"),
                        }
                    }
                    held.complete();
                    black_box(lim.lock().unwrap().started());
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_admission_throttled(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_admission_throttled");
    for n in [30u32, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let n = n as usize;
            b.iter_batched_ref(
                || {
                    let cfg = sender_config(n, 4);
                    let indices: Vec<usize> = (0..n).collect();
                    let limiter = Arc::new(Mutex::new(ConnectLimiter::new(4)));
                    let sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
                    let out = Vec::new();
                    (sender, cfg, out)
                },
                |fixture| {
                    let (sender, cfg, out) = fixture;
                    sender.tick(cfg, out);
                    black_box(sender.sched_stats());
                    black_box(sender.limiter_snapshot());
                    out.clear();
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_sched_stats_readout(c: &mut Criterion) {
    let mut group = c.benchmark_group("sender_sched_stats");
    for n in [1u32, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched_ref(
                || make_sender(n as usize, n as usize),
                |fixture| {
                    let (sender, _cfg, _out) = fixture;
                    let stats = sender.sched_stats();
                    black_box(stats.tick_calls);
                    black_box(stats.dirty_slot_visits);
                    black_box(stats.application_due_visits);
                    black_box(stats.handshake_state_visits);
                    black_box(stats.closing_slot_visits);
                    black_box(stats.slot_visits());
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// Prices the constant-space source-clock work added to each payload path.
fn bench_source_clock(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_clock");
    group.throughput(Throughput::Elements(1_000));
    group.bench_function("tick_and_accept", |b| {
        b.iter_batched(
            || {
                srt_bench::source::SourceClock::new(
                    std::num::NonZeroU64::new(8_000_000).expect("non-zero source rate"),
                    256,
                )
            },
            |mut clock| {
                for micros in 0..1_000 {
                    clock.tick(Duration::from_micros(micros * 1_316));
                    if clock.pending() > 0 {
                        clock.accepted();
                    }
                }
                black_box(clock.stats());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_bounded_datapath_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("bounded_datapath_queue");
    group.bench_function("send_receive", |b| {
        b.iter_batched(
            || srt_bench::queue::bounded_channel(64),
            |(sender, receiver)| {
                sender.try_send(black_box(1_u64)).unwrap();
                black_box(receiver.try_recv().unwrap());
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("full_reject", |b| {
        b.iter_batched(
            || {
                let (sender, receiver) = srt_bench::queue::bounded_channel(1);
                sender.try_send(1_u64).unwrap();
                (sender, receiver)
            },
            |(sender, receiver)| {
                black_box(sender.try_send(2_u64).is_err());
                black_box(receiver.stats());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_tokio_scheduling_telemetry(c: &mut Criterion) {
    let mut group = c.benchmark_group("tokio_scheduling_telemetry");
    group.bench_function("retry_would_block_retain", |b| {
        b.iter_batched(
            || {
                let mut queue = srt_bench::scheduling::RetryQueue::new(
                    srt_bench::scheduling::WouldBlockPolicy::Retain,
                    4096,
                );
                let mut generated = vec![("127.0.0.1:9000".parse().unwrap(), vec![0; 1316]); 32];
                queue.append(&mut generated);
                queue
            },
            |mut queue| {
                queue
                    .flush_with(|_| Err(std::io::ErrorKind::WouldBlock.into()))
                    .unwrap();
                black_box(queue.stats());
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function("timer_lateness_record", |b| {
        let mut stats = srt_bench::scheduling::RecvSchedulingStats::default();
        b.iter(|| {
            stats.record_lateness(black_box(std::time::Duration::from_micros(17)));
            black_box(stats.percentile_bucket_us(99));
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_handshaking_tick,
    bench_quiescent_scheduler_tick,
    bench_sparse_due_tick,
    bench_done_check,
    bench_next_wait,
    bench_quiescent_scheduler_next_wait,
    bench_admission_throttled,
    bench_sequential_admission,
    bench_sched_stats_readout,
    bench_source_clock,
    bench_bounded_datapath_queue,
    bench_tokio_scheduling_telemetry
);
criterion_main!(benches);
