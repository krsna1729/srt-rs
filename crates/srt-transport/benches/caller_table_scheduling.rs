use std::hint::black_box;
use std::net::SocketAddr;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{ConnectionOptions, ConnectionOutput, SRTGROUP_MASK, SrtConnection, Timestamp};
use srt_transport::{CallerLeg, CallerTable};

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
        if caller.state() == shiguredo_srt::ConnectionState::Connected {
            break;
        }
    }
    assert_eq!(caller.state(), shiguredo_srt::ConnectionState::Connected);
    caller
}

type TableFixture = (CallerTable, Vec<srt_transport::LogicalCallerId>);

fn make_table(n: usize, base_now: Timestamp) -> TableFixture {
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
    // Drain initial handshake/connected work so table becomes idle (deadlines in future, no ready).
    table.poll_outbound(base_now, &mut out);
    // Second poll at same now is an idle check.
    table.poll_outbound(base_now, &mut out);
    (table, ids)
}

// Timing model: `iter_batched_ref` holds the fixture (N full SRT connections)
// outside the timer. The routine borrows it mutably and returns the output
// vector by value, so both fixture teardown and packet-buffer destruction
// happen outside the measured region. `PerIteration` guarantees a fresh
// connected fixture per iteration (no cross-iteration drain-state reuse).
fn bench_idle_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("caller_idle_poll");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let n = n as usize;
            b.iter_batched_ref(
                || {
                    let now = Timestamp::from_micros(1_000_000);
                    make_table(n, now)
                },
                |fixture| {
                    let (table, _ids) = fixture;
                    let mut out = Vec::new();
                    let now = Timestamp::from_micros(1_000_000);
                    let budget = srt_transport::OutputDrainBudget::new(64, 32, 256 * 1024);
                    let report = table.poll_outbound_bounded(now, budget, &mut out);
                    black_box(report);
                    #[cfg(feature = "bench-internals")]
                    {
                        black_box(table.sched_counters());
                        black_box(table.deadline_count());
                        black_box(table.ready_queue_len());
                    }
                    out
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_one_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group("caller_one_ready");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let n = n as usize;
            b.iter_batched_ref(
                || {
                    let now = Timestamp::from_micros(1_000_000);
                    let (mut table, ids) = make_table(n, now);
                    // Make exactly one caller ready via send on a connected caller.
                    if n > 0 {
                        let first_id = ids[0];
                        let mut m = table.logical_caller_mut(&first_id).expect("exists");
                        let res = m.send(b"benchmark-payload-data", now);
                        assert!(
                            res.is_ok(),
                            "send must succeed on Connected caller: {:?}",
                            res
                        );
                    }
                    (table, ids)
                },
                |fixture| {
                    let (table, _ids) = fixture;
                    let mut out = Vec::new();
                    let now = Timestamp::from_micros(1_000_000);
                    let budget = srt_transport::OutputDrainBudget::new(64, 32, 256 * 1024);
                    let report = table.poll_outbound_bounded(now, budget, &mut out);
                    black_box(report);
                    #[cfg(feature = "bench-internals")]
                    {
                        black_box(table.sched_counters());
                    }
                    out
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_one_due(c: &mut Criterion) {
    let mut group = c.benchmark_group("caller_one_due");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let n = n as usize;
            b.iter_batched_ref(
                || {
                    let now = Timestamp::from_micros(1_000_000);
                    let (mut table, ids) = make_table(n, now);
                    if n > 0 {
                        let first_id = ids[0];
                        // Arm a real Ack timer on first_id exactly at now.
                        table.bench_arm_timer(first_id, shiguredo_srt::TimerId::Ack, 0, now);
                    }
                    (table, ids)
                },
                |fixture| {
                    let (table, _ids) = fixture;
                    let mut out = Vec::new();
                    let now = Timestamp::from_micros(1_000_000);
                    let budget = srt_transport::OutputDrainBudget::new(64, 32, 256 * 1024);
                    let report = table.poll_outbound_bounded(now, budget, &mut out);
                    black_box(report);
                    #[cfg(feature = "bench-internals")]
                    {
                        black_box(table.sched_counters());
                    }
                    out
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_sparse_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group("caller_sparse_ready");
    for n in [30u32, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let n = n as usize;
            b.iter_batched_ref(
                || {
                    let now = Timestamp::from_micros(1_000_000);
                    let (mut table, ids) = make_table(n, now);
                    let ready = (n / 100).max(1); // 1%
                    for id in ids.iter().copied().take(ready) {
                        let mut m = table.logical_caller_mut(&id).expect("exists");
                        let res = m.send(b"benchmark-payload-data", now);
                        assert!(
                            res.is_ok(),
                            "send must succeed on Connected caller: {:?}",
                            res
                        );
                    }
                    (table, ids)
                },
                |fixture| {
                    let (table, _ids) = fixture;
                    let mut out = Vec::new();
                    let budget = srt_transport::OutputDrainBudget::new(64, 32, 256 * 1024);
                    let now = Timestamp::from_micros(1_000_000);
                    let report = table.poll_outbound_bounded(now, budget, &mut out);
                    black_box(report);
                    out
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_all_ready(c: &mut Criterion) {
    let mut group = c.benchmark_group("caller_all_ready");
    for n in [1u32, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let n = n as usize;
            b.iter_batched_ref(
                || {
                    let now = Timestamp::from_micros(1_000_000);
                    let (mut table, ids) = make_table(n, now);
                    // Make all callers ready via send.
                    for id in &ids {
                        let mut m = table.logical_caller_mut(id).expect("exists");
                        let res = m.send(b"benchmark-payload-data", now);
                        assert!(
                            res.is_ok(),
                            "send must succeed on Connected caller: {:?}",
                            res
                        );
                    }
                    (table, ids)
                },
                |fixture| {
                    let (table, _ids) = fixture;
                    let mut out = Vec::new();
                    let now = Timestamp::from_micros(1_000_000);
                    let budget =
                        srt_transport::OutputDrainBudget::new(usize::MAX, usize::MAX, usize::MAX);
                    let report = table.poll_outbound_bounded(now, budget, &mut out);
                    black_box(report);
                    out
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_reschedule(c: &mut Criterion) {
    let mut group = c.benchmark_group("caller_reschedule");
    for n in [30u32, 200, 1000, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched_ref(
                || {
                    let now = Timestamp::from_micros(1_000_000);
                    let (table, ids) = make_table(n as usize, now);
                    let first_id = ids[0];
                    (table, first_id, now)
                },
                |state: &mut (CallerTable, srt_transport::LogicalCallerId, Timestamp)| {
                    let mut now = state.2;
                    for i in 0..100 {
                        now = Timestamp::from_micros(now.as_micros() + 1000 + i);
                        state.0.bench_arm_timer(
                            state.1,
                            shiguredo_srt::TimerId::Ack,
                            1000 + i,
                            now,
                        );
                        black_box(state.0.time_until_next_deadline(now, 100_000));
                    }
                    black_box(state.0.deadline_count());
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_churn(c: &mut Criterion) {
    let mut group = c.benchmark_group("caller_churn");
    for n in [30u32, 200, 1000, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched_ref(
                || {
                    let now = Timestamp::from_micros(1_000_000);
                    make_table(n as usize, now)
                },
                |fixture| {
                    let (table, ids) = fixture;
                    // churn 10% of entries: remove and re-add
                    let churn = (ids.len() / 10).max(1);
                    for (idx, id) in ids.drain(..).take(churn).enumerate() {
                        table.remove(id);
                        let peer = make_peer(90000 + (idx % 1000));
                        let conn = new_connected_caller_connection(200000 + (idx as u32 % 100000));
                        let _ = table.add_direct(CallerLeg {
                            peer,
                            connection: conn,
                        });
                    }
                    black_box(table.len());
                    black_box(table.deadline_count());
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

fn bench_groups(c: &mut Criterion) {
    let mut group = c.benchmark_group("caller_groups");
    for n in [1u32, 30, 200, 1000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched_ref(
                || {
                    let mut table = CallerTable::new();
                    let now = Timestamp::default();
                    let mut first_group_id = None;
                    for i in 0..n as usize {
                        let gid = SRTGROUP_MASK | (1000 + i as u32);
                        let legs = (0..2).map(|j| {
                            let peer = make_peer(i * 10 + j);
                            let conn =
                                new_connected_caller_connection(300000 + (i * 10 + j) as u32);
                            srt_transport::CallerGroupLeg {
                                member_id: j as u32,
                                weight: 1,
                                peer,
                                connection: conn,
                            }
                        });
                        let id = table
                            .add_group(gid, shiguredo_srt::GroupMode::Broadcast, legs)
                            .unwrap();
                        if first_group_id.is_none() {
                            first_group_id = Some(id);
                        }
                    }
                    let mut out = Vec::new();
                    table.poll_outbound(now, &mut out);
                    if let Some(id) = first_group_id {
                        let mut m = table.logical_caller_mut(&id).expect("exists");
                        let res = m.send(b"benchmark-payload-data", now);
                        assert!(
                            res.is_ok(),
                            "group send must succeed on connected group: {:?}",
                            res
                        );
                    }
                    table
                },
                |table| {
                    let mut out = Vec::new();
                    let budget = srt_transport::OutputDrainBudget::new(64, 32, 256 * 1024);
                    let report =
                        table.poll_outbound_bounded(Timestamp::default(), budget, &mut out);
                    black_box(report);
                    out
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_idle_poll,
    bench_one_ready,
    bench_one_due,
    bench_sparse_ready,
    bench_all_ready,
    bench_reschedule,
    bench_churn,
    bench_groups
);
criterion_main!(benches);
