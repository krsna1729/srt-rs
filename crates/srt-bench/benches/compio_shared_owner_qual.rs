//! Two-process shared-`Owner` qualification: SENDER role.
//!
//! The point of this bench is that the sender is the real production
//! [`srt_transport::compio::Owner`] on its production attach path
//! (`Owner::connect`, sealed sides, finite TX pool, bounded `service`
//! budget, reserve-then-commit final-buffer TX), talking to a **separate
//! receiver process** over real UDP. It replaces the single-process
//! `compio_production_fanout` smoke bench as the capacity evidence.
//!
//! Run it against an external receiver:
//!
//! ```text
//! # terminal 1 (receiver, independent process)
//! srt-bench runtime=compio mode=receiver <base_port> <duration> 120 \
//!     --connections <fanout>
//! # terminal 2 (sender, this bench)
//! cargo bench -p srt-bench --bench compio_shared_owner_qual -- \
//!     --fanout <fanout> --duration-ms <ms> --base-port <base_port>
//! ```
//!
//! Semantics that matter for the numbers:
//!
//! * **F, K and H are independent inputs.** `--fanout F` is the destination
//!   population, `--tx-lanes K` is the fixed TX lane count (= TX capacity),
//!   and `--connect-cc H` is the number of connect attempts allowed in flight
//!   at once. Neither K nor H is derived from F: a run is only comparable to
//!   another run with the same K and H, which is what makes the capacity
//!   frontier a statement about the fixed-cost shard model.
//!
//! * **Establishment barrier.** Nothing is measured until every logical
//!   destination has reached `Connected`, or a connect deadline expires. A
//!   partial establishment is reported as such and the run is not a
//!   capacity result.
//! * **Open-loop source.** The source clock advances independently of
//!   service capacity at the 8 Mbps / 1316-byte cadence; a destination that
//!   cannot accept a tick loses that copy and it is counted as
//!   `not_accepted`, never queued in an unbounded harness backlog.
//! * **TX-enabled drain.** After the window the Owner keeps servicing with
//!   TX enabled until protocol output and in-flight sends reach zero, so the
//!   final `pending_after_drain` is a real equilibrium check.
//! * **RX mode is reported.** The Owner selects its receive datapath at
//!   attach; the selected mode is printed, because a host whose kernel
//!   cannot register a provided-buffer ring runs the raw reader and is NOT a
//!   managed-RX qualification.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use srt_proto::{Bytes, Timestamp};
use srt_transport::compio::{
    Owner, OwnerRxMode, OwnerServiceBudget, ProductionRuntimeConfig, RxModePolicy,
    production_runtime_builder,
};
use srt_transport::{CallerConfig, SocketOwnership};

const PAYLOAD_SIZE: usize = 1316;
/// 8 Mbps of 1316-byte payloads: one payload every 1316 microseconds.
const PACKET_INTERVAL_US: u64 = 1316;
const CONNECT_DEADLINE: Duration = Duration::from_secs(30);
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, Default)]
struct QualReport {
    fanout: usize,
    tx_lanes: usize,
    connect_cc: usize,
    desired: usize,
    /// `connect` calls the pool accepted (admitted or queued).
    issued: usize,
    admitted: usize,
    queued: usize,
    /// `connect` calls the pool refused because its bounded queue was full.
    /// Refusal is expected under a fixed H; the harness re-issues later.
    refused: usize,
    established: usize,
    /// Source ticks the window's wall-clock elapsed time called for.
    expected_ticks: u64,
    /// Ticks the generator actually produced.
    generated_ticks: u64,
    /// Ticks the generator never produced because a service visit overran its
    /// interval. Counted explicitly so a service-coupled shortfall cannot look
    /// like a lower offered rate.
    missed_source_ticks: u64,
    /// Application copies offered in the window (generated_ticks x F minus
    /// destinations that no longer existed).
    offered: u64,
    accepted: u64,
    /// Wire submissions attributed to the WINDOW only; the drain phase is
    /// counted separately so the two are never mixed.
    submitted: u64,
    completed_ok: u64,
    short_sends: u64,
    failed_sends: u64,
    peer_local_failures: u64,
    transient_failures: u64,
    /// Wire submissions during the post-window drain phase.
    drain_submitted: u64,
    drain_completed_ok: u64,
    tx_failures_pending: usize,
    service_visits: u64,
    lateness_p50_us: u64,
    lateness_p99_us: u64,
    lateness_max_us: u64,
    pending_after_drain: u64,
    drained: bool,
    /// Whether the pre-measurement drain reached equilibrium, so no
    /// handshake/control completion can cross the window start.
    pre_window_drained: bool,
    /// In-flight wire sends at the end of the measurement window.
    inflight_at_window_end: u64,
    rx_mode: String,
    rx_dropped: u64,
    rx_truncated: u64,
    tx_pool_free: usize,
    tx_pool_capacity: usize,
    /// Process CPU consumed by the measurement window alone; the drain phase
    /// is excluded.
    cpu_ms: f64,
}

fn process_cpu_ms() -> f64 {
    // CLOCK_PROCESS_CPUTIME_ID: service demand, not wall time.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid `timespec`; the clock id is a constant.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return 0.0;
    }
    ts.tv_sec as f64 * 1000.0 + ts.tv_nsec as f64 / 1_000_000.0
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * pct).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn parse_arg<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn run_sender(
    fanout: usize,
    duration_ms: u64,
    base_port: u16,
    tx_lanes: usize,
    connect_cc: usize,
) -> QualReport {
    let mut report = QualReport {
        fanout,
        tx_lanes,
        connect_cc,
        desired: fanout,
        ..Default::default()
    };

    // Production attach path: require io_uring and the managed RX substrate.
    // `ManagedPreferred` (not Required) so this run still produces evidence on
    // a fallback host -- and reports that it did.
    //
    // A plain session (no passphrase) carries no authentication tag, so the
    // cipher argument is `None`.
    let wire_ceiling = srt_transport::compio::required_session_wire_ceiling(PAYLOAD_SIZE, None);
    // K is an input, never a function of F: the whole point of the fixed-cost
    // shard model is that TX concurrency does not grow with the destination
    // population.
    let tx_capacity = tx_lanes;
    let cfg = ProductionRuntimeConfig::for_owner(tx_capacity, wire_ceiling);
    let builder = match production_runtime_builder(cfg) {
        Ok(builder) => builder,
        Err(error) => {
            panic!("production runtime builder refused: {error}");
        }
    };
    let runtime = builder.build().expect("production runtime builds");

    runtime.block_on(async {
        let mut owner = Owner::new_with_ceiling(tx_capacity, wire_ceiling);
        owner.set_rx_mode_policy(RxModePolicy::ManagedPreferred);
        // H is an input too: F sessions may be desired while only H
        // connection attempts are active at any moment.
        owner
            .set_caller_pool_policy(
                std::num::NonZeroUsize::new(connect_cc.max(1)).expect("nonzero"),
                CONNECT_DEADLINE,
            )
            .expect("pool policy set before first connect");

        let mut now = Timestamp::from_micros(10_000);
        // F sessions are DESIRED; H controls how many connect requests the
        // pool works on at once. The pool's own queue is bounded too, so a
        // refused request is simply re-issued on a later tick -- exactly how a
        // real application fills a bounded pool -- and refusals are reported.
        let mut ids: Vec<srt_transport::advanced::caller::LogicalCallerId> =
            Vec::with_capacity(fanout);
        let mut issued = 0usize;
        let caller_cfgs: Vec<CallerConfig> = (0..fanout)
            .map(|index| {
                let remote: SocketAddr =
                    SocketAddr::from(([127, 0, 0, 1], base_port + (index as u16 % 4096)));
                CallerConfig::builder(remote)
                    .ownership(SocketOwnership::Shared)
                    .configure_session(|session| {
                        session.handshake.timeout = CONNECT_DEADLINE;
                    })
                    .build()
                    .expect("caller config")
            })
            .collect();
        // Requests the pool queued under `--connect-cc`: the pool reports their
        // admission as an event, and the event stream also mirrors
        // immediately-admitted requests, so only queued ids are matched here.
        let mut queued_requests = std::collections::HashSet::new();

        // --- establishment barrier: nothing is measured until every
        // destination is Connected, or the deadline expires.
        let budget = OwnerServiceBudget::default();
        let barrier_start = Instant::now();
        let mut pool_events = Vec::new();
        while barrier_start.elapsed() < CONNECT_DEADLINE {
            now = Timestamp::from_micros(now.as_micros() + 1_000);
            // Bounded per tick: at most H new requests, and only while the
            // pool's bounded queue still accepts them.
            for _ in 0..connect_cc.max(1) {
                if issued == fanout {
                    break;
                }
                match owner
                    .connect(&caller_cfgs[issued], now)
                    .expect("owner connect")
                {
                    srt_transport::advanced::caller::PoolOutcome::Admitted(id) => {
                        ids.push(id);
                        issued += 1;
                    }
                    srt_transport::advanced::caller::PoolOutcome::Queued(request) => {
                        queued_requests.insert(request);
                        report.queued += 1;
                        issued += 1;
                    }
                    srt_transport::advanced::caller::PoolOutcome::Full => {
                        report.refused += 1;
                        break;
                    }
                }
            }
            report.issued = issued;
            let _ = owner.service(now, budget).await;
            // A queued request becomes a real logical caller when a permit
            // frees up: the pool event carries its id.
            owner.poll_caller_pool_events(&mut pool_events);
            for event in &pool_events {
                if let srt_transport::advanced::caller::PoolEvent::Admitted {
                    request_id,
                    caller_id,
                } = event
                    && queued_requests.remove(request_id)
                {
                    ids.push(*caller_id);
                }
            }
            owner.wait_for_activity(Duration::from_millis(1)).await;
            let connected = ids
                .iter()
                .filter(|id| {
                    owner.logical_caller(id).and_then(|caller| caller.state())
                        == Some(srt_transport::advanced::caller::LogicalCallerState::Connected)
                })
                .count();
            if connected == fanout {
                break;
            }
        }
        // --- pre-measurement equilibrium: every handshake/timer/socket
        // completion that belongs to establishment is drained BEFORE the
        // window opens, so the window's counters cannot include a completion
        // whose submission happened before it.
        let warm_start = Instant::now();
        while warm_start.elapsed() < DRAIN_DEADLINE {
            now = Timestamp::from_micros(now.as_micros() + 1_000);
            let _ = owner.service(now, budget).await;
            if owner.tx_in_flight() == 0 && !owner.has_pending_work(now) {
                report.pre_window_drained = true;
                break;
            }
            owner.wait_for_activity(Duration::from_millis(1)).await;
        }

        report.admitted = ids.len();
        report.established = ids
            .iter()
            .filter(|id| {
                owner.logical_caller(id).and_then(|caller| caller.state())
                    == Some(srt_transport::advanced::caller::LogicalCallerState::Connected)
            })
            .count();
        if report.established == 0 {
            report.rx_mode = format!("{:?}", owner.rx_mode());
            report.tx_pool_capacity = owner.tx_pool().capacity();
            report.tx_pool_free = owner.tx_pool().free_count();
            return report;
        }

        // --- open-loop measurement window
        //
        // Both clocks in this loop are derived from ONE wall-clock epoch:
        //
        //   * source deadlines are `epoch + n x interval`, so an overrunning
        //     service visit can no longer slow the source down, and any
        //     interval it consumes is counted in `missed_source_ticks` instead
        //     of quietly reducing the offered load;
        //   * the SRT `Timestamp` handed to the protocol is
        //     `srt_epoch + wall_elapsed`, so protocol time cannot drift away
        //     from wall time under overload (which is exactly when it drifts
        //     furthest).
        let cpu_start = process_cpu_ms();
        let interval = Duration::from_micros(PACKET_INTERVAL_US);
        let epoch = Instant::now();
        let srt_epoch = now;
        let deadline = epoch + Duration::from_millis(duration_ms);
        let payload = Bytes::from(vec![0x5A_u8; PAYLOAD_SIZE]);
        let mut lateness =
            Vec::with_capacity((duration_ms * 1000 / PACKET_INTERVAL_US) as usize + 8);
        let mut next_tick = epoch + interval;
        loop {
            if Instant::now() >= deadline {
                break;
            }
            // Pace to the next source deadline when service left time over.
            let early = next_tick.saturating_duration_since(Instant::now());
            if !early.is_zero() {
                compio::time::sleep(early).await;
            }
            let tick_wall = Instant::now();
            if tick_wall >= deadline {
                break;
            }
            // The schedule is anchored to the epoch and advances by WHOLE
            // intervals, so the remainder of an overrun stays pending instead
            // of shifting the source clock. Every boundary the visit passed is
            // then either a generated tick or an explicitly counted missed
            // tick -- `generated + missed == expected` is the identity a
            // service-coupled producer would break.
            let scheduled = next_tick;
            next_tick += interval;
            while next_tick <= tick_wall {
                next_tick += interval;
                report.missed_source_ticks += 1;
            }
            report.generated_ticks += 1;
            // Protocol time tracks wall time from the single epoch.
            now = Timestamp::from_micros(
                srt_epoch.as_micros() + (tick_wall - epoch).as_micros() as u64,
            );

            // Open loop: the tick happens whether or not the Owner can take
            // it. A destination that refuses loses this copy.
            for id in &ids {
                report.offered += 1;
                if let Some(mut caller) = owner.logical_caller_mut(id)
                    && caller.send_shared(payload.clone(), now).is_ok()
                {
                    report.accepted += 1;
                }
            }
            let visit = owner.service(now, budget).await;
            report.submitted += visit.tx_packets_submitted as u64;
            report.completed_ok += visit.tx_completed_ok as u64;
            report.short_sends += visit.tx_short_sends as u64;
            report.failed_sends += visit.tx_failed_sends as u64;
            report.peer_local_failures += visit.tx_peer_local_failures as u64;
            report.transient_failures += visit.tx_transient_failures as u64;
            report.service_visits += 1;

            // How late this tick's service completed relative to its own
            // source deadline.
            lateness.push(
                Instant::now()
                    .saturating_duration_since(scheduled)
                    .as_micros() as u64,
            );
            // Do not idle the Owner past its own receive work.
            owner.wait_for_activity(Duration::from_micros(0)).await;
        }
        let window_elapsed = deadline.saturating_duration_since(epoch);
        report.expected_ticks = (window_elapsed.as_micros() / PACKET_INTERVAL_US as u128) as u64;
        report.cpu_ms = process_cpu_ms() - cpu_start;
        // Sampled at the END OF THE WINDOW, before any post-window drain: this
        // is what the shard had outstanding when the measurement stopped.
        report.inflight_at_window_end = owner.tx_in_flight() as u64;

        lateness.sort_unstable();
        report.lateness_p50_us = percentile(&lateness, 0.50);
        report.lateness_p99_us = percentile(&lateness, 0.99);
        report.lateness_max_us = lateness.last().copied().unwrap_or(0);

        // --- TX-enabled drain to equilibrium, bounded
        let drain_start = Instant::now();
        while drain_start.elapsed() < DRAIN_DEADLINE {
            now = Timestamp::from_micros(now.as_micros() + 1_000);
            let visit = owner.service(now, budget).await;
            // Drain-phase traffic is counted separately so no window figure
            // ever includes it.
            report.drain_submitted += visit.tx_packets_submitted as u64;
            report.drain_completed_ok += visit.tx_completed_ok as u64;
            report.short_sends += visit.tx_short_sends as u64;
            report.failed_sends += visit.tx_failed_sends as u64;
            report.peer_local_failures += visit.tx_peer_local_failures as u64;
            report.transient_failures += visit.tx_transient_failures as u64;
            if owner.tx_in_flight() == 0 && !owner.has_pending_work(now) {
                report.drained = true;
                break;
            }
            owner.wait_for_activity(Duration::from_millis(1)).await;
        }
        report.pending_after_drain =
            owner.tx_in_flight() as u64 + if owner.has_pending_work(now) { 1 } else { 0 };

        report.rx_mode = format!("{:?}", owner.rx_mode());
        // The sender's own receive side is the caller socket.
        if let Some(stats) = owner.rx_stats().caller {
            report.rx_dropped = stats.dropped;
            report.rx_truncated = stats.truncated;
        }
        report.tx_failures_pending = owner.tx_failures_pending();
        report.tx_pool_capacity = owner.tx_pool().capacity();
        report.tx_pool_free = owner.tx_pool().free_count();
        report
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fanout: usize = parse_arg(&args, "--fanout", 100);
    let duration_ms: u64 = parse_arg(&args, "--duration-ms", 30_000);
    let base_port: u16 = parse_arg(&args, "--base-port", 12_000);
    let tx_lanes: usize = parse_arg(&args, "--tx-lanes", 256);
    let connect_cc: usize = parse_arg(&args, "--connect-cc", 64);
    let send_shards: usize = parse_arg(&args, "--send-shards", 1);
    assert_eq!(
        send_shards, 1,
        "one Owner shard per process; run more processes for more shards"
    );

    let runtime = compio::runtime::Runtime::new().expect("runtime for setup");
    let report = runtime.block_on(run_sender(
        fanout,
        duration_ms,
        base_port,
        tx_lanes,
        connect_cc,
    ));

    let managed = report.rx_mode == format!("{:?}", OwnerRxMode::ManagedMultishot);
    println!(
        // Field labels distinguish the measurement domains explicitly:
        // `data_offered`/`data_accepted` are application copies, while
        // `tx_submitted_wire`/`tx_completed` count wire datagrams, which
        // include control traffic and therefore do not have to be equal.
        "SHARED_OWNER_QUAL fanout={} tx_lanes={} connect_cc={} desired={} \
         issued={} admitted={} queued={} refused={} established={} pre_window_drained={} \
         expected_ticks={} generated_ticks={} missed_source_ticks={} \
         data_offered={} data_accepted={} tx_submitted_wire={} tx_completed={} \
         short={} failed={} peer_local={} transient={} tx_failures_pending={} \
         service_visits={} lateness_us_p50={} p99={} max={} drain_ok={} \
         inflight_at_window_end={} drain_submitted={} drain_completed={} \
         pending_after_drain={} rx_mode={} managed_rx={} \
         rx_dropped={} rx_truncated={} tx_pool={}/{} cpu_ms={:.1}",
        report.fanout,
        report.tx_lanes,
        report.connect_cc,
        report.desired,
        report.issued,
        report.admitted,
        report.queued,
        report.refused,
        report.established,
        report.pre_window_drained,
        report.expected_ticks,
        report.generated_ticks,
        report.missed_source_ticks,
        report.offered,
        report.accepted,
        report.submitted,
        report.completed_ok,
        report.short_sends,
        report.failed_sends,
        report.peer_local_failures,
        report.transient_failures,
        report.tx_failures_pending,
        report.service_visits,
        report.lateness_p50_us,
        report.lateness_p99_us,
        report.lateness_max_us,
        report.drained,
        report.inflight_at_window_end,
        report.drain_submitted,
        report.drain_completed_ok,
        report.pending_after_drain,
        report.rx_mode,
        managed,
        report.rx_dropped,
        report.rx_truncated,
        report.tx_pool_free,
        report.tx_pool_capacity,
        report.cpu_ms,
    );
}
