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
//! * **Wall-clock-anchored source with explicit missed-deadline accounting.**
//!   The source schedule is anchored to one wall-clock epoch and advances by
//!   whole intervals, and protocol time is `srt_epoch + wall_elapsed`, so a
//!   slow `service()` cannot shift either clock. It is NOT a fully independent
//!   producer: it runs in the same loop as `owner.service()`, so a service
//!   overrun prevents ticks from being produced at all -- those intervals are
//!   counted in `missed_source_ticks` and the window close asserts
//!   `expected == generated + missed`. A destination that cannot accept a tick
//!   loses that copy instead of queueing it. A separately paced producer is the
//!   stronger design for a later target-hardware qualification.
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
    Owner, OwnerRxMode, OwnerServiceBudget, OwnerTxClassCounters, ProductionRuntimeConfig,
    RxModePolicy, production_runtime_builder,
};
use srt_transport::{CallerConfig, SocketOwnership};

/// Default payload size: 1316 bytes, which at 8 Mbps is one payload every
/// 1316 microseconds. The interval is not a separate constant any more --
/// it is derived from the payload size and [`RATE_BPS`] by
/// [`interval_us_for`], so changing one of the two cannot silently change
/// the offered bitrate.
const PAYLOAD_SIZE: usize = 1316;
/// Offered bitrate per destination when `--rate-mbps-per-dest` is absent.
///
/// The rate is an *independent experimental variable*, not a harness constant:
/// the capacity question is "what is the largest per-destination bitrate this
/// shard sustains at fanout F", which cannot be asked by a harness that only
/// knows how to offer 8 Mbps. The default keeps every previously published row
/// reproducible.
const RATE_BPS: u64 = 8_000_000;
/// The instant of tick boundary `n` (1-based) on the epoch-anchored schedule.
///
/// A helper rather than `epoch + interval * n` because `Duration * u32`
/// saturates on overflow and the multiplication is easy to get wrong at the
/// boundary; one place computes it for both the offer and the wake-up.
fn next_after(epoch: Instant, interval: Duration, n: u64) -> Instant {
    epoch + interval.saturating_mul(n.min(u32::MAX as u64) as u32)
}

const CONNECT_DEADLINE: Duration = Duration::from_secs(30);
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// Source interval holding `rate_bps` constant for this payload size:
/// `interval = bytes * 8 / rate`. A property of the offer, not of how much of
/// it the shard manages to serve.
fn interval_us_for(payload_bytes: usize, rate_bps: u64) -> u64 {
    (payload_bytes as u64 * 8 * 1_000_000).div_ceil(rate_bps.max(1))
}

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
    /// Punctuality of the *source offer*: how late `send_shared` was attempted
    /// relative to each boundary's deadline, sampled before `service()`.
    ///
    /// Not dataplane lateness: a payload admitted here can leave the socket much
    /// later, so this alone cannot support a real-time claim.
    offer_lateness_us_p50: u64,
    offer_lateness_us_p99: u64,
    offer_lateness_us_max: u64,
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
    /// Monotonic peak of simultaneously checked-out TX slots.
    tx_pool_high_water: usize,
    /// Wire submissions in the WINDOW, partitioned by what each datagram
    /// carried. `tx_class.total() == submitted` is asserted before the row is
    /// printed: a total that cannot be decomposed cannot say whether the wire
    /// traffic was the media or the control cadence around it.
    tx_class: OwnerTxClassCounters,
    /// The same partition for the post-window drain, so no window figure ever
    /// includes drain traffic.
    drain_class: OwnerTxClassCounters,
    /// First-transmission submit lateness for the window: source due instant to
    /// lane handoff. Distinct from `offer_lateness_us_*`, which is sampled
    /// before `service()` and says nothing about the dataplane.
    first_submit_lateness_us_p50: u64,
    first_submit_lateness_us_p99: u64,
    first_submit_lateness_us_max: u64,
    first_submit_lateness_samples: u64,
    /// SRT-level receive accounting for the sender's own caller socket: what
    /// this endpoint's receiver half concluded, over live and retired sessions.
    /// Distinct from `rx_dropped`/`rx_truncated`, which count socket work.
    rx_lost: u64,
    rx_duplicates: u64,
    /// Process CPU consumed by the measurement window alone; the drain phase
    /// is excluded.
    cpu_ms: f64,
    /// Payload size and source interval actually used. Reported because a
    /// row is only comparable to another row at the same offered bitrate:
    /// `payload_bytes * 8 / interval_us` is the per-destination rate.
    payload_bytes: u64,
    interval_us: u64,
    /// Offered bitrate per destination, `payload_bytes * 8 / interval_us`.
    /// A capacity sweep is unreadable unless the offer sits on the same line as
    /// the delivery.
    offered_bps_per_dest: u64,
    /// Diagnostic fences offered / accepted after the measured window.
    ///
    /// Excluded from every workload figure: they exist to force later sequence
    /// progress and make an end-of-run tail observable.
    fence_offered: u64,
    fence_accepted: u64,
    /// CPU consumed by the measurement window alone.
    ///
    /// `cpu_ms` spans window + post-window drain, and the drain is not
    /// small: an F=200 shard submits ~1.2x its window traffic again while
    /// draining, so a per-copy cost derived from `cpu_ms` charges the
    /// window for work the window did not do. This field is sampled at
    /// the window close so the per-copy cost of the measured workload is
    /// separable from teardown work.
    window_cpu_ms: f64,
    /// CPU consumed by the post-window drain alone.
    drain_cpu_ms: f64,
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

/// What the source offers: payload framing, cadence, and whether the diagnostic
/// fence is sent after the measured window. Grouped because these are the
/// producer's inputs, distinct from the run's shape (fanout, window, ports).
struct Source {
    payload_size: usize,
    interval_us: u64,
    with_fence: bool,
    /// Tag each measured payload with its zero-based source tick.
    ///
    /// Diagnostic runs turn this on so the receiver can tell *which* ticks
    /// arrived; the canonical capacity run leaves it off, keeping the original
    /// single-shared-payload allocation profile.
    identity: bool,
    /// Ticks the offer contains, from the shared offer arithmetic. Used for the
    /// fence's `final_tick` so sender and receiver agree on the last tick id.
    expected_ticks: u64,
}

async fn run_sender(
    fanout: usize,
    duration_ms: u64,
    base_port: u16,
    tx_lanes: usize,
    connect_cc: usize,
    source: &Source,
) -> QualReport {
    let Source {
        payload_size,
        interval_us,
        with_fence,
        identity,
        expected_ticks,
    } = *source;
    let mut report = QualReport {
        fanout,
        tx_lanes,
        connect_cc,
        payload_bytes: payload_size as u64,
        interval_us,
        offered_bps_per_dest: payload_size as u64 * 8 * 1_000_000 / interval_us.max(1),
        desired: fanout,
        ..Default::default()
    };

    // Production attach path: require io_uring and the managed RX substrate.
    // `ManagedPreferred` (not Required) so this run still produces evidence on
    // a fallback host -- and reports that it did.
    //
    // A plain session (no passphrase) carries no authentication tag, so the
    // cipher argument is `None`.
    let wire_ceiling = srt_transport::compio::required_session_wire_ceiling(payload_size, None);
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

        // --- measurement window (wall-clock-anchored source; see the module
        //     docs for why this is not an independent producer)
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
        let interval = Duration::from_micros(interval_us);
        let epoch = Instant::now();
        let srt_epoch = now;
        let deadline = epoch + Duration::from_millis(duration_ms);
        // Canonical runs share one static payload; diagnostic runs tag each tick
        // so the receiver can attribute a missing payload to a tick id.
        let payload = Bytes::from(vec![0x5A_u8; payload_size]);
        let mut offer_lateness =
            Vec::with_capacity((duration_ms * 1000 / interval_us) as usize + 8);
        let mut next_tick = epoch + interval;
        // Tick boundaries already offered. The schedule is a count of
        // boundaries, not a clock that service can move.
        let mut ticks_offered: u64 = 0;
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
            // CATCH-UP, BOUNDED. The schedule advances by whole intervals from
            // the epoch, and every boundary the visit has passed is offered in
            // that same visit rather than being dropped because `service()`
            // overran. Dropping them is what made the cadence gate
            // unfalsifiable: `generated_ticks` measured the service loop's
            // punctuality, not the shard's throughput, so a harness that slept
            // slightly too long looked like an overloaded transport.
            //
            // The catch-up is capped so a long stall cannot turn into an
            // unbounded burst, and any boundary beyond the cap is counted as
            // missed exactly as before: `generated + missed == expected` still
            // holds over the window.
            let passed = ((tick_wall - epoch).as_micros() / interval_us as u128) as u64;
            // One policy, in the library and under test: offer up to the cap,
            // declare everything past it lost *in this visit*. Carrying the
            // remainder forward would make the effective cap larger than the
            // declared one and would let a boundary documented as lost become a
            // generated tick later.
            let step = srt_bench::source_schedule::catch_up(
                ticks_offered,
                passed,
                srt_bench::source_schedule::MAX_TICK_CATCHUP,
            );
            for _ in 0..step.offer {
                ticks_offered += 1;
                let scheduled = next_after(epoch, interval, ticks_offered);
                // Protocol time is this tick's own deadline: a caught-up tick
                // is offered as if on time, because that is when the media
                // schedule says it was due.
                now = Timestamp::from_micros(
                    srt_epoch.as_micros() + (scheduled - epoch).as_micros() as u64,
                );
                // The tick is offered whatever the Owner's state: a destination
                // that refuses loses this copy, and it is never queued in a
                // harness backlog.
                // Zero-based tick id, matching the receiver's `0..expected-1`.
                // Deliberately not the scheduler's 1-based boundary count.
                let tick_payload = if identity {
                    srt_bench::qual_payload::measured_payload(
                        payload_size,
                        (ticks_offered - 1) as u32,
                    )
                } else {
                    payload.clone()
                };
                for id in &ids {
                    report.offered += 1;
                    if let Some(mut caller) = owner.logical_caller_mut(id)
                        && caller.send_shared(tick_payload.clone(), now).is_ok()
                    {
                        report.accepted += 1;
                    }
                }
                report.generated_ticks += 1;
                // OFFER lateness: how late this boundary's `send_shared` was
                // attempted, measured before `service()`. It says the source was
                // punctual, not that the dataplane was -- a payload admitted here
                // can leave the socket much later. Naming it `lateness` invited
                // exactly that misreading, so it is `offer_lateness` everywhere,
                // and the real-time gate must eventually use first-transmission
                // submit lateness.
                offer_lateness.push(
                    Instant::now()
                        .saturating_duration_since(scheduled)
                        .as_micros() as u64,
                );
            }
            report.missed_source_ticks += step.missed;
            ticks_offered = step.offered_through;
            // Next wake-up is the next unoffered boundary.
            next_tick = next_after(epoch, interval, ticks_offered + 1);
            let visit = owner.service(now, budget).await;
            report.submitted += visit.tx_packets_submitted as u64;
            report.tx_class.merge(visit.tx_class);
            report.completed_ok += visit.tx_completed_ok as u64;
            report.short_sends += visit.tx_short_sends as u64;
            report.failed_sends += visit.tx_failed_sends as u64;
            report.peer_local_failures += visit.tx_peer_local_failures as u64;
            report.transient_failures += visit.tx_transient_failures as u64;
            report.service_visits += 1;

            // Do not idle the Owner past its own receive work.
            owner.wait_for_activity(Duration::from_micros(0)).await;
        }
        // Window close: reconcile the source accounting.
        //
        // The incremental counter above records intervals the generator saw
        // itself skip mid-window (diagnostics); the authoritative figure is
        // derived here, so the final boundary cannot be lost to the loop
        // exiting exactly on the deadline. The identity is asserted, not merely
        // documented:
        //
        //     expected == generated + missed
        let window_elapsed = deadline.saturating_duration_since(epoch);
        report.expected_ticks = (window_elapsed.as_micros() / interval_us as u128) as u64;
        report.missed_source_ticks = report
            .missed_source_ticks
            .max(report.expected_ticks.saturating_sub(report.generated_ticks));
        assert_eq!(
            report.expected_ticks,
            report.generated_ticks + report.missed_source_ticks,
            "source accounting must reconcile: expected == generated + missed"
        );
        assert!(
            report.generated_ticks > 0,
            "a zero-tick window is not a measurement"
        );
        report.window_cpu_ms = process_cpu_ms() - cpu_start;
        // The submission partition must close, and it must close against the
        // window's own wire count: a row whose classes do not sum to what it
        // sent has no interpretable per-class figure at all.
        assert_eq!(
            report.tx_class.total(),
            report.submitted,
            "sum(tx_class) must equal the window's tx_submitted_wire"
        );
        // Taken at window close, before the drain, so the window's lateness is
        // not diluted by post-window traffic.
        let submit_lateness = owner.take_first_submit_lateness();
        report.first_submit_lateness_us_p50 = submit_lateness.percentile_us(0.50);
        report.first_submit_lateness_us_p99 = submit_lateness.percentile_us(0.99);
        report.first_submit_lateness_us_max = submit_lateness.max_us();
        report.first_submit_lateness_samples = submit_lateness.samples();
        // Sampled at the END OF THE WINDOW, before any post-window drain: this
        // is what the shard had outstanding when the measurement stopped.
        report.inflight_at_window_end = owner.tx_in_flight() as u64;
        let drain_cpu_start = process_cpu_ms();

        offer_lateness.sort_unstable();
        report.offer_lateness_us_p50 = percentile(&offer_lateness, 0.50);
        report.offer_lateness_us_p99 = percentile(&offer_lateness, 0.99);
        report.offer_lateness_us_max = offer_lateness.last().copied().unwrap_or(0);

        // --- diagnostic terminal fence (measurement only)
        //
        // One ordinary SRT DATA payload per destination, offered AFTER the last
        // measured tick and BEFORE the drain. It exists to test one hypothesis
        // about the end-of-run conservation deficit: that the missing payloads
        // are a tail the receiver has no evidence for, because no later sequence
        // number ever arrives to expose the gap. A fence provides exactly that
        // later sequence progress, so:
        //
        //   deficit closes with the fence and retransmission appears  -> the tail
        //       needed later sequence progress (end-of-stream recovery property)
        //   deficit closes with the fence and no retransmission       -> snapshot /
        //       teardown race
        //   deficit persists with the fence                           -> delivery or
        //       accounting defect, not lifecycle
        //
        // Fence payloads are deliberately a different size and pattern from the
        // measured workload, and are counted in their own fields: nothing here
        // enters `data_offered`, `data_accepted`, the r ratios, or any CPU
        // normalisation.
        let fence_payload = if identity {
            srt_bench::qual_payload::fence_payload(
                payload_size,
                expected_ticks.saturating_sub(1) as u32,
            )
        } else {
            Bytes::from(vec![0x5Fu8; PAYLOAD_SIZE / 8])
        };
        for id in &ids {
            if !with_fence {
                break;
            }
            report.fence_offered += 1;
            if let Some(mut caller) = owner.logical_caller_mut(id)
                && caller.send_shared(fence_payload.clone(), now).is_ok()
            {
                report.fence_accepted += 1;
            }
        }

        // --- TX-enabled drain to equilibrium, bounded
        let drain_start = Instant::now();
        while drain_start.elapsed() < DRAIN_DEADLINE {
            now = Timestamp::from_micros(now.as_micros() + 1_000);
            let visit = owner.service(now, budget).await;
            // Drain-phase traffic is counted separately so no window figure
            // ever includes it.
            report.drain_submitted += visit.tx_packets_submitted as u64;
            report.drain_class.merge(visit.tx_class);
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
        report.drain_cpu_ms = process_cpu_ms() - drain_cpu_start;
        report.pending_after_drain =
            owner.tx_in_flight() as u64 + if owner.has_pending_work(now) { 1 } else { 0 };

        report.rx_mode = format!("{:?}", owner.rx_mode());
        // The sender's own receive side is the caller socket.
        if let Some(stats) = owner.rx_stats().caller {
            report.rx_dropped = stats.dropped;
            report.rx_truncated = stats.truncated;
        }
        // `cpu_ms` is the whole measured run: window + drain + the teardown
        // bookkeeping between them. It is set here rather than at window close
        // so it cannot be a stale zero (it was, for one commit: the field was
        // still printed as `cpu_ms=0.0` while `window_cpu_ms` and
        // `drain_cpu_ms` carried the real values).
        report.cpu_ms = process_cpu_ms() - cpu_start;
        report.tx_failures_pending = owner.tx_failures_pending();
        report.tx_pool_capacity = owner.tx_pool().capacity();
        report.tx_pool_free = owner.tx_pool().free_count();
        report.tx_pool_high_water = owner.tx_pool().high_water();
        // The sender's own receive side is the caller socket. Reported through
        // the Owner's session totals, not the socket-level stats above, because
        // only these survive a session being retired.
        if let Some(totals) = owner.rx_session_totals().caller {
            report.rx_lost = totals.lost;
            report.rx_duplicates = totals.duplicates;
        }
        assert_eq!(
            report.drain_class.total(),
            report.drain_submitted,
            "sum(tx_class) must equal the drain's wire submissions"
        );
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
    let payload_bytes: usize = parse_arg(&args, "--payload-bytes", PAYLOAD_SIZE);
    // Offered cadence, swept by the qualification rather than assumed.
    let fence: bool = parse_arg(&args, "--fence", false);
    let identity: bool = parse_arg(&args, "--identity", false);
    let rate_mbps_per_dest: f64 = parse_arg(&args, "--rate-mbps-per-dest", RATE_BPS as f64 / 1e6);
    let rate_bps = (rate_mbps_per_dest * 1e6) as u64;
    assert!(
        rate_bps > 0,
        "--rate-mbps-per-dest must be positive; an unoffered run is not a measurement"
    );
    let send_shards: usize = parse_arg(&args, "--send-shards", 1);
    assert_eq!(
        send_shards, 1,
        "one Owner shard per process; run more processes for more shards"
    );

    let runtime = compio::runtime::Runtime::new().expect("runtime for setup");
    let interval_us = interval_us_for(payload_bytes, rate_bps);
    let report = runtime.block_on(run_sender(
        fanout,
        duration_ms,
        base_port,
        tx_lanes,
        connect_cc,
        &Source {
            payload_size: payload_bytes,
            interval_us,
            with_fence: fence,
            identity,
            expected_ticks: srt_bench::source_schedule::expected_ticks(
                duration_ms * 1000,
                interval_us,
            ),
        },
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
         service_visits={} offer_lateness_us_p50={} offer_lateness_us_p99={} offer_lateness_us_max={} drain_ok={} \
         inflight_at_window_end={} drain_submitted={} drain_completed={} \
         tx_class_data_first={} tx_class_data_retx={} tx_class_ack={} tx_class_ackack={} \
         tx_class_nak={} tx_class_keepalive={} tx_class_handshake={} tx_class_dropreq={} \
         tx_class_km={} tx_class_shutdown={} tx_class_other_control={} tx_class_total={} \
         drain_class_total={} \
         first_submit_lateness_us_p50={} first_submit_lateness_us_p99={} \
         first_submit_lateness_us_max={} first_submit_lateness_samples={} \
         pending_after_drain={} rx_mode={} managed_rx={} \
         rx_dropped={} rx_truncated={} rx_lost={} rx_duplicates={} \
         tx_pool_free={} tx_pool_capacity={} tx_pool_high_water={} \
         payload_bytes={} interval_us={} \
         offered_bps_per_dest={} fence_offered={} fence_accepted={} \
         cpu_ms={:.1} window_cpu_ms={:.1} drain_cpu_ms={:.1}",
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
        report.offer_lateness_us_p50,
        report.offer_lateness_us_p99,
        report.offer_lateness_us_max,
        report.drained,
        report.inflight_at_window_end,
        report.drain_submitted,
        report.drain_completed_ok,
        report.tx_class.data_first,
        report.tx_class.data_retx,
        report.tx_class.ack,
        report.tx_class.ackack,
        report.tx_class.nak,
        report.tx_class.keepalive,
        report.tx_class.handshake,
        report.tx_class.dropreq,
        report.tx_class.km,
        report.tx_class.shutdown,
        report.tx_class.other_control,
        report.tx_class.total(),
        report.drain_class.total(),
        report.first_submit_lateness_us_p50,
        report.first_submit_lateness_us_p99,
        report.first_submit_lateness_us_max,
        report.first_submit_lateness_samples,
        report.pending_after_drain,
        report.rx_mode,
        managed,
        report.rx_dropped,
        report.rx_truncated,
        report.rx_lost,
        report.rx_duplicates,
        report.tx_pool_free,
        report.tx_pool_capacity,
        report.tx_pool_high_water,
        report.payload_bytes,
        report.interval_us,
        report.offered_bps_per_dest,
        report.fence_offered,
        report.fence_accepted,
        report.cpu_ms,
        report.window_cpu_ms,
        report.drain_cpu_ms,
    );
}
