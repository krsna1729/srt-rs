use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use shiguredo_srt::Timestamp;

/// Fixed number of power-of-two buckets used for owner-local shard lateness.
pub const SHARD_LATENESS_BUCKETS: usize = 32;
/// Fixed number of overload counters in each shard snapshot.
pub const SHARD_OVERLOAD_REASONS: usize = 4;

/// Fixed overload categories. Keeping this an enum rather than accepting
/// arbitrary labels makes snapshot storage and exporter cardinality bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardOverloadReason {
    ReceiveBudget = 0,
    OutputBudget = 1,
    OutputBackpressure = 2,
    QueueLimit = 3,
}

impl ShardOverloadReason {
    const fn index(self) -> usize {
        self as usize
    }
}

/// Fixed-size, serialization-friendly snapshot for one application-owned
/// shard. The shard owns and mutates [`ShardTelemetry`]; exporters can copy
/// this value without taking a global lock or allocating per-shard labels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShardTelemetrySnapshot {
    /// Number of service visits represented by this snapshot.
    pub service_visits: u64,
    /// Sum and maximum of observed service duration in microseconds.
    pub service_time_total_us: u64,
    pub service_time_max_us: u64,
    /// The most recently observed intended deadline and service start.
    pub last_intended_deadline: Option<Timestamp>,
    pub last_service_start: Option<Timestamp>,
    /// Number and maximum of positive deadline lateness samples.
    pub lateness_samples: u64,
    pub lateness_max_us: u64,
    pub lateness_buckets: [u64; SHARD_LATENESS_BUCKETS],
    /// Last observed queue state and high-water marks for one shard's
    /// application queue. Age is the oldest retained item age in microseconds.
    pub queue_items: usize,
    pub queue_bytes: usize,
    pub queue_oldest_age_us: u64,
    pub queue_peak_items: usize,
    pub queue_peak_bytes: usize,
    pub queue_peak_age_us: u64,
    /// Bounded work and outcome counters.
    pub receive_datagrams: u64,
    pub receive_syscalls: u64,
    pub receive_truncated: u64,
    pub output_actions: u64,
    pub output_packets: u64,
    pub output_bytes: u64,
    pub output_syscalls: u64,
    pub output_would_block: u64,
    pub budget_exhausted: u64,
    pub backpressured: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub expired: u64,
    pub failed: u64,
    /// Counts indexed by [`ShardOverloadReason`]'s discriminant.
    pub overloads: [u64; SHARD_OVERLOAD_REASONS],
}

impl ShardTelemetrySnapshot {
    #[must_use]
    pub fn overload_count(self, reason: ShardOverloadReason) -> u64 {
        self.overloads[reason.index()]
    }

    #[must_use]
    pub fn overload_total(self) -> u64 {
        self.overloads.into_iter().fold(0, u64::saturating_add)
    }
}

/// Owner-local telemetry for one runtime shard.
///
/// This type deliberately contains no atomics and no dynamic collections.
/// A runtime records into the instance it already owns, then periodically
/// exports [`Self::snapshot`]. Cross-shard aggregation belongs to the
/// application and can merge fixed snapshots at its chosen cadence.
#[derive(Clone, Debug, Default)]
pub struct ShardTelemetry {
    snapshot: ShardTelemetrySnapshot,
}

impl ShardTelemetry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one bounded service visit. `intended_deadline` is optional for
    /// work that has no deadline; lateness is recorded only when it exists.
    pub fn record_service(
        &mut self,
        intended_deadline: Option<Timestamp>,
        service_start: Timestamp,
        service_time: Duration,
    ) {
        let service_us = service_time.as_micros().min(u64::MAX as u128) as u64;
        self.snapshot.service_visits = self.snapshot.service_visits.saturating_add(1);
        self.snapshot.service_time_total_us = self
            .snapshot
            .service_time_total_us
            .saturating_add(service_us);
        self.snapshot.service_time_max_us = self.snapshot.service_time_max_us.max(service_us);
        self.snapshot.last_intended_deadline = intended_deadline;
        self.snapshot.last_service_start = Some(service_start);
        if let Some(deadline) = intended_deadline {
            let lateness = service_start.saturating_sub(deadline);
            self.record_lateness(lateness);
        }
    }

    /// Record a positive or zero deadline lateness sample in a fixed
    /// power-of-two histogram. Zero is kept in bucket zero.
    pub fn record_lateness(&mut self, lateness: u64) {
        let bucket = if lateness == 0 {
            0
        } else {
            (u64::BITS - lateness.leading_zeros()) as usize
        }
        .min(SHARD_LATENESS_BUCKETS - 1);
        self.snapshot.lateness_samples = self.snapshot.lateness_samples.saturating_add(1);
        self.snapshot.lateness_max_us = self.snapshot.lateness_max_us.max(lateness);
        self.snapshot.lateness_buckets[bucket] =
            self.snapshot.lateness_buckets[bucket].saturating_add(1);
    }

    /// Observe the current application queue. The caller supplies the oldest
    /// retained item's age; no item references or dynamic labels are retained.
    pub fn observe_queue(&mut self, items: usize, bytes: usize, oldest_age: Duration) {
        let age_us = oldest_age.as_micros().min(u64::MAX as u128) as u64;
        self.snapshot.queue_items = items;
        self.snapshot.queue_bytes = bytes;
        self.snapshot.queue_oldest_age_us = age_us;
        self.snapshot.queue_peak_items = self.snapshot.queue_peak_items.max(items);
        self.snapshot.queue_peak_bytes = self.snapshot.queue_peak_bytes.max(bytes);
        self.snapshot.queue_peak_age_us = self.snapshot.queue_peak_age_us.max(age_us);
    }

    /// Record receive work from one bounded receive visit.
    pub fn record_receive(
        &mut self,
        datagrams: usize,
        syscalls: usize,
        truncated: usize,
        budget_exhausted: bool,
    ) {
        self.snapshot.receive_datagrams = self
            .snapshot
            .receive_datagrams
            .saturating_add(datagrams as u64);
        self.snapshot.receive_syscalls = self
            .snapshot
            .receive_syscalls
            .saturating_add(syscalls as u64);
        self.snapshot.receive_truncated = self
            .snapshot
            .receive_truncated
            .saturating_add(truncated as u64);
        if budget_exhausted {
            self.record_overload(ShardOverloadReason::ReceiveBudget);
        }
    }

    /// Record one bounded output visit using the public report's already
    /// accounted units.
    pub fn record_output(&mut self, report: &crate::OutputDrainReport) {
        self.snapshot.output_actions = self
            .snapshot
            .output_actions
            .saturating_add(report.actions as u64);
        self.snapshot.output_packets = self
            .snapshot
            .output_packets
            .saturating_add(report.packets as u64);
        self.snapshot.output_bytes = self
            .snapshot
            .output_bytes
            .saturating_add(report.bytes as u64);
        self.snapshot.output_syscalls = self
            .snapshot
            .output_syscalls
            .saturating_add(report.syscalls as u64);
        if report.would_block {
            self.snapshot.output_would_block = self.snapshot.output_would_block.saturating_add(1);
        }
        match report.status {
            crate::OutputDrainStatus::Drained => {}
            crate::OutputDrainStatus::BudgetExhausted => {
                self.snapshot.budget_exhausted = self.snapshot.budget_exhausted.saturating_add(1);
                self.record_overload(ShardOverloadReason::OutputBudget);
            }
            crate::OutputDrainStatus::Backpressured => {
                self.snapshot.backpressured = self.snapshot.backpressured.saturating_add(1);
                self.record_overload(ShardOverloadReason::OutputBackpressure);
            }
        }
    }

    pub fn record_overload(&mut self, reason: ShardOverloadReason) {
        self.snapshot.overloads[reason.index()] =
            self.snapshot.overloads[reason.index()].saturating_add(1);
    }

    pub fn record_accepted(&mut self) {
        self.snapshot.accepted = self.snapshot.accepted.saturating_add(1);
    }

    pub fn record_rejected(&mut self) {
        self.snapshot.rejected = self.snapshot.rejected.saturating_add(1);
    }

    pub fn record_expired(&mut self) {
        self.snapshot.expired = self.snapshot.expired.saturating_add(1);
    }

    pub fn record_failed(&mut self) {
        self.snapshot.failed = self.snapshot.failed.saturating_add(1);
    }

    #[must_use]
    pub const fn snapshot(&self) -> ShardTelemetrySnapshot {
        self.snapshot
    }
}

/// Counters for one reuseport listener's admission path.
///
/// Every acceptor thread shares one of these, so the fields are atomics
/// and `&self` is enough to record. Each runtime adapter used to declare
/// its own five file-local statics; six copies of "the same" counters is
/// exactly how their meanings drifted apart unnoticed (one backend
/// counted relocations as promotions while five counted only local ones,
/// so identical-looking log lines meant different things). One
/// definition, one `report` line, one meaning.
#[derive(Debug, Default)]
pub struct IngressTelemetry {
    /// Connections given a private socket on the acceptor that admitted
    /// them. Disjoint from [`Self::handoffs`] -- the two never count the
    /// same connection, so total promotions is their sum.
    pub local_promotions: AtomicU64,
    /// Connections relocated to a different worker for bond affinity.
    pub handoffs: AtomicU64,
    /// CONCLUSION datagrams that reached an acceptor holding no state for
    /// the peer and carried no usable routing information -- flows the
    /// kernel rehashed mid-handshake that could not be rescued.
    pub stranded_conclusions: AtomicU64,
    /// CONCLUSION datagrams assigned to their owning acceptor by SYN cookie.
    /// Closed-channel delivery failures are counted separately.
    pub cookie_routed: AtomicU64,
    /// Cookie-routed CONCLUSIONs whose owning worker channel was closed.
    pub cookie_route_failures: AtomicU64,
    /// Late or duplicate CONCLUSIONs for a connection this acceptor had
    /// already promoted (so its peer entry was gone). Harmless, but
    /// indistinguishable from a stranded handshake without checking the
    /// cookie -- counted apart so the two are never conflated again.
    pub promoted_duplicates: AtomicU64,
    /// Malformed or out-of-state datagrams rejected before protocol work.
    pub invalid_datagrams: AtomicU64,
    /// CONCLUSIONs whose cookie did not match the retained half-open peer.
    pub invalid_cookies: AtomicU64,
    /// Valid new inductions refused because the half-open table was full.
    pub admission_capacity_drops: AtomicU64,
    /// Valid inductions refused by the incomplete-handshake sub-limit.
    pub half_open_capacity_drops: AtomicU64,
    /// Valid conclusions refused by the established-peer sub-limit.
    pub established_capacity_drops: AtomicU64,
    /// Valid inductions refused by the per-source-IP limit.
    pub source_capacity_drops: AtomicU64,
    /// Valid-cookie CONCLUSIONs presented to application policy. Identity is
    /// still only claimed until KM succeeds.
    pub policy_requests: AtomicU64,
    /// Per-peer typed policy configurations successfully applied.
    pub policy_configurations: AtomicU64,
    /// Policy decisions deferred without extending half-open lifetime.
    pub policy_deferred: AtomicU64,
    /// Invalid or out-of-state policy configurations rejected internally.
    pub policy_errors: AtomicU64,
    /// Claimed handshake identities rejected by application policy.
    pub policy_rejections: AtomicU64,
    /// CONCLUSIONs that failed KM validation after credential selection.
    pub credential_failures: AtomicU64,
    /// Incomplete handshakes evicted after the configured inactivity bound.
    pub expired_half_open: AtomicU64,
}

/// Point-in-time, serialization-friendly admission/ingress counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngressTelemetrySnapshot {
    pub local_promotions: u64,
    pub handoffs: u64,
    pub stranded_conclusions: u64,
    pub cookie_routed: u64,
    pub cookie_route_failures: u64,
    pub promoted_duplicates: u64,
    pub invalid_datagrams: u64,
    pub invalid_cookies: u64,
    pub admission_capacity_drops: u64,
    pub half_open_capacity_drops: u64,
    pub established_capacity_drops: u64,
    pub source_capacity_drops: u64,
    pub policy_requests: u64,
    pub policy_configurations: u64,
    pub policy_deferred: u64,
    pub policy_errors: u64,
    pub policy_rejections: u64,
    pub credential_failures: u64,
    pub expired_half_open: u64,
}

impl IngressTelemetrySnapshot {
    #[must_use]
    pub fn total_promotions(self) -> u64 {
        self.local_promotions.saturating_add(self.handoffs)
    }

    #[must_use]
    pub fn total_capacity_drops(self) -> u64 {
        self.admission_capacity_drops
            .saturating_add(self.half_open_capacity_drops)
            .saturating_add(self.established_capacity_drops)
            .saturating_add(self.source_capacity_drops)
    }
}

impl IngressTelemetry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_local_promotion(&self) {
        Self::bump(&self.local_promotions);
    }
    pub fn record_handoff(&self) {
        Self::bump(&self.handoffs);
    }
    pub fn record_stranded_conclusion(&self) {
        Self::bump(&self.stranded_conclusions);
    }
    pub fn record_cookie_routed(&self) {
        Self::bump(&self.cookie_routed);
    }
    pub fn record_cookie_route_failure(&self) {
        Self::bump(&self.cookie_route_failures);
    }
    pub fn record_promoted_duplicate(&self) {
        Self::bump(&self.promoted_duplicates);
    }
    pub fn record_invalid_datagram(&self) {
        Self::bump(&self.invalid_datagrams);
    }
    pub fn record_invalid_cookie(&self) {
        Self::bump(&self.invalid_cookies);
    }
    pub fn record_admission_capacity_drop(&self) {
        Self::bump(&self.admission_capacity_drops);
    }
    pub fn record_half_open_capacity_drop(&self) {
        Self::bump(&self.half_open_capacity_drops);
    }
    pub fn record_established_capacity_drop(&self) {
        Self::bump(&self.established_capacity_drops);
    }
    pub fn record_source_capacity_drop(&self) {
        Self::bump(&self.source_capacity_drops);
    }
    pub fn record_policy_rejection(&self) {
        Self::bump(&self.policy_rejections);
    }
    pub fn record_policy_request(&self) {
        Self::bump(&self.policy_requests);
    }
    pub fn record_policy_configuration(&self) {
        Self::bump(&self.policy_configurations);
    }
    pub fn record_policy_deferred(&self) {
        Self::bump(&self.policy_deferred);
    }
    pub fn record_policy_error(&self) {
        Self::bump(&self.policy_errors);
    }
    pub fn record_credential_failure(&self) {
        Self::bump(&self.credential_failures);
    }
    pub fn record_expired_half_open(&self, count: usize) {
        // Called per datagram, where nothing has expired almost every time.
        // This counter is shared by every acceptor thread, so an
        // unconditional RMW bounces its cacheline between cores on each
        // packet for no recorded change.
        if count == 0 {
            return;
        }
        self.expired_half_open
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Read every counter into a plain value suitable for metrics exporters,
    /// structured logs, or control-plane decisions. Individual relaxed loads
    /// intentionally do not imply a cross-counter transaction.
    #[must_use]
    pub fn snapshot(&self) -> IngressTelemetrySnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        IngressTelemetrySnapshot {
            local_promotions: get(&self.local_promotions),
            handoffs: get(&self.handoffs),
            stranded_conclusions: get(&self.stranded_conclusions),
            cookie_routed: get(&self.cookie_routed),
            cookie_route_failures: get(&self.cookie_route_failures),
            promoted_duplicates: get(&self.promoted_duplicates),
            invalid_datagrams: get(&self.invalid_datagrams),
            invalid_cookies: get(&self.invalid_cookies),
            admission_capacity_drops: get(&self.admission_capacity_drops),
            half_open_capacity_drops: get(&self.half_open_capacity_drops),
            established_capacity_drops: get(&self.established_capacity_drops),
            source_capacity_drops: get(&self.source_capacity_drops),
            policy_requests: get(&self.policy_requests),
            policy_configurations: get(&self.policy_configurations),
            policy_deferred: get(&self.policy_deferred),
            policy_errors: get(&self.policy_errors),
            policy_rejections: get(&self.policy_rejections),
            credential_failures: get(&self.credential_failures),
            expired_half_open: get(&self.expired_half_open),
        }
    }

    /// One-line shutdown summary, identical in shape for every runtime so
    /// two backends' output can be compared directly.
    #[must_use]
    pub fn report(&self, backend: &str) -> String {
        let snapshot = self.snapshot();
        format!(
            "[bench-{backend}] pool receiver: {} local promotions, {} bond handoffs, \
             {} stranded CONCLUSIONs, {} cookie-routed, {} cookie-route failures, \
             {} post-promotion dups, \
             {} invalid datagrams, {} invalid cookies, {} total-capacity drops, \
             {} half-open-capacity drops, {} established-capacity drops, \
             {} source-capacity drops, {} policy requests, {} policy configurations, \
             {} policy deferrals, {} policy errors, {} policy rejections, \
             {} credential failures, {} expired half-open",
            snapshot.local_promotions,
            snapshot.handoffs,
            snapshot.stranded_conclusions,
            snapshot.cookie_routed,
            snapshot.cookie_route_failures,
            snapshot.promoted_duplicates,
            snapshot.invalid_datagrams,
            snapshot.invalid_cookies,
            snapshot.admission_capacity_drops,
            snapshot.half_open_capacity_drops,
            snapshot.established_capacity_drops,
            snapshot.source_capacity_drops,
            snapshot.policy_requests,
            snapshot.policy_configurations,
            snapshot.policy_deferred,
            snapshot.policy_errors,
            snapshot.policy_rejections,
            snapshot.credential_failures,
            snapshot.expired_half_open,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn snapshot_starts_at_zero() {
        let t = IngressTelemetry::new();
        let s = t.snapshot();
        assert_eq!(s, IngressTelemetrySnapshot::default());
        assert_eq!(s.total_promotions(), 0);
        assert_eq!(s.total_capacity_drops(), 0);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn each_recorder_increments_its_counter() {
        let t = IngressTelemetry::new();
        t.record_local_promotion();
        t.record_handoff();
        t.record_stranded_conclusion();
        t.record_cookie_routed();
        t.record_cookie_route_failure();
        t.record_promoted_duplicate();
        t.record_invalid_datagram();
        t.record_invalid_cookie();
        t.record_admission_capacity_drop();
        t.record_half_open_capacity_drop();
        t.record_established_capacity_drop();
        t.record_source_capacity_drop();
        t.record_policy_request();
        t.record_policy_configuration();
        t.record_policy_deferred();
        t.record_policy_error();
        t.record_policy_rejection();
        t.record_credential_failure();
        t.record_expired_half_open(5);
        let s = t.snapshot();
        assert_eq!(s.local_promotions, 1);
        assert_eq!(s.handoffs, 1);
        assert_eq!(s.stranded_conclusions, 1);
        assert_eq!(s.cookie_routed, 1);
        assert_eq!(s.cookie_route_failures, 1);
        assert_eq!(s.promoted_duplicates, 1);
        assert_eq!(s.invalid_datagrams, 1);
        assert_eq!(s.invalid_cookies, 1);
        assert_eq!(s.admission_capacity_drops, 1);
        assert_eq!(s.half_open_capacity_drops, 1);
        assert_eq!(s.established_capacity_drops, 1);
        assert_eq!(s.source_capacity_drops, 1);
        assert_eq!(s.policy_requests, 1);
        assert_eq!(s.policy_configurations, 1);
        assert_eq!(s.policy_deferred, 1);
        assert_eq!(s.policy_errors, 1);
        assert_eq!(s.policy_rejections, 1);
        assert_eq!(s.credential_failures, 1);
        assert_eq!(s.expired_half_open, 5);
        assert_eq!(s.total_promotions(), 2);
        assert_eq!(s.total_capacity_drops(), 4);
    }

    #[test]
    fn expired_half_open_zero_is_free() {
        let t = IngressTelemetry::new();
        t.record_expired_half_open(0);
        assert_eq!(t.snapshot().expired_half_open, 0);
    }

    #[test]
    fn concurrent_increments_are_not_lost() {
        let t = Arc::new(IngressTelemetry::new());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let t = Arc::clone(&t);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        t.record_local_promotion();
                        t.record_invalid_datagram();
                        t.record_expired_half_open(1);
                    }
                })
            })
            .collect();
        for handle in threads {
            handle.join().expect("thread");
        }
        let s = t.snapshot();
        assert_eq!(s.local_promotions, 4000);
        assert_eq!(s.invalid_datagrams, 4000);
        assert_eq!(s.expired_half_open, 4000);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn shard_snapshot_reconciles_service_work_and_queue_state() {
        let mut telemetry = ShardTelemetry::new();
        telemetry.record_service(
            Some(Timestamp::from_micros(100)),
            Timestamp::from_micros(125),
            Duration::from_micros(7),
        );
        telemetry.record_receive(3, 2, 1, true);
        telemetry.record_output(&crate::OutputDrainReport {
            actions: 4,
            packets: 2,
            bytes: 1200,
            status: crate::OutputDrainStatus::BudgetExhausted,
            syscalls: 1,
            would_block: false,
        });
        telemetry.observe_queue(3, 900, Duration::from_micros(11));
        telemetry.observe_queue(1, 200, Duration::from_micros(4));
        telemetry.record_accepted();
        telemetry.record_rejected();
        telemetry.record_expired();
        telemetry.record_failed();
        telemetry.record_overload(ShardOverloadReason::QueueLimit);

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.service_visits, 1);
        assert_eq!(snapshot.service_time_total_us, 7);
        assert_eq!(snapshot.service_time_max_us, 7);
        assert_eq!(snapshot.lateness_samples, 1);
        assert_eq!(snapshot.lateness_max_us, 25);
        assert_eq!(snapshot.receive_datagrams, 3);
        assert_eq!(snapshot.receive_syscalls, 2);
        assert_eq!(snapshot.receive_truncated, 1);
        assert_eq!(snapshot.output_actions, 4);
        assert_eq!(snapshot.output_packets, 2);
        assert_eq!(snapshot.output_bytes, 1200);
        assert_eq!(snapshot.output_syscalls, 1);
        assert_eq!(snapshot.budget_exhausted, 1);
        assert_eq!(snapshot.queue_items, 1);
        assert_eq!(snapshot.queue_bytes, 200);
        assert_eq!(snapshot.queue_oldest_age_us, 4);
        assert_eq!(snapshot.queue_peak_items, 3);
        assert_eq!(snapshot.queue_peak_bytes, 900);
        assert_eq!(snapshot.queue_peak_age_us, 11);
        assert_eq!(snapshot.accepted, 1);
        assert_eq!(snapshot.rejected, 1);
        assert_eq!(snapshot.expired, 1);
        assert_eq!(snapshot.failed, 1);
        assert_eq!(
            snapshot.overload_count(ShardOverloadReason::ReceiveBudget),
            1
        );
        assert_eq!(
            snapshot.overload_count(ShardOverloadReason::OutputBudget),
            1
        );
        assert_eq!(snapshot.overload_count(ShardOverloadReason::QueueLimit), 1);
        assert_eq!(snapshot.overload_total(), 3);
    }

    #[test]
    fn shard_lateness_histogram_keeps_a_fixed_storage_shape() {
        let mut telemetry = ShardTelemetry::new();
        telemetry.record_lateness(0);
        telemetry.record_lateness(1);
        telemetry.record_lateness(u64::MAX);
        telemetry.record_service(None, Timestamp::from_micros(9), Duration::ZERO);

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.lateness_samples, 3);
        assert_eq!(snapshot.lateness_max_us, u64::MAX);
        assert_eq!(snapshot.lateness_buckets.len(), SHARD_LATENESS_BUCKETS);
        assert_eq!(snapshot.lateness_buckets[0], 1);
        assert_eq!(snapshot.lateness_buckets[1], 1);
        assert_eq!(snapshot.lateness_buckets[SHARD_LATENESS_BUCKETS - 1], 1);
        assert_eq!(snapshot.service_visits, 1);
        assert_eq!(snapshot.last_intended_deadline, None);
        assert_eq!(snapshot.last_service_start, Some(Timestamp::from_micros(9)));
    }
}
