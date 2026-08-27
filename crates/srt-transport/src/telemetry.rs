use std::sync::atomic::{AtomicU64, Ordering};

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
