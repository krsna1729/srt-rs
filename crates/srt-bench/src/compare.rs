//! Comparative analysis across two benchmark result TSVs (e.g. pre-DSA baseline vs post-DSA HEAD).
//!
//! Pairs identical cells between BASE and HEAD runs, reporting median performance,
//! measurement spreads (min..max), range overlap, efficiency deltas (CPU/Gbit, CPU/Mpkt,
//! role-separated peak RSS/conn), recovery telemetry, and clean capacity frontier shifts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use crate::PAYLOAD_SIZE;
use crate::harness::{CONFIG_COLUMNS, Record, Spread, read_results};

pub use crate::harness::CONFIG_COLUMNS as CELL_KEY_COLUMNS;

type RepRecordPair<'a> = (Option<&'a Record>, Option<&'a Record>);
type CellRepMap<'a> = BTreeMap<String, BTreeMap<String, RepRecordPair<'a>>>;

/// Computed metrics for a single caller/listener pair in one rep.
#[derive(Clone, Debug, Default)]
pub struct PairMetrics {
    /// Physical connections the caller established. Distinct from
    /// `logical_streams` and `source_streams`: a two-leg bonded group is
    /// two physical connections carrying one stream from one source, and
    /// using one number for all three made a healthy bonded cell read as
    /// half-offered and half-established.
    pub conns: f64,
    /// Source payload rate in bits per second (the `source_bps` column).
    pub source_bps: f64,
    /// Application-visible streams: what a group-aware listener admits.
    pub logical_streams: f64,
    /// Independent payload producers the sender ran; the multiplier for
    /// the aggregate source workload.
    pub source_streams: f64,
    pub secs: f64,
    pub caller_established: f64,
    pub listener_established: f64,
    pub torn_c: f64,
    pub torn_l: f64,
    pub sent_pkts: f64,
    pub recv_pkts: f64,
    pub target_pkts: f64,
    pub offer_pct: f64,
    pub good_pct: f64,
    pub deliv_pct: f64,
    pub caller_cpu_ms: f64,
    pub listener_cpu_ms: f64,
    pub total_cpu_ms: f64,
    pub caller_cpu_ms_per_mpkt: f64,
    pub listener_cpu_ms_per_mpkt: f64,
    pub combined_cpu_ms_per_gbit: f64,
    pub caller_peak_rss_kb: f64,
    pub listener_peak_rss_kb: f64,
    pub caller_peak_rss_per_conn_kb: f64,
    pub listener_peak_rss_per_conn_kb: f64,
    pub max_role_peak_rss_per_conn_kb: f64,
    pub rtt_ms: f64,
    pub caller_retransmits: f64,
    pub caller_loss_list: f64,
    pub listener_lost: f64,
    pub listener_duplicates: f64,
    pub caller_udp_rcvbuf_err: f64,
    pub listener_udp_rcvbuf_err: f64,
    /// Payload opportunities the sender's application source had to drop
    /// because its bounded backlog was full: the transport could not keep
    /// up with the configured workload. Distinct from `offer_pct`, which
    /// is a rate, and from protocol loss, which is a wire event.
    pub source_overflow: f64,
    /// Worst pending-source backlog any one connection reached.
    pub source_backlog_hwm: f64,
    /// The configured bound that high-water mark is measured against.
    pub source_backlog_cap: f64,
    pub datapath_queue_overflow: f64,
    pub outbound_retry_loss: f64,
}

#[inline]
fn ratio_pct(num: f64, den: f64) -> f64 {
    if den > 0.0 { 100.0 * num / den } else { 0.0 }
}

#[inline]
fn rate_per_mpkt(cpu_ms: f64, pkts: f64) -> f64 {
    if pkts > 0.0 {
        (cpu_ms / pkts) * 1_000_000.0
    } else {
        0.0
    }
}

#[inline]
fn per_conn(val: f64, conns: f64) -> f64 {
    if conns > 0.0 { val / conns } else { val }
}

impl PairMetrics {
    pub fn compute(caller: &Record, listener: &Record) -> Option<Self> {
        let conns = listener
            .number("conns")
            .or_else(|| caller.number("conns"))?;
        let source_bps = listener
            .number("source_bps")
            .or_else(|| caller.number("source_bps"))?;
        let secs = listener.number("secs").or_else(|| caller.number("secs"))?;
        // Three distinct cardinalities. `conns` is physical connections
        // (what the caller establishes); `logical_streams` is what a
        // group-aware listener admits; `source_streams` is how many
        // payload producers the sender actually ran. They coincide unless
        // the cell is bonded, where two legs carry one stream from one
        // source -- and using `conns` for all three made a perfect bonded
        // run look half-offered and half-established.
        let logical_streams = listener
            .number("logical_streams")
            .or_else(|| caller.number("logical_streams"))
            .filter(|streams| *streams > 0.0)
            .unwrap_or(conns);
        let source_streams = caller
            .number("source_streams")
            .filter(|streams| *streams > 0.0)
            .unwrap_or(logical_streams);

        let caller_established = caller.number("established").unwrap_or(0.0);
        let listener_established = listener.number("established").unwrap_or(0.0);
        let torn_c = caller.number("torn_down").unwrap_or(0.0);
        let torn_l = listener.number("torn_down").unwrap_or(0.0);

        let sent_pkts = caller.number("core_total").unwrap_or(0.0);
        let recv_pkts = listener.number("core_total").unwrap_or(0.0);

        // The target is what the APPLICATION SOURCE asked for, so the
        // denominator is the payload size and the multiplier is the
        // number of sources. It used to be the wire size (payload + SRT
        // header), which is SRTO_MAXBW's unit -- so "did the sender offer
        // its load?" was measured against the pacing ceiling that
        // produced the load, and could not fail. A cell whose MAXBW
        // cannot carry its source rate now visibly falls short here,
        // which is the point.
        let target_pkts = (source_streams * (source_bps / 8.0) * secs) / PAYLOAD_SIZE as f64;
        let offer_pct = ratio_pct(sent_pkts, target_pkts);
        let good_pct = ratio_pct(recv_pkts, target_pkts);
        let deliv_pct = ratio_pct(recv_pkts, sent_pkts);

        let caller_cpu_user = caller.number("cpu_user_ms").unwrap_or(0.0);
        let caller_cpu_sys = caller.number("cpu_sys_ms").unwrap_or(0.0);
        let caller_cpu_ms = caller_cpu_user + caller_cpu_sys;

        let listener_cpu_user = listener.number("cpu_user_ms").unwrap_or(0.0);
        let listener_cpu_sys = listener.number("cpu_sys_ms").unwrap_or(0.0);
        let listener_cpu_ms = listener_cpu_user + listener_cpu_sys;

        let total_cpu_ms = caller_cpu_ms + listener_cpu_ms;
        let caller_cpu_ms_per_mpkt = rate_per_mpkt(caller_cpu_ms, sent_pkts);
        let listener_cpu_ms_per_mpkt = rate_per_mpkt(listener_cpu_ms, recv_pkts);

        let delivered_gbit = (recv_pkts * PAYLOAD_SIZE as f64 * 8.0) / 1e9;
        let combined_cpu_ms_per_gbit = if delivered_gbit > 0.0 {
            total_cpu_ms / delivered_gbit
        } else {
            0.0
        };

        let caller_peak_rss_kb = caller.number("peak_rss_kb").unwrap_or(0.0);
        let listener_peak_rss_kb = listener.number("peak_rss_kb").unwrap_or(0.0);
        let caller_peak_rss_per_conn_kb = per_conn(caller_peak_rss_kb, caller_established);
        let listener_peak_rss_per_conn_kb = per_conn(listener_peak_rss_kb, listener_established);
        let max_role_peak_rss_per_conn_kb =
            caller_peak_rss_per_conn_kb.max(listener_peak_rss_per_conn_kb);

        let rtt_ms = listener.number("rtt_ms").unwrap_or(0.0);
        let caller_retransmits = caller.number("sec_a").unwrap_or(0.0);
        let caller_loss_list = caller.number("sec_b").unwrap_or(0.0);
        let listener_lost = listener.number("sec_a").unwrap_or(0.0);
        let listener_duplicates = listener.number("sec_b").unwrap_or(0.0);
        let caller_udp_rcvbuf_err = caller.number("udp_rcvbuf_err").unwrap_or(0.0);
        let listener_udp_rcvbuf_err = listener.number("udp_rcvbuf_err").unwrap_or(0.0);
        // Source state is the caller's: only the sender has a workload.
        let source_overflow = caller.number("src_overflow").unwrap_or(0.0);
        let source_backlog_hwm = caller.number("src_backlog_hwm").unwrap_or(0.0);
        let source_backlog_cap = caller.number("src_backlog_cap").unwrap_or(0.0);
        let datapath_queue_overflow = caller.number("datapath_q_dropped").unwrap_or(0.0)
            + listener.number("datapath_q_dropped").unwrap_or(0.0);
        // `local_dropped` is the TOTAL number of datagrams the harness
        // dropped locally; `retry_overflow` is one of the reasons, and is
        // already included in that total. Adding them counted every
        // overflowed datagram twice.
        let outbound_retry_loss = caller.number("local_dropped").unwrap_or(0.0)
            + listener.number("local_dropped").unwrap_or(0.0);

        Some(Self {
            conns,
            source_bps,
            logical_streams,
            source_streams,
            secs,
            caller_established,
            listener_established,
            torn_c,
            torn_l,
            sent_pkts,
            recv_pkts,
            target_pkts,
            offer_pct,
            good_pct,
            deliv_pct,
            caller_cpu_ms,
            listener_cpu_ms,
            total_cpu_ms,
            caller_cpu_ms_per_mpkt,
            listener_cpu_ms_per_mpkt,
            combined_cpu_ms_per_gbit,
            caller_peak_rss_kb,
            listener_peak_rss_kb,
            caller_peak_rss_per_conn_kb,
            listener_peak_rss_per_conn_kb,
            max_role_peak_rss_per_conn_kb,
            rtt_ms,
            caller_retransmits,
            caller_loss_list,
            listener_lost,
            listener_duplicates,
            caller_udp_rcvbuf_err,
            listener_udp_rcvbuf_err,
            source_overflow,
            source_backlog_hwm,
            source_backlog_cap,
            datapath_queue_overflow,
            outbound_retry_loss,
        })
    }

    /// Canonical strict per-repetition clean capacity predicate.
    ///
    /// Requires that all asked-for connections established on both sides,
    /// zero torn connections, offer and goodput sustained at >=99.0% of
    /// the **source workload** (not of SRT's own pacing ceiling),
    /// delivery >=99.9%, zero UDP receive buffer drop errors on either
    /// side, no application source backlog overflow, and no benchmark-owned
    /// datapath queue rejection.
    ///
    /// Note what is deliberately *not* here: a cell whose SRT bandwidth
    /// policy paces below its source rate is a legitimate diagnostic
    /// configuration, not an invalid one. It is not rejected for being
    /// bandwidth-constrained; it simply fails `offer_pct`, which is the
    /// honest way to say the protocol could not service the workload.
    /// Diagnoses every condition that caused this repetition to fail the canonical
    /// clean predicate. Returns an empty vec if the repetition is clean.
    #[must_use]
    pub fn unclean_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.conns <= 0.0 {
            reasons.push(format!(
                "physical connection count is zero ({})",
                self.conns
            ));
        }
        if self.caller_established != self.conns {
            reasons.push(format!(
                "caller established {}/{}",
                self.caller_established, self.conns
            ));
        }
        if self.listener_established != self.logical_streams {
            reasons.push(format!(
                "listener established {}/{}",
                self.listener_established, self.logical_streams
            ));
        }
        if self.torn_c > 0.0 {
            reasons.push(format!("caller torn down {}", self.torn_c));
        }
        if self.torn_l > 0.0 {
            reasons.push(format!("listener torn down {}", self.torn_l));
        }
        if self.offer_pct < 99.0 {
            reasons.push(format!("source offer {:.1}% < 99.0%", self.offer_pct));
        }
        if self.good_pct < 99.0 {
            reasons.push(format!("source goodput {:.1}% < 99.0%", self.good_pct));
        }
        if self.deliv_pct < 99.9 {
            reasons.push(format!("delivery {:.1}% < 99.9%", self.deliv_pct));
        }
        if self.caller_udp_rcvbuf_err > 0.0 {
            reasons.push(format!(
                "caller UDP rcvbuf errors {}",
                self.caller_udp_rcvbuf_err
            ));
        }
        if self.listener_udp_rcvbuf_err > 0.0 {
            reasons.push(format!(
                "listener UDP rcvbuf errors {}",
                self.listener_udp_rcvbuf_err
            ));
        }
        if self.source_overflow > 0.0 {
            reasons.push(format!("source overflow {}", self.source_overflow));
        }
        if self.datapath_queue_overflow > 0.0 {
            reasons.push(format!(
                "datapath queue dropped {}",
                self.datapath_queue_overflow
            ));
        }
        if self.outbound_retry_loss > 0.0 {
            reasons.push(format!("outbound retry loss {}", self.outbound_retry_loss));
        }
        reasons
    }

    pub fn is_clean(&self) -> bool {
        self.unclean_reasons().is_empty()
    }
}

/// Aggregated summary with measurement spreads across repetitions for a cell.
#[derive(Clone, Debug)]
pub struct CellSummary {
    pub key: String,
    pub pairs: usize,
    pub incomplete_reps: usize,
    /// Physical connections. See [`PairMetrics`] for why three separate
    /// cardinalities exist.
    pub conns: f64,
    /// Source payload rate in bits per second (the `source_bps` column).
    pub source_bps: f64,
    /// Independent payload producers: the multiplier for the aggregate
    /// source workload, and not the same as `conns` for a bonded cell.
    pub source_streams: f64,
    pub caller_established: Spread,
    pub listener_established: Spread,
    pub torn_c: Spread,
    pub torn_l: Spread,
    pub offer_pct: Spread,
    pub good_pct: Spread,
    pub deliv_pct: Spread,
    pub caller_cpu_ms_per_mpkt: Spread,
    pub listener_cpu_ms_per_mpkt: Spread,
    pub combined_cpu_ms_per_gbit: Spread,
    pub caller_peak_rss_per_conn_kb: Spread,
    pub listener_peak_rss_per_conn_kb: Spread,
    pub max_role_peak_rss_per_conn_kb: Spread,
    pub rtt_ms: Spread,
    pub caller_retransmits: Spread,
    pub caller_loss_list: Spread,
    pub listener_lost: Spread,
    pub listener_duplicates: Spread,
    pub caller_udp_rcvbuf_err: Spread,
    pub listener_udp_rcvbuf_err: Spread,
    pub is_clean: bool,
}

fn group_records_by_cell(records: &[Record]) -> CellRepMap<'_> {
    let mut by_cell: CellRepMap<'_> = BTreeMap::new();
    for r in records {
        let key = cell_key(r);
        let rep = r.get("rep").unwrap_or("1");
        let attempt = r.get("attempt").unwrap_or_default();
        let rep = format!("{rep} attempt={attempt}");
        let slot = by_cell.entry(key).or_default().entry(rep).or_default();
        match r.get("role") {
            Some("caller") => slot.0 = Some(r),
            Some("listener") => slot.1 = Some(r),
            _ => {}
        }
    }
    by_cell
}

fn compute_cell_summary(key: String, pairs: &[PairMetrics], incomplete_reps: usize) -> CellSummary {
    let n = pairs.len();
    let conns = pairs[0].conns;
    let source_bps = pairs[0].source_bps;
    let source_streams = pairs[0].source_streams;

    let caller_established = Spread::of(pairs.iter().map(|p| p.caller_established).collect());
    let listener_established = Spread::of(pairs.iter().map(|p| p.listener_established).collect());
    let torn_c = Spread::of(pairs.iter().map(|p| p.torn_c).collect());
    let torn_l = Spread::of(pairs.iter().map(|p| p.torn_l).collect());
    let offer_pct = Spread::of(pairs.iter().map(|p| p.offer_pct).collect());
    let good_pct = Spread::of(pairs.iter().map(|p| p.good_pct).collect());
    let deliv_pct = Spread::of(pairs.iter().map(|p| p.deliv_pct).collect());

    let caller_cpu_ms_per_mpkt =
        Spread::of(pairs.iter().map(|p| p.caller_cpu_ms_per_mpkt).collect());
    let listener_cpu_ms_per_mpkt =
        Spread::of(pairs.iter().map(|p| p.listener_cpu_ms_per_mpkt).collect());
    let combined_cpu_ms_per_gbit =
        Spread::of(pairs.iter().map(|p| p.combined_cpu_ms_per_gbit).collect());
    let caller_peak_rss_per_conn_kb = Spread::of(
        pairs
            .iter()
            .map(|p| p.caller_peak_rss_per_conn_kb)
            .collect(),
    );
    let listener_peak_rss_per_conn_kb = Spread::of(
        pairs
            .iter()
            .map(|p| p.listener_peak_rss_per_conn_kb)
            .collect(),
    );
    let max_role_peak_rss_per_conn_kb = Spread::of(
        pairs
            .iter()
            .map(|p| p.max_role_peak_rss_per_conn_kb)
            .collect(),
    );
    let rtt_ms = Spread::of(pairs.iter().map(|p| p.rtt_ms).collect());
    let caller_retransmits = Spread::of(pairs.iter().map(|p| p.caller_retransmits).collect());
    let caller_loss_list = Spread::of(pairs.iter().map(|p| p.caller_loss_list).collect());
    let listener_lost = Spread::of(pairs.iter().map(|p| p.listener_lost).collect());
    let listener_duplicates = Spread::of(pairs.iter().map(|p| p.listener_duplicates).collect());
    let caller_udp_rcvbuf_err = Spread::of(pairs.iter().map(|p| p.caller_udp_rcvbuf_err).collect());
    let listener_udp_rcvbuf_err =
        Spread::of(pairs.iter().map(|p| p.listener_udp_rcvbuf_err).collect());

    // Strict rule: EVERY repetition must satisfy is_clean, and zero incomplete reps.
    let is_clean =
        !pairs.is_empty() && incomplete_reps == 0 && pairs.iter().all(PairMetrics::is_clean);

    CellSummary {
        key,
        pairs: n,
        incomplete_reps,
        conns,
        source_bps,
        source_streams,
        caller_established,
        listener_established,
        torn_c,
        torn_l,
        offer_pct,
        good_pct,
        deliv_pct,
        caller_cpu_ms_per_mpkt,
        listener_cpu_ms_per_mpkt,
        combined_cpu_ms_per_gbit,
        caller_peak_rss_per_conn_kb,
        listener_peak_rss_per_conn_kb,
        max_role_peak_rss_per_conn_kb,
        rtt_ms,
        caller_retransmits,
        caller_loss_list,
        listener_lost,
        listener_duplicates,
        caller_udp_rcvbuf_err,
        listener_udp_rcvbuf_err,
        is_clean,
    }
}

fn compute_empty_summary(key: String, incomplete_reps: usize, sample: &Record) -> CellSummary {
    let conns = sample.number("conns").unwrap_or(0.0);
    let source_bps = sample.number("source_bps").unwrap_or(0.0);
    let source_streams = sample
        .number("source_streams")
        .filter(|streams| *streams > 0.0)
        .or_else(|| sample.number("logical_streams").filter(|s| *s > 0.0))
        .unwrap_or(conns);
    CellSummary {
        key,
        pairs: 0,
        incomplete_reps,
        conns,
        source_bps,
        source_streams,
        caller_established: Spread::default(),
        listener_established: Spread::default(),
        torn_c: Spread::default(),
        torn_l: Spread::default(),
        offer_pct: Spread::default(),
        good_pct: Spread::default(),
        deliv_pct: Spread::default(),
        caller_cpu_ms_per_mpkt: Spread::default(),
        listener_cpu_ms_per_mpkt: Spread::default(),
        combined_cpu_ms_per_gbit: Spread::default(),
        caller_peak_rss_per_conn_kb: Spread::default(),
        listener_peak_rss_per_conn_kb: Spread::default(),
        max_role_peak_rss_per_conn_kb: Spread::default(),
        rtt_ms: Spread::default(),
        caller_retransmits: Spread::default(),
        caller_loss_list: Spread::default(),
        listener_lost: Spread::default(),
        listener_duplicates: Spread::default(),
        caller_udp_rcvbuf_err: Spread::default(),
        listener_udp_rcvbuf_err: Spread::default(),
        is_clean: false,
    }
}

pub fn summarize_cells(records: &[Record]) -> BTreeMap<String, CellSummary> {
    let by_cell = group_records_by_cell(records);
    let mut summaries = BTreeMap::new();
    for (key, reps) in by_cell {
        let mut pairs: Vec<PairMetrics> = Vec::new();
        let mut incomplete_reps = 0usize;
        for (caller, listener) in reps.values() {
            if let (Some(c), Some(l)) = (caller, listener) {
                if let Some(m) = PairMetrics::compute(c, l) {
                    pairs.push(m);
                } else {
                    incomplete_reps += 1;
                }
            } else {
                incomplete_reps += 1;
            }
        }
        if !pairs.is_empty() {
            summaries.insert(
                key.clone(),
                compute_cell_summary(key, &pairs, incomplete_reps),
            );
        } else if let Some(sample) = reps.values().find_map(|(c, l)| (*c).or(*l)) {
            summaries.insert(
                key.clone(),
                compute_empty_summary(key, incomplete_reps, sample),
            );
        }
    }
    summaries
}

pub fn cell_key(r: &Record) -> String {
    let mut parts = Vec::new();
    for col in CONFIG_COLUMNS {
        if unscoped_column_is_shadowed(r, col) {
            continue;
        }
        if let Some(val) = r.get(col) {
            parts.push(format!("{col}={val}"));
        }
    }
    parts.join(" ")
}

fn unscoped_column_is_shadowed(record: &Record, column: &str) -> bool {
    let scoped = match column {
        "cpus" => ["recv_cpus", "send_cpus"],
        "workers" => ["recv_workers", "send_workers"],
        "runtime" => ["recv_runtime", "send_runtime"],
        "ingress" => ["recv_ingress", "send_ingress"],
        _ => return false,
    };
    scoped
        .iter()
        .any(|field| record.get(field).is_some_and(|value| !value.is_empty()))
}

pub fn extract_key_field<'a>(key: &'a str, target: &str) -> &'a str {
    for part in key.split(' ') {
        if let Some((k, v)) = part.split_once('=')
            && k == target
        {
            return v;
        }
    }
    ""
}

pub fn format_short_cell_label(key: &str) -> String {
    let runtime = extract_key_field(key, "runtime");
    let conns = extract_key_field(key, "conns");
    let source_bps = extract_key_field(key, "source_bps");
    let enc = extract_key_field(key, "encryption");
    let ingress = extract_key_field(key, "ingress");
    let loss = extract_key_field(key, "link_loss");
    let reorder = extract_key_field(key, "link_reorder");
    let bond = extract_key_field(key, "bond");

    let br_label = match source_bps.parse::<u64>() {
        Ok(b) if b >= 1_000_000 => format!("{}M", b / 1_000_000),
        Ok(b) if b >= 1_000 => format!("{}k", b / 1_000),
        _ => source_bps.to_string(),
    };

    let mut label = format!("{runtime} {conns}c×{br_label}");
    if enc != "plain" && !enc.is_empty() {
        label.push_str(&format!(" {enc}"));
    }
    if ingress != "per-port" && !ingress.is_empty() {
        label.push_str(&format!(" {ingress}"));
    }
    if bond != "none" && !bond.is_empty() {
        label.push_str(&format!(" {bond}"));
    }
    if loss != "0" && loss != "0.0" && loss != "off" && !loss.is_empty() {
        label.push_str(&format!(" loss={loss}"));
    }
    if reorder != "0" && reorder != "0.0" && reorder != "off" && !reorder.is_empty() {
        label.push_str(&format!(" reorder={reorder}"));
    }
    label
}

/// Aggregate source workload a cell was configured to produce, in bits
/// per second: payload sources times each source's payload rate.
///
/// This is the *workload*, not SRT's pacing ceiling. The two were the
/// same number before the source/pacing split, and a frontier expressed
/// in MAXBW answered a question about the protocol's configuration rather
/// than about the load the stack actually carried.
#[must_use]
pub fn aggregate_source_bps(summary: &CellSummary) -> f64 {
    summary.source_streams * summary.source_bps
}

/// Finds the highest clean aggregate *source workload* strictly among
/// cells where all repetitions passed `is_clean`.
pub fn calculate_capacity_frontier<'a>(
    summaries: &'a BTreeMap<String, CellSummary>,
) -> Option<&'a CellSummary> {
    let mut best: Option<&'a CellSummary> = None;
    let mut max_rate = 0.0;

    for s in summaries.values() {
        if s.is_clean {
            let agg_bps = aggregate_source_bps(s);
            if agg_bps > max_rate {
                max_rate = agg_bps;
                best = Some(s);
            }
        }
    }
    best
}

pub fn delta_pct(base: f64, head: f64) -> f64 {
    if base > 0.0 {
        100.0 * (head - base) / base
    } else {
        0.0
    }
}

pub fn format_spread(s: Spread) -> String {
    format!("{:.1} [{:.1}..{:.1}]", s.median, s.min, s.max)
}

fn format_frontier_label(summary: Option<&CellSummary>) -> String {
    summary
        .map(|s| {
            // `source_bps` is already a PAYLOAD rate, so achieved payload
            // is simply the fraction of it that arrived. The old code
            // additionally multiplied by PAYLOAD/(PAYLOAD + SRT_HEADER),
            // which is the wire-overhead haircut appropriate to a MAXBW
            // figure -- applying it here charged SRT's header cost to a
            // number that never contained it.
            let achieved_payload_gbps =
                (s.good_pct.median / 100.0) * aggregate_source_bps(s) / 1e9;
            format!(
                "{} (source workload: {:.3} Gbit/s, {}, achieved payload: {:.3} Gbit/s, offer: {:.1}%, good: {:.1}%)",
                format_short_cell_label(&s.key),
                aggregate_source_bps(s) / 1e9,
                describe_srt_pacing(&s.key),
                achieved_payload_gbps,
                s.offer_pct.median,
                s.good_pct.median
            )
        })
        .unwrap_or_else(|| "none (no cell met strict >=99% offer/good across all repetitions)".into())
}

/// How the cell configured SRT's pacing, read back from its key.
///
/// Printed next to the source workload precisely so the two can never be
/// read as the same quantity again: a cell can perfectly well have an
/// 8 Mbit/s source and a 4 Mbit/s ceiling, and that pair is the whole
/// point of the split.
fn describe_srt_pacing(key: &str) -> String {
    match extract_key_field(key, "srt_bw_mode") {
        "" => "SRT pacing: unrecorded".to_string(),
        mode => format!("SRT pacing: {mode}"),
    }
}

fn render_frontier_markdown(
    out: &mut String,
    base_frontier: Option<&CellSummary>,
    head_frontier: Option<&CellSummary>,
) {
    writeln!(
        out,
        "## 1. Capacity Frontier Analysis (Strict All-Repetition Clean Criteria)"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Clean capacity criteria, across **all** repetitions: \
         `caller_established == conns` (physical legs), \
         `listener_established == logical_streams` (a bonded group is one \
         admitted stream, not two), `torn == 0`, `offer >= 99.0%`, \
         `goodput >= 99.0%`, `deliv >= 99.9%`, `udp_rcvbuf_err == 0` on \
         both roles, and zero benchmark-owned overflow \
         (`src_overflow`, `datapath_q_dropped`, `local_dropped`). \
         A cell whose SRT pacing ceiling sits below its source rate is a \
         legitimate diagnostic configuration and is not rejected for that; \
         it simply fails `offer`, which is the honest way to say the \
         protocol could not service the workload."
    )
    .unwrap();
    writeln!(
        out,
        "Source target is the application workload, not SRT's pacing ceiling: \
         `target = source_streams × (source_bps ÷ 8) × secs ÷ 1316`. SRT's own ceiling is \
         recorded separately as `srt_maxbw_bps`."
    )
    .unwrap();
    writeln!(out).unwrap();

    let base_source_bps = base_frontier.map(aggregate_source_bps).unwrap_or(0.0);
    let head_source_bps = head_frontier.map(aggregate_source_bps).unwrap_or(0.0);
    let delta = delta_pct(base_source_bps, head_source_bps);

    let base_label = format_frontier_label(base_frontier);
    let head_label = format_frontier_label(head_frontier);

    writeln!(out, "| Metric | Pre-DSA Baseline | Post-DSA HEAD | Delta |").unwrap();
    writeln!(out, "|---|---|---|---|").unwrap();
    writeln!(
        out,
        "| **Max Clean Aggregate Rate** | **{:.3} Gbit/s** ({}) | **{:.3} Gbit/s** ({}) | **{:+.1}%** |",
        base_source_bps / 1e9,
        base_label,
        head_source_bps / 1e9,
        head_label,
        delta
    )
    .unwrap();
    writeln!(out).unwrap();
}

fn render_reps_string(b: &CellSummary, h: &CellSummary) -> String {
    if b.pairs == h.pairs && b.incomplete_reps == 0 && h.incomplete_reps == 0 {
        format!("n={}", h.pairs)
    } else {
        format!(
            "B={}/{} H={}/{} (unequal)",
            b.pairs,
            b.pairs + b.incomplete_reps,
            h.pairs,
            h.pairs + h.incomplete_reps
        )
    }
}

fn render_markdown_cell_row(out: &mut String, label: &str, b: &CellSummary, h: &CellSummary) {
    if b.pairs == 0 || h.pairs == 0 {
        writeln!(
            out,
            "| **{label}** | B={}/{} H={}/{} | incomplete (no complete pairs) | -- | -- | -- | -- | -- | -- |",
            b.pairs, b.pairs + b.incomplete_reps, h.pairs, h.pairs + h.incomplete_reps
        )
        .unwrap();
        return;
    }

    let gbit_delta = delta_pct(
        b.combined_cpu_ms_per_gbit.median,
        h.combined_cpu_ms_per_gbit.median,
    );
    let gbit_overlap = b
        .combined_cpu_ms_per_gbit
        .overlaps(h.combined_cpu_ms_per_gbit);
    let caller_delta = delta_pct(
        b.caller_cpu_ms_per_mpkt.median,
        h.caller_cpu_ms_per_mpkt.median,
    );
    let listener_delta = delta_pct(
        b.listener_cpu_ms_per_mpkt.median,
        h.listener_cpu_ms_per_mpkt.median,
    );
    let rss_caller_delta = delta_pct(
        b.caller_peak_rss_per_conn_kb.median,
        h.caller_peak_rss_per_conn_kb.median,
    );
    let rss_listener_delta = delta_pct(
        b.listener_peak_rss_per_conn_kb.median,
        h.listener_peak_rss_per_conn_kb.median,
    );

    let overlap_str = if gbit_overlap { "yes" } else { "no" };
    let reps_str = render_reps_string(b, h);

    let clean_b = if b.is_clean { "yes" } else { "no" };
    let clean_h = if h.is_clean { "yes" } else { "no" };
    let clean_str = format!("{clean_b}/{clean_h}");

    writeln!(
        out,
        "| **{label}** | {} | {:.1}% → {:.1}% | {:.1}% → {:.1}% | {:.1}% → {:.1}% | {} | {} → {} (**{:+.1}%**, overlap: {}) | {:.1} → {:.1} ({:+.1}%) | {:.1} → {:.1} ({:+.1}%) | C: {:.0}→{:.0} ({:+.1}%), L: {:.0}→{:.0} ({:+.1}%) | Retx: {:.0}→{:.0}, Lost: {:.0}→{:.0}, Dup: {:.0}→{:.0} | {:.2} → {:.2} |",
        reps_str,
        b.offer_pct.median,
        h.offer_pct.median,
        b.good_pct.median,
        h.good_pct.median,
        b.deliv_pct.median,
        h.deliv_pct.median,
        clean_str,
        format_spread(b.combined_cpu_ms_per_gbit),
        format_spread(h.combined_cpu_ms_per_gbit),
        gbit_delta,
        overlap_str,
        b.caller_cpu_ms_per_mpkt.median,
        h.caller_cpu_ms_per_mpkt.median,
        caller_delta,
        b.listener_cpu_ms_per_mpkt.median,
        h.listener_cpu_ms_per_mpkt.median,
        listener_delta,
        b.caller_peak_rss_per_conn_kb.median,
        h.caller_peak_rss_per_conn_kb.median,
        rss_caller_delta,
        b.listener_peak_rss_per_conn_kb.median,
        h.listener_peak_rss_per_conn_kb.median,
        rss_listener_delta,
        b.caller_retransmits.median,
        h.caller_retransmits.median,
        b.listener_lost.median,
        h.listener_lost.median,
        b.listener_duplicates.median,
        h.listener_duplicates.median,
        b.rtt_ms.median,
        h.rtt_ms.median
    )
    .unwrap();
}

fn render_unmatched_section(out: &mut String, base_only: &[&str], head_only: &[&str]) {
    if !base_only.is_empty() || !head_only.is_empty() {
        writeln!(out, "### Unmatched Workload Cells").unwrap();
        writeln!(out).unwrap();
        if !base_only.is_empty() {
            writeln!(out, "**Baseline Only Cells (missing in HEAD)**:").unwrap();
            for k in base_only {
                writeln!(out, "- `{}`", format_short_cell_label(k)).unwrap();
            }
            writeln!(out).unwrap();
        }
        if !head_only.is_empty() {
            writeln!(out, "**HEAD Only Cells (missing in Baseline)**:").unwrap();
            for k in head_only {
                writeln!(out, "- `{}`", format_short_cell_label(k)).unwrap();
            }
            writeln!(out).unwrap();
        }
    }
}

pub fn render_markdown_scorecard(
    base_path: &Path,
    head_path: &Path,
    base_summaries: &BTreeMap<String, CellSummary>,
    head_summaries: &BTreeMap<String, CellSummary>,
) -> String {
    let mut out = String::new();
    let base_frontier = calculate_capacity_frontier(base_summaries);
    let head_frontier = calculate_capacity_frontier(head_summaries);

    writeln!(out, "# Pre/Post DSA End-to-End Benchmark Scorecard").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "- **Baseline (Pre-DSA #37)**: `{}`",
        base_path.display()
    )
    .unwrap();
    writeln!(out, "- **Head (Post-DSA #61)**: `{}`", head_path.display()).unwrap();
    writeln!(out).unwrap();

    render_frontier_markdown(&mut out, base_frontier, head_frontier);

    writeln!(out, "## 2. Cell-by-Cell Comparative Scorecard").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "| Workload Cell | Reps | Offer% (B→H) | Good% (B→H) | Deliv% (B→H) | Clean B/H | CPU ms/Gbit (Base [min..max] → Head [min..max], Δ%, Overlap) | Caller CPU ms/Mpkt | Listener CPU ms/Mpkt | Peak RSS/conn KB (Caller, Listener) | Recovery Telemetry (Retx, Lost, Dup) | RTT ms |"
    )
    .unwrap();
    writeln!(
        out,
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|"
    )
    .unwrap();

    let mut base_only = Vec::new();
    let mut head_only = Vec::new();

    let all_keys: BTreeSet<&str> = base_summaries
        .keys()
        .chain(head_summaries.keys())
        .map(String::as_str)
        .collect();

    for key in all_keys {
        let label = format_short_cell_label(key);
        match (base_summaries.get(key), head_summaries.get(key)) {
            (Some(b), Some(h)) => {
                render_markdown_cell_row(&mut out, &label, b, h);
            }
            (Some(_), None) => {
                base_only.push(key);
            }
            (None, Some(_)) => {
                head_only.push(key);
            }
            (None, None) => {}
        }
    }
    writeln!(out).unwrap();
    render_unmatched_section(&mut out, &base_only, &head_only);

    out
}

fn render_table_cell_row(out: &mut String, label: &str, b: &CellSummary, h: &CellSummary) {
    if b.pairs == 0 || h.pairs == 0 {
        writeln!(
            out,
            "{:<32} {:>7} {:>8} {:>17} {:>17} {:>11} {:>7} {:>10} {:>10} {:>9}",
            label,
            format!("B{}H{}", b.pairs, h.pairs),
            "incompl",
            "--",
            "--",
            "--",
            "--",
            "--",
            "--",
            "--"
        )
        .unwrap();
        return;
    }

    let gbit_delta = delta_pct(
        b.combined_cpu_ms_per_gbit.median,
        h.combined_cpu_ms_per_gbit.median,
    );
    let caller_delta = delta_pct(
        b.caller_cpu_ms_per_mpkt.median,
        h.caller_cpu_ms_per_mpkt.median,
    );
    let listener_delta = delta_pct(
        b.listener_cpu_ms_per_mpkt.median,
        h.listener_cpu_ms_per_mpkt.median,
    );
    let overlap_str = if b
        .combined_cpu_ms_per_gbit
        .overlaps(h.combined_cpu_ms_per_gbit)
    {
        "yes"
    } else {
        "no"
    };

    let base_str = format!(
        "{:.0} [{:.0}..{:.0}]",
        b.combined_cpu_ms_per_gbit.median,
        b.combined_cpu_ms_per_gbit.min,
        b.combined_cpu_ms_per_gbit.max
    );
    let head_str = format!(
        "{:.0} [{:.0}..{:.0}]",
        h.combined_cpu_ms_per_gbit.median,
        h.combined_cpu_ms_per_gbit.min,
        h.combined_cpu_ms_per_gbit.max
    );

    let reps_str = if b.pairs == h.pairs && b.incomplete_reps == 0 && h.incomplete_reps == 0 {
        format!("n={}", h.pairs)
    } else {
        format!("B{}H{}*", b.pairs, h.pairs)
    };

    let clean_str = format!(
        "{}/{}",
        if b.is_clean { "Y" } else { "N" },
        if h.is_clean { "Y" } else { "N" }
    );
    let offer_str = format!("{:.0}%->{:.0}%", b.offer_pct.median, h.offer_pct.median);
    let good_str = format!("{:.0}%->{:.0}%", b.good_pct.median, h.good_pct.median);

    writeln!(
        out,
        "{:<32} {:>7} {:>11} {:>11} {:>6.1}% {:>7} {:>17} {:>17} {:>+10.1}% {:>7} {:>+9.1}% {:>+9.1}% {:>4.0}/{:<4.0}",
        label,
        reps_str,
        offer_str,
        good_str,
        h.deliv_pct.median,
        clean_str,
        base_str,
        head_str,
        gbit_delta,
        overlap_str,
        caller_delta,
        listener_delta,
        h.caller_peak_rss_per_conn_kb.median,
        h.listener_peak_rss_per_conn_kb.median,
    )
    .unwrap();
}

pub fn render_table_scorecard(
    base_path: &Path,
    head_path: &Path,
    base_summaries: &BTreeMap<String, CellSummary>,
    head_summaries: &BTreeMap<String, CellSummary>,
) -> String {
    let mut out = String::new();
    let base_frontier = calculate_capacity_frontier(base_summaries);
    let head_frontier = calculate_capacity_frontier(head_summaries);

    writeln!(out, "=== Pre/Post DSA End-to-End Benchmark Scorecard ===").unwrap();
    writeln!(out, "Baseline (Pre-DSA): {}", base_path.display()).unwrap();
    writeln!(out, "Head (Post-DSA):     {}", head_path.display()).unwrap();
    writeln!(out).unwrap();

    let base_source_bps = base_frontier.map(aggregate_source_bps).unwrap_or(0.0);
    let head_source_bps = head_frontier.map(aggregate_source_bps).unwrap_or(0.0);
    let delta = delta_pct(base_source_bps, head_source_bps);

    writeln!(
        out,
        "--- Capacity Frontier (Strict All-Rep Clean Criteria) ---"
    )
    .unwrap();
    writeln!(
        out,
        "Max Clean Aggregate Rate: {:.3} Gbit/s -> {:.3} Gbit/s ({:+.1}%)",
        base_source_bps / 1e9,
        head_source_bps / 1e9,
        delta
    )
    .unwrap();
    let base_label = format_frontier_label(base_frontier);
    let head_label = format_frontier_label(head_frontier);
    writeln!(out, "  Baseline frontier: {base_label}").unwrap();
    writeln!(out, "  HEAD frontier:     {head_label}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "{:<32} {:>7} {:>11} {:>11} {:>7} {:>7} {:>17} {:>17} {:>11} {:>7} {:>10} {:>10} {:>9}",
        "Workload",
        "Reps",
        "Offer B->H",
        "Good B->H",
        "Deliv%",
        "Clean",
        "CPU/Gbit B",
        "CPU/Gbit H",
        "CPU/Gbit Δ",
        "Overlap",
        "Call Mpkt",
        "List Mpkt",
        "RSS C/L"
    )
    .unwrap();
    writeln!(out, "{:-<160}", "").unwrap();

    let mut base_only = Vec::new();
    let mut head_only = Vec::new();

    let all_keys: BTreeSet<&str> = base_summaries
        .keys()
        .chain(head_summaries.keys())
        .map(String::as_str)
        .collect();

    for key in all_keys {
        let label = format_short_cell_label(key);
        match (base_summaries.get(key), head_summaries.get(key)) {
            (Some(b), Some(h)) => {
                render_table_cell_row(&mut out, &label, b, h);
            }
            (Some(_), None) => {
                base_only.push(key);
            }
            (None, Some(_)) => {
                head_only.push(key);
            }
            (None, None) => {}
        }
    }

    if !base_only.is_empty() || !head_only.is_empty() {
        writeln!(out).unwrap();
        if !base_only.is_empty() {
            writeln!(
                out,
                "Warning: {} cells only present in baseline",
                base_only.len()
            )
            .unwrap();
        }
        if !head_only.is_empty() {
            writeln!(
                out,
                "Warning: {} cells only present in head",
                head_only.len()
            )
            .unwrap();
        }
    }

    out
}

pub fn compare_files(base_path: &Path, head_path: &Path, markdown: bool) -> Result<String, String> {
    let base_records = read_results(base_path)
        .map_err(|e| format!("failed reading base file {}: {e}", base_path.display()))?;
    let head_records = read_results(head_path)
        .map_err(|e| format!("failed reading head file {}: {e}", head_path.display()))?;

    let base_summaries = summarize_cells(&base_records);
    let head_summaries = summarize_cells(&head_records);

    if markdown {
        Ok(render_markdown_scorecard(
            base_path,
            head_path,
            &base_summaries,
            &head_summaries,
        ))
    } else {
        Ok(render_table_scorecard(
            base_path,
            head_path,
            &base_summaries,
            &head_summaries,
        ))
    }
}

/// Validate that every cell and repetition in `path` satisfies the canonical
/// clean benchmark predicate ([`PairMetrics::is_clean`]).
///
/// Returns `Ok(summary)` on success, or `Err(diagnostics)` if any repetition
/// failed the clean predicate or was incomplete (missing a caller or listener).
pub fn check_clean_file(path: &Path) -> Result<String, String> {
    let records =
        read_results(path).map_err(|e| format!("check-clean: {}: {e}\n", path.display()))?;
    if records.is_empty() {
        return Err(format!(
            "check-clean: {}: result file has no rows\n",
            path.display()
        ));
    }

    let by_cell = group_records_by_cell(&records);
    let mut total = 0;
    let mut unclean = 0;
    let mut incomplete = 0;
    let mut failures = Vec::new();

    for (cell, reps) in &by_cell {
        for (rep, pair) in reps {
            total += 1;
            if let Some((is_incomplete, message)) = pair_failure(cell, rep, *pair) {
                incomplete += usize::from(is_incomplete);
                unclean += usize::from(!is_incomplete);
                failures.push(message);
            }
        }
    }

    if !failures.is_empty() {
        let mut out = failures.join("\n");
        out.push('\n');
        out.push_str(&format!(
            "check-clean: FAILED: {} incomplete, {} unclean out of {} total pairs across {} cells\n",
            incomplete,
            unclean,
            total,
            by_cell.len()
        ));
        return Err(out);
    }

    Ok(format!(
        "check-clean: OK: all {} cells ({} pairs) satisfy the canonical clean predicate\n",
        by_cell.len(),
        total
    ))
}

fn pair_failure(
    cell: &str,
    rep: &str,
    (caller, listener): RepRecordPair<'_>,
) -> Option<(bool, String)> {
    let (caller, listener) = match (caller, listener) {
        (Some(caller), Some(listener)) => (caller, listener),
        (Some(_), None) => {
            return Some((
                true,
                format!("INCOMPLETE: cell=[{cell}] rep={rep}: missing listener row"),
            ));
        }
        (None, Some(_)) => {
            return Some((
                true,
                format!("INCOMPLETE: cell=[{cell}] rep={rep}: missing caller row"),
            ));
        }
        (None, None) => return None,
    };
    let Some(metrics) = PairMetrics::compute(caller, listener) else {
        return Some((
            false,
            format!("FAIL: cell=[{cell}] rep={rep}: could not compute pair metrics"),
        ));
    };
    let reasons = metrics.unclean_reasons();
    (!reasons.is_empty()).then(|| {
        (
            false,
            format!("FAIL: cell=[{cell}] rep={rep}: {}", reasons.join(", ")),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn make_test_caller(
        rep: &str,
        conns: &str,
        source_bps: &str,
        secs: &str,
        core_total: &str,
        cpu_user: &str,
        cpu_sys: &str,
        rss: &str,
        retx: &str,
        loss_list: &str,
        torn: &str,
        estab: &str,
        rcvbuf_err: &str,
    ) -> Record {
        Record {
            fields: [
                ("runtime".to_string(), "mio".to_string()),
                ("encryption".to_string(), "plain".to_string()),
                ("role".to_string(), "caller".to_string()),
                ("ingress".to_string(), "shared-pool:4".to_string()),
                ("egress".to_string(), "per-connection".to_string()),
                ("promotion".to_string(), "all".to_string()),
                ("cookie".to_string(), "on".to_string()),
                ("batch".to_string(), "on".to_string()),
                (
                    "sock_buf_requested_bytes".to_string(),
                    "16777216".to_string(),
                ),
                ("cpus".to_string(), "6".to_string()),
                ("pin".to_string(), "off".to_string()),
                ("link_delay".to_string(), "off".to_string()),
                ("link_jitter".to_string(), "off".to_string()),
                ("link_loss".to_string(), "off".to_string()),
                ("link_rate".to_string(), "off".to_string()),
                ("link_reorder".to_string(), "off".to_string()),
                ("link_duplicate".to_string(), "off".to_string()),
                ("link_corrupt".to_string(), "off".to_string()),
                ("link_limit".to_string(), "off".to_string()),
                ("workers".to_string(), "1".to_string()),
                ("conns".to_string(), conns.to_string()),
                ("source_bps".to_string(), source_bps.to_string()),
                ("secs".to_string(), secs.to_string()),
                ("rep".to_string(), rep.to_string()),
                ("established".to_string(), estab.to_string()),
                ("torn_down".to_string(), torn.to_string()),
                ("core_total".to_string(), core_total.to_string()),
                ("sec_a".to_string(), retx.to_string()),
                ("sec_b".to_string(), loss_list.to_string()),
                ("cpu_user_ms".to_string(), cpu_user.to_string()),
                ("cpu_sys_ms".to_string(), cpu_sys.to_string()),
                ("peak_rss_kb".to_string(), rss.to_string()),
                ("udp_rcvbuf_err".to_string(), rcvbuf_err.to_string()),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_test_listener(
        rep: &str,
        conns: &str,
        source_bps: &str,
        secs: &str,
        core_total: &str,
        cpu_user: &str,
        cpu_sys: &str,
        rss: &str,
        lost: &str,
        dup: &str,
        torn: &str,
        estab: &str,
        rcvbuf_err: &str,
    ) -> Record {
        Record {
            fields: [
                ("runtime".to_string(), "mio".to_string()),
                ("encryption".to_string(), "plain".to_string()),
                ("role".to_string(), "listener".to_string()),
                ("ingress".to_string(), "shared-pool:4".to_string()),
                ("egress".to_string(), "per-connection".to_string()),
                ("promotion".to_string(), "all".to_string()),
                ("cookie".to_string(), "on".to_string()),
                ("batch".to_string(), "on".to_string()),
                (
                    "sock_buf_requested_bytes".to_string(),
                    "16777216".to_string(),
                ),
                ("cpus".to_string(), "6".to_string()),
                ("pin".to_string(), "off".to_string()),
                ("link_delay".to_string(), "off".to_string()),
                ("link_jitter".to_string(), "off".to_string()),
                ("link_loss".to_string(), "off".to_string()),
                ("link_rate".to_string(), "off".to_string()),
                ("link_reorder".to_string(), "off".to_string()),
                ("link_duplicate".to_string(), "off".to_string()),
                ("link_corrupt".to_string(), "off".to_string()),
                ("link_limit".to_string(), "off".to_string()),
                ("workers".to_string(), "1".to_string()),
                ("conns".to_string(), conns.to_string()),
                ("source_bps".to_string(), source_bps.to_string()),
                ("secs".to_string(), secs.to_string()),
                ("rep".to_string(), rep.to_string()),
                ("established".to_string(), estab.to_string()),
                ("torn_down".to_string(), torn.to_string()),
                ("core_total".to_string(), core_total.to_string()),
                ("sec_a".to_string(), lost.to_string()),
                ("sec_b".to_string(), dup.to_string()),
                ("rtt_ms".to_string(), "1.5".to_string()),
                ("cpu_user_ms".to_string(), cpu_user.to_string()),
                ("cpu_sys_ms".to_string(), cpu_sys.to_string()),
                ("peak_rss_kb".to_string(), rss.to_string()),
                ("udp_rcvbuf_err".to_string(), rcvbuf_err.to_string()),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn test_format_short_cell_label() {
        let key = "runtime=mio conns=600 source_bps=1000000 encryption=plain ingress=shared-pool:4 bond=none link_loss=0 link_reorder=0";
        let label = format_short_cell_label(key);
        assert_eq!(label, "mio 600c×1M shared-pool:4");

        let key_loss = "runtime=tokio conns=1 source_bps=8000000 encryption=256 ingress=per-port bond=none link_loss=0.01 link_reorder=0";
        let label_loss = format_short_cell_label(key_loss);
        assert_eq!(label_loss, "tokio 1c×8M 256 loss=0.01");
    }

    #[test]
    fn test_recovery_semantics() {
        // Target paced packets for conns=10, bitrate=1000000 (1M), secs=10:
        // Source target, payload denominator:
        // (10 * (1_000_000 / 8) * 10) / 1316 = 1_250_000 / 1316 = 9498.5 -> 9499 pkts
        let caller = make_test_caller(
            "1", "10", "1000000", "10", "9499", "120.0", "80.0", "2048", "42", "7", "0", "10", "0",
        );
        let listener = make_test_listener(
            "1", "10", "1000000", "10", "9499", "150.0", "100.0", "4096", "15", "3", "0", "10", "0",
        );
        let m = PairMetrics::compute(&caller, &listener).expect("pair metrics compute");

        // Verify recovery semantics: caller sec_a -> retransmits, sec_b -> loss_list
        assert_eq!(m.caller_retransmits, 42.0);
        assert_eq!(m.caller_loss_list, 7.0);

        // Verify recovery semantics: listener sec_a -> lost, sec_b -> duplicates
        assert_eq!(m.listener_lost, 15.0);
        assert_eq!(m.listener_duplicates, 3.0);
    }

    #[test]
    fn test_role_separated_metrics() {
        let caller = make_test_caller(
            "1", "10", "1000000", "10", "9499", "120.0", "80.0", "2048", "0", "0", "0", "10", "0",
        );
        let listener = make_test_listener(
            "1", "10", "1000000", "10", "9499", "150.0", "100.0", "4096", "0", "0", "0", "10", "0",
        );
        let m = PairMetrics::compute(&caller, &listener).expect("pair metrics compute");

        assert_eq!(m.conns, 10.0);
        assert_eq!(m.caller_established, 10.0);
        assert_eq!(m.listener_established, 10.0);
        assert_eq!(m.deliv_pct, 100.0);
        assert!(m.offer_pct >= 99.0);
        assert!(m.good_pct >= 99.0);

        // Role-separated RSS per connection
        assert_eq!(m.caller_peak_rss_per_conn_kb, 204.8);
        assert_eq!(m.listener_peak_rss_per_conn_kb, 409.6);
        assert_eq!(m.max_role_peak_rss_per_conn_kb, 409.6);

        // CPU metrics
        assert_eq!(m.caller_cpu_ms, 200.0);
        assert_eq!(m.listener_cpu_ms, 250.0);
        assert_eq!(m.total_cpu_ms, 450.0);
        assert!(m.is_clean());
    }

    #[test]
    fn test_clean_predicate_thresholds() {
        // Base clean pair: 9499 packets over the source target
        // (10 * 125000 * 10 / 1316 = 9498.5)
        let c = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let l = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        assert!(PairMetrics::compute(&c, &l).unwrap().is_clean());

        // 1. Offer < 99% rejected
        let c_low_offer = make_test_caller(
            "1", "10", "1000000", "10", "8000", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let l_matched = make_test_listener(
            "1", "10", "1000000", "10", "8000", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let m_low_offer = PairMetrics::compute(&c_low_offer, &l_matched).unwrap();
        assert_eq!(m_low_offer.deliv_pct, 100.0);
        assert!(m_low_offer.offer_pct < 99.0);
        assert!(
            !m_low_offer.is_clean(),
            "offer < 99% must be rejected as clean capacity"
        );

        // 2. Goodput < 99% rejected
        let l_low_recv = make_test_listener(
            "1", "10", "1000000", "10", "8000", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let m_low_good = PairMetrics::compute(&c, &l_low_recv).unwrap();
        assert!(m_low_good.good_pct < 99.0);
        assert!(
            !m_low_good.is_clean(),
            "goodput < 99% must be rejected as clean capacity"
        );

        // 3. Delivery < 99.9% rejected
        let l_lost = make_test_listener(
            "1", "10", "1000000", "10", "9300", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let m_low_deliv = PairMetrics::compute(&c, &l_lost).unwrap();
        assert!(m_low_deliv.deliv_pct < 99.9);
        assert!(!m_low_deliv.is_clean(), "deliv < 99.9% must be rejected");

        // 4. UDP receive-buffer drop rejected (listener or caller)
        let l_drop = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "5",
        );
        assert!(
            !PairMetrics::compute(&c, &l_drop).unwrap().is_clean(),
            "listener udp_rcvbuf_err > 0 must be rejected"
        );
        let c_drop = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "3",
        );
        assert!(
            !PairMetrics::compute(&c_drop, &l).unwrap().is_clean(),
            "caller udp_rcvbuf_err > 0 must be rejected"
        );

        // 5. Caller or listener unestablished rejected
        let c_unestab = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "9", "0",
        );
        assert!(
            !PairMetrics::compute(&c_unestab, &l).unwrap().is_clean(),
            "caller_established < conns must be rejected"
        );
        let l_unestab = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "9", "0",
        );
        assert!(
            !PairMetrics::compute(&c, &l_unestab).unwrap().is_clean(),
            "listener_established < conns must be rejected"
        );

        // 6. Torn connections rejected
        let c_torn = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "1", "10", "0",
        );
        assert!(
            !PairMetrics::compute(&c_torn, &l).unwrap().is_clean(),
            "torn_c > 0 must be rejected"
        );
        let l_torn = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "1", "10", "0",
        );
        assert!(
            !PairMetrics::compute(&c, &l_torn).unwrap().is_clean(),
            "torn_l > 0 must be rejected"
        );
    }

    #[test]
    fn test_unclean_reasons_diagnostics() {
        let c = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "9", "5",
        );
        let l = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "1", "10", "10",
        );
        let m = PairMetrics::compute(&c, &l).unwrap();
        assert!(!m.is_clean());
        let reasons = m.unclean_reasons();
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("caller established 9/10"))
        );
        assert!(reasons.iter().any(|r| r.contains("listener torn down 1")));
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("caller UDP rcvbuf errors 5"))
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("listener UDP rcvbuf errors 10"))
        );
    }

    #[test]
    fn summaries_do_not_pair_rows_from_different_attempts() {
        let mut caller = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let mut listener = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let set_attempt = |record: &mut Record, value: &str| {
            if let Some((_, attempt)) = record.fields.iter_mut().find(|(key, _)| key == "attempt") {
                *attempt = value.to_string();
            } else {
                record.fields.push(("attempt".into(), value.into()));
            }
        };
        set_attempt(&mut caller, "old");
        set_attempt(&mut listener, "new");

        let summaries = summarize_cells(&[caller, listener]);
        let summary = summaries.values().next().unwrap();
        assert_eq!(summary.pairs, 0);
        assert_eq!(summary.incomplete_reps, 2);
        assert!(!summary.is_clean);
    }

    #[test]
    fn test_check_clean_file_clean_and_unclean() {
        let dir = std::env::temp_dir().join(format!("check_clean_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let clean_path = dir.join("clean.tsv");
        let header = crate::harness::COLUMNS.join("\t");
        let mut c_row = vec![String::new(); crate::harness::COLUMNS.len()];
        let mut l_row = vec![String::new(); crate::harness::COLUMNS.len()];

        let set_field = |row: &mut [String], col: &str, val: &str| {
            if let Some(pos) = crate::harness::COLUMNS.iter().position(|&c| c == col) {
                row[pos] = val.to_string();
            }
        };

        for row in [&mut c_row, &mut l_row] {
            set_field(row, "runtime", "mio");
            set_field(row, "encryption", "plain");
            set_field(row, "ingress", "per-port");
            set_field(row, "egress", "per-connection");
            set_field(row, "promotion", "relocate");
            set_field(row, "cookie", "on");
            set_field(row, "batch", "on");
            set_field(row, "recv_rounds", "8");
            set_field(row, "would_block_policy", "retain");
            set_field(row, "sock_buf_requested_bytes", "16777216");
            set_field(row, "sock_rcvbuf_effective_min_bytes", "2097152");
            set_field(row, "sock_rcvbuf_effective_max_bytes", "2097152");
            set_field(row, "sock_sndbuf_effective_min_bytes", "2097152");
            set_field(row, "sock_sndbuf_effective_max_bytes", "2097152");
            set_field(row, "cpus", "0-3");
            set_field(row, "pin", "off");
            set_field(row, "workers", "1");
            set_field(row, "conns", "10");
            set_field(row, "logical_streams", "10");
            set_field(row, "source_streams", "10");
            set_field(row, "connect_cc", "1");
            set_field(row, "cc_peak", "1");
            set_field(row, "bond", "none");
            set_field(row, "source_bps", "1000000");
            set_field(row, "srt_bw_mode", "input-relative:25");
            set_field(row, "source_backlog_ms", "250");
            set_field(row, "datapath_q_horizon_ms", "250");
            set_field(row, "retry_horizon_ms", "250");
            set_field(row, "rep", "1");
            set_field(row, "secs", "10");
            set_field(row, "attempt", "test-1");
            set_field(row, "established", "10");
            set_field(row, "torn_down", "0");
            set_field(row, "pkt_sent", "9499");
            set_field(row, "core_total", "9499");
            set_field(row, "udp_rcvbuf_err", "0");
            set_field(row, "src_overflow", "0");
            set_field(row, "datapath_q_dropped", "0");
            set_field(row, "local_dropped", "0");
        }
        set_field(&mut c_row, "role", "caller");
        set_field(&mut l_row, "role", "listener");

        let clean_content = format!("{}\n{}\n{}\n", header, c_row.join("\t"), l_row.join("\t"));
        std::fs::write(&clean_path, &clean_content).unwrap();

        let res = check_clean_file(&clean_path);
        assert!(res.is_ok(), "clean file must pass: {:?}", res.err());

        // Now test unclean file (failed establishment)
        let unclean_path = dir.join("unclean.tsv");
        let mut bad_c_row = c_row.clone();
        set_field(&mut bad_c_row, "established", "9");
        let unclean_content = format!(
            "{}\n{}\n{}\n",
            header,
            bad_c_row.join("\t"),
            l_row.join("\t")
        );
        std::fs::write(&unclean_path, &unclean_content).unwrap();
        let bad_res = check_clean_file(&unclean_path);
        assert!(bad_res.is_err(), "unclean file must fail");
        assert!(bad_res.unwrap_err().contains("caller established 9/10"));

        // Incomplete file (missing listener)
        let incomplete_path = dir.join("incomplete.tsv");
        let incomplete_content = format!("{}\n{}\n", header, c_row.join("\t"));
        std::fs::write(&incomplete_path, &incomplete_content).unwrap();
        let inc_res = check_clean_file(&incomplete_path);
        assert!(inc_res.is_err(), "incomplete file must fail");
        assert!(inc_res.unwrap_err().contains("missing listener row"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A two-leg bonded group is two physical connections carrying one
    /// stream from one source. Charging the workload to `conns` doubled
    /// the target, so a source that produced exactly what it was asked
    /// for read as ~50% offered; and requiring `listener_established ==
    /// conns` marked every healthy bonded cell unclean, because a
    /// group-aware listener admits one stream, not two.
    #[test]
    fn a_bonded_cell_is_measured_against_streams_not_physical_legs() {
        // 10 physical legs = 5 bonded groups = 5 sources.
        // Source target: 5 * 125000 * 10 / 1316 = 4749.2 -> 4750 packets.
        let mut caller = make_test_caller(
            "1", "10", "1000000", "10", "4750", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        caller
            .fields
            .push(("logical_streams".to_string(), "5".to_string()));
        caller
            .fields
            .push(("source_streams".to_string(), "5".to_string()));
        let mut listener = make_test_listener(
            "1", "10", "1000000", "10", "4750", "100.0", "100.0", "1000", "0", "0", "0", "5", "0",
        );
        listener
            .fields
            .push(("logical_streams".to_string(), "5".to_string()));

        let metrics = PairMetrics::compute(&caller, &listener).expect("pair metrics");
        assert_eq!(metrics.source_streams, 5.0);
        assert!(
            (metrics.offer_pct - 100.0).abs() < 0.5,
            "a source that produced its full workload must read as ~100%, got {}",
            metrics.offer_pct
        );
        assert!(
            metrics.is_clean(),
            "a healthy bonded cell must be clean: listener admits {} of {} logical streams",
            metrics.listener_established,
            metrics.logical_streams
        );
    }

    /// Absent the bonded columns, the three cardinalities collapse to
    /// `conns` and nothing about an unbonded cell changes.
    #[test]
    fn an_unbonded_cell_still_uses_the_physical_connection_count() {
        let caller = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let listener = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let metrics = PairMetrics::compute(&caller, &listener).expect("pair metrics");
        assert_eq!(metrics.source_streams, 10.0);
        assert_eq!(metrics.logical_streams, 10.0);
        assert!(metrics.is_clean());
    }

    #[test]
    fn datapath_queue_overflow_invalidates_a_clean_pair() {
        let c = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let mut l = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        assert!(PairMetrics::compute(&c, &l).unwrap().is_clean());
        l.fields
            .push(("datapath_q_dropped".to_string(), "1".to_string()));
        assert!(!PairMetrics::compute(&c, &l).unwrap().is_clean());
    }

    #[test]
    fn outbound_retry_loss_invalidates_a_clean_pair() {
        let mut c = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let l = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        assert!(PairMetrics::compute(&c, &l).unwrap().is_clean());
        // A retry overflow is also a local drop, so the total is what the
        // predicate reads.
        c.fields
            .push(("retry_overflow".to_string(), "1".to_string()));
        c.fields
            .push(("local_dropped".to_string(), "1".to_string()));
        let metrics = PairMetrics::compute(&c, &l).unwrap();
        assert!(!metrics.is_clean());
        assert_eq!(
            metrics.outbound_retry_loss, 1.0,
            "`retry_overflow` is a reason inside `local_dropped`, not a second loss to add to it"
        );
    }

    /// Dropping on WouldBlock loses datagrams without any overflow: the
    /// total has to count those too, or a drop policy would look clean.
    #[test]
    fn a_would_block_drop_counts_even_without_overflow() {
        let mut c = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let l = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        c.fields
            .push(("retry_overflow".to_string(), "0".to_string()));
        c.fields
            .push(("local_dropped".to_string(), "7".to_string()));
        let metrics = PairMetrics::compute(&c, &l).unwrap();
        assert_eq!(metrics.outbound_retry_loss, 7.0);
        assert!(!metrics.is_clean());
    }

    #[test]
    fn test_cell_level_all_reps_required_for_clean() {
        let records = vec![
            make_test_caller(
                "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            make_test_listener(
                "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            make_test_caller(
                "2", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            make_test_listener(
                "2", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            make_test_caller(
                "3", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            make_test_listener(
                "3", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            make_test_caller(
                "4", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            make_test_listener(
                "4", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            // Rep 5 has 1 UDP drop:
            make_test_caller(
                "5", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "0",
            ),
            make_test_listener(
                "5", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10",
                "1",
            ),
        ];

        let summaries = summarize_cells(&records);
        assert_eq!(summaries.len(), 1);
        let summary = summaries.values().next().unwrap();
        assert_eq!(summary.pairs, 5);
        assert_eq!(summary.listener_udp_rcvbuf_err.median, 0.0); // Median is 0!
        assert!(
            !summary.is_clean,
            "One failed repetition out of five must invalidate cell cleanliness"
        );
    }

    #[test]
    fn test_pairing_and_config_isolation() {
        let mut r1 = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        r1.fields.retain(|(k, _)| k != "pin");
        r1.fields.push(("pin".to_string(), "off".to_string()));

        let mut r2 = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        r2.fields.retain(|(k, _)| k != "pin");
        r2.fields.push(("pin".to_string(), "on".to_string()));

        let l1 = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );

        let records = vec![r1, r2, l1];
        let summaries = summarize_cells(&records);
        assert_eq!(
            summaries.len(),
            2,
            "Cells differing in pin must be distinct"
        );
    }

    #[test]
    fn test_spread_overlap_and_capacity_frontier() {
        let s1 = Spread {
            n: 5,
            median: 100.0,
            min: 90.0,
            max: 110.0,
        };
        let s2_overlapping = Spread {
            n: 5,
            median: 105.0,
            min: 95.0,
            max: 115.0,
        };
        let s3_non_overlapping = Spread {
            n: 5,
            median: 130.0,
            min: 120.0,
            max: 140.0,
        };

        assert!(s1.overlaps(s2_overlapping));
        assert!(!s1.overlaps(s3_non_overlapping));

        // Capacity frontier selection
        let mut summaries = BTreeMap::new();
        // Cell 1: 10c x 1M = 10 Mbps, clean
        let c1 = make_test_caller(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        let l1 = make_test_listener(
            "1", "10", "1000000", "10", "9499", "100.0", "100.0", "1000", "0", "0", "0", "10", "0",
        );
        summaries.extend(summarize_cells(&[c1, l1]));

        // Cell 2: 100c x 8M = 800 Mbps, but has a torn connection -> NOT clean
        let c2 = make_test_caller(
            "1", "100", "8000000", "10", "75000", "100.0", "100.0", "1000", "0", "0", "1", "100",
            "0",
        );
        let l2 = make_test_listener(
            "1", "100", "8000000", "10", "75000", "100.0", "100.0", "1000", "0", "0", "1", "100",
            "0",
        );
        summaries.extend(summarize_cells(&[c2, l2]));

        let frontier = calculate_capacity_frontier(&summaries).expect("frontier found");
        assert_eq!(
            frontier.conns * frontier.source_bps,
            10_000_000.0,
            "Only strict clean cells qualify for capacity frontier"
        );
    }
}
