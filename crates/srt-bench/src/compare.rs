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
    pub conns: f64,
    /// Source payload rate in bits per second (the `source_bps` column).
    pub source_bps: f64,
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

        let caller_established = caller.number("established").unwrap_or(0.0);
        let listener_established = listener.number("established").unwrap_or(0.0);
        let torn_c = caller.number("torn_down").unwrap_or(0.0);
        let torn_l = listener.number("torn_down").unwrap_or(0.0);

        let sent_pkts = caller.number("core_total").unwrap_or(0.0);
        let recv_pkts = listener.number("core_total").unwrap_or(0.0);

        // The target is what the APPLICATION SOURCE asked for, so the
        // denominator is the payload size. It used to be the wire size
        // (payload + SRT header), which is SRTO_MAXBW's unit -- so "did
        // the sender offer its load?" was measured against the pacing
        // ceiling that produced the load, and could not fail. A cell
        // whose MAXBW cannot carry its source rate now visibly falls
        // short here, which is the point.
        let target_pkts = (conns * (source_bps / 8.0) * secs) / PAYLOAD_SIZE as f64;
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

        Some(Self {
            conns,
            source_bps,
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
    pub fn is_clean(&self) -> bool {
        self.conns > 0.0
            && self.caller_established == self.conns
            && self.listener_established == self.conns
            && self.torn_c == 0.0
            && self.torn_l == 0.0
            && self.offer_pct >= 99.0
            && self.good_pct >= 99.0
            && self.deliv_pct >= 99.9
            && self.caller_udp_rcvbuf_err == 0.0
            && self.listener_udp_rcvbuf_err == 0.0
            && self.source_overflow == 0.0
            && self.datapath_queue_overflow == 0.0
    }
}

/// Aggregated summary with measurement spreads across repetitions for a cell.
#[derive(Clone, Debug)]
pub struct CellSummary {
    pub key: String,
    pub pairs: usize,
    pub incomplete_reps: usize,
    pub conns: f64,
    /// Source payload rate in bits per second (the `source_bps` column).
    pub source_bps: f64,
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
        let rep = r.get("rep").unwrap_or("1").to_string();
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
    CellSummary {
        key,
        pairs: 0,
        incomplete_reps,
        conns,
        source_bps,
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
        if let Some(val) = r.get(col) {
            parts.push(format!("{col}={val}"));
        }
    }
    parts.join(" ")
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

/// Finds the highest clean aggregate configured bandwidth (connections * configured bitrate)
/// strictly among cells where all repetitions passed `is_clean`.
pub fn calculate_capacity_frontier<'a>(
    summaries: &'a BTreeMap<String, CellSummary>,
) -> Option<&'a CellSummary> {
    let mut best: Option<&'a CellSummary> = None;
    let mut max_rate = 0.0;

    for s in summaries.values() {
        if s.is_clean {
            let agg_bps = s.conns * s.source_bps;
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
            let payload_ratio = PAYLOAD_SIZE as f64 / (PAYLOAD_SIZE + shiguredo_srt::SRT_HEADER_SIZE) as f64;
            let achieved_payload_gbps = (s.good_pct.median / 100.0) * (s.conns * s.source_bps / 1e9) * payload_ratio;
            format!(
                "{} (configured MAXBW: {:.3} Gbit/s, payload: {:.3} Gbit/s, offer: {:.1}%, good: {:.1}%)",
                format_short_cell_label(&s.key),
                s.conns * s.source_bps / 1e9,
                achieved_payload_gbps,
                s.offer_pct.median,
                s.good_pct.median
            )
        })
        .unwrap_or_else(|| "none (no cell met strict >=99% offer/good across all repetitions)".into())
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
        "Clean capacity criteria: `caller_established == conns`, `listener_established == conns`, `torn == 0`, `offer >= 99.0%`, `goodput >= 99.0%`, `deliv >= 99.9%`, and `udp_rcvbuf_err == 0` (both caller and listener) across **all** repetitions."
    )
    .unwrap();
    writeln!(
        out,
        "Source target is the application workload, not SRT's pacing ceiling: \
         `target = conns × (source_bps ÷ 8) × secs ÷ 1316`. SRT's own ceiling is \
         recorded separately as `srt_maxbw_bps`."
    )
    .unwrap();
    writeln!(out).unwrap();

    let base_maxbw = base_frontier.map(|s| s.conns * s.source_bps).unwrap_or(0.0);
    let head_maxbw = head_frontier.map(|s| s.conns * s.source_bps).unwrap_or(0.0);
    let delta = delta_pct(base_maxbw, head_maxbw);

    let base_label = format_frontier_label(base_frontier);
    let head_label = format_frontier_label(head_frontier);

    writeln!(out, "| Metric | Pre-DSA Baseline | Post-DSA HEAD | Delta |").unwrap();
    writeln!(out, "|---|---|---|---|").unwrap();
    writeln!(
        out,
        "| **Max Clean Aggregate Rate** | **{:.3} Gbit/s** ({}) | **{:.3} Gbit/s** ({}) | **{:+.1}%** |",
        base_maxbw / 1e9,
        base_label,
        head_maxbw / 1e9,
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

    let base_maxbw = base_frontier.map(|s| s.conns * s.source_bps).unwrap_or(0.0);
    let head_maxbw = head_frontier.map(|s| s.conns * s.source_bps).unwrap_or(0.0);
    let delta = delta_pct(base_maxbw, head_maxbw);

    writeln!(
        out,
        "--- Capacity Frontier (Strict All-Rep Clean Criteria) ---"
    )
    .unwrap();
    writeln!(
        out,
        "Max Clean Aggregate Rate: {:.3} Gbit/s -> {:.3} Gbit/s ({:+.1}%)",
        base_maxbw / 1e9,
        head_maxbw / 1e9,
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
                ("sock_buf".to_string(), "16m".to_string()),
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
                ("sock_buf".to_string(), "16m".to_string()),
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
