//! `cargo xtask qualify` -- apply the sustained-capacity gate to a sweep file.
//!
//! PR #117 established a *burst* result and explicitly recorded sustained
//! capacity as unqualified, because several committed rows looked like capacity
//! evidence and were not. The gate that distinguishes them was written in prose
//! in `docs/results/scaling-to-1000.md` and applied by hand. Prose gates decay;
//! this one is executable, so "does this row count?" has one answer.
//!
//! A row is capacity evidence only if **all** of these hold, simultaneously:
//!
//! * `generated_ticks / expected_ticks` >= the tolerance (default 0.999);
//! * `data_accepted == rx_core_total` -- every accepted payload was delivered;
//! * `data_zero == 0` and `data_below_half_mean == 0` -- no starved destination
//!   and no slow subset;
//! * `sec_a == 0` -- no reported loss;
//! * `drain_ok == true` and `pending_after_drain == 0` -- equilibrium reached;
//! * `window_cpu_ms > 0` and `cpu_ms > 0` -- the CPU accounting is real.
//!
//! Necessary-but-insufficient conditions are deliberately *not* part of the
//! gate, because treating them as if they were is the mistake this exists to
//! prevent: `drain_ok` alone makes a *cost* denominator conserved and says
//! nothing about whether the offer was held.
//!
//! Usage:
//!
//! Two verdicts come out of it, because they are different claims:
//!
//! * **throughput** -- the gate above. The bounded catch-up source replays
//!   wall-clock boundaries after `service()` returns, so this is capacity with a
//!   bounded external backlog, not proof that every source event was serviced on
//!   time.
//! * **real-time** -- throughput *and* `p99`/`max` lateness within a budget
//!   declared with `--lateness-budget-us`. Without a declared budget no
//!   real-time verdict is given, rather than implying one.
//!
//! ```text
//! cargo xtask qualify docs/results/scaling-1000/scale-N1000-S5-2reps.tsv
//! cargo xtask qualify --tolerance 0.999 --lateness-budget-us 5000 fence.tsv
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Column names a field can appear under.
///
/// `cargo xtask scaling` prefixes every receiver field with `rx_`, while the
/// sender's own fields are unprefixed, so the gate has to accept both spellings
/// or it fails rows for a naming convention rather than for a measurement.
const ALIASES: &[(&str, &[&str])] = &[
    ("data_zero", &["data_zero", "rx_data_zero"]),
    (
        "data_below_half_mean",
        &["data_below_half_mean", "rx_data_below_half_mean"],
    ),
    ("sec_a", &["sec_a", "rx_sec_a"]),
    ("rx_core_total", &["rx_core_total", "core_total"]),
];

fn field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Option<&'a String> {
    if let Some(value) = fields.get(key) {
        return Some(value);
    }
    let names = ALIASES
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, names)| *names)?;
    names.iter().find_map(|name| fields.get(*name))
}

fn number(fields: &BTreeMap<String, String>, key: &str) -> Result<f64, String> {
    let raw = field(fields, key).ok_or_else(|| format!("missing {key}"))?;
    raw.parse::<f64>()
        .map_err(|_| format!("{key}={raw:?} does not parse"))
}

/// The offer was held, not merely made.
fn cadence_failures(fields: &BTreeMap<String, String>, tolerance: f64) -> Vec<String> {
    match (
        number(fields, "expected_ticks"),
        number(fields, "generated_ticks"),
    ) {
        (Ok(expected), Ok(generated)) if expected > 0.0 => {
            let ratio = generated / expected;
            if ratio < tolerance {
                vec![format!(
                    "cadence {ratio:.4} < {tolerance:.4} (generated {generated:.0} of {expected:.0})"
                )]
            } else {
                Vec::new()
            }
        }
        (Ok(expected), Ok(_)) => vec![format!("expected_ticks={expected:.0} is not positive")],
        (Err(e), _) | (_, Err(e)) => vec![e],
    }
}

/// Accepted is not delivered.
fn delivery_failures(fields: &BTreeMap<String, String>) -> Vec<String> {
    // The terminal fence offers extra payloads AFTER the measured window, and
    // the receiver counts them: `rx_core_total` therefore contains
    // `fence_accepted` payloads that are not part of the measured workload (the
    // harness excludes them from `data_accepted`, `data_offered` and every rate,
    // and they are a different size and pattern). Naming them here keeps the
    // identity strict instead of leaving the reader to subtract them by hand --
    // and a canonical run with the fence enabled is exactly the run this gate is
    // for.
    // The receiver's own count of fence payloads, not the sender's: the identity
    // being checked is what the receiver accounted for, and using the sender's
    // number would silently assume the fence itself was lossless -- which is a
    // diagnostic fact, not a workload one, and is reported separately.
    let fence = number(fields, "rx_diag_fences_seen")
        .or_else(|_| number(fields, "fence_accepted"))
        .unwrap_or(0.0);
    match (
        number(fields, "data_accepted"),
        number(fields, "rx_core_total"),
    ) {
        (Ok(accepted), Ok(received)) if accepted + fence != received => vec![format!(
            "data_accepted {accepted:.0} + fence seen {fence:.0} != rx_core_total \
             {received:.0} ({} % of accepted delivered, fence excluded)",
            100.0 * (received - fence) / accepted.max(1.0)
        )],
        (Err(e), _) | (_, Err(e)) => vec![e],
        _ => Vec::new(),
    }
}

/// Fields that must be exactly zero, each named with the value it held.
fn zero_failures(fields: &BTreeMap<String, String>, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| match number(fields, key) {
            Ok(0.0) => None,
            Ok(v) => Some(format!("{key}={v:.0} (must be 0)")),
            Err(e) => Some(e),
        })
        .collect()
}

/// Equilibrium: the run finished rather than merely stopped.
fn equilibrium_failures(fields: &BTreeMap<String, String>) -> Vec<String> {
    let mut failures = Vec::new();
    if fields.get("drain_ok").map(String::as_str) != Some("true") {
        failures.push(format!(
            "drain_ok={:?} (must be true)",
            fields.get("drain_ok").cloned().unwrap_or_default()
        ));
    }
    match number(fields, "pending_after_drain") {
        Ok(0.0) => {}
        Ok(v) => failures.push(format!("pending_after_drain={v:.0} (must be 0)")),
        Err(e) => failures.push(e),
    }
    failures
}

/// Real CPU accounting: a stale zero is the bug #117 shipped once.
fn cpu_failures(fields: &BTreeMap<String, String>) -> Vec<String> {
    ["window_cpu_ms", "cpu_ms"]
        .iter()
        .filter_map(|key| match number(fields, key) {
            Ok(v) if v > 0.0 => None,
            Ok(v) => Some(format!("{key}={v} is not positive")),
            Err(e) => Some(e),
        })
        .collect()
}

/// A verdict for one thresholded property.
///
/// "No threshold declared" is not a pass. Treating it as one is how a row gets
/// summarised as sustained (or real-time) while the summary text says no such
/// verdict was given -- a contradiction that would have quietly promoted every
/// row to the strongest claim the moment a flag was forgotten.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Undeclared,
    Pass,
    Fail(Vec<String>),
}

impl Verdict {
    pub fn passed(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    fn label(&self) -> &'static str {
        match self {
            Verdict::Undeclared => "undeclared",
            Verdict::Pass => "pass",
            Verdict::Fail(_) => "fail",
        }
    }

    fn reasons(&self) -> String {
        match self {
            Verdict::Fail(r) => r.join("; "),
            _ => String::new(),
        }
    }
}

/// Stationarity: did service keep pace with arrival during the source window?
///
/// Conservation across the whole experiment is not capacity. A run can offer at
/// full cadence, accept everything into protocol queues, fail to transmit at that
/// cadence, and then drain the backlog for seconds after the source stops -- with
/// every accepted payload eventually delivered. That is admission plus eventual
/// drain, and it passes every check built before this one.
///
/// The executable form is the share of wire work that happened after the source
/// stopped:
///
/// ```text
/// f_drain = drain_submitted / (tx_submitted_wire + drain_submitted)
/// ```
///
/// A run that keeps pace has essentially none. The threshold is *declared*
/// (`--drain-fraction-max`) rather than hardcoded, because the natural tail has
/// to be measured on unquestionably underloaded configurations first: F=50 at
/// 8 Mbps measures 0.0 %, while every other configuration currently measured
/// sits at 40-76 %.
fn stationarity(fields: &BTreeMap<String, String>, max_fraction: Option<f64>) -> Verdict {
    let Some(max) = max_fraction else {
        return Verdict::Undeclared;
    };
    let (window, drain) = match (
        wire_count(fields, "tx_submitted_wire"),
        wire_count(fields, "drain_submitted"),
    ) {
        (Ok(w), Ok(d)) => (w, d),
        (Err(e), _) | (_, Err(e)) => return Verdict::Fail(vec![e]),
    };
    let fraction = match drain_fraction(fields) {
        Ok(f) => f,
        Err(e) => return Verdict::Fail(vec![e]),
    };
    if fraction <= max {
        Verdict::Pass
    } else {
        Verdict::Fail(vec![format!(
            "f_drain={:.1} % > declared {:.1} %: {drain:.0} of {:.0} wire datagrams were \
             submitted after the source stopped, so service did not keep pace",
            100.0 * fraction,
            100.0 * max,
            window + drain,
        )])
    }
}

/// A wire-traffic count, required to be present and finite.
///
/// These used to default to `0.0`, which turned malformed evidence into the
/// strongest possible result: a missing `drain_submitted` beside a valid window
/// is `f_drain = 0`, i.e. a perfectly stationary run. A missing field is
/// missing, not zero.
fn wire_count(fields: &BTreeMap<String, String>, key: &str) -> Result<f64, String> {
    let value = number(fields, key)?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("{key}={value} is not a non-negative finite count"));
    }
    Ok(value)
}

/// The post-window share of wire work, as a ratio.
pub fn drain_fraction(fields: &BTreeMap<String, String>) -> Result<f64, String> {
    let window = wire_count(fields, "tx_submitted_wire")?;
    let drain = wire_count(fields, "drain_submitted")?;
    if window + drain <= 0.0 {
        return Err("no wire traffic recorded".to_string());
    }
    Ok(drain / (window + drain))
}

/// Lateness of a row against a declared budget, if one was declared.
///
/// Throughput and real-time are different claims. The bounded catch-up source
/// replays wall-clock boundaries after `service()` returns, which is a valid way
/// to measure *throughput* capacity with a bounded external backlog, and is not
/// the same as proving the dataplane serviced each source event on time. A row
/// can therefore pass throughput while being far outside any latency budget --
/// F=100 at 8 Mbps does exactly that, at ~28 ms p99 -- and an optimization that
/// accumulates work and services it later would otherwise look like a win.
///
/// Gated on `first_submit_lateness_us_{p99,max}`, not `offer_lateness_us_*`:
/// `offer_lateness` is sampled before `service()` is even entered, so it is
/// source punctuality, not dataplane behaviour, and cannot by itself support a
/// claim about whether the transport serviced anything on time. Gating a
/// verdict named "real-time" on it would let the stronger claim ride on the
/// weaker measurement. `first_submit_lateness` spans admission, drain, pacing
/// and pool/lane reservation through to wire handoff -- the whole path this
/// verdict is actually supposed to speak to.
fn lateness(fields: &BTreeMap<String, String>, budget_us: Option<f64>) -> Verdict {
    let Some(budget) = budget_us else {
        return Verdict::Undeclared;
    };
    let failures: Vec<String> = [
        "first_submit_lateness_us_p99",
        "first_submit_lateness_us_max",
    ]
    .iter()
    .filter_map(|key| match number(fields, key) {
        Ok(v) if v <= budget => None,
        Ok(v) => Some(format!("{key}={v:.0}us > budget {budget:.0}us")),
        Err(e) => Some(e),
    })
    .collect();
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

/// The TX submission classes a canonical row must decompose into.
///
/// The names are the row's own field names, so a missing one is a missing
/// measurement rather than a zero.
pub const TX_CLASS_KEYS: &[&str] = &[
    "tx_class_data_first",
    "tx_class_data_retx",
    "tx_class_ack",
    "tx_class_ackack",
    "tx_class_nak",
    "tx_class_keepalive",
    "tx_class_handshake",
    "tx_class_dropreq",
    "tx_class_km",
    "tx_class_shutdown",
    "tx_class_other_control",
];

/// A non-negative integer count, required to be present and well formed.
///
/// Counts are compared for exact equality, so they are parsed as integers
/// rather than floats: `465000.0 == 465000` would hide a truncation, and a
/// negative or non-numeric value is malformed evidence, never zero.
fn count(fields: &BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    let raw = field(fields, key).ok_or_else(|| format!("missing {key}"))?;
    raw.parse::<u64>()
        .map_err(|_| format!("{key}={raw:?} is not a non-negative integer count"))
}

/// TX submission accounting must be decomposable and closed.
///
/// `tx_submitted_wire` on its own cannot distinguish a dataplane that sent the
/// media from one that spent its submission capacity on control traffic, and a
/// total that does not equal the sum of its parts is an accounting defect: every
/// per-class number derived from it would be wrong without saying so. Two
/// identities are therefore required exactly, not approximately:
///
/// ```text
/// sum(tx_class_*) == tx_class_total == tx_submitted_wire
/// ```
///
/// The first-transmission lateness fields are required to be present as well --
/// a row without them cannot support the real-time claim they exist for -- but
/// no threshold is applied to them here, because this project has not declared
/// one.
fn tx_class_failures(fields: &BTreeMap<String, String>) -> Vec<String> {
    let mut failures = Vec::new();
    let mut sum: u64 = 0;
    for key in TX_CLASS_KEYS {
        match count(fields, key) {
            Ok(value) => sum = sum.saturating_add(value),
            Err(error) => failures.push(error),
        }
    }
    for key in [
        "first_submit_lateness_us_p50",
        "first_submit_lateness_us_p99",
        "first_submit_lateness_us_max",
        "first_submit_lateness_samples",
    ] {
        if let Err(error) = count(fields, key) {
            failures.push(error);
        }
    }
    // "No send failed" has to be a recorded fact, not an absent field: these
    // counters were printed by the harness but never captured, so a row could
    // neither support nor refute the claim.
    for key in ["short", "failed", "peer_local", "transient"] {
        match count(fields, key) {
            Ok(0) => {}
            Ok(value) => failures.push(format!("{key}={value} (must be 0)")),
            Err(error) => failures.push(error),
        }
    }
    if !failures.is_empty() {
        return failures;
    }

    match count(fields, "tx_class_total") {
        Ok(total) if total == sum => {}
        Ok(total) => failures.push(format!(
            "tx_class_total={total} != sum(tx_class_*)={sum}: the submission partition \
             does not close"
        )),
        Err(error) => failures.push(error),
    }
    match (
        count(fields, "tx_submitted_wire"),
        count(fields, "tx_class_total"),
    ) {
        (Ok(wire), Ok(total)) if wire == total => {}
        (Ok(wire), Ok(total)) => failures.push(format!(
            "tx_class_total={total} != tx_submitted_wire={wire}: classified submissions \
             must account for every submission"
        )),
        _ => {}
    }
    failures
}

/// A fence-enabled run's missing-final count against what the source itself
/// explains, not zero.
///
/// A tick the source never offered (`missed_source_ticks > 0`, e.g. a
/// scheduler hiccup) is missing at every established peer, contributing
/// `missed_source_ticks * rx_established` to `rx_diag_missing_final` -- and
/// that is not transport loss, it is the source's own declared cadence
/// shortfall, already accounted for by the separately declared `--tolerance`
/// (default 0.999). Requiring `rx_diag_missing_final == 0` outright silently
/// turns the fence criterion into "source cadence must be exactly 100%",
/// contradicting that tolerance: sweep A's own A1 row measures
/// `missing_final=750` (`15 missed_source_ticks x 50 rx_established`) while
/// passing cadence at 0.999671. The gate below requires exact equality with
/// what the source-stall accounting predicts, so the tolerated shortfall is
/// exactly explained -- and any further discrepancy, `unexpected_transport_missing
/// = rx_diag_missing_final - expected_source_missing`, is real transport loss.
fn unexpected_missing_final_failures(fields: &BTreeMap<String, String>) -> Vec<String> {
    let missed_source_ticks = match count(fields, "missed_source_ticks") {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    let rx_established = match count(fields, "rx_established") {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    let missing_final = match count(fields, "rx_diag_missing_final") {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    let expected = missed_source_ticks.saturating_mul(rx_established);
    if missing_final == expected {
        return Vec::new();
    }
    let unexpected = missing_final as i128 - expected as i128;
    vec![format!(
        "rx_diag_missing_final={missing_final} != expected_source_missing={expected} \
         ({missed_source_ticks} missed_source_ticks x {rx_established} rx_established): \
         unexpected_transport_missing={unexpected} (must be 0)"
    )]
}

/// Fence-conservation gate for a fence-enabled canonical run.
///
/// `delivery_failures` already folds `rx_diag_fences_seen` (or, failing that,
/// the sender's own `fence_accepted`) into `data_accepted + fence ==
/// rx_core_total`. That fallback to the sender's own count is exactly the
/// optimistic accounting this project's qualification work found unsafe: it
/// assumes the fence itself was lossless rather than checking it. This gate
/// makes every terminal-state fact a fence-enabled run is supposed to close
/// an explicit, required pass/fail, rather than an assumption folded into one
/// identity check:
///
/// ```text
/// fence_offered == fanout
/// fence_accepted == fanout
/// rx_diag_fences_seen == fanout
/// rx_diag_missing_final == missed_source_ticks * rx_established
/// tx_failures_pending == 0
/// rx_lost == 0
/// rx_diag_duplicate_payloads == 0
/// ```
///
/// `rx_duplicates` (packet-level, ARQ-visible) is deliberately not required to
/// be zero: a duplicate packet is what a successful repair looks like from the
/// receiver's side. The documented rule this gate owns is narrower and about
/// application identity, not the wire: protocol-level duplicates are accounted
/// by recovery traffic, so only `rx_diag_duplicate_payloads` -- payloads
/// actually delivered twice -- must be exactly zero.
///
/// Only applied when `--require-fence` declares that this evidence is
/// expected to carry a terminal fence; undeclared is not a pass, by the same
/// convention every other declared threshold in this gate follows.
fn fence_failures(fields: &BTreeMap<String, String>) -> Vec<String> {
    let fanout = match number(fields, "fanout") {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    let mut failures = Vec::new();
    for key in ["fence_offered", "fence_accepted", "rx_diag_fences_seen"] {
        match number(fields, key) {
            Ok(v) if v == fanout => {}
            Ok(v) => failures.push(format!("{key}={v:.0} != fanout={fanout:.0}")),
            Err(e) => failures.push(e),
        }
    }
    failures.extend(unexpected_missing_final_failures(fields));
    failures.extend(zero_failures(fields, &["tx_failures_pending", "rx_lost"]));
    match number(fields, "rx_diag_duplicate_payloads") {
        Ok(0.0) => {}
        Ok(v) => failures.push(format!(
            "rx_diag_duplicate_payloads={v:.0} (must be 0): protocol-level duplicates \
             (rx_duplicates) are accounted by recovery traffic, but application identity \
             must report no duplicate payload delivery"
        )),
        Err(e) => failures.push(e),
    }
    failures
}

/// Apply the gate to one row, returning every reason it fails.
fn judge(
    fields: &BTreeMap<String, String>,
    tick_tolerance: f64,
    require_fence: bool,
    require_clean: bool,
) -> Vec<String> {
    let mut failures = cadence_failures(fields, tick_tolerance);
    failures.extend(delivery_failures(fields));
    failures.extend(zero_failures(
        fields,
        &["data_zero", "data_below_half_mean", "sec_a"],
    ));
    failures.extend(equilibrium_failures(fields));
    failures.extend(cpu_failures(fields));
    failures.extend(tx_class_failures(fields));
    if require_fence {
        failures.extend(fence_failures(fields));
    }
    if require_clean {
        failures.extend(clean_provenance_failures(fields));
    }
    failures
}

/// Provenance gate for a canonical qualification artifact: a dirty working
/// tree, or a measurement window that started before connection-setup
/// residue (admission backlog, in-flight handshake/keepalive traffic) had
/// actually drained, cannot support the claim that this row is trustworthy
/// evidence for the source it names.
///
/// Only applied when `--require-clean` declares that this evidence is meant
/// to be canonical; undeclared is not a pass, by the same convention every
/// other declared threshold in this gate follows.
fn clean_provenance_failures(fields: &BTreeMap<String, String>) -> Vec<String> {
    let mut failures = Vec::new();
    match field(fields, "git_dirty").map(String::as_str) {
        Some("false") => {}
        Some(other) => failures.push(format!("git_dirty={other:?} (must be \"false\")")),
        None => failures.push("missing git_dirty".to_string()),
    }
    match field(fields, "pre_window_drained").map(String::as_str) {
        Some("true") => {}
        Some(other) => failures.push(format!("pre_window_drained={other:?} (must be \"true\")")),
        None => failures.push("missing pre_window_drained".to_string()),
    }
    failures
}

/// Minimum repetitions a `(fanout, rate, tx_lanes, payload size, RX mode)`
/// point must have before it can qualify at all.
///
/// A `1/3` or `2/3` file is not weaker evidence of the same claim -- it is not
/// evidence for the claim, because the claim is about a *repeatable* point,
/// and a repetition that failed is exactly the outcome the repetitions exist
/// to catch. Sweep A is intentionally `2/3` for this reason: this constant is
/// what makes `qualify` refuse to call it qualified.
const MIN_QUALIFICATION_REPS: usize = 3;

/// The identity a row's qualification counts against: two rows are
/// repetitions of the *same point* only if all seven of these match.
///
/// `window_ms` and `git_sha` matter as much as the workload shape: `qualify`
/// combines rows across every input file, so without them three rows from
/// different measurement durations, or from different source revisions
/// entirely, could combine into a synthetic "3/3" that is not evidence for
/// one experiment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct QualificationIdentity {
    fanout: String,
    rate: String,
    tx_lanes: String,
    payload_size: String,
    rx_mode: String,
    window_ms: String,
    git_sha: String,
}

impl std::fmt::Display for QualificationIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "F={} rate={} K={} payload={} rx_mode={} window_ms={} git_sha={}",
            self.fanout,
            self.rate,
            self.tx_lanes,
            self.payload_size,
            self.rx_mode,
            self.window_ms,
            self.git_sha
        )
    }
}

fn identity(fields: &BTreeMap<String, String>) -> Result<QualificationIdentity, String> {
    let get = |key: &str| -> Result<String, String> {
        field(fields, key)
            .cloned()
            .ok_or_else(|| format!("missing {key}"))
    };
    Ok(QualificationIdentity {
        fanout: get("fanout")?,
        rate: get("offered_bps_per_dest")?,
        tx_lanes: get("tx_lanes")?,
        payload_size: get("payload_bytes")?,
        rx_mode: get("rx_mode")?,
        window_ms: get("window_ms")?,
        git_sha: get("git_sha")?,
    })
}

/// One `(fanout, rate, tx_lanes, payload size, RX mode)` point: how many
/// repetitions were judged, and how many of those were fully sustained.
#[derive(Debug)]
struct QualifiedPoint {
    identity: QualificationIdentity,
    rows: usize,
    sustained: usize,
}

impl QualifiedPoint {
    /// A point qualifies only when every required repetition, with at least
    /// [`MIN_QUALIFICATION_REPS`] repetitions, passes. `rows > sustained` is a
    /// failed repetition, not a partial success; `rows < MIN_QUALIFICATION_REPS`
    /// is insufficient evidence regardless of whether the reps that exist
    /// passed.
    fn qualifies(&self) -> bool {
        self.rows >= MIN_QUALIFICATION_REPS && self.sustained == self.rows
    }
}

/// Group every row by its qualification identity and apply the repetition
/// rule to each group.
///
/// `sustained_rows` marks, by index into `rows`, which rows are individually
/// sustained (passed [`judge`] and [`stationarity`]) -- computed by the caller
/// so this function stays a pure grouping/counting step or a caller can label
/// the group; malformed identity fields (a row missing one of the five
/// identity dimensions) are reported as an error rather than silently
/// dropping the row from every group.
fn group_by_identity(
    rows: &[BTreeMap<String, String>],
    sustained_rows: &[bool],
) -> Result<Vec<QualifiedPoint>, String> {
    let mut groups: BTreeMap<QualificationIdentity, (usize, usize)> = BTreeMap::new();
    for (fields, &sustained) in rows.iter().zip(sustained_rows) {
        let id = identity(fields)?;
        let entry = groups.entry(id).or_insert((0, 0));
        entry.0 += 1;
        if sustained {
            entry.1 += 1;
        }
    }
    Ok(groups
        .into_iter()
        .map(|(identity, (rows, sustained))| QualifiedPoint {
            identity,
            rows,
            sustained,
        })
        .collect())
}

/// `(tolerance, paths)` from the command line.
/// Command-line inputs: two declared thresholds and the files to judge.
struct Args {
    tolerance: f64,
    lateness_budget_us: Option<f64>,
    drain_fraction_max: Option<f64>,
    require_fence: bool,
    require_clean: bool,
    paths: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut tolerance = 0.999;
    let mut budget: Option<f64> = None;
    let mut drain_max: Option<f64> = None;
    let mut require_fence = false;
    let mut require_clean = false;
    let mut paths = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tolerance" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--tolerance needs a value".to_string())?;
                tolerance = value
                    .parse()
                    .map_err(|_| format!("--tolerance does not parse: {value:?}"))?;
                i += 2;
            }
            "--drain-fraction-max" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--drain-fraction-max needs a value".to_string())?;
                drain_max = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--drain-fraction-max does not parse: {value:?}"))?,
                );
                i += 2;
            }
            "--lateness-budget-us" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--lateness-budget-us needs a value".to_string())?;
                budget = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--lateness-budget-us does not parse: {value:?}"))?,
                );
                i += 2;
            }
            "--require-fence" => {
                require_fence = true;
                i += 1;
            }
            "--require-clean" => {
                require_clean = true;
                i += 1;
            }
            other => {
                paths.push(other.to_string());
                i += 1;
            }
        }
    }
    if let Some(max) = drain_max
        && !(0.0..=1.0).contains(&max)
    {
        return Err(format!(
            "--drain-fraction-max must be a fraction in 0..=1, got {max}"
        ));
    }
    if paths.is_empty() {
        return Err(
            "usage: cargo xtask qualify <sweep.tsv> [--tolerance 0.999] \
             [--lateness-budget-us N] [--drain-fraction-max F] [--require-fence] \
             [--require-clean]"
                .to_string(),
        );
    }
    Ok(Args {
        tolerance,
        lateness_budget_us: budget,
        drain_fraction_max: drain_max,
        require_fence,
        require_clean,
        paths,
    })
}

/// One `key=value` token from the sweep's own `# scaling-sweep ...` /
/// `# reps=...` header comment lines.
///
/// Unlike `fanout`, `payload_bytes`, `offered_bps_per_dest` and `rx_mode`,
/// run-shape arguments like `tx_lanes`, `window_ms`, `git_sha` and
/// `git_dirty` are never echoed on a `ROW` line -- they are constant for the
/// whole file, not a per-row measurement. Reading them from the header is the
/// only way a row's qualification identity, or a provenance gate, can use
/// them at all.
fn header_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    text.lines()
        .filter(|line| line.starts_with('#'))
        .find_map(|line| {
            line.split_whitespace()
                .find_map(|token| token.strip_prefix(prefix.as_str()))
        })
}

/// Header run-shape values injected into every row (see [`header_value`]).
const HEADER_INJECTED_KEYS: &[&str] = &["tx_lanes", "window_ms", "git_sha", "git_dirty"];

/// ROW lines as field maps, keyed by the file's own header.
///
/// [`HEADER_INJECTED_KEYS`] are injected from the file's header comment into
/// every row that does not already carry them, so identity grouping
/// ([`identity`]) and provenance gates (`--require-clean`) can use them
/// without every row having to repeat a run-shape constant.
fn load_rows(text: &str) -> Vec<BTreeMap<String, String>> {
    let header: Vec<String> = text
        .lines()
        .find(|h| h.starts_with("kind\t"))
        .map(|h| h.split('\t').map(str::to_string).collect())
        .unwrap_or_default();
    let injected: Vec<(&str, Option<&str>)> = HEADER_INJECTED_KEYS
        .iter()
        .map(|&key| (key, header_value(text, key)))
        .collect();
    text.lines()
        .filter(|l| l.starts_with("ROW\t"))
        .map(|l| {
            let mut fields: BTreeMap<String, String> = l
                .split('\t')
                .enumerate()
                .filter_map(|(i, v)| header.get(i).map(|k| (k.clone(), v.to_string())))
                .collect();
            for (key, value) in &injected {
                if let Some(value) = value {
                    fields
                        .entry((*key).to_string())
                        .or_insert_with(|| (*value).to_string());
                }
            }
            fields
        })
        .collect()
}

/// Totals from judging every row of one file, plus the raw rows and their
/// per-row sustained/real-time flags so [`run`] can group across every
/// file's rows by qualification identity.
struct ReportOutcome {
    rows: Vec<BTreeMap<String, String>>,
    /// Parallel to `rows`: whether each row individually passed [`judge`] and
    /// [`stationarity`] (a per-row fact, not yet the repetition rule).
    sustained_rows: Vec<bool>,
    /// Parallel to `rows`: whether each row is sustained *and* meets the
    /// declared lateness budget. The real-time verdict must not carry weaker
    /// repetition semantics than the sustained one it is strictly stronger
    /// than.
    realtime_rows: Vec<bool>,
    sustained: usize,
    admitted: usize,
    realtime: usize,
}

/// Apply the gate to every row of one file, printing each verdict.
fn report(
    path: &str,
    tolerance: f64,
    lateness_budget_us: Option<f64>,
    drain_fraction_max: Option<f64>,
    require_fence: bool,
    require_clean: bool,
) -> Result<ReportOutcome, String> {
    let text = fs::read_to_string(Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
    let rows = load_rows(&text);
    if rows.is_empty() {
        return Err(format!("{path}: no ROW lines"));
    }
    println!(
        "# {path}  gate: cadence>={tolerance}, accepted==received, no starvation, no loss, drained, real CPU"
    );
    let (mut sustained, mut admitted, mut realtime) = (0usize, 0usize, 0usize);
    let mut sustained_rows = Vec::with_capacity(rows.len());
    let mut realtime_rows = Vec::with_capacity(rows.len());
    for (index, fields) in rows.iter().enumerate() {
        let failures = judge(fields, tolerance, require_fence, require_clean);
        let stationarity = stationarity(fields, drain_fraction_max);
        let late = lateness(fields, lateness_budget_us);
        let position = |key: &str| fields.get(key).cloned().unwrap_or_default();
        let offered = number(fields, "offered_bps_per_dest").unwrap_or(0.0);
        let label = format!(
            "row {index} rep={} shard={} F={}",
            position("rep"),
            position("shard"),
            position("fanout")
        );
        if !failures.is_empty() {
            println!("  FAIL      {label}: {}", failures.join("; "));
            sustained_rows.push(false);
            realtime_rows.push(false);
            continue;
        }
        let drain = drain_fraction(fields)
            .map(|f| format!("{:.1}%", 100.0 * f))
            .unwrap_or_else(|_| "?".to_string());
        match &stationarity {
            Verdict::Fail(_) => {
                admitted += 1;
                sustained_rows.push(false);
                realtime_rows.push(false);
                println!(
                    "  PASS adm  {label} offered={:.3} Mbps/dest f_drain={drain} \
                     (not sustained: {})",
                    offered / 1e6,
                    stationarity.reasons()
                );
            }
            Verdict::Undeclared => {
                admitted += 1;
                sustained_rows.push(false);
                realtime_rows.push(false);
                println!(
                    "  PASS adm  {label} offered={:.3} Mbps/dest f_drain={drain} \
                     (stationarity {}: --drain-fraction-max not supplied)",
                    offered / 1e6,
                    stationarity.label()
                );
            }
            Verdict::Pass => {
                debug_assert!(
                    stationarity.passed(),
                    "reached the pass arm with a non-passing verdict"
                );
                sustained += 1;
                sustained_rows.push(true);
                match &late {
                    Verdict::Pass => {
                        realtime += 1;
                        realtime_rows.push(true);
                        println!(
                            "  PASS sus  {label} offered={:.3} Mbps/dest f_drain={drain}",
                            offered / 1e6
                        );
                    }
                    Verdict::Undeclared => {
                        realtime_rows.push(false);
                        println!(
                            "  PASS sus  {label} offered={:.3} Mbps/dest f_drain={drain} \
                             (real-time {}: --lateness-budget-us not supplied)",
                            offered / 1e6,
                            late.label()
                        );
                    }
                    Verdict::Fail(_) => {
                        realtime_rows.push(false);
                        println!(
                            "  PASS sus  {label} offered={:.3} Mbps/dest f_drain={drain} \
                             (not real-time: {})",
                            offered / 1e6,
                            late.reasons()
                        );
                    }
                }
            }
        }
    }
    Ok(ReportOutcome {
        rows,
        sustained_rows,
        realtime_rows,
        sustained,
        admitted,
        realtime,
    })
}

/// Totals accumulated across every input file.
struct RunTotals {
    sustained: usize,
    admitted: usize,
    realtime: usize,
    total: usize,
    rows: Vec<BTreeMap<String, String>>,
    sustained_rows: Vec<bool>,
    realtime_rows: Vec<bool>,
}

/// Judge every path in turn, accumulating totals and every row (for
/// cross-file repetition grouping) as it goes.
fn collect_reports(
    paths: &[String],
    tolerance: f64,
    budget: Option<f64>,
    drain_max: Option<f64>,
    require_fence: bool,
    require_clean: bool,
) -> Result<RunTotals, String> {
    let mut totals = RunTotals {
        sustained: 0,
        admitted: 0,
        realtime: 0,
        total: 0,
        rows: Vec::new(),
        sustained_rows: Vec::new(),
        realtime_rows: Vec::new(),
    };
    for path in paths {
        let outcome = report(
            path,
            tolerance,
            budget,
            drain_max,
            require_fence,
            require_clean,
        )?;
        totals.sustained += outcome.sustained;
        totals.admitted += outcome.admitted;
        totals.realtime += outcome.realtime;
        totals.total += outcome.rows.len();
        totals.rows.extend(outcome.rows);
        totals.sustained_rows.extend(outcome.sustained_rows);
        totals.realtime_rows.extend(outcome.realtime_rows);
    }
    Ok(totals)
}

/// The repetition rule: a point is capacity evidence only when every required
/// repetition, with at least [`MIN_QUALIFICATION_REPS`] repetitions, is
/// individually sustained. This is the gate the "sustained" row count alone
/// cannot express -- a 1/3 or 2/3 file has a nonzero sustained count without
/// being qualified evidence for anything repeatable.
///
/// Applied identically to the real-time verdict (`kind = "real-time"`,
/// against `realtime_rows`) as to the sustained one (`kind = "sustained"`):
/// the stronger claim must not ship with weaker repetition semantics than the
/// weaker claim it is built on.
///
/// Prints one verdict line per identity group and returns whether the gate as
/// a whole passed: at least one group existed, and every group qualified.
fn print_repetition_verdicts(
    kind: &str,
    rows: &[BTreeMap<String, String>],
    outcome_rows: &[bool],
) -> Result<bool, String> {
    let groups = group_by_identity(rows, outcome_rows)?;
    let mut all_qualify = true;
    for point in &groups {
        let qualifies = point.qualifies();
        all_qualify &= qualifies;
        let verdict = if qualifies {
            "QUALIFIED"
        } else {
            "UNQUALIFIED"
        };
        let reason = point_reason(point, qualifies);
        println!(
            "qualify: {verdict} ({kind})  {}  {}/{}{reason}",
            point.identity, point.sustained, point.rows
        );
    }
    Ok(!groups.is_empty() && all_qualify)
}

/// Why one point did or did not qualify, as the trailing note on its verdict
/// line (empty when it qualified).
fn point_reason(point: &QualifiedPoint, qualifies: bool) -> String {
    if point.rows < MIN_QUALIFICATION_REPS {
        format!(
            " (fewer than {MIN_QUALIFICATION_REPS} repetitions: {} of {} sustained)",
            point.sustained, point.rows
        )
    } else if !qualifies {
        format!(
            " (not every repetition sustained: {} of {})",
            point.sustained, point.rows
        )
    } else {
        String::new()
    }
}

pub fn run(args: &[String]) -> std::process::ExitCode {
    let Args {
        tolerance,
        lateness_budget_us: budget,
        drain_fraction_max: drain_max,
        require_fence,
        require_clean,
        paths,
    } = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("qualify: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let totals = match collect_reports(
        &paths,
        tolerance,
        budget,
        drain_max,
        require_fence,
        require_clean,
    ) {
        Ok(totals) => totals,
        Err(e) => {
            eprintln!("qualify: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let RunTotals {
        sustained,
        admitted,
        realtime,
        total,
        rows,
        sustained_rows,
        realtime_rows,
    } = totals;

    let drain_note = match drain_max {
        Some(max) => format!("--drain-fraction-max {max:.3}"),
        None => "no --drain-fraction-max declared, so no stationarity verdict".to_string(),
    };
    println!(
        "qualify: {sustained} of {total} rows sustained, {admitted} admitted-but-not-sustained \
         ({drain_note})"
    );
    match budget {
        Some(budget) => println!(
            "qualify: {realtime} of {total} rows also meet the {budget:.0}us lateness budget"
        ),
        None => println!("qualify: no --lateness-budget-us declared, so no real-time verdict"),
    }

    let sustained_gate_passed = if drain_max.is_some() {
        match print_repetition_verdicts("sustained", &rows, &sustained_rows) {
            Ok(passed) => Some(passed),
            Err(e) => {
                eprintln!("qualify: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        None
    };
    let realtime_gate_passed = if budget.is_some() {
        match print_repetition_verdicts("real-time", &rows, &realtime_rows) {
            Ok(passed) => Some(passed),
            Err(e) => {
                eprintln!("qualify: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    // A declared threshold with nothing meeting it is a failed gate, not a
    // successful report: `qualify` exists to be an executable check.
    if sustained_gate_passed == Some(false) || realtime_gate_passed == Some(false) {
        return std::process::ExitCode::FAILURE;
    }
    if sustained + admitted == 0 {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn passing() -> Vec<(&'static str, &'static str)> {
        vec![
            ("rep", "1"),
            ("shard", "0"),
            ("fanout", "200"),
            ("expected_ticks", "7599"),
            ("generated_ticks", "7598"),
            ("data_accepted", "1519600"),
            ("rx_core_total", "1519600"),
            ("data_zero", "0"),
            ("data_below_half_mean", "0"),
            ("rx_sec_a", "0"),
            ("drain_ok", "true"),
            ("pending_after_drain", "0"),
            ("window_cpu_ms", "2719.4"),
            ("cpu_ms", "7251.8"),
            ("offered_bps_per_dest", "8000000"),
            // The TX submission partition, closed: 465 000 wire datagrams of
            // which the media is the overwhelming majority, plus the control
            // cadence that carries it. Sum == tx_submitted_wire, which the gate
            // requires exactly.
            ("tx_submitted_wire", "465000"),
            ("tx_class_data_first", "440000"),
            ("tx_class_data_retx", "10000"),
            ("tx_class_ack", "10000"),
            ("tx_class_ackack", "2000"),
            ("tx_class_nak", "1000"),
            ("tx_class_keepalive", "1000"),
            ("tx_class_handshake", "500"),
            ("tx_class_dropreq", "0"),
            ("tx_class_km", "0"),
            ("tx_class_shutdown", "0"),
            ("tx_class_other_control", "500"),
            ("tx_class_total", "465000"),
            // Present, unthresholded: no real-time budget is declared here.
            ("first_submit_lateness_us_p50", "300"),
            ("first_submit_lateness_us_p99", "2400"),
            ("first_submit_lateness_us_max", "9100"),
            ("first_submit_lateness_samples", "440000"),
            // Send outcomes: absent would not be zero, so the gate requires
            // them explicitly.
            ("short", "0"),
            ("failed", "0"),
            ("peer_local", "0"),
            ("transient", "0"),
        ]
    }

    #[test]
    fn a_held_cadence_with_full_delivery_passes() {
        let tolerance = 0.999;
        assert!(judge(&row(&passing()), tolerance, false, false).is_empty());
    }

    #[test]
    fn a_conserved_cost_row_that_missed_cadence_fails() {
        // The exact shape #117 had to withdraw: drained, no loss, no starvation,
        // but only two thirds of the offered cadence was held.
        let tolerance = 0.999;
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "generated_ticks");
        fields.push(("generated_ticks", "5000"));
        let failures = judge(&row(&fields), tolerance, false, false);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].starts_with("cadence"), "{failures:?}");
    }

    #[test]
    fn accepted_but_undelivered_fails() {
        let tolerance = 0.999;
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "rx_core_total");
        fields.push(("rx_core_total", "587401"));
        let failures = judge(&row(&fields), tolerance, false, false);
        assert!(
            failures.iter().any(|f| f.contains("!= rx_core_total")),
            "{failures:?}"
        );
    }

    /// Throughput and real-time are different claims, and a row that passes one
    /// while missing a latency budget must say so.
    /// A run that keeps pace has almost no post-window wire work; one that
    /// accepts more than it can transmit does, and that is the difference
    /// between admission and sustained service.
    #[test]
    fn stationarity_separates_admission_from_sustained_service() {
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "tx_submitted_wire" && *k != "drain_submitted");
        // F=50 at 8 Mbps as measured: ~46.5 K in-window, ~0 in the drain.
        fields.push(("tx_submitted_wire", "465000"));
        fields.push(("drain_submitted", "0"));
        let steady = row(&fields);
        assert!((drain_fraction(&steady).unwrap() - 0.0).abs() < 1e-9);
        assert!(stationarity(&steady, Some(0.05)).passed());

        // F=200 at 4 Mbps as measured: the drain carries 70 % of the wire work.
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "tx_submitted_wire" && *k != "drain_submitted");
        fields.push(("tx_submitted_wire", "443469"));
        fields.push(("drain_submitted", "1060611"));
        let backlogged = row(&fields);
        let fraction = drain_fraction(&backlogged).unwrap();
        assert!(fraction > 0.70 && fraction < 0.71, "{fraction}");
        match stationarity(&backlogged, Some(0.05)) {
            Verdict::Fail(reasons) => {
                assert_eq!(reasons.len(), 1, "{reasons:?}");
                assert!(reasons[0].contains("did not keep pace"), "{reasons:?}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert_eq!(
            stationarity(&backlogged, None),
            Verdict::Undeclared,
            "no declared threshold, so no stationarity verdict"
        );
    }

    /// An undeclared threshold is not a pass: otherwise omitting a flag promotes
    /// every row to the strongest claim while the summary says otherwise.
    #[test]
    fn undeclared_thresholds_are_not_passes() {
        let steady = row(&passing());
        assert_eq!(stationarity(&steady, None), Verdict::Undeclared);
        assert!(!stationarity(&steady, None).passed());
    }

    /// Missing wire counts used to default to zero, which turns malformed
    /// evidence into a perfect drain result.
    #[test]
    fn malformed_wire_counts_fail_rather_than_default_to_zero() {
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "drain_submitted");
        fields.push(("tx_submitted_wire", "465000"));
        let missing_drain = row(&fields);
        assert!(drain_fraction(&missing_drain).is_err());
        assert!(matches!(
            stationarity(&missing_drain, Some(0.05)),
            Verdict::Fail(_)
        ));

        let mut fields = passing();
        fields.retain(|(k, _)| *k != "tx_submitted_wire");
        fields.push(("tx_submitted_wire", "not-a-number"));
        fields.push(("drain_submitted", "10"));
        assert!(matches!(
            stationarity(&row(&fields), Some(0.05)),
            Verdict::Fail(_)
        ));
    }

    /// A submission total that cannot be decomposed, or that does not close,
    /// is not evidence about the dataplane: it cannot say whether the wire
    /// traffic was the media or the control cadence around it.
    #[test]
    fn tx_submission_partition_is_required_and_must_close() {
        let tolerance = 0.999;
        assert!(
            judge(&row(&passing()), tolerance, false, false).is_empty(),
            "a closed partition passes"
        );

        // Missing one class: a missing measurement, not a zero.
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "tx_class_data_retx");
        let failures = judge(&row(&fields), tolerance, false, false);
        assert!(
            failures
                .iter()
                .any(|f| f.contains("missing tx_class_data_retx")),
            "{failures:?}"
        );

        // Sum does not reach the declared total.
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "tx_class_data_first");
        fields.push(("tx_class_data_first", "430000"));
        let failures = judge(&row(&fields), tolerance, false, false);
        assert!(
            failures
                .iter()
                .any(|f| f.contains("does not close") && f.contains("tx_class_total")),
            "{failures:?}"
        );

        // Sum closes but disagrees with the wire count the gate already reads.
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "tx_class_total" && *k != "tx_submitted_wire");
        fields.push(("tx_class_total", "465000"));
        fields.push(("tx_submitted_wire", "464999"));
        let failures = judge(&row(&fields), tolerance, false, false);
        assert!(
            failures
                .iter()
                .any(|f| f.contains("!= tx_submitted_wire=464999")),
            "{failures:?}"
        );

        // The lateness fields are evidence for the real-time claim: absent is
        // absent, not zero.
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "first_submit_lateness_us_p99");
        let failures = judge(&row(&fields), tolerance, false, false);
        assert!(
            failures
                .iter()
                .any(|f| f.contains("missing first_submit_lateness_us_p99")),
            "{failures:?}"
        );

        // "No send failed" must be recorded, not merely unmentioned.
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "transient");
        let failures = judge(&row(&fields), tolerance, false, false);
        assert!(
            failures.iter().any(|f| f.contains("missing transient")),
            "{failures:?}"
        );
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "failed");
        fields.push(("failed", "3"));
        let failures = judge(&row(&fields), tolerance, false, false);
        assert!(
            failures.iter().any(|f| f.contains("failed=3 (must be 0)")),
            "{failures:?}"
        );
    }

    #[test]
    fn lateness_budget_separates_throughput_from_real_time() {
        // `offer_lateness` is source punctuality, sampled before `service()` is
        // even entered: pushing it far outside any sane budget must not move
        // the real-time verdict, which is gated on `first_submit_lateness`
        // instead (the metric that actually spans admission through wire
        // handoff).
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "offer_lateness_us_p99" && *k != "offer_lateness_us_max");
        fields.push(("offer_lateness_us_p99", "28334"));
        fields.push(("offer_lateness_us_max", "51200"));
        fields.retain(|(k, _)| {
            *k != "first_submit_lateness_us_p99" && *k != "first_submit_lateness_us_max"
        });
        fields.push(("first_submit_lateness_us_p99", "28334"));
        fields.push(("first_submit_lateness_us_max", "51200"));
        let row = row(&fields);
        assert!(
            judge(&row, 0.999, false, false).is_empty(),
            "still a throughput pass"
        );
        assert_eq!(
            lateness(&row, None),
            Verdict::Undeclared,
            "no budget declared, so no real-time verdict"
        );
        match lateness(&row, Some(5_000.0)) {
            Verdict::Fail(reasons) => {
                assert_eq!(reasons.len(), 2, "{reasons:?}");
                assert!(reasons[0].contains("first_submit_lateness"), "{reasons:?}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(
            lateness(&row, Some(60_000.0)).passed(),
            "a generous budget is met"
        );
    }

    /// `offer_lateness` alone must never move the real-time verdict: it is
    /// sampled before `service()` is entered, so it cannot say anything about
    /// dataplane behaviour. Only `first_submit_lateness` may.
    #[test]
    fn offer_lateness_alone_cannot_fail_the_real_time_verdict() {
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "offer_lateness_us_p99" && *k != "offer_lateness_us_max");
        fields.push(("offer_lateness_us_p99", "999999"));
        fields.push(("offer_lateness_us_max", "999999"));
        let row = row(&fields);
        // `passing()`'s own first_submit_lateness values (p99=2400, max=9100)
        // are well within this budget.
        assert!(
            lateness(&row, Some(60_000.0)).passed(),
            "a wild offer_lateness value must not affect a verdict gated on \
             first_submit_lateness"
        );
    }

    #[test]
    fn starvation_loss_and_stale_cpu_each_fail() {
        let tolerance = 0.999;
        for (key, value, needle) in [
            ("data_zero", "3", "data_zero"),
            ("data_below_half_mean", "31", "data_below_half_mean"),
            ("rx_sec_a", "1", "sec_a"),
            ("window_cpu_ms", "0.0", "window_cpu_ms"),
            ("drain_ok", "false", "drain_ok"),
            ("pending_after_drain", "257", "pending_after_drain"),
        ] {
            let mut fields = passing();
            fields.retain(|(k, _)| *k != key);
            fields.push((key, value));
            let failures = judge(&row(&fields), tolerance, false, false);
            assert!(
                failures.iter().any(|f| f.contains(needle)),
                "{key}={value} produced {failures:?}"
            );
        }
    }

    /// A conserved fence, matching `passing()`'s `fanout=200`. `rx_core_total`
    /// is bumped by the fence contribution to keep `delivery_failures`'s own
    /// `data_accepted + fence == rx_core_total` identity satisfied -- a fence
    /// this fixture declares conserved must also be one the delivery identity
    /// already accounts for.
    fn fence_passing() -> Vec<(&'static str, &'static str)> {
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "rx_core_total");
        fields.push(("rx_core_total", "1519800"));
        fields.extend([
            ("fence_offered", "200"),
            ("fence_accepted", "200"),
            ("rx_diag_fences_seen", "200"),
            ("missed_source_ticks", "0"),
            ("rx_established", "200"),
            ("rx_diag_missing_final", "0"),
            ("tx_failures_pending", "0"),
            ("rx_lost", "0"),
            ("rx_diag_duplicate_payloads", "0"),
        ]);
        fields
    }

    #[test]
    fn a_conserved_fence_passes_when_required() {
        assert!(
            judge(&row(&fence_passing()), 0.999, true, false).is_empty(),
            "a fully conserved fence must pass its own gate"
        );
    }

    /// `0 missed_source_ticks` predicts zero missing-final: the baseline case
    /// with no source-stall accounting in play.
    #[test]
    fn zero_missed_source_ticks_predicts_zero_missing_final() {
        assert!(
            unexpected_missing_final_failures(&row(&fence_passing())).is_empty(),
            "0 missed_source_ticks x rx_established must predict 0 missing_final"
        );
    }

    /// Sweep A's own A1 shape: 15 missed source ticks across 50 established
    /// peers explains exactly 750 of `rx_diag_missing_final`, none of it
    /// transport loss. The fence criterion must pass and leave the (separate,
    /// already-declared) cadence tolerance to judge the source shortfall.
    #[test]
    fn source_explained_missing_final_passes_the_fence_criterion() {
        let mut fields = fence_passing();
        fields.retain(|(k, _)| {
            *k != "missed_source_ticks" && *k != "rx_established" && *k != "rx_diag_missing_final"
        });
        fields.push(("missed_source_ticks", "15"));
        fields.push(("rx_established", "50"));
        fields.push(("rx_diag_missing_final", "750"));
        assert!(
            unexpected_missing_final_failures(&row(&fields)).is_empty(),
            "15 missed_source_ticks x 50 rx_established == 750: fully explained by the \
             source's own cadence shortfall, not transport loss"
        );
    }

    /// One more missing than the source-stall accounting predicts is real,
    /// unexplained transport loss and must fail.
    #[test]
    fn one_unexplained_missing_final_fails() {
        let mut fields = fence_passing();
        fields.retain(|(k, _)| {
            *k != "missed_source_ticks" && *k != "rx_established" && *k != "rx_diag_missing_final"
        });
        fields.push(("missed_source_ticks", "15"));
        fields.push(("rx_established", "50"));
        fields.push(("rx_diag_missing_final", "751"));
        let failures = unexpected_missing_final_failures(&row(&fields));
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].contains("unexpected_transport_missing=1"),
            "{failures:?}"
        );
    }

    /// Without `--require-fence`, a broken fence must not fail the gate: these
    /// fields are only an executable claim once the run declares it is
    /// fence-enabled.
    #[test]
    fn fence_failures_are_ignored_unless_required() {
        let mut fields = fence_passing();
        fields.retain(|(k, _)| *k != "fence_offered");
        fields.push(("fence_offered", "0"));
        assert!(
            judge(&row(&fields), 0.999, false, false).is_empty(),
            "a broken fence must not fail the gate when fencing was not declared"
        );
    }

    #[test]
    fn each_fence_conservation_field_is_individually_required() {
        for (key, value, needle) in [
            ("fence_offered", "199", "fence_offered"),
            ("fence_accepted", "150", "fence_accepted"),
            ("rx_diag_fences_seen", "0", "rx_diag_fences_seen"),
            ("rx_diag_missing_final", "3", "rx_diag_missing_final"),
            ("tx_failures_pending", "1", "tx_failures_pending"),
            ("rx_lost", "2", "rx_lost"),
            (
                "rx_diag_duplicate_payloads",
                "1",
                "rx_diag_duplicate_payloads",
            ),
        ] {
            let mut fields = fence_passing();
            fields.retain(|(k, _)| *k != key);
            fields.push((key, value));
            let failures = judge(&row(&fields), 0.999, true, false);
            assert!(
                failures.iter().any(|f| f.contains(needle)),
                "{key}={value} with --require-fence produced {failures:?}"
            );
        }
    }

    /// The documented rule this gate owns: protocol-level duplicates
    /// (`rx_duplicates`) are recovery traffic, not duplicate delivery, and
    /// must not fail the fence gate on their own -- only application-identity
    /// duplicates (`rx_diag_duplicate_payloads`) may.
    #[test]
    fn packet_level_duplicates_do_not_fail_the_fence_gate() {
        let mut fields = fence_passing();
        fields.push(("rx_duplicates", "37"));
        assert!(
            judge(&row(&fields), 0.999, true, false).is_empty(),
            "recovery-traffic duplicates at the packet level must not fail the gate"
        );
    }

    /// A row carrying an identity for [`group_by_identity`], matching
    /// `passing()`'s `fanout=200`/`offered_bps_per_dest=8000000`.
    fn identified() -> Vec<(&'static str, &'static str)> {
        let mut fields = passing();
        fields.extend([
            ("tx_lanes", "256"),
            ("payload_bytes", "1316"),
            ("rx_mode", "ManagedMultishot"),
            ("window_ms", "60000"),
            ("git_sha", "abc1234"),
        ]);
        fields
    }

    /// The repetition rule's whole point: three passing repetitions is
    /// evidence, and only three passing repetitions is evidence.
    #[test]
    fn three_of_three_sustained_repetitions_qualify() {
        let rows: Vec<_> = (0..3).map(|_| row(&identified())).collect();
        let sustained = vec![true, true, true];
        let groups = group_by_identity(&rows, &sustained).expect("identity fields present");
        assert_eq!(groups.len(), 1);
        assert_eq!((groups[0].sustained, groups[0].rows), (3, 3));
        assert!(groups[0].qualifies(), "3/3 sustained repetitions qualify");
    }

    /// Sweep A's own shape: two of three repetitions sustained must not be
    /// promoted to a qualified point. This is the exact case the PR's prose
    /// gate was applied by hand for, and the executable gate has to refuse it
    /// too.
    #[test]
    fn two_of_three_sustained_repetitions_fail_to_qualify() {
        let rows: Vec<_> = (0..3).map(|_| row(&identified())).collect();
        let sustained = vec![true, true, false];
        let groups = group_by_identity(&rows, &sustained).expect("identity fields present");
        assert_eq!(groups.len(), 1);
        assert_eq!((groups[0].sustained, groups[0].rows), (2, 3));
        assert!(
            !groups[0].qualifies(),
            "2/3 sustained repetitions must not qualify"
        );
    }

    /// A single failed repetition is enough to disqualify a point regardless
    /// of how many others passed.
    #[test]
    fn one_of_three_sustained_repetitions_fails_to_qualify() {
        let rows: Vec<_> = (0..3).map(|_| row(&identified())).collect();
        let sustained = vec![true, false, false];
        let groups = group_by_identity(&rows, &sustained).expect("identity fields present");
        assert_eq!(groups.len(), 1);
        assert_eq!((groups[0].sustained, groups[0].rows), (1, 3));
        assert!(
            !groups[0].qualifies(),
            "1/3 sustained repetitions must not qualify"
        );
    }

    /// Every repetition passing is not enough on its own: fewer than
    /// [`MIN_QUALIFICATION_REPS`] repetitions is insufficient evidence for a
    /// repeatable point, independent of whether the reps that exist passed.
    #[test]
    fn two_of_two_sustained_repetitions_fail_on_repetition_count_alone() {
        let rows: Vec<_> = (0..2).map(|_| row(&identified())).collect();
        let sustained = vec![true, true];
        let groups = group_by_identity(&rows, &sustained).expect("identity fields present");
        assert_eq!(groups.len(), 1);
        assert_eq!((groups[0].sustained, groups[0].rows), (2, 2));
        assert!(
            !groups[0].qualifies(),
            "2/2 sustained repetitions is still fewer than the required 3"
        );
    }

    /// Rows with a different identity dimension are different points, never
    /// pooled into the same repetition count.
    #[test]
    fn distinct_identities_are_grouped_separately() {
        let mut fields_b = identified();
        fields_b.retain(|(k, _)| *k != "fanout");
        fields_b.push(("fanout", "50"));
        let rows = vec![row(&identified()), row(&identified()), row(&fields_b)];
        let sustained = vec![true, true, true];
        let groups = group_by_identity(&rows, &sustained).expect("identity fields present");
        assert_eq!(groups.len(), 2, "F=200 and F=50 must not share a group");
    }

    /// A row missing one of the seven identity dimensions cannot be grouped
    /// at all: silently dropping it would let an incomplete row disappear
    /// from the repetition count instead of failing loudly.
    #[test]
    fn a_row_missing_an_identity_field_is_an_error() {
        let mut fields = identified();
        fields.retain(|(k, _)| *k != "rx_mode");
        let rows = vec![row(&fields)];
        let sustained = vec![true];
        let error = group_by_identity(&rows, &sustained).unwrap_err();
        assert!(error.contains("rx_mode"), "{error}");
    }

    /// Rows from different measurement windows, or different source
    /// revisions, are not repetitions of the same experiment even if every
    /// workload dimension matches: pooling them would let `qualify` combine
    /// evidence across files into a synthetic "3/3" for a claim no single run
    /// actually supports.
    #[test]
    fn different_window_ms_or_git_sha_are_grouped_separately() {
        let mut different_window = identified();
        different_window.retain(|(k, _)| *k != "window_ms");
        different_window.push(("window_ms", "3000"));

        let mut different_sha = identified();
        different_sha.retain(|(k, _)| *k != "git_sha");
        different_sha.push(("git_sha", "deadbee"));

        let rows = vec![
            row(&identified()),
            row(&different_window),
            row(&different_sha),
        ];
        let sustained = vec![true, true, true];
        let groups = group_by_identity(&rows, &sustained).expect("identity fields present");
        assert_eq!(
            groups.len(),
            3,
            "different window_ms and git_sha must each be a distinct point"
        );
    }

    #[test]
    fn clean_provenance_passes_when_required() {
        let mut fields = passing();
        fields.push(("git_dirty", "false"));
        fields.push(("pre_window_drained", "true"));
        assert!(
            judge(&row(&fields), 0.999, false, true).is_empty(),
            "a clean tree and a drained pre-window must pass their own gate"
        );
    }

    #[test]
    fn clean_provenance_is_ignored_unless_required() {
        let mut fields = passing();
        fields.push(("git_dirty", "true"));
        fields.push(("pre_window_drained", "false"));
        assert!(
            judge(&row(&fields), 0.999, false, false).is_empty(),
            "provenance must not gate the run unless --require-clean is declared"
        );
    }

    #[test]
    fn each_provenance_field_is_individually_required() {
        for (key, value, needle) in [
            ("git_dirty", "true", "git_dirty"),
            ("pre_window_drained", "false", "pre_window_drained"),
        ] {
            let mut fields = passing();
            fields.push(("git_dirty", "false"));
            fields.push(("pre_window_drained", "true"));
            fields.retain(|(k, _)| *k != key);
            fields.push((key, value));
            let failures = judge(&row(&fields), 0.999, false, true);
            assert!(
                failures.iter().any(|f| f.contains(needle)),
                "{key}={value} with --require-clean produced {failures:?}"
            );
        }
    }

    /// TSV text for `report()` to read back from disk: a header line built
    /// from the first row's own keys, plus one `ROW` line per row, in the
    /// same column order. No header *comment* is needed here because every
    /// identity field (including `window_ms`/`git_sha`) is already present
    /// per-row, unlike a real sweep file's run-shape constants.
    fn write_report_tsv(rows: &[Vec<(&'static str, &'static str)>]) -> std::path::PathBuf {
        let keys: Vec<&str> = rows[0].iter().map(|(k, _)| *k).collect();
        let mut text = String::from("kind\t");
        text.push_str(&keys.join("\t"));
        text.push('\n');
        for fields in rows {
            let values: Vec<&str> = fields.iter().map(|(_, v)| *v).collect();
            text.push_str("ROW\t");
            text.push_str(&values.join("\t"));
            text.push('\n');
        }
        let path = std::env::temp_dir().join(format!(
            "qualify-test-{}-{}.tsv",
            std::process::id(),
            text.len()
        ));
        fs::write(&path, text).expect("write temp tsv");
        path
    }

    /// The real-time verdict must not ship with weaker repetition semantics
    /// than the sustained verdict it is built on: two of three repetitions
    /// meeting the lateness budget must not qualify, exactly like two of
    /// three sustained repetitions.
    #[test]
    fn realtime_repetition_uses_the_same_grouping_as_sustained() {
        let mut on_time = identified();
        on_time.retain(|(k, _)| {
            *k != "first_submit_lateness_us_p99" && *k != "first_submit_lateness_us_max"
        });
        on_time.push(("first_submit_lateness_us_p99", "1000"));
        on_time.push(("first_submit_lateness_us_max", "1000"));
        on_time.push(("drain_submitted", "0"));

        let mut late = identified();
        late.retain(|(k, _)| {
            *k != "first_submit_lateness_us_p99" && *k != "first_submit_lateness_us_max"
        });
        late.push(("first_submit_lateness_us_p99", "50000"));
        late.push(("first_submit_lateness_us_max", "50000"));
        late.push(("drain_submitted", "0"));

        let path = write_report_tsv(&[on_time.clone(), on_time, late]);
        let outcome = report(
            path.to_str().unwrap(),
            0.999,
            Some(5_000.0),
            Some(0.05),
            false,
            false,
        );
        let _ = fs::remove_file(&path);
        let outcome = outcome.expect("report succeeds");

        assert_eq!(outcome.realtime, 2, "two of three rows meet the budget");
        let groups =
            group_by_identity(&outcome.rows, &outcome.realtime_rows).expect("identity present");
        assert_eq!(groups.len(), 1);
        assert_eq!((groups[0].sustained, groups[0].rows), (2, 3));
        assert!(
            !groups[0].qualifies(),
            "2/3 real-time repetitions must not qualify, exactly like sustained"
        );
    }
}
