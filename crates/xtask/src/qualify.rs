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
    match (
        number(fields, "data_accepted"),
        number(fields, "rx_core_total"),
    ) {
        (Ok(accepted), Ok(received)) if accepted != received => vec![format!(
            "data_accepted {accepted:.0} != rx_core_total {received:.0} ({} % delivered)",
            100.0 * received / accepted.max(1.0)
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
fn lateness(fields: &BTreeMap<String, String>, budget_us: Option<f64>) -> Verdict {
    let Some(budget) = budget_us else {
        return Verdict::Undeclared;
    };
    let failures: Vec<String> = ["offer_lateness_us_p99", "offer_lateness_us_max"]
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

/// Apply the gate to one row, returning every reason it fails.
fn judge(fields: &BTreeMap<String, String>, tick_tolerance: f64) -> Vec<String> {
    let mut failures = cadence_failures(fields, tick_tolerance);
    failures.extend(delivery_failures(fields));
    failures.extend(zero_failures(
        fields,
        &["data_zero", "data_below_half_mean", "sec_a"],
    ));
    failures.extend(equilibrium_failures(fields));
    failures.extend(cpu_failures(fields));
    failures.extend(tx_class_failures(fields));
    failures
}

/// `(tolerance, paths)` from the command line.
/// Command-line inputs: two declared thresholds and the files to judge.
struct Args {
    tolerance: f64,
    lateness_budget_us: Option<f64>,
    drain_fraction_max: Option<f64>,
    paths: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut tolerance = 0.999;
    let mut budget: Option<f64> = None;
    let mut drain_max: Option<f64> = None;
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
             [--lateness-budget-us N] [--drain-fraction-max F]"
                .to_string(),
        );
    }
    Ok(Args {
        tolerance,
        lateness_budget_us: budget,
        drain_fraction_max: drain_max,
        paths,
    })
}

/// ROW lines as field maps, keyed by the file's own header.
fn load_rows(text: &str) -> Vec<BTreeMap<String, String>> {
    let header: Vec<String> = text
        .lines()
        .find(|h| h.starts_with("kind\t"))
        .map(|h| h.split('\t').map(str::to_string).collect())
        .unwrap_or_default();
    text.lines()
        .filter(|l| l.starts_with("ROW\t"))
        .map(|l| {
            l.split('\t')
                .enumerate()
                .filter_map(|(i, v)| header.get(i).map(|k| (k.clone(), v.to_string())))
                .collect()
        })
        .collect()
}

/// Apply the gate to every row of one file, printing each verdict.
fn report(
    path: &str,
    tolerance: f64,
    lateness_budget_us: Option<f64>,
    drain_fraction_max: Option<f64>,
) -> Result<(usize, usize, usize, usize), String> {
    let text = fs::read_to_string(Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
    let rows = load_rows(&text);
    if rows.is_empty() {
        return Err(format!("{path}: no ROW lines"));
    }
    println!(
        "# {path}  gate: cadence>={tolerance}, accepted==received, no starvation, no loss, drained, real CPU"
    );
    let (mut sustained, mut admitted, mut realtime) = (0usize, 0usize, 0usize);
    for (index, fields) in rows.iter().enumerate() {
        let failures = judge(fields, tolerance);
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
            continue;
        }
        let drain = drain_fraction(fields)
            .map(|f| format!("{:.1}%", 100.0 * f))
            .unwrap_or_else(|_| "?".to_string());
        match &stationarity {
            Verdict::Fail(_) => {
                admitted += 1;
                println!(
                    "  PASS adm  {label} offered={:.3} Mbps/dest f_drain={drain} \
                     (not sustained: {})",
                    offered / 1e6,
                    stationarity.reasons()
                );
            }
            Verdict::Undeclared => {
                admitted += 1;
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
                match &late {
                    Verdict::Pass => {
                        realtime += 1;
                        println!(
                            "  PASS sus  {label} offered={:.3} Mbps/dest f_drain={drain}",
                            offered / 1e6
                        );
                    }
                    Verdict::Undeclared => println!(
                        "  PASS sus  {label} offered={:.3} Mbps/dest f_drain={drain} \
                         (real-time {}: --lateness-budget-us not supplied)",
                        offered / 1e6,
                        late.label()
                    ),
                    Verdict::Fail(_) => println!(
                        "  PASS sus  {label} offered={:.3} Mbps/dest f_drain={drain} \
                         (not real-time: {})",
                        offered / 1e6,
                        late.reasons()
                    ),
                }
            }
        }
    }
    Ok((sustained, admitted, realtime, rows.len()))
}

pub fn run(args: &[String]) -> std::process::ExitCode {
    let Args {
        tolerance,
        lateness_budget_us: budget,
        drain_fraction_max: drain_max,
        paths,
    } = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("qualify: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let (mut sustained, mut admitted, mut realtime, mut total) = (0usize, 0usize, 0usize, 0usize);
    for path in &paths {
        match report(path, tolerance, budget, drain_max) {
            Ok((s, a, r, n)) => {
                sustained += s;
                admitted += a;
                realtime += r;
                total += n;
            }
            Err(e) => {
                eprintln!("qualify: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }
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
    // A declared threshold with nothing meeting it is a failed gate, not a
    // successful report: `qualify` exists to be an executable check.
    if drain_max.is_some() && sustained == 0 {
        return std::process::ExitCode::FAILURE;
    }
    if budget.is_some() && realtime == 0 {
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
        ]
    }

    #[test]
    fn a_held_cadence_with_full_delivery_passes() {
        let tolerance = 0.999;
        assert!(judge(&row(&passing()), tolerance).is_empty());
    }

    #[test]
    fn a_conserved_cost_row_that_missed_cadence_fails() {
        // The exact shape #117 had to withdraw: drained, no loss, no starvation,
        // but only two thirds of the offered cadence was held.
        let tolerance = 0.999;
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "generated_ticks");
        fields.push(("generated_ticks", "5000"));
        let failures = judge(&row(&fields), tolerance);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].starts_with("cadence"), "{failures:?}");
    }

    #[test]
    fn accepted_but_undelivered_fails() {
        let tolerance = 0.999;
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "rx_core_total");
        fields.push(("rx_core_total", "587401"));
        let failures = judge(&row(&fields), tolerance);
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
            judge(&row(&passing()), tolerance).is_empty(),
            "a closed partition passes"
        );

        // Missing one class: a missing measurement, not a zero.
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "tx_class_data_retx");
        let failures = judge(&row(&fields), tolerance);
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
        let failures = judge(&row(&fields), tolerance);
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
        let failures = judge(&row(&fields), tolerance);
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
        let failures = judge(&row(&fields), tolerance);
        assert!(
            failures
                .iter()
                .any(|f| f.contains("missing first_submit_lateness_us_p99")),
            "{failures:?}"
        );
    }

    #[test]
    fn lateness_budget_separates_throughput_from_real_time() {
        let mut fields = passing();
        fields.retain(|(k, _)| *k != "offer_lateness_us_p99" && *k != "offer_lateness_us_max");
        fields.push(("offer_lateness_us_p99", "28334"));
        fields.push(("offer_lateness_us_max", "51200"));
        let row = row(&fields);
        assert!(judge(&row, 0.999).is_empty(), "still a throughput pass");
        assert_eq!(
            lateness(&row, None),
            Verdict::Undeclared,
            "no budget declared, so no real-time verdict"
        );
        match lateness(&row, Some(5_000.0)) {
            Verdict::Fail(reasons) => {
                assert_eq!(reasons.len(), 2, "{reasons:?}");
                assert!(reasons[0].contains("offer_lateness"), "{reasons:?}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
        assert!(
            lateness(&row, Some(60_000.0)).passed(),
            "a generous budget is met"
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
            let failures = judge(&row(&fields), tolerance);
            assert!(
                failures.iter().any(|f| f.contains(needle)),
                "{key}={value} produced {failures:?}"
            );
        }
    }
}
