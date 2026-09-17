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
//! ```text
//! cargo xtask qualify docs/results/scaling-1000/scale-N1000-S5-2reps.tsv
//! cargo xtask qualify --tolerance 0.999 fence.tsv
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
    failures
}

/// `(tolerance, paths)` from the command line.
fn parse_args(args: &[String]) -> Result<(f64, Vec<String>), String> {
    let mut tolerance = 0.999;
    let mut paths = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--tolerance" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| "--tolerance needs a value".to_string())?;
            tolerance = value
                .parse()
                .map_err(|_| format!("--tolerance does not parse: {value:?}"))?;
            i += 2;
        } else {
            paths.push(args[i].clone());
            i += 1;
        }
    }
    if paths.is_empty() {
        return Err("usage: cargo xtask qualify <sweep.tsv> [--tolerance 0.999]".to_string());
    }
    Ok((tolerance, paths))
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
fn report(path: &str, tolerance: f64) -> Result<(usize, usize), String> {
    let text = fs::read_to_string(Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
    let rows = load_rows(&text);
    if rows.is_empty() {
        return Err(format!("{path}: no ROW lines"));
    }
    println!(
        "# {path}  gate: cadence>={tolerance}, accepted==received, no starvation, no loss, drained, real CPU"
    );
    let mut passed = 0usize;
    for (index, fields) in rows.iter().enumerate() {
        let failures = judge(fields, tolerance);
        let position = |key: &str| fields.get(key).cloned().unwrap_or_default();
        let offered = number(fields, "offered_bps_per_dest").unwrap_or(0.0);
        if failures.is_empty() {
            passed += 1;
            println!(
                "  PASS row {index} rep={} shard={} F={} offered={:.3} Mbps/dest",
                position("rep"),
                position("shard"),
                position("fanout"),
                offered / 1e6
            );
        } else {
            println!(
                "  FAIL row {index} rep={} shard={} F={}: {}",
                position("rep"),
                position("shard"),
                position("fanout"),
                failures.join("; ")
            );
        }
    }
    Ok((passed, rows.len()))
}

pub fn run(args: &[String]) -> std::process::ExitCode {
    let (tolerance, paths) = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("qualify: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let (mut passed, mut total) = (0usize, 0usize);
    for path in &paths {
        match report(path, tolerance) {
            Ok((p, n)) => {
                passed += p;
                total += n;
            }
            Err(e) => {
                eprintln!("qualify: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }
    println!("qualify: {passed} of {total} rows pass the sustained-capacity gate");
    if passed == 0 {
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
