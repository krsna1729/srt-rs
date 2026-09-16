//! Machine-readable qualification evidence.
//!
//! The qualification harness prints one `key=value` line per run, and the
//! receiver process prints one `STATS key=value` line. Those lines are the
//! primary evidence; this module turns them into the committed JSON artifact
//! so a reviewer can read numbers without a harness run.
//!
//! # Why the parser is code with tests rather than an ad-hoc script
//!
//! An earlier hand-written transcription silently **dropped** fields: it looked
//! for keys the harness does not print (`lateness_us_p99`) and cast fractional
//! values (`rtt_ms=0.027`) with an integer parser, so those values became
//! `null` in the committed artifact while the raw line still held them. That is
//! evidence loss that reads as missing data.
//!
//! [`parse_kv_line`] therefore parses **every** token and returns every one of
//! them, and the tests cross-check the parsed key set against the token set of
//! the input, plus assert that every numeric-looking token parsed as a number
//! and never fell back to text. A line the parser cannot represent is an error,
//! not a silently shorter schema.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// One parsed value from a `key=value` line.
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceValue {
    /// An integer token.
    Int(i64),
    /// A fractional token (for example an `_ms` duration).
    Float(f64),
    /// `true` or `false`.
    Bool(bool),
    /// Anything else, kept verbatim rather than coerced.
    Text(String),
}

/// One run's evidence: every printed field of the sender line and of the
/// receiver line, plus both lines verbatim.
#[derive(Debug, Clone, PartialEq)]
pub struct RunEvidence {
    /// Destination population the run was configured for.
    pub fanout: u64,
    /// Fields of the sender's `SHARED_OWNER_QUAL` line.
    pub sender: BTreeMap<String, EvidenceValue>,
    /// Fields of the receiver's `STATS` line.
    pub receiver: BTreeMap<String, EvidenceValue>,
    /// Sender line, verbatim.
    pub raw_sender_stdout: String,
    /// Receiver line, verbatim.
    pub raw_receiver_stdout: String,
}

/// Parse one `key=value` line into every token it contains.
///
/// `prefix` is dropped from the first token when present (the harness's own
/// line label). `tx_pool=free/capacity` is expanded into
/// `tx_pool_free`/`tx_pool_capacity` so both halves survive as numbers.
///
/// Returns an error if any token is malformed, because a malformed token means
/// the artifact would silently lose a field.
pub fn parse_kv_line(line: &str, prefix: &str) -> Result<BTreeMap<String, EvidenceValue>, String> {
    let body = line.strip_prefix(prefix).unwrap_or(line).trim();
    let mut out = BTreeMap::new();
    for token in body.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            return Err(format!("token without '=' in {line:?}: {token:?}"));
        };
        if key.is_empty() {
            return Err(format!("empty key in {line:?}: {token:?}"));
        }
        // `tx_pool` is printed as a pair; keep both halves as numbers.
        if key == "tx_pool" {
            let (free, capacity) = value
                .split_once('/')
                .ok_or_else(|| format!("tx_pool is not free/capacity: {token:?}"))?;
            out.insert(
                "tx_pool_free".to_string(),
                EvidenceValue::Int(parse_int(free, token)?),
            );
            out.insert(
                "tx_pool_capacity".to_string(),
                EvidenceValue::Int(parse_int(capacity, token)?),
            );
            continue;
        }
        let parsed = if let Ok(int) = value.parse::<i64>() {
            EvidenceValue::Int(int)
        } else if let Ok(float) = value.parse::<f64>() {
            // Reject nan/inf spellings that would serialize as invalid JSON.
            if !float.is_finite() {
                return Err(format!("non-finite numeric value: {token:?}"));
            }
            EvidenceValue::Float(float)
        } else if value == "true" {
            EvidenceValue::Bool(true)
        } else if value == "false" {
            EvidenceValue::Bool(false)
        } else {
            EvidenceValue::Text(value.to_string())
        };
        out.insert(key.to_string(), parsed);
    }
    Ok(out)
}

fn parse_int(value: &str, token: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|_| format!("expected an integer in {token:?}"))
}

/// Parse one harness sender line plus its receiver line into run evidence.
pub fn parse_run(sender_line: &str, receiver_line: &str) -> Result<RunEvidence, String> {
    let sender = parse_kv_line(sender_line, "SHARED_OWNER_QUAL")?;
    let receiver = parse_kv_line(receiver_line, "STATS")?;
    let fanout = match sender.get("fanout") {
        Some(EvidenceValue::Int(fanout)) if *fanout > 0 => *fanout as u64,
        other => return Err(format!("sender line has no positive fanout: {other:?}")),
    };
    if let (
        Some(EvidenceValue::Int(expected)),
        Some(EvidenceValue::Int(generated)),
        Some(EvidenceValue::Int(missed)),
    ) = (
        sender.get("expected_ticks"),
        sender.get("generated_ticks"),
        sender.get("missed_source_ticks"),
    ) {
        // The harness asserts this at window close; re-checking it here means a
        // committed artifact can never carry an unreconciled row.
        if expected != &(generated + missed) {
            return Err(format!(
                "source accounting does not reconcile: expected={expected} generated={generated} \
                 missed={missed}"
            ));
        }
    } else {
        return Err("sender line is missing the source-tick counters".to_string());
    }
    Ok(RunEvidence {
        fanout,
        sender,
        receiver,
        raw_sender_stdout: sender_line.trim().to_string(),
        raw_receiver_stdout: receiver_line.trim().to_string(),
    })
}

/// Provenance for one artifact: exactly which code and host produced it.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub git_sha: String,
    /// Whether the measuring worktree had uncommitted changes.
    pub git_dirty: bool,
    pub kernel: String,
    pub machine: String,
    pub cpus: usize,
}

/// Render the artifact as indented JSON.
///
/// Hand-rolled so the bench crate needs no serialization dependency; every
/// value is emitted, and any key or string that needs escaping is escaped.
pub fn render_json(provenance: &Provenance, runs: &[RunEvidence]) -> String {
    let mut out = String::with_capacity(4096 + runs.len() * 2048);
    out.push_str("{\n");
    out.push_str("  \"kind\": \"srt-rs shared-Owner qualification (fixed K/H, one sender process, independent receiver process)\",\n");
    out.push_str("  \"harness\": \"crates/srt-bench/benches/compio_shared_owner_qual.rs (sender) + `srt-bench runtime=compio mode=receiver` (receiver)\",\n");
    let _ = writeln!(out, "  \"git_sha\": {},", json_string(&provenance.git_sha));
    let _ = writeln!(out, "  \"git_dirty\": {},", provenance.git_dirty);
    out.push_str("  \"host\": {\n");
    let _ = writeln!(out, "    \"kernel\": {},", json_string(&provenance.kernel));
    let _ = writeln!(
        out,
        "    \"machine\": {},",
        json_string(&provenance.machine)
    );
    let _ = writeln!(out, "    \"cpus\": {}", provenance.cpus);
    out.push_str("  },\n");
    out.push_str("  \"field_notes\": {\n");
    out.push_str("    \"sender\": \"every `key=value` token of raw_sender_stdout, parsed; `tx_pool=free/capacity` is expanded to tx_pool_free/tx_pool_capacity\",\n");
    out.push_str("    \"receiver\": \"every `key=value` token of raw_receiver_stdout, parsed\",\n");
    out.push_str(
        "    \"raw_sender_stdout\": \"the harness's own output line for this run, verbatim\",\n",
    );
    out.push_str("    \"raw_receiver_stdout\": \"the receiver process's STATS line for this run, verbatim\"\n");
    out.push_str("  },\n");
    out.push_str("  \"rows\": [\n");
    for (index, run) in runs.iter().enumerate() {
        out.push_str("    {\n");
        let _ = writeln!(out, "      \"fanout\": {},", run.fanout);
        let _ = writeln!(
            out,
            "      \"raw_sender_stdout\": {},",
            json_string(&run.raw_sender_stdout)
        );
        let _ = writeln!(
            out,
            "      \"raw_receiver_stdout\": {},",
            json_string(&run.raw_receiver_stdout)
        );
        write_map(&mut out, "sender", &run.sender);
        write_map(&mut out, "receiver", &run.receiver);
        out.push_str("      \"row_end\": true\n");
        out.push_str("    }");
        if index + 1 != runs.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

fn write_map(out: &mut String, label: &str, map: &BTreeMap<String, EvidenceValue>) {
    let _ = writeln!(out, "      \"{label}\": {{");
    for (index, (key, value)) in map.iter().enumerate() {
        let comma = if index + 1 == map.len() { "" } else { "," };
        let rendered = match value {
            EvidenceValue::Int(int) => int.to_string(),
            EvidenceValue::Float(float) => {
                // Keep fractional precision; the harness prints up to 3 places.
                let mut s = format!("{float}");
                if !s.contains('.') && !s.contains('e') && !s.contains('E') {
                    s.push_str(".0");
                }
                s
            }
            EvidenceValue::Bool(flag) => flag.to_string(),
            EvidenceValue::Text(text) => json_string(text),
        };
        let _ = writeln!(out, "        {}: {}{comma}", json_string(key), rendered);
    }
    out.push_str("      },\n");
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete sender line, including the fractional fields whose earlier
    /// transcription became `null`.
    const SENDER: &str = "SHARED_OWNER_QUAL fanout=100 tx_lanes=256 connect_cc=64 desired=100 \
issued=100 admitted=100 queued=36 refused=0 established=100 pre_window_drained=true \
expected_ticks=2279 generated_ticks=2278 missed_source_ticks=1 data_offered=227800 \
data_accepted=227800 tx_submitted_wire=271834 tx_completed=271599 short=0 failed=0 \
peer_local=0 transient=0 tx_failures_pending=0 service_visits=2278 lateness_us_p50=367 \
p99=1077 max=3011 drain_ok=true inflight_at_window_end=235 drain_submitted=62 \
drain_completed=297 pending_after_drain=0 rx_mode=Some(RawReadiness) managed_rx=false \
rx_dropped=0 rx_truncated=0 tx_pool=256/256 cpu_ms=2525.6";

    const RECEIVER: &str = "STATS role=listener backend=compio connections=100 established=100 \
pkt_sent=227800 core_total=227800 sec_a=0 sec_b=0 rtt_ms=0.027 elapsed_s=3.307 \
throughput_pps=21344 cpu_user_ms=20.000 cpu_sys_ms=30.000 peak_rss_kb=28544";

    /// Every token of the input must come back as a parsed field: a parser that
    /// drops or renames a key silently loses evidence.
    #[test]
    fn parses_every_token_it_was_given() {
        let sender = parse_kv_line(SENDER, "SHARED_OWNER_QUAL").expect("sender parses");
        let receiver = parse_kv_line(RECEIVER, "STATS").expect("receiver parses");

        let tokens = |line: &str, prefix: &str| -> Vec<String> {
            line.strip_prefix(prefix)
                .unwrap_or(line)
                .split_whitespace()
                .map(|token| token.split_once('=').expect("key=value").0.to_string())
                .collect()
        };
        // `tx_pool` expands into two fields; everything else is 1:1.
        let mut expected_sender = tokens(SENDER, "SHARED_OWNER_QUAL");
        expected_sender.retain(|key| key != "tx_pool");
        expected_sender.push("tx_pool_free".to_string());
        expected_sender.push("tx_pool_capacity".to_string());
        expected_sender.sort();
        let mut parsed_sender: Vec<String> = sender.keys().cloned().collect();
        parsed_sender.sort();
        assert_eq!(parsed_sender, expected_sender, "sender field set");

        let mut expected_receiver = tokens(RECEIVER, "STATS");
        expected_receiver.sort();
        let mut parsed_receiver: Vec<String> = receiver.keys().cloned().collect();
        parsed_receiver.sort();
        assert_eq!(parsed_receiver, expected_receiver, "receiver field set");
    }

    /// Numeric-looking tokens must parse as numbers, never fall through to
    /// text: that fallback is exactly how `rtt_ms=0.027` became `null`.
    #[test]
    fn fractional_fields_parse_as_floats() {
        let receiver = parse_kv_line(RECEIVER, "STATS").expect("receiver parses");
        assert_eq!(receiver["rtt_ms"], EvidenceValue::Float(0.027));
        assert_eq!(receiver["elapsed_s"], EvidenceValue::Float(3.307));
        assert_eq!(receiver["cpu_user_ms"], EvidenceValue::Float(20.0));
        assert_eq!(receiver["cpu_sys_ms"], EvidenceValue::Float(30.0));
        assert_eq!(receiver["peak_rss_kb"], EvidenceValue::Int(28_544));
        assert_eq!(receiver["sec_a"], EvidenceValue::Int(0));

        let sender = parse_kv_line(SENDER, "SHARED_OWNER_QUAL").expect("sender parses");
        assert_eq!(sender["cpu_ms"], EvidenceValue::Float(2525.6));
        // No numeric-looking token may be Text.
        for (key, value) in sender.iter().chain(receiver.iter()) {
            let looks_numeric = matches!(value, EvidenceValue::Int(_) | EvidenceValue::Float(_));
            if let EvidenceValue::Text(text) = value {
                assert!(
                    text.parse::<f64>().is_err(),
                    "{key} looks numeric but parsed as text: {text:?}"
                );
            }
            let _ = looks_numeric;
        }
    }

    /// A malformed token is an error, never a silently smaller artifact.
    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(parse_kv_line("SHARED_OWNER_QUAL fanout=1 broken", "").is_err());
        assert!(parse_kv_line("SHARED_OWNER_QUAL tx_pool=256", "").is_err());
        assert!(parse_kv_line("SHARED_OWNER_QUAL tx_pool=x/256", "").is_err());
        assert!(parse_kv_line("SHARED_OWNER_QUAL latency=inf", "").is_err());
    }

    /// The reconciliation the harness asserts is re-checked when evidence is
    /// built, so an unreconciled row can never reach the committed artifact.
    #[test]
    fn parse_run_rejects_unreconciled_source_accounting() {
        let broken = SENDER.replace("missed_source_ticks=1", "missed_source_ticks=2");
        assert!(parse_run(&broken, RECEIVER).is_err());

        let run = parse_run(SENDER, RECEIVER).expect("valid run parses");
        assert_eq!(run.fanout, 100);
        assert_eq!(run.receiver["rtt_ms"], EvidenceValue::Float(0.027));
        assert!(run.raw_sender_stdout.starts_with("SHARED_OWNER_QUAL"));
        assert!(run.raw_receiver_stdout.starts_with("STATS"));
    }

    /// The rendered artifact must carry every parsed field of every run.
    #[test]
    fn rendered_json_carries_every_field_and_both_raw_lines() {
        let run = parse_run(SENDER, RECEIVER).expect("valid run parses");
        let provenance = Provenance {
            git_sha: "deadbeef".to_string(),
            git_dirty: false,
            kernel: "test".to_string(),
            machine: "x86_64".to_string(),
            cpus: 6,
        };
        let json = render_json(&provenance, std::slice::from_ref(&run));
        assert!(json.contains("\"git_dirty\": false"));
        for key in run.sender.keys().chain(run.receiver.keys()) {
            assert!(
                json.contains(&format!("\"{key}\":")),
                "rendered JSON is missing {key}"
            );
        }
        assert!(json.contains("\"rtt_ms\": 0.027"));
        assert!(!json.contains("null"), "no field may render as null");
        assert!(json.contains("SHARED_OWNER_QUAL fanout=100"));
    }
}
