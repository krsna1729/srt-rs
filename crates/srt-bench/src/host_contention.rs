//! Host-contention admission and evidence for timing-sensitive cells.
//!
//! Contention is an *environment* property, not a run property: it can
//! degrade offer/goodput without violating the canonical clean predicate.
//! This module therefore never redefines cleanliness. It only (1) waits for
//! a quiet host before a cell starts, (2) refuses or marks when the host is
//! not quiet, and (3) records the thresholds and observed signals on every
//! result row so a contaminated cell is never silently ordinary.
//!
//! Primary signal: `/proc/pressure/cpu` (PSI). Also memory/io PSI and
//! `/proc/stat` steal time. No process-name allow/deny lists — those miss
//! every workload nobody thought to enumerate. Load average is deliberately
//! unused: it lags for minutes after the campaign's own build and produces
//! false refusals.

use std::time::{Duration, Instant};

/// How the harness reacts when the host is (or becomes) contended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostContentionMode {
    /// Wait for quiet; on timeout refuse the cell. Mid-cell contention
    /// also fails the cell after the run (rows are still written and marked).
    Refuse,
    /// Always run. Contended cells are stamped in the result row and the
    /// matrix still exits 0 for that reason alone.
    Mark,
    /// Skip admission waits and never treat contention as a failure.
    /// Observed PSI/steal numbers are still recorded; status is `allowed`.
    /// For noisy CI / shared developer boxes.
    Allow,
}

impl HostContentionMode {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "refuse" => Some(Self::Refuse),
            "mark" => Some(Self::Mark),
            "allow" | "ignore" | "off" => Some(Self::Allow),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::Mark => "mark",
            Self::Allow => "allow",
        }
    }
}

/// Thresholds and reaction policy. Recorded per row via [`Self::fingerprint`].
#[derive(Clone, Debug, PartialEq)]
pub struct HostContentionPolicy {
    pub mode: HostContentionMode,
    /// CPU PSI `some avg10` percent above which the host is contended.
    pub cpu_psi_avg10_pct: f64,
    /// Memory PSI `some avg10` percent threshold.
    pub mem_psi_avg10_pct: f64,
    /// IO PSI `some avg10` percent threshold.
    pub io_psi_avg10_pct: f64,
    /// Fraction of cell wall time spent in CPU PSI `some` stalls (from the
    /// cumulative `total` counter), as a percent.
    pub cpu_stall_pct: f64,
    /// Steal time as a percent of CPU jiffies over the sampling window.
    pub steal_pct: f64,
    /// Bounded wait for a quiet host before starting a cell.
    pub admission_timeout_secs: u64,
    /// Poll interval while waiting for quiet.
    pub admission_poll_ms: u64,
}

impl Default for HostContentionPolicy {
    fn default() -> Self {
        Self {
            // Mark by default: contaminated rows are visible without failing
            // noisy CI that has not opted into hard admission yet.
            mode: HostContentionMode::Mark,
            cpu_psi_avg10_pct: 10.0,
            mem_psi_avg10_pct: 10.0,
            io_psi_avg10_pct: 10.0,
            cpu_stall_pct: 10.0,
            steal_pct: 5.0,
            admission_timeout_secs: 60,
            admission_poll_ms: 250,
        }
    }
}

impl HostContentionPolicy {
    /// Stable identity for the complete policy content (mode + thresholds).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        format!(
            "mode={};cpu_avg10={:.17};mem_avg10={:.17};io_avg10={:.17};cpu_stall={:.17};steal={:.17};timeout_s={};poll_ms={}",
            self.mode.as_str(),
            self.cpu_psi_avg10_pct,
            self.mem_psi_avg10_pct,
            self.io_psi_avg10_pct,
            self.cpu_stall_pct,
            self.steal_pct,
            self.admission_timeout_secs,
            self.admission_poll_ms,
        )
    }
}

/// One PSI resource line set (`some` / `full`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PsiResource {
    pub some_avg10: f64,
    pub some_total_us: u64,
    pub full_avg10: f64,
    pub full_total_us: u64,
    pub available: bool,
}

/// Snapshot of host contention signals at one instant.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct HostContentionSnapshot {
    pub cpu: PsiResource,
    pub memory: PsiResource,
    pub io: PsiResource,
    /// Aggregate `/proc/stat` steal jiffies.
    pub steal_jiffies: u64,
    /// Sum of all aggregate cpu jiffies (for steal fraction).
    pub cpu_jiffies: u64,
    pub steal_available: bool,
}

/// Verdict recorded on a result row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostContentionStatus {
    Quiet,
    Contended,
    /// PSI/steal unreadable (non-Linux, restricted /proc, …).
    Unknown,
    /// Operator opted out with `--host-contention=allow`.
    Allowed,
}

impl HostContentionStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quiet => "quiet",
            Self::Contended => "contended",
            Self::Unknown => "unknown",
            Self::Allowed => "allowed",
        }
    }
}

/// Evidence written beside measurements on every result row.
#[derive(Clone, Debug, PartialEq)]
pub struct HostContentionEvidence {
    pub status: HostContentionStatus,
    pub signals: Vec<&'static str>,
    pub policy_fingerprint: String,
    pub cpu_psi_some_avg10_pre: String,
    pub cpu_psi_some_avg10_post: String,
    pub cpu_psi_stall_pct: String,
    pub mem_psi_some_avg10_max: String,
    pub io_psi_some_avg10_max: String,
    pub steal_pct: String,
}

impl HostContentionEvidence {
    #[must_use]
    pub fn signals_joined(&self) -> String {
        self.signals.join(",")
    }
}

/// Outcome of the pre-cell admission wait.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionOutcome {
    Quiet,
    /// Timed out still contended; caller should refuse when mode is Refuse.
    Timeout {
        detail: String,
    },
    /// Mode is Allow, or signals are unavailable so we cannot gate.
    Skipped {
        reason: &'static str,
    },
}

/// Parse one `/proc/pressure/{cpu,memory,io}` document.
#[must_use]
pub fn parse_psi(text: &str) -> PsiResource {
    let mut resource = PsiResource::default();
    for line in text.lines() {
        let Some((kind, rest)) = line.split_once(' ') else {
            continue;
        };
        let (avg10, total) = parse_psi_kv(rest);
        apply_psi_kind(&mut resource, kind, avg10, total);
    }
    resource
}

fn parse_psi_kv(rest: &str) -> (Option<f64>, Option<u64>) {
    let mut avg10 = None;
    let mut total = None;
    for token in rest.split_whitespace() {
        if let Some(value) = token.strip_prefix("avg10=") {
            avg10 = value.parse().ok();
        } else if let Some(value) = token.strip_prefix("total=") {
            total = value.parse().ok();
        }
    }
    (avg10, total)
}

fn apply_psi_kind(resource: &mut PsiResource, kind: &str, avg10: Option<f64>, total: Option<u64>) {
    let (avg_slot, total_slot) = match kind {
        "some" => (&mut resource.some_avg10, &mut resource.some_total_us),
        "full" => (&mut resource.full_avg10, &mut resource.full_total_us),
        _ => return,
    };
    if let Some(v) = avg10 {
        *avg_slot = v;
    }
    if let Some(v) = total {
        *total_slot = v;
    }
    resource.available = true;
}

/// Parse aggregate steal and total jiffies from `/proc/stat`.
///
/// Returns `(steal, total_jiffies)`. `total` is the sum of every field on
/// the `cpu` line so a steal fraction is well-defined even when guest
/// fields are absent.
#[must_use]
pub fn parse_stat_steal(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|line| line.starts_with("cpu "))?;
    let mut fields = line.split_whitespace();
    let _cpu = fields.next()?;
    let values: Vec<u64> = fields.filter_map(|f| f.parse().ok()).collect();
    // user nice system idle iowait irq softirq steal [guest guest_nice]
    if values.len() < 8 {
        return None;
    }
    let steal = values[7];
    let total = values.iter().sum();
    Some((steal, total))
}

/// Sample the live host. Missing files yield `available = false` rather
/// than inventing zeros that look like a quiet machine.
#[must_use]
pub fn sample_host() -> HostContentionSnapshot {
    let read_psi = |path: &str| {
        std::fs::read_to_string(path)
            .map(|text| parse_psi(&text))
            .unwrap_or_default()
    };
    let mut snap = HostContentionSnapshot {
        cpu: read_psi("/proc/pressure/cpu"),
        memory: read_psi("/proc/pressure/memory"),
        io: read_psi("/proc/pressure/io"),
        ..HostContentionSnapshot::default()
    };
    if let Ok(text) = std::fs::read_to_string("/proc/stat")
        && let Some((steal, total)) = parse_stat_steal(&text)
    {
        snap.steal_jiffies = steal;
        snap.cpu_jiffies = total;
        snap.steal_available = true;
    }
    snap
}

/// Process-lifetime baseline, captured once so a result row can report a
/// before/after delta for *this* role run alone.
#[must_use]
pub fn baseline() -> HostContentionSnapshot {
    static BASELINE: std::sync::OnceLock<HostContentionSnapshot> = std::sync::OnceLock::new();
    *BASELINE.get_or_init(sample_host)
}

fn fmt_opt_f64(available: bool, value: f64) -> String {
    if available {
        format!("{value:.3}")
    } else {
        String::new()
    }
}

fn psi_exceeds(resource: PsiResource, threshold: f64) -> bool {
    resource.available && resource.some_avg10 > threshold
}

fn stall_pct(pre: PsiResource, post: PsiResource, elapsed: Duration) -> Option<f64> {
    if !pre.available || !post.available {
        return None;
    }
    let elapsed_us = elapsed.as_micros() as u64;
    if elapsed_us == 0 {
        return None;
    }
    let stalled = post.some_total_us.saturating_sub(pre.some_total_us);
    Some((stalled as f64) * 100.0 / (elapsed_us as f64))
}

fn steal_pct(pre: &HostContentionSnapshot, post: &HostContentionSnapshot) -> Option<f64> {
    if !pre.steal_available || !post.steal_available {
        return None;
    }
    let steal = post.steal_jiffies.saturating_sub(pre.steal_jiffies);
    let total = post.cpu_jiffies.saturating_sub(pre.cpu_jiffies);
    if total == 0 {
        return Some(0.0);
    }
    Some((steal as f64) * 100.0 / (total as f64))
}

/// Instantaneous level check used by admission (no before/after delta).
#[must_use]
pub fn instantaneous_signals(
    policy: &HostContentionPolicy,
    snap: &HostContentionSnapshot,
) -> Vec<&'static str> {
    let mut signals = Vec::new();
    if psi_exceeds(snap.cpu, policy.cpu_psi_avg10_pct) {
        signals.push("cpu_psi");
    }
    if psi_exceeds(snap.memory, policy.mem_psi_avg10_pct) {
        signals.push("mem_psi");
    }
    if psi_exceeds(snap.io, policy.io_psi_avg10_pct) {
        signals.push("io_psi");
    }
    // Steal needs a window; a single snapshot cannot compute a fraction.
    // Admission therefore keys on PSI only — steal is a mid-cell signal.
    let _ = snap.steal_available;
    signals
}

/// Wait until the host looks quiet, or until the policy timeout.
///
/// `allow` skips admission. `mark` probes once (and a short optional settle)
/// so a campaign still records evidence without blocking for a full timeout
/// on a chronically noisy host. `refuse` waits up to `admission_timeout_secs`.
pub fn wait_until_quiet(policy: &HostContentionPolicy) -> AdmissionOutcome {
    if policy.mode == HostContentionMode::Allow {
        return AdmissionOutcome::Skipped {
            reason: "host-contention=allow",
        };
    }
    let probe = sample_host();
    if !(probe.cpu.available || probe.memory.available || probe.io.available) {
        return AdmissionOutcome::Skipped {
            reason: "host pressure signals unavailable",
        };
    }

    let timeout_secs = match policy.mode {
        HostContentionMode::Refuse => policy.admission_timeout_secs,
        // Mark: brief settle only. Contended cells are stamped on the row;
        // spending the full refuse timeout would stall every noisy-CI cell.
        HostContentionMode::Mark => policy.admission_timeout_secs.min(2),
        HostContentionMode::Allow => 0,
    };
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let poll = Duration::from_millis(policy.admission_poll_ms.max(1));
    loop {
        let snap = sample_host();
        let signals = instantaneous_signals(policy, &snap);
        if signals.is_empty() {
            return AdmissionOutcome::Quiet;
        }
        if Instant::now() >= deadline {
            return AdmissionOutcome::Timeout {
                detail: format!(
                    "still contended after {}s ({})",
                    timeout_secs,
                    signals.join(",")
                ),
            };
        }
        std::thread::sleep(poll);
    }
}

/// Evaluate before/after samples against the policy.
#[must_use]
pub fn evaluate(
    policy: &HostContentionPolicy,
    pre: &HostContentionSnapshot,
    post: &HostContentionSnapshot,
    elapsed: Duration,
) -> HostContentionEvidence {
    let fingerprint = policy.fingerprint();
    let observed_steal = steal_pct(pre, post);
    let stall = stall_pct(pre.cpu, post.cpu, elapsed);

    if policy.mode == HostContentionMode::Allow {
        return build_evidence(
            HostContentionStatus::Allowed,
            Vec::new(),
            fingerprint,
            pre,
            post,
            stall,
            observed_steal,
        );
    }

    if !any_host_signal(pre, post) {
        return build_evidence(
            HostContentionStatus::Unknown,
            Vec::new(),
            fingerprint,
            pre,
            post,
            stall,
            observed_steal,
        );
    }

    let signals = collect_contention_signals(policy, pre, post, stall, observed_steal);
    let status = if signals.is_empty() {
        HostContentionStatus::Quiet
    } else {
        HostContentionStatus::Contended
    };
    build_evidence(
        status,
        signals,
        fingerprint,
        pre,
        post,
        stall,
        observed_steal,
    )
}

fn any_host_signal(pre: &HostContentionSnapshot, post: &HostContentionSnapshot) -> bool {
    pre.cpu.available
        || post.cpu.available
        || pre.memory.available
        || post.memory.available
        || pre.io.available
        || post.io.available
        || pre.steal_available
        || post.steal_available
}

fn collect_contention_signals(
    policy: &HostContentionPolicy,
    pre: &HostContentionSnapshot,
    post: &HostContentionSnapshot,
    stall: Option<f64>,
    observed_steal: Option<f64>,
) -> Vec<&'static str> {
    let mut signals = Vec::new();
    if psi_exceeds(pre.cpu, policy.cpu_psi_avg10_pct)
        || psi_exceeds(post.cpu, policy.cpu_psi_avg10_pct)
    {
        signals.push("cpu_psi");
    }
    if let Some(stall_pct_value) = stall
        && stall_pct_value > policy.cpu_stall_pct
    {
        signals.push("cpu_stall");
    }
    let mem_max = pre.memory.some_avg10.max(post.memory.some_avg10);
    if (pre.memory.available || post.memory.available) && mem_max > policy.mem_psi_avg10_pct {
        signals.push("mem_psi");
    }
    let io_max = pre.io.some_avg10.max(post.io.some_avg10);
    if (pre.io.available || post.io.available) && io_max > policy.io_psi_avg10_pct {
        signals.push("io_psi");
    }
    if let Some(steal) = observed_steal
        && steal > policy.steal_pct
    {
        signals.push("steal");
    }
    signals
}

fn build_evidence(
    status: HostContentionStatus,
    signals: Vec<&'static str>,
    policy_fingerprint: String,
    pre: &HostContentionSnapshot,
    post: &HostContentionSnapshot,
    stall: Option<f64>,
    observed_steal: Option<f64>,
) -> HostContentionEvidence {
    let mem_available = pre.memory.available || post.memory.available;
    let io_available = pre.io.available || post.io.available;
    HostContentionEvidence {
        status,
        signals,
        policy_fingerprint,
        cpu_psi_some_avg10_pre: fmt_opt_f64(pre.cpu.available, pre.cpu.some_avg10),
        cpu_psi_some_avg10_post: fmt_opt_f64(post.cpu.available, post.cpu.some_avg10),
        cpu_psi_stall_pct: stall.map(|v| format!("{v:.3}")).unwrap_or_default(),
        mem_psi_some_avg10_max: fmt_opt_f64(
            mem_available,
            pre.memory.some_avg10.max(post.memory.some_avg10),
        ),
        io_psi_some_avg10_max: fmt_opt_f64(io_available, pre.io.some_avg10.max(post.io.some_avg10)),
        steal_pct: match observed_steal {
            Some(v) => format!("{v:.3}"),
            None if pre.steal_available || post.steal_available => "0.000".to_string(),
            None => String::new(),
        },
    }
}

/// Parse policy flags from CLI. Unknown `--host-contention` values error.
pub fn policy_from_cli(cli: &crate::Cli) -> Result<HostContentionPolicy, String> {
    let mut policy = HostContentionPolicy::default();

    // Discoverable opt-out aliases for noisy CI.
    if cli.flags.contains_key("allow-host-contention") {
        let raw = cli
            .flags
            .get("allow-host-contention")
            .map(String::as_str)
            .unwrap_or("");
        if raw.is_empty() || matches!(raw, "1" | "true" | "on" | "yes") {
            policy.mode = HostContentionMode::Allow;
        } else if matches!(raw, "0" | "false" | "off" | "no") {
            // leave default / explicit --host-contention
        } else {
            return Err(format!(
                "unknown --allow-host-contention value {raw:?} (want on/off, or omit the value)"
            ));
        }
    }

    if let Some(raw) = cli.flags.get("host-contention") {
        let Some(mode) = HostContentionMode::parse(raw) else {
            return Err(format!(
                "unknown --host-contention {raw:?} (want refuse|mark|allow)"
            ));
        };
        policy.mode = mode;
    }

    policy.cpu_psi_avg10_pct = flag_f64(cli, "host-cpu-psi-avg10", policy.cpu_psi_avg10_pct)?;
    policy.mem_psi_avg10_pct = flag_f64(cli, "host-mem-psi-avg10", policy.mem_psi_avg10_pct)?;
    policy.io_psi_avg10_pct = flag_f64(cli, "host-io-psi-avg10", policy.io_psi_avg10_pct)?;
    policy.cpu_stall_pct = flag_f64(cli, "host-cpu-stall-pct", policy.cpu_stall_pct)?;
    policy.steal_pct = flag_f64(cli, "host-steal-pct", policy.steal_pct)?;
    policy.admission_timeout_secs = flag_u64(
        cli,
        "host-contention-timeout-secs",
        policy.admission_timeout_secs,
    )?;
    policy.admission_poll_ms = flag_u64(cli, "host-contention-poll-ms", policy.admission_poll_ms)?;
    Ok(policy)
}

/// Forward the parent's policy to matrix children so rows record the same
/// thresholds the operator asked for.
#[must_use]
pub fn policy_argv(policy: &HostContentionPolicy) -> Vec<String> {
    vec![
        format!("--host-contention={}", policy.mode.as_str()),
        format!("--host-cpu-psi-avg10={}", policy.cpu_psi_avg10_pct),
        format!("--host-mem-psi-avg10={}", policy.mem_psi_avg10_pct),
        format!("--host-io-psi-avg10={}", policy.io_psi_avg10_pct),
        format!("--host-cpu-stall-pct={}", policy.cpu_stall_pct),
        format!("--host-steal-pct={}", policy.steal_pct),
        format!(
            "--host-contention-timeout-secs={}",
            policy.admission_timeout_secs
        ),
        format!("--host-contention-poll-ms={}", policy.admission_poll_ms),
    ]
}

fn flag_f64(cli: &crate::Cli, name: &str, default: f64) -> Result<f64, String> {
    match cli.flags.get(name) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<f64>()
            .map_err(|_| format!("--{name} must be a number, got {raw:?}")),
    }
}

fn flag_u64(cli: &crate::Cli, name: &str, default: u64) -> Result<u64, String> {
    match cli.flags.get(name) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| format!("--{name} must be an unsigned integer, got {raw:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PSI: &str = "\
some avg10=12.50 avg60=1.00 avg300=0.50 total=1000000
full avg10=0.10 avg60=0.00 avg300=0.00 total=1000
";

    #[test]
    fn parse_psi_reads_some_and_full() {
        let psi = parse_psi(SAMPLE_PSI);
        assert!(psi.available);
        assert!((psi.some_avg10 - 12.5).abs() < f64::EPSILON);
        assert_eq!(psi.some_total_us, 1_000_000);
        assert!((psi.full_avg10 - 0.1).abs() < f64::EPSILON);
        assert_eq!(psi.full_total_us, 1_000);
    }

    #[test]
    fn parse_psi_empty_is_unavailable() {
        let psi = parse_psi("");
        assert!(!psi.available);
        assert_eq!(psi.some_total_us, 0);
    }

    #[test]
    fn parse_stat_steal_reads_eighth_field() {
        let text = "\
cpu  100 0 50 1000 0 0 10 25 0 0
cpu0 50 0 25 500 0 0 5 10 0 0
";
        let (steal, total) = parse_stat_steal(text).expect("steal");
        assert_eq!(steal, 25);
        assert_eq!(
            total,
            [100, 0, 50, 1000, 0, 0, 10, 25, 0, 0].iter().sum::<u64>()
        );
    }

    #[test]
    fn evaluate_marks_cpu_psi_from_post_sample() {
        let policy = HostContentionPolicy {
            mode: HostContentionMode::Mark,
            cpu_psi_avg10_pct: 10.0,
            ..HostContentionPolicy::default()
        };
        let pre = HostContentionSnapshot {
            cpu: PsiResource {
                some_avg10: 0.0,
                some_total_us: 1_000_000,
                available: true,
                ..PsiResource::default()
            },
            ..HostContentionSnapshot::default()
        };
        let mut post = pre;
        post.cpu.some_avg10 = 15.0;
        post.cpu.some_total_us = 1_000_000;
        let evidence = evaluate(&policy, &pre, &post, Duration::from_secs(8));
        assert_eq!(evidence.status, HostContentionStatus::Contended);
        assert!(evidence.signals.contains(&"cpu_psi"));
        assert!(evidence.policy_fingerprint.contains("mode=mark"));
    }

    #[test]
    fn evaluate_detects_mid_cell_stall_delta() {
        let policy = HostContentionPolicy {
            mode: HostContentionMode::Refuse,
            cpu_psi_avg10_pct: 99.0, // avg10 alone would not fire
            cpu_stall_pct: 10.0,
            ..HostContentionPolicy::default()
        };
        let pre = HostContentionSnapshot {
            cpu: PsiResource {
                some_avg10: 0.0,
                some_total_us: 1_000_000,
                available: true,
                ..PsiResource::default()
            },
            ..HostContentionSnapshot::default()
        };
        let mut post = pre;
        // 2_000_000 us stalled over an 8s (8_000_000 us) cell => 25%.
        post.cpu.some_total_us = 3_000_000;
        let evidence = evaluate(&policy, &pre, &post, Duration::from_secs(8));
        assert_eq!(evidence.status, HostContentionStatus::Contended);
        assert!(evidence.signals.contains(&"cpu_stall"));
        assert_eq!(evidence.cpu_psi_stall_pct, "25.000");
    }

    #[test]
    fn evaluate_detects_steal() {
        let policy = HostContentionPolicy {
            mode: HostContentionMode::Mark,
            steal_pct: 5.0,
            cpu_psi_avg10_pct: 99.0,
            mem_psi_avg10_pct: 99.0,
            io_psi_avg10_pct: 99.0,
            cpu_stall_pct: 99.0,
            ..HostContentionPolicy::default()
        };
        let pre = HostContentionSnapshot {
            steal_jiffies: 100,
            cpu_jiffies: 10_000,
            steal_available: true,
            ..HostContentionSnapshot::default()
        };
        let post = HostContentionSnapshot {
            steal_jiffies: 200,  // +100
            cpu_jiffies: 11_000, // +1000 => 10% steal
            steal_available: true,
            ..HostContentionSnapshot::default()
        };
        let evidence = evaluate(&policy, &pre, &post, Duration::from_secs(1));
        assert_eq!(evidence.status, HostContentionStatus::Contended);
        assert!(evidence.signals.contains(&"steal"));
    }

    #[test]
    fn allow_mode_never_contends() {
        let policy = HostContentionPolicy {
            mode: HostContentionMode::Allow,
            ..HostContentionPolicy::default()
        };
        let snap = HostContentionSnapshot {
            cpu: PsiResource {
                some_avg10: 90.0,
                some_total_us: 1,
                available: true,
                ..PsiResource::default()
            },
            ..HostContentionSnapshot::default()
        };
        let evidence = evaluate(&policy, &snap, &snap, Duration::from_secs(1));
        assert_eq!(evidence.status, HostContentionStatus::Allowed);
        assert!(evidence.signals.is_empty());
    }

    #[test]
    fn opt_out_cli_sets_allow() {
        let args = vec!["srt-bench".into(), "--allow-host-contention".into()];
        // Cli::parse starts at index 1 when given args[1..] style — pass full argv.
        let cli = crate::Cli::parse(&args);
        let policy = policy_from_cli(&cli).expect("parse");
        assert_eq!(policy.mode, HostContentionMode::Allow);
    }

    #[test]
    fn host_contention_cli_refuse() {
        let args = vec![
            "srt-bench".into(),
            "--host-contention=refuse".into(),
            "--host-cpu-psi-avg10=5".into(),
        ];
        let cli = crate::Cli::parse(&args);
        let policy = policy_from_cli(&cli).expect("parse");
        assert_eq!(policy.mode, HostContentionMode::Refuse);
        assert!((policy.cpu_psi_avg10_pct - 5.0).abs() < f64::EPSILON);
        assert!(policy.fingerprint().contains("mode=refuse"));
        assert!(policy.fingerprint().contains("cpu_avg10=5"));
    }

    #[test]
    fn quiet_when_below_thresholds() {
        let policy = HostContentionPolicy::default();
        let snap = HostContentionSnapshot {
            cpu: PsiResource {
                some_avg10: 1.0,
                some_total_us: 100,
                available: true,
                ..PsiResource::default()
            },
            steal_available: true,
            steal_jiffies: 0,
            cpu_jiffies: 1000,
            ..HostContentionSnapshot::default()
        };
        let evidence = evaluate(&policy, &snap, &snap, Duration::from_secs(5));
        assert_eq!(evidence.status, HostContentionStatus::Quiet);
        assert!(evidence.signals.is_empty());
    }
}
