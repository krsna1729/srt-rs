//! A small, bounded qualification contract for the shipping transport path.
//!
//! The existing matrix remains useful for exploration. This module supplies
//! the fixed SRT-600 corpus used for promotion decisions: ten named scenarios,
//! four resource metrics, and a hard correctness gate. It intentionally does
//! not grow a second runtime; a runner records one row per scenario and this
//! module only validates and scores those rows.

use std::io::Read;
use std::path::Path;

pub const SCENARIO_COUNT: usize = 10;
pub const MAX_INPUT_BYTES: u64 = 64 * 1024;
pub const PLAN_COLUMNS: &[&str] = &[
    "scenario",
    "connections",
    "encryption",
    "impairment",
    "consumer",
];
pub const MEASUREMENT_COLUMNS: &[&str] = &[
    "scenario",
    "workload_id",
    "offered",
    "offered_bytes",
    "duration_ms",
    "delivered",
    "correctness_failures",
    "cpu_ms",
    "p99_lateness_us",
    "rss_kb",
    "syscalls",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    Clean,
    Fanout600,
    LossReorder,
    BurstLoss,
    EncryptedRotation,
    SlowConsumer,
    ConnectChurn,
    RelayAge,
    LibsrtInterop,
    BondedBroadcast,
}

impl Scenario {
    pub const ALL: [Self; SCENARIO_COUNT] = [
        Self::Clean,
        Self::Fanout600,
        Self::LossReorder,
        Self::BurstLoss,
        Self::EncryptedRotation,
        Self::SlowConsumer,
        Self::ConnectChurn,
        Self::RelayAge,
        Self::LibsrtInterop,
        Self::BondedBroadcast,
    ];

    pub const fn index(self) -> usize {
        match self {
            Self::Clean => 0,
            Self::Fanout600 => 1,
            Self::LossReorder => 2,
            Self::BurstLoss => 3,
            Self::EncryptedRotation => 4,
            Self::SlowConsumer => 5,
            Self::ConnectChurn => 6,
            Self::RelayAge => 7,
            Self::LibsrtInterop => 8,
            Self::BondedBroadcast => 9,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Clean => "clean-1",
            Self::Fanout600 => "fanout-600",
            Self::LossReorder => "loss-reorder",
            Self::BurstLoss => "burst-loss",
            Self::EncryptedRotation => "encrypted-rotation",
            Self::SlowConsumer => "slow-consumer",
            Self::ConnectChurn => "connect-churn",
            Self::RelayAge => "relay-age",
            Self::LibsrtInterop => "libsrt-interop",
            Self::BondedBroadcast => "bonded-broadcast",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|scenario| scenario.name() == value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScenarioSpec {
    pub scenario: Scenario,
    pub connections: usize,
    pub encryption: &'static str,
    pub impairment: &'static str,
    pub consumer: &'static str,
}

pub const SCENARIOS: [ScenarioSpec; SCENARIO_COUNT] = [
    ScenarioSpec {
        scenario: Scenario::Clean,
        connections: 1,
        encryption: "plain",
        impairment: "none",
        consumer: "normal",
    },
    ScenarioSpec {
        scenario: Scenario::Fanout600,
        connections: 600,
        encryption: "plain",
        impairment: "none",
        consumer: "normal",
    },
    ScenarioSpec {
        scenario: Scenario::LossReorder,
        connections: 600,
        encryption: "plain",
        impairment: "loss=1%,reorder=1%",
        consumer: "normal",
    },
    ScenarioSpec {
        scenario: Scenario::BurstLoss,
        connections: 600,
        encryption: "plain",
        impairment: "loss=5%",
        consumer: "normal",
    },
    ScenarioSpec {
        scenario: Scenario::EncryptedRotation,
        connections: 600,
        encryption: "aes256+rotation",
        impairment: "none",
        consumer: "normal",
    },
    ScenarioSpec {
        scenario: Scenario::SlowConsumer,
        connections: 600,
        encryption: "plain",
        impairment: "none",
        consumer: "one-slow-destination",
    },
    ScenarioSpec {
        scenario: Scenario::ConnectChurn,
        connections: 600,
        encryption: "plain",
        impairment: "connect-disconnect-churn",
        consumer: "normal",
    },
    ScenarioSpec {
        scenario: Scenario::RelayAge,
        connections: 600,
        encryption: "plain",
        impairment: "one-hop-relay",
        consumer: "normal",
    },
    ScenarioSpec {
        scenario: Scenario::LibsrtInterop,
        connections: 600,
        encryption: "plain",
        impairment: "libsrt-peer",
        consumer: "normal",
    },
    ScenarioSpec {
        scenario: Scenario::BondedBroadcast,
        connections: 600,
        encryption: "plain",
        impairment: "bonded-broadcast",
        consumer: "normal",
    },
];

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Measurement {
    /// Stable digest/ID of the complete workload contract (rate, shape,
    /// runtime, topology, seed and repetitions). Baseline and candidate must
    /// carry the same ID before resource totals are compared.
    pub workload_id: u64,
    pub offered: u64,
    pub offered_bytes: u64,
    pub duration_ms: u64,
    pub delivered: u64,
    pub correctness_failures: u64,
    pub cpu_ms: f64,
    pub p99_lateness_us: f64,
    pub rss_kb: f64,
    pub syscalls: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QualificationPolicy {
    pub required_delivery_ratio: f64,
    pub max_noise_ratio: f64,
    pub complexity_lambda: f64,
    pub production_loc_delta: f64,
}

impl Default for QualificationPolicy {
    fn default() -> Self {
        Self {
            required_delivery_ratio: 0.99,
            max_noise_ratio: 0.03,
            complexity_lambda: 0.0,
            production_loc_delta: 0.0,
        }
    }
}

impl QualificationPolicy {
    pub fn validate(self) -> Result<Self, String> {
        if !(0.0..=1.0).contains(&self.required_delivery_ratio) {
            return Err("required delivery ratio must be between 0 and 1".into());
        }
        if !self.max_noise_ratio.is_finite() || self.max_noise_ratio < 0.0 {
            return Err("noise ratio must be finite and non-negative".into());
        }
        if !self.complexity_lambda.is_finite() || self.complexity_lambda < 0.0 {
            return Err("complexity lambda must be finite and non-negative".into());
        }
        if !self.production_loc_delta.is_finite() {
            return Err("production LOC delta must be finite".into());
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScenarioResult {
    pub scenario: Scenario,
    pub passed: bool,
    pub score: f64,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct QualificationReport {
    pub passed: bool,
    pub score: f64,
    pub scenarios: [ScenarioResult; SCENARIO_COUNT],
}

pub fn read_measurements(path: &Path) -> Result<[Measurement; SCENARIO_COUNT], String> {
    let text = read_bounded_text(path)?;
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| format!("{}: empty file", path.display()))?;
    if header.split('\t').collect::<Vec<_>>() != MEASUREMENT_COLUMNS {
        return Err(format!(
            "{}: unexpected qualification header",
            path.display()
        ));
    }
    let mut rows = [None; SCENARIO_COUNT];
    let mut row_count = 0usize;
    for (line_number, line) in lines.enumerate() {
        let Some((scenario, measurement)) = parse_measurement_line(path, line_number, line)? else {
            continue;
        };
        if row_count >= SCENARIO_COUNT {
            return Err(format!(
                "{}: more than {SCENARIO_COUNT} scenarios",
                path.display()
            ));
        }
        row_count += 1;
        if rows[scenario.index()].replace(measurement).is_some() {
            return Err(format!(
                "{}:{}: duplicate scenario {}",
                path.display(),
                line_number + 2,
                scenario.name()
            ));
        }
    }
    let mut measurements = [Measurement::default(); SCENARIO_COUNT];
    for index in 0..SCENARIO_COUNT {
        measurements[index] = rows[index].ok_or_else(|| {
            format!(
                "{}: missing scenario {}",
                path.display(),
                Scenario::ALL[index].name()
            )
        })?;
    }
    Ok(measurements)
}

fn read_bounded_text(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{}: qualification input must be a regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "{}: qualification input exceeds {MAX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    let mut text = String::new();
    let mut reader = file.take(MAX_INPUT_BYTES + 1);
    reader
        .read_to_string(&mut text)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if text.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!(
            "{}: qualification input exceeds {MAX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    Ok(text)
}

fn parse_measurement_line(
    path: &Path,
    line_number: usize,
    line: &str,
) -> Result<Option<(Scenario, Measurement)>, String> {
    if line.trim().is_empty() {
        return Ok(None);
    }
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != MEASUREMENT_COLUMNS.len() {
        return Err(format!(
            "{}:{}: expected {} fields",
            path.display(),
            line_number + 2,
            MEASUREMENT_COLUMNS.len()
        ));
    }
    let scenario = Scenario::parse(fields[0]).ok_or_else(|| {
        format!(
            "{}:{}: unknown scenario {:?}",
            path.display(),
            line_number + 2,
            fields[0]
        )
    })?;
    let measurement = Measurement {
        workload_id: parse_u64(fields[1], path, line_number)?,
        offered: parse_u64(fields[2], path, line_number)?,
        offered_bytes: parse_u64(fields[3], path, line_number)?,
        duration_ms: parse_u64(fields[4], path, line_number)?,
        delivered: parse_u64(fields[5], path, line_number)?,
        correctness_failures: parse_u64(fields[6], path, line_number)?,
        cpu_ms: parse_metric(fields[7], path, line_number)?,
        p99_lateness_us: parse_metric(fields[8], path, line_number)?,
        rss_kb: parse_metric(fields[9], path, line_number)?,
        syscalls: parse_metric(fields[10], path, line_number)?,
    };
    Ok(Some((scenario, measurement)))
}

fn parse_u64(value: &str, path: &Path, line: usize) -> Result<u64, String> {
    value.parse().map_err(|_| {
        format!(
            "{}:{}: invalid integer {:?}",
            path.display(),
            line + 2,
            value
        )
    })
}

fn parse_metric(value: &str, path: &Path, line: usize) -> Result<f64, String> {
    let metric: f64 = value.parse().map_err(|_| {
        format!(
            "{}:{}: invalid metric {:?}",
            path.display(),
            line + 2,
            value
        )
    })?;
    if !metric.is_finite() || metric <= 0.0 {
        return Err(format!(
            "{}:{}: metric must be finite and positive",
            path.display(),
            line + 2
        ));
    }
    Ok(metric)
}

pub fn evaluate(
    baseline: [Measurement; SCENARIO_COUNT],
    candidate: [Measurement; SCENARIO_COUNT],
    policy: QualificationPolicy,
) -> Result<QualificationReport, String> {
    let policy = policy.validate()?;
    let mut product_log = 0.0;
    let mut scenarios = std::array::from_fn(|index| ScenarioResult {
        scenario: Scenario::ALL[index],
        passed: false,
        score: 0.0,
        reason: String::new(),
    });
    let mut all_passed = true;
    for index in 0..SCENARIO_COUNT {
        let (result, contribution) = evaluate_scenario(
            Scenario::ALL[index],
            baseline[index],
            candidate[index],
            policy,
        );
        all_passed &= result.passed;
        product_log += contribution.unwrap_or(0.0);
        scenarios[index] = result;
    }
    let penalty = (-policy.complexity_lambda * policy.production_loc_delta.max(0.0)).exp();
    let score = if all_passed {
        (product_log / SCENARIO_COUNT as f64).exp() * penalty
    } else {
        0.0
    };
    Ok(QualificationReport {
        passed: all_passed,
        score,
        scenarios,
    })
}

fn evaluate_scenario(
    scenario: Scenario,
    baseline: Measurement,
    candidate: Measurement,
    policy: QualificationPolicy,
) -> (ScenarioResult, Option<f64>) {
    let mut result = ScenarioResult {
        scenario,
        passed: false,
        score: 0.0,
        reason: String::new(),
    };
    if !same_workload(baseline, candidate) {
        result.reason = "baseline and candidate use different workloads".into();
        return (result, None);
    }
    let baseline_ok = correctness_ok(baseline, policy.required_delivery_ratio);
    let candidate_ok = correctness_ok(candidate, policy.required_delivery_ratio);
    if !baseline_ok || !candidate_ok {
        result.reason = if !baseline_ok {
            "baseline violates the correctness gate"
        } else {
            "candidate violates the correctness gate"
        }
        .into();
        return (result, None);
    }
    let ratios = [
        candidate.cpu_ms / baseline.cpu_ms,
        candidate.p99_lateness_us / baseline.p99_lateness_us,
        candidate.rss_kb / baseline.rss_kb,
        candidate.syscalls / baseline.syscalls,
    ];
    if ratios
        .iter()
        .any(|ratio| *ratio > 1.0 + policy.max_noise_ratio)
    {
        result.reason = "candidate regresses beyond the noise budget".into();
        return (result, None);
    }
    let log_score = ratios.iter().map(|ratio| -ratio.ln()).sum::<f64>() / ratios.len() as f64;
    result.score = log_score.exp();
    if result.score < 1.0 {
        result.reason = "candidate is not a resource non-regression".into();
        return (result, None);
    }
    result.passed = true;
    result.reason = "pass".into();
    (result, Some(log_score))
}

fn correctness_ok(measurement: Measurement, required_delivery_ratio: f64) -> bool {
    measurement.workload_id > 0
        && measurement.offered > 0
        && measurement.offered_bytes > 0
        && measurement.duration_ms > 0
        && measurement.delivered <= measurement.offered
        && measurement.correctness_failures == 0
        && (measurement.delivered as f64 / measurement.offered as f64) >= required_delivery_ratio
        && [
            measurement.cpu_ms,
            measurement.p99_lateness_us,
            measurement.rss_kb,
            measurement.syscalls,
        ]
        .iter()
        .all(|metric| metric.is_finite() && *metric > 0.0)
}

fn same_workload(baseline: Measurement, candidate: Measurement) -> bool {
    baseline.workload_id == candidate.workload_id
        && baseline.offered == candidate.offered
        && baseline.offered_bytes == candidate.offered_bytes
        && baseline.duration_ms == candidate.duration_ms
}

pub fn render_plan() -> String {
    let mut output = PLAN_COLUMNS.join("\t");
    output.push('\n');
    for spec in SCENARIOS {
        output.push_str(spec.scenario.name());
        output.push('\t');
        output.push_str(&spec.connections.to_string());
        output.push('\t');
        output.push_str(spec.encryption);
        output.push('\t');
        output.push_str(spec.impairment);
        output.push('\t');
        output.push_str(spec.consumer);
        output.push('\n');
    }
    output
}

pub fn render_report(report: &QualificationReport) -> String {
    let mut output = format!(
        "passed={}\tscore={:.6}\nscenario\tpassed\tscore\treason\n",
        report.passed, report.score
    );
    for result in &report.scenarios {
        output.push_str(result.scenario.name());
        output.push('\t');
        output.push_str(if result.passed { "true" } else { "false" });
        output.push('\t');
        output.push_str(&format!("{:.6}\t{}\n", result.score, result.reason));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurement() -> Measurement {
        Measurement {
            workload_id: 1,
            offered: 100,
            offered_bytes: 131_600,
            duration_ms: 1_000,
            delivered: 100,
            correctness_failures: 0,
            cpu_ms: 10.0,
            p99_lateness_us: 10.0,
            rss_kb: 100.0,
            syscalls: 100.0,
        }
    }

    #[test]
    fn corpus_is_fixed_and_bounded() {
        assert_eq!(SCENARIOS.len(), SCENARIO_COUNT);
        assert_eq!(Scenario::ALL.len(), SCENARIO_COUNT);
        assert!(render_plan().lines().count() <= SCENARIO_COUNT + 1);
    }

    #[test]
    fn score_requires_correctness_and_rejects_large_regressions() {
        let baseline = [measurement(); SCENARIO_COUNT];
        let mut candidate = baseline;
        candidate[Scenario::Fanout600.index()].cpu_ms = 20.0;
        let report = evaluate(baseline, candidate, QualificationPolicy::default()).expect("score");
        assert!(!report.passed);
        assert_eq!(report.score, 0.0);

        candidate = baseline;
        candidate[Scenario::Clean.index()].delivered = 98;
        let report = evaluate(baseline, candidate, QualificationPolicy::default()).expect("score");
        assert!(!report.passed);
        assert_eq!(report.score, 0.0);

        candidate = baseline;
        for measurement in &mut candidate {
            measurement.cpu_ms *= 1.02;
            measurement.p99_lateness_us *= 1.02;
            measurement.rss_kb *= 1.02;
            measurement.syscalls *= 1.02;
        }
        let report = evaluate(baseline, candidate, QualificationPolicy::default()).expect("score");
        assert!(!report.passed, "an aggregate resource regression must fail");
    }

    #[test]
    fn score_is_geometric_and_rewards_a_uniform_improvement() {
        let baseline = [measurement(); SCENARIO_COUNT];
        let mut candidate = baseline;
        for measurement in &mut candidate {
            measurement.cpu_ms = 5.0;
            measurement.p99_lateness_us = 5.0;
            measurement.rss_kb = 50.0;
            measurement.syscalls = 50.0;
        }
        let report = evaluate(baseline, candidate, QualificationPolicy::default()).expect("score");
        assert!(report.passed);
        assert!((report.score - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn measurement_reader_rejects_non_regular_inputs() {
        let path =
            std::env::temp_dir().join(format!("srt600-qualification-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).expect("temporary directory");
        let error = read_measurements(&path).expect_err("directories are not measurements");
        std::fs::remove_dir(&path).expect("temporary directory cleanup");
        assert!(error.contains("regular file"));
    }

    #[test]
    fn mismatched_workloads_and_zero_metrics_fail_closed() {
        let baseline = [measurement(); SCENARIO_COUNT];
        let mut candidate = baseline;
        candidate[Scenario::Clean.index()].offered += 1;
        let report = evaluate(baseline, candidate, QualificationPolicy::default()).expect("score");
        assert!(!report.passed);

        candidate = baseline;
        candidate[Scenario::Clean.index()].syscalls = 0.0;
        let report = evaluate(baseline, candidate, QualificationPolicy::default()).expect("score");
        assert!(!report.passed);
    }
}
