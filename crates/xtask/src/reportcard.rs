use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde_json::{Value, json};

const ANALYZER_VERSION: &str = "0.0.25";
const MANIFEST_FILE: &str = "Cargo.toml";
const REPORT_DIR: &str = "target/reportcard";

#[derive(Clone, Debug)]
struct FunctionMetric {
    key: String,
    name: String,
    path: String,
    start_line: usize,
    end_line: usize,
    cyclomatic: u64,
    cognitive: u64,
}

#[derive(Default)]
struct Summary {
    files: usize,
    named_functions: usize,
    closures: usize,
    sloc: u64,
    cyclomatic: u64,
    cognitive: u64,
    units: Vec<FunctionMetric>,
}

#[derive(Clone, Debug)]
struct Limits {
    max_cyclomatic: u64,
    max_cognitive: u64,
}

#[derive(Clone, Debug)]
struct Violation {
    key: String,
    path: String,
    line: usize,
    metric: &'static str,
    actual: u64,
    limit: u64,
    reason: &'static str,
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    if let Err(message) = parse_args(args) {
        eprintln!("reportcard: {message}");
        eprintln!("usage: cargo xtask reportcard");
        return ExitCode::FAILURE;
    }
    let root = match env::current_dir() {
        Ok(path) => path,
        Err(error) => return fail("find repository root", error),
    };
    let summary = match analyze_sources(&root) {
        Ok(summary) => summary,
        Err(message) => {
            return fail("analyze Rust sources", message);
        }
    };
    let limits = match load_limits(&root) {
        Ok(limits) => limits,
        Err(error) => return fail("read Cargo.toml reportcard metadata", error),
    };

    let violations = check_limits(&summary, &limits);
    let markdown = render_markdown(&summary, &limits, &violations);
    if let Err(error) = write_reports(&root, &summary, &limits, &violations, &markdown) {
        return fail("write reportcard artifacts", error);
    }
    print!("{markdown}");

    if violations.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn parse_args(args: &[String]) -> Result<(), String> {
    if let Some(arg) = args.first() {
        return Err(format!("unknown argument {arg:?}"));
    }
    Ok(())
}

fn fail(action: &str, error: impl std::fmt::Display) -> ExitCode {
    eprintln!("reportcard: could not {action}: {error}");
    ExitCode::FAILURE
}

fn analyze_sources(root: &Path) -> io::Result<Summary> {
    let raw_files = run_analyzer(root)?;
    let mut summary = Summary::default();
    for path in raw_files {
        analyze_file(&path, &mut summary)?;
    }
    if summary.files == 0 || summary.units.is_empty() {
        return Err(io::Error::other(
            "no Rust source functions found under crates/*/src",
        ));
    }
    Ok(summary)
}

fn run_analyzer(root: &Path) -> io::Result<Vec<PathBuf>> {
    ensure_analyzer()?;
    let raw_directory = root.join(REPORT_DIR).join("raw");
    if raw_directory.exists() {
        fs::remove_dir_all(&raw_directory)?;
    }
    fs::create_dir_all(&raw_directory)?;
    let status = Command::new("rust-code-analysis-cli")
        .args([
            "-m", "-p", "crates", "-I", "*.rs", "--pr", "-O", "json", "-o",
        ])
        .arg(&raw_directory)
        .current_dir(root)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "rust-code-analysis-cli exited with {status}"
        )));
    }

    let mut raw_files = Vec::new();
    collect_json_files(&raw_directory, &mut raw_files)?;
    raw_files.sort();
    if raw_files.is_empty() {
        return Err(io::Error::other("analyzer produced no JSON files"));
    }
    Ok(raw_files)
}

fn analyze_file(path: &Path, summary: &mut Summary) -> io::Result<()> {
    let value: Value = serde_json::from_str(&fs::read_to_string(path)?)
        .map_err(|error| io::Error::other(format!("invalid analyzer JSON: {error}")))?;
    let relative = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("analyzer JSON is missing a file name"))?;
    if !Path::new(relative)
        .components()
        .any(|component| component.as_os_str() == "src")
    {
        return Ok(());
    }
    summary.files += 1;
    summary.sloc += metric_value(&value, "loc", "sloc");
    let mut scope_ordinals = HashMap::new();
    let mut function_ordinals = HashMap::new();
    if let Some(children) = value.get("spaces").and_then(Value::as_array) {
        for child in children {
            collect_functions(
                child,
                relative,
                None,
                &mut scope_ordinals,
                &mut function_ordinals,
                summary,
            );
        }
    }
    Ok(())
}

fn ensure_analyzer() -> io::Result<()> {
    let output = Command::new("rust-code-analysis-cli")
        .arg("--version")
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            if version
                .lines()
                .any(|line| line.trim_end().ends_with(ANALYZER_VERSION))
            {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "rust-code-analysis-cli {ANALYZER_VERSION} is required, found {:?}",
                    version.trim()
                )))
            }
        }
        Ok(output) => Err(io::Error::other(format!(
            "rust-code-analysis-cli {ANALYZER_VERSION} is required (status {})",
            output.status
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::other(
            "rust-code-analysis-cli is required; install it with `cargo install \\
             rust-code-analysis-cli --version 0.0.25 --locked`",
        )),
        Err(error) => Err(error),
    }
}

fn collect_json_files(path: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_json_files(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn metric_value(value: &Value, group: &str, metric: &str) -> u64 {
    value
        .get("metrics")
        .and_then(|metrics| metrics.get(group))
        .and_then(|group| group.get(metric))
        .and_then(Value::as_f64)
        .unwrap_or_default()
        .round() as u64
}

fn collect_functions(
    space: &Value,
    path: &str,
    parent_key: Option<&str>,
    scope_ordinals: &mut HashMap<String, usize>,
    function_ordinals: &mut HashMap<String, usize>,
    summary: &mut Summary,
) {
    let key = build_function_metric(space, path, parent_key, scope_ordinals, function_ordinals)
        .map(|metric| {
            let key = metric.key.clone();
            record_function(summary, metric);
            key
        });
    collect_children(
        space,
        path,
        key.as_deref().or(parent_key),
        function_ordinals,
        summary,
    );
}

fn build_function_metric(
    space: &Value,
    path: &str,
    parent_key: Option<&str>,
    scope_ordinals: &mut HashMap<String, usize>,
    function_ordinals: &mut HashMap<String, usize>,
) -> Option<FunctionMetric> {
    if space.get("kind").and_then(Value::as_str) != Some("function") {
        return None;
    }
    let name = space
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>")
        .to_string();
    let scope_ordinal = scope_ordinals.entry(name.clone()).or_default();
    let function_ordinal = function_ordinals.entry(name.clone()).or_default();
    let key = format!("{path}::{name}#{function_ordinal}");
    let key = if name == "<anonymous>" {
        parent_key.map_or_else(
            || key.clone(),
            |parent| format!("{parent}::<anonymous>#{scope_ordinal}"),
        )
    } else {
        key
    };
    *scope_ordinal += 1;
    *function_ordinal += 1;
    Some(FunctionMetric {
        key,
        name,
        path: path.to_string(),
        start_line: space
            .get("start_line")
            .and_then(Value::as_u64)
            .unwrap_or_default() as usize,
        end_line: space
            .get("end_line")
            .and_then(Value::as_u64)
            .unwrap_or_default() as usize,
        cyclomatic: own_metric(space, "cyclomatic"),
        cognitive: own_metric(space, "cognitive"),
    })
}

fn record_function(summary: &mut Summary, metric: FunctionMetric) {
    summary.cyclomatic += metric.cyclomatic;
    summary.cognitive += metric.cognitive;
    if metric.name == "<anonymous>" {
        summary.closures += 1;
    } else {
        summary.named_functions += 1;
    }
    summary.units.push(metric);
}

fn collect_children(
    space: &Value,
    path: &str,
    parent_key: Option<&str>,
    function_ordinals: &mut HashMap<String, usize>,
    summary: &mut Summary,
) {
    let Some(children) = space.get("spaces").and_then(Value::as_array) else {
        return;
    };
    let mut scope_ordinals = HashMap::new();
    for child in children {
        collect_functions(
            child,
            path,
            parent_key,
            &mut scope_ordinals,
            function_ordinals,
            summary,
        );
    }
}

fn own_metric(space: &Value, metric: &str) -> u64 {
    let total = metric_value(space, metric, "sum");
    let children = space
        .get("spaces")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|child| metric_value(child, metric, "sum"))
        .sum::<u64>();
    total.saturating_sub(children)
}

fn max_cyclomatic(summary: &Summary) -> u64 {
    summary
        .units
        .iter()
        .map(|unit| unit.cyclomatic)
        .max()
        .unwrap_or_default()
}

fn max_cognitive(summary: &Summary) -> u64 {
    summary
        .units
        .iter()
        .map(|unit| unit.cognitive)
        .max()
        .unwrap_or_default()
}

fn load_limits(root: &Path) -> io::Result<Limits> {
    let path = root.join(MANIFEST_FILE);
    let value: toml::Value = toml::from_str(&fs::read_to_string(path)?)
        .map_err(|error| io::Error::other(format!("invalid Cargo.toml: {error}")))?;
    let reportcard = value
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|workspace| workspace.get("metadata"))
        .and_then(toml::Value::as_table)
        .and_then(|metadata| metadata.get("reportcard"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| io::Error::other("Cargo.toml is missing workspace.metadata.reportcard"))?;
    let required = |name: &str| {
        reportcard
            .get(name)
            .and_then(toml::Value::as_integer)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| {
                io::Error::other(format!(
                    "workspace.metadata.reportcard.{name} must be a non-negative integer"
                ))
            })
    };
    Ok(Limits {
        max_cyclomatic: required("max_cyclomatic")?,
        max_cognitive: required("max_cognitive")?,
    })
}

fn check_limits(summary: &Summary, limits: &Limits) -> Vec<Violation> {
    let mut violations = Vec::new();
    for unit in &summary.units {
        check_metric(
            &mut violations,
            unit,
            "cyclomatic",
            unit.cyclomatic,
            limits.max_cyclomatic,
            "complexity limit",
        );
        check_metric(
            &mut violations,
            unit,
            "cognitive",
            unit.cognitive,
            limits.max_cognitive,
            "complexity limit",
        );
    }
    violations
}

fn check_metric(
    violations: &mut Vec<Violation>,
    unit: &FunctionMetric,
    metric: &'static str,
    actual: u64,
    limit: u64,
    reason: &'static str,
) {
    if actual > limit {
        violations.push(Violation {
            key: unit.key.clone(),
            path: unit.path.clone(),
            line: unit.start_line,
            metric,
            actual,
            limit,
            reason,
        });
    }
}

fn average(total: u64, count: usize) -> f64 {
    if count == 0 {
        0.0
    } else {
        total as f64 / count as f64
    }
}

fn percentile(summary: &Summary, cognitive: bool, percentile: f64) -> u64 {
    let mut values: Vec<_> = summary
        .units
        .iter()
        .map(|unit| {
            if cognitive {
                unit.cognitive
            } else {
                unit.cyclomatic
            }
        })
        .collect();
    values.sort_unstable();
    let index = ((values.len() as f64 * percentile).ceil() as usize).saturating_sub(1);
    values[index]
}

fn render_markdown(summary: &Summary, limits: &Limits, violations: &[Violation]) -> String {
    let units = summary.units.len();
    let status = if violations.is_empty() {
        "PASS"
    } else {
        "FAIL"
    };
    let mut output = format!("# srt-rs report card\n\nStatus: **{status}**\n\n");
    output.push_str("Scope: `crates/*/src/**/*.rs` (inline test modules included)\n\n");
    output.push_str("| Gate | Current | Limit | Result |\n|---|---:|---:|:---:|\n");
    output.push_str(&format!(
        "| Cyclomatic complexity | {} | {} | {} |\n",
        max_cyclomatic(summary),
        limits.max_cyclomatic,
        gate_for(summary, limits, false),
    ));
    output.push_str(&format!(
        "| Cognitive complexity | {} | {} | {} |\n",
        max_cognitive(summary),
        limits.max_cognitive,
        gate_for(summary, limits, true),
    ));
    output.push_str(&format!(
        "\nFunctions: {} named + {} closures · SLOC: {}\n\n",
        summary.named_functions, summary.closures, summary.sloc
    ));
    output.push_str(&format!(
        "Totals are informational: cyclomatic **{}** (avg {:.2}, p95 {}) · cognitive **{}** (avg {:.2}, p95 {}).\n\n",
        summary.cyclomatic,
        average(summary.cyclomatic, units),
        percentile(summary, false, 0.95),
        summary.cognitive,
        average(summary.cognitive, units),
        percentile(summary, true, 0.95),
    ));
    output
        .push_str("## Hotspots\n\n| Function | CC | Cognitive | Location |\n|---|---:|---:|---|\n");
    let mut hotspots = summary.units.clone();
    hotspots.sort_by_key(|unit| std::cmp::Reverse((unit.cognitive, unit.cyclomatic)));
    for unit in hotspots.iter().take(10) {
        output.push_str(&format!(
            "| `{}` | {} | {} | `{}`:{}-{} |\n",
            unit.name, unit.cyclomatic, unit.cognitive, unit.path, unit.start_line, unit.end_line,
        ));
    }
    if !violations.is_empty() {
        output.push_str("\n## Violations\n\n");
        for violation in violations {
            output.push_str(&format!(
                "- `{}` {}={} exceeds {} {} at `{}:{}`\n",
                violation.key,
                violation.metric,
                violation.actual,
                violation.reason,
                violation.limit,
                violation.path,
                violation.line,
            ));
        }
    }
    output
}

fn gate_for(summary: &Summary, limits: &Limits, cognitive: bool) -> &'static str {
    let passed = summary.units.iter().all(|unit| {
        if cognitive {
            unit.cognitive <= limits.max_cognitive
        } else {
            unit.cyclomatic <= limits.max_cyclomatic
        }
    });
    if passed { "PASS" } else { "FAIL" }
}

fn write_reports(
    root: &Path,
    summary: &Summary,
    limits: &Limits,
    violations: &[Violation],
    markdown: &str,
) -> io::Result<()> {
    let directory = root.join(REPORT_DIR);
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("reportcard.md"), markdown)?;
    let value = json!({
        "tool": {"name": "rust-code-analysis", "version": ANALYZER_VERSION},
        "scope": "crates/*/src/**/*.rs",
        "files": summary.files,
        "named_functions": summary.named_functions,
        "closures": summary.closures,
        "sloc": summary.sloc,
        "cyclomatic": {
            "total": summary.cyclomatic,
            "average": average(summary.cyclomatic, summary.units.len()),
            "p95": percentile(summary, false, 0.95),
            "max": max_cyclomatic(summary),
        },
        "cognitive": {
            "total": summary.cognitive,
            "average": average(summary.cognitive, summary.units.len()),
            "p95": percentile(summary, true, 0.95),
            "max": max_cognitive(summary),
        },
        "limits": {
            "max_cyclomatic": limits.max_cyclomatic,
            "max_cognitive": limits.max_cognitive,
        },
        "violations": violations.iter().map(|violation| json!({
            "key": violation.key,
            "path": violation.path,
            "line": violation.line,
            "metric": violation.metric,
            "actual": violation.actual,
            "limit": violation.limit,
            "reason": violation.reason,
        })).collect::<Vec<_>>(),
    });
    fs::write(
        directory.join("reportcard.json"),
        serde_json::to_vec_pretty(&value).expect("reportcard JSON is serializable"),
    )?;
    if let Some(path) = env::var_os("GITHUB_STEP_SUMMARY") {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(markdown.as_bytes())?;
    }
    Ok(())
}
