//! `cargo xtask ingest-matrix` -- rerun the ingest-scaling matrix on the
//! production listener.
//!
//! One command for a question that keeps coming back: what does each
//! listener layout (topology x promotion x cookie routing) cost per packet as
//! publishers grow? It builds `srt-bench` (the binary it runs, from cargo's own
//! artifact record, never a leftover), runs `srt-bench matrix` over
//! `docs/plans/ingest-scaling.plan` with interleaved repetitions, and prints the
//! report grouped by layout and publisher count. `rx_us/pkt` is the listener's
//! CPU per delivered packet; `deliv%` must stay at 100 for a cell to count.
//!
//! ```text
//! cargo xtask ingest-matrix                      # full plan, 3 reps
//! cargo xtask ingest-matrix --reps 1 --axis connections=50 --axis ingress=reuseport-multi:1
//! ```
//!
//! Anything after the known flags is passed to `srt-bench matrix` unchanged
//! (`--axis`, `--secs`, `--seed`, ...). The numbers guide the documented
//! defaults in `docs/owner-contract.md`; they never decide what is allowed.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

pub const PLAN: &str = "docs/plans/ingest-scaling.plan";
/// Result-file column names (the TSV schema, not the plan axis names).
pub const GROUP_BY: &str = "ingress,promotion,cookie,conns";

/// Parsed command line: the result file, repetitions, and pass-through
/// arguments for `srt-bench matrix`.
#[derive(Debug, PartialEq, Eq)]
pub struct Args {
    pub out: PathBuf,
    pub reps: usize,
    pub passthrough: Vec<String>,
}

pub fn parse(args: &[String], default_out: PathBuf) -> Result<Args, String> {
    let mut parsed = Args {
        out: default_out,
        reps: 3,
        passthrough: Vec::new(),
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--out" => {
                parsed.out = PathBuf::from(rest.next().ok_or("--out needs a path")?);
            }
            "--reps" => {
                let value = rest.next().ok_or("--reps needs a count")?;
                parsed.reps = value
                    .parse()
                    .ok()
                    .filter(|reps| *reps > 0)
                    .ok_or_else(|| format!("--reps must be a positive count, got '{value}'"))?;
            }
            "--plan" => {
                return Err(
                    "ingest-matrix always runs its own plan; pass --axis to narrow it".into(),
                );
            }
            _ => parsed.passthrough.push(arg.clone()),
        }
    }
    Ok(parsed)
}

/// `srt-bench matrix` arguments for one invocation.
pub fn matrix_argv(args: &Args) -> Vec<String> {
    let mut argv = vec![
        "matrix".to_string(),
        "--plan".into(),
        PLAN.into(),
        "--order".into(),
        "interleaved".into(),
        "--reps".into(),
        args.reps.to_string(),
        "--out".into(),
        args.out.display().to_string(),
    ];
    argv.extend(args.passthrough.iter().cloned());
    argv
}

pub fn run(root: &Path, args: &[String]) -> ExitCode {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let args = match parse(
        args,
        root.join(format!("scratch/ingest-matrix-{stamp}.tsv")),
    ) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("ingest-matrix: {error}");
            return ExitCode::from(2);
        }
    };
    let bench = match build_srt_bench(root) {
        Ok(bench) => bench,
        Err(error) => {
            eprintln!("ingest-matrix: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(parent) = args.out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let matrix = Command::new(&bench)
        .args(matrix_argv(&args))
        .current_dir(root)
        .status();
    if !matches!(matrix, Ok(status) if status.success()) {
        eprintln!(
            "ingest-matrix: srt-bench matrix failed ({matrix:?}); partial rows are in {}",
            args.out.display()
        );
    }
    let report = Command::new(&bench)
        .args(["report", &args.out.display().to_string(), "--by", GROUP_BY])
        .current_dir(root)
        .status();
    println!("ingest-matrix: results in {}", args.out.display());
    match (matrix, report) {
        (Ok(matrix), Ok(report)) if matrix.success() && report.success() => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// Release `srt-bench`, located through cargo's artifact record.
fn build_srt_bench(root: &Path) -> Result<PathBuf, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .args([
            "build",
            "--release",
            "-p",
            "srt-bench",
            "--bin",
            "srt-bench",
            "--message-format=json",
        ])
        .current_dir(root)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("running `{cargo} build`: {e}"))?;
    if !output.status.success() {
        return Err(format!("building srt-bench exited with {}", output.status));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| {
            message["reason"] == "compiler-artifact" && message["target"]["name"] == "srt-bench"
        })
        .find_map(|message| message["executable"].as_str().map(PathBuf::from))
        .ok_or_else(|| format!("{cargo} reported no srt-bench executable; refusing to guess"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn defaults_run_the_whole_plan_interleaved() {
        let args = parse(&[], PathBuf::from("o.tsv")).unwrap();
        assert_eq!(
            matrix_argv(&args),
            strings(&[
                "matrix",
                "--plan",
                PLAN,
                "--order",
                "interleaved",
                "--reps",
                "3",
                "--out",
                "o.tsv"
            ])
        );
    }

    #[test]
    fn known_flags_are_consumed_and_the_rest_passes_through() {
        let args = parse(
            &strings(&[
                "--reps",
                "1",
                "--axis",
                "connections=50",
                "--out",
                "x.tsv",
                "--secs",
                "5",
            ]),
            PathBuf::from("o.tsv"),
        )
        .unwrap();
        assert_eq!(args.reps, 1);
        assert_eq!(args.out, PathBuf::from("x.tsv"));
        assert_eq!(
            args.passthrough,
            strings(&["--axis", "connections=50", "--secs", "5"])
        );
    }

    #[test]
    fn bad_flags_are_refused() {
        let out = || PathBuf::from("o.tsv");
        assert!(parse(&strings(&["--reps", "0"]), out()).is_err());
        assert!(parse(&strings(&["--reps"]), out()).is_err());
        assert!(parse(&strings(&["--plan", "other.plan"]), out()).is_err());
    }

    /// The plan this command runs exists, uses the production listener, and
    /// keeps every layout axis the matrix doc reports on.
    #[test]
    fn checked_in_plan_targets_the_production_listener() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let plan = std::fs::read_to_string(root.join(PLAN)).expect("plan is checked in");
        let value = |key: &str| {
            plan.lines()
                .filter_map(|line| line.split_once('='))
                .find(|(name, _)| name.trim() == key)
                .map(|(_, value)| value.trim().to_string())
        };
        assert_eq!(value("recv-runtime").as_deref(), Some("owner"));
        for axis in ["ingress", "promotion", "cookie-routing", "connections"] {
            assert!(value(axis).is_some(), "plan sets {axis}");
        }
    }
}
