//! Unified bench/scale driver over the pure-Rust SRT Core.
//!
//! One binary for all six runtime backends and both roles. Loss mode
//! (connections=1) and scale mode (connections=N) are the same code path
//! per runtime -- only the STATS schema differs.
//!
//! Usage:
//!
//! One run (either role):
//!   srt-bench runtime=<mio|tokio|smol|monoio|glommio|compio> \
//!     mode=sender <host> <port> <duration_secs> <latency_ms> [source_bitrate_bps] [--connections N]
//!   srt-bench runtime=<...> mode=receiver <port> <duration_secs> <latency_ms> [--connections N]
//!   ... plus --out FILE to append a result row.
//!
//! A sweep, one child process per role per cell:
//!   srt-bench matrix --runtimes mio,tokio --ingress reuseport-multi:4 \
//!     --egress per-connection,shared-socket \
//!     --encryption plain,128,192,256 --promotion never,all \
//!     --connections 25,150 --reps 3 --out results.tsv
//!   srt-bench matrix --plan docs/plans/full-matrix.plan \
//!     --axis encryption=plain,128 --order interleaved --seed 0
//!
//! Host capacity diagnostics:
//!   srt-bench system-info
//!
//! Median table over a result file, grouped however you like:
//!   srt-bench report results.tsv --by runtime,promotion
//!   srt-bench report results.tsv --format github-benchmark --out benchmark.json
//!
//! Comparative analysis across two result files:
//!   srt-bench compare BASE.tsv HEAD.tsv [--format table|markdown] [--out FILE]
//!
//! Validate every cell satisfies the canonical clean capacity predicate:
//!   srt-bench check-clean sentinel.tsv
//!
//! Generate or score the fixed SRT-600 qualification corpus:
//!   srt-bench qualify plan --out scratch/srt600-plan.tsv
//!   srt-bench qualify score BASE.tsv HEAD.tsv
//!
//! Syscall/io_uring attribution for one pair (needs `perf`):
//!   srt-bench sysprof --runtime glommio --connections 150
//!
//! Live host watch while a benchmark runs:
//!   srt-bench watch [interval_secs] [heartbeat_every_n_samples]
//!
//! Reporting and host watching live here with the benchmark process, so the
//! result schema and diagnostic sampling do not depend on separate scripts.

fn main() {
    // Raise the soft descriptor limit before either a matrix parent or a
    // runtime child starts opening sockets. Children inherit this limit.
    srt_bench::system::raise_nofile_limit();

    // Subcommands come before the runtime=/mode= form so that reporting
    // and orchestration live in the same binary as the thing being
    // measured -- there is no second tool to keep in sync with the
    // result schema.
    let args: Vec<String> = std::env::args().collect();
    let context = match args.get(1).map(String::as_str) {
        Some(
            "report" | "watch" | "compare" | "check-clean" | "classify" | "validate" | "qualify",
        ) => None,
        Some("system-info") => Some("system-info"),
        Some("matrix") => Some("matrix"),
        Some("sysprof") => Some("sysprof"),
        _ => Some("runtime"),
    };
    if std::env::var_os("SRT_BENCH_CHILD").is_none()
        && let Some(context) = context
    {
        srt_bench::system::print_startup_diagnostics(context);
    }
    if dispatch_subcommand(&args) {
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cfg = srt_bench::bench_config_from_args();
    srt_bench::runtimes::run(cfg);
}

fn dispatch_subcommand(args: &[String]) -> bool {
    match args.get(1).map(String::as_str) {
        Some("system-info") => true,
        Some("report") => {
            report(args);
            true
        }
        Some("compare") => {
            compare(args);
            true
        }
        Some("check-clean") => {
            check_clean(args);
            true
        }
        Some("qualify") => {
            qualify(args);
            true
        }
        Some("classify") => {
            classify(args);
            true
        }
        Some("validate") => {
            validate(args);
            true
        }
        Some("watch") => {
            let cli = srt_bench::Cli::parse(&args[1..]);
            if let Err(e) = srt_bench::watch::run(&cli) {
                eprintln!("watch: {e}");
                std::process::exit(1);
            }
            true
        }
        Some("sysprof") => {
            let cli = srt_bench::Cli::parse(&args[1..]);
            if let Err(e) = srt_bench::harness::run_sysprof(&cli) {
                eprintln!("sysprof: {e}");
                std::process::exit(1);
            }
            true
        }
        Some("matrix") => {
            matrix(args);
            true
        }
        _ => false,
    }
}

/// `srt-bench qualify plan|score ...` -- emit the fixed SRT-600 corpus or
/// score two bounded measurement files against one another.
fn qualify(args: &[String]) {
    let cli = srt_bench::Cli::parse(&args[1..]);
    match cli.positional.first().map(String::as_str) {
        Some("plan") => qualify_plan(&cli),
        Some("score") => qualify_score(&cli),
        _ => {
            eprintln!("usage: srt-bench qualify plan [--out FILE]");
            eprintln!("       srt-bench qualify score BASE.tsv HEAD.tsv [--noise 0.03]");
            std::process::exit(2);
        }
    }
}

fn qualify_plan(cli: &srt_bench::Cli) {
    let output = srt_bench::qualification::render_plan();
    if let Some(destination) = cli.flags.get("out").filter(|value| !value.is_empty()) {
        if let Err(error) = std::fs::write(destination, output) {
            eprintln!("qualify plan: {destination}: {error}");
            std::process::exit(1);
        }
    } else {
        print!("{output}");
    }
}

fn qualify_score(cli: &srt_bench::Cli) {
    if cli.positional.len() < 3 {
        eprintln!("usage: srt-bench qualify score BASE.tsv HEAD.tsv [--noise 0.03]");
        std::process::exit(2);
    }
    let policy = srt_bench::qualification::QualificationPolicy {
        required_delivery_ratio: score_flag(cli, "delivery", 0.99),
        max_noise_ratio: score_flag(cli, "noise", 0.03),
        complexity_lambda: score_flag(cli, "complexity-lambda", 0.0),
        production_loc_delta: score_flag(cli, "production-loc-delta", 0.0),
    };
    let baseline = score_input(&cli.positional[1]);
    let candidate = score_input(&cli.positional[2]);
    let report = match srt_bench::qualification::evaluate(baseline, candidate, policy) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("qualify score: {error}");
            std::process::exit(2);
        }
    };
    print!("{}", srt_bench::qualification::render_report(&report));
    if !report.passed {
        std::process::exit(1);
    }
}

fn score_flag(cli: &srt_bench::Cli, name: &str, default: f64) -> f64 {
    cli.flags
        .get(name)
        .map_or(default, |value| match value.parse() {
            Ok(parsed) => parsed,
            Err(_) => {
                eprintln!("qualify score: invalid --{name} value {value:?}");
                std::process::exit(2);
            }
        })
}

fn score_input(
    path: &str,
) -> [srt_bench::qualification::Measurement; srt_bench::qualification::SCENARIO_COUNT] {
    match srt_bench::qualification::read_measurements(std::path::Path::new(path)) {
        Ok(measurements) => measurements,
        Err(error) => {
            eprintln!("qualify score: {error}");
            std::process::exit(1);
        }
    }
}

/// `srt-bench matrix ...` -- run the sweep, then exit 0 **only** if every
/// required cell and role completed successfully.
///
/// A child that crashed, was signalled, or exited cleanly without writing
/// its result row fails the whole invocation. Without that, automation
/// could report a green benchmark campaign over a sweep whose sender had
/// died (issue #39).
fn matrix(args: &[String]) {
    let cli = srt_bench::Cli::parse(&args[1..]);
    match srt_bench::harness::run_matrix(&cli) {
        Ok(report) if report.ok() => {}
        Ok(report) => {
            eprint!("{}", report.failure_summary());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("matrix: {e}");
            std::process::exit(1);
        }
    }
}

/// `srt-bench report FILE [--by col,col,...]` -- median table over a result
/// file, or `--format github-benchmark` for benchmark-action trend data.
fn report(args: &[String]) {
    let cli = srt_bench::Cli::parse(&args[1..]);
    let path = cli.positional.first().cloned().unwrap_or_else(|| {
        eprintln!(
            "usage: srt-bench report FILE [--by runtime,ingress,promotion,...] \
             [--format table|github-benchmark] [--out FILE]"
        );
        std::process::exit(2)
    });
    let records = match srt_bench::harness::read_results(std::path::Path::new(&path)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("report: {path}: {e}");
            std::process::exit(1)
        }
    };
    if records.is_empty() {
        eprintln!("report: {path} has no rows");
        std::process::exit(1);
    }
    let format = cli
        .flags
        .get("format")
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .unwrap_or("table");
    let output = match format {
        "table" => {
            let by: Vec<String> = cli.flags.get("by").filter(|v| !v.is_empty()).map_or_else(
                || vec!["runtime".to_string()],
                |v| v.split(',').map(str::trim).map(str::to_string).collect(),
            );
            srt_bench::harness::report(&records, &by)
        }
        "github-benchmark" => srt_bench::harness::github_benchmark_json(&records),
        other => {
            eprintln!("report: unknown format {other:?} (expected table or github-benchmark)");
            std::process::exit(2)
        }
    };
    if let Some(destination) = cli.flags.get("out").filter(|value| !value.is_empty()) {
        if let Err(e) = std::fs::write(destination, output) {
            eprintln!("report: {destination}: {e}");
            std::process::exit(1);
        }
    } else {
        print!("{output}");
    }
}

/// `srt-bench compare BASE.tsv HEAD.tsv [--format table|markdown] [--out FILE]`
fn compare(args: &[String]) {
    let cli = srt_bench::Cli::parse(&args[1..]);
    if cli.positional.len() < 2 {
        eprintln!(
            "usage: srt-bench compare BASE.tsv HEAD.tsv [--format table|markdown] [--out FILE]"
        );
        std::process::exit(2);
    }
    let base_path = std::path::Path::new(&cli.positional[0]);
    let head_path = std::path::Path::new(&cli.positional[1]);
    let markdown = cli
        .flags
        .get("format")
        .map(|f| f == "markdown")
        .unwrap_or(false);

    let output = match srt_bench::compare::compare_files(base_path, head_path, markdown) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("compare: {e}");
            std::process::exit(1);
        }
    };

    if let Some(destination) = cli.flags.get("out").filter(|value| !value.is_empty()) {
        if let Err(e) = std::fs::write(destination, output) {
            eprintln!("compare: {destination}: {e}");
            std::process::exit(1);
        }
    } else {
        print!("{output}");
    }
}

/// `srt-bench check-clean FILE.tsv` -- validate that every cell and repetition
/// in the file satisfies the canonical clean capacity predicate.
fn check_clean(args: &[String]) {
    let cli = srt_bench::Cli::parse(&args[1..]);
    let path = cli.positional.first().cloned().unwrap_or_else(|| {
        eprintln!("usage: srt-bench check-clean FILE.tsv");
        std::process::exit(2);
    });
    match srt_bench::compare::check_clean_file(std::path::Path::new(&path)) {
        Ok(msg) => {
            print!("{msg}");
        }
        Err(msg) => {
            eprint!("{msg}");
            std::process::exit(1);
        }
    }
}

/// `srt-bench classify [--plan FILE] [--format table|tsv]` -- classify
/// explicit input or every Cartesian-product cell in a declarative plan.
fn classify(args: &[String]) {
    let cli = srt_bench::Cli::parse(&args[1..]);
    let output = match srt_bench::classifier::classify(&cli) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("classify: {error}");
            std::process::exit(1);
        }
    };
    write_output(&cli, "classify", output);
}

/// `srt-bench validate FILE.tsv` -- compare persisted model predictions with
/// the existing canonical observed clean predicate.
fn validate(args: &[String]) {
    let cli = srt_bench::Cli::parse(&args[1..]);
    let Some(path) = cli.positional.first() else {
        eprintln!("usage: srt-bench validate FILE.tsv [--format table|tsv]");
        std::process::exit(2);
    };
    let format = cli
        .flags
        .get("format")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("table");
    let output = match srt_bench::classifier::validate_results(std::path::Path::new(path), format) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("validate: {error}");
            std::process::exit(1);
        }
    };
    write_output(&cli, "validate", output);
}

fn write_output(cli: &srt_bench::Cli, command: &str, output: String) {
    if let Some(destination) = cli.flags.get("out").filter(|value| !value.is_empty()) {
        if let Err(error) = std::fs::write(destination, output) {
            eprintln!("{command}: {destination}: {error}");
            std::process::exit(1);
        }
    } else {
        print!("{output}");
    }
}
