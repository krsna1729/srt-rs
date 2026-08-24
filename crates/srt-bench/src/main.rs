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
//!     mode=sender <host> <port> <duration_secs> <latency_ms> [bitrate_bps] [--connections N]
//!   srt-bench runtime=<...> mode=receiver <port> <duration_secs> <latency_ms> [--connections N]
//!   ... plus --out FILE to append a result row.
//!
//! A sweep, one child process per role per cell:
//!   srt-bench matrix --runtimes mio,tokio --ingress reuseport-multi:4 \
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
//!
//! Syscall/io_uring attribution for one pair (needs `perf`):
//!   srt-bench sysprof --runtime glommio --connections 150
//!
//! These replace the former bench.sh. It had grown to 344 lines of shell
//! wrapping 86 lines of inline Python whose only job was re-parsing this
//! binary's own stdout -- so the result schema lived in two places and
//! silently drifted. The process that has the numbers now writes them,
//! and the process that reports them reads the same columns back.

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
        Some("report") => None,
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
    match args.get(1).map(String::as_str) {
        Some("system-info") => {
            return;
        }
        Some("report") => return report(&args),
        Some("sysprof") => {
            let cli = srt_bench::Cli::parse(&args[1..]);
            if let Err(e) = srt_bench::harness::run_sysprof(&cli) {
                eprintln!("sysprof: {e}");
                std::process::exit(1);
            }
            return;
        }
        Some("matrix") => {
            let cli = srt_bench::Cli::parse(&args[1..]);
            if let Err(e) = srt_bench::harness::run_matrix(&cli) {
                eprintln!("matrix: {e}");
                std::process::exit(1);
            }
            return;
        }
        _ => {}
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cfg = srt_bench::bench_config_from_args();
    srt_bench::runtimes::run(cfg);
}

/// `srt-bench report FILE [--by col,col,...]` -- median table over a
/// result file, grouped by whichever dimensions matter for the question
/// being asked.
fn report(args: &[String]) {
    let cli = srt_bench::Cli::parse(&args[1..]);
    let path = cli.positional.first().cloned().unwrap_or_else(|| {
        eprintln!("usage: srt-bench report FILE [--by runtime,ingress,promotion,...]");
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
    let by: Vec<String> = cli.flags.get("by").filter(|v| !v.is_empty()).map_or_else(
        || vec!["runtime".to_string()],
        |v| v.split(',').map(str::trim).map(str::to_string).collect(),
    );
    print!("{}", srt_bench::harness::report(&records, &by));
}
