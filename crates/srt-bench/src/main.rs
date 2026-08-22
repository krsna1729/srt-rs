//! Unified bench/scale driver over the pure-Rust SRT Core.
//!
//! One binary for all six runtime backends and both roles. Loss mode
//! (connections=1) and scale mode (connections=N) are the same code path
//! per runtime -- only the STATS schema differs.
//!
//! Usage:
//!   srt-bench runtime=<mio|tokio|smol|monoio|glommio|compio> \
//!     mode=sender <host> <port> <duration_secs> <latency_ms> [bitrate_bps] [--connections N]
//!   srt-bench runtime=<...> mode=receiver <port> <duration_secs> <latency_ms> [--connections N]

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cfg = srt_bench::bench_config_from_args();
    srt_bench::runtimes::run(cfg);
}
