//! Unified bench/scale driver: one shared orchestration layer, one adapter
//! file per runtime. Loss mode and scale mode are the SAME code everywhere:
//! loss runs one connection, scale runs N. Only the STATS schema differs.
//!
//! # Ingress strategies (all four, on all six runtimes)
//!
//! How a listener fans many callers across sockets and threads. Selected
//! with `--ingress`; every combination is implemented everywhere, so a
//! sweep compares strategies rather than coverage.
//!
//! ```text
//!  per-port          shared-pool:K       reuseport-multi:K    reuseport-single:W
//!  ────────          ─────────────       ─────────────────    ──────────────────
//!  N sockets         K sockets           1 port, K sockets    1 port, K sockets
//!  N ports           K ports             SO_REUSEPORT         SO_REUSEPORT
//!  1 conn each       many conns each     kernel hashes flows  1 acceptor thread
//!                    no SO_REUSEPORT     acceptor == worker   + W worker threads
//!
//!  :12345 ─ c0       :12345 ┬ c0 c4      :12345 ┬ [acc0] ─┐   :12345 ─ [acceptor]
//!  :12346 ─ c1       :12346 ┼ c1 c5             ├ [acc1] ─┤            │ promotes
//!  :12347 ─ c2       :12347 ┼ c2 c6             ├ [acc2] ─┼─ peers     │ every conn
//!  :…     ─ …        :12348 ┴ c3 c7             └ [acc3] ─┘            ▼
//!                                                                [w0] [w1] [w2]
//! ```
//!
//! `--promotion` then decides which connections get a private connected
//! socket at their first `Connected`. The modes nest, and that nesting is
//! a property test in `srt-lifecycle`, not a convention:
//!
//! ```text
//!   Never  ⊂  Relocate  ⊂  Bonded  ⊂  All
//! ```
//!
//! Promotion buys independent scheduling and costs socket churn plus
//! SO_REUSEPORT group perturbation. Which way that trades is
//! runtime-dependent -- a runtime with a real task scheduler gains from
//! it, mio (a flat epoll loop with no task model) does not.
//!
//! # Scaling architecture (core/thread/worker model per runtime)
//!
//! | Runtime | Threads/workers      | Connection mapping            | Timers                          |
//! |---------|----------------------|-------------------------------|---------------------------------|
//! | mio     | no runtime, raw epoll| 1 thread : N sockets (`Token(i)` on one `Poll`) | software `ManualTimerStore` scans, gated to active conns |
//! | tokio   | cooperative tasks    | 1 thread : N spawned tasks (`spawn_local` + `LocalSet`) | native wheel, 1 `Sleep` future/conn |
//! | smol    | cooperative tasks    | 1 thread : N tasks (`async_executor::LocalExecutor`; smol's own block_on needs `Send`) | `smol::Timer` futures/conn |
//! | monoio  | thread-per-core      | 1 core : N tasks, completion-based, blocking recvs own their socket | io_uring kernel timeouts |
//! | glommio | thread-per-core      | 1 core : N tasks, shared submission ring | `glommio::timer` wheel          |
//! | compio  | thread-per-core      | 1 thread : 2N tasks (protocol task + never-cancelled reader task/channel) | `compio::time::sleep` |
//!
//! # Measured findings (6-core shared-tenant EPYC VPS, load avg 2-5)
//!
//! Baselines come from `srt-bench matrix … --reps 3` plus `srt-bench
//! report`; syscall attribution from `srt-bench sysprof <rt>` (perf
//! tracepoints: recvfrom/sendto/sendmsg/recvmsg/epoll_wait +
//! io_uring_submit_req). Rankings are only valid within one measurement
//! window -- this box is shared-tenant, so re-run before comparing.
//!
//! The numbers below predate the x86-64-v3 + LTO release profile and the
//! shared admission machinery, and were taken with the former shell
//! harness. Treat them as order-of-magnitude until re-measured.
//!
//! ## @300 conns, 8 Mbps/conn (2026-08-22 window)
//!
//! | runtime | sent | recv | retx | caller elapsed_s | verdict |
//! |---|---|---|---|---|---|
//! | mio     | 830k  | 757k | 0      | 8.2 on-time | delivery trails into listener grace under load |
//! | tokio   | 2463k | 363k | 1.03M  | 18.6-21.4   | pacing-starved; listener sees 15% |
//! | smol    | 2447k | 238k | 1.81M  | ~21         | same shape as tokio |
//! | monoio  | 2458k | 1104k| 10k    | 28.5        | rtt=100.00 timer artifact |
//! | glommio | 2425k | 253k | 1.56M  | 18.7        | worst ops/pkt of all six |
//! | compio  | 2458k | 965k | 0      | 30.2        | integrity intact, pacing starved |
//!
//! Every task-per-conn runtime is PACING-STARVED: callers push 8 s of
//! traffic in 19-30 s wall clock. Not packet loss -- scheduling delay.
//!
//! ## Syscall attribution @300 (listener side, per 10k delivered pkts)
//!
//! | runtime | rx syscalls | wakes (epoll) or SQEs | datagrams/wake | delivery |
//! |---|---|---|---|---|
//! | tokio   | 10.7k recvfrom | 831 epoll_waits | 11  | 19% |
//! | mio     | 10.9k recvfrom | 565 epoll_waits | 34  | ~100% |
//! | monoio  | --             | 16.9k SQEs      | --  | 42% |
//! | compio  | --             | 11.5k SQEs      | --  | 38% |
//! | glommio | 10.1k recvmsg + 6.1k SQE | --    | --  | 12% |
//!
//! tokio issues the SAME rx-syscalls-per-packet as mio; the difference is
//! wakeup batching (mio drains 34 datagrams per return). The bottleneck
//! is per-task wake scheduling, not syscall count.
//!
//! ## Knee sweep on this box: NOT REPRODUCIBLE
//!
//! Delivery vs N at fixed rate: 300->98%, 600->92%, 900->72%, 925->91%,
//! 950->86%, 975->71%. Non-monotonic => tenant noise dominates. The
//! WSL-era "mio perfect to 900" knee cannot be pinned here; sweeps need
//! taskset pinning or a quiet window to mean anything.
//!
//! ## Next lever: ingress pooling (per-task wakeup cost)
//!
//! Per-task-per-socket wakeup is the measured bottleneck (11 vs 34
//! datagrams/wake). The fix is cross-socket batching inside ONE task --
//! pool K UDP sockets demuxed by destination port into M>K connections,
//! so K readiness events serve M connections. This is handoff dimension
//! E (`--ingress pool`); it requires listener-side demux by port, which
//! no adapter expresses today.

pub mod compio;
#[cfg(target_os = "linux")]
pub mod glommio;
pub mod mio;
pub mod monoio;
pub mod smol;
pub mod tokio;

use crate::{BenchConfig, Runtime};

/// Dispatch to the selected runtime's driver.
/// Exit code for "this runtime does not implement that ingress
/// strategy". Distinct from a real failure so a sweep can tell a gap in
/// coverage from a bug.
pub const EXIT_UNSUPPORTED: i32 = 3;

/// Does `runtime` actually implement `ingress` on the receiving side?
///
/// Asking a runtime for a strategy it lacks used to fall through to the
/// per-port path, where every connection computes the same handful of
/// ports and they collide on bind -- surfacing as a pile of EADDRINUSE
/// panics rather than "not implemented", which is alarming and hard to
/// tell from a real port-allocation bug. Checked up front instead.
#[must_use]
pub fn ingress_supported(runtime: Runtime, ingress: crate::Ingress) -> bool {
    // All four strategies now exist on every backend. Kept as a function
    // rather than deleted: it is the one place a future strategy declares
    // where it is implemented, and the matrix already consults it.
    let _ = (runtime, ingress);
    true
}

pub fn run(cfg: BenchConfig) {
    // Receivers are what bind; a sender just dials whatever the topology
    // says, so it needs no capability of its own.
    if cfg.mode == crate::Mode::Receiver
        && cfg.connections > 1
        && !ingress_supported(cfg.runtime, cfg.ingress)
    {
        eprintln!(
            "srt-bench: {} does not implement --ingress {} (only mio does)",
            cfg.runtime.name(),
            crate::harness::describe_ingress(cfg.ingress),
        );
        std::process::exit(EXIT_UNSUPPORTED);
    }
    match cfg.runtime {
        Runtime::Mio => mio::run(cfg),
        Runtime::Tokio => tokio::run(cfg),
        Runtime::Smol => smol::run(cfg),
        Runtime::Monoio => monoio::run(cfg),
        Runtime::Glommio => {
            #[cfg(target_os = "linux")]
            glommio::run(cfg);
            #[cfg(not(target_os = "linux"))]
            {
                let _ = cfg;
                eprintln!("srt-bench: glommio is Linux-only (io_uring)");
                std::process::exit(2);
            }
        }
        Runtime::Compio => compio::run(cfg),
    }
}

/// Destination address of a sender connection i.
/// Report a failed output drain, tagged with the adapter that owns it.
///
/// Each adapter's `drain_outputs` differs only in the label it prints, so
/// the reporting lives here rather than being copied per runtime. The
/// differing `Conn` types never enter the signature -- callers pass the
/// already-awaited result -- so this needs no trait or generic.
pub fn report_drain_error<T, E: std::fmt::Display>(label: &str, result: Result<T, E>) {
    if let Err(error) = result {
        eprintln!("[bench-{label}] output send failed: {error}");
    }
}

pub fn sender_endpoint(cfg: &BenchConfig, i: usize) -> std::net::SocketAddr {
    cfg.addr_for(i)
}
