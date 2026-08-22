//! Framework-agnostic process CPU/memory accounting, shared by every
//! loss-caller/loss-listener backend (mio/tokio/smol/monoio/glommio/compio)
//! so their STATS lines are directly comparable on resource cost, not just
//! throughput/RTT -- the docs/srt-pure-rust-plan.md Phase 4
//! driver-framework bake-off is judged on latency introduced, throughput,
//! *and* CPU/memory.
//!
//! `getrusage(RUSAGE_SELF, ...)` rather than reading `/proc/self/stat`:
//! portable within the libc crate already in the dependency graph, no
//! string parsing, and reports microsecond-resolution CPU time plus peak
//! RSS directly in one syscall.

pub struct ProcessStats {
    /// User-mode CPU time consumed so far, in milliseconds.
    pub cpu_user_ms: f64,
    /// Kernel-mode CPU time consumed so far, in milliseconds.
    pub cpu_sys_ms: f64,
    /// Peak resident set size so far, in KiB (`ru_maxrss` is already
    /// KiB on Linux -- unlike macOS/BSD, where it's bytes; this crate only
    /// targets Linux, see Cargo.toml's doc comment on the io_uring
    /// backends).
    pub peak_rss_kb: u64,
}

pub fn process_stats() -> ProcessStats {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 {
        return ProcessStats {
            cpu_user_ms: 0.0,
            cpu_sys_ms: 0.0,
            peak_rss_kb: 0,
        };
    }
    ProcessStats {
        cpu_user_ms: usage.ru_utime.tv_sec as f64 * 1000.0 + usage.ru_utime.tv_usec as f64 / 1000.0,
        cpu_sys_ms: usage.ru_stime.tv_sec as f64 * 1000.0 + usage.ru_stime.tv_usec as f64 / 1000.0,
        peak_rss_kb: usage.ru_maxrss.max(0) as u64,
    }
}
