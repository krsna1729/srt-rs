//! Framework-agnostic process CPU/memory accounting, shared by every
//! bench-caller/bench-listener backend (mio/tokio/smol/monoio/glommio/compio)
//! so their STATS lines are directly comparable on resource cost, not just
//! throughput/RTT. The driver-framework bake-off is judged on latency
//! introduced, throughput, *and* CPU/memory.
//!
//! CPU time comes from `getrusage(RUSAGE_SELF, ...)`. On Linux, peak RSS is
//! read from `/proc/self/status`'s `VmHWM`: unlike `ru_maxrss`, it resets at
//! `exec`, so a matrix child's memory does not include the matrix parent's
//! Cartesian-product allocation.

pub struct ProcessStats {
    /// User-mode CPU time consumed so far, in milliseconds.
    pub cpu_user_ms: f64,
    /// Kernel-mode CPU time consumed so far, in milliseconds.
    pub cpu_sys_ms: f64,
    /// Peak resident set size so far, in KiB.
    pub peak_rss_kb: u64,
}

pub fn process_stats() -> ProcessStats {
    // SAFETY: all-zero is valid for `rusage`.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is valid writable storage; RUSAGE_SELF is always valid.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 {
        return ProcessStats {
            cpu_user_ms: 0.0,
            cpu_sys_ms: 0.0,
            peak_rss_kb: 0,
        };
    }
    let peak_rss_kb = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name == "VmHWM")
                    .then(|| value.split_whitespace().next()?.parse::<u64>().ok())
                    .flatten()
            })
        })
        .unwrap_or_else(|| usage.ru_maxrss.max(0) as u64);
    ProcessStats {
        cpu_user_ms: usage.ru_utime.tv_sec as f64 * 1000.0 + usage.ru_utime.tv_usec as f64 / 1000.0,
        cpu_sys_ms: usage.ru_stime.tv_sec as f64 * 1000.0 + usage.ru_stime.tv_usec as f64 / 1000.0,
        peak_rss_kb,
    }
}

/// Kernel-side UDP counters, from `/proc/net/snmp`.
///
/// These are the difference between "the protocol lost packets" and "the
/// kernel threw them away before the protocol ever saw them", and nothing
/// else in a result row can tell those apart. A listener that shows heavy
/// loss with *zero* retransmits is the signature of `rcvbuf_errors`: the
/// receive queue overflowed, so no gap was ever detected to NAK.
///
/// Read inside whatever network namespace the process is in, so a run
/// under `--link-*` measures its own emulated link rather than the host.
#[derive(Clone, Copy, Default)]
pub struct UdpCounters {
    /// Datagrams dropped because the socket receive queue was full. The
    /// one to watch: it is silent loss from the protocol's point of view.
    pub rcvbuf_errors: u64,
    /// Datagrams dropped for any other reason (bad checksum, no buffer).
    pub in_errors: u64,
    /// Datagrams delivered to a port nobody was listening on.
    pub no_ports: u64,
    /// Send-side queue overflows.
    pub sndbuf_errors: u64,
}

impl UdpCounters {
    /// Counters accumulated since `earlier`, saturating so a counter
    /// reset (or a namespace change) reads as zero rather than wrapping.
    #[must_use]
    pub fn since(self, earlier: Self) -> Self {
        Self {
            rcvbuf_errors: self.rcvbuf_errors.saturating_sub(earlier.rcvbuf_errors),
            in_errors: self.in_errors.saturating_sub(earlier.in_errors),
            no_ports: self.no_ports.saturating_sub(earlier.no_ports),
            sndbuf_errors: self.sndbuf_errors.saturating_sub(earlier.sndbuf_errors),
        }
    }
}

/// Read the `Udp:` row of `/proc/net/snmp`. Header and values are two
/// parallel whitespace-separated lines, so the field order is looked up
/// by name rather than assumed.
#[must_use]
pub fn udp_counters() -> UdpCounters {
    let Ok(text) = std::fs::read_to_string("/proc/net/snmp") else {
        return UdpCounters::default();
    };
    let mut lines = text.lines().filter(|l| l.starts_with("Udp:"));
    let (Some(header), Some(values)) = (lines.next(), lines.next()) else {
        return UdpCounters::default();
    };
    let names: Vec<&str> = header.split_whitespace().collect();
    let nums: Vec<&str> = values.split_whitespace().collect();
    let get = |field: &str| -> u64 {
        names
            .iter()
            .position(|n| *n == field)
            .and_then(|i| nums.get(i))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    UdpCounters {
        rcvbuf_errors: get("RcvbufErrors"),
        in_errors: get("InErrors"),
        no_ports: get("NoPorts"),
        sndbuf_errors: get("SndbufErrors"),
    }
}

/// Counters as they were when this process started, captured on first
/// use so every later read can be reported as a delta for this run alone.
pub fn udp_baseline() -> UdpCounters {
    static BASELINE: std::sync::OnceLock<UdpCounters> = std::sync::OnceLock::new();
    *BASELINE.get_or_init(udp_counters)
}
