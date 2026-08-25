//! Linux host watch used while a benchmark is running.
//!
//! This intentionally stays a small diagnostic command rather than becoming
//! part of matrix orchestration. It samples the same host signals as the old
//! shell helper, but reads `/proc` directly so the watcher has no `awk`, `ps`,
//! `cut`, or shell process to distort the snapshot it is reporting.

use crate::cpu_stats;
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::time::Duration;

/// Run `srt-bench watch [interval_secs] [heartbeat_every_n_samples]`.
pub fn run(cli: &crate::Cli) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        return run_linux(cli);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cli;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "watch is currently supported on Linux only",
        ))
    }
}

#[cfg(target_os = "linux")]
fn run_linux(cli: &crate::Cli) -> io::Result<()> {
    let interval_secs = positive_arg(cli, "interval", 0, 5)?;
    let heartbeat_every = positive_arg(cli, "heartbeat", 1, 12)?;
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let swap_base = read_memory().swap_used_mb();
    let mut previous_udp = cpu_stats::udp_counters();
    let mut sample = 0u64;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    writeln!(stdout, "watching: {cores} cores, interval {interval_secs}s")?;
    loop {
        std::thread::sleep(Duration::from_secs(interval_secs));
        sample += 1;

        let current_udp = cpu_stats::udp_counters();
        let udp = current_udp.since(previous_udp);
        previous_udp = current_udp;

        let load = read_loadavg();
        let memory = read_memory();
        let swap_used = memory.swap_used_mb();
        let swap_grown = swap_used.saturating_sub(swap_base);
        let top = top_processes();

        if udp.rcvbuf_errors > 1000 {
            writeln!(
                stdout,
                "ANOMALY udp-rcvbuf-drops {} in {interval_secs}s (silent loss: no NAK will follow) | {top}",
                udp.rcvbuf_errors
            )?;
        }
        if udp.in_errors > 1000 {
            writeln!(
                stdout,
                "ANOMALY udp-in-errors {} in {interval_secs}s | {top}",
                udp.in_errors
            )?;
        }
        if udp.no_ports > 1000 {
            writeln!(
                stdout,
                "ANOMALY udp-no-ports {} in {interval_secs}s (sending to a closed port) | {top}",
                udp.no_ports
            )?;
        }
        if swap_grown > 64 {
            writeln!(
                stdout,
                "ANOMALY swap-grew {swap_grown}MB since start, {swap_used}MB total (every latency number is now suspect) | {top}"
            )?;
        }
        if memory.available_mb.saturating_mul(10) < memory.total_mb {
            writeln!(
                stdout,
                "ANOMALY mem-available {}MB of {}MB | {top}",
                memory.available_mb, memory.total_mb
            )?;
        }
        if load > cores as f64 * 1.5 {
            writeln!(stdout, "ANOMALY load {load} on {cores} cores | {top}")?;
        }

        if sample.is_multiple_of(heartbeat_every) {
            writeln!(
                stdout,
                "beat load={load} mem_avail={}MB swap+{swap_grown}MB udp_drops/{}s={} | {top}",
                memory.available_mb, interval_secs, udp.rcvbuf_errors
            )?;
        }
    }
}

#[cfg(target_os = "linux")]
fn positive_arg(cli: &crate::Cli, flag: &str, positional: usize, default: u64) -> io::Result<u64> {
    let value = cli
        .flags
        .get(flag)
        .or_else(|| cli.positional.get(positional))
        .map(String::as_str)
        .unwrap_or_else(|| match default {
            5 => "5",
            12 => "12",
            _ => "0",
        });
    let value = value.parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("watch: {flag} must be a positive integer, got {value:?}"),
        )
    })?;
    if value == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("watch: {flag} must be positive"),
        ));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Default)]
struct Memory {
    available_mb: u64,
    total_mb: u64,
    swap_total_mb: u64,
    swap_free_mb: u64,
}

#[cfg(target_os = "linux")]
impl Memory {
    fn swap_used_mb(self) -> u64 {
        self.swap_total_mb.saturating_sub(self.swap_free_mb)
    }
}

#[cfg(target_os = "linux")]
fn read_memory() -> Memory {
    std::fs::read_to_string("/proc/meminfo")
        .map(|text| parse_meminfo(&text))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn parse_meminfo(text: &str) -> Memory {
    let mut memory = Memory::default();
    for line in text.lines() {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let Some(kib) = values
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        match name {
            "MemAvailable" => memory.available_mb = kib / 1024,
            "MemTotal" => memory.total_mb = kib / 1024,
            "SwapTotal" => memory.swap_total_mb = kib / 1024,
            "SwapFree" => memory.swap_free_mb = kib / 1024,
            _ => {}
        }
    }
    memory
}

#[cfg(target_os = "linux")]
fn read_loadavg() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .map(|text| parse_loadavg(&text))
        .unwrap_or(0.0)
}

#[cfg(target_os = "linux")]
fn parse_loadavg(text: &str) -> f64 {
    text.split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0)
}

#[cfg(target_os = "linux")]
struct ProcessSnapshot {
    name: String,
    cpu_pct: f64,
    rss_mb: u64,
}

#[cfg(target_os = "linux")]
fn top_processes() -> String {
    let Ok(uptime) = std::fs::read_to_string("/proc/uptime") else {
        return String::new();
    };
    let Some(uptime) = uptime
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())
    else {
        return String::new();
    };
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ticks <= 0 || page_size <= 0 {
        return String::new();
    }
    let page_kb = page_size as u64 / 1024;
    let current_pid = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return String::new();
    };
    let mut processes = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        if pid == current_pid {
            continue;
        }
        let path = entry.path().join("stat");
        let Ok(stat) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some(process) = parse_proc_stat(&stat, uptime, ticks as f64, page_kb) {
            processes.push(process);
        }
    }
    processes.sort_by(|a, b| {
        b.cpu_pct
            .total_cmp(&a.cpu_pct)
            .then_with(|| b.rss_mb.cmp(&a.rss_mb))
    });

    let mut top = String::new();
    for process in processes.into_iter().take(3) {
        let _ = write!(
            top,
            "{}({:.0}% {}MB) ",
            process.name, process.cpu_pct, process.rss_mb
        );
    }
    top
}

#[cfg(target_os = "linux")]
fn parse_proc_stat(text: &str, uptime: f64, ticks: f64, page_kb: u64) -> Option<ProcessSnapshot> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let name = text.get(open + 1..close)?.to_string();
    let fields: Vec<&str> = text.get(close + 2..)?.split_whitespace().collect();
    let user_ticks: f64 = fields.get(11)?.parse::<u64>().ok()? as f64;
    let system_ticks: f64 = fields.get(12)?.parse::<u64>().ok()? as f64;
    let start_ticks: f64 = fields.get(19)?.parse::<u64>().ok()? as f64;
    let rss_pages = fields.get(21)?.parse::<i64>().ok()?.max(0) as u64;
    let elapsed = (uptime - start_ticks / ticks).max(0.001);
    Some(ProcessSnapshot {
        name,
        cpu_pct: 100.0 * (user_ticks + system_ticks) / ticks / elapsed,
        rss_mb: rss_pages.saturating_mul(page_kb) / 1024,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{parse_loadavg, parse_meminfo, parse_proc_stat};

    #[test]
    fn parses_memory_fields_in_kib() {
        let memory = parse_meminfo(
            "MemTotal:       2048000 kB\nMemAvailable:   1024000 kB\nSwapTotal:       204800 kB\nSwapFree:        102400 kB\n",
        );
        assert_eq!(memory.total_mb, 2000);
        assert_eq!(memory.available_mb, 1000);
        assert_eq!(memory.swap_used_mb(), 100);
    }

    #[test]
    fn parses_loadavg_first_field() {
        assert_eq!(parse_loadavg("2.50 1.25 0.75 1/100 1234\n"), 2.5);
        assert_eq!(parse_loadavg("unavailable"), 0.0);
    }

    #[test]
    fn parses_process_stat_after_a_parenthesized_name() {
        let stat = "123 (worker) S 1 2 3 4 5 6 7 8 9 10 110 20 0 0 0 0 0 0 1000 0 10";
        let process = parse_proc_stat(stat, 20.0, 100.0, 4).expect("process");
        assert_eq!(process.name, "worker");
        assert_eq!(process.cpu_pct, 13.0);
        assert_eq!(process.rss_mb, 0);
    }
}
