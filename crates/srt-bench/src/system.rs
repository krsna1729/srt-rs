//! Host-capacity diagnostics and process resource setup for `srt-bench`.
//!
//! The matrix launches one process per role. Raising the soft file-descriptor
//! limit before that fan-out means every child inherits the capacity the host
//! already permits, while the diagnostic output records the limits and kernel
//! settings that make a result reproducible.

/// Raise the soft open-file limit to the hard limit when the platform allows
/// it. The result is inherited by matrix children.
pub fn raise_nofile_limit() {
    #[cfg(unix)]
    // SAFETY: `rlimit` is initialized by getrlimit before use; setrlimit receives valid storage.
    unsafe {
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        if libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) != 0 {
            eprintln!(
                "srt-bench: getrlimit(RLIMIT_NOFILE) failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let mut limit = limit.assume_init();
        if limit.rlim_cur >= limit.rlim_max {
            return;
        }
        let old = limit.rlim_cur;
        limit.rlim_cur = limit.rlim_max;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            eprintln!(
                "srt-bench: could not raise RLIMIT_NOFILE from {} to {}: {}",
                old,
                limit.rlim_max,
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Print the host settings that bound socket, CPU, memory, and io_uring
/// capacity. This is intentionally key/value-shaped so it can be captured in
/// a benchmark log and compared between machines.
pub fn print_startup_diagnostics(context: &str) {
    eprintln!("srt-bench system diagnostics context={context}");
    eprintln!("system.os={}", std::env::consts::OS);
    eprintln!("system.arch={}", std::env::consts::ARCH);

    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get().to_string())
        .unwrap_or_else(|e| format!("unavailable:{e}"));
    eprintln!("cpu.available_parallelism={parallelism}");
    eprintln!(
        "cpu.transport_available={}",
        srt_transport::available_cpus()
    );
    print_proc_line("cpu.affinity", "/proc/self/status", "Cpus_allowed_list:");

    print_rlimit_files();
    for (name, path) in SYSCTLS {
        print_file(name, path);
    }
    print_memory();
}

const SYSCTLS: &[(&str, &str)] = &[
    ("kernel.osrelease", "/proc/sys/kernel/osrelease"),
    (
        "kernel.io_uring_disabled",
        "/proc/sys/kernel/io_uring_disabled",
    ),
    ("kernel.io_uring_group", "/proc/sys/kernel/io_uring_group"),
    ("net.core.rmem_default", "/proc/sys/net/core/rmem_default"),
    ("net.core.rmem_max", "/proc/sys/net/core/rmem_max"),
    ("net.core.wmem_default", "/proc/sys/net/core/wmem_default"),
    ("net.core.wmem_max", "/proc/sys/net/core/wmem_max"),
    (
        "net.core.netdev_max_backlog",
        "/proc/sys/net/core/netdev_max_backlog",
    ),
    ("net.core.somaxconn", "/proc/sys/net/core/somaxconn"),
    (
        "net.ipv4.ip_local_port_range",
        "/proc/sys/net/ipv4/ip_local_port_range",
    ),
    ("net.ipv4.udp_mem", "/proc/sys/net/ipv4/udp_mem"),
    ("net.ipv4.udp_rmem_min", "/proc/sys/net/ipv4/udp_rmem_min"),
    ("net.ipv4.udp_wmem_min", "/proc/sys/net/ipv4/udp_wmem_min"),
];

fn print_file(name: &str, path: &str) {
    let value = std::fs::read_to_string(path)
        .map(|value| value.trim().replace('\n', " "))
        .unwrap_or_else(|e| format!("unavailable:{e}"));
    eprintln!("{name}={value}");
}

fn print_proc_line(name: &str, path: &str, prefix: &str) {
    let value = std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| {
            contents
                .lines()
                .find_map(|line| line.strip_prefix(prefix).map(str::trim))
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unavailable".to_string());
    eprintln!("{name}={value}");
}

fn print_rlimit_files() {
    #[cfg(unix)]
    // SAFETY: `rlimit` is initialized by getrlimit; read-only query with no side effects.
    unsafe {
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        if libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) == 0 {
            let limit = limit.assume_init();
            eprintln!(
                "limit.nofile.soft={} limit.nofile.hard={}",
                limit.rlim_cur, limit.rlim_max
            );
        }
    }
    print_proc_line(
        "limit.max_open_files",
        "/proc/self/limits",
        "Max open files",
    );
    print_proc_line(
        "limit.max_locked_memory",
        "/proc/self/limits",
        "Max locked memory",
    );
    print_proc_line(
        "limit.max_user_processes",
        "/proc/self/limits",
        "Max processes",
    );
}

fn print_memory() {
    let mut values = std::collections::BTreeMap::<String, String>::new();
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if matches!(name, "MemTotal" | "MemAvailable" | "SwapTotal" | "SwapFree") {
                values.insert(name.to_string(), value.trim().replace(' ', ""));
            }
        }
    }
    for name in ["MemTotal", "MemAvailable", "SwapTotal", "SwapFree"] {
        eprintln!(
            "memory.{}={}",
            name.to_ascii_lowercase(),
            values
                .get(name)
                .map(String::as_str)
                .unwrap_or("unavailable")
        );
    }
}
