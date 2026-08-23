//! Result files and the orchestration that produces them.
//!
//! A benchmark run's output used to be a `STATS` line on stdout that a
//! shell harness re-parsed with inline Python. That put the schema in two
//! places -- the code that printed it and the regex that read it -- and
//! they drifted (an added column silently broke the median table). Here
//! the process that *has* the numbers writes them, and the process that
//! reports them reads the same struct back.
//!
//! The on-disk format is TSV with a header row, chosen over JSON because
//! it needs no dependency to write or parse, stays greppable, and drops
//! straight into `cut`/`sort`/a spreadsheet when someone wants to look at
//! it by hand.

use crate::{Batching, Ingress, LossConfig, Mode};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

/// Columns, in order. One place; both the writer and the reader use it.
pub const COLUMNS: &[&str] = &[
    "runtime",
    "role",
    "ingress",
    "promotion",
    "cookie",
    "batch",
    "sock_buf",
    "cpus",
    "pin",
    "conns",
    "connect_cc",
    "bond",
    "bitrate",
    "rep",
    "established",
    "pkt_sent",
    "core_total",
    "sec_a",
    "sec_b",
    "rtt_ms",
    "elapsed_s",
    "cpu_user_ms",
    "cpu_sys_ms",
    "peak_rss_kb",
];

/// The dimensions a run was configured with, rendered for the result
/// file. Kept separate from the measurements so a report can group by any
/// subset without knowing what the measurements mean.
#[must_use]
pub fn describe_ingress(ingress: Ingress) -> String {
    match ingress {
        Ingress::PerPort => "per-port".to_string(),
        Ingress::SharedPool(k) => format!("shared-pool:{k}"),
        Ingress::ReuseportMulti(k) => format!("reuseport-multi:{k}"),
        Ingress::ReuseportSingle { workers } => format!("reuseport-single:{workers}"),
    }
}

#[must_use]
fn describe_bond(cfg: &LossConfig) -> String {
    match cfg.bond_mode {
        crate::BondMode::None => "none".to_string(),
        crate::BondMode::Broadcast => format!("broadcast:{}", cfg.bond_pairs),
        crate::BondMode::Backup => format!("backup:{}", cfg.bond_pairs),
    }
}

/// One measured run: its configuration plus what came out of it.
#[derive(Clone, Debug, Default)]
pub struct Record {
    pub fields: Vec<(String, String)>,
}

impl Record {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[must_use]
    pub fn number(&self, key: &str) -> Option<f64> {
        self.get(key)?.parse().ok()
    }
}

/// Append one run's result, writing the header first if the file is new.
///
/// Appending (rather than truncating) is deliberate: a sweep is many
/// processes writing to one file, and each is a separate `srt-bench`
/// invocation with no knowledge of its siblings.
pub fn append_result(
    path: &Path,
    cfg: &LossConfig,
    rep: usize,
    established: u64,
    pkt_sent: u64,
    core_total: u64,
    sec_a: u64,
    sec_b: u64,
    rtt_ms: f64,
    elapsed_s: f64,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let fresh = !path.exists()
        || std::fs::metadata(path)
            .map(|m| m.len() == 0)
            .unwrap_or(true);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if fresh {
        writeln!(file, "{}", COLUMNS.join("\t"))?;
    }
    let p = crate::cpu_stats::process_stats();
    let mut row = String::new();
    let values: Vec<String> = vec![
        cfg.runtime.name().to_string(),
        match cfg.mode {
            Mode::Sender => "caller".into(),
            Mode::Receiver => "listener".into(),
        },
        describe_ingress(cfg.ingress),
        format!("{:?}", cfg.promotion).to_lowercase(),
        if cfg.cookie_routing { "on" } else { "off" }.into(),
        match cfg.batching {
            Batching::On => "on".into(),
            Batching::Off => "off".into(),
        },
        cfg.sock_buf_bytes.to_string(),
        srt_transport::available_cpus().to_string(),
        if cfg.pin { "on" } else { "off" }.into(),
        cfg.connections.to_string(),
        cfg.connect_concurrency.to_string(),
        describe_bond(cfg),
        cfg.bitrate_bps.to_string(),
        rep.to_string(),
        established.to_string(),
        pkt_sent.to_string(),
        core_total.to_string(),
        sec_a.to_string(),
        sec_b.to_string(),
        format!("{rtt_ms:.3}"),
        format!("{elapsed_s:.3}"),
        format!("{:.1}", p.cpu_user_ms),
        format!("{:.1}", p.cpu_sys_ms),
        p.peak_rss_kb.to_string(),
    ];
    debug_assert_eq!(values.len(), COLUMNS.len(), "row/header width mismatch");
    let _ = write!(row, "{}", values.join("\t"));
    writeln!(file, "{row}")
}

/// Read every record from a TSV result file.
pub fn read_results(path: &Path) -> std::io::Result<Vec<Record>> {
    let text = std::fs::read_to_string(path)?;
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Ok(Vec::new());
    };
    let keys: Vec<&str> = header.split('\t').collect();
    Ok(lines
        .filter(|l| !l.trim().is_empty())
        .map(|line| Record {
            fields: keys
                .iter()
                .zip(line.split('\t'))
                .map(|(k, v)| ((*k).to_string(), v.to_string()))
                .collect(),
        })
        .collect())
}

/// Median, and the range it was drawn from.
///
/// A median alone cannot answer "is A better than B or is this noise?".
/// Reporting the spread lets a reader see overlap directly, which is the
/// honest form for n in the single digits -- too few samples for a
/// meaningful significance test, more than enough to see when two ranges
/// sit on top of each other.
#[derive(Clone, Copy, Debug, Default)]
pub struct Spread {
    pub n: usize,
    pub median: f64,
    pub min: f64,
    pub max: f64,
}

impl Spread {
    #[must_use]
    pub fn of(mut values: Vec<f64>) -> Self {
        if values.is_empty() {
            return Self::default();
        }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Self {
            n: values.len(),
            median: median(values.clone()),
            min: values[0],
            max: values[values.len() - 1],
        }
    }

    /// Do these two ranges overlap? If so, the difference between their
    /// medians is not supported by the samples taken.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.min <= other.max && other.min <= self.max
    }

    /// Spread as a percentage of the median -- how noisy this cell was.
    #[must_use]
    pub fn rel_spread_pct(self) -> f64 {
        if self.median.abs() < f64::EPSILON {
            return 0.0;
        }
        100.0 * (self.max - self.min) / self.median
    }
}

fn median(mut values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

/// Per-group dispersion for one column, for callers that need to reason
/// about overlap rather than read a table.
#[must_use]
pub fn spread_by(results: &[Record], group_by: &[String], column: &str) -> Vec<(String, Spread)> {
    let key_of = |r: &Record| -> String {
        group_by
            .iter()
            .map(|k| r.get(k).unwrap_or("-").to_string())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut keys: Vec<String> = Vec::new();
    for r in results {
        let k = key_of(r);
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    keys.sort();
    keys.into_iter()
        .map(|key| {
            let values: Vec<f64> = results
                .iter()
                .filter(|r| key_of(r) == key)
                .filter_map(|r| r.number(column))
                .collect();
            (key, Spread::of(values))
        })
        .collect()
}

/// Print a median table over `results`, one row per distinct combination
/// of `group_by` columns.
///
/// Pairs each listener row with the caller rows sharing its configuration
/// so delivery can be shown as received-over-sent; a listener count on its
/// own cannot distinguish "dropped packets" from "the sender sent fewer".
pub fn report(results: &[Record], group_by: &[String]) -> String {
    let key_of = |r: &Record| -> String {
        group_by
            .iter()
            .map(|k| r.get(k).unwrap_or("-").to_string())
            .collect::<Vec<_>>()
            .join("\t")
    };

    let mut keys: Vec<String> = Vec::new();
    for r in results {
        let k = key_of(r);
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    keys.sort();

    let mut out = String::new();
    let headers: Vec<String> = group_by
        .iter()
        .cloned()
        .chain(
            [
                "estab", "sent", "recv", "deliv%", "lost", "rtt_ms", "cpu_s", "rss_kb",
            ]
            .iter()
            .map(|s| (*s).to_string()),
        )
        .collect();
    let mut rows: Vec<Vec<String>> = vec![headers];

    for key in keys {
        let cells: Vec<&Record> = results.iter().filter(|r| key_of(r) == key).collect();
        let listeners: Vec<&&Record> = cells
            .iter()
            .filter(|r| r.get("role") == Some("listener"))
            .collect();
        let callers: Vec<&&Record> = cells
            .iter()
            .filter(|r| r.get("role") == Some("caller"))
            .collect();
        if listeners.is_empty() {
            continue;
        }
        let med = |rs: &[&&Record], col: &str| -> f64 {
            median(rs.iter().filter_map(|r| r.number(col)).collect())
        };
        let recv = med(&listeners, "core_total");
        let sent = med(&callers, "core_total");
        let deliv = if sent > 0.0 { 100.0 * recv / sent } else { 0.0 };
        // CPU is the whole pipeline's cost, so both sides count.
        let cpu = (med(&listeners, "cpu_user_ms")
            + med(&listeners, "cpu_sys_ms")
            + med(&callers, "cpu_user_ms")
            + med(&callers, "cpu_sys_ms"))
            / 1000.0;
        let mut row: Vec<String> = key.split('\t').map(str::to_string).collect();
        row.push(format!("{:.0}", med(&listeners, "established")));
        row.push(format!("{sent:.0}"));
        row.push(format!("{recv:.0}"));
        row.push(format!("{deliv:.1}"));
        row.push(format!("{:.0}", med(&listeners, "sec_a")));
        row.push(format!("{:.2}", med(&listeners, "rtt_ms")));
        row.push(format!("{cpu:.1}"));
        row.push(format!(
            "{:.0}",
            med(&listeners, "peak_rss_kb").max(med(&callers, "peak_rss_kb"))
        ));
        rows.push(row);
    }

    let width = rows[0].len();
    let mut widths = vec![0usize; width];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i + 1 == width {
                let _ = writeln!(out, "{cell:>w$}", w = widths[i]);
            } else if i < group_by.len() {
                let _ = write!(out, "{cell:<w$}  ", w = widths[i]);
            } else {
                let _ = write!(out, "{cell:>w$}  ", w = widths[i]);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Matrix orchestration
// ---------------------------------------------------------------------------

/// One axis of the sweep: a name and the values to try.
type Axis = (&'static str, Vec<String>);

/// Find `count` consecutive free UDP ports and return the base.
///
/// A cell may need a whole range, not one port: `per-port` binds
/// `base..base+connections`, and `shared-pool:K` binds `base..base+K`.
/// Reserving a single port and assuming the rest of the range is free is
/// how a sweep ends up with half its tokio cells dying on EADDRINUSE.
///
/// Candidates come from below the ephemeral range
/// (`/proc/sys/net/ipv4/ip_local_port_range`, 32768+ on this host)
/// because the kernel hands those out to unrelated sockets while the
/// sweep runs, so a port that probes free can be taken moments later.
fn free_port_range(count: usize) -> std::io::Result<u16> {
    const LOW: u16 = 20_000;
    const HIGH: u16 = 31_000;
    let span = u32::from(HIGH - LOW) - count as u32;
    for attempt in 0..200u32 {
        // Cheap spread without pulling in a RNG: the clock's low bits,
        // walked forward on each retry.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = LOW
            + ((seed
                .wrapping_mul(2_654_435_761)
                .wrapping_add(attempt * 7_919))
                % span) as u16;
        // Hold every port at once: binding them one at a time would let
        // the range be interleaved with someone else's socket.
        let held: Vec<std::net::UdpSocket> = (0..count)
            .map_while(|i| std::net::UdpSocket::bind(("127.0.0.1", base + i as u16)).ok())
            .collect();
        if held.len() == count {
            return Ok(base);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!("no run of {count} free ports in {LOW}..{HIGH}"),
    ))
}

fn axis_values(cli: &crate::Cli, flag: &str, default: &str) -> Vec<String> {
    cli.flags.get(flag).filter(|v| !v.is_empty()).map_or_else(
        || vec![default.to_string()],
        |v| v.split(',').map(str::trim).map(str::to_string).collect(),
    )
}

/// Run the cartesian product of the requested axes, one receiver/sender
/// pair per cell, appending both sides' results to `out`.
///
/// Each side is a fresh child process rather than a thread: CPU is
/// measured with `getrusage`, which is per-process, so running both roles
/// in one process would attribute the sender's cost to the listener.
pub fn run_matrix(cli: &crate::Cli) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let out = std::path::PathBuf::from(
        cli.flags
            .get("out")
            .cloned()
            .unwrap_or_else(|| "scratch/results.tsv".to_string()),
    );
    let reps: usize = cli.flag_or("reps", 3);
    let secs: u64 = cli.flag_or("secs", 8);
    let latency: u16 = cli.flag_or("latency", 120);

    let axes: Vec<Axis> = vec![
        ("runtime", axis_values(cli, "runtimes", "mio")),
        ("ingress", axis_values(cli, "ingress", "per-port")),
        ("promotion", axis_values(cli, "promotion", "relocate")),
        ("cookie-routing", axis_values(cli, "cookie-routing", "on")),
        ("batch", axis_values(cli, "batch", "on")),
        ("sock-buf", axis_values(cli, "sock-buf", "16m")),
        ("cpus", axis_values(cli, "cpus", "0")),
        ("pin", axis_values(cli, "pin", "off")),
        ("connections", axis_values(cli, "connections", "25")),
        (
            "connect-concurrency",
            axis_values(cli, "connect-concurrency", "1"),
        ),
        ("bond", axis_values(cli, "bond", "none")),
        ("bitrate", axis_values(cli, "bitrate", "8000000")),
    ];

    // Cartesian product, expanded eagerly: the whole point is to know how
    // many cells there are before starting a long sweep.
    let mut cells: Vec<Vec<(&str, String)>> = vec![Vec::new()];
    for (name, values) in &axes {
        let mut next = Vec::new();
        for base in &cells {
            for v in values {
                let mut row = base.clone();
                row.push((name, v.clone()));
                next.push(row);
            }
        }
        cells = next;
    }

    let total = cells.len() * reps;
    eprintln!(
        "matrix: {} cells x {reps} reps = {total} runs -> {}",
        cells.len(),
        out.display()
    );

    let mut skipped = 0usize;
    for (index, cell) in cells.iter().enumerate() {
        let label: Vec<String> = cell.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let value = |name: &str| -> Option<String> {
            cell.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
        };
        let ingress = value("ingress").unwrap_or_else(|| "per-port".into());
        let conns_in_cell: usize = value("connections")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let bitrate = value("bitrate").unwrap_or_else(|| "8000000".into());
        let runtime = value("runtime").unwrap_or_else(|| "mio".into());
        // per-port needs one port per connection; the pooled and
        // reuseport strategies need at most K. Ask for the worst case
        // this cell could use.
        let ports_needed = if ingress == "per-port" {
            conns_in_cell
        } else {
            ingress
                .split_once(':')
                .and_then(|(_, k)| k.parse().ok())
                .unwrap_or(1)
        };
        // Skip combinations the runtime does not implement rather than
        // running them and recording the wreckage: an unsupported cell
        // produces bind collisions that look exactly like a harness bug.
        if !crate::runtimes::ingress_supported(
            crate::Runtime::parse(&runtime).unwrap_or(crate::Runtime::Mio),
            parse_ingress_spec(&ingress),
        ) {
            skipped += 1;
            eprintln!("[skip] {} (unsupported)", label.join(" "));
            continue;
        }
        for rep in 1..=reps {
            let port = free_port_range(ports_needed)?;
            let flags: Vec<String> = cell
                .iter()
                .filter(|(k, _)| *k != "bitrate")
                .map(|(k, v)| format!("--{k}={v}"))
                .collect();
            let common: Vec<String> = flags
                .iter()
                .filter(|f| !f.starts_with("--runtime="))
                .cloned()
                .collect();

            // Receiver outlives the sender so it is still listening when
            // the last packets arrive; +5s mirrors the old harness.
            let mut recv = std::process::Command::new(&exe)
                .arg(format!("runtime={runtime}"))
                .arg("mode=receiver")
                .arg(port.to_string())
                .arg((secs + 5).to_string())
                .arg(latency.to_string())
                // The receiver ignores this functionally, but both rows
                // must record the same configured bitrate or a report
                // grouping on it would split the pair and lose delivery%.
                .arg(&bitrate)
                .args(&common)
                .arg(format!("--rep={rep}"))
                .arg(format!("--out={}", out.display()))
                .stdout(std::process::Stdio::null())
                .spawn()?;

            std::thread::sleep(std::time::Duration::from_millis(700));

            let send = std::process::Command::new(&exe)
                .arg(format!("runtime={runtime}"))
                .arg("mode=sender")
                .arg("127.0.0.1")
                .arg(port.to_string())
                .arg(secs.to_string())
                .arg(latency.to_string())
                .arg(&bitrate)
                .args(&common)
                .arg(format!("--rep={rep}"))
                .arg(format!("--out={}", out.display()))
                .stdout(std::process::Stdio::null())
                .status()?;

            let recv_status = recv.wait()?;
            eprintln!(
                "[{:>4}/{total}] rep {rep} {}{}",
                index * reps + rep,
                label.join(" "),
                if send.success() && recv_status.success() {
                    String::new()
                } else {
                    format!(" (sender={send} receiver={recv_status})")
                }
            );
        }
    }
    if skipped > 0 {
        eprintln!("matrix: skipped {skipped} unsupported cells");
    }
    Ok(())
}

/// Re-parse an ingress spec as recorded in a result file (`:` separated).
fn parse_ingress_spec(spec: &str) -> crate::Ingress {
    match spec.split_once(':') {
        Some(("shared-pool", k)) => crate::Ingress::SharedPool(k.parse().unwrap_or(1)),
        Some(("reuseport-multi", k)) => crate::Ingress::ReuseportMulti(k.parse().unwrap_or(1)),
        Some(("reuseport-single", w)) => crate::Ingress::ReuseportSingle {
            workers: w.parse().unwrap_or(1),
        },
        _ => crate::Ingress::PerPort,
    }
}

// ---------------------------------------------------------------------------
// perf attribution
// ---------------------------------------------------------------------------

/// Tracepoints worth attributing per packet.
///
/// Socket syscalls cover the readiness backends. The io_uring backends
/// issue almost none -- every operation is a submission queue entry --
/// so without the SQE tracepoint they would look free rather than
/// different.
const PERF_EVENTS: &str = "syscalls:sys_enter_recvfrom,syscalls:sys_enter_sendto,\
syscalls:sys_enter_sendmsg,syscalls:sys_enter_recvmsg,\
syscalls:sys_enter_epoll_wait,io_uring:io_uring_submit_req";

/// Parse `perf stat -x,` CSV into event name -> count.
///
/// Rows are `count,unit,event,...`; anything without a `subsystem:event`
/// in the third column is a comment or a header line.
fn parse_perf_csv(text: &str) -> Vec<(String, u64)> {
    text.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            let event = parts.get(2)?;
            let (_, name) = event.split_once(':')?;
            let count = parts.first()?.trim().parse::<f64>().ok()?;
            Some((name.to_string(), count as u64))
        })
        .collect()
}

/// Run one receiver/sender pair under `perf stat` and print syscall and
/// io_uring counts normalised per 10k packets.
///
/// Lives here rather than in a shell script because the parsing is a
/// comma split and a division; the only thing genuinely external is
/// `perf` itself.
pub fn run_sysprof(cli: &crate::Cli) -> std::io::Result<()> {
    let exe = std::env::current_exe()?;
    let runtime = cli
        .flags
        .get("runtime")
        .cloned()
        .unwrap_or_else(|| "mio".to_string());
    let conns: usize = cli.flag_or("connections", 25);
    let secs: u64 = cli.flag_or("secs", 8);
    let latency: u16 = cli.flag_or("latency", 120);
    let dir = std::path::PathBuf::from(
        cli.flags
            .get("dir")
            .cloned()
            .unwrap_or_else(|| "scratch".to_string()),
    );
    std::fs::create_dir_all(&dir)?;
    let port = free_port_range(1)?;

    let results = dir.join(format!("sysprof_{runtime}.tsv"));
    let _ = std::fs::remove_file(&results);
    let side = |role: &str| dir.join(format!("sysprof_{runtime}_{role}.perf"));

    let mut recv = std::process::Command::new("perf")
        .args(["stat", "-e", PERF_EVENTS, "-x,", "-o"])
        .arg(side("listener"))
        .arg(&exe)
        .arg(format!("runtime={runtime}"))
        .arg("mode=receiver")
        .arg(port.to_string())
        .arg((secs + 5).to_string())
        .arg(latency.to_string())
        .arg(format!("--connections={conns}"))
        .arg(format!("--out={}", results.display()))
        .stdout(std::process::Stdio::null())
        .spawn()?;
    std::thread::sleep(std::time::Duration::from_millis(700));
    let _ = std::process::Command::new("perf")
        .args(["stat", "-e", PERF_EVENTS, "-x,", "-o"])
        .arg(side("caller"))
        .arg(&exe)
        .arg(format!("runtime={runtime}"))
        .arg("mode=sender")
        .arg("127.0.0.1")
        .arg(port.to_string())
        .arg(secs.to_string())
        .arg(latency.to_string())
        .arg(format!("--connections={conns}"))
        .arg(format!("--out={}", results.display()))
        .stdout(std::process::Stdio::null())
        .status()?;
    recv.wait()?;

    let records = read_results(&results).unwrap_or_default();
    println!("=== syscall attribution: {runtime}, {conns} connections ===");
    for role in ["caller", "listener"] {
        let counts = std::fs::read_to_string(side(role))
            .map(|t| parse_perf_csv(&t))
            .unwrap_or_default();
        let packets = records
            .iter()
            .find(|r| r.get("role") == Some(role))
            .and_then(|r| r.number("core_total"))
            .unwrap_or(0.0);
        let total: u64 = counts.iter().map(|(_, c)| c).sum();
        println!("{role:9} packets={packets:.0} total_ops={total}");
        if packets > 0.0 {
            let scale = 10_000.0 / packets;
            for (event, count) in &counts {
                println!(
                    "{:9} {event:<28} {:>10.1} per 10k pkt",
                    "",
                    *count as f64 * scale
                );
            }
        }
    }
    Ok(())
}
