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
    "netem",
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
        cfg.netem.clone(),
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

/// Map an axis name/value to the (column, value) it will be *recorded*
/// as, so a resumed sweep can tell which cells are already done.
///
/// Most axes round-trip unchanged. `sock-buf` does not: the axis takes
/// `16m` while the row records `16777216`, and comparing those as strings
/// would re-run every cell forever.
fn recorded_as(axis: &str, value: &str) -> (&'static str, String) {
    match axis {
        "runtime" => ("runtime", value.to_string()),
        "ingress" => ("ingress", value.to_string()),
        "promotion" => ("promotion", value.to_string()),
        "cookie-routing" => ("cookie", value.to_string()),
        "batch" => ("batch", value.to_string()),
        "sock-buf" => (
            "sock_buf",
            match value {
                "default" | "0" => "0".to_string(),
                v => {
                    let (digits, scale) = match v.strip_suffix(['m', 'M']) {
                        Some(d) => (d, 1usize << 20),
                        None => match v.strip_suffix(['k', 'K']) {
                            Some(d) => (d, 1usize << 10),
                            None => (v, 1),
                        },
                    };
                    digits
                        .parse::<usize>()
                        .map_or_else(|_| v.to_string(), |n| (n * scale).to_string())
                }
            },
        ),
        "connections" => ("conns", value.to_string()),
        "connect-concurrency" => ("connect_cc", value.to_string()),
        "bond" => ("bond", value.to_string()),
        "bitrate" => ("bitrate", value.to_string()),
        "pin" => ("pin", value.to_string()),
        other => (
            Box::leak(other.to_string().into_boxed_str()),
            value.to_string(),
        ),
    }
}

/// Identity of one (cell, rep) as it appears in a result file.
fn cell_key(cell: &[(&str, String)], rep: usize) -> String {
    let mut parts: Vec<String> = cell
        .iter()
        .map(|(axis, value)| {
            let (col, v) = recorded_as(axis, value);
            format!("{col}={v}")
        })
        .collect();
    parts.sort();
    parts.push(format!("rep={rep}"));
    parts.join(" ")
}

/// The same identity, read back off a recorded row.
fn record_key(record: &Record, cell: &[(&str, String)], rep: usize) -> Option<String> {
    let mut parts: Vec<String> = Vec::with_capacity(cell.len());
    for (axis, _) in cell {
        let (col, _) = recorded_as(axis, "");
        parts.push(format!("{col}={}", record.get(col)?));
    }
    parts.sort();
    parts.push(format!("rep={rep}"));
    Some(parts.join(" "))
}

/// Read a declarative sweep plan: `axis = v1,v2,v3` per line, `#` for
/// comments. Values merge with (and override) any given on the CLI.
///
/// A plan in a file rather than a shell loop because a comprehensive
/// sweep is hundreds of runs over hours: it needs to be reviewable before
/// it starts, reproducible afterwards, and identical across re-runs.
fn read_plan(path: &Path) -> std::io::Result<Vec<(String, Vec<String>)>> {
    let text = std::fs::read_to_string(path)?;
    let mut axes = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, values)) = line.split_once('=') {
            axes.push((
                name.trim().to_string(),
                values
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .collect(),
            ));
        }
    }
    Ok(axes)
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
    // Per-role CPU sets. Disjoint sets let the compute-bound side be
    // given cores without the other taking them back; see
    // docs/cpu-budget.md. Empty leaves the inherited mask alone.
    let recv_cpus = cli
        .flags
        .get("recv-cpus")
        .cloned()
        .unwrap_or_else(|| cli.flags.get("cpus").cloned().unwrap_or_default());
    let send_cpus = cli
        .flags
        .get("send-cpus")
        .cloned()
        .unwrap_or_else(|| cli.flags.get("cpus").cloned().unwrap_or_default());
    if !recv_cpus.is_empty() || !send_cpus.is_empty() {
        eprintln!("matrix: receiver CPUs [{recv_cpus}], sender CPUs [{send_cpus}]");
    }
    let reps: usize = cli.flag_or("reps", 3);
    let secs: u64 = cli.flag_or("secs", 8);
    let latency: u16 = cli.flag_or("latency", 120);

    // A plan file, when given, supplies axis values; anything it omits
    // falls back to the CLI flag and then the built-in default.
    let plan: Vec<(String, Vec<String>)> = match cli.flags.get("plan") {
        Some(path) if !path.is_empty() => read_plan(Path::new(path))?,
        _ => Vec::new(),
    };
    let from_plan = |name: &str| -> Option<Vec<String>> {
        plan.iter()
            .find(|(axis, _)| axis == name)
            .map(|(_, values)| values.clone())
    };
    let axis = |name: &'static str, flag: &str, default: &str| -> Axis {
        (
            name,
            from_plan(name).unwrap_or_else(|| axis_values(cli, flag, default)),
        )
    };

    let axes: Vec<Axis> = vec![
        axis("runtime", "runtimes", "mio"),
        axis("ingress", "ingress", "per-port"),
        axis("promotion", "promotion", "relocate"),
        axis("cookie-routing", "cookie-routing", "on"),
        axis("batch", "batch", "on"),
        axis("sock-buf", "sock-buf", "16m"),
        axis("pin", "pin", "off"),
        axis("netem", "netem", "none"),
        axis("connections", "connections", "25"),
        axis("connect-concurrency", "connect-concurrency", "1"),
        axis("bond", "bond", "none"),
        axis("bitrate", "bitrate", "8000000"),
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
    // Resume: a sweep of this size will be interrupted at some point, and
    // re-running completed cells wastes hours and mixes measurement
    // windows. Anything already in the output file is skipped.
    let done: std::collections::HashSet<String> = read_results(&out)
        .unwrap_or_default()
        .iter()
        .filter(|r| r.get("role") == Some("listener"))
        .filter_map(|r| {
            let rep: usize = r.number("rep")? as usize;
            cells
                .iter()
                .find_map(|cell| record_key(r, cell, rep).filter(|k| *k == cell_key(cell, rep)))
        })
        .collect();
    eprintln!(
        "matrix: {} cells x {reps} reps = {total} runs -> {}{}",
        cells.len(),
        out.display(),
        if done.is_empty() {
            String::new()
        } else {
            format!(" ({} already done, resuming)", done.len())
        }
    );


    // Every cell of a netem sweep runs inside the namespace, including the
    // `netem=none` ones: a namespace's loopback is not identical to the
    // host's, so mixing the two would confound the comparison the sweep
    // exists to make.
    let netns = if cells
        .iter()
        .any(|cell| cell.iter().any(|(a, v)| *a == "netem" && v != "none"))
    {
        // Fail before the first cell rather than midway through a sweep.
        for cell in &cells {
            for (axis, value) in cell {
                if *axis == "netem" && value != "none" {
                    netem_args(value).map_err(std::io::Error::other)?;
                }
            }
        }
        let p = Priv::detect()
            .ok_or_else(|| std::io::Error::other(netem_privilege_help()))?;
        netns_up(p)?;
        eprintln!("matrix: running roles inside netns '{NETNS}' (netem active)");
        Some(p)
    } else {
        None
    };

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
            if done.contains(&cell_key(cell, rep)) {
                continue;
            }
            if let Some(p) = netns {
                netem_apply(
                    p,
                    cell.iter()
                        .find(|(a, _)| *a == "netem")
                        .map_or("none", |(_, v)| v.as_str()),
                )?;
            }
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
            let mut recv = if let Some(p) = netns {
                in_netns(p, &exe)
            } else {
                std::process::Command::new(&exe)
            }
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
                .arg(format!("--cpus={recv_cpus}"))
                .arg(format!("--out={}", out.display()))
                .stdout(std::process::Stdio::null())
                .spawn()?;

            std::thread::sleep(std::time::Duration::from_millis(700));

            let send = if let Some(p) = netns {
                in_netns(p, &exe)
            } else {
                std::process::Command::new(&exe)
            }
                .arg(format!("runtime={runtime}"))
                .arg("mode=sender")
                .arg("127.0.0.1")
                .arg(port.to_string())
                .arg(secs.to_string())
                .arg(latency.to_string())
                .arg(&bitrate)
                .args(&common)
                .arg(format!("--rep={rep}"))
                .arg(format!("--cpus={send_cpus}"))
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
    if let Some(p) = netns {
        netns_down(p);
    }
    if skipped > 0 {
        eprintln!("matrix: skipped {skipped} unsupported cells");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Emulated network conditions
// ---------------------------------------------------------------------------

/// Name of the private network namespace the harness runs roles in when a
/// `--netem` spec is active.
const NETNS: &str = "srtbench";

/// Translate a `key=value,...` spec into `tc qdisc ... netem` arguments.
///
/// Deliberately a strict whitelist rather than a pass-through: these
/// arguments are handed to `sudo`, so an unrecognised key or a value that
/// is not a bare number with a known unit is rejected instead of
/// forwarded. Recognised keys mirror the netem options that matter for a
/// live streaming protocol:
///
/// - `delay` / `jitter` -- one-way latency and its variation. Loopback
///   RTT is ~0, so nothing that depends on RTT estimation, on the ACK
///   cadence, or on TLPKTDROP's deadline is otherwise under test.
/// - `loss` -- what the whole retransmission path exists for.
/// - `rate` -- a hard bottleneck, to produce genuine queueing rather
///   than the CPU-bound saturation loopback gives.
/// - `reorder` / `duplicate` -- the receiver's sequencing edge cases.
/// - `limit` -- netem's own backlog, in packets. Defaults to 1000, which
///   at these packet rates would silently make netem the bottleneck and
///   attribute its drops to the protocol; we raise it unless asked
///   otherwise.
fn netem_args(spec: &str) -> Result<Vec<String>, String> {
    /// A value is valid if some accepted unit suffix leaves a parseable
    /// number behind. Testing every unit rather than the first that
    /// strips matters: "100mbit" ends with "bit", and stopping there
    /// would leave "100m".
    fn valid(value: &str, units: &[&str]) -> bool {
        units.iter().any(|unit| {
            if unit.is_empty() {
                return value.parse::<u64>().is_ok();
            }
            value
                .strip_suffix(unit)
                .is_some_and(|d| !d.is_empty() && d.parse::<f64>().is_ok())
        })
    }

    const TIME: &[&str] = &["ms", "us", "s"];
    const PCT: &[&str] = &["%"];
    const RATE: &[&str] = &["bit", "kbit", "mbit", "gbit"];
    const PLAIN: &[&str] = &[""];

    let mut delay: Option<String> = None;
    let mut jitter: Option<String> = None;
    let mut limit = "100000".to_string();
    let mut rest: Vec<(String, String)> = Vec::new();

    for field in spec.split(',').map(str::trim).filter(|f| !f.is_empty()) {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| format!("netem: '{field}' is not key=value"))?;
        let (key, value) = (key.trim(), value.trim());
        let units: &[&str] = match key {
            "delay" | "jitter" => TIME,
            "loss" | "reorder" | "duplicate" | "corrupt" => PCT,
            "rate" => RATE,
            "limit" => PLAIN,
            other => {
                return Err(format!(
                    "netem: unknown key '{other}' (delay, jitter, loss, rate, \
                     reorder, duplicate, corrupt, limit)"
                ));
            }
        };
        if !valid(value, units) {
            return Err(format!("netem: bad value '{value}' for '{key}'"));
        }
        match key {
            "delay" => delay = Some(value.to_string()),
            "jitter" => jitter = Some(value.to_string()),
            "limit" => limit = value.to_string(),
            _ => rest.push((key.to_string(), value.to_string())),
        }
    }

    if jitter.is_some() && delay.is_none() {
        return Err("netem: jitter= requires delay=".to_string());
    }

    let mut args = vec!["limit".to_string(), limit];
    if let Some(d) = delay {
        args.push("delay".to_string());
        args.push(d);
        if let Some(j) = jitter {
            args.push(j);
        }
    }
    for (k, v) in rest {
        args.push(k);
        args.push(v);
    }
    Ok(args)
}

/// How this process can reach the privileged operations netem needs
/// (`ip netns`, `tc`). Resolved once per sweep.
///
/// Deliberately *not* solved with file capabilities on the binary:
/// entering a namespace needs `CAP_SYS_ADMIN`, `cargo build` replaces the
/// executable and silently drops any `setcap` grant, and a standing
/// `CAP_SYS_ADMIN` on a benchmark that spawns child processes is a far
/// wider grant than running one wrapper under sudo.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Priv {
    /// Already running as root -- typically because the whole sweep was
    /// started under `sudo ip netns exec`. Run the tools directly.
    Root,
    /// Not root, but `sudo -n` works. Prefix each privileged step.
    Sudo,
}

impl Priv {
    fn detect() -> Option<Self> {
        if unsafe { libc::geteuid() } == 0 {
            return Some(Self::Root);
        }
        std::process::Command::new("sudo")
            .args(["-n", "true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()
            .filter(std::process::ExitStatus::success)
            .map(|_| Self::Sudo)
    }

    fn command(self, program: &str) -> std::process::Command {
        match self {
            Self::Root => std::process::Command::new(program),
            Self::Sudo => {
                let mut c = std::process::Command::new("sudo");
                c.arg("-n").arg(program);
                c
            }
        }
    }
}

/// What to tell the user when neither route is available.
fn netem_privilege_help() -> String {
    let exe = std::env::args().next().unwrap_or_else(|| "srt-bench".into());
    format!(
        "--netem needs to create a private network namespace, which is a \
         privileged operation.\n\
         \n\
         Either allow passwordless sudo, or set the namespace up once and \
         run the sweep inside it:\n\
         \n    sudo ip netns add {NETNS}\n\
           sudo ip netns exec {NETNS} ip link set lo up\n\
           sudo ip netns exec {NETNS} {exe} matrix ...\n\
         \n\
         Started that way the harness is already root, applies netem \
         itself, and drops back to your uid for the bench processes so \
         the result file stays yours."
    )
}

/// Run one privileged setup step, returning a readable error on failure.
fn privileged(p: Priv, args: &[&str]) -> std::io::Result<()> {
    let (program, rest) = args.split_first().expect("non-empty command");
    let out = p.command(program).args(rest).output()?;
    if out.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "`{}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

/// Create the namespace and bring its loopback up. Idempotent.
fn netns_up(p: Priv) -> std::io::Result<()> {
    // A leftover namespace from an interrupted run is reused, not an error.
    let _ = privileged(p, &["ip", "netns", "add", NETNS]);
    privileged(
        p,
        &["ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up"],
    )
}

fn netns_down(p: Priv) {
    let _ = privileged(p, &["ip", "netns", "del", NETNS]);
}

/// Apply (or clear) the emulated conditions on the namespace's loopback.
fn netem_apply(p: Priv, spec: &str) -> std::io::Result<()> {
    let base = ["ip", "netns", "exec", NETNS, "tc", "qdisc"];
    if spec == "none" {
        let mut args: Vec<&str> = base.to_vec();
        args.extend(["del", "dev", "lo", "root"]);
        // Nothing to delete on the first cell; that is not a failure.
        let _ = privileged(p, &args);
        return Ok(());
    }
    let netem = netem_args(spec).map_err(std::io::Error::other)?;
    let mut args: Vec<&str> = base.to_vec();
    args.extend(["replace", "dev", "lo", "root", "netem"]);
    let owned: Vec<&str> = netem.iter().map(String::as_str).collect();
    args.extend(owned);
    privileged(p, &args)
}

/// Wrap a role invocation so it runs inside the namespace, as the calling
/// user rather than as root -- the child appends to the result file, and
/// a root-owned result file would break every later run.
fn in_netns(p: Priv, exe: &std::path::Path) -> std::process::Command {
    // When the sweep itself was started under sudo, `SUDO_UID` names the
    // human who ran it; otherwise we are already that user.
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or_else(|| unsafe { libc::getuid() });
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or_else(|| unsafe { libc::getgid() });

    let mut cmd = p.command("ip");
    cmd.args(["netns", "exec", NETNS]);
    if uid != 0 {
        cmd.arg("setpriv")
            .arg(format!("--reuid={uid}"))
            .arg(format!("--regid={gid}"))
            .arg("--clear-groups");
    }
    cmd.arg(exe);
    cmd
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


#[cfg(test)]
mod netem_tests {
    use super::netem_args;

    #[test]
    fn builds_tc_arguments_in_netem_order() {
        assert_eq!(
            netem_args("delay=25ms,jitter=5ms,loss=1%").unwrap(),
            ["limit", "100000", "delay", "25ms", "5ms", "loss", "1%"]
        );
    }

    #[test]
    fn raises_the_backlog_unless_told_otherwise() {
        // netem's default limit of 1000 packets would silently become the
        // bottleneck at these packet rates and look like protocol loss.
        assert_eq!(netem_args("loss=1%").unwrap()[..2], ["limit", "100000"]);
        assert_eq!(
            netem_args("loss=1%,limit=64").unwrap()[..2],
            ["limit", "64"]
        );
    }

    #[test]
    fn accepts_every_rate_unit() {
        for rate in ["1000bit", "100kbit", "100mbit", "1gbit"] {
            assert!(
                netem_args(&format!("rate={rate}")).is_ok(),
                "rejected rate={rate}"
            );
        }
    }

    #[test]
    fn rejects_anything_it_would_have_to_forward_blindly() {
        // These arguments are handed to a privileged command, so an
        // unknown key or a non-numeric value must not pass through.
        for spec in [
            "loss=1%; rm -rf /",
            "delay=$(whoami)",
            "script=evil",
            "loss=abc",
            "delay=25",   // unit required
            "loss=1",     // unit required
            "rate=100mb", // not a netem unit
            "delay",      // not key=value
        ] {
            assert!(netem_args(spec).is_err(), "accepted {spec:?}");
        }
    }

    #[test]
    fn jitter_without_delay_is_meaningless() {
        assert!(netem_args("jitter=5ms").is_err());
    }
}
