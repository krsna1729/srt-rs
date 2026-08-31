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

use crate::{Batching, BenchConfig, Ingress, Mode};
use std::fmt::Write as _;
use std::io::Read as _;
use std::io::Write as _;
use std::path::Path;

/// Advisory lock held while a complete header/row record is appended.
///
/// Matrix roles are separate processes, so a Rust mutex cannot protect the
/// shared result file. `flock` also covers the fresh-file check, which is the
/// part that previously allowed two children to both write a header.
struct AppendLock {
    #[cfg(unix)]
    fd: std::os::fd::RawFd,
    #[cfg(not(unix))]
    _marker: std::marker::PhantomData<*const std::fs::File>,
}

impl AppendLock {
    fn acquire(file: &std::fs::File) -> std::io::Result<Self> {
        Self::acquire_mode(file, libc::LOCK_EX)
    }

    fn shared(file: &std::fs::File) -> std::io::Result<Self> {
        Self::acquire_mode(file, libc::LOCK_SH)
    }

    fn acquire_mode(file: &std::fs::File, mode: libc::c_int) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = file.as_raw_fd();
            // SAFETY: `fd` is a valid open file descriptor owned by `file`.
            let result = unsafe { libc::flock(fd, mode) };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self { fd })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                _marker: std::marker::PhantomData,
            })
        }
    }
}

impl Drop for AppendLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // SAFETY: `self.fd` was a valid fd at construction and is released here.
            let _ = unsafe { libc::flock(self.fd, libc::LOCK_UN) };
        }
    }
}

/// Columns, in order. One place; both the writer and the reader use it.
pub const COLUMNS: &[&str] = &[
    "runtime",
    "encryption",
    "role",
    "ingress",
    "egress",
    "promotion",
    "cookie",
    "batch",
    "sock_buf",
    "cpus",
    "pin",
    "link_delay",
    "link_jitter",
    "link_loss",
    "link_rate",
    "link_reorder",
    "link_duplicate",
    "link_corrupt",
    "link_limit",
    "workers",
    "recv_runtime",
    "send_runtime",
    "recv_ingress",
    "send_ingress",
    "recv_workers",
    "send_workers",
    "conns",
    "connect_cc",
    "bond",
    "bitrate",
    "rep",
    "established",
    "torn_down",
    "pkt_sent",
    "core_total",
    "sec_a",
    "sec_b",
    "rtt_ms",
    "elapsed_s",
    "cpu_user_ms",
    "cpu_sys_ms",
    "peak_rss_kb",
    "secs",
    "udp_rcvbuf_err",
    "udp_in_err",
    "udp_no_ports",
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
fn describe_bond(cfg: &BenchConfig) -> String {
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
#[expect(
    clippy::too_many_arguments,
    reason = "the append-only TSV row keeps each recorded benchmark field explicit"
)]
pub fn append_result(
    path: &Path,
    cfg: &BenchConfig,
    rep: usize,
    established: u64,
    torn_down: u64,
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
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let _lock = AppendLock::acquire(&file)?;
    let fresh = file.metadata()?.len() == 0;
    if fresh {
        writeln!(file, "{}", COLUMNS.join("\t"))?;
    }
    let p = crate::cpu_stats::process_stats();
    // Kernel-side drops for this process's lifetime: the only thing that
    // distinguishes "the protocol lost it" from "the kernel dropped it
    // before the protocol saw it".
    let udp = crate::cpu_stats::udp_counters().since(crate::cpu_stats::udp_baseline());
    let mut row = String::new();
    let values: Vec<String> = vec![
        cfg.runtime.name().to_string(),
        cfg.encryption.name().to_string(),
        match cfg.mode {
            Mode::Sender => "caller".into(),
            Mode::Receiver => "listener".into(),
        },
        describe_ingress(cfg.ingress),
        match cfg.egress {
            crate::Egress::PerConnection => "per-connection".into(),
            crate::Egress::SharedSocket => "shared-socket".into(),
        },
        format!("{:?}", cfg.promotion).to_lowercase(),
        if cfg.cookie_routing { "on" } else { "off" }.into(),
        match cfg.batching {
            Batching::On => "on".into(),
            Batching::Off => "off".into(),
        },
        cfg.sock_buf_bytes.to_string(),
        srt_transport::available_cpus().to_string(),
        if cfg.pin { "on" } else { "off" }.into(),
        cfg.link.get("delay").to_string(),
        cfg.link.get("jitter").to_string(),
        cfg.link.get("loss").to_string(),
        cfg.link.get("rate").to_string(),
        cfg.link.get("reorder").to_string(),
        cfg.link.get("duplicate").to_string(),
        cfg.link.get("corrupt").to_string(),
        cfg.link.get("limit").to_string(),
        cfg.workers.to_string(),
        cfg.peer_topology.recv_runtime.clone(),
        cfg.peer_topology.send_runtime.clone(),
        cfg.peer_topology.recv_ingress.clone(),
        cfg.peer_topology.send_ingress.clone(),
        cfg.peer_topology.recv_workers.clone(),
        cfg.peer_topology.send_workers.clone(),
        cfg.connections.to_string(),
        cfg.connect_concurrency.to_string(),
        describe_bond(cfg),
        cfg.bitrate_bps.to_string(),
        rep.to_string(),
        established.to_string(),
        torn_down.to_string(),
        pkt_sent.to_string(),
        core_total.to_string(),
        sec_a.to_string(),
        sec_b.to_string(),
        format!("{rtt_ms:.3}"),
        format!("{elapsed_s:.3}"),
        format!("{:.1}", p.cpu_user_ms),
        format!("{:.1}", p.cpu_sys_ms),
        p.peak_rss_kb.to_string(),
        format!("{:.0}", cfg.stream_secs),
        udp.rcvbuf_errors.to_string(),
        udp.in_errors.to_string(),
        udp.no_ports.to_string(),
    ];
    debug_assert_eq!(values.len(), COLUMNS.len(), "row/header width mismatch");
    let _ = write!(row, "{}", values.join("\t"));
    writeln!(file, "{row}")
}

/// Read every record from a TSV result file.
pub fn read_results(path: &Path) -> std::io::Result<Vec<Record>> {
    let mut file = std::fs::File::open(path)?;
    let _lock = AppendLock::shared(&file)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return Ok(Vec::new());
    };
    let keys: Vec<&str> = header.split('\t').collect();
    if keys != COLUMNS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{}: unexpected TSV header (expected {} columns, got {})",
                path.display(),
                COLUMNS.len(),
                keys.len()
            ),
        ));
    }
    let mut records = Vec::new();
    for (line_number, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let values: Vec<&str> = line.split('\t').collect();
        if values.len() != keys.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{}:{}: malformed TSV row (expected {} columns, got {})",
                    path.display(),
                    line_number + 2,
                    keys.len(),
                    values.len()
                ),
            ));
        }
        records.push(Record {
            fields: keys
                .iter()
                .zip(values)
                .map(|(k, v)| ((*k).to_string(), v.to_string()))
                .collect(),
        });
    }
    Ok(records)
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
    if values.len().is_multiple_of(2) {
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
                "pairs",
                "estab",
                "sent",
                "recv",
                "offer%",
                "good%",
                "deliv%",
                "lost",
                "rcvbuf_drop",
                "torn_c",
                "torn_l",
                "rtt_ms",
                "cpu_s",
                "rss_kb",
            ]
            .iter()
            .map(|s| (*s).to_string()),
        )
        .collect();
    let mut rows: Vec<Vec<String>> = vec![headers];

    for key in keys {
        let cells: Vec<&Record> = results.iter().filter(|r| key_of(r) == key).collect();

        // Pair the two roles per rep instead of averaging each side
        // independently. A run interrupted mid-cell leaves a caller row
        // with no listener row, and resume only counts listener rows, so
        // re-running appends a *second* caller row. Medianing the two
        // sides separately then divides a complete listener figure by the
        // median of one complete and one truncated caller -- which is how
        // a delivery rate of 139% appeared. Later rows win, the file
        // being append-only, and a rep missing either side is dropped.
        let mut paired: std::collections::BTreeMap<String, (Option<&Record>, Option<&Record>)> =
            std::collections::BTreeMap::new();
        for r in &cells {
            let rep = r.get("rep").unwrap_or("1").to_string();
            let slot = paired.entry(rep).or_default();
            match r.get("role") {
                Some("caller") => slot.0 = Some(r),
                Some("listener") => slot.1 = Some(r),
                _ => {}
            }
        }
        let (callers, listeners): (Vec<&Record>, Vec<&Record>) = paired
            .values()
            .filter_map(|(c, l)| Some((*c.as_ref()?, *l.as_ref()?)))
            .unzip();
        if listeners.is_empty() {
            continue;
        }
        let med = |rs: &[&Record], col: &str| -> f64 {
            median(rs.iter().filter_map(|r| r.number(col)).collect())
        };
        let recv = med(&listeners, "core_total");
        let sent = med(&callers, "core_total");
        let deliv = if sent > 0.0 { 100.0 * recv / sent } else { 0.0 };

        // `deliv%` is recv/sent -- a ratio against whatever the sender
        // happened to emit, which says nothing when the sender itself was
        // the constraint. These two are measured against the load that was
        // *asked for*, so a load generator that could not keep up shows up
        // as a low `offer%` instead of silently deflating the listener's
        // score. `--` on results recorded before `secs` was a column.
        let target = |r: &&Record| -> Option<f64> {
            let (conns, bitrate, secs) =
                (r.number("conns")?, r.number("bitrate")?, r.number("secs")?);
            let pkts = conns * bitrate * secs / (8.0 * crate::PAYLOAD_SIZE as f64);
            (pkts > 0.0).then_some(pkts)
        };
        let target_pkts = median(callers.iter().filter_map(target).collect());
        let pct = |n: f64| -> String {
            if target_pkts > 0.0 {
                format!("{:.1}", 100.0 * n / target_pkts)
            } else {
                "--".to_string()
            }
        };
        // `sent` is `SenderBuffer::total_sent`, which counts a packet when
        // it is first queued and is NOT incremented by `pop_retransmit`.
        // Retransmits are already excluded, so subtracting them again
        // double-counts -- and where loss was heavy enough that retransmits
        // exceeded originals it floored the figure at zero, reporting a
        // sender that offered nothing while it sent two million packets.
        let offered = sent;
        // CPU is the whole pipeline's cost, so both sides count.
        let cpu = (med(&listeners, "cpu_user_ms")
            + med(&listeners, "cpu_sys_ms")
            + med(&callers, "cpu_user_ms")
            + med(&callers, "cpu_sys_ms"))
            / 1000.0;
        let mut row: Vec<String> = key.split('\t').map(str::to_string).collect();
        // All reported medians below are based on these complete caller /
        // listener pairs. Expose their count so a human or downstream tool
        // never mistakes one recovered sample for a stable comparison.
        row.push(listeners.len().to_string());
        row.push(format!("{:.0}", med(&listeners, "established")));
        row.push(format!("{sent:.0}"));
        row.push(format!("{recv:.0}"));
        row.push(pct(offered));
        row.push(pct(recv));
        row.push(format!("{deliv:.1}"));
        row.push(format!("{:.0}", med(&listeners, "sec_a")));
        row.push(format!("{:.0}", med(&listeners, "udp_rcvbuf_err")));
        // Caller and listener are two independent observers of the same
        // connections, and they do not always agree on which ones broke
        // -- the investigation this column exists for found every
        // instance on the caller side and none on the listener. Reporting
        // both, rather than a combined count, is what makes that visible.
        row.push(format!("{:.0}", med(&callers, "torn_down")));
        row.push(format!("{:.0}", med(&listeners, "torn_down")));
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

/// Render the listener-side throughput series expected by
/// benchmark-action's `customBiggerIsBetter` tool.
///
/// Keep this beside `report`: both consumers read the same validated TSV
/// records, and the runtime order remains the first-seen order from the
/// result file so chart updates stay stable.
pub fn github_benchmark_json(results: &[Record]) -> String {
    let mut series: Vec<(String, f64, f64)> = Vec::new();
    for record in results {
        if record.get("role") != Some("listener") {
            continue;
        }
        let Some(runtime) = record.get("runtime") else {
            continue;
        };
        let sent = record
            .number("pkt_sent")
            .filter(|value| value.is_finite())
            .unwrap_or(0.0);
        let elapsed = record
            .number("elapsed_s")
            .filter(|value| value.is_finite())
            .unwrap_or(0.0);
        if let Some((_, total_sent, total_elapsed)) =
            series.iter_mut().find(|(name, _, _)| name == runtime)
        {
            *total_sent += sent;
            *total_elapsed += elapsed;
        } else {
            series.push((runtime.to_string(), sent, elapsed));
        }
    }

    let mut out = String::from("[");
    let mut emitted = false;
    for (runtime, sent, elapsed) in series {
        if elapsed <= 0.0 {
            continue;
        }
        if emitted {
            out.push(',');
        }
        let value = sent / elapsed;
        let _ = write!(
            out,
            "\n  {{\"name\": {}, \"unit\": \"pkt/s\", \"value\": {value:.1}}}",
            json_string(&runtime)
        );
        emitted = true;
    }
    out.push_str("\n]\n");
    out
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Matrix orchestration
// ---------------------------------------------------------------------------

/// One axis of the sweep: a name and the values to try.
/// Which role an axis value applies to.
///
/// `Both` is the default and keeps the two ends in lockstep, which is
/// what you want while looking for a ceiling: one number to move. `Recv`
/// and `Send` appear only once a knob has been given a role-prefixed
/// value, and then the two sides are genuinely independent axes -- the
/// production shape, where ingest and egress are configured separately.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    Both,
    Recv,
    Send,
}

impl Scope {
    /// Does a value with this scope reach the given role's process?
    fn applies_to(self, role: Scope) -> bool {
        self == Scope::Both || self == role
    }

    /// Column prefix used to record this scope's value.
    fn prefix(self) -> &'static str {
        match self {
            Scope::Both => "",
            Scope::Recv => "recv_",
            Scope::Send => "send_",
        }
    }
}

type Axis = (&'static str, Scope, Vec<String>);

/// One point in the sweep: every axis resolved to a value, with the role
/// it applies to.
type Cell<'a> = Vec<(&'a str, Scope, String)>;

#[derive(Default)]
struct MatrixFilterSummary {
    by_reason: std::collections::BTreeMap<&'static str, usize>,
}

impl MatrixFilterSummary {
    fn record(&mut self, reason: &'static str) {
        *self.by_reason.entry(reason).or_default() += 1;
    }

    fn total(&self) -> usize {
        self.by_reason.values().sum()
    }
}

fn matrix_axis_values<'a>(axes: &'a [Axis], name: &str) -> &'a [String] {
    axes.iter()
        .find(|(axis, _, _)| *axis == name)
        .map_or(&[], |(_, _, values)| values.as_slice())
}

fn axis_has(axes: &[Axis], name: &str, value: &str) -> bool {
    matrix_axis_values(axes, name)
        .iter()
        .any(|candidate| candidate == value)
}

fn representative<'a>(axes: &'a [Axis], name: &str, preferred: &str) -> Option<&'a str> {
    let values = matrix_axis_values(axes, name);
    values
        .iter()
        .find(|candidate| candidate.as_str() == preferred)
        .or_else(|| values.first())
        .map(String::as_str)
}

fn representative_for_role<'a>(
    axes: &'a [Axis],
    name: &str,
    role: Scope,
    preferred: &str,
) -> Option<&'a str> {
    let values = axes
        .iter()
        .find(|(axis, scope, _)| *axis == name && (*scope == role || *scope == Scope::Both))
        .map(|(_, _, values)| values.as_slice())
        .unwrap_or_default();
    values
        .iter()
        .find(|candidate| candidate.as_str() == preferred)
        .or_else(|| values.first())
        .map(String::as_str)
}

fn cell_value<'a>(cell: &'a Cell<'_>, name: &str, scope: Option<Scope>) -> Option<&'a str> {
    cell.iter()
        .find(|(axis, cell_scope, _)| {
            *axis == name && scope.is_none_or(|wanted| *cell_scope == wanted)
        })
        .map(|(_, _, value)| value.as_str())
}

fn role_value<'a>(cell: &'a Cell<'_>, name: &str, role: Scope) -> Option<&'a str> {
    cell_value(cell, name, Some(role)).or_else(|| cell_value(cell, name, Some(Scope::Both)))
}

fn bond_pairs(value: &str) -> Option<usize> {
    value
        .split_once(':')
        .and_then(|(_, pairs)| pairs.parse().ok())
}

/// Return why a cell is redundant or invalid, if it should not be run.
///
/// The matrix remains a cartesian product at the plan level, but this removes
/// combinations where the selected runtime/topology cannot observe an axis.
/// A representative value is retained when an axis is inert so a user-supplied
/// one-value plan still runs as written.
fn filter_reason(cell: &Cell<'_>, axes: &[Axis]) -> Option<&'static str> {
    let ingress = role_value(cell, "ingress", Scope::Recv).unwrap_or("per-port");
    let egress = role_value(cell, "egress", Scope::Send).unwrap_or("per-connection");
    let runtime_recv = role_value(cell, "runtime", Scope::Recv).unwrap_or("mio");
    let runtime_send = role_value(cell, "runtime", Scope::Send).unwrap_or(runtime_recv);
    let bond = cell_value(cell, "bond", Some(Scope::Both));
    let send_workers = role_value(cell, "workers", Scope::Send);
    let bonded = bond.is_some_and(|mode| mode != "none");

    if let Some(reason) = filter_shared_egress(cell, axes, egress, send_workers) {
        return Some(reason);
    }
    if bonded && egress != "shared-socket" {
        return Some("bonded-egress-unsupported");
    }
    if let Some(reason) = filter_bond_capacity(cell, bond) {
        return Some(reason);
    }

    let is_multi = ingress.starts_with("reuseport-multi:");
    let is_single = ingress.starts_with("reuseport-single:");
    let is_per_port = ingress == "per-port";

    // A bonded publisher is one logical ingress stream, so its legs must
    // reach the same group-aware PeerTable. Every runtime provides that on
    // the one-socket shared pool. A shared sender socket is valid too: SRT
    // Socket IDs, not UDP tuples, select each physical leg.
    if bonded && ingress != "shared-pool:1" {
        return Some("bonded-ingress-unsupported");
    }

    if let Some(reason) = filter_promotion(cell, axes, bond, is_multi, is_single) {
        return Some(reason);
    }

    if let Some(reason) = filter_cookie_routing(cell, axes, is_multi) {
        return Some(reason);
    }

    if let Some(reason) = filter_batching(cell, axes, runtime_recv, is_per_port) {
        return Some(reason);
    }

    if let Some(reason) = filter_pinning(cell, axes, runtime_recv, runtime_send) {
        return Some(reason);
    }

    None
}

fn filter_shared_egress(
    cell: &Cell<'_>,
    axes: &[Axis],
    egress: &str,
    send_workers: Option<&str>,
) -> Option<&'static str> {
    if egress != "shared-socket" {
        return None;
    }
    // A shared caller socket drives all handshakes from one readiness loop;
    // per-connection launch concurrency cannot alter that implementation.
    if let Some(value) = cell_value(cell, "connect-concurrency", Some(Scope::Both))
        && let Some(keep) = representative(axes, "connect-concurrency", "1")
        && value != keep
    {
        return Some("connect-concurrency-inert");
    }
    // One shared UDP socket has one owning runtime loop. Extra sender workers
    // cannot alter it; receiver workers remain independently variable when a
    // plan splits the axis by role.
    if let Some(value) = send_workers
        && let Some(keep) = representative_for_role(axes, "workers", Scope::Send, "1")
        && value != keep
    {
        return Some("shared-egress-workers-inert");
    }
    None
}

fn filter_bond_capacity(cell: &Cell<'_>, bond: Option<&str>) -> Option<&'static str> {
    let pairs = bond.and_then(bond_pairs);
    let connections = cell_value(cell, "connections", Some(Scope::Both))
        .and_then(|value| value.parse::<usize>().ok());
    if let (Some(pairs), Some(connections)) = (pairs, connections)
        && pairs > connections / 2
    {
        Some("bond-capacity")
    } else {
        None
    }
}

fn filter_promotion(
    cell: &Cell<'_>,
    axes: &[Axis],
    bond: Option<&str>,
    is_multi: bool,
    is_single: bool,
) -> Option<&'static str> {
    let promotion = cell_value(cell, "promotion", Some(Scope::Both))?;
    if is_single || !is_multi {
        return representative(axes, "promotion", "all")
            .filter(|keep| promotion != *keep)
            .map(|_| "promotion-inert");
    }
    if bond != Some("none") {
        return None;
    }
    let keep_never = axis_has(axes, "promotion", "never");
    let keep_all = axis_has(axes, "promotion", "all");
    ((promotion == "relocate" || promotion == "bonded") && keep_never
        || (!keep_never && keep_all && promotion != "all"))
        .then_some("promotion-inert")
}

fn filter_cookie_routing(cell: &Cell<'_>, axes: &[Axis], is_multi: bool) -> Option<&'static str> {
    if is_multi {
        return None;
    }
    let cookie = cell_value(cell, "cookie-routing", Some(Scope::Both))?;
    representative(axes, "cookie-routing", "on")
        .filter(|keep| cookie != *keep)
        .map(|_| "cookie-routing-inert")
}

fn filter_batching(
    cell: &Cell<'_>,
    axes: &[Axis],
    runtime_recv: &str,
    is_per_port: bool,
) -> Option<&'static str> {
    if runtime_recv == "mio" && !is_per_port {
        return None;
    }
    let batch = cell_value(cell, "batch", Some(Scope::Both))?;
    representative(axes, "batch", "on")
        .filter(|keep| batch != *keep)
        .map(|_| "batch-inert")
}

fn filter_pinning(
    cell: &Cell<'_>,
    axes: &[Axis],
    runtime_recv: &str,
    runtime_send: &str,
) -> Option<&'static str> {
    if runtime_recv == "glommio" || runtime_send == "glommio" {
        return None;
    }
    let pin = cell_value(cell, "pin", Some(Scope::Both))?;
    representative(axes, "pin", "off")
        .filter(|keep| pin != *keep)
        .map(|_| "pin-inert")
}

#[cfg(test)]
fn filter_matrix_cells<'a>(
    cells: Vec<Cell<'a>>,
    axes: &[Axis],
) -> (Vec<Cell<'a>>, MatrixFilterSummary) {
    let mut summary = MatrixFilterSummary::default();
    let cells = cells
        .into_iter()
        .filter(|cell| {
            if let Some(reason) = filter_reason(cell, axes) {
                summary.record(reason);
                false
            } else {
                true
            }
        })
        .collect();
    (cells, summary)
}

/// Expand and filter one Cartesian point at a time.
///
/// Materializing the raw product first made the full plan's 1,769,472 cells
/// consume several GiB before capability filtering could discard the inert
/// combinations. The matrix parent then passed that peak RSS through
/// fork/exec to every child, contaminating the per-role memory measurement.
fn filtered_cartesian_cells(
    axes: &[Axis],
) -> std::io::Result<(Vec<Cell<'_>>, usize, MatrixFilterSummary)> {
    let raw_cells = axes.iter().try_fold(1usize, |total, (_, _, values)| {
        total.checked_mul(values.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "matrix Cartesian product overflows usize",
            )
        })
    })?;
    let mut kept = Vec::new();
    let mut summary = MatrixFilterSummary::default();
    let mut indices = vec![0usize; axes.len()];
    for _ in 0..raw_cells {
        let cell: Cell<'_> = axes
            .iter()
            .zip(&indices)
            .map(|((name, scope, values), index)| (*name, *scope, values[*index].clone()))
            .collect();
        if let Some(reason) = filter_reason(&cell, axes) {
            summary.record(reason);
        } else {
            kept.push(cell);
        }

        for axis in (0..indices.len()).rev() {
            indices[axis] += 1;
            if indices[axis] < axes[axis].2.len() {
                break;
            }
            indices[axis] = 0;
        }
    }
    Ok((kept, raw_cells, summary))
}

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
        "encryption" => ("encryption", value.to_string()),
        "ingress" => ("ingress", value.to_string()),
        "egress" => ("egress", value.to_string()),
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
        "workers" => ("workers", value.to_string()),
        "connections" => ("conns", value.to_string()),
        "connect-concurrency" => ("connect_cc", value.to_string()),
        "bond" => ("bond", value.to_string()),
        "bitrate" => ("bitrate", value.to_string()),
        "pin" => ("pin", value.to_string()),
        // `off` is how a plan or CLI spells "no emulation"; the process
        // records that as an empty cell. Normalise here so a cell's key
        // and its recorded row agree -- they did not, which silently
        // disabled resume for every sweep once link axes existed.
        link if link.starts_with("link-") => (
            Box::leak(link.replace('-', "_").into_boxed_str()),
            if value == "off" {
                String::new()
            } else {
                value.to_string()
            },
        ),
        other => (
            Box::leak(other.to_string().into_boxed_str()),
            value.to_string(),
        ),
    }
}

/// Identity of one (cell, rep) as it appears in a result file.
fn cell_key(cell: &[(&str, Scope, String)], rep: usize) -> String {
    let mut parts: Vec<String> = cell
        .iter()
        .map(|(axis, scope, value)| {
            let (col, v) = recorded_as(axis, value);
            format!("{}{col}={v}", scope.prefix())
        })
        .collect();
    parts.sort();
    parts.push(format!("rep={rep}"));
    parts.join(" ")
}

/// The same identity, read back off a recorded row.
fn record_key(record: &Record, cell: &[(&str, Scope, String)], rep: usize) -> Option<String> {
    let mut parts: Vec<String> = Vec::with_capacity(cell.len());
    for (axis, scope, _) in cell {
        let (col, _) = recorded_as(axis, "");
        let col = format!("{}{col}", scope.prefix());
        parts.push(format!("{col}={}", record.get(&col)?));
    }
    parts.sort();
    parts.push(format!("rep={rep}"));
    Some(parts.join(" "))
}

/// Read a declarative sweep plan: `axis = v1,v2,v3` per line, `#` for
/// comments. Explicit `--axis name=value` overrides are applied later.
///
/// A plan in a file rather than a shell loop because a comprehensive
/// sweep is hundreds of runs over hours: it needs to be reviewable before
/// it starts, reproducible afterwards, and identical across re-runs.
fn read_plan(path: &Path) -> std::io::Result<Vec<(String, Vec<String>)>> {
    let text = std::fs::read_to_string(path)?;
    let mut axes = Vec::new();
    // `[recv]` / `[send]` scope the keys under them to one role, which is
    // how a plan expresses an asymmetric topology -- a pooled listener
    // against a sharded sender, say. Keys outside any section apply to
    // both roles and move in lockstep.
    //
    // There is no "end section" marker: a key after `[recv]`/`[send]`
    // stays scoped to it even if it looks like it should be global again.
    // Put unscoped keys before the first section, or reset explicitly
    // with any other bracketed header (`[all]` reads best) -- it falls
    // through to the unscoped case below.
    let mut scope = String::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            scope = match section.trim() {
                "recv" | "receiver" | "listener" => "recv-".to_string(),
                "send" | "sender" | "caller" => "send-".to_string(),
                _ => String::new(),
            };
            continue;
        }
        if let Some((name, values)) = line.split_once('=') {
            let name = format!("{scope}{}", name.trim());
            if axes.iter().any(|(axis, _)| *axis == name) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{path:?}: duplicate axis '{name}'"),
                ));
            }
            axes.push((
                name,
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

fn canonical_axis_name(name: &str) -> Option<&'static str> {
    Some(match name.trim() {
        "runtime" | "runtimes" => "runtime",
        "recv-runtime" | "recv-runtimes" => "recv-runtime",
        "send-runtime" | "send-runtimes" => "send-runtime",
        "workers" => "workers",
        "recv-workers" => "recv-workers",
        "send-workers" => "send-workers",
        "ingress" => "ingress",
        "egress" => "egress",
        "encryption" => "encryption",
        "promotion" => "promotion",
        "cookie-routing" => "cookie-routing",
        "batch" => "batch",
        "sock-buf" => "sock-buf",
        "pin" => "pin",
        "connections" => "connections",
        "connect-concurrency" => "connect-concurrency",
        "bond" => "bond",
        "bitrate" => "bitrate",
        "link-delay" => "link-delay",
        "link-jitter" => "link-jitter",
        "link-loss" => "link-loss",
        "link-rate" => "link-rate",
        "link-reorder" => "link-reorder",
        "link-duplicate" => "link-duplicate",
        "link-corrupt" => "link-corrupt",
        "link-limit" => "link-limit",
        _ => return None,
    })
}

fn axis_overrides(
    cli: &crate::Cli,
) -> std::io::Result<std::collections::HashMap<String, Vec<String>>> {
    let mut overrides = std::collections::HashMap::new();
    for spec in cli.repeated.get("axis").into_iter().flatten() {
        let Some((name, values)) = spec.split_once('=') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--axis requires NAME=VALUE[,VALUE...] (got '{spec}')"),
            ));
        };
        let Some(name) = canonical_axis_name(name) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--axis: unknown matrix axis '{name}'"),
            ));
        };
        let values: Vec<String> = values
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect();
        if values.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--axis {name}=... must contain at least one value"),
            ));
        }
        if overrides.insert(name.to_string(), values).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--axis '{name}' was specified more than once"),
            ));
        }
    }
    Ok(overrides)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatrixOrder {
    Default,
    Interleaved,
    Random,
}

fn matrix_order(cli: &crate::Cli) -> std::io::Result<(MatrixOrder, u64)> {
    let order = cli
        .flags
        .get("order")
        .map(String::as_str)
        .unwrap_or("default");
    let order = match order {
        "default" => MatrixOrder::Default,
        "interleaved" => MatrixOrder::Interleaved,
        "random" | "randomized" => MatrixOrder::Random,
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--order: unknown value '{other}' (want default|interleaved|random)"),
            ));
        }
    };
    let seed = cli
        .flags
        .get("seed")
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("--seed: invalid integer '{value}'"),
                )
            })
        })
        .transpose()?
        .unwrap_or(0);
    Ok((order, seed))
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut state = seed;
    for i in (1..items.len()).rev() {
        let j = (splitmix64(&mut state) % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

/// Round-robin each Cartesian level so runtime, ingress, encryption, and
/// subsequent axes are spread through the run instead of appearing in one
/// long block. This remains deterministic and preserves each axis's plan
/// value order within its round-robin lanes.
fn interleave_indices(cells: &[Cell<'_>], axes: &[Axis]) -> Vec<usize> {
    fn visit(cells: &[Cell<'_>], axes: &[Axis], depth: usize, indices: Vec<usize>) -> Vec<usize> {
        if depth == axes.len() || indices.len() < 2 {
            return indices;
        }
        let (name, scope, values) = &axes[depth];
        let mut groups: Vec<Vec<usize>> = values
            .iter()
            .map(|value| {
                indices
                    .iter()
                    .copied()
                    .filter(|index| {
                        cells[*index].iter().any(|(axis, cell_scope, cell_value)| {
                            axis == name && cell_scope == scope && cell_value == value
                        })
                    })
                    .collect()
            })
            .filter(|group: &Vec<usize>| !group.is_empty())
            .collect();
        if groups.len() < 2 {
            return visit(cells, axes, depth + 1, indices);
        }
        for group in &mut groups {
            let replacement = visit(cells, axes, depth + 1, std::mem::take(group));
            *group = replacement;
        }
        let mut out = Vec::with_capacity(indices.len());
        let longest = groups.iter().map(Vec::len).max().unwrap_or(0);
        for offset in 0..longest {
            for group in &groups {
                if let Some(index) = group.get(offset) {
                    out.push(*index);
                }
            }
        }
        out
    }

    visit(cells, axes, 0, (0..cells.len()).collect())
}

/// Run the cartesian product of the requested axes, one receiver/sender
/// pair per cell, appending both sides' results to `out`.
///
/// Each side is a fresh child process rather than a thread: CPU is
/// measured with `getrusage`, which is per-process, so running both roles
/// in one process would attribute the sender's cost to the listener.
#[expect(clippy::cognitive_complexity)]
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
    let reps: usize = cli.flag_or("reps", 3);
    let secs: u64 = cli.flag_or("secs", 8);
    let latency: u16 = cli.flag_or("latency", 120);

    // A plan file, when given, supplies axis values; anything it omits
    // falls back to the CLI flag and then the built-in default. Explicit
    // `--axis name=value` entries are the only CLI inputs that override a
    // plan value.
    let plan: Vec<(String, Vec<String>)> = match cli.flags.get("plan") {
        Some(path) if !path.is_empty() => read_plan(Path::new(path))?,
        _ => Vec::new(),
    };
    let overrides = axis_overrides(cli)?;
    for (name, values) in &overrides {
        eprintln!("matrix: axis override {name}={}", values.join(","));
    }
    // Track every plan key actually looked up, so a key nobody queries
    // -- a typo, or (as happened) an axis that stopped being role-
    // splittable after `ingress` was pulled back to Both-only because
    // splitting it silently broke connectivity -- is a hard error
    // instead of a silently-ignored line in the plan file.
    let queried = std::cell::RefCell::new(std::collections::HashSet::new());
    let from_plan = |name: &str| -> Option<Vec<String>> {
        queried.borrow_mut().insert(name.to_string());
        plan.iter()
            .find(|(axis, _)| axis == name)
            .map(|(_, values)| values.clone())
    };
    let resolved_axis = |name: &str, flag: &str, default: &str| -> Vec<String> {
        let plan_value = from_plan(name);
        overrides
            .get(name)
            .cloned()
            .or(plan_value)
            .unwrap_or_else(|| axis_values(cli, flag, default))
    };

    // CPU sets are a single value per role rather than an axis, but they
    // must still be settable from a plan: a config key that is silently
    // ignored is worse than one that fails.
    let cpu_set = |role: &str| -> String {
        from_plan(&format!("{role}-cpus"))
            .or_else(|| from_plan("cpus"))
            .and_then(|v| v.first().cloned())
            .or_else(|| cli.flags.get(&format!("{role}-cpus")).cloned())
            .or_else(|| cli.flags.get("cpus").cloned())
            .unwrap_or_default()
    };
    let recv_cpus = cpu_set("recv");
    let send_cpus = cpu_set("send");
    if !recv_cpus.is_empty() || !send_cpus.is_empty() {
        eprintln!("matrix: receiver CPUs [{recv_cpus}], sender CPUs [{send_cpus}]");
    }
    let axis = |name: &'static str, flag: &str, default: &str| -> Axis {
        (name, Scope::Both, resolved_axis(name, flag, default))
    };

    // Topology knobs that mean different things to each end. Given
    // unprefixed they stay ONE axis applied to both roles, so the two move
    // in lockstep and the cell count does not change. Given `--recv-x` or
    // `--send-x` (or a `[recv]`/`[send]` plan section) they split into two
    // independent axes -- which is a genuine cartesian product, and is the
    // only way to express "pooled listener, sharded sender".
    //
    // Splitting matters because these knobs are not symmetric in the first
    // place: `ingress` is a listener concept the sender only mirrors, and
    // `workers` reaches the listener's loop on `per-port` but not on the
    // pooled strategies. Holding them equal conflates the two ends and
    // hides whichever one is the constraint.
    let mut split_axes: Vec<Axis> = Vec::new();
    let role_axis = |name: &'static str, flag: &str, default: &str, out: &mut Vec<Axis>| {
        let per_role = |prefix: &str| -> Option<Vec<String>> {
            let scoped_name = format!("{prefix}{name}");
            let plan_value = from_plan(&scoped_name);
            overrides
                .get(&scoped_name)
                .cloned()
                .or(plan_value)
                .or_else(|| {
                    cli.flags
                        .get(&format!("{prefix}{flag}"))
                        .filter(|v| !v.is_empty())
                        .map(|v| v.split(',').map(str::trim).map(str::to_string).collect())
                })
        };
        let (recv, send) = (per_role("recv-"), per_role("send-"));
        if recv.is_none() && send.is_none() {
            out.push((name, Scope::Both, resolved_axis(name, flag, default)));
            return;
        }
        let shared = resolved_axis(name, flag, default);
        out.push((name, Scope::Recv, recv.unwrap_or_else(|| shared.clone())));
        out.push((name, Scope::Send, send.unwrap_or(shared)));
    };
    role_axis("runtime", "runtimes", "mio", &mut split_axes);
    role_axis("workers", "workers", "1", &mut split_axes);

    let mut axes: Vec<Axis> = split_axes;
    axes.extend([
        axis("ingress", "ingress", "per-port"),
        axis("egress", "egress", "per-connection"),
        axis("encryption", "encryption", "plain"),
        axis("promotion", "promotion", "relocate"),
        axis("cookie-routing", "cookie-routing", "on"),
        axis("batch", "batch", "on"),
        axis("sock-buf", "sock-buf", "16m"),
        axis("pin", "pin", "off"),
        axis("link-delay", "link-delay", "off"),
        axis("link-jitter", "link-jitter", "off"),
        axis("link-loss", "link-loss", "off"),
        axis("link-rate", "link-rate", "off"),
        axis("link-reorder", "link-reorder", "off"),
        axis("link-duplicate", "link-duplicate", "off"),
        axis("link-corrupt", "link-corrupt", "off"),
        axis("link-limit", "link-limit", "off"),
        axis("connections", "connections", "25"),
        axis("connect-concurrency", "connect-concurrency", "1"),
        axis("bond", "bond", "none"),
        axis("bitrate", "bitrate", "8000000"),
    ]);

    let unused: Vec<&str> = plan
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| !queried.borrow().contains(*name))
        .collect();
    if !unused.is_empty() {
        return Err(std::io::Error::other(format!(
            "plan declares axes nothing reads: {} -- check for a typo, or an \
             axis that isn't (or is no longer) role-splittable",
            unused.join(", ")
        )));
    }

    // Cartesian product, filtered one point at a time: the whole point is
    // to know how many cells there are before starting a long sweep without
    // holding the raw 1.7-million-cell product in memory.
    let (cells, raw_cells, filter_summary) = filtered_cartesian_cells(&axes)?;
    if filter_summary.total() > 0 {
        let reasons = filter_summary
            .by_reason
            .iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!(
            "matrix: filtered {} of {} cells ({reasons})",
            filter_summary.total(),
            raw_cells
        );
    }
    let total = cells.len() * reps;
    let (order, seed) = matrix_order(cli)?;
    let mut cell_order: Vec<usize> = match order {
        MatrixOrder::Default | MatrixOrder::Random => (0..cells.len()).collect(),
        MatrixOrder::Interleaved => interleave_indices(&cells, &axes),
    };
    if order == MatrixOrder::Random {
        shuffle(&mut cell_order, seed);
    }
    let schedule: Vec<(usize, usize)> = match order {
        MatrixOrder::Default => cell_order
            .iter()
            .flat_map(|cell| (1..=reps).map(move |rep| (*cell, rep)))
            .collect(),
        MatrixOrder::Interleaved | MatrixOrder::Random => (1..=reps)
            .flat_map(|rep| cell_order.iter().map(move |cell| (*cell, rep)))
            .collect(),
    };
    eprintln!(
        "matrix: order={:?} seed={seed} scheduled_runs={}",
        order,
        schedule.len()
    );
    // Resume: a sweep of this size will be interrupted at some point, and
    // re-running completed cells wastes hours and mixes measurement
    // windows. Anything already in the output file is skipped.
    // A cell counts as done only when BOTH roles recorded a row. Keying
    // on the listener alone meant a run interrupted mid-cell left an
    // orphan caller row, was re-run, and appended a second caller row for
    // the same cell -- two senders, one listener, and any statistic over
    // them silently wrong.
    let recorded = if out.exists() {
        read_results(&out)?
    } else {
        Vec::new()
    };
    let keys_for = |role: &str| -> std::collections::HashSet<String> {
        recorded
            .iter()
            .filter(|r| r.get("role") == Some(role))
            .filter_map(|r| {
                let rep: usize = r.number("rep")? as usize;
                cells
                    .iter()
                    .find_map(|cell| record_key(r, cell, rep).filter(|k| *k == cell_key(cell, rep)))
            })
            .collect()
    };
    let (listener_keys, caller_keys) = (keys_for("listener"), keys_for("caller"));
    let done: std::collections::HashSet<String> =
        listener_keys.intersection(&caller_keys).cloned().collect();
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
    let cell_link = |cell: &[(&str, Scope, String)], flag: &str| -> Option<String> {
        cell.iter()
            .find(|(a, _, _)| *a == flag)
            .map(|(_, _, v)| v.clone())
    };
    // Fail before the first cell rather than midway through a sweep.
    let mut any_link = false;
    for cell in &cells {
        if netem_args(|f| cell_link(cell, f))
            .map_err(std::io::Error::other)?
            .is_some()
        {
            any_link = true;
        }
    }
    let netns = if any_link {
        let p = Priv::detect().ok_or_else(|| std::io::Error::other(netem_privilege_help()))?;
        netns_up(p)?;
        eprintln!("matrix: running roles inside netns '{NETNS}' (link emulation active)");
        Some(p)
    } else {
        None
    };

    let mut skipped_runs = 0usize;
    let mut unsupported_cells = std::collections::HashSet::new();
    for (run_index, (cell_index, rep)) in schedule.iter().copied().enumerate() {
        let cell = &cells[cell_index];
        let label: Vec<String> = cell
            .iter()
            .map(|(k, scope, v)| format!("{}{k}={v}", scope.prefix().replace('_', "-")))
            .collect();
        // Resolve one axis for one role: its role-scoped value if the axis
        // was split, otherwise the shared one.
        let for_role = |name: &str, role: Scope, default: &str| -> String {
            cell.iter()
                .find(|(k, scope, _)| *k == name && *scope == role)
                .or_else(|| {
                    cell.iter()
                        .find(|(k, scope, _)| *k == name && *scope == Scope::Both)
                })
                .map_or_else(|| default.to_string(), |(_, _, v)| v.clone())
        };
        let value = |name: &str| -> Option<String> {
            cell.iter()
                .find(|(k, _, _)| *k == name)
                .map(|(_, _, v)| v.clone())
        };
        let recv_ingress = for_role("ingress", Scope::Recv, "per-port");
        let send_ingress = for_role("ingress", Scope::Send, "per-port");
        let recv_runtime = for_role("runtime", Scope::Recv, "mio");
        let send_runtime = for_role("runtime", Scope::Send, "mio");
        let conns_in_cell: usize = value("connections")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let bitrate = value("bitrate").unwrap_or_else(|| "8000000".into());
        // Port budget and support checks follow the LISTENER: it is the
        // side that binds.
        let ingress = recv_ingress.clone();
        let runtime = recv_runtime.clone();
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
        ) || !crate::runtimes::ingress_supported(
            crate::Runtime::parse(&send_runtime).unwrap_or(crate::Runtime::Mio),
            parse_ingress_spec(&send_ingress),
        ) {
            if unsupported_cells.insert(cell_index) {
                skipped_runs += reps;
                eprintln!("[skip] {} (unsupported)", label.join(" "));
            }
            continue;
        }
        if done.contains(&cell_key(cell, rep)) {
            continue;
        }
        if let Some(p) = netns {
            netem_apply(
                p,
                netem_args(|f| cell_link(cell, f)).map_err(std::io::Error::other)?,
            )?;
        }
        // A per-port cell at the top of the sweep can legitimately ask
        // for more descriptors than this process may hold while probing
        // the range (the full plan reaches 1200 connections). Treat that
        // as an unavailable resource cell and continue the sweep so one
        // impossible topology does not hide every pooled result after it.
        let port = match free_port_range(ports_needed) {
            Ok(port) => port,
            Err(error) => {
                skipped_runs += 1;
                eprintln!(
                    "[skip] {} (port allocation failed: {error})",
                    label.join(" ")
                );
                continue;
            }
        };
        // Each role gets the axes scoped to it plus the shared ones.
        // Both roles additionally get every split axis's *other* side
        // as a record-only `--recv-*`/`--send-*` flag, so a single row
        // states the whole cell -- without which two cells differing
        // only on the far side would be indistinguishable, and resume
        // would skip one of them.
        let argv_for = |role: Scope| -> Vec<String> {
            let mut out: Vec<String> = cell
                .iter()
                .filter(|(k, scope, _)| {
                    *k != "bitrate" && *k != "runtime" && scope.applies_to(role)
                })
                .map(|(k, _, v)| format!("--{k}={v}"))
                .collect();
            for (k, scope, v) in cell {
                if *scope != Scope::Both {
                    out.push(format!("--{}{k}={v}", scope.prefix().replace('_', "-")));
                }
            }
            out
        };
        let mut recv_argv = argv_for(Scope::Recv);
        let send_argv = argv_for(Scope::Send);
        // The listener runs to a long backstop, but the cell's stream
        // length is what any rate is computed against.
        recv_argv.push(format!("--stream-secs={secs}"));

        // Receiver outlives the sender so it is still listening when
        // the last packets arrive; +5s mirrors the old harness.
        let mut recv = if let Some(p) = netns {
            in_netns(p, &exe)
        } else {
            std::process::Command::new(&exe)
        }
        .arg(format!("runtime={recv_runtime}"))
        .arg("mode=receiver")
        .arg(port.to_string())
        // Backstop only: the harness signals the real stop once
        // the sender finishes. Generous, because a sender under
        // overload can run well past its nominal duration and the
        // listener must still be there when it does.
        .arg((secs + 60).to_string())
        .arg(latency.to_string())
        .env("SRT_BENCH_CHILD", "1")
        // The receiver ignores this functionally, but both rows
        // must record the same configured bitrate or a report
        // grouping on it would split the pair and lose delivery%.
        .arg(&bitrate)
        .args(&recv_argv)
        .arg(format!("--rep={rep}"))
        .arg(format!("--cpus={recv_cpus}"))
        .arg(format!("--out={}", out.display()))
        .stdout(std::process::Stdio::piped())
        .spawn()?;

        if !wait_for_listening(&mut recv, std::time::Duration::from_secs(60)) {
            eprintln!(
                "[warn] listener never reported LISTENING: {}",
                label.join(" ")
            );
        }

        let send = if let Some(p) = netns {
            in_netns(p, &exe)
        } else {
            std::process::Command::new(&exe)
        }
        .arg(format!("runtime={send_runtime}"))
        .arg("mode=sender")
        .arg("127.0.0.1")
        .arg(port.to_string())
        .arg(secs.to_string())
        .arg(latency.to_string())
        .arg(&bitrate)
        .env("SRT_BENCH_CHILD", "1")
        .args(&send_argv)
        .arg(format!("--rep={rep}"))
        .arg(format!("--cpus={send_cpus}"))
        .arg(format!("--out={}", out.display()))
        .stdout(std::process::Stdio::null())
        .status()?;

        // Let the ordered SRT SHUTDOWN reach the listener and flush its
        // receive/event queues. Signalling immediately here raced the final
        // runtime tick and under-counted delivery even though wire telemetry
        // had received the packets. Most listeners exit naturally within a
        // few milliseconds; SIGTERM remains the bounded fallback.
        let recv_status =
            match wait_for_natural_exit(&mut recv, std::time::Duration::from_millis(500))? {
                Some(status) => status,
                None => {
                    request_stop(&recv);
                    recv.wait()?
                }
            };
        eprintln!(
            "[{:>4}/{total}] rep {rep} {}{}",
            run_index + 1,
            label.join(" "),
            if send.success() && recv_status.success() {
                String::new()
            } else {
                format!(" (sender={send} receiver={recv_status})")
            }
        );
    }
    if let Some(p) = netns {
        netns_down(p);
    }
    if skipped_runs > 0 {
        eprintln!("matrix: skipped {skipped_runs} scheduled runs");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Emulated network conditions
// ---------------------------------------------------------------------------

/// Name of the private network namespace the harness runs roles in when a
/// `--netem` spec is active.
const NETNS: &str = "srtbench";

/// The link-condition flags, in the order `tc` wants them.
///
/// One flat flag per knob (`--link-delay=25ms --link-loss=1%`) rather
/// than one nested spec: a nested value has to carry its own separator,
/// and the sweep axes are already comma-separated, so the two collided.
/// Flat flags also make each knob sweepable on its own, which is the
/// whole point of an axis.
pub const LINK_FLAGS: &[&str] = &[
    "link-delay",
    "link-jitter",
    "link-loss",
    "link-rate",
    "link-reorder",
    "link-duplicate",
    "link-corrupt",
    "link-limit",
];

/// Accepted unit suffixes per knob. Empty string means a bare integer.
fn link_units(flag: &str) -> &'static [&'static str] {
    match flag {
        "link-delay" | "link-jitter" => &["ms", "us", "s"],
        "link-loss" | "link-reorder" | "link-duplicate" | "link-corrupt" => &["%"],
        "link-rate" => &["bit", "kbit", "mbit", "gbit"],
        _ => &[""],
    }
}

/// A value is valid if some accepted unit suffix leaves a parseable
/// number behind. Testing every unit rather than the first that strips
/// matters: "100mbit" ends with "bit", and stopping there would leave
/// "100m".
fn link_value_ok(value: &str, units: &[&str]) -> bool {
    units.iter().any(|unit| {
        if unit.is_empty() {
            return value.parse::<u64>().is_ok();
        }
        value
            .strip_suffix(unit)
            .is_some_and(|d| !d.is_empty() && d.parse::<f64>().is_ok())
    })
}

/// Render the link settings of one cell as `tc qdisc ... netem` arguments.
///
/// Values are validated rather than forwarded: these reach a privileged
/// command, so anything that is not a bare number with a known unit is
/// rejected. Returns `None` when the cell asks for no emulation at all.
///
/// `limit` is netem's own backlog in packets. Its default of 1000 would
/// quietly become the bottleneck at these packet rates and charge its
/// drops to the protocol, so it is raised unless set explicitly.
fn netem_args(get: impl Fn(&str) -> Option<String>) -> Result<Option<Vec<String>>, String> {
    let mut set: Vec<(&str, String)> = Vec::new();
    for flag in LINK_FLAGS {
        let Some(value) = get(flag).filter(|v| !v.is_empty() && v != "off") else {
            continue;
        };
        if !link_value_ok(&value, link_units(flag)) {
            return Err(format!("--{flag}: bad value '{value}'"));
        }
        set.push((flag.trim_start_matches("link-"), value));
    }
    if set.is_empty() || set.iter().all(|(k, _)| *k == "limit") {
        return Ok(None);
    }

    let find = |k: &str| set.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
    let mut args = vec![
        "limit".to_string(),
        find("limit").unwrap_or_else(|| "100000".to_string()),
    ];
    // netem wants jitter as a bare second argument to delay.
    if let Some(delay) = find("delay") {
        args.push("delay".to_string());
        args.push(delay);
        if let Some(jitter) = find("jitter") {
            args.push(jitter);
        }
    } else if find("jitter").is_some() {
        return Err("--link-jitter needs --link-delay".to_string());
    }
    for (key, value) in &set {
        if matches!(*key, "delay" | "jitter" | "limit") {
            continue;
        }
        args.push((*key).to_string());
        args.push(value.clone());
    }
    Ok(Some(args))
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
        // SAFETY: geteuid() is always safe to call and has no preconditions.
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
    let exe = std::env::args()
        .next()
        .unwrap_or_else(|| "srt-bench".into());
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
        &[
            "ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up",
        ],
    )
}

fn netns_down(p: Priv) {
    let _ = privileged(p, &["ip", "netns", "del", NETNS]);
}

/// Apply (or clear) the emulated conditions on the namespace's loopback.
/// `None` clears them.
fn netem_apply(p: Priv, netem: Option<Vec<String>>) -> std::io::Result<()> {
    let base = ["ip", "netns", "exec", NETNS, "tc", "qdisc"];
    let Some(netem) = netem else {
        let mut args: Vec<&str> = base.to_vec();
        args.extend(["del", "dev", "lo", "root"]);
        // Nothing to delete on the first cell; that is not a failure.
        let _ = privileged(p, &args);
        return Ok(());
    };
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
        // SAFETY: getuid() is always safe to call.
        .unwrap_or_else(|| unsafe { libc::getuid() });
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        // SAFETY: getgid() is always safe to call.
        .unwrap_or_else(|| unsafe { libc::getgid() });

    let mut cmd = p.command("ip");
    cmd.args(["netns", "exec", NETNS]);
    if uid != 0 {
        cmd.arg("setpriv")
            .arg(format!("--reuid={uid}"))
            .arg(format!("--regid={gid}"))
            .arg("--clear-groups");
    }
    // Put the marker inside the namespace command. Setting it on the outer
    // `sudo ip` process is not reliable because sudo may sanitize it.
    cmd.arg("env").arg("SRT_BENCH_CHILD=1").arg(exe);
    cmd
}

/// Block until the listener says it is bound, or give up.
///
/// It prints `LISTENING` before binding anything the sender will target.
/// The old code slept 700 ms instead, which is a race in both directions:
/// too short under load (the sender's first INDUCTION packets hit a closed
/// port), and pure waste when the listener was ready immediately.
fn wait_for_listening(child: &mut std::process::Child, timeout: std::time::Duration) -> bool {
    use std::io::{BufRead, BufReader};
    let Some(stdout) = child.stdout.take() else {
        return false;
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut announced = false;
        // Drain to EOF rather than stopping at the marker. Dropping the
        // read end early closes the pipe, and the listener then dies with
        // EPIPE on its next print -- which is its STATS line, so the run
        // would produce no result row at all.
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if !announced && line.contains("LISTENING") {
                announced = true;
                let _ = tx.send(());
            }
        }
    });
    rx.recv_timeout(timeout).is_ok()
}

/// Ask a child to stop cleanly. It finishes draining, writes its result
/// row, and exits; see `crate::shutdown` for why this replaced a timer.
fn request_stop(child: &std::process::Child) {
    // SAFETY: the child is still owned here, so its pid has not been reaped.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
}

fn wait_for_natural_exit(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
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

    let records = read_results(&results)?;
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
mod matrix_filter_tests {
    use super::{
        Axis, Cell, Scope, axis_overrides, filter_matrix_cells, filter_reason,
        filtered_cartesian_cells, interleave_indices, read_results, shuffle,
    };
    use crate::Cli;

    fn cli(args: &[&str]) -> Cli {
        let args = std::iter::once("srt-bench")
            .chain(args.iter().copied())
            .map(str::to_string)
            .collect::<Vec<_>>();
        Cli::parse(&args)
    }

    fn axes() -> Vec<Axis> {
        vec![
            (
                "promotion",
                Scope::Both,
                ["never", "relocate", "bonded", "all"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            (
                "cookie-routing",
                Scope::Both,
                ["on", "off"].into_iter().map(str::to_string).collect(),
            ),
            (
                "batch",
                Scope::Both,
                ["on", "off"].into_iter().map(str::to_string).collect(),
            ),
            (
                "pin",
                Scope::Both,
                ["off", "on"].into_iter().map(str::to_string).collect(),
            ),
        ]
    }

    fn cell(values: &[(&'static str, &'static str)]) -> Cell<'static> {
        values
            .iter()
            .map(|(name, value)| (*name, Scope::Both, (*value).to_string()))
            .collect()
    }

    #[test]
    fn filters_non_multi_promotion_and_cookie_variants() {
        let axes = axes();
        assert_eq!(
            filter_reason(
                &cell(&[
                    ("ingress", "shared-pool:4"),
                    ("promotion", "all"),
                    ("cookie-routing", "on"),
                    ("batch", "on"),
                    ("pin", "off"),
                    ("runtime", "mio"),
                    ("connections", "200"),
                    ("bond", "none"),
                ]),
                &axes
            ),
            None
        );
        assert_eq!(
            filter_reason(
                &cell(&[
                    ("ingress", "shared-pool:4"),
                    ("promotion", "all"),
                    ("cookie-routing", "off"),
                    ("batch", "on"),
                    ("pin", "off"),
                    ("runtime", "mio"),
                    ("connections", "200"),
                    ("bond", "none"),
                ]),
                &axes
            ),
            Some("cookie-routing-inert")
        );
    }

    #[test]
    fn shared_egress_filters_per_connection_launch_concurrency() {
        let axes = vec![
            (
                "connect-concurrency",
                Scope::Both,
                ["1", "50"].into_iter().map(str::to_string).collect(),
            ),
            (
                "egress",
                Scope::Both,
                ["per-connection", "shared-socket"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
        ];
        assert_eq!(
            filter_reason(
                &cell(&[("egress", "shared-socket"), ("connect-concurrency", "50"),]),
                &axes,
            ),
            Some("connect-concurrency-inert")
        );
        assert_eq!(
            filter_reason(
                &cell(&[("egress", "per-connection"), ("connect-concurrency", "50"),]),
                &axes,
            ),
            None
        );
    }

    #[test]
    fn shared_egress_filters_only_sender_workers() {
        let axes = vec![
            (
                "workers",
                Scope::Send,
                ["1", "3"].into_iter().map(str::to_string).collect(),
            ),
            (
                "workers",
                Scope::Recv,
                ["1", "2"].into_iter().map(str::to_string).collect(),
            ),
            (
                "egress",
                Scope::Send,
                ["per-connection", "shared-socket"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
        ];
        let cell = |send_workers: &str, recv_workers: &str| {
            vec![
                ("egress", Scope::Send, "shared-socket".to_string()),
                ("workers", Scope::Send, send_workers.to_string()),
                ("workers", Scope::Recv, recv_workers.to_string()),
            ]
        };
        assert_eq!(
            filter_reason(&cell("3", "1"), &axes),
            Some("shared-egress-workers-inert")
        );
        assert_eq!(filter_reason(&cell("1", "2"), &axes), None);
    }

    #[test]
    fn rejects_bonded_ingress_without_one_group_aware_listener() {
        let axes = axes();
        let bonded = cell(&[
            ("ingress", "reuseport-multi:4"),
            ("egress", "shared-socket"),
            ("promotion", "bonded"),
            ("cookie-routing", "on"),
            ("batch", "on"),
            ("pin", "off"),
            ("runtime", "mio"),
            ("connections", "200"),
            ("bond", "broadcast:64"),
        ]);
        assert_eq!(
            filter_reason(&bonded, &axes),
            Some("bonded-ingress-unsupported")
        );

        let unsupported_egress = cell(&[
            ("ingress", "shared-pool:1"),
            ("egress", "per-connection"),
            ("promotion", "all"),
            ("cookie-routing", "on"),
            ("batch", "on"),
            ("pin", "off"),
            ("runtime", "mio"),
            ("connections", "2"),
            ("bond", "broadcast:1"),
        ]);
        assert_eq!(
            filter_reason(&unsupported_egress, &axes),
            Some("bonded-egress-unsupported")
        );

        for runtime in ["mio", "tokio", "smol", "monoio", "glommio", "compio"] {
            let supported = cell(&[
                ("ingress", "shared-pool:1"),
                ("promotion", "all"),
                ("cookie-routing", "on"),
                ("batch", "on"),
                ("pin", "off"),
                ("runtime", runtime),
                ("connections", "200"),
                ("bond", "broadcast:64"),
                ("egress", "shared-socket"),
            ]);
            assert_eq!(filter_reason(&supported, &axes), None, "{runtime}");
        }

        let unbonded = cell(&[
            ("ingress", "reuseport-multi:4"),
            ("promotion", "relocate"),
            ("cookie-routing", "on"),
            ("batch", "on"),
            ("pin", "off"),
            ("runtime", "mio"),
            ("connections", "200"),
            ("bond", "none"),
        ]);
        assert_eq!(filter_reason(&unbonded, &axes), Some("promotion-inert"));
    }

    #[test]
    fn rejects_bond_groups_larger_than_the_connection_population() {
        let axes = axes();
        let cell = cell(&[
            ("ingress", "reuseport-multi:4"),
            ("egress", "shared-socket"),
            ("promotion", "all"),
            ("cookie-routing", "on"),
            ("batch", "on"),
            ("pin", "off"),
            ("runtime", "mio"),
            ("connections", "50"),
            ("bond", "broadcast:64"),
        ]);
        assert_eq!(filter_reason(&cell, &axes), Some("bond-capacity"));
    }

    #[test]
    fn filters_batch_and_pin_only_where_the_backend_ignores_them() {
        let axes = axes();
        let batch_non_mio = [
            ("ingress", "shared-pool:4"),
            ("promotion", "all"),
            ("cookie-routing", "on"),
            ("batch", "off"),
            ("pin", "off"),
            ("connections", "200"),
            ("bond", "none"),
        ];
        let non_mio = batch_non_mio
            .iter()
            .copied()
            .chain([("runtime", "tokio")])
            .collect::<Vec<_>>();
        assert_eq!(filter_reason(&cell(&non_mio), &axes), Some("batch-inert"));

        let pin_base = [
            ("ingress", "shared-pool:4"),
            ("promotion", "all"),
            ("cookie-routing", "on"),
            ("batch", "on"),
            ("pin", "on"),
            ("connections", "200"),
            ("bond", "none"),
        ];
        let mio = pin_base
            .iter()
            .copied()
            .chain([("runtime", "mio")])
            .collect::<Vec<_>>();
        assert_eq!(filter_reason(&cell(&mio), &axes), Some("pin-inert"));

        let glommio = pin_base
            .iter()
            .copied()
            .chain([("runtime", "glommio")])
            .collect::<Vec<_>>();
        assert_eq!(filter_reason(&cell(&glommio), &axes), None);
    }

    #[test]
    fn filter_summary_counts_each_removed_cell_once() {
        let axes = axes();
        let cells = vec![
            cell(&[
                ("ingress", "shared-pool:4"),
                ("promotion", "relocate"),
                ("cookie-routing", "on"),
                ("batch", "on"),
                ("pin", "off"),
                ("runtime", "mio"),
                ("connections", "200"),
                ("bond", "none"),
            ]),
            cell(&[
                ("ingress", "reuseport-multi:4"),
                ("promotion", "all"),
                ("cookie-routing", "on"),
                ("batch", "on"),
                ("pin", "off"),
                ("runtime", "mio"),
                ("connections", "50"),
                ("bond", "backup:64"),
            ]),
        ];
        let (kept, summary) = filter_matrix_cells(cells, &axes);
        assert!(kept.is_empty());
        assert_eq!(summary.total(), 2);
    }

    #[test]
    fn filtered_cartesian_expansion_keeps_only_capable_cells() {
        let axes: Vec<Axis> = vec![
            (
                "runtime",
                Scope::Both,
                ["mio", "tokio"].into_iter().map(str::to_string).collect(),
            ),
            (
                "ingress",
                Scope::Both,
                ["per-port", "shared-pool:4"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            (
                "batch",
                Scope::Both,
                ["on", "off"].into_iter().map(str::to_string).collect(),
            ),
        ];
        let (cells, raw, summary) = filtered_cartesian_cells(&axes).unwrap();
        assert_eq!(raw, 8);
        assert_eq!(cells.len(), 5);
        assert_eq!(summary.total(), 3);
    }

    #[test]
    fn axis_overrides_use_canonical_names_and_reject_duplicates() {
        let parsed = axis_overrides(&cli(&[
            "--axis",
            "encryption=plain,128",
            "--axis=recv-runtimes=mio,tokio",
            "--axis=egress=per-connection,shared-socket",
        ]))
        .unwrap();
        assert_eq!(parsed["encryption"], ["plain", "128"]);
        assert_eq!(parsed["recv-runtime"], ["mio", "tokio"]);
        assert_eq!(parsed["egress"], ["per-connection", "shared-socket"]);

        let error = axis_overrides(&cli(&[
            "--axis",
            "encryption=plain",
            "--axis",
            "encryption=128",
        ]))
        .unwrap_err();
        assert!(error.to_string().contains("specified more than once"));

        let error = axis_overrides(&cli(&["--axis", "not-an-axis=on"])).unwrap_err();
        assert!(error.to_string().contains("unknown matrix axis"));
    }

    #[test]
    fn interleaved_order_rotates_the_outer_axis() {
        let axes: Vec<Axis> = vec![
            (
                "runtime",
                Scope::Both,
                ["mio", "tokio"].into_iter().map(str::to_string).collect(),
            ),
            (
                "encryption",
                Scope::Both,
                ["plain", "128"].into_iter().map(str::to_string).collect(),
            ),
        ];
        let cells: Vec<Cell<'_>> = vec![
            vec![
                ("runtime", Scope::Both, "mio".into()),
                ("encryption", Scope::Both, "plain".into()),
            ],
            vec![
                ("runtime", Scope::Both, "mio".into()),
                ("encryption", Scope::Both, "128".into()),
            ],
            vec![
                ("runtime", Scope::Both, "tokio".into()),
                ("encryption", Scope::Both, "plain".into()),
            ],
            vec![
                ("runtime", Scope::Both, "tokio".into()),
                ("encryption", Scope::Both, "128".into()),
            ],
        ];
        assert_eq!(interleave_indices(&cells, &axes), [0, 2, 1, 3]);
    }

    #[test]
    fn shuffle_is_reproducible_and_seed_sensitive() {
        let mut first = [0, 1, 2, 3, 4, 5];
        let mut second = first;
        let mut third = first;
        shuffle(&mut first, 42);
        shuffle(&mut second, 42);
        shuffle(&mut third, 43);
        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn malformed_result_files_are_rejected() {
        let path = std::env::temp_dir().join(format!(
            "srt-bench-malformed-{}-{}.tsv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, format!("{}\nshort\n", super::COLUMNS.join("\t"))).unwrap();
        let error = read_results(&path).unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(error.to_string().contains("malformed TSV row"));
    }
}

#[cfg(test)]
mod netem_tests {
    use super::netem_args;

    /// Build the arg list from a `--link-*` flag map, the way a cell does.
    fn args(pairs: &[(&str, &str)]) -> Result<Option<Vec<String>>, String> {
        netem_args(|flag| {
            pairs
                .iter()
                .find(|(k, _)| format!("link-{k}") == flag)
                .map(|(_, v)| (*v).to_string())
        })
    }

    #[test]
    fn builds_tc_arguments_in_netem_order() {
        assert_eq!(
            args(&[("delay", "25ms"), ("jitter", "5ms"), ("loss", "1%")])
                .unwrap()
                .unwrap(),
            ["limit", "100000", "delay", "25ms", "5ms", "loss", "1%"]
        );
    }

    #[test]
    fn no_link_flags_means_no_emulation() {
        assert_eq!(args(&[]).unwrap(), None);
        assert_eq!(args(&[("delay", "off")]).unwrap(), None);
        // A backlog alone is not a condition worth a qdisc.
        assert_eq!(args(&[("limit", "64")]).unwrap(), None);
    }

    #[test]
    fn raises_the_backlog_unless_told_otherwise() {
        // netem's default limit of 1000 packets would silently become the
        // bottleneck at these packet rates and look like protocol loss.
        assert_eq!(
            args(&[("loss", "1%")]).unwrap().unwrap()[..2],
            ["limit", "100000"]
        );
        assert_eq!(
            args(&[("loss", "1%"), ("limit", "64")]).unwrap().unwrap()[..2],
            ["limit", "64"]
        );
    }

    #[test]
    fn accepts_every_rate_unit() {
        for rate in ["1000bit", "100kbit", "100mbit", "1gbit"] {
            assert!(args(&[("rate", rate)]).is_ok(), "rejected {rate}");
        }
    }

    #[test]
    fn rejects_anything_it_would_have_to_forward_blindly() {
        // These arguments are handed to a privileged command, so a
        // non-numeric or wrongly-united value must not pass through.
        for (flag, value) in [
            ("loss", "1%; rm -rf /"),
            ("delay", "$(whoami)"),
            ("loss", "abc"),
            ("delay", "25"),   // unit required
            ("loss", "1"),     // unit required
            ("rate", "100mb"), // not a netem unit
        ] {
            assert!(args(&[(flag, value)]).is_err(), "accepted {flag}={value}");
        }
    }

    #[test]
    fn jitter_without_delay_is_meaningless() {
        assert!(args(&[("jitter", "5ms")]).is_err());
    }
}

#[cfg(test)]
mod report_tests {
    use super::{Record, github_benchmark_json, recorded_as, report};

    fn rec(pairs: &[(&str, &str)]) -> Record {
        Record {
            fields: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    /// Base row: one runtime, one cell, everything a report reads.
    fn row(role: &str, rep: &str, sent: &str, retx: &str) -> Record {
        rec(&[
            ("runtime", "smol"),
            ("role", role),
            ("rep", rep),
            ("conns", "400"),
            ("bitrate", "8000000"),
            ("secs", "10"),
            ("established", "400"),
            ("core_total", sent),
            ("sec_a", retx),
            ("rtt_ms", "1"),
            ("cpu_user_ms", "0"),
            ("cpu_sys_ms", "0"),
            ("peak_rss_kb", "0"),
            ("udp_rcvbuf_err", "0"),
        ])
    }

    fn field(out: &str, name: &str) -> String {
        let mut lines = out.lines();
        let headers: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
        let values: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
        let i = headers.iter().position(|h| *h == name).expect("column");
        values[i].to_string()
    }

    /// An interrupted run leaves a caller row with no listener row. Resume
    /// keyed only on listener rows, so the cell re-ran and appended a
    /// SECOND caller row -- and averaging each side independently then
    /// divided a complete listener figure by the median of one complete
    /// and one truncated caller. That is how a 139% delivery rate
    /// appeared in a real sweep.
    #[test]
    fn an_orphaned_caller_row_does_not_corrupt_delivery() {
        let rows = vec![
            row("caller", "1", "1336760", "0"), // truncated, no listener
            row("caller", "1", "3045575", "0"), // the completed re-run
            row("listener", "1", "3045575", "0"),
        ];
        let out = report(&rows, &["runtime".to_string()]);
        assert_eq!(field(&out, "deliv%"), "100.0", "got:\n{out}");
        assert_eq!(field(&out, "pairs"), "1", "got:\n{out}");
    }

    /// `SenderBuffer::total_sent` counts a packet when it is first queued
    /// and is never incremented by `pop_retransmit`, so retransmits are
    /// already excluded. Subtracting them again floored the figure at zero
    /// under heavy loss: a sender that pushed two million packets was
    /// reported as having offered nothing.
    #[test]
    fn offered_load_does_not_subtract_retransmits_twice() {
        let rows = vec![
            row("caller", "1", "2029411", "2048059"),
            row("listener", "1", "731424", "0"),
        ];
        let out = report(&rows, &["runtime".to_string()]);
        assert_ne!(field(&out, "offer%"), "0.0", "floored at zero:\n{out}");
        // 2029411 / (400 * 8e6 * 10 / (8 * 1316)) = 66.8%
        assert_eq!(field(&out, "offer%"), "66.8", "got:\n{out}");
    }

    /// A cell says `link-delay=off`; the process records that as an empty
    /// column. If the two disagree no cell ever matches its own recorded
    /// row, and resume silently re-runs an entire completed sweep.
    #[test]
    fn link_off_keys_the_same_as_it_records() {
        assert_eq!(
            recorded_as("link-delay", "off"),
            ("link_delay", String::new())
        );
        assert_eq!(
            recorded_as("link-loss", "1%"),
            ("link_loss", "1%".to_string())
        );
    }

    #[test]
    fn github_benchmark_json_aggregates_listener_throughput_in_first_seen_order() {
        let rows = vec![
            rec(&[
                ("runtime", "mio"),
                ("role", "listener"),
                ("pkt_sent", "10"),
                ("elapsed_s", "2"),
            ]),
            rec(&[
                ("runtime", "tokio"),
                ("role", "caller"),
                ("pkt_sent", "999"),
                ("elapsed_s", "1"),
            ]),
            rec(&[
                ("runtime", "mio"),
                ("role", "listener"),
                ("pkt_sent", "5"),
                ("elapsed_s", "1"),
            ]),
            rec(&[
                ("runtime", "tokio"),
                ("role", "listener"),
                ("pkt_sent", "6"),
                ("elapsed_s", "3"),
            ]),
            rec(&[
                ("runtime", "empty"),
                ("role", "listener"),
                ("pkt_sent", "4"),
                ("elapsed_s", "0"),
            ]),
        ];
        assert_eq!(
            github_benchmark_json(&rows),
            "[\n  {\"name\": \"mio\", \"unit\": \"pkt/s\", \"value\": 5.0},\n  {\"name\": \"tokio\", \"unit\": \"pkt/s\", \"value\": 2.0}\n]\n"
        );
    }
}
