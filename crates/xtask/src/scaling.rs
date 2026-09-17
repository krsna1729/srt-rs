//! `cargo xtask scaling` -- the concurrent-shard scaling sweep.
//!
//! This is the driver for `docs/results/scaling-to-1000.md`. It replaces a
//! shell script that did the same job, for the usual reason: the experiment is
//! part of the evidence, so it belongs in the repository's own tooling where it
//! compiles, is reviewed like code, and cannot silently drift from the result
//! schema it writes.
//!
//! Semantics that matter, and why:
//!
//! * **Every shard runs concurrently.** The claim under test is about `S`
//!   simultaneous shards; running them one after another measures a different
//!   and much easier system. Each shard is a separate process with its own
//!   sender socket and its own receiver process, disjoint port ranges, nothing
//!   shared. A configuration only reachable by sharing state cannot be
//!   expressed here -- deliberately.
//! * **One destination per UDP port**: destination `i` is `base + i` for both
//!   roles. Several senders on one port do not all get admitted (measured:
//!   `connections=3 established=1 data_zero=2`), so the topology is fixed.
//! * **The receiver must outlive the drain.** The sender keeps servicing after
//!   the measurement window until its TX reaches equilibrium, and that drain is
//!   not small. A receiver whose lifetime is shorter sends the drain into a
//!   closed socket while window-phase reconciliation still looks exact --
//!   `data_min == data_max == generated_ticks`, `sec_a == 0` -- which is
//!   precisely how that defect hid the first time. The lifetime here is derived
//!   from the window, and the sweep waits for the sender processes to exit
//!   before stopping receivers.
//!
//! Output: a TSV with a generated header, one `ROW` line per shard per rep, and
//! one `AGG` line summing the last rep. Every column is a field the two roles
//! actually print; nothing is transcribed by hand.
//!
//! ```text
//! cargo xtask scaling --out /tmp/x.tsv --n 1000 --shards 5 --reps 2
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

/// Fields read from the sender's `SHARED_OWNER_QUAL` line.
const TX_KEYS: &[&str] = &[
    "established",
    "expected_ticks",
    "generated_ticks",
    "missed_source_ticks",
    "data_offered",
    "data_accepted",
    "tx_submitted_wire",
    "tx_completed",
    "drain_submitted",
    "drain_completed",
    "drain_ok",
    "pending_after_drain",
    "inflight_at_window_end",
    "service_visits",
    "lateness_us_p50",
    "p99",
    "max",
    "window_cpu_ms",
    "drain_cpu_ms",
    "cpu_ms",
    "rx_mode",
    "managed_rx",
    "rx_dropped",
    "rx_truncated",
    "tx_pool_free",
    "tx_pool_capacity",
    "payload_bytes",
    "interval_us",
];

/// Fields read from the receiver's `STATS` line.
const RX_KEYS: &[&str] = &[
    "connections",
    "established",
    "pkt_sent",
    "core_total",
    "sec_a",
    "rtt_ms",
    "elapsed_s",
    "cpu_user_ms",
    "cpu_sys_ms",
    "data_min",
    "data_p50",
    "data_max",
    "data_zero",
    "data_below_half_mean",
];

/// Columns summed across shards in the `AGG` line.
const SUM_KEYS: &[&str] = &[
    "expected_ticks",
    "generated_ticks",
    "missed_source_ticks",
    "data_offered",
    "data_accepted",
    "tx_submitted_wire",
    "tx_completed",
    "drain_submitted",
    "drain_completed",
    "service_visits",
    "rx_core_total",
    "rx_data_zero",
    "rx_data_below_half_mean",
    "rx_established",
    "rx_connections",
    "rx_sec_a",
];

/// Columns aggregated by minimum rather than summed: a minimum of per-shard
/// minima is the only aggregation of them that means anything.
const MIN_KEYS: &[&str] = &["rx_data_min"];

/// Columns aggregated by maximum: per-shard worst cases.
const MAX_KEYS: &[&str] = &["lateness_us_p50", "p99", "max", "rx_data_below_half_mean"];

struct Options {
    out: PathBuf,
    n: usize,
    shards: usize,
    reps: usize,
    window_ms: u64,
    tx_lanes: usize,
    connect_cc: usize,
    base_port: u16,
    payload_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            out: PathBuf::from("scaling-sweep.tsv"),
            n: 200,
            shards: 1,
            reps: 1,
            window_ms: 3000,
            tx_lanes: 256,
            connect_cc: 64,
            base_port: 30_000,
            payload_bytes: 1316,
        }
    }
}

impl Options {
    /// Apply one `--flag value` pair. Kept separate from [`parse_options`] so
    /// the flag table does not also carry the validation branches.
    fn set(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--out" => self.out = PathBuf::from(value),
            "--n" => self.n = parse(value, flag)?,
            "--shards" => self.shards = parse(value, flag)?,
            "--reps" => self.reps = parse(value, flag)?,
            "--window-ms" => self.window_ms = parse(value, flag)?,
            "--tx-lanes" => self.tx_lanes = parse(value, flag)?,
            "--connect-cc" => self.connect_cc = parse(value, flag)?,
            "--base-port" => self.base_port = parse(value, flag)?,
            "--payload-bytes" => self.payload_bytes = parse(value, flag)?,
            other => return Err(format!("unknown argument {other}")),
        }
        Ok(())
    }

    fn validate(self) -> Result<Self, String> {
        if self.shards == 0 || self.reps == 0 || self.n == 0 {
            return Err("--n, --shards and --reps must be positive".to_string());
        }
        if !self.n.is_multiple_of(self.shards) {
            return Err(format!(
                "--n {} must divide by --shards {}",
                self.n, self.shards
            ));
        }
        if self.base_port as usize + self.reps * 2000 + self.n > (u16::MAX as usize - 1) {
            return Err("port range overflows; lower --base-port or --n".to_string());
        }
        Ok(self)
    }
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    for pair in args.chunks(2) {
        let flag = pair[0].as_str();
        let value = pair.get(1).ok_or_else(|| format!("{flag} needs a value"))?;
        options.set(flag, value)?;
    }
    options.validate()
}

fn parse<T: std::str::FromStr>(s: &str, flag: &str) -> Result<T, String> {
    s.parse()
        .map_err(|_| format!("{flag} does not parse: {s:?}"))
}

/// Parse `key=value` tokens out of a harness line.
fn kv(line: &str) -> BTreeMap<String, String> {
    line.split_whitespace()
        .filter_map(|tok| tok.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn find_bench(root: &Path) -> Result<PathBuf, String> {
    let deps = root.join("target/release/deps");
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(&deps).map_err(|e| format!("{}: {e}", deps.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if !name.starts_with("compio_shared_owner_qual-") || name.ends_with(".d") {
            continue;
        }
        let modified = fs::metadata(&path)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(t, _)| modified > *t) {
            best = Some((modified, path));
        }
    }
    best.map(|(_, p)| p).ok_or_else(|| {
        "no compio_shared_owner_qual binary; build it first:\n  \
         cargo build --release -p srt-bench --benches"
            .to_string()
    })
}

fn receiver_binary(root: &Path) -> Result<PathBuf, String> {
    let path = root.join("target/release/srt-bench");
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "{} missing; build it first:\n  cargo build --release -p srt-bench",
            path.display()
        ))
    }
}

/// Wait for a child to exit, reporting whether it succeeded.
fn reap(child: &mut Child) -> bool {
    matches!(child.wait(), Ok(status) if status.success())
}

/// Everything the sweep needs to launch work: where the workspace is and
/// which binaries to run.
struct Harness {
    bench: PathBuf,
    receiver: PathBuf,
}

pub fn run(args: &[String]) -> std::process::ExitCode {
    let options = match parse_options(args) {
        Ok(o) => o,
        Err(e) => return fail(&e),
    };
    let harness = match locate() {
        Ok(h) => h,
        Err(e) => return fail(&e),
    };
    let text = match sweep(&options, &harness) {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    if let Err(e) = fs::write(&options.out, text) {
        return fail(&format!("writing {}: {e}", options.out.display()));
    }
    println!(
        "scaling: n={} shards={} fanout={} reps={} -> {}",
        options.n,
        options.shards,
        options.n / options.shards,
        options.reps,
        options.out.display()
    );
    std::process::ExitCode::SUCCESS
}

fn fail(message: &str) -> std::process::ExitCode {
    eprintln!("scaling: {message}");
    std::process::ExitCode::FAILURE
}

fn locate() -> Result<Harness, String> {
    let root = find_root()?;
    Ok(Harness {
        bench: find_bench(&root)?,
        receiver: receiver_binary(&root)?,
    })
}

/// Run every rep and return the whole TSV, header included.
fn sweep(options: &Options, harness: &Harness) -> Result<String, String> {
    let mut out = header(options)?;
    let mut last_rep: Vec<Vec<String>> = Vec::new();
    for rep in 1..=options.reps {
        last_rep = run_rep(options, harness, rep, &mut out)?;
    }
    if !last_rep.is_empty() {
        out.push_str(&aggregate(options.reps, &last_rep));
        out.push('\n');
    }
    Ok(out)
}

fn header(options: &Options) -> Result<String, String> {
    let root = find_root()?;
    let dirty = git(&root, &["diff", "--quiet"]).is_err();
    let sha = git(&root, &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|_| "unknown".into());
    let mut columns: Vec<String> =
        vec!["kind".into(), "rep".into(), "shard".into(), "fanout".into()];
    columns.extend(TX_KEYS.iter().map(|k| k.to_string()));
    columns.extend(RX_KEYS.iter().map(|k| format!("rx_{k}")));
    Ok(format!(
        "# scaling-sweep n={} shards={} fanout={} tx_lanes={} connect_cc={} window_ms={} \n\
         # reps={} base_port={} payload_bytes={} git_sha={} git_dirty={}\n{}\n",
        options.n,
        options.shards,
        options.n / options.shards,
        options.tx_lanes,
        options.connect_cc,
        options.window_ms,
        options.reps,
        options.base_port,
        options.payload_bytes,
        sha,
        dirty,
        columns.join("\t")
    ))
}

/// One rep: `S` receivers, then `S` sender shards concurrently, then the rows.
fn run_rep(
    options: &Options,
    harness: &Harness,
    rep: usize,
    out: &mut String,
) -> Result<Vec<Vec<String>>, String> {
    let rep_base = options.base_port + (rep as u16) * 2000;
    let fanout = options.n / options.shards;
    let work = std::env::temp_dir().join(format!("scaling-sweep-{}-{rep}", std::process::id()));
    fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;

    let mut receivers = spawn_receivers(harness, &work, rep_base, fanout, options)?;
    sleep(Duration::from_secs(1));
    let mut senders = spawn_senders(harness, &work, rep_base, fanout, options)?;

    // Wait for the shards, then give receivers time to read the post-window
    // drain before stopping them.
    for (port, sender) in senders.iter_mut() {
        if !reap(sender) {
            eprintln!("scaling: sender shard on port {port} failed");
        }
    }
    sleep(Duration::from_secs(12));
    for receiver in receivers.iter_mut() {
        if receiver.try_wait().ok().flatten().is_none() {
            let _ = receiver.kill();
        }
        let _ = receiver.wait();
    }

    let mut rows = Vec::with_capacity(options.shards);
    for shard in 0..options.shards {
        let row: Vec<String> = read_shard_row(&work, shard, rep)?;
        out.push_str(&row.join("\t"));
        out.push('\n');
        rows.push(row);
    }
    let _ = fs::remove_dir_all(&work);
    Ok(rows)
}

fn spawn_receivers(
    harness: &Harness,
    work: &Path,
    rep_base: u16,
    fanout: usize,
    options: &Options,
) -> Result<Vec<Child>, String> {
    // The lifetime covers connect + window + drain with margin; a receiver
    // that dies early sends the drain into a closed socket while
    // window-phase reconciliation still looks exact.
    let seconds = (options.window_ms / 1000 + 30).to_string();
    let mut children = Vec::with_capacity(options.shards);
    for shard in 0..options.shards {
        let port = rep_base + (shard * fanout) as u16;
        let log = open_log(work, &format!("rx.{shard}.log"))?;
        let child = Command::new(&harness.receiver)
            .args([
                "runtime=compio",
                "mode=receiver",
                &port.to_string(),
                &seconds,
                "120",
                "--connections",
                &fanout.to_string(),
            ])
            .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(|e| format!("spawning receiver on {port}: {e}"))?;
        children.push(child);
    }
    Ok(children)
}

fn spawn_senders(
    harness: &Harness,
    work: &Path,
    rep_base: u16,
    fanout: usize,
    options: &Options,
) -> Result<Vec<(u16, Child)>, String> {
    let mut children = Vec::with_capacity(options.shards);
    for shard in 0..options.shards {
        let port = rep_base + (shard * fanout) as u16;
        let log = open_log(work, &format!("tx.{shard}.log"))?;
        let child = Command::new(&harness.bench)
            .args([
                "--fanout".to_string(),
                fanout.to_string(),
                "--duration-ms".to_string(),
                options.window_ms.to_string(),
                "--base-port".to_string(),
                port.to_string(),
                "--tx-lanes".to_string(),
                options.tx_lanes.to_string(),
                "--connect-cc".to_string(),
                options.connect_cc.to_string(),
                "--payload-bytes".to_string(),
                options.payload_bytes.to_string(),
            ])
            .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(|e| format!("spawning sender shard on {port}: {e}"))?;
        children.push((port, child));
    }
    Ok(children)
}

fn open_log(work: &Path, name: &str) -> Result<fs::File, String> {
    let path = work.join(name);
    fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The row for one shard, read from the logs the two processes wrote.
fn read_shard_row(work: &Path, shard: usize, rep: usize) -> Result<Vec<String>, String> {
    let tx = read_log(work, &format!("tx.{shard}.log"));
    let rx = read_log(work, &format!("rx.{shard}.log"));
    let tx_fields = tx
        .lines()
        .find(|l| l.starts_with("SHARED_OWNER_QUAL"))
        .map(kv)
        .unwrap_or_default();
    let rx_fields = rx
        .lines()
        .find(|l| l.starts_with("STATS"))
        .map(kv)
        .unwrap_or_default();
    if tx_fields.is_empty() {
        return Err(format!(
            "shard {shard} rep {rep}: no SHARED_OWNER_QUAL line"
        ));
    }
    let mut row = vec![
        "ROW".to_string(),
        rep.to_string(),
        shard.to_string(),
        tx_fields
            .get("fanout")
            .cloned()
            .unwrap_or_else(|| "?".into()),
    ];
    row.extend(
        TX_KEYS
            .iter()
            .map(|k| tx_fields.get(*k).cloned().unwrap_or_default()),
    );
    row.extend(
        RX_KEYS
            .iter()
            .map(|k| rx_fields.get(*k).cloned().unwrap_or_default()),
    );
    Ok(row)
}

fn read_log(work: &Path, name: &str) -> String {
    fs::read_to_string(work.join(name)).unwrap_or_default()
}

/// Largest (or smallest) value in column `i` across `rows`, as text.
fn extremum(rows: &[Vec<String>], i: usize, want_max: bool) -> String {
    let values = rows
        .iter()
        .filter_map(|r| r.get(i).and_then(|v| v.parse::<u64>().ok()));
    let picked = if want_max { values.max() } else { values.min() };
    picked.map(|v| v.to_string()).unwrap_or_default()
}

/// Sum the last rep's shards so a partially failed sweep stays visible.
fn aggregate(reps: usize, rows: &[Vec<String>]) -> String {
    let columns: Vec<String> = {
        let mut c: Vec<String> = vec!["kind".into(), "rep".into(), "shard".into(), "fanout".into()];
        c.extend(TX_KEYS.iter().map(|k| k.to_string()));
        c.extend(RX_KEYS.iter().map(|k| format!("rx_{k}")));
        c
    };
    let index = |key: &str| columns.iter().position(|c| c == key);
    let mut total = vec![String::new(); columns.len()];
    total[0] = "AGG".into();
    total[1] = reps.to_string();
    total[2] = rows.len().to_string();
    for key in SUM_KEYS {
        let Some(i) = index(key) else { continue };
        let sum: f64 = rows
            .iter()
            .filter_map(|r| r.get(i).and_then(|v| v.parse::<f64>().ok()))
            .sum();
        total[i] = if sum.fract() == 0.0 {
            format!("{}", sum as i64)
        } else {
            format!("{sum:.1}")
        };
    }
    for key in MAX_KEYS {
        if let Some(i) = index(key) {
            total[i] = extremum(rows, i, true);
        }
    }
    for key in MIN_KEYS {
        if let Some(i) = index(key) {
            total[i] = extremum(rows, i, false);
        }
    }
    total.join("\t")
}

fn find_root() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| e.to_string())?;
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("crates/xtask").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err("run from inside the workspace".to_string());
        }
    }
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
