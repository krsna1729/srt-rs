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
//! * **The sweep builds its own children.** A release `cargo build` for
//!   `srt-bench` and the `compio_shared_owner_qual` bench runs immediately before
//!   the first repetition, and the executables come from cargo's own artifact
//!   records rather than from a scan of `target/`. The header's `git_sha`
//!   therefore describes the code that produced the rows, instead of whatever
//!   happened to be left in the build directory.
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
use std::time::{Duration, Instant};

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
    "offer_lateness_us_p50",
    "offer_lateness_us_p99",
    "offer_lateness_us_max",
    "window_cpu_ms",
    "drain_cpu_ms",
    "cpu_ms",
    "rx_mode",
    "managed_rx",
    "rx_dropped",
    "rx_truncated",
    "tx_pool_free",
    "tx_pool_capacity",
    "tx_pool_high_water",
    // Send-outcome counters. They were printed by the harness and never
    // captured here, so a row could not support (or refute) "no send failed".
    "short",
    "failed",
    "peer_local",
    "transient",
    "tx_failures_pending",
    // TX submission partition (sum(tx_class_*) == tx_class_total ==
    // tx_submitted_wire, enforced by `qualify`). A total cannot say whether the
    // wire traffic was the media or the control cadence around it.
    "tx_class_data_first",
    "tx_class_data_retx",
    "tx_class_ack",
    "tx_class_ackack",
    "tx_class_nak",
    "tx_class_keepalive",
    "tx_class_handshake",
    "tx_class_dropreq",
    "tx_class_km",
    "tx_class_shutdown",
    "tx_class_other_control",
    "tx_class_total",
    // Drain-phase retransmissions, so the receiver's own packet-duplicate count
    // can be accounted against the repair traffic that explains it (see
    // `qualify`'s canonical gate). `drain_class_total` alone cannot: it is not
    // what a duplicate is made of.
    "drain_class_data_retx",
    // First-transmission submit lateness: source due instant to lane handoff.
    // Distinct from `offer_lateness_us_*`, which is sampled before `service()`.
    "first_submit_lateness_us_p50",
    "first_submit_lateness_us_p99",
    "first_submit_lateness_us_max",
    "first_submit_lateness_samples",
    // SRT-level receive accounting for the sender's own caller socket, summed
    // over live and retired sessions.
    "rx_lost",
    "rx_duplicates",
    "payload_bytes",
    "interval_us",
    // The offer is part of the row: a capacity sweep is unreadable without it,
    // and the gate needs it to name what was sustained.
    "offered_bps_per_dest",
    // Diagnostic fence counters: offered and accepted after the measured
    // window, excluded from every workload figure. They exist to test whether an
    // end-of-run tail closes when later sequence progress is forced.
    "fence_offered",
    "fence_accepted",
    // Whether connection-setup residue (admission backlog, in-flight
    // handshake/keepalive traffic) had actually drained before the measured
    // window began. A row without this confirmed cannot support a claim that
    // the measurement started at a genuinely steady state.
    "pre_window_drained",
    // Whether the Owner's typed fault state was still clear at the end of the
    // run. A fault (dead TX lane, short/failed send completion, stopped managed
    // RX task) stops admission and transmission; a row that cannot report this
    // cannot support a claim that the transport under test stayed healthy.
    "owner_faulted",
];

/// Fields read from the receiver's `STATS` line.
const RX_KEYS: &[&str] = &[
    "connections",
    "established",
    "pkt_sent",
    "core_total",
    "sec_a",
    // Receiver duplicate count. Already mapped from `total_duplicates` in the
    // receiver's per-connection stats; simply not collected here, which made
    // duplicate accounting look like work to build rather than work to read.
    "sec_b",
    "rtt_ms",
    "elapsed_s",
    "cpu_user_ms",
    "cpu_sys_ms",
    "data_min",
    "data_p50",
    "data_max",
    "data_zero",
    "data_below_half_mean",
    // Diagnostic conservation accounting, present only on identity runs. These
    // belong to the receiver's STATS line, not the sender's: putting them in the
    // sender's key list silently dropped every value.
    "diag_conns",
    "diag_fences_seen",
    "diag_data_at_fence",
    "diag_missing_at_fence",
    "diag_missing_final",
    "diag_missing_suffix_peers",
    "diag_missing_scatter_peers",
    "diag_duplicate_payloads",
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
    "tx_class_total",
    "rx_lost",
    "rx_duplicates",
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
const MAX_KEYS: &[&str] = &[
    "offer_lateness_us_p50",
    "offer_lateness_us_p99",
    "offer_lateness_us_max",
    "rx_data_below_half_mean",
];

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
    /// Offered bitrate per destination. The capacity frontier is a function of
    /// it, so the sweep has to be able to vary it rather than assuming 8 Mbps.
    rate_mbps_per_dest: f64,
    /// Send the diagnostic terminal fence after the measured window.
    fence: bool,
    /// Tag measured payloads with their tick id (diagnostic runs only).
    identity: bool,
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
            rate_mbps_per_dest: 8.0,
            fence: false,
            identity: false,
        }
    }
}

impl Options {
    /// Apply one `--flag value` pair.
    ///
    /// Split into the two groups the flags actually fall into -- how the run is
    /// shaped (output, destinations, shards, repetitions) and how the engine and
    /// offer are configured -- so neither group's table carries the other's
    /// branches. Each returns whether it recognised the flag.
    fn set(&mut self, flag: &str, value: &str) -> Result<(), String> {
        if self.set_run_shape(flag, value)? || self.set_engine(flag, value)? {
            return Ok(());
        }
        Err(format!("unknown argument {flag}"))
    }

    fn set_run_shape(&mut self, flag: &str, value: &str) -> Result<bool, String> {
        match flag {
            "--out" => self.out = PathBuf::from(value),
            "--n" => self.n = parse(value, flag)?,
            "--shards" => self.shards = parse(value, flag)?,
            "--reps" => self.reps = parse(value, flag)?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn set_engine(&mut self, flag: &str, value: &str) -> Result<bool, String> {
        match flag {
            "--window-ms" => self.window_ms = parse(value, flag)?,
            "--tx-lanes" => self.tx_lanes = parse(value, flag)?,
            "--connect-cc" => self.connect_cc = parse(value, flag)?,
            "--base-port" => self.base_port = parse(value, flag)?,
            "--payload-bytes" => self.payload_bytes = parse(value, flag)?,
            "--rate-mbps-per-dest" => self.rate_mbps_per_dest = parse(value, flag)?,
            "--fence" => self.fence = parse(value, flag)?,
            "--identity" => self.identity = parse(value, flag)?,
            _ => return Ok(false),
        }
        Ok(true)
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

/// Build the sweep's child executables and return the exact paths cargo
/// produced for them.
///
/// This driver builds what it benchmarks, immediately before running it. It
/// used to scan `target/release/deps` for the most recently modified
/// `compio_shared_owner_qual-*` binary and take `target/release/srt-bench`
/// wherever it existed -- while the TSV header recorded the *working tree's*
/// `git_sha`. That combination proves nothing: build at revision A, check out B,
/// run the sweep, and the artifact names B while executing A. The failure mode
/// is not hypothetical here; a stale binary already contaminated one round of
/// this PR's own diagnostics.
///
/// `--message-format=json` is what makes the paths authoritative rather than
/// inferred: cargo reports the artifact it produced, so the executable that runs
/// is the one cargo just built, never a same-named file someone left behind.
fn build_harness(root: &Path) -> Result<Harness, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .args([
            "build",
            "--release",
            "-p",
            "srt-bench",
            "--bin",
            "srt-bench",
            "--bench",
            "compio_shared_owner_qual",
            "--message-format=json",
        ])
        .current_dir(root)
        // Compiler diagnostics belong on the terminal; stdout is JSON.
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("running `{cargo} build`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "building the sweep children exited with {}",
            output.status
        ));
    }
    let (mut bench, mut receiver) = (None, None);
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let Some(executable) = message["executable"].as_str() else {
            continue;
        };
        let name = message["target"]["name"].as_str().unwrap_or_default();
        let kinds = message["target"]["kind"].as_array();
        let is = |kind: &str| kinds.is_some_and(|kinds| kinds.iter().any(|k| k == kind));
        if is("bench") && name == "compio_shared_owner_qual" {
            bench = Some(PathBuf::from(executable));
        }
        if is("bin") && name == "srt-bench" {
            receiver = Some(PathBuf::from(executable));
        }
    }
    match (bench, receiver) {
        (Some(bench), Some(receiver)) => Ok(Harness { bench, receiver }),
        (None, _) => Err(format!(
            "{cargo} reported no executable for the compio_shared_owner_qual bench; \
             refusing to guess which binary to benchmark"
        )),
        (_, None) => Err(format!(
            "{cargo} reported no executable for srt-bench; refusing to guess which \
             binary to benchmark"
        )),
    }
}

/// Owns every child a rep spawns.
///
/// Failing fast is only safe if it also cleans up: dropping a
/// `std::process::Child` leaves the process running, so a failed sweep used to
/// leave receivers holding UDP ports and senders burning CPU into the next
/// experiment. This guard kills and reaps whatever is still alive on any exit
/// path, including the early `return Err` ones.
struct Children {
    receivers: Vec<Child>,
    senders: Vec<(u16, Child)>,
}

impl Children {
    fn wait_for_senders(&mut self) -> Result<(), String> {
        for (port, sender) in self.senders.iter_mut() {
            match sender.wait() {
                Ok(status) if status.success() => {}
                Ok(status) => {
                    return Err(format!("sender shard on port {port} exited with {status}"));
                }
                Err(e) => return Err(format!("sender shard on port {port}: wait failed: {e}")),
            }
        }
        Ok(())
    }

    fn stop_receivers(&mut self) -> Result<(), String> {
        for (shard, receiver) in self.receivers.iter_mut().enumerate() {
            match receiver.try_wait() {
                Ok(Some(status)) if !status.success() => {
                    return Err(format!("receiver for shard {shard} exited with {status}"));
                }
                // Still running is expected: the receiver's own deadline is
                // longer than the window plus drain.
                Ok(None) => {
                    let _ = receiver.kill();
                    let _ = receiver.wait();
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        for (_, sender) in self.senders.iter_mut() {
            let _ = sender.kill();
            let _ = sender.wait();
        }
        for receiver in self.receivers.iter_mut() {
            let _ = receiver.kill();
            let _ = receiver.wait();
        }
    }
}

/// Keep the failed rep's logs and describe where they are.
///
/// A partial log is useful evidence about *why* a run failed, so it is
/// retained on disk; what it must never become is a TSV row.
fn keep_logs(work: &Path, message: String) -> String {
    format!("{message}; logs kept in {}", work.display())
}

/// Everything the sweep needs to launch work: the exact child executables
/// cargo produced for this run (see [`build_harness`]).
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
    build_harness(&find_root()?)
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

/// The TSV header, including the provenance that makes `git_sha` mean
/// something.
///
/// `built_by_scaling=true` and `build_profile=release` are facts about this
/// tool rather than flags: `run` cannot reach `sweep` without having gone
/// through `locate` -> `build_harness`, which builds both children in release
/// mode and returns cargo's own artifact paths. Together with `git_dirty`, they
/// are what let a reader conclude the header's SHA describes the code that
/// actually ran -- and `qualify --require-clean` refuses a canonical artifact
/// without them.
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
         # reps={} base_port={} payload_bytes={} rate_mbps_per_dest={} fence={} identity={} \
         build_profile=release built_by_scaling=true git_sha={} git_dirty={}\n{}\n",
        options.n,
        options.shards,
        options.n / options.shards,
        options.tx_lanes,
        options.connect_cc,
        options.window_ms,
        options.reps,
        options.base_port,
        options.payload_bytes,
        options.rate_mbps_per_dest,
        options.fence,
        options.identity,
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

    let mut children = Children {
        receivers: spawn_receivers(harness, &work, rep_base, fanout, options)?,
        senders: spawn_senders(harness, &work, rep_base, fanout, options)?,
    };

    children
        .wait_for_senders()
        .map_err(|e| keep_logs(&work, e))?;
    sleep(Duration::from_secs(12));
    // Give receivers a bounded window to finish on their own -- they print STATS
    // when their connections close -- before stopping them. Killing a receiver
    // mid-drain is how a slow run produced "no STATS line" instead of a row.
    let grace = Instant::now();
    while grace.elapsed() < Duration::from_secs(20) {
        let mut still_running = false;
        for receiver in children.receivers.iter_mut() {
            if matches!(receiver.try_wait(), Ok(None)) {
                still_running = true;
            }
        }
        if !still_running {
            break;
        }
        sleep(Duration::from_millis(500));
    }
    children.stop_receivers().map_err(|e| keep_logs(&work, e))?;

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
    // Window + the sender's DRAIN_DEADLINE (10 s) + connect and teardown
    // margin. At 30 s the receiver was killed before its own deadline on
    // slow-drain runs, so it never printed STATS and the sweep correctly
    // refused the row -- a harness budget problem reported as a transport
    // failure until the lifetime covered the work.
    let seconds = (options.window_ms / 1000 + 45).to_string();
    let mut children = Vec::with_capacity(options.shards);
    for shard in 0..options.shards {
        let port = rep_base + (shard * fanout) as u16;
        let log = open_log(work, &format!("rx.{shard}.log"))?;
        // Diagnostic runs need the receiver to derive the same tick count the
        // sender offers, from the same parameters and through the same shared
        // arithmetic -- not from its own lifetime, which is deliberately
        // window + drain/grace.
        let mut receiver_args = vec![
            "runtime=compio".to_string(),
            "mode=receiver".to_string(),
            port.to_string(),
            seconds.clone(),
            "120".to_string(),
            "--connections".to_string(),
            fanout.to_string(),
        ];
        if options.identity {
            receiver_args.extend([
                "--diag-payload-bytes".to_string(),
                options.payload_bytes.to_string(),
                "--diag-rate-bps".to_string(),
                ((options.rate_mbps_per_dest * 1e6) as u64).to_string(),
                "--diag-window-ms".to_string(),
                options.window_ms.to_string(),
            ]);
        }
        let child = Command::new(&harness.receiver)
            .args(&receiver_args)
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
                "--rate-mbps-per-dest".to_string(),
                options.rate_mbps_per_dest.to_string(),
                "--fence".to_string(),
                options.fence.to_string(),
                "--identity".to_string(),
                options.identity.to_string(),
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
        return Err(keep_logs(
            work,
            format!("shard {shard} rep {rep}: no SHARED_OWNER_QUAL line from the sender"),
        ));
    }
    if rx_fields.is_empty() {
        return Err(keep_logs(
            work,
            format!("shard {shard} rep {rep}: no STATS line from the receiver"),
        ));
    }
    // Presence is not validity: a stale `cpu_ms=0.0` passes a `contains_key`
    // check, and that exact bug shipped once already. Each CPU field must parse
    // as a finite number, the two measured intervals must be positive, and the
    // whole-run figure must cover them (it spans window + drain plus the
    // bookkeeping between, so it can only be larger).
    let mut cpus = BTreeMap::new();
    for key in ["cpu_ms", "window_cpu_ms", "drain_cpu_ms"] {
        let raw = tx_fields.get(key).ok_or_else(|| {
            keep_logs(
                work,
                format!("shard {shard} rep {rep}: sender record is missing {key}"),
            )
        })?;
        let value: f64 = raw.parse().map_err(|_| {
            keep_logs(
                work,
                format!("shard {shard} rep {rep}: {key}={raw:?} does not parse"),
            )
        })?;
        if !value.is_finite() {
            return Err(keep_logs(
                work,
                format!("shard {shard} rep {rep}: {key}={raw:?} is not finite"),
            ));
        }
        cpus.insert(key, value);
    }
    let cpu_ms = cpus["cpu_ms"];
    let window_cpu_ms = cpus["window_cpu_ms"];
    let drain_cpu_ms = cpus["drain_cpu_ms"];
    if cpu_ms <= 0.0 || window_cpu_ms <= 0.0 || drain_cpu_ms < 0.0 {
        return Err(keep_logs(
            work,
            format!(
                "shard {shard} rep {rep}: implausible CPU accounting \
                 (cpu_ms={cpu_ms}, window_cpu_ms={window_cpu_ms}, drain_cpu_ms={drain_cpu_ms}); \
                 a non-positive window CPU is the stale-field bug, not a fast run"
            ),
        ));
    }
    if cpu_ms + 10.0 < window_cpu_ms + drain_cpu_ms {
        return Err(keep_logs(
            work,
            format!(
                "shard {shard} rep {rep}: cpu_ms ({cpu_ms}) does not cover \
                 window + drain ({}); the fields are not from the same run",
                window_cpu_ms + drain_cpu_ms
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn alive(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    /// The failure path must not leave benchmark processes behind: a receiver
    /// still holding a UDP port contaminates the next experiment, and a sender
    /// still burning CPU contaminates every measurement in it.
    ///
    /// This exercises the mechanism (drop kills and reaps whatever it owns)
    /// rather than trying to provoke a production failure: if `Drop` did not
    /// kill, the children below would still be alive when the assertion runs.
    #[test]
    fn children_guard_kills_and_reaps_every_child() {
        let mut receivers: Vec<Child> = Vec::new();
        let mut senders: Vec<(u16, Child)> = Vec::new();
        for _ in 0..2 {
            receivers.push(
                Command::new("sleep")
                    .arg("30")
                    .stdout(Stdio::null())
                    .spawn()
                    .expect("spawn stand-in receiver"),
            );
            senders.push((
                0,
                Command::new("sleep")
                    .arg("30")
                    .stdout(Stdio::null())
                    .spawn()
                    .expect("spawn stand-in sender"),
            ));
        }
        let pids: Vec<u32> = receivers
            .iter()
            .map(|c| c.id())
            .chain(senders.iter().map(|(_, c)| c.id()))
            .collect();
        for pid in &pids {
            assert!(alive(*pid), "stand-in process {pid} should be running");
        }

        let guard = Children { receivers, senders };
        drop(guard);

        for pid in &pids {
            assert!(
                !alive(*pid),
                "guard dropped but process {pid} is still alive"
            );
        }
    }
}
