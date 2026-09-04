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
    "recv_rounds",
    "would_block_policy",
    "sock_buf_requested_bytes",
    "sock_rcvbuf_effective_min_bytes",
    "sock_rcvbuf_effective_max_bytes",
    "sock_sndbuf_effective_min_bytes",
    "sock_sndbuf_effective_max_bytes",
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
    "recv_cpus",
    "send_cpus",
    // Three different cardinalities that a single `conns` used to stand
    // for. They coincide for an unbonded run and diverge for a bonded
    // one, where two physical legs carry one logical stream driven by one
    // source clock -- so using `conns` as the workload denominator made a
    // perfect bonded source read as ~50% offered.
    //
    // `conns` stays the PHYSICAL connection count (what was asked for,
    // and what `established` is measured against on the caller side).
    "conns",
    // Application-visible streams: what a group-aware listener admits.
    "logical_streams",
    // Independent payload producers this process actually ran. Measured,
    // not derived from topology.
    "source_streams",
    "connect_cc",
    "cc_peak",
    "bond",
    // The application workload rate, in bits per second. Replaces the old
    // `bitrate` column, which was simultaneously this and SRTO_MAXBW; the
    // rename is deliberate, so a row can never be read as either one.
    "source_bps",
    // The pacing policy, and what it resolved to. Recorded rather than
    // recomputed, so no downstream tool has to re-derive MAXBW from the
    // source rate -- which is how the two became the same number.
    "srt_bw_mode",
    "srt_maxbw_bps",
    "srt_inputbw_bps",
    "srt_oheadbw_pct",
    "model_policy_rev",
    "model_class_pre",
    "model_reasons_pre",
    "model_source_pps_total",
    "model_packet_pps",
    "model_srt_total_bps",
    "model_udp_ip_bps",
    "model_nic_wire_bps",
    "model_retransmission_factor",
    "model_bdp_packets",
    "model_required_window_packets",
    "model_flow_window_headroom_packets",
    "model_receive_window_headroom_packets",
    "model_recovery_margin_ms",
    "model_socket_horizon_recv_s",
    "model_socket_horizon_send_s",
    "model_host_utilization",
    "model_nic_utilization",
    "model_admission_waves",
    "rep",
    // Identity of the *attempt* that wrote this row, not of the cell.
    // A results file is append-only, so an interrupted run can leave a
    // half-finished pair behind; without this, a later attempt's listener
    // row plus a previous attempt's caller row read as one complete pair
    // and a row-less child looked successful. Deliberately absent from
    // `CONFIG_COLUMNS`: two attempts at the same cell are the same
    // experiment, and must still group and resume as one.
    "attempt",
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
    // Application source behaviour, distinct from anything the protocol
    // did. `src_backlog_cap` is the configured bound; a clean cell needs
    // `src_overflow` zero.
    "src_generated",
    "src_accepted",
    // Poll-rate dependent: how often a send attempt found the protocol
    // unwilling. Diagnostic only -- a runtime that wakes more often reports
    // more refusals for identical backpressure.
    "src_refusal_polls",
    // Poll-rate independent: one per contiguous episode of backpressure,
    // so this is comparable across runtimes.
    "src_blocked_streaks",
    // The configured backlog POLICY, alongside the packet capacity it
    // resolved to. The policy changes `src_overflow`, which changes
    // whether a cell is clean, so it is part of the experiment's identity
    // -- two runs that differ only in 50ms vs 500ms of source backlog are
    // not the same cell and must not resume or group as one.
    "source_backlog_ms",
    "src_backlog_cap",
    "src_backlog_hwm",
    "src_overflow",
    // Benchmark-owned packet-rate queues. Capacity zero is explicitly
    // not-applicable for paths without such a queue.
    // Benchmark-owned packet queues. Names say WHICH SCOPE each figure
    // measures: one queue, the worst single queue, or the whole process.
    // A merged maximum reported as "high water" reads as process state
    // while meaning "the deepest any one queue got", and at high
    // connection counts those are very different claims.
    "datapath_q_horizon_ms",
    "datapath_q_count",
    "datapath_q_cap_per_queue",
    "datapath_q_total_cap",
    "datapath_q_peak_depth_max",
    // Sum of every queue's own peak: an UPPER BOUND on what the harness
    // ever held at once, not a measured simultaneous total. Measuring the
    // true total needs a process-global counter on every enqueue and
    // dequeue, which is two contended atomics on the per-packet path of a
    // tool built to measure that path.
    "datapath_q_peak_depth_sum",
    "datapath_q_full",
    // Capacity rejections. A clean cell requires this to be zero.
    "datapath_q_dropped",
    // Sends to an already-gone consumer: a shutdown-ordering fact, not a
    // capacity signal, so deliberately not part of cleanliness.
    "datapath_q_disconnected",
    "recv_packets",
    "recv_syscalls",
    "datagrams_per_syscall",
    // Timer-service lateness, from a fixed power-of-two histogram. Named
    // `bucket` because that is what a bucketed histogram can honestly
    // report: the upper edge of the bucket the percentile falls in, not
    // the percentile. Clamped to `timer_late_max_us`, so a "p99" can
    // never come out larger than the largest value actually measured.
    "timer_late_p50_bucket_us",
    "timer_late_p95_bucket_us",
    "timer_late_p99_bucket_us",
    "timer_late_max_us",
    // Retained outbound work. Same scope discipline as the datapath
    // queues above: one queue's capacity, how many exist, the pool total,
    // and the worst any single queue reached.
    "retry_horizon_ms",
    "retry_count",
    "retry_cap_per_queue",
    "retry_total_cap",
    "retry_peak_depth_max",
    "would_block",
    // `retry_overflow` is the REASON datagrams were lost; `local_dropped`
    // is the TOTAL the harness dropped locally, for any reason. The total
    // is a superset -- never add the two.
    "retry_overflow",
    "local_dropped",
];

/// Configuration columns that define a unique benchmark workload/cell.
/// Shared between harness reporting and comparison tooling to guarantee
/// cell identity never drifts.
pub const CONFIG_COLUMNS: &[&str] = &[
    "runtime",
    "encryption",
    "ingress",
    "egress",
    "promotion",
    "cookie",
    "batch",
    "recv_rounds",
    "would_block_policy",
    "sock_buf_requested_bytes",
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
    "recv_cpus",
    "send_cpus",
    "conns",
    "connect_cc",
    "bond",
    "source_bps",
    "srt_bw_mode",
    "source_backlog_ms",
    "datapath_q_horizon_ms",
    "retry_horizon_ms",
    "secs",
    "model_policy_rev",
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

/// Everything one process measured about its own run.
///
/// Grouped rather than passed as a dozen positional arguments: the row
/// keeps growing as the harness learns to record more of its own state,
/// and a positional list means every call site gains another bare `0`
/// each time -- which is exactly how a counter ends up silently written
/// into the wrong column.
#[derive(Clone, Copy, Debug, Default)]
pub struct RunMeasurements {
    pub established: u64,
    pub torn_down: u64,
    pub pkt_sent: u64,
    pub core_total: u64,
    pub sec_a: u64,
    pub sec_b: u64,
    pub rtt_ms: f64,
    pub elapsed_s: f64,
    pub cc_peak: usize,
    /// What the application source offered, as opposed to what the
    /// protocol carried.
    pub source: crate::source::SourceStats,
    /// How many independent payload producers ran. One per logical
    /// stream, so a bonded pair counts once.
    pub source_streams: u64,
    pub datapath_queue: crate::queue::QueueStats,
    pub recv_scheduling: crate::scheduling::RecvSchedulingStats,
    pub outbound_retry: crate::scheduling::RetryStats,
}

/// Append one run's result, writing the header first if the file is new.
///
/// Appending (rather than truncating) is deliberate: a sweep is many
/// processes writing to one file, and each is a separate `srt-bench`
/// invocation with no knowledge of its siblings.
pub fn append_result(
    path: &Path,
    cfg: &BenchConfig,
    rep: usize,
    measurements: &RunMeasurements,
) -> std::io::Result<()> {
    let RunMeasurements {
        established,
        torn_down,
        pkt_sent,
        core_total,
        sec_a,
        sec_b,
        rtt_ms,
        elapsed_s,
        cc_peak,
        source,
        source_streams,
        datapath_queue,
        recv_scheduling,
        outbound_retry,
    } = *measurements;
    let model = crate::classifier::assessment_for_bench_config(cfg)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error.0))?;
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
    // Record what the pacing policy resolved to rather than making a
    // reader re-derive it. MAXBW/INPUTBW are protocol bytes/s; results
    // state bits/s so they sit in the same units as `source_bps`.
    let resolved = cfg.srt_bandwidth().resolve();
    let sock_bufs = srt_transport::socket_buffer_stats();
    let sock_buf_requested = cfg.sock_buf_bytes;
    let observed = |value: usize| {
        if sock_bufs.sockets > 0 {
            value.to_string()
        } else {
            String::new()
        }
    };
    if sock_bufs.sockets > 0
        && sock_buf_requested > 0
        && (sock_bufs.rcvbuf_min_bytes < sock_buf_requested
            || sock_bufs.sndbuf_min_bytes < sock_buf_requested)
    {
        eprintln!(
            "socket buffers clamped: requested={sock_buf_requested}, sockets={}, \
             rcvbuf={}..{}, sndbuf={}..{}",
            sock_bufs.sockets,
            sock_bufs.rcvbuf_min_bytes,
            sock_bufs.rcvbuf_max_bytes,
            sock_bufs.sndbuf_min_bytes,
            sock_bufs.sndbuf_max_bytes,
        );
    }
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
        cfg.recv_rounds.to_string(),
        cfg.would_block.as_str().to_string(),
        sock_buf_requested.to_string(),
        observed(sock_bufs.rcvbuf_min_bytes),
        observed(sock_bufs.rcvbuf_max_bytes),
        observed(sock_bufs.sndbuf_min_bytes),
        observed(sock_bufs.sndbuf_max_bytes),
        srt_transport::current_cpu_spec().unwrap_or_default(),
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
        cfg.peer_topology.recv_cpus.clone(),
        cfg.peer_topology.send_cpus.clone(),
        cfg.connections.to_string(),
        cfg.logical_connection_count().to_string(),
        source_streams.to_string(),
        cfg.connect_concurrency.to_string(),
        cc_peak.to_string(),
        describe_bond(cfg),
        cfg.source_bitrate_bps.to_string(),
        cfg.bandwidth.name(),
        resolved
            .max_bytes_per_sec
            .map_or(String::new(), |b| (b * 8).to_string()),
        resolved
            .input_bytes_per_sec
            .map_or(String::new(), |b| (b * 8).to_string()),
        resolved.overhead_percent.to_string(),
        model.policy_revision.clone(),
        model.class.name().to_string(),
        model
            .reasons
            .iter()
            .map(|reason| reason.code())
            .collect::<Vec<_>>()
            .join(","),
        model.derived.source_pps_total.to_string(),
        model_value(model.derived.host_packet_work_pps),
        model_value(model.derived.srt_total_bps),
        model_value(model.derived.udp_ip_bps),
        model_value(model.derived.nic_wire_bps),
        model_value(model.derived.retransmission_factor),
        model_value(model.derived.bdp_packets),
        model_value(model.derived.required_window_packets),
        model_value(model.derived.flow_window_headroom_packets),
        model_value(model.derived.receive_window_headroom_packets),
        model_value(model.derived.one_repair_margin_ms),
        model_value(
            model
                .derived
                .effective_receive_socket_buffer_horizon_seconds,
        ),
        model_value(model.derived.effective_send_socket_buffer_horizon_seconds),
        model_value(model.derived.host_pps_utilization),
        model_value(model.derived.nic_utilization),
        model.derived.admission_waves.to_string(),
        rep.to_string(),
        cfg.attempt.clone(),
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
        source.generated.to_string(),
        source.accepted.to_string(),
        source.refusal_polls.to_string(),
        source.blocked_streaks.to_string(),
        cfg.source_backlog_ms.to_string(),
        crate::source::backlog_capacity(cfg.source_bitrate_bps, cfg.source_backlog_ms).to_string(),
        source.backlog_hwm.to_string(),
        source.overflow.to_string(),
        cfg.datapath_queue_horizon_ms.to_string(),
        datapath_queue.queues.to_string(),
        datapath_queue.capacity_per_queue.to_string(),
        datapath_queue.total_capacity.to_string(),
        datapath_queue.peak_depth_max.to_string(),
        datapath_queue.peak_depth_sum.to_string(),
        datapath_queue.full_events.to_string(),
        datapath_queue.dropped_or_rejected.to_string(),
        datapath_queue.disconnected.to_string(),
        recv_scheduling.packets.to_string(),
        recv_scheduling.syscalls.to_string(),
        if recv_scheduling.syscalls == 0 {
            "0".to_string()
        } else {
            format!(
                "{:.3}",
                recv_scheduling.packets as f64 / recv_scheduling.syscalls as f64
            )
        },
        recv_scheduling.percentile_bucket_us(50).to_string(),
        recv_scheduling.percentile_bucket_us(95).to_string(),
        recv_scheduling.percentile_bucket_us(99).to_string(),
        recv_scheduling.lateness_max_us.to_string(),
        cfg.outbound_retry_horizon_ms.to_string(),
        outbound_retry.queues.to_string(),
        outbound_retry.capacity.to_string(),
        outbound_retry.total_capacity.to_string(),
        outbound_retry.high_water.to_string(),
        outbound_retry.would_block.to_string(),
        outbound_retry.overflow.to_string(),
        outbound_retry.local_dropped.to_string(),
    ];
    debug_assert_eq!(values.len(), COLUMNS.len(), "row/header width mismatch");
    let _ = write!(row, "{}", values.join("\t"));
    writeln!(file, "{row}")
}

fn model_value<T: std::fmt::Display>(value: crate::model::Availability<T>) -> String {
    match value {
        crate::model::Availability::Known(value) => value.to_string(),
        crate::model::Availability::Unknown => "unknown".to_string(),
        crate::model::Availability::NotApplicable => "n/a".to_string(),
    }
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
        // A pre-source-rate file is rejected by name rather than as a
        // generic column-count mismatch. Its `bitrate` column was both the
        // workload rate and SRTO_MAXBW, so there is no way to read it as
        // either one -- and silently reinterpreting it as a source rate
        // would attach new semantics to old measurements.
        let legacy = keys.contains(&"bitrate") && !keys.contains(&"source_bps");
        let legacy_sock_buf =
            keys.contains(&"sock_buf") && !keys.contains(&"sock_buf_requested_bytes");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            if legacy {
                format!(
                    "{}: legacy result schema (has `bitrate`, which meant both the source \
                     payload rate and SRTO_MAXBW). Those are now separate columns \
                     (`source_bps`, `srt_bw_mode`, `srt_maxbw_bps`), and an old row cannot \
                     be reinterpreted as either. Re-run the sweep, or compare old files \
                     with an older srt-bench.",
                    path.display(),
                )
            } else if legacy_sock_buf {
                format!(
                    "{}: legacy result schema (has `sock_buf`, which aliased requested vs effective \
                     socket buffer size). Those are now separate requested/effective min/max columns. \
                     Re-run the sweep, \
                     or compare old files with an older srt-bench.",
                    path.display(),
                )
            } else {
                format!(
                    "{}: unexpected TSV header (expected {} columns, got {})",
                    path.display(),
                    COLUMNS.len(),
                    keys.len()
                )
            },
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

pub fn median(mut values: Vec<f64>) -> f64 {
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
fn report_key(record: &Record, group_by: &[String]) -> String {
    group_by
        .iter()
        .map(|key| record.get(key).unwrap_or("-").to_string())
        .collect::<Vec<_>>()
        .join("\t")
}

fn report_keys(results: &[Record], group_by: &[String]) -> Vec<String> {
    let mut keys = Vec::new();
    for record in results {
        let key = report_key(record, group_by);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys.sort();
    keys
}

fn report_headers(group_by: &[String]) -> Vec<String> {
    group_by
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
            .map(|name| (*name).to_string()),
        )
        .collect()
}

fn report_median(records: &[&Record], column: &str) -> f64 {
    median(
        records
            .iter()
            .filter_map(|record| record.number(column))
            .collect(),
    )
}

/// How many payload packets the *application source* asked for.
///
/// The denominator is `PAYLOAD_SIZE`, not `PAYLOAD_SIZE +
/// SRT_HEADER_SIZE`: this counts what the workload offered, and the
/// workload does not produce SRT headers. Using the wire size here is
/// what made "offer" a measurement of SRT's own pacing ceiling rather
/// than of whether the configured load was actually produced. SRT's
/// pacing ceiling is a separate quantity, recorded in `srt_maxbw_bps`.
pub fn source_target_packets(record: &Record) -> Option<f64> {
    let (source_bps, seconds) = (record.number("source_bps")?, record.number("secs")?);
    // Denominator is the number of independent payload PRODUCERS, not
    // physical connections. A two-leg bonded group is two connections
    // carrying one source, so `conns` would double the target and make a
    // perfect source read as ~50% offered. `source_streams` is measured
    // by the sender itself; a listener row has none, so fall back to the
    // logical stream count it does record, and only then to `conns`.
    let streams = record
        .number("source_streams")
        .filter(|streams| *streams > 0.0)
        .or_else(|| record.number("logical_streams").filter(|s| *s > 0.0))
        .or_else(|| record.number("conns"))?;
    let packets = streams * (source_bps / 8.0) * seconds / crate::PAYLOAD_SIZE as f64;
    (packets > 0.0).then_some(packets)
}

fn report_group_row(key: &str, cells: &[&Record]) -> Option<Vec<String>> {
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
    for record in cells {
        let rep = record.get("rep").unwrap_or("1").to_string();
        let slot = paired.entry(rep).or_default();
        match record.get("role") {
            Some("caller") => slot.0 = Some(record),
            Some("listener") => slot.1 = Some(record),
            _ => {}
        }
    }
    let (callers, listeners): (Vec<&Record>, Vec<&Record>) = paired
        .values()
        .filter_map(|(caller, listener)| Some((*caller.as_ref()?, *listener.as_ref()?)))
        .unzip();
    if listeners.is_empty() {
        return None;
    }

    let recv = report_median(&listeners, "core_total");
    let sent = report_median(&callers, "core_total");
    let deliv = if sent > 0.0 { 100.0 * recv / sent } else { 0.0 };
    let target_pkts = median(
        callers
            .iter()
            .filter_map(|record| source_target_packets(record))
            .collect(),
    );
    let pct = |value: f64| {
        if target_pkts > 0.0 {
            format!("{:.1}", 100.0 * value / target_pkts)
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
    let cpu = (report_median(&listeners, "cpu_user_ms")
        + report_median(&listeners, "cpu_sys_ms")
        + report_median(&callers, "cpu_user_ms")
        + report_median(&callers, "cpu_sys_ms"))
        / 1000.0;
    let mut row: Vec<String> = key.split('\t').map(str::to_string).collect();
    // All reported medians below are based on these complete caller /
    // listener pairs. Expose their count so a human or downstream tool
    // never mistakes one recovered sample for a stable comparison.
    row.push(listeners.len().to_string());
    row.push(format!("{:.0}", report_median(&listeners, "established")));
    row.push(format!("{sent:.0}"));
    row.push(format!("{recv:.0}"));
    row.push(pct(offered));
    row.push(pct(recv));
    row.push(format!("{deliv:.1}"));
    row.push(format!("{:.0}", report_median(&listeners, "sec_a")));
    row.push(format!(
        "{:.0}",
        report_median(&listeners, "udp_rcvbuf_err")
    ));
    // Caller and listener are two independent observers of the same
    // connections, and they do not always agree on which ones broke
    // -- the investigation this column exists for found every
    // instance on the caller side and none on the listener. Reporting
    // both, rather than a combined count, is what makes that visible.
    row.push(format!("{:.0}", report_median(&callers, "torn_down")));
    row.push(format!("{:.0}", report_median(&listeners, "torn_down")));
    row.push(format!("{:.2}", report_median(&listeners, "rtt_ms")));
    row.push(format!("{cpu:.1}"));
    row.push(format!(
        "{:.0}",
        report_median(&listeners, "peak_rss_kb").max(report_median(&callers, "peak_rss_kb"))
    ));
    Some(row)
}

fn render_report_table(rows: &[Vec<String>], group_by_len: usize) -> String {
    let width = rows[0].len();
    let mut widths = vec![0usize; width];
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.len());
        }
    }
    let mut out = String::new();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index + 1 == width {
                let _ = writeln!(out, "{cell:>w$}", w = widths[index]);
            } else if index < group_by_len {
                let _ = write!(out, "{cell:<w$}  ", w = widths[index]);
            } else {
                let _ = write!(out, "{cell:>w$}  ", w = widths[index]);
            }
        }
    }
    out
}

pub fn report(results: &[Record], group_by: &[String]) -> String {
    let keys = report_keys(results, group_by);
    let mut rows = vec![report_headers(group_by)];
    for key in keys {
        let cells: Vec<&Record> = results
            .iter()
            .filter(|record| report_key(record, group_by) == key)
            .collect();
        if let Some(row) = report_group_row(&key, &cells) {
            rows.push(row);
        }
    }
    render_report_table(&rows, group_by.len())
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
    if bonded && let Some(cc_str) = cell_value(cell, "connect-concurrency", Some(Scope::Both)) {
        let cc: usize = cc_str.parse().unwrap_or(1);
        if cc < 2 {
            return Some("bonded-cc-requires-2");
        }
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
    _cell: &Cell<'_>,
    axes: &[Axis],
    egress: &str,
    send_workers: Option<&str>,
) -> Option<&'static str> {
    if egress != "shared-socket" {
        return None;
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
    if axis == "sock-buf" {
        return ("sock_buf_requested_bytes", recorded_socket_buffer(value));
    }
    if let Some(column) = recorded_column(axis) {
        return (column, value.to_string());
    }
    if axis.starts_with("link-") {
        return (
            Box::leak(axis.replace('-', "_").into_boxed_str()),
            recorded_link_value(value),
        );
    }
    (
        Box::leak(axis.to_string().into_boxed_str()),
        value.to_string(),
    )
}

fn recorded_column(axis: &str) -> Option<&'static str> {
    const COLUMNS: &[(&str, &str)] = &[
        ("runtime", "runtime"),
        ("encryption", "encryption"),
        ("ingress", "ingress"),
        ("egress", "egress"),
        ("promotion", "promotion"),
        ("cookie-routing", "cookie"),
        ("batch", "batch"),
        ("workers", "workers"),
        ("connections", "conns"),
        ("connect-concurrency", "connect_cc"),
        ("bond", "bond"),
        ("bitrate", "source_bps"),
        ("srt-bandwidth", "srt_bw_mode"),
        ("source-backlog-ms", "source_backlog_ms"),
        ("recv-rounds", "recv_rounds"),
        ("would-block", "would_block_policy"),
        ("datapath-queue-horizon-ms", "datapath_q_horizon_ms"),
        ("datapath-q-horizon-ms", "datapath_q_horizon_ms"),
        ("outbound-retry-horizon-ms", "retry_horizon_ms"),
        ("retry-horizon-ms", "retry_horizon_ms"),
        ("pin", "pin"),
    ];
    COLUMNS
        .iter()
        .find(|(name, _)| *name == axis)
        .map(|(_, column)| *column)
}

fn recorded_socket_buffer(value: &str) -> String {
    match value {
        "default" | "0" => "0".to_string(),
        value => {
            let (digits, scale) = match value.strip_suffix(['m', 'M']) {
                Some(digits) => (digits, 1usize << 20),
                None => match value.strip_suffix(['k', 'K']) {
                    Some(digits) => (digits, 1usize << 10),
                    None => (value, 1),
                },
            };
            digits
                .parse::<usize>()
                .map_or_else(|_| value.to_string(), |n| (n * scale).to_string())
        }
    }
}

// `off` is how a plan or CLI spells "no emulation"; the process records that
// as an empty cell. Normalise here so a cell's key and its recorded row agree.
fn recorded_link_value(value: &str) -> String {
    if value == "off" {
        String::new()
    } else {
        value.to_string()
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
pub fn read_plan(path: &Path) -> std::io::Result<Vec<(String, Vec<String>)>> {
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

const CANONICAL_AXIS_NAMES: &[(&str, &str)] = &[
    ("runtime", "runtime"),
    ("runtimes", "runtime"),
    ("recv-runtime", "recv-runtime"),
    ("recv-runtimes", "recv-runtime"),
    ("send-runtime", "send-runtime"),
    ("send-runtimes", "send-runtime"),
    ("workers", "workers"),
    ("recv-workers", "recv-workers"),
    ("send-workers", "send-workers"),
    ("ingress", "ingress"),
    ("egress", "egress"),
    ("encryption", "encryption"),
    ("promotion", "promotion"),
    ("cookie-routing", "cookie-routing"),
    ("batch", "batch"),
    ("sock-buf", "sock-buf"),
    ("pin", "pin"),
    ("connections", "connections"),
    ("connect-concurrency", "connect-concurrency"),
    ("bond", "bond"),
    ("bitrate", "bitrate"),
    ("srt-bandwidth", "srt-bandwidth"),
    ("source-backlog-ms", "source-backlog-ms"),
    ("recv-rounds", "recv-rounds"),
    ("would-block", "would-block"),
    ("datapath-queue-horizon-ms", "datapath-queue-horizon-ms"),
    ("datapath-q-horizon-ms", "datapath-queue-horizon-ms"),
    ("outbound-retry-horizon-ms", "outbound-retry-horizon-ms"),
    ("retry-horizon-ms", "outbound-retry-horizon-ms"),
    ("link-delay", "link-delay"),
    ("link-jitter", "link-jitter"),
    ("link-loss", "link-loss"),
    ("link-rate", "link-rate"),
    ("link-reorder", "link-reorder"),
    ("link-duplicate", "link-duplicate"),
    ("link-corrupt", "link-corrupt"),
    ("link-limit", "link-limit"),
];

fn canonical_axis_name(name: &str) -> Option<&'static str> {
    CANONICAL_AXIS_NAMES
        .iter()
        .find(|(alias, _)| *alias == name.trim())
        .map(|(_, canonical)| *canonical)
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

struct MatrixAxisConfig {
    axes: Vec<Axis>,
    recv_cpus: String,
    send_cpus: String,
}

fn resolve_matrix_axes(cli: &crate::Cli) -> std::io::Result<MatrixAxisConfig> {
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
        // The application workload rate...
        axis("bitrate", "bitrate", "8000000"),
        // ...and, separately, how SRT is told to pace it. Defaults to the
        // historical coupling so an unchanged command line keeps producing
        // unchanged numbers; permanent plans state it explicitly.
        axis("srt-bandwidth", "srt-bandwidth", "legacy-source-fixed"),
        // How much source the application may hold before dropping it.
        // Sweepable because it is the knob that decides whether a cell
        // reports overflow, and therefore whether it is clean.
        axis(
            "source-backlog-ms",
            "source-backlog-ms",
            &crate::source::DEFAULT_SOURCE_BACKLOG_MS.to_string(),
        ),
        // The receive quantum and the outbound-yield policy. First-class
        // axes because the evidence for either value is a sweep, and a
        // knob that cannot be swept from a plan is a knob whose setting
        // never makes it into a result row's identity.
        axis("recv-rounds", "recv-rounds", "8"),
        axis("would-block", "would-block", "retain"),
        axis(
            "datapath-queue-horizon-ms",
            "datapath-queue-horizon-ms",
            &crate::queue::DEFAULT_DATAPATH_QUEUE_HORIZON_MS.to_string(),
        ),
        axis(
            "outbound-retry-horizon-ms",
            "outbound-retry-horizon-ms",
            &crate::scheduling::DEFAULT_OUTBOUND_RETRY_HORIZON_MS.to_string(),
        ),
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
    Ok(MatrixAxisConfig {
        axes,
        recv_cpus,
        send_cpus,
    })
}

/// Round-robin each Cartesian level so runtime, ingress, encryption, and
/// subsequent axes are spread through the run instead of appearing in one
/// long block. This remains deterministic and preserves each axis's plan
/// value order within its round-robin lanes.
fn axis_groups(
    cells: &[Cell<'_>],
    name: &str,
    scope: Scope,
    values: &[String],
    indices: &[usize],
) -> Vec<Vec<usize>> {
    values
        .iter()
        .map(|value| {
            indices
                .iter()
                .copied()
                .filter(|index| {
                    cells[*index].iter().any(|(axis, cell_scope, cell_value)| {
                        *axis == name && *cell_scope == scope && cell_value == value
                    })
                })
                .collect()
        })
        .filter(|group: &Vec<usize>| !group.is_empty())
        .collect()
}

fn round_robin_groups(groups: &[Vec<usize>], capacity: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(capacity);
    let longest = groups.iter().map(Vec::len).max().unwrap_or(0);
    for offset in 0..longest {
        for group in groups {
            if let Some(index) = group.get(offset) {
                out.push(*index);
            }
        }
    }
    out
}

fn visit_interleaved(
    cells: &[Cell<'_>],
    axes: &[Axis],
    depth: usize,
    indices: Vec<usize>,
) -> Vec<usize> {
    if depth == axes.len() || indices.len() < 2 {
        return indices;
    }
    let (name, scope, values) = &axes[depth];
    let mut groups = axis_groups(cells, name, *scope, values, &indices);
    if groups.len() < 2 {
        return visit_interleaved(cells, axes, depth + 1, indices);
    }
    for group in &mut groups {
        *group = visit_interleaved(cells, axes, depth + 1, std::mem::take(group));
    }
    round_robin_groups(&groups, indices.len())
}

fn interleave_indices(cells: &[Cell<'_>], axes: &[Axis]) -> Vec<usize> {
    visit_interleaved(cells, axes, 0, (0..cells.len()).collect())
}

struct MatrixSchedule {
    runs: Vec<(usize, usize)>,
    done: std::collections::HashSet<String>,
    total: usize,
}

fn build_matrix_schedule(
    cells: &[Cell<'_>],
    axes: &[Axis],
    reps: usize,
    order: MatrixOrder,
    seed: u64,
    out: &Path,
) -> std::io::Result<MatrixSchedule> {
    let total = cells.len() * reps;
    let mut cell_order: Vec<usize> = match order {
        MatrixOrder::Default | MatrixOrder::Random => (0..cells.len()).collect(),
        MatrixOrder::Interleaved => interleave_indices(cells, axes),
    };
    if order == MatrixOrder::Random {
        shuffle(&mut cell_order, seed);
    }
    let runs: Vec<(usize, usize)> = match order {
        MatrixOrder::Default => cell_order
            .iter()
            .flat_map(|cell| (1..=reps).map(move |rep| (*cell, rep)))
            .collect(),
        MatrixOrder::Interleaved | MatrixOrder::Random => (1..=reps)
            .flat_map(|rep| cell_order.iter().map(move |cell| (*cell, rep)))
            .collect(),
    };
    eprintln!(
        "matrix: order={order:?} seed={seed} scheduled_runs={}",
        runs.len()
    );

    // Resume: a sweep of this size will be interrupted at some point, and
    // re-running completed cells wastes hours and mixes measurement
    // windows. Anything already in the output file is skipped.
    // A cell counts as done only when BOTH roles recorded a row **in the
    // same attempt**. Keying on the listener alone meant a run interrupted
    // mid-cell left an orphan caller row, was re-run, and appended a
    // second caller row for the same cell -- two senders, one listener,
    // and any statistic over them silently wrong. Requiring one shared
    // attempt additionally rules out a pair assembled from two different
    // interrupted runs, which is a complete-looking cell whose two halves
    // never ran together.
    let recorded = if out.exists() {
        read_results(out)?
    } else {
        Vec::new()
    };
    let keys_for = |role: &str| -> std::collections::HashSet<(String, String)> {
        recorded
            .iter()
            .filter(|r| r.get("role") == Some(role))
            .filter_map(|r| {
                let rep: usize = r.number("rep")? as usize;
                let attempt = r.get("attempt")?.to_string();
                cells
                    .iter()
                    .find_map(|cell| record_key(r, cell, rep).filter(|k| *k == cell_key(cell, rep)))
                    .map(|key| (key, attempt))
            })
            .collect()
    };
    let (listener_keys, caller_keys) = (keys_for("listener"), keys_for("caller"));
    let done: std::collections::HashSet<String> = listener_keys
        .intersection(&caller_keys)
        .map(|(key, _attempt)| key.clone())
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
    Ok(MatrixSchedule { runs, done, total })
}

struct MatrixCellConfig {
    label: Vec<String>,
    recv_ingress: String,
    send_ingress: String,
    recv_runtime: String,
    send_runtime: String,
    /// The source payload rate, passed positionally to both roles. Not
    /// SRT's pacing ceiling -- that travels as the `--srt-bandwidth` flag
    /// like any other axis.
    source_bitrate: String,
    ports_needed: usize,
}

fn matrix_cell_value(cell: &Cell<'_>, name: &str) -> Option<String> {
    cell.iter()
        .find(|(axis, _, _)| *axis == name)
        .map(|(_, _, value)| value.clone())
}

fn matrix_cell_config(cell: &Cell<'_>) -> MatrixCellConfig {
    let label = cell
        .iter()
        .map(|(key, scope, value)| format!("{}{key}={value}", scope.prefix().replace('_', "-")))
        .collect();
    let for_role = |name: &str, role: Scope, default: &str| -> String {
        cell.iter()
            .find(|(key, scope, _)| *key == name && *scope == role)
            .or_else(|| {
                cell.iter()
                    .find(|(key, scope, _)| *key == name && *scope == Scope::Both)
            })
            .map_or_else(|| default.to_string(), |(_, _, value)| value.clone())
    };
    let recv_ingress = for_role("ingress", Scope::Recv, "per-port");
    let send_ingress = for_role("ingress", Scope::Send, "per-port");
    let recv_runtime = for_role("runtime", Scope::Recv, "mio");
    let send_runtime = for_role("runtime", Scope::Send, "mio");
    let connections = matrix_cell_value(cell, "connections")
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let source_bitrate = matrix_cell_value(cell, "bitrate").unwrap_or_else(|| "8000000".into());
    // per-port needs one port per connection; the pooled and reuseport
    // strategies need at most K. Ask for the worst case this cell could use.
    let ports_needed = if recv_ingress == "per-port" {
        connections
    } else {
        recv_ingress
            .split_once(':')
            .and_then(|(_, count)| count.parse().ok())
            .unwrap_or(1)
    };
    MatrixCellConfig {
        label,
        recv_ingress,
        send_ingress,
        recv_runtime,
        send_runtime,
        source_bitrate,
        ports_needed,
    }
}

fn matrix_cell_supported(config: &MatrixCellConfig) -> bool {
    crate::runtimes::ingress_supported(
        crate::Runtime::parse(&config.recv_runtime).unwrap_or(crate::Runtime::Mio),
        parse_ingress_spec(&config.recv_ingress),
    ) && crate::runtimes::ingress_supported(
        crate::Runtime::parse(&config.send_runtime).unwrap_or(crate::Runtime::Mio),
        parse_ingress_spec(&config.send_ingress),
    )
}

fn matrix_cell_link(cell: &Cell<'_>, flag: &str) -> Option<String> {
    cell.iter()
        .find(|(axis, _, _)| *axis == flag)
        .map(|(_, _, value)| value.clone())
}

fn matrix_cell_argv(cell: &Cell<'_>, role: Scope) -> Vec<String> {
    let mut out: Vec<String> = cell
        .iter()
        .filter(|(axis, scope, _)| {
            *axis != "bitrate" && *axis != "runtime" && *axis != "cpus" && scope.applies_to(role)
        })
        .map(|(axis, _, value)| format!("--{axis}={value}"))
        .collect();
    for (axis, scope, value) in cell {
        if *scope != Scope::Both {
            out.push(format!(
                "--{}{axis}={value}",
                scope.prefix().replace('_', "-")
            ));
        }
    }
    out
}

/// Why one scheduled matrix run did not complete.
///
/// Every variant here is a *required* role failing to do its job. None of
/// them is "this configuration is not supported": an unsupported cell is
/// classified up front from configuration (`matrix_cell_supported`) and
/// never inferred from a crash, because a crash and an unimplemented
/// combination look identical from the outside and conflating them is how
/// a broken sweep reports success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatrixFailureKind {
    /// The child exited non-zero, or was killed by a signal.
    ChildStatus { role: &'static str, status: String },
    /// The child exited cleanly but recorded no result row for this cell.
    /// A benchmark row is the child's actual output; producing none is
    /// exactly as useless as crashing.
    MissingResult { role: &'static str },
    /// The result file could not be read back, so the run cannot be
    /// confirmed either way.
    UnreadableResults { detail: String },
    /// The cell could not be run at all for an environmental reason (no
    /// free port range, netem apply failure). Not a protocol result and
    /// not an unsupported configuration -- the sweep asked for it and did
    /// not get it.
    Infrastructure { detail: String },
}

impl std::fmt::Display for MatrixFailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChildStatus { role, status } => write!(f, "{role} child failed ({status})"),
            Self::MissingResult { role } => write!(f, "{role} recorded no result row"),
            Self::UnreadableResults { detail } => write!(f, "result file unreadable: {detail}"),
            Self::Infrastructure { detail } => write!(f, "could not run cell: {detail}"),
        }
    }
}

/// One failed (cell, rep), kept so the sweep can carry on and still fail
/// at the end.
#[derive(Clone, Debug)]
pub struct MatrixFailure {
    pub label: String,
    pub rep: usize,
    pub kind: MatrixFailureKind,
}

impl std::fmt::Display for MatrixFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rep {} {}: {}", self.rep, self.label, self.kind)
    }
}

/// What a whole `srt-bench matrix` invocation did.
///
/// The invariant this type exists to enforce: **exit status 0 if and only
/// if every required cell and role completed successfully.** Previously a
/// child could exit non-zero, get one `eprintln!`, and the sweep would
/// still return `Ok(())` -- automation could therefore report a green
/// benchmark campaign whose sender had crashed.
#[derive(Clone, Debug, Default)]
pub struct MatrixReport {
    /// Every required-role failure seen, in schedule order.
    pub failures: Vec<MatrixFailure>,
    /// Runs not attempted because their configuration is explicitly
    /// unsupported. Not a failure.
    pub skipped_runs: usize,
    /// Runs skipped because a previous invocation already recorded them.
    pub resumed_runs: usize,
    /// Runs that started and recorded both roles.
    pub completed_runs: usize,
    /// Runs that were attempted and did not complete. One run can
    /// contribute several entries to `failures` (both roles crashed, say),
    /// so this is not `failures.len()`.
    pub failed_runs: usize,
}

impl MatrixReport {
    /// True when every required role of every attempted cell succeeded.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }

    /// Human-readable summary of what failed, for the process's stderr.
    #[must_use]
    pub fn failure_summary(&self) -> String {
        use std::fmt::Write as _;
        let mut out = format!(
            "matrix: {} of {} attempted runs failed ({} distinct failures)\n",
            self.failed_runs,
            self.failed_runs + self.completed_runs,
            self.failures.len()
        );
        for failure in &self.failures {
            let _ = writeln!(out, "  {failure}");
        }
        out
    }
}

struct MatrixProcessContext<'a, 'cell> {
    sender_exe: &'a Path,
    receiver_exe: &'a Path,
    out: &'a Path,
    cell: &'a Cell<'cell>,
    config: &'a MatrixCellConfig,
    rep: usize,
    secs: u64,
    latency: u16,
    recv_cpus: &'a str,
    send_cpus: &'a str,
    netns: Option<Priv>,
    run_index: usize,
    total: usize,
    /// Stamped onto both roles so their rows can be told apart from rows
    /// an earlier, interrupted attempt at the same cell left behind.
    attempt: &'a str,
}

/// Which roles recorded a row for this (cell, rep) in `out`.
///
/// Reuses `record_key`/`cell_key`, the same identity the resume logic
/// uses, so "this run recorded its output" and "this run is already done"
/// can never disagree.
/// Which roles recorded a row for this (cell, rep) **in this attempt**.
///
/// The attempt filter is the whole point. A result file is append-only
/// and a sweep gets interrupted, so it routinely contains a half-finished
/// pair from an earlier attempt. Asking only "does a caller row for this
/// cell exist?" let a previous attempt's caller row stand in for a
/// current sender that exited 0 and wrote nothing -- the sweep then
/// reported success for a run that produced no sender data at all.
fn recorded_roles(
    out: &Path,
    cell: &Cell<'_>,
    rep: usize,
    attempt: &str,
) -> std::io::Result<(bool /* caller */, bool /* listener */)> {
    if !out.exists() {
        return Ok((false, false));
    }
    let want = cell_key(cell, rep);
    let records = read_results(out)?;
    let mut caller = false;
    let mut listener = false;
    for record in &records {
        if record.get("attempt") != Some(attempt) {
            continue;
        }
        if record.number("rep").map(|r| r as usize) != Some(rep) {
            continue;
        }
        if record_key(record, cell, rep).as_ref() != Some(&want) {
            continue;
        }
        match record.get("role") {
            Some("caller") => caller = true,
            Some("listener") => listener = true,
            _ => {}
        }
    }
    Ok((caller, listener))
}

/// Generate a nonce that remains fresh even when the OS reuses a PID.
fn new_invocation_nonce() -> std::io::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
    let mut nonce = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut nonce, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(nonce)
}

/// Identity for one attempted cell. Both roles of one attempt share it.
fn attempt_id(invocation_nonce: &str, sequence: usize) -> String {
    format!("{invocation_nonce}-{sequence}")
}

/// Run one cell's receiver/sender pair, returning every way a *required*
/// role failed. An empty vec means both roles exited cleanly and both
/// recorded their result row.
fn run_matrix_processes(
    context: MatrixProcessContext<'_, '_>,
    port: u16,
) -> std::io::Result<Vec<MatrixFailureKind>> {
    let MatrixProcessContext {
        sender_exe,
        receiver_exe,
        out,
        cell,
        config,
        rep,
        secs,
        latency,
        recv_cpus,
        send_cpus,
        netns,
        run_index,
        total,
        attempt,
    } = context;
    // Each role gets the axes scoped to it plus the shared ones.
    // Both roles additionally get every split axis's *other* side
    // as a record-only `--recv-*`/`--send-*` flag, so a single row
    // states the whole cell -- without which two cells differing
    // only on the far side would be indistinguishable, and resume
    // would skip one of them.
    let mut recv_argv = matrix_cell_argv(cell, Scope::Recv);
    let send_argv = matrix_cell_argv(cell, Scope::Send);
    // The listener runs to a long backstop, but the cell's stream
    // length is what any rate is computed against.
    recv_argv.push(format!("--stream-secs={secs}"));
    // Receiver outlives the sender so it is still listening when
    // the last packets arrive; +5s mirrors the old harness.
    let mut recv = if let Some(p) = netns {
        in_netns(p, receiver_exe)
    } else {
        std::process::Command::new(receiver_exe)
    }
    .arg(format!("runtime={}", config.recv_runtime))
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
    // must record the same configured source rate or a report
    // grouping on it would split the pair and lose delivery%.
    .arg(&config.source_bitrate)
    .args(&recv_argv)
    .arg(format!("--rep={rep}"))
    .arg(format!("--attempt={attempt}"))
    .arg(format!("--cpus={recv_cpus}"))
    .arg(format!("--out={}", out.display()))
    .stdout(std::process::Stdio::piped())
    .spawn()?;

    if !wait_for_listening(&mut recv, std::time::Duration::from_secs(60)) {
        eprintln!(
            "[warn] listener never reported LISTENING: {}",
            config.label.join(" ")
        );
    }

    let send = if let Some(p) = netns {
        in_netns(p, sender_exe)
    } else {
        std::process::Command::new(sender_exe)
    }
    .arg(format!("runtime={}", config.send_runtime))
    .arg("mode=sender")
    .arg("127.0.0.1")
    .arg(port.to_string())
    .arg(secs.to_string())
    .arg(latency.to_string())
    .arg(&config.source_bitrate)
    .env("SRT_BENCH_CHILD", "1")
    .args(&send_argv)
    .arg(format!("--rep={rep}"))
    .arg(format!("--attempt={attempt}"))
    .arg(format!("--cpus={send_cpus}"))
    .arg(format!("--out={}", out.display()))
    .stdout(std::process::Stdio::null())
    .status()?;

    // Let the ordered SRT SHUTDOWN reach the listener and flush its
    // receive/event queues. Signalling immediately here raced the final
    // runtime tick and under-counted delivery even though wire telemetry
    // had received the packets. Most listeners exit naturally within a
    // few milliseconds; SIGTERM remains the bounded fallback.
    let recv_status = match wait_for_natural_exit(&mut recv, std::time::Duration::from_millis(500))?
    {
        Some(status) => status,
        None => {
            request_stop(&recv);
            recv.wait()?
        }
    };
    // A required role failing has to be remembered, not just printed.
    // Both roles are always required today: a cell's delivery percentage
    // is meaningless without the pair.
    let mut failures = Vec::new();
    if !send.success() {
        failures.push(MatrixFailureKind::ChildStatus {
            role: "sender",
            status: send.to_string(),
        });
    }
    if !recv_status.success() {
        failures.push(MatrixFailureKind::ChildStatus {
            role: "receiver",
            status: recv_status.to_string(),
        });
    }
    // Exiting 0 is necessary but not sufficient: the child's deliverable
    // is a result row. Check for it whichever way the statuses went, so a
    // silently row-less success is caught too. A malformed row makes
    // `read_results` fail; that is recorded as its own failure rather than
    // aborting the sweep, so later independent cells still run.
    match recorded_roles(out, cell, rep, attempt) {
        Ok((caller, listener)) => {
            if !caller && send.success() {
                failures.push(MatrixFailureKind::MissingResult { role: "sender" });
            }
            if !listener && recv_status.success() {
                failures.push(MatrixFailureKind::MissingResult { role: "receiver" });
            }
        }
        Err(error) => failures.push(MatrixFailureKind::UnreadableResults {
            detail: error.to_string(),
        }),
    }
    eprintln!(
        "[{:>4}/{total}] rep {rep} {}{}",
        run_index + 1,
        config.label.join(" "),
        if failures.is_empty() {
            String::new()
        } else {
            format!(
                " FAILED (sender={send} receiver={recv_status}: {})",
                failures
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        }
    );
    Ok(failures)
}

fn detect_matrix_netns(cells: &[Cell<'_>]) -> std::io::Result<Option<Priv>> {
    let mut any_link = false;
    for cell in cells {
        if netem_args(|flag| matrix_cell_link(cell, flag))
            .map_err(std::io::Error::other)?
            .is_some()
        {
            any_link = true;
        }
    }
    if !any_link {
        return Ok(None);
    }

    let privilege = Priv::detect().ok_or_else(|| std::io::Error::other(netem_privilege_help()))?;
    netns_up(privilege)?;
    eprintln!("matrix: running roles inside netns '{NETNS}' (link emulation active)");
    Ok(Some(privilege))
}

struct MatrixScheduleContext<'a, 'cell> {
    sender_exe: &'a Path,
    receiver_exe: &'a Path,
    out: &'a Path,
    cells: &'a [Cell<'cell>],
    schedule: &'a MatrixSchedule,
    reps: usize,
    secs: u64,
    latency: u16,
    recv_cpus: &'a str,
    send_cpus: &'a str,
    invocation_nonce: &'a str,
    netns: Option<Priv>,
}

fn run_matrix_schedule(context: MatrixScheduleContext<'_, '_>) -> std::io::Result<MatrixReport> {
    let MatrixScheduleContext {
        sender_exe,
        receiver_exe,
        out,
        cells,
        schedule,
        reps,
        secs,
        latency,
        recv_cpus,
        send_cpus,
        invocation_nonce,
        netns,
    } = context;
    let mut report = MatrixReport::default();
    let mut unsupported_cells = std::collections::HashSet::new();
    // A failing cell does not stop the sweep: later cells are independent
    // experiments and their data is worth having. The failure is
    // remembered and turned into a non-zero exit at the end instead.
    for (run_index, (cell_index, rep)) in schedule.runs.iter().copied().enumerate() {
        let cell = &cells[cell_index];
        let config = matrix_cell_config(cell);
        // Skip combinations the runtime does not implement rather than
        // running them and recording the wreckage: an unsupported cell
        // produces bind collisions that look exactly like a harness bug.
        // This is the *only* legitimate skip, and it is decided from
        // configuration alone -- never inferred from a child crashing.
        if !matrix_cell_supported(&config) {
            if unsupported_cells.insert(cell_index) {
                report.skipped_runs += reps;
                eprintln!("[skip] {} (unsupported)", config.label.join(" "));
            }
            continue;
        }
        if schedule.done.contains(&cell_key(cell, rep)) {
            report.resumed_runs += 1;
            continue;
        }
        // One identity per attempted cell, stamped on both roles. The
        // invocation nonce separates independent matrix processes; the
        // sequence separates attempts within this invocation.
        let attempt = attempt_id(invocation_nonce, run_index);
        let failures = run_scheduled_cell(
            MatrixProcessContext {
                sender_exe,
                receiver_exe,
                out,
                cell,
                config: &config,
                rep,
                secs,
                latency,
                recv_cpus,
                send_cpus,
                netns,
                run_index,
                total: schedule.total,
                attempt: &attempt,
            },
            |flag| matrix_cell_link(cell, flag),
        )?;
        if failures.is_empty() {
            report.completed_runs += 1;
            continue;
        }
        report.failed_runs += 1;
        for kind in failures {
            eprintln!("[fail] {} rep {rep}: {kind}", config.label.join(" "));
            report.failures.push(MatrixFailure {
                label: config.label.join(" "),
                rep,
                kind,
            });
        }
    }
    Ok(report)
}

/// Prepare the environment for one scheduled cell and run its role pair.
///
/// Returns the ways the cell failed; empty means it completed. Setup that
/// the sweep asked for and did not get -- link emulation that would not
/// apply, no free port range -- is a failure of that cell rather than a
/// skip: an environment problem and a configuration the runtime does not
/// implement are different things, and only the latter may be silently
/// passed over.
fn run_scheduled_cell(
    context: MatrixProcessContext<'_, '_>,
    link: impl Fn(&str) -> Option<String>,
) -> std::io::Result<Vec<MatrixFailureKind>> {
    if let Some(privilege) = context.netns
        && let Err(error) = netem_args(link)
            .map_err(std::io::Error::other)
            .and_then(|args| netem_apply(privilege, args))
    {
        return Ok(vec![MatrixFailureKind::Infrastructure {
            detail: format!("link emulation could not be applied: {error}"),
        }]);
    }
    // A per-port cell can ask for more descriptors than this process may
    // hold while probing the range.
    let port = match free_port_range(context.config.ports_needed) {
        Ok(port) => port,
        Err(error) => {
            return Ok(vec![MatrixFailureKind::Infrastructure {
                detail: format!("port allocation failed: {error}"),
            }]);
        }
    };
    run_matrix_processes(context, port)
}

/// Run the cartesian product of the requested axes, one receiver/sender
/// pair per cell, appending both sides' results to `out`.
///
/// Each side is a fresh child process rather than a thread: CPU is
/// measured with `getrusage`, which is per-process, so running both roles
/// in one process would attribute the sender's cost to the listener.
///
/// Returns what happened. The caller is responsible for turning a report
/// with failures into a non-zero process exit -- `Ok` here means "the
/// sweep ran to the end", not "everything in it worked".
pub fn run_matrix(cli: &crate::Cli) -> std::io::Result<MatrixReport> {
    let exe = std::env::current_exe()?;
    let sender_exe = cli
        .flags
        .get("sender-exe")
        .or_else(|| cli.flags.get("caller-exe"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| exe.clone());
    let receiver_exe = cli
        .flags
        .get("receiver-exe")
        .or_else(|| cli.flags.get("listener-exe"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| exe.clone());
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

    let MatrixAxisConfig {
        axes,
        recv_cpus,
        send_cpus,
    } = resolve_matrix_axes(cli)?;

    // Cartesian product, filtered one point at a time: the whole point is
    // to know how many cells there are before starting a long sweep without
    // holding the raw 1.7-million-cell product in memory.
    let (mut cells, raw_cells, filter_summary) = filtered_cartesian_cells(&axes)?;
    add_cpu_identity(&mut cells, &recv_cpus, &send_cpus);
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
    let (order, seed) = matrix_order(cli)?;
    let schedule = build_matrix_schedule(&cells, &axes, reps, order, seed, &out)?;
    let invocation_nonce = new_invocation_nonce()?;

    // Every cell of a netem sweep runs inside the namespace, including the
    // `netem=none` ones: a namespace's loopback is not identical to the
    // host's, so mixing the two would confound the comparison the sweep
    // exists to make.
    // Fail before the first cell rather than midway through a sweep.
    let netns = detect_matrix_netns(&cells)?;

    let report = run_matrix_schedule(MatrixScheduleContext {
        out: &out,
        cells: &cells,
        schedule: &schedule,
        reps,
        secs,
        latency,
        recv_cpus: &recv_cpus,
        send_cpus: &send_cpus,
        invocation_nonce: &invocation_nonce,
        sender_exe: &sender_exe,
        receiver_exe: &receiver_exe,
        netns,
    })?;
    if let Some(p) = netns {
        netns_down(p);
    }
    if report.skipped_runs > 0 {
        eprintln!(
            "matrix: skipped {} scheduled runs (unsupported configurations)",
            report.skipped_runs
        );
    }
    Ok(report)
}

fn add_cpu_identity(cells: &mut [Cell<'_>], recv_cpus: &str, send_cpus: &str) {
    let inherited = srt_transport::current_cpu_spec().unwrap_or_default();
    for cell in cells {
        if recv_cpus.is_empty() && send_cpus.is_empty() {
            if !inherited.is_empty() {
                cell.push(("cpus", Scope::Both, inherited.clone()));
            }
            continue;
        }
        cell.push((
            "cpus",
            Scope::Recv,
            if recv_cpus.is_empty() {
                inherited.clone()
            } else {
                recv_cpus.to_string()
            },
        ));
        cell.push((
            "cpus",
            Scope::Send,
            if send_cpus.is_empty() {
                inherited.clone()
            } else {
                send_cpus.to_string()
            },
        ));
    }
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
                let _ = tx.send(true);
            }
        }
        // EOF without the marker means the listener is already gone.
        // Report that immediately instead of making the whole sweep sit
        // out the timeout once per dead cell.
        if !announced {
            let _ = tx.send(false);
        }
    });
    rx.recv_timeout(timeout).unwrap_or(false)
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
        Axis, COLUMNS, Cell, MatrixOrder, Record, Scope, attempt_id, axis_overrides,
        build_matrix_schedule, cell_key, filter_matrix_cells, filter_reason,
        filtered_cartesian_cells, interleave_indices, matrix_cell_argv, matrix_cell_config,
        read_results, record_key, recorded_as, recorded_roles, resolve_matrix_axes, shuffle,
    };
    use crate::Cli;
    use std::path::PathBuf;

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

    fn temp_tsv(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "srt-bench-{name}-{}-{}.tsv",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn set_field(fields: &mut [(String, String)], key: &str, value: impl Into<String>) {
        let (_, slot) = fields
            .iter_mut()
            .find(|(field, _)| field == key)
            .unwrap_or_else(|| panic!("unknown result column {key}"));
        *slot = value.into();
    }

    fn record_for(cell: &Cell<'_>, role: &str, rep: usize) -> Record {
        let mut fields = COLUMNS
            .iter()
            .map(|column| ((*column).to_string(), String::new()))
            .collect::<Vec<_>>();
        set_field(&mut fields, "role", role);
        set_field(&mut fields, "rep", rep.to_string());
        for (axis, scope, value) in cell {
            let (column, value) = recorded_as(axis, value);
            set_field(&mut fields, &format!("{}{column}", scope.prefix()), value);
        }
        Record { fields }
    }

    fn write_records(path: &std::path::Path, records: &[Record]) {
        let mut text = format!("{}\n", COLUMNS.join("\t"));
        for record in records {
            text.push_str(
                &COLUMNS
                    .iter()
                    .map(|column| record.get(column).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("\t"),
            );
            text.push('\n');
        }
        std::fs::write(path, text).unwrap();
    }

    fn schedule_cells() -> Vec<Cell<'static>> {
        vec![
            cell(&[
                ("runtime", "mio"),
                ("connections", "1"),
                ("link-delay", "off"),
            ]),
            cell(&[
                ("runtime", "tokio"),
                ("connections", "2"),
                ("link-delay", "off"),
            ]),
        ]
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
    fn shared_egress_now_exercises_connect_concurrency() {
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
            None,
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
    fn bonded_cc_below_2_is_rejected() {
        let axes = vec![
            (
                "connect-concurrency",
                Scope::Both,
                ["1", "50"].into_iter().map(str::to_string).collect(),
            ),
            (
                "bond",
                Scope::Both,
                ["none", "broadcast:4"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            (
                "egress",
                Scope::Both,
                ["shared-socket"].into_iter().map(str::to_string).collect(),
            ),
            (
                "ingress",
                Scope::Both,
                ["shared-pool:1"].into_iter().map(str::to_string).collect(),
            ),
        ];
        assert_eq!(
            filter_reason(
                &cell(&[
                    ("egress", "shared-socket"),
                    ("ingress", "shared-pool:1"),
                    ("bond", "broadcast:4"),
                    ("connect-concurrency", "1"),
                ]),
                &axes,
            ),
            Some("bonded-cc-requires-2"),
        );
        assert_eq!(
            filter_reason(
                &cell(&[
                    ("egress", "shared-socket"),
                    ("ingress", "shared-pool:1"),
                    ("bond", "broadcast:4"),
                    ("connect-concurrency", "50"),
                ]),
                &axes,
            ),
            None,
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

    #[test]
    fn matrix_schedule_covers_each_cell_and_rep_once() {
        let cells = schedule_cells();
        let path = temp_tsv("schedule");

        let default =
            build_matrix_schedule(&cells, &[], 2, MatrixOrder::Default, 0, &path).unwrap();
        assert_eq!(default.total, 4);
        assert_eq!(default.runs, [(0, 1), (0, 2), (1, 1), (1, 2)]);
        assert!(default.done.is_empty());

        let axes = vec![(
            "runtime",
            Scope::Both,
            ["mio", "tokio"].into_iter().map(str::to_string).collect(),
        )];
        let interleaved =
            build_matrix_schedule(&cells, &axes, 2, MatrixOrder::Interleaved, 0, &path).unwrap();
        let expected = [(0, 1), (0, 2), (1, 1), (1, 2)]
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(interleaved.runs.len(), expected.len());
        assert_eq!(
            interleaved
                .runs
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>(),
            expected
        );

        let random_a =
            build_matrix_schedule(&cells, &axes, 2, MatrixOrder::Random, 7, &path).unwrap();
        let random_b =
            build_matrix_schedule(&cells, &axes, 2, MatrixOrder::Random, 7, &path).unwrap();
        assert_eq!(random_a.runs, random_b.runs);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn matrix_resume_requires_both_roles_and_round_trips_cell_identity() {
        let cells = schedule_cells();
        let path = temp_tsv("resume");
        let listener = record_for(&cells[0], "listener", 1);
        let caller = record_for(&cells[0], "caller", 1);
        assert_eq!(
            record_key(&listener, &cells[0], 1),
            Some(cell_key(&cells[0], 1))
        );
        write_records(&path, &[listener, caller]);

        let schedule =
            build_matrix_schedule(&cells, &[], 2, MatrixOrder::Default, 0, &path).unwrap();
        assert!(schedule.done.contains(&cell_key(&cells[0], 1)));
        assert!(!schedule.done.contains(&cell_key(&cells[0], 2)));
        assert!(!schedule.done.contains(&cell_key(&cells[1], 1)));

        let orphan_path = temp_tsv("resume-orphan");
        write_records(&orphan_path, &[record_for(&cells[0], "caller", 1)]);
        let orphaned =
            build_matrix_schedule(&cells, &[], 2, MatrixOrder::Default, 0, &orphan_path).unwrap();
        assert!(orphaned.done.is_empty());
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(orphan_path);
    }

    #[test]
    fn attempt_nonce_keeps_stale_partial_rows_out_of_a_new_run() {
        let cells = schedule_cells();
        let path = temp_tsv("attempt-nonce");
        let old_attempt = attempt_id("old-invocation-nonce", 0);
        let new_attempt = attempt_id("new-invocation-nonce", 0);
        let mut listener = record_for(&cells[0], "listener", 1);
        let mut caller = record_for(&cells[0], "caller", 1);
        set_field(&mut listener.fields, "attempt", old_attempt.clone());
        set_field(&mut caller.fields, "attempt", new_attempt.clone());
        write_records(&path, &[listener, caller]);

        assert_eq!(
            recorded_roles(&path, &cells[0], 1, &new_attempt).unwrap(),
            (true, false),
            "rows from a previous invocation nonce must not satisfy a new attempt"
        );
        assert_eq!(
            recorded_roles(&path, &cells[0], 1, &old_attempt).unwrap(),
            (false, true)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn matrix_cell_config_and_argv_keep_role_split_explicit() {
        let cell = vec![
            ("runtime", Scope::Recv, "tokio".to_string()),
            ("runtime", Scope::Send, "mio".to_string()),
            ("ingress", Scope::Recv, "shared-pool:4".to_string()),
            ("ingress", Scope::Send, "per-port".to_string()),
            ("workers", Scope::Recv, "2".to_string()),
            ("workers", Scope::Send, "3".to_string()),
            ("connections", Scope::Both, "4".to_string()),
            ("bitrate", Scope::Both, "1000000".to_string()),
        ];
        let config = matrix_cell_config(&cell);
        assert_eq!(config.recv_ingress, "shared-pool:4");
        assert_eq!(config.send_ingress, "per-port");
        assert_eq!(config.recv_runtime, "tokio");
        assert_eq!(config.send_runtime, "mio");
        assert_eq!(config.source_bitrate, "1000000");
        assert_eq!(config.ports_needed, 4);

        assert_eq!(
            matrix_cell_argv(&cell, Scope::Recv),
            [
                "--ingress=shared-pool:4",
                "--workers=2",
                "--connections=4",
                "--recv-runtime=tokio",
                "--send-runtime=mio",
                "--recv-ingress=shared-pool:4",
                "--send-ingress=per-port",
                "--recv-workers=2",
                "--send-workers=3",
            ]
        );
    }

    #[test]
    fn matrix_plan_overrides_and_scopes_axes() {
        let path = temp_tsv("plan");
        std::fs::write(
            &path,
            "runtime=mio,tokio\n[recv]\nworkers=2,4\ncpus=0-1\n[send]\nworkers=3\ncpus=2-3\n",
        )
        .unwrap();
        let plan_path = path.to_str().unwrap();
        let config = resolve_matrix_axes(&cli(&[
            "--plan",
            plan_path,
            "--axis",
            "runtime=smol",
            "--axis",
            "datapath-q-horizon-ms=100,200",
            "--axis",
            "retry-horizon-ms=75",
        ]))
        .unwrap();
        assert_eq!(
            config.axes[0],
            ("runtime", Scope::Both, vec!["smol".to_string()])
        );
        assert_eq!(
            config.axes[1],
            (
                "workers",
                Scope::Recv,
                vec!["2".to_string(), "4".to_string()]
            )
        );
        assert_eq!(
            config.axes[2],
            ("workers", Scope::Send, vec!["3".to_string()])
        );
        assert_eq!(config.recv_cpus, "0-1");
        assert_eq!(config.send_cpus, "2-3");
        assert_eq!(
            config
                .axes
                .iter()
                .find(|(name, _, _)| *name == "datapath-queue-horizon-ms")
                .unwrap()
                .2,
            ["100", "200"]
        );
        assert_eq!(
            config
                .axes
                .iter()
                .find(|(name, _, _)| *name == "outbound-retry-horizon-ms")
                .unwrap()
                .2,
            ["75"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn scoped_cpu_sets_are_part_of_recorded_cell_identity() {
        let cell = vec![
            ("runtime", Scope::Both, "mio".to_string()),
            ("cpus", Scope::Recv, "0-1".to_string()),
            ("cpus", Scope::Send, "2-3".to_string()),
        ];
        let record = record_for(&cell, "caller", 1);
        assert_eq!(record_key(&record, &cell, 1), Some(cell_key(&cell, 1)));

        let mut changed = cell.clone();
        changed[2].2 = "4-5".to_string();
        assert_ne!(
            record_key(&record, &changed, 1),
            Some(cell_key(&changed, 1))
        );
        assert_eq!(
            matrix_cell_argv(&cell, Scope::Recv),
            ["--recv-cpus=0-1", "--send-cpus=2-3"]
        );
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
            ("source_bps", "8000000"),
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
        // Against the SOURCE target (payload denominator, not wire):
        // 2029411 / (400 * (8e6/8) * 10 / 1316) = 66.8%
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
