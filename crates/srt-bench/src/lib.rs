//! Shared helpers for the srt-bench bench-caller/bench-listener binaries.

pub mod cpu_stats;
pub mod driver;
pub mod harness;
pub mod shutdown;
pub mod system;

pub use srt_transport::is_ordered_close;
pub mod runtimes;

pub const INTEROP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

// --- Shared constants across all bench-caller/bench-listener binaries ---

pub const PAYLOAD_SIZE: usize = 1316;
pub const DEFAULT_BITRATE_BPS: u64 = 8_000_000;
pub const MAX_WAIT: std::time::Duration = std::time::Duration::from_millis(20);
pub const TAIL_SPIN: std::time::Duration = std::time::Duration::from_micros(300);

/// Convert an `Instant` (session start) to an SRT `Timestamp`.
#[inline]
pub fn now_ts(start: std::time::Instant) -> shiguredo_srt::Timestamp {
    shiguredo_srt::Timestamp::from_micros(start.elapsed().as_micros() as u64)
}

/// Parsed CLI: positional arguments plus `--flag value` pairs.
///
/// Flag values are consumed even when they don't start with `--`, so
/// `--connections 4` never leaks `4` into the positionals (a bug that
/// silently corrupted `bitrate_bps`/`host` in hand-rolled parsers).
#[derive(Default)]
pub struct Cli {
    pub positional: Vec<String>,
    pub flags: std::collections::HashMap<String, String>,
}

impl Cli {
    /// Parse `args[1..]`.
    ///
    /// Accepts both `--flag value` / `--flag=value` and `key=value`.
    /// Flag values are consumed even when they don't start with `--`,
    /// so `connections 4` never leaks `4` into the positionals.
    pub fn parse(args: &[String]) -> Self {
        let mut cli = Cli::default();
        let mut i = 1.min(args.len());
        while i < args.len() {
            let tok = &args[i];
            if let Some(flag) = tok.strip_prefix("--") {
                if let Some((f, v)) = flag.split_once('=') {
                    cli.flags.insert(f.to_string(), v.to_string());
                } else {
                    // Value = next token unless it's another flag/kv pair.
                    let value = match args.get(i + 1) {
                        Some(next) if !next.starts_with("--") && !next.contains('=') => {
                            i += 1;
                            next.clone()
                        }
                        _ => String::new(),
                    };
                    cli.flags.insert(flag.to_string(), value);
                }
            } else if let Some((f, v)) = tok.split_once('=') {
                cli.flags.insert(f.to_string(), v.to_string());
            } else {
                cli.positional.push(tok.clone());
            }
            i += 1;
        }
        cli
    }

    /// Value of `--connections N` (default 1).
    pub fn connections(&self) -> usize {
        self.flags
            .get("connections")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1)
    }

    /// Value of `--<flag>` as a parsed integer, or default.
    pub fn flag_or<T: std::str::FromStr>(&self, flag: &str, default: T) -> T {
        self.flags
            .get(flag)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }
}

// ---------------------------------------------------------------------------
// Unified bench/scale driver configuration + stats (shared by all runtimes)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Runtime {
    Mio,
    Tokio,
    Smol,
    Monoio,
    Glommio,
    Compio,
}

impl Runtime {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "mio" => Self::Mio,
            "tokio" => Self::Tokio,
            "smol" => Self::Smol,
            "monoio" => Self::Monoio,
            "glommio" => Self::Glommio,
            "compio" => Self::Compio,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Mio => "mio",
            Self::Tokio => "tokio",
            Self::Smol => "smol",
            Self::Monoio => "monoio",
            Self::Glommio => "glommio",
            Self::Compio => "compio",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Sender,
    Receiver,
}

/// Encryption mode used by one benchmark cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encryption {
    Plain,
    Aes128,
    Aes192,
    Aes256,
}

impl Encryption {
    /// Parse the spelling used by the single-run CLI and matrix axis.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "plain" => Some(Self::Plain),
            "128" => Some(Self::Aes128),
            "192" => Some(Self::Aes192),
            "256" => Some(Self::Aes256),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Aes128 => "128",
            Self::Aes192 => "192",
            Self::Aes256 => "256",
        }
    }

    /// Apply the benchmark's shared passphrase and selected AES key length.
    pub fn apply_to(self, options: &mut shiguredo_srt::ConnectionOptions) {
        let key_length = match self {
            Self::Plain => {
                options.passphrase = None;
                options.crypto_salt = None;
                options.crypto_sek = None;
                options.key_length = shiguredo_srt::KeyLength::Aes128;
                return;
            }
            Self::Aes128 => shiguredo_srt::KeyLength::Aes128,
            Self::Aes192 => shiguredo_srt::KeyLength::Aes192,
            Self::Aes256 => shiguredo_srt::KeyLength::Aes256,
        };
        options.passphrase = Some("srt-bench-encryption".to_string());
        options.key_length = key_length;
    }
}

/// Fully-parsed configuration for one bench process invocation.
#[derive(Clone, Debug)]
pub struct BenchConfig {
    pub runtime: Runtime,
    pub mode: Mode,
    pub encryption: Encryption,
    /// Sender only: destination host.
    pub host: String,
    /// Base port. Sender connects to port+i, receiver binds port+i,
    /// for connection i in 0..connections.
    pub port: u16,
    pub duration_secs: f64,
    pub latency_ms: u16,
    pub bitrate_bps: u64,
    pub connections: usize,
    /// Listener ingress topology.
    ///
    /// - `PerPort`: today's default -- each connection owns a UDP socket
    ///   on its own port; N sockets, N wakeups.
    /// - `SharedPool(K)`: K real, distinct, plainly-bound ports; each
    ///   socket stays unconnected and serves multiple peers for their
    ///   entire connection lifetime via `recv_from` + a peer-address
    ///   lookup. No SO_REUSEPORT, no promotion -- isolates the benefit of
    ///   fewer wakeups from the benefit of kernel-level demux (that's
    ///   `ReuseportMulti`'s job). Single-threaded at the default
    ///   `--workers 1`, which is what makes it that control; above 1 the
    ///   K sockets are dealt across that many OS threads, because one
    ///   thread is a hard throughput ceiling and a sender strong enough
    ///   to cross it produces a collapse rather than a legible limit.
    /// - `ReuseportMulti(K)`: one shared port via SO_REUSEPORT. K acceptor
    ///   threads each admit their kernel-hash-routed share of flows in
    ///   parallel, then promote each connection to its own connected
    ///   socket (kernel demux follows the exact 4-tuple thereafter).
    ///   Acceptor and steady-state worker are the same thread; a bonded
    ///   leg landing on a non-owner thread is shipped once via MPSC.
    /// - `ReuseportSingle { workers }`: one shared port via SO_REUSEPORT,
    ///   but only ONE acceptor thread, which admits and promotes every
    ///   connection then routes it once to one of `workers` dedicated
    ///   steady-state threads via SPSC. Unlike `ReuseportMulti`, admission
    ///   and steady-state work are on different threads even in the
    ///   common (non-bonded) case.
    pub ingress: Ingress,
    /// Sender only. `BondMode::None`: no bonding, every connection is
    /// independent. Otherwise: connections `2*g`/`2*g+1` for `g` in
    /// `0..bond_pairs` share a group id and are sent with a
    /// libsrt-compatible group extension of this type, exercising a
    /// reuseport receiver's bond-affinity handoff path. Connections at or
    /// beyond `2*bond_pairs` are ordinary, unbonded connections.
    pub bond_mode: BondMode,
    pub bond_pairs: usize,
    /// Receiver only, and only meaningful where a socket serves more than
    /// one peer at once (a `SharedPool`/`ReuseportMulti`/`ReuseportSingle`
    /// admission listener -- `PerPort` never shares a socket, so this is
    /// a no-op there). `On`: batch multiple queued datagrams into one
    /// syscall/op where the runtime supports it (`recvmmsg` for mio).
    /// `Off`: always one syscall/op per datagram, even where batching is
    /// available -- the baseline `On` should be measured against. See
    /// `Batching` for which runtimes actually have a batched path today.
    pub batching: Batching,
    /// Sender only: how many connections may be simultaneously mid-
    /// handshake (started but not yet `Connected`) at once. `1` opens
    /// them strictly sequentially -- the safe default, since a real
    /// client population doesn't arrive in the same instant, and firing
    /// every connection's INDUCTION packet back-to-back was exactly what
    /// produced an artificial "connection storm" against a reuseport
    /// listener (see mio.rs's `run_pool_acceptor` module doc). Set higher
    /// to deliberately reproduce concurrent-arrival admission behavior,
    /// including the storm pathology itself, for targeted testing.
    pub connect_concurrency: usize,
    /// Receiver only, `ReuseportMulti` only. Which connections get their
    /// own connected socket (and, on task-based runtimes, their own task)
    /// at their first `Connected` event. The modes nest:
    ///
    /// - `Never`: nothing is ever promoted; every connection is serviced
    ///   off the shared listener by peer-address dispatch, and bonded
    ///   legs stay wherever the kernel hashed them (affinity abandoned).
    ///   Diagnostic control: measures what affinity + relocation buy.
    /// - `Relocate` (the default): only a bonded leg whose group owner is
    ///   a *different* worker thread gets promoted, because physically
    ///   moving between reactors requires an fd the destination can
    ///   register. The reuseport group stays frozen at K otherwise.
    /// - `Bonded`: same as `Relocate`, plus bonded legs that already
    ///   landed on their owner are promoted locally too. Needs high
    ///   bond density to have statistical power.
    /// - `All`: everything promotes. Buys per-connection independent
    ///   scheduling -- which only helps runtimes that actually have a
    ///   task scheduler -- and costs socket churn plus SO_REUSEPORT
    ///   group perturbation (see crates/srt-transport/tests/
    ///   reuseport_rehash.rs). Measure per runtime; do not assume.
    pub promotion: Promotion,
    /// Receiver only, `ReuseportMulti` only. Route a handshake datagram
    /// to the acceptor named by its SYN cookie when the kernel delivers
    /// it to the wrong one (see `srt_lifecycle::cookie_for_worker`).
    /// Defaults on; the switch exists so the rescue can be measured
    /// against not having it.
    pub cookie_routing: bool,
    /// SO_RCVBUF/SO_SNDBUF request for every socket, in bytes. `0` leaves
    /// the OS default alone.
    ///
    /// Exists to test a specific claim: once connections are promoted to
    /// their own sockets, the shared listener carries only handshake
    /// traffic, so its buffer should stop needing to be large. If that
    /// holds, the big buffer is load-bearing only for the non-promoting
    /// designs, and this stops being a tuning knob for the others.
    pub sock_buf_bytes: usize,
    /// Append this run's result row here as well as printing STATS. The
    /// process that has the numbers writes them, so no downstream tool
    /// has to re-parse stdout.
    pub out: Option<std::path::PathBuf>,
    /// Repetition index, recorded so a report can take medians across
    /// repeats of the same cell.
    pub rep: usize,
    /// How many logical CPUs this process ended up restricted to. `0`
    /// means the inherited affinity was left alone.
    ///
    /// Recorded in results because a benchmark that does not state its
    /// CPU budget cannot be compared against one from another machine.
    pub cpus: usize,
    /// Pin each executor to its own CPU where the runtime supports it
    /// (glommio's `Placement::Fixed`). Off by default, because pinning is
    /// a real variable: glommio and monoio are thread-per-core designs
    /// that assume it, while the others do not.
    pub pin: bool,
    /// How many OS threads the task-per-connection driver uses, each
    /// with its own executor, connections dealt round-robin between them.
    ///
    /// This exists because the load generator used to be single-threaded
    /// at every connection count, while a `reuseport-multi:4` listener
    /// got four threads. A cell that read as "the listener cannot keep
    /// up" could equally have been "the sender could not offer the load",
    /// and nothing in the results distinguished them. Applies to the
    /// sender always, and to a `PerPort` receiver -- the shared-socket
    /// ingress strategies get their parallelism from their own K instead.
    pub workers: usize,
    /// The stream length the cell asked for, in seconds, as opposed to
    /// `duration_secs`, which for a listener is the generous backstop it
    /// runs to if the harness's stop signal never arrives. Recording the
    /// backstop made a listener row say `secs=70` against the caller's
    /// `secs=10`, so anything computing a rate from a listener row got an
    /// answer 7x too small.
    pub stream_secs: f64,
    /// The role-scoped topology of the cell this process is part of,
    /// recorded (not acted on) so that one result row states the whole
    /// experiment. Empty unless the harness split that axis by role.
    ///
    /// Without this a listener row could not distinguish two cells that
    /// differ only in how the *sender* was configured, and resume would
    /// treat them as the same cell and skip one.
    pub peer_topology: PeerTopology,
    /// Emulated network conditions. Recorded by every process; only the
    /// matrix harness acts on them, and only inside a private network
    /// namespace -- an individual bench process never touches the host's
    /// networking.
    pub link: Link,
}

/// Role-scoped values for axes the harness split, as recorded in results.
#[derive(Clone, Debug, Default)]
pub struct PeerTopology {
    pub recv_runtime: String,
    pub send_runtime: String,
    pub recv_ingress: String,
    pub send_ingress: String,
    pub recv_workers: String,
    pub send_workers: String,
}

/// Link conditions to emulate, one field per `--link-*` flag. Empty means
/// "leave it alone".
///
/// Flat, one flag per knob, rather than one nested spec string: a nested
/// value needs its own separator, and the sweep axes are already
/// comma-separated, so the two collide. Flat also means each knob is
/// independently sweepable, which is the point of an axis.
#[derive(Clone, Debug, Default)]
pub struct Link {
    /// One-way latency, e.g. `25ms`. Loopback RTT is ~0, so nothing that
    /// depends on RTT estimation or on a TLPKTDROP deadline is otherwise
    /// under test.
    pub delay: String,
    /// Variation around `delay`; requires it.
    pub jitter: String,
    /// e.g. `1%`. What the whole retransmission path exists for.
    pub loss: String,
    /// A hard bottleneck, e.g. `100mbit`, to produce real queueing rather
    /// than the CPU-bound saturation loopback gives.
    pub rate: String,
    pub reorder: String,
    pub duplicate: String,
    pub corrupt: String,
    /// netem's own backlog in packets. Defaults to 100000 rather than
    /// netem's 1000, which at these packet rates would silently make
    /// netem the bottleneck and charge its drops to the protocol.
    pub limit: String,
}

impl Link {
    /// Value for one `--link-*` flag name, as the harness records it.
    #[must_use]
    pub fn get(&self, flag: &str) -> &str {
        match flag.trim_start_matches("link-") {
            "delay" => &self.delay,
            "jitter" => &self.jitter,
            "loss" => &self.loss,
            "rate" => &self.rate,
            "reorder" => &self.reorder,
            "duplicate" => &self.duplicate,
            "corrupt" => &self.corrupt,
            "limit" => &self.limit,
            _ => "",
        }
    }
}

/// See [`BenchConfig::batching`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Batching {
    On,
    Off,
}

/// Listener ingress topology. See [`BenchConfig::ingress`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    PerPort,
    SharedPool(usize),
    ReuseportMulti(usize),
    ReuseportSingle { workers: usize },
}

/// The promotion ladder is admission policy, so it lives beside
/// `WorkerRouter` in srt-lifecycle rather than here; re-exported so
/// `BenchConfig` and the runtime adapters can name it unqualified.
pub use srt_lifecycle::{Promotion, PromotionDecision};

/// Bond group type to advertise in the sender's handshake extension. See
/// [`BenchConfig::bond_mode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondMode {
    None,
    Broadcast,
    Backup,
}

/// Shared connection-routing policy: `srt_lifecycle::WorkerRouter` wrapped
/// for cross-thread use. `Ingress::ReuseportMulti` consults it only for
/// bonded legs (an unbonded connection stays wherever the kernel hashed
/// it, no routing decision or lock needed); `Ingress::ReuseportSingle`
/// routes *every* connection through it, bonded or not, which is
/// `WorkerRouter`'s exact designed purpose. `K` is the runtime's
/// peer-tuple key (`SocketAddr` for every adapter so far).
pub type SharedWorkerRouter =
    std::sync::Arc<std::sync::Mutex<srt_lifecycle::WorkerRouter<std::net::SocketAddr>>>;

impl BenchConfig {
    /// Destination/bind address for connection i.
    pub fn addr_for(&self, i: usize) -> std::net::SocketAddr {
        use std::net::{IpAddr, SocketAddr};
        let ip: IpAddr = match self.mode {
            Mode::Sender => self.host.parse().unwrap_or(IpAddr::from([127, 0, 0, 1])),
            Mode::Receiver => IpAddr::from([0, 0, 0, 0]),
        };
        let port = match self.ingress {
            // K distinct ports: the same formula on both sides, since
            // sender and receiver must independently compute the same
            // port for connection i to ever meet.
            Ingress::SharedPool(k) if k > 1 => self.port + (i % k) as u16,
            // One shared port: every connection, sender or receiver,
            // reaches/binds the single base port -- SO_REUSEPORT plus the
            // kernel hash fan the flows out on the receiver side, not the
            // address.
            Ingress::ReuseportMulti(k) if k > 1 => self.port,
            Ingress::ReuseportSingle { .. } => self.port,
            _ => self.port + i as u16,
        };
        SocketAddr::new(ip, port)
    }

    pub fn verbose(&self) -> bool {
        self.connections == 1 && self.ingress == Ingress::PerPort
    }
}

/// Per-connection outcome, widened to u64 so aggregation never overflows.
#[derive(Clone, Copy, Default)]
pub struct ConnStats {
    pub connected: bool,
    /// Ended mid-stream rather than by the sender's ordered close.
    ///
    /// A connection reaped this way still counts as `established` -- it
    /// did connect -- so without this a cell can report 400/400 while a
    /// quarter of its connections were torn down while streaming, and the
    /// only trace is a line on stderr.
    pub torn_down: bool,
    pub data_events: u64,
    pub core_total: u64,
    pub secondary_a: u64,
    pub secondary_b: u64,
    pub rtt_us: u64,
    pub has_stats: bool,
}

/// Accumulates ConnStats across connections and renders the STATS line.
/// Spread `count` indices across `threads` OS threads, round-robin, and
/// collect what each returns.
///
/// The socket-side twin of [`run_workers`], which shards *connections*.
/// A pooled listener shards its *sockets*, so it needs the same dealing
/// but over a different set.
pub fn run_shards<F>(threads: usize, count: usize, body: F) -> Vec<ConnStats>
where
    F: Fn(Vec<usize>) -> Vec<ConnStats> + Send + Sync + 'static,
{
    let threads = threads.clamp(1, count.max(1));
    let indices = |w: usize| -> Vec<usize> { (w..count).step_by(threads).collect() };
    if threads == 1 {
        return body(indices(0));
    }
    let body = std::sync::Arc::new(body);
    let handles: Vec<_> = (0..threads)
        .map(|w| {
            let (body, mine) = (std::sync::Arc::clone(&body), indices(w));
            std::thread::Builder::new()
                .name(format!("bench-pool{w}"))
                .spawn(move || body(mine))
                .expect("spawn pool shard")
        })
        .collect();
    handles
        .into_iter()
        .flat_map(|h| h.join().unwrap_or_default())
        .collect()
}

/// Dispatch a receiver's ingress strategy before falling through to the
/// PerPort path, and announce readiness once it is known that PerPort is
/// the path being taken.
///
/// All five async runtime adapters need exactly this: decide among
/// SharedPool / ReuseportMulti / ReuseportSingle, and otherwise print
/// `LISTENING` (plus the port range on stderr) before starting PerPort.
/// Only the three strategy functions differ, and they differ only because
/// each owns its own socket/executor type -- the decision itself is pure
/// `BenchConfig` inspection with nothing runtime-specific in it, so this
/// was a byte-identical 32-line block copied into all five. (mio is not
/// among them: its dispatch is shaped differently -- a `match` rather
/// than chained `if let`, with its own per-strategy sender-side
/// `eprintln!`s -- consistent with it being a different I/O model
/// throughout, not an oversight.)
///
/// Each strategy function prints its own `LISTENING` once it actually
/// starts listening, so this only prints it on the `false` (PerPort)
/// return -- the caller's cue to continue past this call rather than
/// return immediately.
pub fn dispatch_ingress(
    cfg: &BenchConfig,
    tag: &str,
    reuseport_multi: impl FnOnce(BenchConfig, usize),
    shared_pool: impl FnOnce(BenchConfig, usize),
    reuseport_single: impl FnOnce(BenchConfig, usize),
) -> bool {
    if cfg.mode == Mode::Receiver && cfg.connections > 1 {
        match cfg.ingress {
            Ingress::ReuseportMulti(k) if k > 1 => {
                reuseport_multi(cfg.clone(), k);
                return true;
            }
            Ingress::SharedPool(k) if k > 1 => {
                shared_pool(cfg.clone(), k);
                return true;
            }
            Ingress::ReuseportSingle { workers } if workers >= 1 => {
                reuseport_single(cfg.clone(), workers);
                return true;
            }
            _ => {}
        }
    }
    if cfg.mode == Mode::Receiver {
        // Before any worker starts: the harness waits on this line.
        println!("LISTENING");
        if cfg.connections > 1 {
            eprintln!(
                "[bench-{tag}] scale: ports {}-{}",
                cfg.port,
                cfg.port + cfg.connections as u16 - 1
            );
        }
    }
    false
}

/// Spread `cfg.connections` across `cfg.workers` OS threads, each running
/// `body` with the connection indices it owns, and collect every
/// connection's stats.
///
/// Round-robin (`w, w+W, w+2W, ...`) rather than contiguous blocks, so a
/// workload whose cost varies with connection index spreads evenly.
/// `workers == 1` runs inline, which keeps the single-threaded case free
/// of an extra thread and its join.
pub fn run_workers<F>(cfg: &BenchConfig, body: F) -> Vec<ConnStats>
where
    F: Fn(BenchConfig, Vec<usize>) -> Vec<ConnStats> + Send + Sync + 'static,
{
    let workers = cfg.workers.clamp(1, cfg.connections.max(1));
    let indices = |w: usize| -> Vec<usize> { (w..cfg.connections).step_by(workers).collect() };
    if workers == 1 {
        return body(cfg.clone(), indices(0));
    }
    let body = std::sync::Arc::new(body);
    let handles: Vec<_> = (0..workers)
        .map(|w| {
            let (cfg, body, mine) = (cfg.clone(), std::sync::Arc::clone(&body), indices(w));
            std::thread::Builder::new()
                .name(format!("bench-w{w}"))
                .spawn(move || body(cfg, mine))
                .expect("spawn bench worker")
        })
        .collect();
    handles
        .into_iter()
        .flat_map(|h| h.join().unwrap_or_default())
        .collect()
}

pub struct Aggregate {
    pub config: BenchConfig,
    pub data_events: u64,
    /// Connections that ended mid-stream rather than by the sender's
    /// ordered close -- see [`ConnStats::torn_down`].
    pub torn_down: u64,
    pub core_total: u64,
    pub secondary_a: u64,
    pub secondary_b: u64,
    pub rtt_sum_us: u64,
    pub stats_count: u64,
    pub any_connected: bool,
}

impl Aggregate {
    pub fn new(config: BenchConfig) -> Self {
        Self {
            config,
            data_events: 0,
            torn_down: 0,
            core_total: 0,
            secondary_a: 0,
            secondary_b: 0,
            rtt_sum_us: 0,
            stats_count: 0,
            any_connected: false,
        }
    }

    pub fn add(&mut self, s: ConnStats) {
        self.data_events += s.data_events;
        self.torn_down += u64::from(s.torn_down);
        if s.connected {
            self.any_connected = true;
        }
        if s.has_stats {
            self.core_total += s.core_total;
            self.secondary_a += s.secondary_a;
            self.secondary_b += s.secondary_b;
            self.rtt_sum_us += s.rtt_us;
            self.stats_count += 1;
        }
    }

    pub fn avg_rtt_ms(&self) -> f64 {
        if self.stats_count > 0 {
            self.rtt_sum_us as f64 / self.stats_count as f64 / 1000.0
        } else {
            0.0
        }
    }

    /// Print the STATS line. Legacy single-connection schema when
    /// connections == 1 (orchestration compat); aggregated schema otherwise.
    pub fn print(&self, start: std::time::Instant) {
        let elapsed_s = start.elapsed().as_secs_f64();
        let p = cpu_stats::process_stats();
        let c = &self.config;
        let role = match c.mode {
            Mode::Sender => "caller",
            Mode::Receiver => "listener",
        };
        let rtt = self.avg_rtt_ms();
        if c.connections == 1 {
            println!(
                "STATS role={} backend={} pkt_sent={} core_total={} sec_a={} sec_b={} \
                 rtt_ms={:.3} elapsed_s={:.3} cpu_user_ms={:.1} cpu_sys_ms={:.1} peak_rss_kb={}",
                role,
                c.runtime.name(),
                self.data_events,
                self.core_total,
                self.secondary_a,
                self.secondary_b,
                rtt,
                elapsed_s,
                p.cpu_user_ms,
                p.cpu_sys_ms,
                p.peak_rss_kb,
            );
        } else {
            // `connections` is what was *asked for*; `established` is how
            // many actually reported protocol stats. They are usually
            // equal, and when they aren't that gap is the single most
            // important number on the line -- a listener that only ever
            // admitted half the callers looks exactly like one that
            // admitted all of them and dropped half the packets, unless
            // this is printed. (It was tracked but not shown for a long
            // time, which is precisely how a partial-admission bug got
            // misread as a throughput ceiling.)
            println!(
                "STATS role={} backend={} connections={} established={} pkt_sent={} \
                 core_total={} sec_a={} sec_b={} rtt_ms={:.3} elapsed_s={:.3} \
                 throughput_pps={:.0} cpu_user_ms={:.1} cpu_sys_ms={:.1} peak_rss_kb={}",
                role,
                c.runtime.name(),
                c.connections,
                self.stats_count,
                self.data_events,
                self.core_total,
                self.secondary_a,
                self.secondary_b,
                rtt,
                elapsed_s,
                self.data_events as f64 / elapsed_s,
                p.cpu_user_ms,
                p.cpu_sys_ms,
                p.peak_rss_kb,
            );
        }
        if let Some(path) = &c.out
            && let Err(e) = crate::harness::append_result(
                path,
                c,
                c.rep,
                self.stats_count,
                self.torn_down,
                self.data_events,
                self.core_total,
                self.secondary_a,
                self.secondary_b,
                rtt,
                elapsed_s,
            )
        {
            eprintln!(
                "warning: could not append result to {}: {e}",
                path.display()
            );
        }
    }
}

/// Parse the unified CLI into a BenchConfig, exiting on bad usage.
pub fn bench_config_from_args() -> BenchConfig {
    fn usage() -> ! {
        eprintln!(
            "usage: srt-bench runtime=<mio|tokio|smol|monoio|glommio|compio> \
             mode=<sender|receiver> <host?> <port> <duration_secs> <latency_ms> \
             [bitrate_bps] [--connections N] \
             [--ingress per-port|shared-pool=K|reuseport-multi=K|reuseport-single=W] \
             [--encryption plain|128|192|256] \
             [--bond broadcast:G|backup:G|none] [--batch on|off] \
             [--connect-concurrency N] [--promotion never|relocate|bonded|all] [--cookie-routing on|off] [--sock-buf N|Nk|Nm|default] [--out FILE] [--cpus 0-3|0,2,4] [--pin on|off] [--workers N] [--link-delay 25ms] [--link-jitter 5ms] [--link-loss 1%] [--link-rate 100mbit]"
        );
        std::process::exit(2)
    }

    // The harness signals a clean stop once the sender is done; without
    // this the listener would still be stopping on its own timer.
    crate::shutdown::install();

    // Capture kernel UDP counters before any socket exists, so every
    // later read is a delta for this run alone.
    let _ = crate::cpu_stats::udp_baseline();

    let args: Vec<String> = std::env::args().collect();
    let cli = Cli::parse(&args);

    let runtime_name = cli.flags.get("runtime").cloned().unwrap_or_default();
    let runtime = match Runtime::parse(&runtime_name) {
        Some(r) => r,
        None => {
            eprintln!("missing or unknown runtime=<...>");
            usage()
        }
    };
    let mode = match cli.flags.get("mode").map(String::as_str) {
        Some("sender") => Mode::Sender,
        Some("receiver") => Mode::Receiver,
        _ => {
            eprintln!("missing or unknown mode=<sender|receiver>");
            usage()
        }
    };

    let encryption = match cli.flags.get("encryption").map(String::as_str) {
        None | Some("") | Some("plain") => Encryption::Plain,
        Some(value) => match Encryption::parse(value) {
            Some(mode) => mode,
            None => {
                eprintln!("error: unknown --encryption '{value}' (want plain|128|192|256)");
                usage()
            }
        },
    };

    let needed = match mode {
        Mode::Sender => 4,
        Mode::Receiver => 3,
    };
    if cli.positional.len() < needed {
        usage()
    }
    let mut pos = cli.positional.iter();
    let mut next_pos = || -> String { pos.next().cloned().unwrap_or_else(|| usage()) };
    let host = match mode {
        Mode::Sender => next_pos(),
        Mode::Receiver => String::new(),
    };
    let port: u16 = next_pos().parse().unwrap_or_else(|_| usage());
    let duration_secs: f64 = next_pos().parse().unwrap_or_else(|_| usage());
    let latency_ms: u16 = next_pos().parse().unwrap_or_else(|_| usage());
    let bitrate_bps: u64 = pos
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BITRATE_BPS);

    fn parse_positive(label: &str, raw: &str) -> usize {
        match raw.parse::<usize>() {
            Ok(0) | Err(_) => {
                eprintln!("error: {label} must be a positive integer (got '{raw}')");
                usage()
            }
            // Cap at a sane ceiling; more sockets/threads than
            // connections is just extra bookkeeping with no benefit.
            Ok(n) => n.min(4096),
        }
    }

    let ingress = match cli.flags.get("ingress").map(String::as_str) {
        None | Some("per-port") => Ingress::PerPort,
        Some(spec) => {
            // Accept both `shared-pool=4` and `shared-pool:4`. The colon
            // form is what result files record (an `=` inside a value
            // would collide with the key=value flag syntax), so it has to
            // parse back in for a recorded run to be reproducible.
            let spec = &spec.replacen(':', "=", 1);
            let spec = spec.as_str();
            if let Some(k) = spec.strip_prefix("shared-pool=") {
                Ingress::SharedPool(parse_positive("shared-pool size", k))
            } else if let Some(k) = spec.strip_prefix("reuseport-multi=") {
                Ingress::ReuseportMulti(parse_positive("reuseport-multi acceptor count", k))
            } else if let Some(w) = spec.strip_prefix("reuseport-single=") {
                Ingress::ReuseportSingle {
                    workers: parse_positive("reuseport-single worker count", w),
                }
            } else {
                eprintln!(
                    "error: unknown --ingress '{spec}' (want per-port | shared-pool=K | \
                     reuseport-multi=K | reuseport-single=W)"
                );
                usage()
            }
        }
    };

    let (bond_mode, bond_pairs) = match cli.flags.get("bond").map(String::as_str) {
        None | Some("none") => (BondMode::None, 0),
        Some(spec) => {
            let (kind, count) = spec.split_once(':').unwrap_or((spec, ""));
            let mode = match kind {
                "broadcast" => BondMode::Broadcast,
                "backup" => BondMode::Backup,
                _ => {
                    eprintln!("error: unknown --bond mode '{kind}' (want broadcast|backup|none)");
                    usage()
                }
            };
            (mode, parse_positive("bond pair count", count))
        }
    };

    let batching = match cli.flags.get("batch").map(String::as_str) {
        None | Some("on") => Batching::On,
        Some("off") => Batching::Off,
        Some(other) => {
            eprintln!("error: unknown --batch '{other}' (want on|off)");
            usage()
        }
    };

    let connect_concurrency = match cli.flags.get("connect-concurrency") {
        None => 1,
        Some(raw) => parse_positive("connect-concurrency", raw),
    };

    let promotion = match cli.flags.get("promotion").map(String::as_str) {
        // Bare `--promotion` parses to an empty value.
        None | Some("") | Some("relocate") => Promotion::Relocate,
        Some("never") => Promotion::Never,
        Some("bonded") => Promotion::Bonded,
        Some("all") => Promotion::All,
        Some(other) => {
            eprintln!("error: unknown --promotion '{other}' (want never|relocate|bonded|all)");
            usage()
        }
    };

    let cookie_routing = match cli.flags.get("cookie-routing").map(String::as_str) {
        None | Some("") | Some("on") => true,
        Some("off") => false,
        Some(other) => {
            eprintln!("error: unknown --cookie-routing '{other}' (want on|off)");
            usage()
        }
    };

    let sock_buf_bytes = match cli.flags.get("sock-buf").map(String::as_str) {
        None => srt_transport::SOCK_BUF_BYTES,
        Some("default") | Some("0") => 0,
        Some(raw) => {
            let (digits, scale) = match raw.strip_suffix(['m', 'M']) {
                Some(d) => (d, 1 << 20),
                None => (raw.strip_suffix(['k', 'K']).unwrap_or(raw), 1),
            };
            let scale = if digits.len() == raw.len() { 1 } else { scale };
            match digits.parse::<usize>() {
                Ok(n) => n * scale,
                Err(_) => {
                    eprintln!("error: --sock-buf wants bytes, <N>k, <N>m, or 'default'");
                    usage()
                }
            }
        }
    };

    // A CPU *set*, not a count: the two roles need disjoint cores, so
    // that giving the compute-bound side more does not hand them back to
    // the other. See docs/cpu-budget.md.
    let cpu_list =
        srt_transport::parse_cpu_spec(cli.flags.get("cpus").map(String::as_str).unwrap_or(""));
    if !cpu_list.is_empty()
        && let Err(e) = srt_transport::restrict_to_cpu_list(&cpu_list)
    {
        eprintln!("warning: could not restrict to CPUs {cpu_list:?}: {e}");
    }
    let cpus = cpu_list.len();
    let pin = matches!(
        cli.flags.get("pin").map(String::as_str),
        Some("") | Some("on")
    );

    let workers = cli.flag_or("workers", 1usize).max(1);
    let stream_secs = cli
        .flags
        .get("stream-secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(duration_secs);

    let scoped = |name: &str| -> String { cli.flags.get(name).cloned().unwrap_or_default() };
    // The harness records under the axis name (`runtime`); a human types
    // the plural flag (`--recv-runtimes`, matching `--runtimes`).
    let scoped_runtime = |name: &str, plural: &str| -> String {
        let v = scoped(name);
        if v.is_empty() { scoped(plural) } else { v }
    };
    let peer_topology = PeerTopology {
        recv_runtime: scoped_runtime("recv-runtime", "recv-runtimes"),
        send_runtime: scoped_runtime("send-runtime", "send-runtimes"),
        recv_ingress: scoped("recv-ingress"),
        send_ingress: scoped("send-ingress"),
        recv_workers: scoped("recv-workers"),
        send_workers: scoped("send-workers"),
    };

    let link_flag = |name: &str| -> String {
        cli.flags
            .get(name)
            .filter(|v| !v.is_empty() && v.as_str() != "off")
            .cloned()
            .unwrap_or_default()
    };
    let link = Link {
        delay: link_flag("link-delay"),
        jitter: link_flag("link-jitter"),
        loss: link_flag("link-loss"),
        rate: link_flag("link-rate"),
        reorder: link_flag("link-reorder"),
        duplicate: link_flag("link-duplicate"),
        corrupt: link_flag("link-corrupt"),
        limit: link_flag("link-limit"),
    };

    let out = cli
        .flags
        .get("out")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from);
    let rep = cli.flag_or("rep", 1usize);

    BenchConfig {
        runtime,
        mode,
        encryption,
        host,
        port,
        duration_secs,
        latency_ms,
        bitrate_bps,
        connections: cli.connections(),
        ingress,
        bond_mode,
        bond_pairs,
        batching,
        connect_concurrency,
        promotion,
        cookie_routing,
        sock_buf_bytes,
        out,
        rep,
        cpus,
        pin,
        workers,
        stream_secs,
        peer_topology,
        link,
    }
}

#[cfg(test)]
mod tests {
    use super::Encryption;
    use shiguredo_srt::{ConnectionOptions, KeyLength};

    #[test]
    fn encryption_axis_values_round_trip() {
        for (value, expected) in [
            ("plain", Encryption::Plain),
            ("128", Encryption::Aes128),
            ("192", Encryption::Aes192),
            ("256", Encryption::Aes256),
        ] {
            assert_eq!(Encryption::parse(value), Some(expected));
            assert_eq!(expected.name(), value);
        }
        assert_eq!(Encryption::parse("512"), None);
    }

    #[test]
    fn encryption_configures_connection_options() {
        for (mode, key_length) in [
            (Encryption::Aes128, KeyLength::Aes128),
            (Encryption::Aes192, KeyLength::Aes192),
            (Encryption::Aes256, KeyLength::Aes256),
        ] {
            let mut options = ConnectionOptions::default();
            mode.apply_to(&mut options);
            assert_eq!(options.passphrase.as_deref(), Some("srt-bench-encryption"));
            assert_eq!(options.key_length, key_length);
        }

        let mut options = ConnectionOptions::default();
        Encryption::Aes256.apply_to(&mut options);
        Encryption::Plain.apply_to(&mut options);
        assert_eq!(options.passphrase, None);
        assert_eq!(options.key_length, KeyLength::Aes128);
    }
}
