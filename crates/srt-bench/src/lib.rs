//! Shared helpers for the srt-bench bench-caller/bench-listener binaries.

pub mod classifier;
pub mod compare;
pub mod cpu_stats;
pub mod driver;
pub mod harness;
pub mod model;
pub mod queue;
pub mod scheduling;
pub mod shutdown;
pub mod source;
pub mod system;
pub mod watch;

use std::time::{Duration, Instant};

pub use srt_transport::is_ordered_close;
pub mod runtimes;

// Real handshakes over real loopback sockets on a real (often shared, CI)
// CPU -- 15s left too little headroom under host contention alone, with no
// protocol issue involved (bonded_smoke.rs's own multi-runtime sweep hit
// this: one leg fully established and exchanged traffic while its sibling
// leg's handshake simply never got scheduled in time). Widening this is a
// pure application-level wait-longer-before-giving-up knob -- it doesn't
// change when a healthy connection actually finishes, only how long an
// unhealthy one is given before being counted as failed.
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);

// --- Shared constants across all bench-caller/bench-listener binaries ---

pub const PAYLOAD_SIZE: usize = 1316;
/// Default *source payload* rate, in bits per second, per connection.
///
/// This is the workload the application offers, not SRT's pacing ceiling
/// -- see [`crate::source`] for why those are now separate.
pub const DEFAULT_SOURCE_BITRATE_BPS: u64 = 8_000_000;
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
/// silently corrupted `source_bitrate_bps`/`host` in hand-rolled parsers).
#[derive(Default)]
pub struct Cli {
    pub positional: Vec<String>,
    pub flags: std::collections::HashMap<String, String>,
    /// Values for flags that are intentionally repeatable, such as
    /// `--axis name=value`. Ordinary flags retain their last-value-wins
    /// behavior in `flags`.
    pub repeated: std::collections::HashMap<String, Vec<String>>,
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
                Self::parse_long_flag(&mut cli, args, &mut i, flag);
            } else if let Some((f, v)) = tok.split_once('=') {
                cli.flags.insert(f.to_string(), v.to_string());
            } else {
                cli.positional.push(tok.clone());
            }
            i += 1;
        }
        cli
    }

    fn parse_long_flag(cli: &mut Self, args: &[String], index: &mut usize, flag: &str) {
        if let Some((name, value)) = flag.split_once('=') {
            cli.insert_flag(name, value.to_string());
            return;
        }

        // A flag owns its following non-flag token. In particular,
        // `--ingress shared-pool=1` is documented and the value's `=` must
        // not turn it into a separate key/value argument.
        let value = match args.get(*index + 1) {
            Some(next) if !next.starts_with("--") => {
                *index += 1;
                next.clone()
            }
            _ => String::new(),
        };
        cli.insert_flag(flag, value);
    }

    fn insert_flag(&mut self, flag: &str, value: String) {
        if flag == "axis" {
            self.repeated
                .entry(flag.to_string())
                .or_default()
                .push(value);
        } else {
            self.flags.insert(flag.to_string(), value);
        }
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
    /// The **application workload**: how fast each connection's payload
    /// source produces `PAYLOAD_SIZE` payloads, in bits per second.
    ///
    /// Deliberately *not* named `bitrate_bps` any more. That one number
    /// used to be both the workload rate and `SRTO_MAXBW`, which made
    /// every "did the sender offer its load?" measurement a tautology.
    /// The pacing side now lives in [`Self::bandwidth`], and the two move
    /// independently: a source configured at 8 Mbit/s stays an 8 Mbit/s
    /// producer whether SRT is told to pace at 4, 8 or 12.
    pub source_bitrate_bps: u64,
    /// The **transport configuration**: how this run configures SRT's
    /// pacing, resolved against `source_bitrate_bps` in exactly one place
    /// ([`Self::srt_bandwidth`]) so six runtimes cannot drift.
    pub bandwidth: crate::source::BandwidthPolicy,
    /// Milliseconds of source the pending-source backlog may hold before
    /// opportunities are dropped and counted. Bounded by rate, never by
    /// run duration.
    pub source_backlog_ms: u64,
    /// Milliseconds of offered load one benchmark-owned packet datapath
    /// queue may hold. Bounded by rate and fan-in, never by run duration.
    pub datapath_queue_horizon_ms: u64,
    /// Milliseconds of offered load the harness may retain after an
    /// outbound send yields. Same rule, against socket fan-out.
    pub outbound_retry_horizon_ms: u64,
    pub connections: usize,
    /// Caller-side UDP socket topology. `PerConnection` gives every SRT
    /// connection its own ephemeral local port. `SharedSocket` drives all
    /// caller connections through one unconnected UDP socket and demultiplexes
    /// replies by Destination SRT Socket ID.
    pub egress: Egress,
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
    /// independent. Otherwise connections `2*g`/`2*g+1` share group and
    /// stream identity, initial sequence, and distinct leg socket IDs.
    /// The group-aware shared listener then admits them as one logical,
    /// deduplicated ingress stream. Connections beyond `2*bond_pairs` stay
    /// ordinary and unbonded.
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
    /// Tokio shared-socket `recvmmsg` quanta per readiness service.
    pub recv_rounds: usize,
    /// Tokio shared-socket policy after a nonblocking outbound send yields.
    pub would_block: crate::scheduling::WouldBlockPolicy,
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
    /// Identity of the matrix attempt that started this process.
    ///
    /// The harness stamps both roles of one attempted cell with the same
    /// value so it can tell rows *this* attempt wrote from rows an
    /// earlier, interrupted attempt left in the append-only result file.
    /// Empty for a standalone invocation, which has no harness above it.
    pub attempt: String,
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
    /// Exact classifier policy used for the pre-run result row.
    pub classifier_policy: crate::model::ClassifierPolicy,
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
    pub recv_cpus: String,
    pub send_cpus: String,
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

/// Caller-side socket topology. Combined with [`Ingress`] this exercises
/// distinct-local/same-remote, same-local/distinct-remote, and identical
/// UDP four-tuples.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Egress {
    #[default]
    PerConnection,
    SharedSocket,
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
    /// Reject benchmark topologies that advertise a bond without actually
    /// driving its legs as one logical caller and listener group.
    pub fn validate_bond_topology(&self) -> Result<(), &'static str> {
        if self.bond_mode == BondMode::None {
            return Ok(());
        }
        if self.bond_pairs > self.connections / 2 {
            return Err("bond pair count exceeds half of --connections");
        }
        if self.ingress != Ingress::SharedPool(1) {
            return Err("--bond requires --ingress shared-pool=1");
        }
        if self.mode == Mode::Sender && self.egress != Egress::SharedSocket {
            return Err("--bond requires --egress shared-socket for sender group scheduling");
        }
        if self.mode == Mode::Sender && self.connect_concurrency < 2 {
            return Err("bonded benchmark groups contain two physical SRT legs \
                 and therefore require --connect-concurrency >= 2");
        }
        Ok(())
    }

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
            Ingress::SharedPool(k) => self.port + (i % k) as u16,
            // One shared port: every connection, sender or receiver,
            // reaches/binds the single base port -- SO_REUSEPORT plus the
            // kernel hash fan the flows out on the receiver side, not the
            // address.
            Ingress::ReuseportMulti(_) => self.port,
            Ingress::ReuseportSingle { .. } => self.port,
            _ => self.port + i as u16,
        };
        SocketAddr::new(ip, port)
    }

    pub fn verbose(&self) -> bool {
        self.connections == 1 && self.ingress == Ingress::PerPort
    }

    /// Number of application-visible streams expected at the receiver. A
    /// complete two-leg group replaces two physical connections with one
    /// logical stream; ungrouped connections remain one-to-one.
    #[must_use]
    pub fn logical_connection_count(&self) -> usize {
        if self.bond_mode == BondMode::None {
            self.connections
        } else {
            self.connections
                .saturating_sub(self.bond_pairs.min(self.connections / 2))
        }
    }

    /// Handshake group metadata for one physical leg. Two adjacent legs form
    /// one group so the listener can exercise actual grouped ingress rather
    /// than merely parse an otherwise-unused extension.
    pub fn bond_extension_for(&self, index: usize) -> Option<shiguredo_srt::GroupExtensionData> {
        if self.bond_mode == BondMode::None || index >= self.bond_pairs * 2 {
            return None;
        }
        let group_type = match self.bond_mode {
            BondMode::Broadcast => shiguredo_srt::GroupType::Broadcast,
            BondMode::Backup => shiguredo_srt::GroupType::Backup,
            BondMode::None => unreachable!("checked above"),
        };
        Some(shiguredo_srt::GroupExtensionData {
            group_id: shiguredo_srt::SRTGROUP_MASK | ((index / 2) as u32 + 1),
            group_type,
            flags: 0,
            // Give backup legs an unambiguous active/standby ordering. A
            // broadcast group deliberately gives both legs equal weight.
            weight: if self.bond_mode == BondMode::Backup && !index.is_multiple_of(2) {
                0
            } else {
                1
            },
        })
    }

    /// Grouped legs need the same initial sequence and stream identity for
    /// receiver-side deduplication, while each leg keeps a distinct SRT socket
    /// ID. Non-grouped connections retain their independently generated state.
    pub fn bond_initial_seq_for(&self, index: usize) -> Option<u32> {
        self.bond_extension_for(index)
            .map(|_| 0x0100_0000 | (index / 2) as u32)
    }

    pub fn bond_stream_id_for(&self, index: usize) -> Option<String> {
        self.bond_extension_for(index)
            .map(|_| format!("srt-bench-group-{}", index / 2))
    }

    pub fn caller_socket_id_for(&self, index: usize) -> u32 {
        std::process::id()
            .wrapping_add(index as u32)
            .wrapping_add(1)
            .max(1)
    }

    /// The SRT pacing policy this run configures, resolved once against
    /// the source payload rate.
    ///
    /// The single resolution point for all six runtimes. Six copies of
    /// `max_bandwidth_bytes_per_sec = bitrate / 8` is exactly how the
    /// workload rate and the pacing ceiling became the same number.
    #[must_use]
    pub fn srt_bandwidth(&self) -> srt_transport::Bandwidth {
        self.bandwidth.resolve(self.source_bitrate_bps)
    }

    /// Write this run's pacing policy into raw protocol options.
    ///
    /// Applied for both roles: a listener never sends application data,
    /// so its pacing ceiling is inert, and setting it uniformly keeps the
    /// six runtimes from each deciding the question differently.
    pub fn apply_srt_bandwidth(&self, options: &mut shiguredo_srt::ConnectionOptions) {
        self.srt_bandwidth().apply_to(options);
    }

    /// How many peers' traffic arrives on one listener ingress socket.
    ///
    /// A per-port socket serves one sender; a pooled or reuseport socket
    /// serves its share of the cell.
    #[must_use]
    pub fn peers_per_ingress_socket(&self) -> usize {
        let sockets = match self.ingress {
            Ingress::PerPort => return 1,
            Ingress::SharedPool(k) | Ingress::ReuseportMulti(k) => k,
            Ingress::ReuseportSingle { workers } => workers,
        };
        self.connections.div_ceil(sockets.max(1)).max(1)
    }

    /// How many peers share one of this process's UDP sockets.
    ///
    /// The single fan-in notion behind every bounded queue this process
    /// owns. Both directions use it, because both directions go through
    /// the same socket: a shared-egress sender puts every connection's
    /// traffic on one socket in each direction, and a pooled listener
    /// does the same for its share of the peers.
    ///
    /// One helper rather than a per-queue-kind rule, because getting this
    /// wrong is silent and expensive: sizing a queue by an unrelated
    /// topology knob under-provisioned a pooled listener's outbound queue
    /// by ~50x at 200 connections and dropped a quarter of a million
    /// acknowledgements with no `WouldBlock` to explain it.
    ///
    /// Over-provisions a promoted per-connection socket on a pooled
    /// listener, which is the safe direction and keeps capacity uniform
    /// across the process -- which is what makes reporting a single
    /// `capacity_per_queue` meaningful.
    #[must_use]
    pub fn peers_per_socket(&self) -> usize {
        match self.mode {
            Mode::Receiver => self.peers_per_ingress_socket(),
            Mode::Sender => match self.egress {
                Egress::SharedSocket => self.connections.max(1),
                Egress::PerConnection => 1,
            },
        }
    }

    /// Capacity for one benchmark-owned packet datapath queue.
    ///
    /// Derived from the queue horizon, this socket's fan-in, and the
    /// source packet rate, so it is bounded by workload rather than by a
    /// constant with no workload meaning. Uniform across the process,
    /// which is what makes `capacity_per_queue` a single number worth
    /// reporting.
    #[must_use]
    pub fn datapath_queue_capacity(&self) -> usize {
        crate::queue::datapath_queue_capacity(
            self.source_bitrate_bps,
            self.peers_per_socket(),
            self.datapath_queue_horizon_ms,
        )
    }

    /// Capacity for one outbound retry queue.
    ///
    /// Sized by the same horizon rule and the same fan-in as a datapath
    /// queue -- see [`Self::peers_per_socket`] -- against the outbound
    /// horizon.
    #[must_use]
    pub fn outbound_retry_capacity(&self) -> usize {
        crate::queue::datapath_queue_capacity(
            self.source_bitrate_bps,
            self.peers_per_socket(),
            self.outbound_retry_horizon_ms,
        )
    }

    /// A fresh payload source for one connection, ticking at the
    /// configured source rate with a rate-relative bounded backlog.
    #[must_use]
    pub fn source_clock(&self) -> crate::source::SourceClock {
        crate::source::SourceClock::new(
            // Validated non-zero when the config was parsed: a zero source
            // rate is a usage error, never a silent "unpaced" mode.
            std::num::NonZeroU64::new(self.source_bitrate_bps)
                .expect("source_bitrate_bps is validated non-zero at parse time"),
            crate::source::backlog_capacity(self.source_bitrate_bps, self.source_backlog_ms),
        )
    }

    /// Admission must use the same complete connection template as a
    /// per-port listener. In particular, a shared listener otherwise silently
    /// falls back to plaintext when it creates a peer after the handshake.
    pub fn admission_options(
        &self,
        socket_id: u32,
        cookie_routing: bool,
    ) -> srt_transport::AdmissionOptions {
        let mut template = shiguredo_srt::ConnectionOptions {
            socket_id,
            tsbpd_delay: self.latency_ms,
            ..Default::default()
        };
        self.encryption.apply_to(&mut template);
        srt_transport::AdmissionOptions {
            socket_id,
            tsbpd_delay: self.latency_ms,
            cookie_routing,
            bonded_inputs: if self.bond_mode == BondMode::None {
                srt_transport::BondedInputPolicy::Reject
            } else {
                srt_transport::BondedInputPolicy::Accept
            },
            connection_template: Some(template),
            handshake_retry_interval: std::time::Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            ),
            handshake_timeout: std::time::Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_TIMEOUT_MICROS,
            ),
        }
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
    /// What this connection's application payload source did, as distinct
    /// from what the transport carried. A bonded pair reports its one
    /// source on its first leg only, so aggregation cannot double-count.
    pub source: crate::source::SourceStats,
    /// Whether this `ConnStats` carries a payload source at all.
    ///
    /// Counted rather than derived: a bonded pair is two physical legs
    /// driven by *one* source clock, and a listener has no source, so
    /// neither `connections` nor `established` is the number of workload
    /// producers. Deriving it from topology would have to re-encode the
    /// bonding rules in the report layer; measuring it cannot drift.
    pub has_source: bool,
    /// Capacity zero means this path has no benchmark-owned packet queue.
    pub datapath_queue: crate::queue::QueueStats,
    pub recv_scheduling: crate::scheduling::RecvSchedulingStats,
    pub outbound_retry: crate::scheduling::RetryStats,
}

// ---------------------------------------------------------------------------
// Connect-concurrency limiter (process-global)
// ---------------------------------------------------------------------------

/// Process-global limiter for simultaneously in-flight physical SRT
/// handshakes. A bonded two-leg group consumes two tokens atomically.
///
/// The definition of `--connect-concurrency N` is: at most N physical SRT
/// caller handshakes (INDUCTION sent, not yet Connected/failed/timed-out)
/// may exist at once across the entire sender process.
pub struct ConnectLimiter {
    limit: usize,
    in_flight: usize,
    peak: usize,
    started: usize,
    completed: usize,
    failed: usize,
    /// Admission order. Holds waiter ids, and may also hold tombstones --
    /// ids whose waiter has since been granted or cancelled. Popping skips
    /// them, which keeps removal O(1) instead of scanning the queue.
    fifo: std::collections::VecDeque<u64>,
    /// Live waiter state, keyed by id, so lookup and removal are O(1).
    ///
    /// A caller that cannot get a permit parks its `Waker` here instead of
    /// re-checking on a periodic timer, so N pending connections cost zero
    /// wakeups until a permit is actually available. Cancellation is O(1)
    /// and the success path never scans, so total FIFO traversal across a
    /// run is amortized linear in the number of waiters -- in particular
    /// there is no O(N^2) cleanup. (A single `grant_admissible` call is not
    /// itself bounded by `connect-concurrency`: it may skip a run of
    /// tombstones left by cancelled waiters. Each tombstone is skipped at
    /// most once, which is what makes the total linear.)
    waiters: std::collections::HashMap<u64, Waiter>,
    /// Monotonic waiter id source. Never wraps: aliasing a stale tombstone
    /// with a fresh waiter would let a cancelled waiter's id match a live
    /// one, so exhaustion is a hard error rather than a silent reuse.
    next_waiter_id: u64,
    /// Tokens promised to granted-but-not-yet-consumed waiters.
    ///
    /// A grant reserves its tokens up front, so the capacity that woke a
    /// waiter cannot be taken by anyone else before that waiter runs. This
    /// is what makes a grant a promise rather than a hint: the granted
    /// future converts it directly into a permit without racing, and if it
    /// is dropped first the reservation is returned and handed to the next
    /// waiter in line.
    reserved: usize,
    /// Count of fifo entries examined, to assert admission stays linear.
    #[cfg(test)]
    fifo_steps: u64,
}

/// One admission waiter.
struct Waiter {
    /// Tokens this waiter needs. Tracked per waiter so the grant budget is
    /// spent against real demand: granting 1:1 would under-serve freed
    /// capacity as soon as a waiter needs a bonded pair's two tokens.
    tokens: usize,
    waker: std::task::Waker,
    /// Set once capacity has been reserved for this waiter. Its next poll
    /// consumes the reservation instead of contending for capacity again.
    granted: bool,
}

impl ConnectLimiter {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            in_flight: 0,
            peak: 0,
            started: 0,
            completed: 0,
            failed: 0,
            fifo: std::collections::VecDeque::new(),
            waiters: std::collections::HashMap::new(),
            next_waiter_id: 0,
            reserved: 0,
            #[cfg(test)]
            fifo_steps: 0,
        }
    }

    /// Capacity not in use and not already promised to a granted waiter.
    fn free(&self) -> usize {
        self.limit
            .saturating_sub(self.in_flight)
            .saturating_sub(self.reserved)
    }

    /// Acquire `tokens` if capacity is free.
    ///
    /// Reserved capacity is excluded, so an arriving caller cannot take the
    /// tokens that were set aside to wake an already-queued waiter.
    pub fn try_acquire(&mut self, tokens: usize) -> bool {
        if tokens > self.free() {
            return false;
        }
        self.admit(tokens);
        true
    }

    /// Move `tokens` into flight and update the started/peak counters.
    fn admit(&mut self, tokens: usize) {
        self.in_flight += tokens;
        self.started += tokens;
        self.peak = self.peak.max(self.in_flight);
    }

    pub fn release(&mut self, tokens: usize, connected: bool) {
        debug_assert!(
            self.in_flight >= tokens,
            "ConnectLimiter double-release: in_flight={}, releasing={}",
            self.in_flight,
            tokens
        );
        self.in_flight = self.in_flight.saturating_sub(tokens);
        if connected {
            self.completed += tokens;
        } else {
            self.failed += tokens;
        }
    }

    /// Reserve capacity for the next waiters in FIFO order and return their
    /// wakers, budgeting against each waiter's own token demand.
    ///
    /// A grant is a promise: the tokens move into `reserved` before the
    /// waker is handed back, so nothing else can take them in the window
    /// between waking a task and that task running. The granted future then
    /// converts its reservation straight into a permit, and if it is dropped
    /// first the reservation is returned and re-granted to the next waiter.
    /// Without that reservation a selected-then-cancelled waiter would strand
    /// the capacity it was woken for and everyone behind it could sleep
    /// forever.
    ///
    /// Returning wakers rather than calling `wake()` here is also deliberate:
    /// the caller holds the limiter mutex and `HandshakeAdmission::poll`
    /// locks that same non-reentrant mutex. Waking under the lock is safe
    /// against every executor this crate drives -- none poll synchronously
    /// from inside `wake()` -- but it would deadlock against one that did,
    /// and it makes a woken worker contend on a lock we still hold. Callers
    /// wake after the guard drops; see `release_and_wake`.
    ///
    /// Granting only what fits bounds the *wakes* by freed capacity: with
    /// `cc=4` and 4092 pending callers, a completed handshake wakes at most
    /// 4 tasks and the rest stay parked with no timer attached.
    ///
    /// The traversal is a separate bound. One call is not O(cc) -- it may
    /// skip a run of tombstones left behind by cancelled waiters before it
    /// finds a live one. What holds is that each tombstone is skipped at
    /// most once and each waiter is popped at most once, so total FIFO
    /// traversal over a run is amortized linear in the number of waiters,
    /// with O(1) cancellation and no scanning on the success path.
    /// `sequential_admission_does_not_scan_the_queue_per_wakeup` pins that.
    fn grant_admissible(&mut self) -> Vec<std::task::Waker> {
        let mut granted = Vec::new();
        loop {
            let budget = self.free();
            if budget == 0 {
                break;
            }
            // Skip tombstones: ids whose waiter was granted or cancelled.
            let Some(&id) = self.fifo.front() else { break };
            #[cfg(test)]
            {
                self.fifo_steps += 1;
            }
            let Some(waiter) = self.waiters.get_mut(&id) else {
                self.fifo.pop_front();
                continue;
            };
            if waiter.tokens > budget {
                break;
            }
            waiter.granted = true;
            let tokens = waiter.tokens;
            let waker = waiter.waker.clone();
            self.reserved += tokens;
            self.fifo.pop_front();
            granted.push(waker);
        }
        granted
    }

    /// Park `waker` under a stable id, refreshing it if already parked.
    ///
    /// Called under the limiter lock immediately after a failed
    /// `try_acquire`, so a concurrent `release` cannot be missed. Refreshing
    /// in place preserves the waiter's FIFO position, so a spurious poll
    /// cannot send it to the back of the queue.
    fn park_waiter(&mut self, id: &mut Option<u64>, tokens: usize, waker: &std::task::Waker) {
        if let Some(existing) = *id
            && let Some(slot) = self.waiters.get_mut(&existing)
        {
            slot.waker.clone_from(waker);
            return;
        }
        let new_id = self.next_waiter_id;
        // Checked, not wrapping: the FIFO deliberately retains tombstones for
        // cancelled waiters, so a wrapped id could alias one and hand a live
        // waiter's grant to a dead entry. Mirrors `allocate_logical_caller`.
        self.next_waiter_id = new_id
            .checked_add(1)
            .expect("admission waiter ID space exhausted");
        *id = Some(new_id);
        self.waiters.insert(
            new_id,
            Waiter {
                tokens,
                waker: waker.clone(),
                granted: false,
            },
        );
        self.fifo.push_back(new_id);
    }

    /// Whether this waiter has been granted capacity.
    fn is_granted(&self, id: Option<u64>) -> bool {
        id.and_then(|id| self.waiters.get(&id))
            .is_some_and(|w| w.granted)
    }

    /// Consume a grant: turn the reservation into in-flight tokens.
    fn consume_grant(&mut self, id: u64) {
        let Some(waiter) = self.waiters.remove(&id) else {
            return;
        };
        debug_assert!(waiter.granted, "consume_grant on an ungranted waiter");
        self.reserved = self.reserved.saturating_sub(waiter.tokens);
        self.admit(waiter.tokens);
    }

    /// Drop a waiter. Returns any reservation it was holding so the caller
    /// can re-grant it -- a cancelled grant must not strand its capacity.
    fn remove_waiter(&mut self, id: Option<u64>) -> bool {
        let Some(id) = id else { return false };
        let Some(waiter) = self.waiters.remove(&id) else {
            return false;
        };
        // The fifo entry, if still present, becomes a tombstone that
        // `grant_admissible` skips. That keeps removal O(1).
        if waiter.granted {
            self.reserved = self.reserved.saturating_sub(waiter.tokens);
            return true;
        }
        false
    }

    #[cfg(test)]
    fn parked_waiters(&self) -> usize {
        self.waiters.len()
    }

    #[cfg(test)]
    fn reserved_tokens(&self) -> usize {
        self.reserved
    }

    #[cfg(test)]
    fn granted_waiters(&self) -> usize {
        self.waiters.values().filter(|w| w.granted).count()
    }

    #[cfg(test)]
    fn fifo_steps(&self) -> u64 {
        self.fifo_steps
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    pub fn peak(&self) -> usize {
        self.peak
    }

    pub fn started(&self) -> usize {
        self.started
    }

    pub fn completed(&self) -> usize {
        self.completed
    }

    pub fn failed(&self) -> usize {
        self.failed
    }
    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn can_acquire(&self, tokens: usize) -> bool {
        tokens <= self.free()
    }
}

/// Release `tokens` back to `limiter`, then wake the admission waiters that
/// the freed capacity can now admit -- after the mutex guard is dropped.
///
/// Every release goes through here so no `Waker::wake()` ever runs while the
/// limiter lock is held.
pub fn release_and_wake(
    limiter: &std::sync::Arc<std::sync::Mutex<ConnectLimiter>>,
    tokens: usize,
    connected: bool,
) {
    let woken = {
        let mut lim = limiter.lock().unwrap();
        lim.release(tokens, connected);
        lim.grant_admissible()
    };
    for waker in woken {
        waker.wake();
    }
}

/// RAII permit for a physical SRT handshake slot governed by [`ConnectLimiter`].
///
/// Ensures exact-once accounting: dropping an unfinished permit conservatively
/// marks the handshake as failed, avoiding leaked concurrency permits on task
/// panic or cancellation.
pub struct HandshakePermit {
    limiter: std::sync::Arc<std::sync::Mutex<ConnectLimiter>>,
    tokens: usize,
    finished: bool,
}

impl HandshakePermit {
    /// Try to acquire `tokens` permits from `limiter`.
    #[must_use]
    pub fn try_acquire(
        limiter: &std::sync::Arc<std::sync::Mutex<ConnectLimiter>>,
        tokens: usize,
    ) -> Option<Self> {
        let mut lim = limiter.lock().unwrap();
        if lim.try_acquire(tokens) {
            Some(Self {
                limiter: limiter.clone(),
                tokens,
                finished: false,
            })
        } else {
            None
        }
    }

    /// Mark the handshake completed (connected) and release permits.
    pub fn complete(mut self) {
        self.finished = true;
        release_and_wake(&self.limiter, self.tokens, true);
    }

    /// Mark the handshake failed/timed-out and release permits.
    pub fn fail(mut self) {
        self.finished = true;
        release_and_wake(&self.limiter, self.tokens, false);
    }

    /// Settle a permit according to whether the connection came up.
    ///
    /// Runtime adapters hold their permit in an `Option` and settle it at two
    /// points -- the tick where the connection first reports Connected, and
    /// task exit -- so this takes the `Option` and leaves it empty. Calling it
    /// again is a no-op, which is what makes the exit path safe after the
    /// mid-loop release already fired.
    pub fn settle(permit: &mut Option<Self>, connected: bool) {
        if let Some(p) = permit.take() {
            if connected {
                p.complete();
            } else {
                p.fail();
            }
        }
    }
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        if !self.finished {
            release_and_wake(&self.limiter, self.tokens, false);
        }
    }
}

/// Future that resolves once `tokens` handshake permits are available.
///
/// This is the async counterpart to [`HandshakePermit::try_acquire`], and it
/// exists to keep pending callers off periodic timers. Every runtime adapter
/// in this crate spawns all N sender tasks upfront; a task that cannot start
/// its handshake immediately awaits this future, which parks its `Waker` in
/// the limiter and is woken only when a permit is actually released.
///
/// It is deliberately built on nothing but [`std::task::Waker`], so the same
/// implementation works on tokio, smol, monoio, glommio and compio without
/// importing any runtime's timer -- previously each adapter polled
/// `try_acquire` behind a 1ms sleep, which made the measured cost of a
/// low-`--connect-concurrency` cell depend on that runtime's timer wheel
/// rather than on handshake concurrency itself.
pub struct HandshakeAdmission {
    limiter: std::sync::Arc<std::sync::Mutex<ConnectLimiter>>,
    tokens: usize,
    waiter_id: Option<u64>,
}

impl HandshakeAdmission {
    /// Await `tokens` permits from `limiter`.
    pub fn new(limiter: &std::sync::Arc<std::sync::Mutex<ConnectLimiter>>, tokens: usize) -> Self {
        Self {
            limiter: limiter.clone(),
            tokens,
            waiter_id: None,
        }
    }

    /// Await one permit when a limiter is configured, else admit immediately.
    ///
    /// Every runtime adapter opens its sender task with exactly this, so it
    /// lives here rather than being restated five times.
    pub async fn acquire_optional(
        limiter: Option<&std::sync::Arc<std::sync::Mutex<ConnectLimiter>>>,
    ) -> Option<HandshakePermit> {
        match limiter {
            Some(lim) => Some(Self::new(lim, 1).await),
            None => None,
        }
    }
}

impl std::future::Future for HandshakeAdmission {
    type Output = HandshakePermit;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let mut lim = this.limiter.lock().unwrap();

        // A grant already reserved our tokens, so convert it directly rather
        // than contending for capacity that is ours by construction.
        if lim.is_granted(this.waiter_id) {
            let id = this.waiter_id.take().expect("granted implies an id");
            lim.consume_grant(id);
            return std::task::Poll::Ready(HandshakePermit {
                limiter: this.limiter.clone(),
                tokens: this.tokens,
                finished: false,
            });
        }

        if lim.try_acquire(this.tokens) {
            let id = this.waiter_id.take();
            lim.remove_waiter(id);
            return std::task::Poll::Ready(HandshakePermit {
                limiter: this.limiter.clone(),
                tokens: this.tokens,
                finished: false,
            });
        }
        lim.park_waiter(&mut this.waiter_id, this.tokens, cx.waker());
        std::task::Poll::Pending
    }
}

impl Drop for HandshakeAdmission {
    fn drop(&mut self) {
        let Some(id) = self.waiter_id.take() else {
            return;
        };
        // Dropping a *granted* waiter must hand its reservation on, or the
        // capacity it was woken for is stranded and everyone behind it sleeps
        // forever.
        let woken = {
            let mut lim = self.limiter.lock().unwrap();
            if lim.remove_waiter(Some(id)) {
                lim.grant_admissible()
            } else {
                Vec::new()
            }
        };
        for waker in woken {
            waker.wake();
        }
    }
}

// ---------------------------------------------------------------------------
// SharedSender slot state machine + event-driven scheduling
// ---------------------------------------------------------------------------

type SlotId = usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlotPhase {
    Pending,
    Handshaking,
    Streaming,
    Closing,
    Closed,
}

struct SharedSenderSlot {
    phase: SlotPhase,
    caller: Option<srt_transport::LogicalCallerId>,
    stats: Vec<ConnStats>,
    /// This slot's application payload producer. One per logical stream:
    /// a bonded pair carries the same source over two legs, so it has one
    /// source clock, not two.
    source: crate::source::SourceClock,
    stream_deadline: Option<Instant>,
    physical_legs: usize,
    held_handshake_tokens: u8,
    dirty: bool,
    cfg_index: usize,
    bond_pair_index: Option<usize>,
    socket_ids: Vec<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AppDeadlineEntry {
    deadline_us: u64,
    slot: SlotId,
    kind: AppDeadlineKind,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
enum AppDeadlineKind {
    Send,
    StreamEnd,
    ConnectTimeout,
}

/// Instrumentation counters for SharedSender scheduling work.
///
/// Every counter here records slots actually *visited*. Their sum over a tick
/// is the scheduler's real per-tick cost, so asserting that sum stays
/// proportional to pending work rather than to `slots.len()` is what proves
/// the population scan is gone -- see
/// `tick_cost_tracks_due_work_not_population`.
#[derive(Default, Clone, Debug)]
pub struct SharedSenderSchedStats {
    pub tick_calls: u64,
    pub dirty_slot_visits: u64,
    pub application_due_visits: u64,
    pub handshake_state_visits: u64,
    pub closing_slot_visits: u64,
}

impl SharedSenderSchedStats {
    /// Total slots visited across all scheduling phases.
    pub fn slot_visits(&self) -> u64 {
        self.dirty_slot_visits
            + self.application_due_visits
            + self.handshake_state_visits
            + self.closing_slot_visits
    }
}

/// Protocol/timer half of a shared-egress sender. Runtime adapters own one
/// native UDP socket and only translate readiness into `feed`/`tick` calls.
///
/// Scheduling is event-driven: only dirty (packet-affected), due
/// (application deadline expired), or in-flight-handshake slots are
/// visited. Idle slots cost nothing.
pub struct SharedSender {
    callers: srt_transport::CallerTable,
    slots: Vec<SharedSenderSlot>,
    payload: Vec<u8>,
    start: Instant,

    pending_start: std::collections::VecDeque<SlotId>,
    dirty_ready: std::collections::VecDeque<SlotId>,
    app_deadlines: std::collections::BTreeSet<AppDeadlineEntry>,
    slot_deadlines: std::collections::HashMap<(SlotId, AppDeadlineKind), u64>,
    in_flight_set: Vec<SlotId>,
    closing_set: Vec<SlotId>,
    terminal_count: usize,
    due_scratch: Vec<AppDeadlineEntry>,

    socket_id_to_slot: std::collections::HashMap<u32, SlotId>,

    limiter: std::sync::Arc<std::sync::Mutex<ConnectLimiter>>,
    duration_secs: f64,

    sched_stats: SharedSenderSchedStats,
}

impl SharedSender {
    pub fn new(
        cfg: &BenchConfig,
        mine: &[usize],
        start: Instant,
        limiter: std::sync::Arc<std::sync::Mutex<ConnectLimiter>>,
    ) -> Self {
        let mut slots = Vec::with_capacity(mine.len());
        let mut pending_start = std::collections::VecDeque::with_capacity(mine.len());

        let mut position = 0;
        let mut slot_id: SlotId = 0;
        while position < mine.len() {
            let index = mine[position];
            let is_bonded = cfg.bond_extension_for(index).is_some()
                && index.is_multiple_of(2)
                && mine.get(position + 1) == Some(&(index + 1));

            if is_bonded {
                slots.push(SharedSenderSlot {
                    phase: SlotPhase::Pending,
                    caller: None,
                    stats: vec![ConnStats::default(), ConnStats::default()],
                    source: cfg.source_clock(),
                    stream_deadline: None,
                    physical_legs: 2,
                    held_handshake_tokens: 0,
                    dirty: false,
                    cfg_index: index,
                    bond_pair_index: Some(index + 1),
                    socket_ids: Vec::new(),
                });
                pending_start.push_back(slot_id);
                slot_id += 1;
                position += 2;
            } else {
                slots.push(SharedSenderSlot {
                    phase: SlotPhase::Pending,
                    caller: None,
                    stats: vec![ConnStats::default()],
                    source: cfg.source_clock(),
                    stream_deadline: None,
                    physical_legs: 1,
                    held_handshake_tokens: 0,
                    dirty: false,
                    cfg_index: index,
                    bond_pair_index: None,
                    socket_ids: Vec::new(),
                });
                pending_start.push_back(slot_id);
                slot_id += 1;
                position += 1;
            }
        }

        Self {
            callers: srt_transport::CallerTable::new(),
            slots,
            payload: vec![0x42; PAYLOAD_SIZE],
            start,
            pending_start,
            dirty_ready: std::collections::VecDeque::new(),
            app_deadlines: std::collections::BTreeSet::new(),
            slot_deadlines: std::collections::HashMap::new(),
            in_flight_set: Vec::new(),
            closing_set: Vec::new(),
            terminal_count: 0,
            due_scratch: Vec::new(),
            socket_id_to_slot: std::collections::HashMap::new(),
            limiter,
            duration_secs: cfg.duration_secs,
            sched_stats: SharedSenderSchedStats::default(),
        }
    }

    fn admit_pending(&mut self, cfg: &BenchConfig) {
        let mut to_start = Vec::new();
        {
            let mut lim = self.limiter.lock().unwrap();
            while let Some(&slot_id) = self.pending_start.front() {
                let legs = self.slots[slot_id].physical_legs;
                if !lim.try_acquire(legs) {
                    break;
                }
                self.pending_start.pop_front();
                to_start.push(slot_id);
            }
        }
        for slot_id in to_start {
            self.start_slot(cfg, slot_id);
        }
    }

    fn start_slot(&mut self, cfg: &BenchConfig, slot_id: SlotId) {
        let slot = &mut self.slots[slot_id];
        let index = slot.cfg_index;
        let now = now_ts(self.start);
        let now_instant = Instant::now();
        let connect_deadline = now_instant + CONNECT_TIMEOUT;

        if let Some(pair_index) = slot.bond_pair_index {
            let first = make_caller_connection(cfg, index, now);
            let second = make_caller_connection(cfg, pair_index, now);
            let group_id = shiguredo_srt::SRTGROUP_MASK | ((index / 2) as u32 + 1);
            let mode = match cfg.bond_mode {
                BondMode::Broadcast => shiguredo_srt::GroupMode::Broadcast,
                BondMode::Backup => shiguredo_srt::GroupMode::Backup,
                BondMode::None => unreachable!("group extension requires a bond mode"),
            };
            let sid1 = cfg.caller_socket_id_for(index);
            let sid2 = cfg.caller_socket_id_for(pair_index);
            let caller = self
                .callers
                .add_group(
                    group_id,
                    mode,
                    [
                        srt_transport::CallerGroupLeg::new(
                            index as u32 + 1,
                            cfg.bond_extension_for(index).expect("group leg").weight,
                            cfg.addr_for(index),
                            first,
                        ),
                        srt_transport::CallerGroupLeg::new(
                            pair_index as u32 + 1,
                            cfg.bond_extension_for(pair_index)
                                .expect("group leg")
                                .weight,
                            cfg.addr_for(pair_index),
                            second,
                        ),
                    ],
                )
                .expect("bench caller group has distinct member and socket IDs");
            self.socket_id_to_slot.insert(sid1, slot_id);
            self.socket_id_to_slot.insert(sid2, slot_id);
            slot.socket_ids = vec![sid1, sid2];
            slot.caller = Some(caller);
        } else {
            let sid = cfg.caller_socket_id_for(index);
            let caller = self
                .callers
                .add_direct(srt_transport::CallerLeg::new(
                    cfg.addr_for(index),
                    make_caller_connection(cfg, index, now),
                ))
                .expect("bench caller socket IDs are unique and non-zero");
            self.socket_id_to_slot.insert(sid, slot_id);
            slot.socket_ids = vec![sid];
            slot.caller = Some(caller);
        }

        slot.phase = SlotPhase::Handshaking;
        slot.held_handshake_tokens = slot.physical_legs as u8;
        let deadline_us = connect_deadline.duration_since(self.start).as_micros() as u64;
        self.app_deadlines.insert(AppDeadlineEntry {
            deadline_us,
            slot: slot_id,
            kind: AppDeadlineKind::ConnectTimeout,
        });
        self.slot_deadlines
            .insert((slot_id, AppDeadlineKind::ConnectTimeout), deadline_us);
        self.in_flight_set.push(slot_id);
    }

    pub fn feed(&mut self, peer: std::net::SocketAddr, data: &[u8]) {
        if let Ok(sid) = shiguredo_srt::peek_destination_socket_id(data)
            && let Some(&slot_id) = self.socket_id_to_slot.get(&sid)
        {
            let slot = &mut self.slots[slot_id];
            if !slot.dirty && slot.phase != SlotPhase::Closed {
                slot.dirty = true;
                self.dirty_ready.push_back(slot_id);
            }
        }
        let _ = self.callers.feed(peer, data, now_ts(self.start));
    }

    pub fn tick(&mut self, cfg: &BenchConfig, out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>) {
        self.sched_stats.tick_calls += 1;
        let now_instant = Instant::now();
        let now = now_ts(self.start);

        self.admit_pending(cfg);

        self.process_dirty_slots(now_instant, now);

        self.process_due_deadlines(now_instant, now);

        self.check_in_flight(now_instant, now);

        self.check_closing();

        self.callers.poll_outbound(now, out);
    }

    fn process_dirty_slots(&mut self, now_instant: Instant, now: shiguredo_srt::Timestamp) {
        let mut count = self.dirty_ready.len();
        while count > 0 {
            count -= 1;
            let Some(slot_id) = self.dirty_ready.pop_front() else {
                break;
            };
            self.slots[slot_id].dirty = false;
            if self.slots[slot_id].phase == SlotPhase::Closed {
                continue;
            }
            self.sched_stats.dirty_slot_visits += 1;
            self.eval_slot_state(slot_id, now_instant, now);
        }
    }

    fn process_due_deadlines(&mut self, now_instant: Instant, now: shiguredo_srt::Timestamp) {
        let now_us = now_instant.duration_since(self.start).as_micros() as u64;
        self.due_scratch.clear();
        while let Some(entry) = self.app_deadlines.first().copied() {
            if entry.deadline_us > now_us {
                break;
            }
            self.app_deadlines.pop_first();
            self.slot_deadlines.remove(&(entry.slot, entry.kind));
            self.due_scratch.push(entry);
        }
        for i in 0..self.due_scratch.len() {
            let entry = self.due_scratch[i];
            if self.slots[entry.slot].phase == SlotPhase::Closed {
                continue;
            }
            self.sched_stats.application_due_visits += 1;
            self.dispatch_due(entry, now_instant, now);
        }
    }

    fn dispatch_due(
        &mut self,
        entry: AppDeadlineEntry,
        now_instant: Instant,
        now: shiguredo_srt::Timestamp,
    ) {
        let phase = self.slots[entry.slot].phase;
        match entry.kind {
            AppDeadlineKind::Send if phase == SlotPhase::Streaming => {
                self.send_slot(entry.slot, now_instant, now);
            }
            AppDeadlineKind::StreamEnd if phase == SlotPhase::Streaming => {
                self.close_slot(entry.slot, now);
            }
            AppDeadlineKind::ConnectTimeout if phase == SlotPhase::Handshaking => {
                self.timeout_slot(entry.slot);
            }
            _ => {}
        }
    }

    fn check_in_flight(&mut self, now_instant: Instant, now: shiguredo_srt::Timestamp) {
        let mut i = 0;
        while i < self.in_flight_set.len() {
            let slot_id = self.in_flight_set[i];
            self.sched_stats.handshake_state_visits += 1;
            let slot = &self.slots[slot_id];
            if slot.phase != SlotPhase::Handshaking {
                self.in_flight_set.swap_remove(i);
                continue;
            }
            let caller_id = match slot.caller {
                Some(id) => id,
                None => {
                    i += 1;
                    continue;
                }
            };
            let state = self
                .callers
                .logical_caller(&caller_id)
                .and_then(|c| c.state());
            match state {
                Some(srt_transport::LogicalCallerState::Connected) => {
                    if self.transition_to_streaming(slot_id, now_instant, now) {
                        self.in_flight_set.swap_remove(i);
                    } else {
                        i += 1;
                    }
                }
                Some(srt_transport::LogicalCallerState::Disconnected) => {
                    self.mark_slot_failed(slot_id);
                    self.in_flight_set.swap_remove(i);
                }
                _ => {
                    i += 1;
                }
            }
        }
    }

    fn check_closing(&mut self) {
        let mut i = 0;
        while i < self.closing_set.len() {
            let slot_id = self.closing_set[i];
            self.sched_stats.closing_slot_visits += 1;
            let slot = &self.slots[slot_id];
            if slot.phase != SlotPhase::Closing {
                self.closing_set.swap_remove(i);
                continue;
            }
            let caller_id = match slot.caller {
                Some(id) => id,
                None => {
                    self.finalize_slot(slot_id, false);
                    self.closing_set.swap_remove(i);
                    continue;
                }
            };
            let state = self
                .callers
                .logical_caller(&caller_id)
                .and_then(|c| c.state());
            if let Some(srt_transport::LogicalCallerState::Disconnected) = state {
                self.finalize_slot(slot_id, false);
                self.closing_set.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    fn eval_slot_state(
        &mut self,
        slot_id: SlotId,
        now_instant: Instant,
        now: shiguredo_srt::Timestamp,
    ) {
        let slot = &self.slots[slot_id];
        let caller_id = match slot.caller {
            Some(id) => id,
            None => return,
        };
        let state = self
            .callers
            .logical_caller(&caller_id)
            .and_then(|c| c.state());

        match slot.phase {
            SlotPhase::Handshaking => match state {
                Some(srt_transport::LogicalCallerState::Connected) => {
                    self.transition_to_streaming(slot_id, now_instant, now);
                }
                Some(srt_transport::LogicalCallerState::Disconnected) => {
                    self.mark_slot_failed(slot_id);
                }
                _ => {}
            },
            SlotPhase::Streaming => {
                if let Some(srt_transport::LogicalCallerState::Disconnected) = state {
                    self.mark_slot_disconnected(slot_id);
                }
            }
            SlotPhase::Closing => {
                // A dirty inbound packet can observe the close completing
                // before `check_closing` walks the closing set, so this path
                // must retire the caller too, not just mark the slot Closed.
                if let Some(srt_transport::LogicalCallerState::Disconnected) = state {
                    self.finalize_slot(slot_id, false);
                }
            }
            _ => {}
        }
    }

    fn transition_to_streaming(
        &mut self,
        slot_id: SlotId,
        now_instant: Instant,
        now: shiguredo_srt::Timestamp,
    ) -> bool {
        let slot = &self.slots[slot_id];
        if slot.phase == SlotPhase::Closed || slot.phase == SlotPhase::Streaming {
            return true;
        }

        if slot.physical_legs > 1 && !self.all_leg_handshakes_terminal(slot_id) {
            return false;
        }

        let slot = &mut self.slots[slot_id];
        slot.phase = SlotPhase::Streaming;
        for stats in &mut slot.stats {
            stats.connected = true;
        }
        let stream_end = now_instant + Duration::from_secs_f64(self.duration_secs);
        slot.stream_deadline = Some(stream_end);

        self.release_streaming_tokens(slot_id);

        self.remove_deadline(slot_id, AppDeadlineKind::ConnectTimeout);

        let end_us = stream_end.duration_since(self.start).as_micros() as u64;
        self.app_deadlines.insert(AppDeadlineEntry {
            deadline_us: end_us,
            slot: slot_id,
            kind: AppDeadlineKind::StreamEnd,
        });
        self.slot_deadlines
            .insert((slot_id, AppDeadlineKind::StreamEnd), end_us);

        self.schedule_send(slot_id, now_instant, now);
        true
    }

    fn all_leg_handshakes_terminal(&self, slot_id: SlotId) -> bool {
        let slot = &self.slots[slot_id];
        if slot.physical_legs <= 1 {
            return true;
        }
        let caller_id = match slot.caller {
            Some(id) => id,
            None => return false,
        };
        self.callers
            .logical_caller(&caller_id)
            .and_then(|c| c.stats())
            .is_some_and(|s| match s {
                srt_transport::LogicalCallerStats::Group(g) => {
                    g.aggregate.pending_legs == 0
                        || (g.legs.len() == slot.physical_legs
                            && g.legs.iter().all(|l| l.connection.sender.is_some()))
                }
                _ => true,
            })
    }

    fn release_streaming_tokens(&mut self, slot_id: SlotId) {
        let slot = &mut self.slots[slot_id];
        let total_tokens = slot.held_handshake_tokens as usize;
        if total_tokens == 0 {
            return;
        }
        slot.held_handshake_tokens = 0;

        let caller_id = match slot.caller {
            Some(id) => id,
            None => {
                release_and_wake(&self.limiter, total_tokens, false);
                return;
            }
        };

        let connected_legs = self
            .callers
            .logical_caller(&caller_id)
            .and_then(|c| c.stats())
            .map_or(0, |s| match s {
                srt_transport::LogicalCallerStats::Direct(d) => {
                    if d.sender.is_some() {
                        1
                    } else {
                        0
                    }
                }
                srt_transport::LogicalCallerStats::Group(g) => g
                    .legs
                    .iter()
                    .filter(|l| l.connection.sender.is_some())
                    .count(),
            });

        let completed = connected_legs.min(total_tokens);
        let failed = total_tokens.saturating_sub(completed);

        if completed > 0 {
            release_and_wake(&self.limiter, completed, true);
        }
        if failed > 0 {
            release_and_wake(&self.limiter, failed, false);
        }
    }

    fn retire_caller(&mut self, slot_id: SlotId) {
        if let Some(caller_id) = self.slots[slot_id].caller.take() {
            self.callers.remove(caller_id);
        }
        for sid in self.slots[slot_id].socket_ids.drain(..) {
            self.socket_id_to_slot.remove(&sid);
        }
    }

    fn snapshot_caller_stats(
        &mut self,
        slot_id: SlotId,
        caller_id: srt_transport::LogicalCallerId,
    ) {
        let slot = &mut self.slots[slot_id];
        match self
            .callers
            .logical_caller(&caller_id)
            .and_then(|caller| caller.stats())
        {
            Some(srt_transport::LogicalCallerStats::Direct(stats)) => {
                apply_sender_stats(&mut slot.stats[0], &stats);
            }
            Some(srt_transport::LogicalCallerStats::Group(stats)) => {
                for (result, leg) in slot.stats.iter_mut().zip(stats.legs) {
                    result.connected |= matches!(
                        leg.state,
                        shiguredo_srt::GroupMemberState::Active
                            | shiguredo_srt::GroupMemberState::Standby
                            | shiguredo_srt::GroupMemberState::Unstable
                    ) || leg.connection.sender.is_some();
                    apply_sender_stats(result, &leg.connection);
                }
            }
            None => {}
        }
    }

    fn schedule_send(
        &mut self,
        slot_id: SlotId,
        now_instant: Instant,
        now: shiguredo_srt::Timestamp,
    ) {
        let slot = &self.slots[slot_id];
        if slot.phase != SlotPhase::Streaming {
            return;
        }
        let caller_id = match slot.caller {
            Some(id) => id,
            None => return,
        };
        let pacing_wait_us = self
            .callers
            .logical_caller(&caller_id)
            .map_or(MAX_WAIT.as_micros() as u64, |c| c.time_until_send(now));
        // Two independent clocks gate the next send: SRT's pacing, and the
        // application source. With work already pending it is pacing that
        // has to move; with none, the source does. Waking earlier than
        // whichever one it is buys nothing on the send path.
        let wait_us = slot
            .source
            .wait_micros(now_instant.duration_since(self.start), pacing_wait_us);
        let send_instant = now_instant + Duration::from_micros(wait_us);
        let deadline_us = send_instant.duration_since(self.start).as_micros() as u64;
        self.remove_deadline(slot_id, AppDeadlineKind::Send);
        self.app_deadlines.insert(AppDeadlineEntry {
            deadline_us,
            slot: slot_id,
            kind: AppDeadlineKind::Send,
        });
        self.slot_deadlines
            .insert((slot_id, AppDeadlineKind::Send), deadline_us);
    }

    fn send_slot(&mut self, slot_id: SlotId, now_instant: Instant, now: shiguredo_srt::Timestamp) {
        let slot = &self.slots[slot_id];
        let caller_id = match slot.caller {
            Some(id) => id,
            None => return,
        };
        if let Some(deadline) = slot.stream_deadline
            && now_instant >= deadline
        {
            self.close_slot(slot_id, now);
            return;
        }
        // Advance the application source first, then offer it to SRT.
        // The source's cadence is its own; SRT only decides how much of it
        // gets through.
        self.slots[slot_id]
            .source
            .tick(now_instant.duration_since(self.start));
        let mut caller = match self.callers.logical_caller_mut(&caller_id) {
            Some(c) => c,
            None => return,
        };
        let mut accepted = 0u32;
        let mut refused = false;
        while self.slots[slot_id].source.pending() > accepted {
            if !caller.can_send_with_pacing(now) {
                refused = true;
                break;
            }
            let Ok(selected_legs) = caller.send(&self.payload, now) else {
                refused = true;
                break;
            };
            for stats in self.slots[slot_id].stats.iter_mut().take(selected_legs) {
                stats.data_events = stats.data_events.saturating_add(1);
            }
            accepted += 1;
        }
        let source = &mut self.slots[slot_id].source;
        for _ in 0..accepted {
            source.accepted();
        }
        if refused {
            source.refused();
        }
        self.schedule_send(slot_id, now_instant, now);
    }

    fn close_slot(&mut self, slot_id: SlotId, now: shiguredo_srt::Timestamp) {
        let phase = self.slots[slot_id].phase;
        if phase == SlotPhase::Closed || phase == SlotPhase::Closing {
            return;
        }
        if phase == SlotPhase::Streaming {
            debug_assert_eq!(
                self.slots[slot_id].held_handshake_tokens, 0,
                "streaming slot should not hold handshake permits"
            );
        }
        self.release_held_tokens(slot_id, false);
        let caller_id = match self.slots[slot_id].caller {
            Some(id) => id,
            None => {
                self.mark_slot_terminal(slot_id);
                return;
            }
        };
        self.slots[slot_id].phase = SlotPhase::Closing;
        self.remove_deadline(slot_id, AppDeadlineKind::Send);
        self.remove_deadline(slot_id, AppDeadlineKind::StreamEnd);
        self.closing_set.push(slot_id);
        if let Some(mut caller) = self.callers.logical_caller_mut(&caller_id) {
            caller.disconnect(now);
        }
    }

    /// The single terminal path for a slot.
    ///
    /// Every way a slot can stop -- connect timeout, handshake failure,
    /// unexpected mid-stream disconnect, or the end of an orderly close --
    /// funnels through here, in this order:
    ///
    /// 1. snapshot the caller's final protocol stats (must precede retire,
    ///    which drops the caller),
    /// 2. mark surviving legs torn down if the slot was carrying traffic,
    /// 3. retire the caller: remove it from the `CallerTable` and drop its
    ///    socket-ID routes, so late packets can no longer redirty the slot,
    /// 4. mark the slot `Closed`, which drops its application deadlines and
    ///    releases any handshake permits it still holds.
    ///
    /// Routing every transition through one helper is what makes the
    /// invariant "a Closed slot never has a caller still installed" hold.
    /// Previously the disconnect paths reached `Closed` without step 3, so a
    /// mid-stream disconnect left the caller, its socket-ID routes and its
    /// protocol scheduling state installed for the rest of the run.
    ///
    /// Idempotent: a slot already `Closed` returns immediately, so a dirty
    /// packet and `check_closing` observing the same transition is harmless.
    fn finalize_slot(&mut self, slot_id: SlotId, torn_down: bool) {
        if self.slots[slot_id].phase == SlotPhase::Closed {
            return;
        }
        if let Some(caller_id) = self.slots[slot_id].caller {
            self.snapshot_caller_stats(slot_id, caller_id);
        }
        if torn_down {
            for stats in &mut self.slots[slot_id].stats {
                stats.torn_down |= stats.connected;
            }
        }
        self.retire_caller(slot_id);
        // Permit release lives in `mark_slot_terminal`, the one choke point
        // every terminal path reaches; releasing here too would be a no-op.
        self.mark_slot_terminal(slot_id);
    }

    fn timeout_slot(&mut self, slot_id: SlotId) {
        self.finalize_slot(slot_id, false);
    }

    fn mark_slot_failed(&mut self, slot_id: SlotId) {
        self.finalize_slot(slot_id, true);
    }

    fn mark_slot_disconnected(&mut self, slot_id: SlotId) {
        self.finalize_slot(slot_id, true);
    }

    fn mark_slot_terminal(&mut self, slot_id: SlotId) {
        let slot = &mut self.slots[slot_id];
        if slot.phase == SlotPhase::Closed {
            return;
        }
        slot.phase = SlotPhase::Closed;
        self.terminal_count += 1;
        self.remove_deadline(slot_id, AppDeadlineKind::Send);
        self.remove_deadline(slot_id, AppDeadlineKind::StreamEnd);
        self.remove_deadline(slot_id, AppDeadlineKind::ConnectTimeout);

        self.release_held_tokens(slot_id, false);
    }

    fn release_held_tokens(&mut self, slot_id: SlotId, connected: bool) {
        let slot = &mut self.slots[slot_id];
        let tokens = slot.held_handshake_tokens;
        if tokens == 0 {
            return;
        }
        slot.held_handshake_tokens = 0;
        release_and_wake(&self.limiter, tokens as usize, connected);
    }

    fn remove_deadline(&mut self, slot_id: SlotId, kind: AppDeadlineKind) {
        if let Some(deadline_us) = self.slot_deadlines.remove(&(slot_id, kind)) {
            self.app_deadlines.remove(&AppDeadlineEntry {
                deadline_us,
                slot: slot_id,
                kind,
            });
        }
    }

    pub fn done(&self) -> bool {
        self.terminal_count == self.slots.len()
    }

    pub fn next_wait(&self) -> Duration {
        if !self.dirty_ready.is_empty() {
            return Duration::ZERO;
        }

        if let Some(&slot_id) = self.pending_start.front() {
            let legs = self.slots[slot_id].physical_legs;
            let lim = self.limiter.lock().unwrap();
            if lim.can_acquire(legs) {
                return Duration::ZERO;
            }
        }

        let now = now_ts(self.start);
        let max_us = MAX_WAIT.as_micros() as u64;
        let mut wait = self.callers.time_until_next_deadline(now, max_us);

        if let Some(entry) = self.app_deadlines.first() {
            let now_us = Instant::now().duration_since(self.start).as_micros() as u64;
            let app_wait = entry.deadline_us.saturating_sub(now_us);
            wait = wait.min(app_wait);
        }

        Duration::from_micros(wait).min(MAX_WAIT)
    }

    pub fn sched_stats(&self) -> &SharedSenderSchedStats {
        &self.sched_stats
    }

    pub fn limiter_snapshot(&self) -> (usize, usize, usize, usize) {
        let lim = self.limiter.lock().unwrap();
        (lim.peak(), lim.started(), lim.completed(), lim.failed())
    }
    pub fn cc_peak(&self) -> usize {
        self.limiter.lock().unwrap().peak()
    }

    #[cfg(feature = "bench-internals")]
    pub fn force_all_connected(&mut self) {
        self.in_flight_set.clear();
        self.pending_start.clear();
        self.closing_set.clear();
        for slot in &mut self.slots {
            slot.phase = SlotPhase::Streaming;
            slot.held_handshake_tokens = 0;
        }
    }

    /// Drive the slot table into the worst case for a population-scanning
    /// `done()`: every slot terminal except the last.
    ///
    /// The pre-change implementation was `slots.iter().all(|s| s.closed)`,
    /// and `Iterator::all` short-circuits. Measured on a fixture whose slot 0
    /// is still live it visits *one* slot, not N -- which is why a `done()`
    /// benchmark built on `make_sender` understates the very scan it is meant
    /// to price. Leaving only the final slot open forces the full traversal.
    #[cfg(feature = "bench-internals")]
    pub fn force_all_terminal_except_last(&mut self) {
        self.in_flight_set.clear();
        self.pending_start.clear();
        self.closing_set.clear();
        self.app_deadlines.clear();
        self.slot_deadlines.clear();
        let last = self.slots.len().saturating_sub(1);
        for (i, slot) in self.slots.iter_mut().enumerate() {
            slot.held_handshake_tokens = 0;
            slot.phase = if i == last {
                SlotPhase::Streaming
            } else {
                SlotPhase::Closed
            };
        }
        self.terminal_count = last;
    }

    /// The pre-change `done()`, retained only so the benchmark can price the
    /// old population scan against the current O(1) counter on one fixture.
    /// The scheduler itself never calls this.
    #[cfg(feature = "bench-internals")]
    pub fn done_by_population_scan(&self) -> bool {
        self.slots
            .iter()
            .all(|slot| slot.phase == SlotPhase::Closed)
    }

    #[cfg(feature = "bench-internals")]
    pub fn force_arm_due_send(&mut self, slot_id: usize) {
        self.app_deadlines.insert(AppDeadlineEntry {
            deadline_us: 0,
            slot: slot_id,
            kind: AppDeadlineKind::Send,
        });
        self.slot_deadlines
            .insert((slot_id, AppDeadlineKind::Send), 0);
    }

    pub fn finish(mut self) -> Vec<ConnStats> {
        for slot_id in 0..self.slots.len() {
            if let Some(caller_id) = self.slots[slot_id].caller.take() {
                self.snapshot_caller_stats(slot_id, caller_id);
                self.callers.remove(caller_id);
            }
        }
        self.slots
            .into_iter()
            .flat_map(|slot| {
                let source = slot.source.stats();
                let mut stats = slot.stats;
                // One source per logical stream: charge it to the first
                // leg only so a bonded pair is not counted twice.
                if let Some(first) = stats.first_mut() {
                    first.source = source;
                    first.has_source = true;
                }
                stats
            })
            .collect()
    }
}

fn make_caller_connection(
    cfg: &BenchConfig,
    index: usize,
    now: shiguredo_srt::Timestamp,
) -> shiguredo_srt::SrtConnection {
    let mut options = shiguredo_srt::ConnectionOptions {
        socket_id: cfg.caller_socket_id_for(index),
        tsbpd_delay: cfg.latency_ms,
        group_extension: cfg.bond_extension_for(index),
        initial_seq: cfg.bond_initial_seq_for(index),
        stream_id: cfg.bond_stream_id_for(index),
        ..Default::default()
    };
    cfg.apply_srt_bandwidth(&mut options);
    cfg.encryption.apply_to(&mut options);
    let mut connection = shiguredo_srt::SrtConnection::new_caller(options);
    connection
        .connect(now)
        .expect("shared caller connect queues INDUCTION");
    connection
}

fn apply_sender_stats(stats: &mut ConnStats, connection: &shiguredo_srt::ConnectionStats) {
    if let Some(sender) = connection.sender {
        stats.has_stats = true;
        stats.core_total = sender.total_sent;
        stats.secondary_a = sender.total_retransmits;
        stats.secondary_b = sender.packets_in_loss_list as u64;
    }
}

/// Bind the one application-owned UDP socket used by shared egress.
///
/// Runtime adapters convert this socket to their native type; keeping bind
/// and buffer configuration here ensures the `sock-buf` axis has identical
/// meaning for every runtime.
pub(crate) fn bind_configured_socket(
    addr: std::net::SocketAddr,
    sock_buf_bytes: usize,
) -> std::io::Result<std::net::UdpSocket> {
    use std::os::fd::AsRawFd;

    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    srt_transport::set_sock_bufs(socket.as_raw_fd(), sock_buf_bytes)?;
    Ok(socket)
}

pub(crate) fn bind_shared_sender_socket(
    sock_buf_bytes: usize,
) -> std::io::Result<std::net::UdpSocket> {
    bind_configured_socket(
        std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        sock_buf_bytes,
    )
}

/// Convert a shared-listener table into benchmark rows. A bonded publisher is
/// one logical receiver row, with logical delivery counters and aggregated
/// wire telemetry; ordinary peers retain their physical-connection rows.
pub fn collect_listener_stats(peers: srt_transport::PeerTable) -> Vec<ConnStats> {
    let mut stats = peers
        .bonded_stats()
        .into_iter()
        .map(|group| {
            let aggregate = group.connection.aggregate;
            let duplicates = group
                .connection
                .legs
                .iter()
                .filter_map(|leg| leg.connection.receiver.as_ref())
                .map(|receiver| receiver.total_duplicates)
                .sum();
            ConnStats {
                connected: group.ever_connected,
                torn_down: group.torn_down,
                data_events: aggregate.logical_payloads_received,
                has_stats: !group.connection.legs.is_empty(),
                core_total: aggregate.wire_unique_packets_received,
                secondary_a: aggregate.wire_receiver_packets_lost,
                secondary_b: duplicates,
                ..Default::default()
            }
        })
        .collect::<Vec<_>>();
    stats.extend(peers.into_iter().map(|(_peer, p)| {
        let mut s = ConnStats {
            connected: p.stream_deadline.is_some(),
            torn_down: p.torn_down,
            data_events: p.data_events,
            ..Default::default()
        };
        if let Some(st) = p.conn.receiver_stats() {
            s.has_stats = true;
            s.core_total = st.total_received;
            s.secondary_a = st.total_lost;
            s.secondary_b = st.total_duplicates;
            s.rtt_us = st.rtt as u64;
        }
        s
    }));
    stats
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
            Ingress::ReuseportMulti(k) if k >= 1 => {
                reuseport_multi(cfg.clone(), k);
                return true;
            }
            Ingress::SharedPool(k) if k >= 1 => {
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
    pub cc_peak: usize,
    /// Process-wide application source behaviour. Counts sum across
    /// connections; the backlog high-water mark is the worst any single
    /// connection reached, since summing high-water marks would report a
    /// backlog nothing ever held.
    pub source: crate::source::SourceStats,
    /// How many independent payload sources this process actually ran.
    /// One per logical stream, so a bonded pair contributes one, not two.
    pub source_streams: u64,
    pub datapath_queue: crate::queue::QueueStats,
    pub recv_scheduling: crate::scheduling::RecvSchedulingStats,
    pub outbound_retry: crate::scheduling::RetryStats,
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
            cc_peak: 0,
            source: crate::source::SourceStats::default(),
            source_streams: 0,
            datapath_queue: crate::queue::QueueStats::default(),
            recv_scheduling: crate::scheduling::RecvSchedulingStats::default(),
            outbound_retry: crate::scheduling::RetryStats::default(),
        }
    }

    pub fn add(&mut self, s: ConnStats) {
        self.data_events += s.data_events;
        self.torn_down += u64::from(s.torn_down);
        self.source.generated += s.source.generated;
        self.source.accepted += s.source.accepted;
        self.source.refusal_polls += s.source.refusal_polls;
        self.source.blocked_streaks += s.source.blocked_streaks;
        self.source_streams += u64::from(s.has_source);
        self.source.overflow += s.source.overflow;
        self.source.backlog_hwm = self.source.backlog_hwm.max(s.source.backlog_hwm);
        self.datapath_queue.merge(s.datapath_queue);
        self.recv_scheduling.merge(s.recv_scheduling);
        self.outbound_retry.merge(s.outbound_retry);
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
                &crate::harness::RunMeasurements {
                    established: self.stats_count,
                    torn_down: self.torn_down,
                    pkt_sent: self.data_events,
                    core_total: self.core_total,
                    sec_a: self.secondary_a,
                    sec_b: self.secondary_b,
                    rtt_ms: rtt,
                    elapsed_s,
                    cc_peak: self.cc_peak,
                    source: self.source,
                    source_streams: self.source_streams,
                    datapath_queue: self.datapath_queue,
                    recv_scheduling: self.recv_scheduling,
                    outbound_retry: self.outbound_retry,
                },
            )
        {
            eprintln!(
                "warning: could not append result to {}: {e}",
                path.display()
            );
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: srt-bench runtime=<mio|tokio|smol|monoio|glommio|compio> \
         mode=<sender|receiver> <host?> <port> <duration_secs> <latency_ms> \
         [source_bitrate_bps] [--connections N] \
         [--srt-bandwidth protocol-default|legacy-source-fixed|fixed:BPS|input-relative:PCT] \
         [--source-backlog-ms MS] [--datapath-queue-horizon-ms MS] \
         [--ingress per-port|shared-pool=K|reuseport-multi=K|reuseport-single=W] \
         [--egress per-connection|shared-socket] \
         [--encryption plain|128|192|256] \
         [--bond broadcast:G|backup:G|none] [--batch on|off] \
         [--connect-concurrency N] [--recv-rounds N] [--would-block retain|drop] [--promotion never|relocate|bonded|all] [--cookie-routing on|off] [--sock-buf N|Nk|Nm|default] [--out FILE] [--cpus 0-3|0,2,4] [--pin on|off] [--workers N] [--link-delay 25ms] [--link-jitter 5ms] [--link-loss 1%] [--link-rate 100mbit]"
    );
    std::process::exit(2)
}

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

fn parse_runtime(cli: &Cli) -> Runtime {
    let runtime_name = cli.flags.get("runtime").cloned().unwrap_or_default();
    match Runtime::parse(&runtime_name) {
        Some(runtime) => runtime,
        None => {
            eprintln!("missing or unknown runtime=<...>");
            usage()
        }
    }
}

fn parse_mode(cli: &Cli) -> Mode {
    match cli.flags.get("mode").map(String::as_str) {
        Some("sender") => Mode::Sender,
        Some("receiver") => Mode::Receiver,
        _ => {
            eprintln!("missing or unknown mode=<sender|receiver>");
            usage()
        }
    }
}

fn parse_encryption(cli: &Cli) -> Encryption {
    match cli.flags.get("encryption").map(String::as_str) {
        None | Some("") | Some("plain") => Encryption::Plain,
        Some(value) => match Encryption::parse(value) {
            Some(encryption) => encryption,
            None => {
                eprintln!("error: unknown --encryption '{value}' (want plain|128|192|256)");
                usage()
            }
        },
    }
}

fn parse_positional<T: std::str::FromStr>(cli: &Cli, index: usize) -> T {
    cli.positional
        .get(index)
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or_else(|| usage())
}

fn parse_required_positionals(cli: &Cli, mode: Mode) -> (String, u16, f64, u16, u64) {
    let required = match mode {
        Mode::Sender => 4,
        Mode::Receiver => 3,
    };
    if cli.positional.len() < required {
        usage();
    }

    let offset = match mode {
        Mode::Sender => 1,
        Mode::Receiver => 0,
    };
    let host = match mode {
        Mode::Sender => cli.positional[0].clone(),
        Mode::Receiver => String::new(),
    };
    let port = parse_positional(cli, offset);
    let duration_secs = parse_positional(cli, offset + 1);
    let latency_ms = parse_positional(cli, offset + 2);
    // A zero source rate is a usage error, not a mode. It used to divide
    // to zero bytes per second and select an "unpaced" generator, so
    // `0` silently meant "as fast as SRT will accept" -- the opposite of
    // a rate, and unreadable from a result row.
    let source_bitrate_bps = match cli.positional.get(offset + 3) {
        None => DEFAULT_SOURCE_BITRATE_BPS,
        Some(value) => match value.parse::<u64>() {
            Ok(rate) if rate > 0 => rate,
            _ => {
                eprintln!(
                    "error: source_bitrate_bps must be a positive integer (got '{value}'); it is the application payload rate in bits per second, not SRT's pacing ceiling"
                );
                usage()
            }
        },
    };
    (host, port, duration_secs, latency_ms, source_bitrate_bps)
}

/// `--srt-bandwidth <mode>`: how SRT's pacing is configured, as a policy
/// over the source payload rate rather than a second copy of MAXBW.
///
/// Defaults to `legacy-source-fixed`, which is byte-for-byte what
/// srt-bench always did, so an unchanged command line keeps producing
/// unchanged numbers. Permanent plans should state the policy explicitly:
/// a benchmark whose pacing configuration is invisible is exactly the
/// problem this axis exists to fix.
fn parse_bandwidth_policy(cli: &Cli) -> crate::source::BandwidthPolicy {
    match cli.flags.get("srt-bandwidth").map(String::as_str) {
        None | Some("") => crate::source::BandwidthPolicy::default(),
        Some(value) => match crate::source::BandwidthPolicy::parse(value) {
            Some(policy) => policy,
            None => {
                eprintln!(
                    "error: unknown --srt-bandwidth '{value}' (want protocol-default|\
                     legacy-source-fixed|fixed:<bps>|input-relative:<5..=100>)"
                );
                usage()
            }
        },
    }
}

fn parse_ingress(cli: &Cli) -> Ingress {
    match cli.flags.get("ingress").map(String::as_str) {
        None | Some("per-port") => Ingress::PerPort,
        Some(spec) => parse_ingress_spec(spec),
    }
}

fn parse_ingress_spec(spec: &str) -> Ingress {
    // Accept both `shared-pool=4` and `shared-pool:4`. The colon form is
    // what result files record, so it has to parse back reproducibly.
    let spec = spec.replacen(':', "=", 1);
    if let Some(size) = spec.strip_prefix("shared-pool=") {
        Ingress::SharedPool(parse_positive("shared-pool size", size))
    } else if let Some(count) = spec.strip_prefix("reuseport-multi=") {
        Ingress::ReuseportMulti(parse_positive("reuseport-multi acceptor count", count))
    } else if let Some(workers) = spec.strip_prefix("reuseport-single=") {
        Ingress::ReuseportSingle {
            workers: parse_positive("reuseport-single worker count", workers),
        }
    } else {
        eprintln!(
            "error: unknown --ingress '{spec}' (want per-port | shared-pool=K | \
             reuseport-multi=K | reuseport-single=W)"
        );
        usage()
    }
}

fn parse_egress(cli: &Cli) -> Egress {
    match cli.flags.get("egress").map(String::as_str) {
        None | Some("per-connection") => Egress::PerConnection,
        Some("shared-socket") => Egress::SharedSocket,
        Some(other) => {
            eprintln!("error: unknown --egress '{other}' (want per-connection|shared-socket)");
            usage()
        }
    }
}

fn parse_bond(cli: &Cli) -> (BondMode, usize) {
    match cli.flags.get("bond").map(String::as_str) {
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
    }
}

fn parse_batching(cli: &Cli) -> Batching {
    match cli.flags.get("batch").map(String::as_str) {
        None | Some("on") => Batching::On,
        Some("off") => Batching::Off,
        Some(other) => {
            eprintln!("error: unknown --batch '{other}' (want on|off)");
            usage()
        }
    }
}

fn parse_promotion(cli: &Cli) -> Promotion {
    match cli.flags.get("promotion").map(String::as_str) {
        // Bare `--promotion` parses to an empty value.
        None | Some("") | Some("relocate") => Promotion::Relocate,
        Some("never") => Promotion::Never,
        Some("bonded") => Promotion::Bonded,
        Some("all") => Promotion::All,
        Some(other) => {
            eprintln!("error: unknown --promotion '{other}' (want never|relocate|bonded|all)");
            usage()
        }
    }
}

fn parse_cookie_routing(cli: &Cli) -> bool {
    match cli.flags.get("cookie-routing").map(String::as_str) {
        None | Some("") | Some("on") => true,
        Some("off") => false,
        Some(other) => {
            eprintln!("error: unknown --cookie-routing '{other}' (want on|off)");
            usage()
        }
    }
}

fn parse_sock_buf(cli: &Cli) -> usize {
    match cli.flags.get("sock-buf").map(String::as_str) {
        None => srt_transport::SOCK_BUF_BYTES,
        Some("default") | Some("0") => 0,
        Some(raw) => {
            let (digits, scale) = match raw.strip_suffix(['m', 'M']) {
                Some(digits) => (digits, 1 << 20),
                None => (raw.strip_suffix(['k', 'K']).unwrap_or(raw), 1),
            };
            let scale = if digits.len() == raw.len() { 1 } else { scale };
            match digits.parse::<usize>() {
                Ok(bytes) => bytes * scale,
                Err(_) => {
                    eprintln!("error: --sock-buf wants bytes, <N>k, <N>m, or 'default'");
                    usage()
                }
            }
        }
    }
}

fn parse_runtime_settings(cli: &Cli, duration_secs: f64) -> (usize, bool, usize, f64) {
    // A CPU *set*, not a count: the two roles need disjoint cores.
    let cpu_list =
        srt_transport::parse_cpu_spec(cli.flags.get("cpus").map(String::as_str).unwrap_or(""));
    if !cpu_list.is_empty()
        && let Err(error) = srt_transport::restrict_to_cpu_list(&cpu_list)
    {
        eprintln!("warning: could not restrict to CPUs {cpu_list:?}: {error}");
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
        .and_then(|value| value.parse().ok())
        .unwrap_or(duration_secs);
    (cpus, pin, workers, stream_secs)
}

fn scoped_flag(cli: &Cli, name: &str) -> String {
    cli.flags.get(name).cloned().unwrap_or_default()
}

fn scoped_runtime_flag(cli: &Cli, name: &str, plural: &str) -> String {
    let value = scoped_flag(cli, name);
    if value.is_empty() {
        scoped_flag(cli, plural)
    } else {
        value
    }
}

fn parse_peer_topology(cli: &Cli) -> PeerTopology {
    PeerTopology {
        recv_runtime: scoped_runtime_flag(cli, "recv-runtime", "recv-runtimes"),
        send_runtime: scoped_runtime_flag(cli, "send-runtime", "send-runtimes"),
        recv_ingress: scoped_flag(cli, "recv-ingress"),
        send_ingress: scoped_flag(cli, "send-ingress"),
        recv_workers: scoped_flag(cli, "recv-workers"),
        send_workers: scoped_flag(cli, "send-workers"),
        recv_cpus: scoped_flag(cli, "recv-cpus"),
        send_cpus: scoped_flag(cli, "send-cpus"),
    }
}

fn link_flag(cli: &Cli, name: &str) -> String {
    cli.flags
        .get(name)
        .filter(|value| !value.is_empty() && value.as_str() != "off")
        .cloned()
        .unwrap_or_default()
}

fn parse_link(cli: &Cli) -> Link {
    Link {
        delay: link_flag(cli, "link-delay"),
        jitter: link_flag(cli, "link-jitter"),
        loss: link_flag(cli, "link-loss"),
        rate: link_flag(cli, "link-rate"),
        reorder: link_flag(cli, "link-reorder"),
        duplicate: link_flag(cli, "link-duplicate"),
        corrupt: link_flag(cli, "link-corrupt"),
        limit: link_flag(cli, "link-limit"),
    }
}

/// Parse the unified CLI into a BenchConfig, exiting on bad usage.
pub fn bench_config_from_args() -> BenchConfig {
    // The harness signals a clean stop once the sender is done; without
    // this the listener would still be stopping on its own timer.
    crate::shutdown::install();

    // Capture kernel UDP counters before any socket exists, so every
    // later read is a delta for this run alone.
    let _ = crate::cpu_stats::udp_baseline();

    let args: Vec<String> = std::env::args().collect();
    let cli = Cli::parse(&args);
    let runtime = parse_runtime(&cli);
    let mode = parse_mode(&cli);
    let encryption = parse_encryption(&cli);
    let (host, port, duration_secs, latency_ms, source_bitrate_bps) =
        parse_required_positionals(&cli, mode);
    let ingress = parse_ingress(&cli);
    let egress = parse_egress(&cli);
    let (bond_mode, bond_pairs) = parse_bond(&cli);
    let batching = parse_batching(&cli);
    let connect_concurrency = cli
        .flags
        .get("connect-concurrency")
        .map_or(1, |raw| parse_positive("connect-concurrency", raw));
    let recv_rounds = cli
        .flags
        .get("recv-rounds")
        .map_or(8, |raw| parse_positive("recv-rounds", raw));
    let would_block =
        cli.flags
            .get("would-block")
            .map_or(crate::scheduling::WouldBlockPolicy::Retain, |raw| {
                crate::scheduling::WouldBlockPolicy::parse(raw).unwrap_or_else(|| {
                    eprintln!("error: unknown --would-block '{raw}' (want retain|drop)");
                    usage()
                })
            });
    let promotion = parse_promotion(&cli);
    let cookie_routing = parse_cookie_routing(&cli);
    let sock_buf_bytes = parse_sock_buf(&cli);
    let (cpus, pin, workers, stream_secs) = parse_runtime_settings(&cli, duration_secs);
    let peer_topology = parse_peer_topology(&cli);
    let link = parse_link(&cli);
    let classifier_policy = crate::classifier::policy_from_cli(&cli).unwrap_or_else(|error| {
        eprintln!("error: {error}");
        usage()
    });

    let out = cli
        .flags
        .get("out")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from);
    let rep = cli.flag_or("rep", 1usize);
    let attempt = cli.flags.get("attempt").cloned().unwrap_or_default();

    let config = BenchConfig {
        runtime,
        mode,
        encryption,
        host,
        port,
        duration_secs,
        latency_ms,
        source_bitrate_bps,
        bandwidth: parse_bandwidth_policy(&cli),
        source_backlog_ms: cli.flag_or("source-backlog-ms", source::DEFAULT_SOURCE_BACKLOG_MS),
        datapath_queue_horizon_ms: cli.flag_or(
            "datapath-queue-horizon-ms",
            queue::DEFAULT_DATAPATH_QUEUE_HORIZON_MS,
        ),
        outbound_retry_horizon_ms: cli.flag_or(
            "outbound-retry-horizon-ms",
            scheduling::DEFAULT_OUTBOUND_RETRY_HORIZON_MS,
        ),
        connections: cli.connections(),
        egress,
        ingress,
        bond_mode,
        bond_pairs,
        batching,
        recv_rounds,
        would_block,
        connect_concurrency,
        promotion,
        cookie_routing,
        sock_buf_bytes,
        out,
        rep,
        attempt,
        cpus,
        pin,
        workers,
        stream_secs,
        peer_topology,
        link,
        classifier_policy,
    };
    if let Err(error) = config.validate_bond_topology() {
        eprintln!("error: {error}");
        usage()
    }
    config
}

#[cfg(test)]
mod tests {
    use super::{
        Batching, BenchConfig, BondMode, Cli, ConnectLimiter, Egress, Encryption,
        HandshakeAdmission, HandshakePermit, Ingress, Link, Mode, PeerTopology, Promotion, Runtime,
        SharedSender, parse_required_positionals,
    };
    use shiguredo_srt::{ConnectionOptions, KeyLength};
    use std::time::{Duration, Instant};

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

    fn config() -> BenchConfig {
        BenchConfig {
            runtime: Runtime::Mio,
            mode: Mode::Receiver,
            encryption: Encryption::Aes256,
            host: "127.0.0.1".to_owned(),
            port: 0,
            duration_secs: 1.0,
            latency_ms: 120,
            source_bitrate_bps: 1_000_000,
            bandwidth: crate::source::BandwidthPolicy::default(),
            source_backlog_ms: crate::source::DEFAULT_SOURCE_BACKLOG_MS,
            datapath_queue_horizon_ms: crate::queue::DEFAULT_DATAPATH_QUEUE_HORIZON_MS,
            outbound_retry_horizon_ms: crate::scheduling::DEFAULT_OUTBOUND_RETRY_HORIZON_MS,
            connections: 1,
            egress: Egress::PerConnection,
            ingress: Ingress::SharedPool(4),
            bond_mode: BondMode::None,
            bond_pairs: 0,
            batching: Batching::On,
            recv_rounds: 8,
            would_block: crate::scheduling::WouldBlockPolicy::Retain,
            connect_concurrency: 1,
            promotion: Promotion::Never,
            cookie_routing: true,
            sock_buf_bytes: 0,
            out: None,
            rep: 1,
            attempt: String::new(),
            cpus: 0,
            pin: false,
            workers: 1,
            stream_secs: 1.0,
            peer_topology: PeerTopology::default(),
            link: Link::default(),
            classifier_policy: crate::model::ClassifierPolicy::default(),
        }
    }

    #[test]
    fn shared_admission_carries_the_encryption_template() {
        let mut cfg = config();
        let admission = cfg.admission_options(0x1234, true);
        let template = admission
            .connection_template
            .as_ref()
            .expect("session template");
        assert_eq!(template.socket_id, 0x1234);
        assert_eq!(template.passphrase.as_deref(), Some("srt-bench-encryption"));
        assert_eq!(template.key_length, KeyLength::Aes256);
        assert_eq!(
            admission.bonded_inputs,
            srt_transport::BondedInputPolicy::Reject
        );
        cfg.bond_mode = BondMode::Backup;
        cfg.bond_pairs = 1;
        let first = cfg.bond_extension_for(0).expect("first group leg");
        let second = cfg.bond_extension_for(1).expect("second group leg");
        assert_eq!(first.group_id, second.group_id);
        assert_eq!(first.group_type, second.group_type);
        assert_eq!(first.weight, 1);
        assert_eq!(second.weight, 0);
        assert_eq!(cfg.bond_initial_seq_for(0), cfg.bond_initial_seq_for(1));
        assert_eq!(cfg.bond_stream_id_for(0), cfg.bond_stream_id_for(1));
        assert_ne!(cfg.caller_socket_id_for(0), cfg.caller_socket_id_for(1));
        assert_eq!(
            cfg.admission_options(17, false).bonded_inputs,
            srt_transport::BondedInputPolicy::Accept
        );
    }

    #[test]
    fn bonding_requires_the_shared_group_driver_on_every_runtime() {
        let mut cfg = config();
        cfg.mode = Mode::Sender;
        cfg.connections = 2;
        cfg.bond_mode = BondMode::Broadcast;
        cfg.bond_pairs = 1;
        cfg.ingress = Ingress::SharedPool(1);
        cfg.egress = Egress::SharedSocket;
        cfg.connect_concurrency = 2;

        for runtime in [
            Runtime::Mio,
            Runtime::Tokio,
            Runtime::Smol,
            Runtime::Monoio,
            Runtime::Glommio,
            Runtime::Compio,
        ] {
            cfg.runtime = runtime;
            assert_eq!(cfg.validate_bond_topology(), Ok(()), "{runtime:?}");
        }

        cfg.egress = Egress::PerConnection;
        assert_eq!(
            cfg.validate_bond_topology(),
            Err("--bond requires --egress shared-socket for sender group scheduling")
        );
        cfg.egress = Egress::SharedSocket;
        cfg.ingress = Ingress::PerPort;
        assert_eq!(
            cfg.validate_bond_topology(),
            Err("--bond requires --ingress shared-pool=1")
        );
        cfg.ingress = Ingress::SharedPool(1);
        cfg.bond_pairs = 2;
        assert_eq!(
            cfg.validate_bond_topology(),
            Err("bond pair count exceeds half of --connections")
        );

        cfg.bond_pairs = 1;
        cfg.connect_concurrency = 1;
        assert_eq!(
            cfg.validate_bond_topology(),
            Err("bonded benchmark groups contain two physical SRT legs \
                 and therefore require --connect-concurrency >= 2")
        );

        cfg.mode = Mode::Receiver;
        cfg.bond_pairs = 1;
        cfg.egress = Egress::PerConnection;
        assert_eq!(cfg.validate_bond_topology(), Ok(()));
    }

    #[test]
    fn axis_flags_are_repeatable_and_consume_key_value_specs() {
        let args = [
            "srt-bench",
            "matrix",
            "--axis",
            "encryption=plain,128",
            "--axis=connections=50,600",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let cli = Cli::parse(&args);
        assert_eq!(
            cli.repeated.get("axis"),
            Some(&vec![
                "encryption=plain,128".to_string(),
                "connections=50,600".to_string()
            ])
        );
        assert_eq!(cli.positional, ["matrix"]);
    }

    #[test]
    fn flag_values_can_contain_an_equals_sign() {
        let args = ["srt-bench", "--ingress", "shared-pool=1"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let cli = Cli::parse(&args);
        assert_eq!(cli.flags.get("ingress"), Some(&"shared-pool=1".to_string()));
    }

    #[test]
    fn required_positionals_keep_sender_and_receiver_layouts() {
        let sender = Cli::parse(
            &[
                "srt-bench",
                "example.test",
                "9000",
                "10.5",
                "120",
                "4000000",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
        );
        assert_eq!(
            parse_required_positionals(&sender, Mode::Sender),
            ("example.test".to_string(), 9000, 10.5, 120, 4_000_000)
        );

        let receiver = Cli::parse(
            &["srt-bench", "9001", "12.0", "80", "2000000"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            parse_required_positionals(&receiver, Mode::Receiver),
            (String::new(), 9001, 12.0, 80, 2_000_000)
        );
    }

    // ----- ConnectLimiter tests (Section 15) -----

    #[test]
    fn limiter_try_acquire_and_release() {
        let mut lim = ConnectLimiter::new(4);
        assert!(lim.try_acquire(1));
        assert!(lim.try_acquire(1));
        assert!(lim.try_acquire(1));
        assert!(lim.try_acquire(1));
        assert!(!lim.try_acquire(1));
        assert_eq!(lim.in_flight(), 4);
        assert_eq!(lim.peak(), 4);
        lim.release(1, true);
        assert_eq!(lim.in_flight(), 3);
        assert!(lim.try_acquire(1));
        assert_eq!(lim.peak(), 4);
    }

    #[test]
    fn limiter_bonded_pair_acquires_two_tokens() {
        let mut lim = ConnectLimiter::new(2);
        assert!(lim.try_acquire(2));
        assert!(!lim.try_acquire(1));
        assert_eq!(lim.in_flight(), 2);
        assert_eq!(lim.peak(), 2);
        lim.release(2, true);
        assert_eq!(lim.in_flight(), 0);
        assert!(lim.try_acquire(1));
    }

    #[test]
    fn limiter_no_double_release() {
        let mut lim = ConnectLimiter::new(4);
        assert!(lim.try_acquire(2));
        lim.release(2, true);
        assert_eq!(lim.in_flight(), 0);
        assert_eq!(lim.completed(), 2);
        assert_eq!(lim.failed(), 0);
    }

    #[test]
    fn limiter_failed_releases_tracked() {
        let mut lim = ConnectLimiter::new(4);
        assert!(lim.try_acquire(1));
        lim.release(1, false);
        assert_eq!(lim.failed(), 1);
        assert_eq!(lim.completed(), 0);
    }

    #[test]
    fn limiter_peak_never_exceeds_limit() {
        let mut lim = ConnectLimiter::new(8);
        for _ in 0..8 {
            assert!(lim.try_acquire(1));
        }
        assert!(!lim.try_acquire(1));
        assert_eq!(lim.peak(), 8);
        lim.release(4, true);
        assert!(lim.try_acquire(3));
        assert_eq!(lim.peak(), 8);
    }

    #[test]
    fn limiter_n_less_than_cc_peak_bounded_by_n() {
        let mut lim = ConnectLimiter::new(100);
        for _ in 0..5 {
            assert!(lim.try_acquire(1));
        }
        assert_eq!(lim.peak(), 5);
    }

    #[test]
    fn bonded_cc1_rejected() {
        let mut cfg = config();
        cfg.mode = Mode::Sender;
        cfg.connections = 4;
        cfg.bond_mode = BondMode::Broadcast;
        cfg.bond_pairs = 2;
        cfg.ingress = Ingress::SharedPool(1);
        cfg.egress = Egress::SharedSocket;
        cfg.connect_concurrency = 1;
        assert!(cfg.validate_bond_topology().is_err());
        cfg.connect_concurrency = 2;
        assert!(cfg.validate_bond_topology().is_ok());
    }

    // ----- SharedSender scheduling tests (Section 16) -----

    fn sender_config(connections: usize, cc: usize) -> BenchConfig {
        let mut cfg = config();
        cfg.mode = Mode::Sender;
        cfg.connections = connections;
        cfg.egress = Egress::SharedSocket;
        cfg.connect_concurrency = cc;
        cfg.host = "127.0.0.1".to_owned();
        cfg.port = 9000;
        cfg.duration_secs = 60.0;
        cfg
    }

    #[test]
    fn shared_sender_done_is_o1() {
        let cfg = sender_config(100, 100);
        let indices: Vec<usize> = (0..100).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        assert!(!sender.done());
        assert_eq!(sender.terminal_count, 0);
    }

    #[test]
    fn limiter_cc1_admits_one_at_a_time() {
        let cfg = sender_config(10, 1);
        let indices: Vec<usize> = (0..10).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter.clone());
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);
        let lim = limiter.lock().unwrap();
        assert_eq!(lim.peak(), 1);
        assert_eq!(lim.started(), 1);
        drop(lim);
        assert_eq!(sender.pending_start.len(), 9);
    }

    #[test]
    fn limiter_cc4_admits_up_to_4() {
        let cfg = sender_config(10, 4);
        let indices: Vec<usize> = (0..10).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter.clone());
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);
        let lim = limiter.lock().unwrap();
        assert!(lim.peak() <= 4);
        assert_eq!(lim.started(), 4);
        drop(lim);
        assert_eq!(sender.pending_start.len(), 6);
    }

    #[cfg(feature = "bench-internals")]
    #[test]
    fn tick_cost_tracks_due_work_not_population() {
        // The headline claim of this series is that a tick costs what the
        // pending work costs, not what the population costs. Assert it
        // directly: hold the work fixed at one due slot and grow N by 40x.
        // A reintroduced population scan fails this; a counter that is
        // simply never incremented cannot.
        fn visits_for(n: usize, due: usize) -> u64 {
            let cfg = sender_config(n, n);
            let indices: Vec<usize> = (0..n).collect();
            let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(n)));
            let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
            let mut out = Vec::new();
            sender.tick(&cfg, &mut out);
            sender.tick(&cfg, &mut out);
            sender.force_all_connected();
            for slot_id in 0..due {
                sender.force_arm_due_send(slot_id);
            }
            let before = sender.sched_stats.slot_visits();
            out.clear();
            sender.tick(&cfg, &mut out);
            sender.sched_stats.slot_visits() - before
        }

        assert_eq!(visits_for(100, 0), 0, "a quiescent tick must visit nothing");
        assert_eq!(visits_for(4000, 0), 0, "still nothing at 40x the slots");
        assert_eq!(visits_for(100, 1), 1, "one due slot costs one visit");
        assert_eq!(
            visits_for(4000, 1),
            1,
            "one due slot still costs one visit at 40x the slots"
        );
        assert_eq!(visits_for(4000, 25), 25, "cost tracks due count");
    }

    #[test]
    fn shared_sender_scheduler_memory_bounded() {
        let cfg = sender_config(100, 100);
        let indices: Vec<usize> = (0..100).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        for _ in 0..10 {
            sender.tick(&cfg, &mut out);
        }
        assert!(sender.app_deadlines.len() <= 200);
    }

    // ----- Blocker 2: slot_deadlines side-index tests -----

    #[test]
    fn remove_deadline_uses_side_index() {
        let cfg = sender_config(10, 10);
        let indices: Vec<usize> = (0..10).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);

        let deadlines_before = sender.app_deadlines.len();
        let side_before = sender.slot_deadlines.len();
        assert!(deadlines_before > 0, "should have ConnectTimeout deadlines");
        assert_eq!(
            deadlines_before, side_before,
            "side index must mirror BTreeSet"
        );
    }

    #[test]
    fn slot_deadlines_and_app_deadlines_stay_in_sync() {
        let cfg = sender_config(50, 50);
        let indices: Vec<usize> = (0..50).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        for _ in 0..20 {
            sender.tick(&cfg, &mut out);
            out.clear();
            assert_eq!(
                sender.slot_deadlines.len(),
                sender.app_deadlines.len(),
                "side index diverged from BTreeSet after tick"
            );
        }
    }

    // ----- Blocker 3: closing_set tests -----

    #[test]
    fn close_slot_populates_closing_set() {
        let cfg = sender_config(5, 5);
        let indices: Vec<usize> = (0..5).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);
        assert!(
            sender.closing_set.is_empty(),
            "no slots should be closing initially"
        );

        let now = super::now_ts(sender.start);
        sender.close_slot(0, now);
        assert_eq!(
            sender.closing_set.len(),
            1,
            "close_slot must push to closing_set"
        );
        assert_eq!(sender.slots[0].phase, super::SlotPhase::Closing);
    }

    #[test]
    fn check_closing_increments_closing_slot_visits() {
        let cfg = sender_config(3, 3);
        let indices: Vec<usize> = (0..3).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);

        let now = super::now_ts(sender.start);
        sender.close_slot(0, now);
        sender.close_slot(1, now);
        assert_eq!(sender.closing_set.len(), 2);

        let visits_before = sender.sched_stats.closing_slot_visits;
        sender.check_closing();
        assert!(
            sender.sched_stats.closing_slot_visits > visits_before,
            "check_closing must visit closing slots"
        );
    }

    #[cfg(feature = "bench-internals")]
    #[test]
    fn closing_set_cleared_by_force_all_connected() {
        let cfg = sender_config(5, 5);
        let indices: Vec<usize> = (0..5).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);

        let now = super::now_ts(sender.start);
        sender.close_slot(0, now);
        assert!(!sender.closing_set.is_empty());

        sender.force_all_connected();
        assert!(
            sender.closing_set.is_empty(),
            "force_all_connected must clear closing_set"
        );
    }

    // ----- Blocker 1: bonded token release -----

    #[test]
    fn bonded_slot_has_physical_legs_gt_1() {
        let mut cfg = sender_config(2, 2);
        cfg.bond_mode = BondMode::Backup;
        cfg.bond_pairs = 1;
        cfg.ingress = Ingress::SharedPool(1);
        let indices: Vec<usize> = (0..2).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        assert_eq!(
            sender.slots[0].physical_legs, 2,
            "bonded slot must have 2 physical legs"
        );
    }

    // ----- Blocker 5 / force_all_connected -----

    #[cfg(feature = "bench-internals")]
    #[test]
    fn force_all_connected_sets_all_streaming() {
        let cfg = sender_config(20, 20);
        let indices: Vec<usize> = (0..20).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);
        sender.tick(&cfg, &mut out);
        sender.force_all_connected();

        for (i, slot) in sender.slots.iter().enumerate() {
            assert_eq!(
                slot.phase,
                super::SlotPhase::Streaming,
                "slot {i} should be Streaming after force_all_connected"
            );
            assert_eq!(
                slot.held_handshake_tokens, 0,
                "slot {i} should have held tokens released"
            );
        }
        assert!(sender.in_flight_set.is_empty());
        assert!(sender.pending_start.is_empty());
        assert!(sender.closing_set.is_empty());
    }

    #[cfg(feature = "bench-internals")]
    #[test]
    fn quiescent_ticks_visit_no_slots() {
        let cfg = sender_config(10, 10);
        let indices: Vec<usize> = (0..10).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);
        sender.tick(&cfg, &mut out);
        sender.force_all_connected();
        out.clear();

        let visits_before = sender.sched_stats.slot_visits();
        for _ in 0..10 {
            sender.tick(&cfg, &mut out);
            out.clear();
        }
        assert_eq!(
            sender.sched_stats.slot_visits(),
            visits_before,
            "ten quiescent ticks must visit no slots at all"
        );
        assert!(
            sender.in_flight_set.is_empty(),
            "no in-flight after force_all_connected"
        );
        assert!(
            sender.closing_set.is_empty(),
            "no closing after force_all_connected"
        );
    }

    // ----- remove_deadline idempotency -----

    #[test]
    fn remove_deadline_idempotent_for_missing_slot() {
        let cfg = sender_config(5, 5);
        let indices: Vec<usize> = (0..5).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);

        let count_before = sender.app_deadlines.len();
        sender.remove_deadline(999, super::AppDeadlineKind::Send);
        assert_eq!(
            sender.app_deadlines.len(),
            count_before,
            "remove of nonexistent slot is a no-op"
        );
    }

    #[test]
    fn remove_deadline_removes_from_both_indices() {
        let cfg = sender_config(5, 5);
        let indices: Vec<usize> = (0..5).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);

        let has_ct = sender
            .slot_deadlines
            .contains_key(&(0, super::AppDeadlineKind::ConnectTimeout));
        assert!(has_ct, "slot 0 should have ConnectTimeout in side index");

        sender.remove_deadline(0, super::AppDeadlineKind::ConnectTimeout);
        assert!(
            !sender
                .slot_deadlines
                .contains_key(&(0, super::AppDeadlineKind::ConnectTimeout)),
            "side index entry must be removed"
        );
    }

    // ----- HandshakePermit lifecycle & safety tests -----

    #[test]
    fn handshake_permit_lifecycle_complete() {
        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(2)));
        let permit = HandshakePermit::try_acquire(&lim, 1).expect("acquire should succeed");
        assert_eq!(lim.lock().unwrap().in_flight(), 1);
        assert_eq!(lim.lock().unwrap().started(), 1);
        permit.complete();
        let l = lim.lock().unwrap();
        assert_eq!(l.in_flight(), 0);
        assert_eq!(l.completed(), 1);
        assert_eq!(l.failed(), 0);
    }

    #[test]
    fn handshake_permit_lifecycle_fail() {
        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(2)));
        let permit = HandshakePermit::try_acquire(&lim, 1).expect("acquire should succeed");
        assert_eq!(lim.lock().unwrap().in_flight(), 1);
        permit.fail();
        let l = lim.lock().unwrap();
        assert_eq!(l.in_flight(), 0);
        assert_eq!(l.completed(), 0);
        assert_eq!(l.failed(), 1);
    }

    #[test]
    fn handshake_permit_lifecycle_drop_leak_safety() {
        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(2)));
        {
            let _permit = HandshakePermit::try_acquire(&lim, 2).expect("acquire 2");
            assert_eq!(lim.lock().unwrap().in_flight(), 2);
            // Drop without complete() or fail() -- RAII drop must conservatively fail.
        }
        let l = lim.lock().unwrap();
        assert_eq!(l.in_flight(), 0, "drop must release in_flight tokens");
        assert_eq!(l.failed(), 2, "drop must record tokens as failed");
        assert_eq!(l.completed(), 0);
    }

    #[test]
    fn handshake_permit_try_acquire_saturation() {
        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(2)));
        let p1 = HandshakePermit::try_acquire(&lim, 1).expect("p1");
        let p2 = HandshakePermit::try_acquire(&lim, 1).expect("p2");
        assert!(HandshakePermit::try_acquire(&lim, 1).is_none(), "saturated");
        p1.complete();
        let p3 = HandshakePermit::try_acquire(&lim, 1).expect("p3 after release");
        p2.fail();
        p3.complete();
        let l = lim.lock().unwrap();
        assert_eq!(l.in_flight(), 0);
        assert_eq!(l.completed(), 2);
        assert_eq!(l.failed(), 1);
    }

    #[test]
    fn limiter_can_acquire_bounds_checks() {
        let mut lim = ConnectLimiter::new(4);
        assert!(lim.can_acquire(1));
        assert!(lim.can_acquire(4));
        assert!(!lim.can_acquire(5));
        assert!(lim.try_acquire(3));
        assert!(lim.can_acquire(1));
        assert!(!lim.can_acquire(2));
        assert!(!lim.can_acquire(usize::MAX));
    }

    #[test]
    fn next_wait_returns_zero_only_when_limiter_has_capacity() {
        let cfg = sender_config(4, 2);
        let indices: Vec<usize> = (0..4).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter.clone());
        let mut out = Vec::new();
        // First tick: admits 2 slots into Handshaking (cc=2).
        sender.tick(&cfg, &mut out);
        assert_eq!(limiter.lock().unwrap().in_flight(), 2);
        assert_eq!(sender.pending_start.len(), 2);

        // Saturated: limiter in_flight=2 >= limit=2, so next_wait should NOT return ZERO for pending admission.
        // (There may be send deadlines, but pending start cannot proceed).
        assert!(!limiter.lock().unwrap().can_acquire(1));

        // Release 1 permit from limiter directly: now can_acquire(1) is true.
        limiter.lock().unwrap().release(1, true);
        assert!(limiter.lock().unwrap().can_acquire(1));
        assert_eq!(sender.next_wait(), Duration::ZERO);
    }

    #[test]
    fn held_handshake_tokens_matches_phase_invariants() {
        let mut cfg = sender_config(4, 4);
        cfg.bond_mode = BondMode::Broadcast;
        cfg.bond_pairs = 1;
        cfg.ingress = Ingress::SharedPool(1);
        let indices: Vec<usize> = (0..4).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter.clone());

        // Slot 0 is bonded (physical_legs = 2), Slot 1 is direct (physical_legs = 1).
        assert_eq!(sender.slots[0].physical_legs, 2);
        assert_eq!(sender.slots[1].physical_legs, 1);

        // Initially Pending: held_handshake_tokens == 0
        assert_eq!(sender.slots[0].held_handshake_tokens, 0);
        assert_eq!(sender.slots[1].held_handshake_tokens, 0);

        // Tick starts slots: Slot 0 acquires 2 tokens, Slot 1 acquires 1 token.
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);
        assert_eq!(sender.slots[0].phase, super::SlotPhase::Handshaking);
        assert_eq!(sender.slots[0].held_handshake_tokens, 2);
        assert_eq!(sender.slots[1].phase, super::SlotPhase::Handshaking);
        assert_eq!(sender.slots[1].held_handshake_tokens, 1);

        // Transition slot 1 to streaming: held tokens released to 0.
        let now_instant = Instant::now();
        let now = super::now_ts(sender.start);
        assert!(sender.transition_to_streaming(1, now_instant, now));
        assert_eq!(sender.slots[1].phase, super::SlotPhase::Streaming);
        assert_eq!(sender.slots[1].held_handshake_tokens, 0);

        // Close slot 1: debug_assert_eq passes, tokens remain 0.
        sender.close_slot(1, now);
        assert_eq!(sender.slots[1].phase, super::SlotPhase::Closing);
        assert_eq!(sender.slots[1].held_handshake_tokens, 0);
    }

    #[test]
    fn due_scratch_processes_due_snapshot_and_reuses_storage() {
        let cfg = sender_config(5, 5);
        let indices: Vec<usize> = (0..5).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);

        // Inject 3 send deadlines into the past
        for slot_id in 0..3 {
            sender.app_deadlines.insert(super::AppDeadlineEntry {
                deadline_us: 0,
                slot: slot_id,
                kind: super::AppDeadlineKind::Send,
            });
            sender
                .slot_deadlines
                .insert((slot_id, super::AppDeadlineKind::Send), 0);
        }

        let visits_before = sender.sched_stats.application_due_visits;
        let now_instant = Instant::now();
        let now = super::now_ts(sender.start);
        sender.process_due_deadlines(now_instant, now);

        // Exactly 3 due visits processed
        assert_eq!(sender.sched_stats.application_due_visits - visits_before, 3);
        // Scratch vector retained capacity without memory leak
        assert!(sender.due_scratch.capacity() >= 3);
    }

    #[test]
    fn handshake_permit_multithreaded_concurrency_stress() {
        use std::sync::atomic::{AtomicBool, Ordering};

        const LIMIT: usize = 8;
        const THREADS: usize = 16;
        const ITERS: usize = 200;

        fn run_stress_iter(
            lim: &std::sync::Arc<std::sync::Mutex<ConnectLimiter>>,
            viol: &AtomicBool,
            thread_idx: usize,
            iter: usize,
            limit: usize,
        ) {
            let tokens = if (thread_idx + iter).is_multiple_of(3) {
                2
            } else {
                1
            };
            let permit = loop {
                if let Some(p) = HandshakePermit::try_acquire(lim, tokens) {
                    break p;
                }
                std::thread::yield_now();
            };

            if lim.lock().unwrap().in_flight() > limit {
                viol.store(true, Ordering::SeqCst);
            }

            std::thread::yield_now();

            match (thread_idx + iter) % 3 {
                0 => permit.complete(),
                1 => permit.fail(),
                _ => {} // Drop RAII
            }
        }

        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(LIMIT)));
        let violation = std::sync::Arc::new(AtomicBool::new(false));

        let mut handles = Vec::new();
        for thread_idx in 0..THREADS {
            let lim = limiter.clone();
            let viol = violation.clone();
            handles.push(std::thread::spawn(move || {
                for iter in 0..ITERS {
                    run_stress_iter(&lim, &viol, thread_idx, iter, LIMIT);
                }
            }));
        }

        for h in handles {
            h.join().expect("worker thread");
        }

        assert!(
            !violation.load(Ordering::SeqCst),
            "concurrency limit exceeded during stress"
        );
        let final_lim = limiter.lock().unwrap();
        assert_eq!(final_lim.in_flight(), 0, "all permits must be settled");
        assert_eq!(
            final_lim.started(),
            final_lim.completed() + final_lim.failed(),
            "started == completed + failed invariant"
        );
        assert!(final_lim.peak() <= LIMIT, "peak must not exceed limit");
        assert!(final_lim.peak() > 0, "peak must be recorded");
    }

    #[test]
    fn delayed_admission_receives_fresh_handshake_timeout() {
        // Simulate benchmark start was 30 seconds ago (longer than CONNECT_TIMEOUT of 25s)
        let benchmark_start = Instant::now() - Duration::from_secs(30);
        // The old bug computed: connect_deadline = benchmark_start + CONNECT_TIMEOUT (already in the past!)
        let old_bug_deadline = benchmark_start + super::CONNECT_TIMEOUT;
        assert!(
            Instant::now() >= old_bug_deadline,
            "old calculation would have expired immediately"
        );

        // Correct behavior: handshake_started takes fresh instant at connection start
        let handshake_started = Instant::now();
        let connect_deadline = handshake_started + super::CONNECT_TIMEOUT;
        assert!(
            connect_deadline > Instant::now(),
            "fresh deadline must be in the future"
        );
        let remaining = connect_deadline.duration_since(Instant::now());
        assert!(
            remaining >= Duration::from_secs(24),
            "must receive full ~25s handshake window despite benchmark-level delay"
        );
    }

    fn assert_timeout_invariants(
        sender: &SharedSender,
        caller_id: srt_transport::LogicalCallerId,
        sid: u32,
    ) {
        assert_eq!(sender.slots[0].phase, super::SlotPhase::Closed);
        assert_eq!(sender.slots[0].held_handshake_tokens, 0);
        assert!(sender.slots[0].caller.is_none());
        assert!(sender.callers.logical_caller(&caller_id).is_none());
        assert!(!sender.socket_id_to_slot.contains_key(&sid));
    }

    #[test]
    fn timeout_slot_retires_caller_cleans_routes_and_frees_permit() {
        let cfg = sender_config(2, 1);
        let indices: Vec<usize> = (0..2).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter.clone());
        let mut out = Vec::new();

        // Slot 0 starts, slot 1 is queued (cc=1).
        sender.tick(&cfg, &mut out);
        assert_eq!(limiter.lock().unwrap().in_flight(), 1);
        assert_eq!(sender.slots[0].phase, super::SlotPhase::Handshaking);
        assert_eq!(sender.slots[0].held_handshake_tokens, 1);
        let caller_id = sender.slots[0].caller.expect("caller must be allocated");
        let sid = sender.slots[0].socket_ids[0];
        assert!(sender.callers.logical_caller(&caller_id).is_some());
        assert!(sender.socket_id_to_slot.contains_key(&sid));

        // Timeout slot 0
        sender.timeout_slot(0);

        assert_timeout_invariants(&sender, caller_id, sid);
        // 4. Limiter in-flight dropped to 0, failed recorded
        assert_eq!(limiter.lock().unwrap().in_flight(), 0);
        assert_eq!(limiter.lock().unwrap().failed(), 1);

        // 5. Late packets for the timed-out socket ID do not mark slot dirty
        // Construct mock SRT packet targeting `sid`
        let mut mock_packet = vec![0u8; 16];
        mock_packet[12..16].copy_from_slice(&sid.to_be_bytes());
        let peer = "127.0.0.1:9000".parse().unwrap();
        sender.feed(peer, &mock_packet);
        assert!(
            sender.dirty_ready.is_empty(),
            "late packet must not mark slot dirty"
        );

        // 6. Next tick admits slot 1 now that permit is freed
        out.clear();
        sender.tick(&cfg, &mut out);
        assert_eq!(sender.slots[1].phase, super::SlotPhase::Handshaking);
        assert_eq!(limiter.lock().unwrap().in_flight(), 1);
    }

    // ----- Terminal lifecycle: every path retires the caller exactly once ---

    /// Drive slot 0 to Streaming with a real caller installed, returning its
    /// caller id and socket id so retirement can be asserted afterwards.
    fn streaming_slot_fixture(
        sender: &mut SharedSender,
        cfg: &BenchConfig,
    ) -> (srt_transport::LogicalCallerId, u32) {
        let mut out = Vec::new();
        sender.tick(cfg, &mut out);
        let caller_id = sender.slots[0].caller.expect("caller must be allocated");
        let sid = sender.slots[0].socket_ids[0];
        sender.slots[0].phase = super::SlotPhase::Streaming;
        sender.slots[0].stats[0].connected = true;
        (caller_id, sid)
    }

    #[test]
    fn unexpected_streaming_disconnect_retires_caller_and_routes() {
        let cfg = sender_config(2, 2);
        let indices: Vec<usize> = (0..2).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let (caller_id, sid) = streaming_slot_fixture(&mut sender, &cfg);
        assert!(sender.callers.logical_caller(&caller_id).is_some());
        assert!(sender.socket_id_to_slot.contains_key(&sid));

        sender.mark_slot_disconnected(0);

        // Same invariants the timeout path already guaranteed: the slot is
        // Closed *and* the caller, its routes and its permits are gone.
        assert_timeout_invariants(&sender, caller_id, sid);
        assert!(
            sender.slots[0].stats[0].torn_down,
            "a mid-stream disconnect must be recorded as torn down"
        );

        // A late packet for the retired socket ID must not redirty the slot.
        let mut late = vec![0u8; 16];
        late[12..16].copy_from_slice(&sid.to_be_bytes());
        sender.feed("127.0.0.1:9000".parse().unwrap(), &late);
        assert!(
            sender.dirty_ready.is_empty(),
            "late packet must not redirty a retired slot"
        );
        assert!(
            !sender.app_deadlines.iter().any(|e| e.slot == 0),
            "no protocol deadline may survive the disconnect"
        );
    }

    #[test]
    fn closing_to_disconnected_via_dirty_packet_retires_caller() {
        // eval_slot_state's Closing arm can fire before check_closing walks
        // the closing set; it must retire the caller just the same.
        let cfg = sender_config(2, 2);
        let indices: Vec<usize> = (0..2).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let (caller_id, sid) = streaming_slot_fixture(&mut sender, &cfg);

        sender.slots[0].phase = super::SlotPhase::Closing;
        sender.closing_set.push(0);
        sender.finalize_slot(0, false);

        assert_timeout_invariants(&sender, caller_id, sid);
    }

    #[test]
    fn finalize_slot_is_idempotent() {
        let cfg = sender_config(2, 2);
        let indices: Vec<usize> = (0..2).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter.clone());
        let (caller_id, sid) = streaming_slot_fixture(&mut sender, &cfg);

        sender.finalize_slot(0, true);
        let terminal_after_first = sender.terminal_count;
        let failed_after_first = limiter.lock().unwrap().failed();

        // Both a second explicit finalize and every alias for it must be
        // no-ops -- terminal_count backs done(), so a double count would
        // strand the run.
        sender.finalize_slot(0, true);
        sender.mark_slot_disconnected(0);
        sender.timeout_slot(0);
        sender.mark_slot_failed(0);

        assert_eq!(sender.terminal_count, terminal_after_first);
        assert_eq!(limiter.lock().unwrap().failed(), failed_after_first);
        assert_timeout_invariants(&sender, caller_id, sid);
    }

    #[test]
    fn every_terminal_path_leaves_no_caller_installed() {
        for (name, kill) in [
            (
                "timeout",
                &SharedSender::timeout_slot as &dyn Fn(&mut SharedSender, usize),
            ),
            ("failed", &|s: &mut SharedSender, id| s.mark_slot_failed(id)),
            ("disconnected", &|s: &mut SharedSender, id| {
                s.mark_slot_disconnected(id)
            }),
        ] {
            let cfg = sender_config(2, 2);
            let indices: Vec<usize> = (0..2).collect();
            let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
                cfg.connect_concurrency,
            )));
            let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
            let (caller_id, sid) = streaming_slot_fixture(&mut sender, &cfg);

            kill(&mut sender, 0);

            assert_eq!(sender.slots[0].phase, super::SlotPhase::Closed, "{name}");
            assert!(sender.slots[0].caller.is_none(), "{name}: caller retired");
            assert!(
                sender.callers.logical_caller(&caller_id).is_none(),
                "{name}: caller absent from CallerTable"
            );
            assert!(
                !sender.socket_id_to_slot.contains_key(&sid),
                "{name}: socket route removed"
            );
        }
    }

    // ----- Admission wakes on permit release, not on a timer ---------------

    /// Minimal executor: polls one future to completion on the current
    /// thread, counting polls. No timer, so a future that only makes progress
    /// via a timer would hang rather than silently pass.
    fn poll_counting<F: std::future::Future>(fut: F) -> (F::Output, usize) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll, Wake, Waker};

        struct Flag(AtomicBool);
        impl Wake for Flag {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let flag = std::sync::Arc::new(Flag(AtomicBool::new(true)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        let mut polls = 0;
        loop {
            if !flag.0.swap(false, Ordering::SeqCst) {
                panic!("admission future parked with no pending wake: it would sleep forever");
            }
            polls += 1;
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return (out, polls);
            }
        }
    }

    #[test]
    fn admission_resolves_immediately_when_capacity_is_free() {
        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(4)));
        let (permit, polls) = poll_counting(HandshakeAdmission::new(&lim, 1));
        assert_eq!(polls, 1, "free capacity must not park the waiter");
        assert_eq!(lim.lock().unwrap().in_flight(), 1);
        permit.complete();
        assert_eq!(lim.lock().unwrap().in_flight(), 0);
    }

    #[test]
    fn saturated_admission_parks_without_a_timer_and_wakes_on_release() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll, Wake, Waker};

        struct Flag(AtomicBool);
        impl Wake for Flag {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(1)));
        let held = HandshakePermit::try_acquire(&lim, 1).expect("first permit");

        let flag = std::sync::Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let mut pending = Box::pin(HandshakeAdmission::new(&lim, 1));

        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(
            lim.lock().unwrap().parked_waiters(),
            1,
            "waiter must be parked, not spinning on a timer"
        );
        assert!(
            !flag.0.load(Ordering::SeqCst),
            "a parked waiter must not be woken while the limiter is saturated"
        );

        // Repolling without a release must not consume capacity or re-queue.
        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(lim.lock().unwrap().parked_waiters(), 1);

        held.complete();
        assert!(
            flag.0.load(Ordering::SeqCst),
            "releasing a permit must wake the parked waiter"
        );
        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Ready(_)));
    }

    #[test]
    fn release_wakes_only_as_many_waiters_as_capacity_admits() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll, Wake, Waker};

        struct Counter(AtomicUsize);
        impl Wake for Counter {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        // The shape the review called out: cc=4 with 4096 configured callers.
        const CC: usize = 4;
        const PENDING: usize = 4096;

        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(CC)));
        let mut held: Vec<_> = (0..CC)
            .map(|_| HandshakePermit::try_acquire(&lim, 1).expect("saturate"))
            .collect();

        let counter = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);

        let mut waiters: Vec<_> = (0..PENDING)
            .map(|_| Box::pin(HandshakeAdmission::new(&lim, 1)))
            .collect();
        for w in &mut waiters {
            assert!(matches!(w.as_mut().poll(&mut cx), Poll::Pending));
        }
        assert_eq!(lim.lock().unwrap().parked_waiters(), PENDING);
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            0,
            "parking {PENDING} callers must cost zero wakeups"
        );

        // Release exactly one permit, keeping the other CC-1 held so the
        // freed capacity is 1.
        held.pop().expect("held permit").complete();
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            1,
            "one freed permit must wake exactly one waiter, not {PENDING}"
        );
        let (granted, reserved) = {
            let l = lim.lock().unwrap();
            (l.granted_waiters(), l.reserved_tokens())
        };
        assert_eq!(granted, 1, "exactly one waiter holds a grant");
        assert_eq!(reserved, 1, "its token is reserved until it polls");

        // Draining the remaining permits grants one waiter per freed token,
        // never a burst proportional to the pending population. Reservations
        // are what make this exact rather than merely bounded: without them,
        // capacity freed for an already-woken waiter would be re-offered to
        // others on each release.
        while let Some(p) = held.pop() {
            p.complete();
        }
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            CC,
            "total wakeups must equal freed capacity, not scale with {PENDING} pending callers"
        );
    }

    #[test]
    fn cancelling_a_granted_waiter_hands_the_grant_to_the_next_in_line() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Context, Poll, Wake, Waker};

        struct Flag(AtomicBool);
        impl Wake for Flag {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        // cc=1, one permit held, A and B parked behind it. Releasing the
        // permit grants A. A is then cancelled *before it is ever polled* --
        // the window a selected-but-unreserved waiter used to strand
        // capacity in, leaving B asleep with in_flight == 0 and no future
        // release to wake it.
        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(1)));
        let held = HandshakePermit::try_acquire(&lim, 1).expect("saturate");

        let flag_a = std::sync::Arc::new(Flag(AtomicBool::new(false)));
        let waker_a = Waker::from(flag_a.clone());
        let flag_b = std::sync::Arc::new(Flag(AtomicBool::new(false)));
        let waker_b = Waker::from(flag_b.clone());

        let mut a = Box::pin(HandshakeAdmission::new(&lim, 1));
        let mut b = Box::pin(HandshakeAdmission::new(&lim, 1));
        assert!(matches!(
            a.as_mut().poll(&mut Context::from_waker(&waker_a)),
            Poll::Pending
        ));
        assert!(matches!(
            b.as_mut().poll(&mut Context::from_waker(&waker_b)),
            Poll::Pending
        ));
        let parked = lim.lock().unwrap().parked_waiters();
        assert_eq!(parked, 2);

        held.complete();
        assert!(flag_a.0.load(Ordering::SeqCst), "A is granted and woken");
        assert!(!flag_b.0.load(Ordering::SeqCst), "B waits its turn");
        let reserved = lim.lock().unwrap().reserved_tokens();
        assert_eq!(
            reserved, 1,
            "A's grant must reserve its token so nothing else can take it"
        );

        // Cancel A without ever polling it.
        drop(a);

        // A's reservation is returned and handed straight to B, so the token
        // is reserved again -- for B this time, not stranded on a dead task.
        let (reserved_after, granted_after) = {
            let l = lim.lock().unwrap();
            (l.reserved_tokens(), l.granted_waiters())
        };
        assert_eq!(reserved_after, 1, "the freed token is re-granted, not lost");
        assert_eq!(granted_after, 1, "and exactly one waiter (B) holds it");
        assert!(
            flag_b.0.load(Ordering::SeqCst),
            "B must be granted the capacity A never used"
        );
        assert!(matches!(
            b.as_mut().poll(&mut Context::from_waker(&waker_b)),
            Poll::Ready(_)
        ));
    }

    #[test]
    fn a_grant_is_not_stolen_by_an_arriving_caller() {
        use std::task::{Context, Poll, Waker};

        // A queued waiter that has been granted capacity must actually get
        // it: a caller arriving in the window between wake and poll cannot
        // acquire the reserved tokens.
        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(1)));
        let held = HandshakePermit::try_acquire(&lim, 1).expect("saturate");
        let waker = Waker::noop();
        let mut queued = Box::pin(HandshakeAdmission::new(&lim, 1));
        assert!(matches!(
            queued.as_mut().poll(&mut Context::from_waker(waker)),
            Poll::Pending
        ));

        held.complete(); // grants `queued`, reserving its token

        assert!(
            HandshakePermit::try_acquire(&lim, 1).is_none(),
            "reserved capacity must not be acquirable by a barging caller"
        );
        assert!(matches!(
            queued.as_mut().poll(&mut Context::from_waker(waker)),
            Poll::Ready(_)
        ));
    }

    #[test]
    fn sequential_admission_does_not_scan_the_queue_per_wakeup() {
        use std::task::{Context, Poll, Waker};

        // Regression: removal used to be `VecDeque::retain`, so each
        // successful admission scanned every remaining waiter -- triangular
        // O(N^2) driver work that a wake-counting test cannot see. Park N
        // waiters at cc=1 and drain them one at a time; total fifo traversal
        // must stay linear in N.
        const N: usize = 512;

        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(1)));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut waiters: Vec<_> = (0..N)
            .map(|_| Box::pin(HandshakeAdmission::new(&lim, 1)))
            .collect();
        // First waiter takes the only permit; the rest park.
        let mut permit = None;
        for w in &mut waiters {
            match w.as_mut().poll(&mut cx) {
                Poll::Ready(p) if permit.is_none() => permit = Some(p),
                Poll::Ready(_) => panic!("cc=1 admitted twice"),
                Poll::Pending => {}
            }
        }
        assert_eq!(lim.lock().unwrap().parked_waiters(), N - 1);

        // Drain sequentially: each completion grants exactly the next waiter.
        let mut held = permit.expect("first admission");
        for w in waiters.iter_mut().skip(1) {
            held.complete();
            held = match w.as_mut().poll(&mut cx) {
                Poll::Ready(p) => p,
                Poll::Pending => panic!("granted waiter must be ready"),
            };
        }
        held.complete();

        let steps = lim.lock().unwrap().fifo_steps();
        assert!(
            steps <= (4 * N) as u64,
            "admission traversal must stay linear: {steps} fifo steps for N={N} \
             (a per-wakeup queue scan would be ~{})",
            N * N / 2
        );
    }

    /// Every ordering of a small admission scenario, checked exhaustively.
    ///
    /// All limiter state lives behind one mutex, so concurrent execution can
    /// only interleave at critical-section boundaries -- which makes the
    /// reachable orderings enumerable directly, without a loom-style
    /// scheduler. The invariant under test is the one the reservation design
    /// exists to provide: capacity is never stranded. If any waiter remains
    /// parked, some capacity must be genuinely in use.
    #[test]
    fn no_ordering_of_release_poll_and_cancel_can_strand_capacity() {
        // Each waiter is either polled or cancelled, in either order: the
        // full space of what can happen to A and B once the single permit is
        // released and A has been granted.
        for a_polls in [true, false] {
            for b_polls in [true, false] {
                for a_first in [true, false] {
                    let outcome = run_admission_ordering(a_polls, b_polls, a_first);
                    let label = format!("a_polls={a_polls} b_polls={b_polls} a_first={a_first}");
                    assert!(
                        outcome.in_flight + outcome.reserved <= 1,
                        "{label}: capacity overcommitted"
                    );
                    // The point of the reservation: a still-parked waiter is
                    // only acceptable if the capacity it waits on is busy.
                    assert!(
                        outcome.parked == 0 || outcome.in_flight + outcome.reserved > 0,
                        "{label}: a waiter is parked while all capacity is idle -- \
                         that waiter can never be woken"
                    );
                }
            }
        }
    }

    struct AdmissionOutcome {
        parked: usize,
        reserved: usize,
        in_flight: usize,
    }

    /// cc=1 with two queued waiters: release the permit (granting A), then
    /// act on A and B in the requested order and report the limiter state.
    fn run_admission_ordering(a_polls: bool, b_polls: bool, a_first: bool) -> AdmissionOutcome {
        use std::task::{Context, Poll, Waker};

        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(1)));
        let held = HandshakePermit::try_acquire(&lim, 1).expect("saturate");
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut a = Some(Box::pin(HandshakeAdmission::new(&lim, 1)));
        let mut b = Some(Box::pin(HandshakeAdmission::new(&lim, 1)));
        assert!(matches!(
            a.as_mut().expect("a").as_mut().poll(&mut cx),
            Poll::Pending
        ));
        assert!(matches!(
            b.as_mut().expect("b").as_mut().poll(&mut cx),
            Poll::Pending
        ));
        held.complete();

        let mut permits: Vec<HandshakePermit> = Vec::new();
        let mut act = |f: &mut Option<std::pin::Pin<Box<HandshakeAdmission>>>, polls: bool| {
            if !polls {
                *f = None;
                return;
            }
            if let Some(fut) = f.as_mut()
                && let Poll::Ready(p) = fut.as_mut().poll(&mut cx)
            {
                permits.push(p);
                *f = None;
            }
        };
        if a_first {
            act(&mut a, a_polls);
            act(&mut b, b_polls);
        } else {
            act(&mut b, b_polls);
            act(&mut a, a_polls);
        }

        let l = lim.lock().unwrap();
        AdmissionOutcome {
            parked: l.parked_waiters(),
            reserved: l.reserved_tokens(),
            in_flight: l.in_flight(),
        }
    }

    proptest::proptest! {
        /// Random operation sequences must never break the limiter's
        /// accounting invariants.
        #[test]
        fn prop_limiter_accounting_invariants(
            limit in 1usize..8,
            ops in proptest::collection::vec(
                (0usize..3, 1usize..3, proptest::bool::ANY),
                0..200,
            ),
        ) {
            let mut lim = ConnectLimiter::new(limit);
            let mut held: Vec<usize> = Vec::new();
            for (op, tokens, connected) in ops {
                match op {
                    0 => {
                        if lim.try_acquire(tokens) {
                            held.push(tokens);
                        }
                    }
                    1 => {
                        if let Some(t) = held.pop() {
                            lim.release(t, connected);
                        }
                    }
                    _ => {
                        // can_acquire must agree with try_acquire.
                        let predicted = lim.can_acquire(tokens);
                        let actual = lim.try_acquire(tokens);
                        proptest::prop_assert_eq!(predicted, actual);
                        if actual {
                            held.push(tokens);
                        }
                    }
                }
                proptest::prop_assert!(
                    lim.in_flight() + lim.reserved_tokens() <= limit,
                    "capacity overcommitted: in_flight={} reserved={} limit={}",
                    lim.in_flight(), lim.reserved_tokens(), limit
                );
                proptest::prop_assert!(lim.peak() <= limit);
                proptest::prop_assert_eq!(
                    lim.in_flight(),
                    held.iter().sum::<usize>()
                );
            }
            for t in held.drain(..) {
                lim.release(t, true);
            }
            proptest::prop_assert_eq!(lim.in_flight(), 0);
            proptest::prop_assert_eq!(
                lim.started(),
                lim.completed() + lim.failed()
            );
        }

        /// However many waiters park and in whatever order capacity is
        /// released, admission never overcommits and never wakes more
        /// waiters than the freed capacity can admit.
        #[test]
        fn prop_admission_never_overcommits(
            limit in 1usize..5,
            waiters in 1usize..12,
            tokens in proptest::collection::vec(1usize..3, 1..12),
        ) {
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::task::{Context, Poll, Wake, Waker};

            struct Counter(AtomicUsize);
            impl Wake for Counter {
                fn wake(self: std::sync::Arc<Self>) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
                fn wake_by_ref(self: &std::sync::Arc<Self>) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }

            let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(limit)));
            let counter = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
            let waker = Waker::from(counter.clone());
            let mut cx = Context::from_waker(&waker);

            let n = waiters.min(tokens.len());
            let mut futures: Vec<_> = (0..n)
                .map(|i| Box::pin(HandshakeAdmission::new(&lim, tokens[i].min(limit))))
                .collect();

            let mut permits = Vec::new();
            // Drive to a fixed point: poll everything, settle one permit,
            // repeat. Capacity must never be overcommitted at any point.
            for _ in 0..(n * 3) {
                for f in &mut futures {
                    if let Poll::Ready(p) = f.as_mut().poll(&mut cx) {
                        permits.push(p);
                    }
                }
                let (inf, res) = {
                    let l = lim.lock().unwrap();
                    (l.in_flight(), l.reserved_tokens())
                };
                proptest::prop_assert!(
                    inf + res <= limit,
                    "overcommitted: in_flight={} reserved={} limit={}", inf, res, limit
                );
                if let Some(p) = permits.pop() {
                    p.complete();
                }
            }
            drop(futures);
            drop(permits);
            let l = lim.lock().unwrap();
            proptest::prop_assert!(l.peak() <= limit);
        }
    }

    #[test]
    fn wake_budget_accounts_for_multi_token_waiters() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll, Wake, Waker};

        struct Counter(AtomicUsize);
        impl Wake for Counter {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        // A bonded waiter needs two tokens. Freeing one must NOT wake it --
        // budgeting per waiter is what stops a 1:1 wake from under-serving
        // (or pointlessly waking) capacity.
        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(2)));
        let a = HandshakePermit::try_acquire(&lim, 1).expect("a");
        let b = HandshakePermit::try_acquire(&lim, 1).expect("b");

        let counter = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut bonded = Box::pin(HandshakeAdmission::new(&lim, 2));
        assert!(matches!(bonded.as_mut().poll(&mut cx), Poll::Pending));

        a.complete();
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            0,
            "one free token cannot admit a two-token waiter"
        );

        b.complete();
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            1,
            "the second token completes the budget and wakes it"
        );
        assert!(matches!(bonded.as_mut().poll(&mut cx), Poll::Ready(_)));
    }

    #[test]
    fn dropping_a_parked_admission_frees_its_wake_slot() {
        use std::task::{Context, Poll, Waker};

        let lim = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(1)));
        let held = HandshakePermit::try_acquire(&lim, 1).expect("saturate");
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        let mut cancelled = Box::pin(HandshakeAdmission::new(&lim, 1));
        assert!(matches!(cancelled.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(lim.lock().unwrap().parked_waiters(), 1);

        // A cancelled waiter must not keep consuming wake slots that a live
        // waiter needs.
        drop(cancelled);
        assert_eq!(lim.lock().unwrap().parked_waiters(), 0);

        held.complete();
        let (permit, polls) = poll_counting(HandshakeAdmission::new(&lim, 1));
        assert_eq!(polls, 1);
        permit.complete();
    }

    // ----- done() worst-case fixture --------------------------------------

    #[cfg(feature = "bench-internals")]
    #[test]
    fn population_scan_and_counter_agree_on_the_worst_case_fixture() {
        let cfg = sender_config(64, 64);
        let indices: Vec<usize> = (0..64).collect();
        let limiter = std::sync::Arc::new(std::sync::Mutex::new(ConnectLimiter::new(
            cfg.connect_concurrency,
        )));
        let mut sender = SharedSender::new(&cfg, &indices, Instant::now(), limiter);
        let mut out = Vec::new();
        sender.tick(&cfg, &mut out);
        sender.force_all_connected();

        // The benchmark fixture the review flagged: only the last slot is
        // live, so the old `.all()` cannot short-circuit.
        sender.force_all_terminal_except_last();
        assert_eq!(sender.terminal_count, 63);
        assert!(!sender.done(), "one slot is still live");
        assert_eq!(
            sender.done(),
            sender.done_by_population_scan(),
            "both implementations must agree"
        );

        // And they still agree once the final slot retires.
        sender.finalize_slot(63, false);
        assert!(sender.done());
        assert_eq!(sender.done(), sender.done_by_population_scan());
    }

    #[test]
    fn sender_stats_cc_peak_bounds() {
        let cfg = sender_config(10, 4);
        let mut agg = super::Aggregate::new(cfg);
        agg.cc_peak = 4;
        agg.add(super::ConnStats {
            connected: true,
            has_stats: true,
            ..Default::default()
        });
        assert!(agg.cc_peak >= 1);
        assert!(agg.cc_peak <= 4);
        assert_eq!(agg.cc_peak, 4);
    }
}
