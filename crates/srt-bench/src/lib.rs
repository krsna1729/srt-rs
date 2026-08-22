//! Shared helpers for the srt-bench bench-caller/bench-listener binaries.

pub mod cpu_stats;
pub mod driver;
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

/// Fully-parsed configuration for one bench process invocation.
#[derive(Clone, Debug)]
pub struct LossConfig {
    pub runtime: Runtime,
    pub mode: Mode,
    /// Sender only: destination host.
    pub host: String,
    /// Base port. Sender connects to port+i, receiver binds port+i,
    /// for connection i in 0..connections.
    pub port: u16,
    pub duration_secs: f64,
    pub latency_ms: u16,
    pub bitrate_bps: u64,
    pub connections: usize,
    /// Listener ingress topology (receiver only).
    ///
    /// - `per-port`: today's default -- each connection owns a UDP socket
    ///   on its own port; N sockets, N wakeups.
    /// - `pool K`: K UDP sockets, round-robin over connection ports;
    ///   M>K connections multiplexed across them. One readiness event on
    ///   a pooled socket serves every connection whose peer sends to it.
    pub ingress: Ingress,
    /// Sender only: number of bonded groups to form. Connections
    /// `2*g`/`2*g+1` for `g` in `0..bond_groups` share a group id and are
    /// sent with a libsrt-compatible group extension (`GroupType::
    /// Broadcast`), exercising the pool receiver's bond-affinity handoff
    /// path. `0` disables bonding; connections beyond `2*bond_groups`
    /// are ordinary, non-bonded connections.
    pub bond_groups: usize,
}

/// Listener ingress topology. See [`LossConfig::ingress`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    PerPort,
    Pool(usize),
}

impl LossConfig {
    /// Destination/bind address for connection i.
    pub fn addr_for(&self, i: usize) -> std::net::SocketAddr {
        use std::net::{IpAddr, SocketAddr};
        let ip: IpAddr = match self.mode {
            Mode::Sender => self.host.parse().unwrap_or_else(|_| {
                format!("{host}", host = self.host)
                    .parse()
                    .unwrap_or(IpAddr::from([127, 0, 0, 1]))
            }),
            Mode::Receiver => IpAddr::from([0, 0, 0, 0]),
        };
        let port = match self.ingress {
            // Pooled listener: connection i's port is pool socket
            // (i % K)'s bind port, so senders land on a shared socket.
            Ingress::Pool(k) if self.mode == Mode::Receiver => self.port + (i % k) as u16,
            // Pooled sender: all K acceptors share one SO_REUSEPORT port on
            // the receiver side, so every sender dials the same base port
            // regardless of connection index -- there is only one port to
            // reach, never K distinct ones.
            Ingress::Pool(k) if self.mode == Mode::Sender && k > 1 => self.port,
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
    pub data_events: u64,
    pub core_total: u64,
    pub secondary_a: u64,
    pub secondary_b: u64,
    pub rtt_us: u64,
    pub has_stats: bool,
}

/// Accumulates ConnStats across connections and renders the STATS line.
pub struct Aggregate {
    pub config: LossConfig,
    pub data_events: u64,
    pub core_total: u64,
    pub secondary_a: u64,
    pub secondary_b: u64,
    pub rtt_sum_us: u64,
    pub stats_count: u64,
    pub any_connected: bool,
}

impl Aggregate {
    pub fn new(config: LossConfig) -> Self {
        Self {
            config,
            data_events: 0,
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
            println!(
                "STATS role={} backend={} connections={} pkt_sent={} core_total={} sec_a={} \
                 sec_b={} rtt_ms={:.3} elapsed_s={:.3} throughput_pps={:.0} cpu_user_ms={:.1} \
                 cpu_sys_ms={:.1} peak_rss_kb={}",
                role,
                c.runtime.name(),
                c.connections,
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
    }
}

/// Parse the unified CLI into a LossConfig, exiting on bad usage.
pub fn bench_config_from_args() -> LossConfig {
    fn usage() -> ! {
        eprintln!(
            "usage: srt-bench runtime=<mio|tokio|smol|monoio|glommio|compio> \
             mode=<sender|receiver> <host?> <port> <duration_secs> <latency_ms> \
             [bitrate_bps] [--connections N]"
        );
        std::process::exit(2)
    }

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

    let ingress = match cli.flags.get("ingress").map(String::as_str) {
        None | Some("per-port") => Ingress::PerPort,
        Some(pool) => match pool.strip_prefix("pool=").unwrap_or("").parse::<usize>() {
            Ok(0) | Err(_) => {
                eprintln!("error: pool size must be a positive integer (got '{pool}')");
                usage()
            }
            // Cap pool size at the connection count; more sockets than
            // connections is just per-port with extra bookkeeping.
            Ok(k) => Ingress::Pool(k.min(4096)),
        },
    };

    let bond_groups: usize = cli.flag_or("bond-groups", 0usize);

    LossConfig {
        runtime,
        mode,
        host,
        port,
        duration_secs,
        latency_ms,
        bitrate_bps,
        connections: cli.connections(),
        ingress,
        bond_groups,
    }
}
