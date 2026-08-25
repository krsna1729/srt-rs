# srt-bench

Standalone caller/listener binaries over
[`srt-protocol`](../srt-protocol) + [`srt-transport`](../srt-transport),
for wire-level interop testing and the six-runtime driver-framework
bake-off — without linking an application crate or libsrt.
`publish = false`.

One binary, **six runtime backends**, two roles. At startup it raises the
soft `RLIMIT_NOFILE` to the hard limit when permitted; `matrix` also prints a
host-capacity diagnostic, and `system-info` prints the same report on demand.

| Backend | Execution model | Notes |
|---|---|---|
| `mio` | flat single-threaded epoll loop | only architecture sustaining line-rate at 600 conns (see below) |
| `tokio` | task-per-connection (`spawn_local` + `LocalSet`) | native `Sleep` timers |
| `smol` | task-per-connection (`async_executor::LocalExecutor`) | smol's own `block_on` needs `Send`; Conn timers are `!Send` |
| `monoio` | thread-per-core, completion-based | blocking recvs own their socket |
| `glommio` | thread-per-core (Linux-only, io_uring) | known listener starvation ≥300 conns — see `src/runtimes/glommio.rs` header |
| `compio` | completion-based | protocol task + never-cancelled reader task/channel per conn |

## Usage

One binary, six subcommands: run a role, sweep a matrix of them, report on
the results, profile one pair, inspect host capacity, or watch a running
benchmark.

```
srt-bench runtime=<mio|tokio|smol|monoio|glommio|compio> \
  mode=<sender|receiver> <host?> <port> <duration_secs> <latency_ms> \
  [bitrate_bps] [--connections N] [--encryption plain|128|192|256]
  [--ingress …] [--egress per-connection|shared-socket] [--promotion …]
  [--cookie-routing on|off] [--batch on|off] [--sock-buf …]
  [--connect-concurrency N] [--bond …] [--out FILE]
```

- Sender takes `<host>`; receiver doesn't. Defaults: bitrate 8 Mbps,
  connections 1.
- `per-port` uses port+i; `shared-pool:K` maps connection *i* to
  `port + i % K`; reuseport topologies share the base port.
- Loss mode and scale mode are the same code path per runtime — loss runs
  one connection, scale runs N; only the STATS schema differs.
- Receiver prints `LISTENING` when its sockets are bound.

### Sweeping, reporting, profiling

```sh
# Cartesian product of the axes; one child process per role per cell.
srt-bench matrix --runtimes mio,tokio,smol,monoio,glommio,compio \
  --ingress per-port,shared-pool:4,reuseport-multi:4,reuseport-single:4 \
  --encryption plain,128,192,256 --promotion never,all \
  --connections 25,150 --reps 3 --out scratch/base.tsv

# Median table over a result file, grouped however the question demands.
srt-bench report scratch/base.tsv --by ingress,runtime

# Syscall / io_uring attribution for one pair (external dep: `perf`).
srt-bench sysprof --runtime glommio --connections 150

# Print the host settings that bound benchmark capacity.
srt-bench system-info

# Watch host pressure and kernel UDP drops while a benchmark runs.
srt-bench watch 5 12

# Explicitly override axes from a plan; repeat --axis for more axes.
srt-bench matrix --plan docs/plans/full-matrix.plan \
  --axis encryption=plain,128 --axis connections=50,600

# Broad early coverage, deterministic across runs.
srt-bench matrix --plan docs/plans/full-matrix.plan \
  --order interleaved --seed 0
```

Every axis is a comma-separated list; unspecified axes take one default
value. `egress=per-connection|shared-socket` controls whether callers use
distinct ephemeral UDP ports or one application-owned socket. Combined with
`ingress`, it can produce distinct-local/same-remote, same-local/distinct-
remote, or identical-four-tuple sessions. `encryption` selects plaintext or
AES-128/AES-192/AES-256 using a shared benchmark passphrase. A cell a runtime
does not implement is skipped and counted, so a gap in coverage reads as a
gap rather than as a failure.
For shared egress, `sock-buf` configures the shared socket itself. Matrix
filtering retains one sender `workers` and `connect-concurrency` value because
one shared socket has one owning runtime loop; independently scoped receiver
workers and every per-connection egress worker value remain variable.

The exhaustive matrix is filtered as its raw cartesian product is enumerated,
without retaining all raw cells in memory. This removes combinations that
cannot change behavior: promotion and cookie routing outside `reuseport-multi`,
batching outside mio's shared-socket paths, and pinning outside glommio. It
also removes bond-group requests larger than half the connection population and
bonded ingress outside the one group-aware `shared-pool:1` listener (the mio
pool and reuseport handoff paths do not yet own a logical group). One
representative value is retained for an inert axis, so a one-value custom plan
remains runnable. The filter summary is printed before the run and the
reported cell count is the filtered count.

Bonded cells with `egress=shared-socket` and `ingress=shared-pool:1` remain in
the matrix. SRT's shared UDP binding and Destination Socket IDs make those
identical-four-tuple legs valid protocol/group exercises. They do not provide
the independent network paths recommended for real redundancy, so their
results must not be interpreted as a path-diversity/failover measurement; see
[SRT bonding](https://github.com/Haivision/srt/blob/master/docs/features/bonding-intro.md).
In `srt-test-live`'s group syntax the equivalent shape is conceptually
`srt://*?type=broadcast&adapter=127.0.0.1&port=4000 127.0.0.1:5000 127.0.0.1:5000`:
the repeated nodes select the same remote endpoint and the inherited caller
bind options select one local endpoint. At the API level the unambiguous form
is two prepared group endpoints using that same source and destination; URI
parsing is an application convention, not part of the SRT wire protocol.

For the checked-in `full-matrix.plan`, the raw product is 4,423,680 cells and
the current capability-aware product is 67,200 cells. The harness recalculates
and prints both values, so this documentation cannot hide a future filtering
change. The omitted combinations are either no-op repetitions, over-capacity
bond requests, or topologies that cannot yet realize one logical bonded
ingress stream.

`docs/plans/bonded-ingress.plan` is the focused semantic sweep: it runs a
two-leg Broadcast and Backup publisher through the supported shared listener,
including every encryption mode. The receiver reports one established logical
stream, while its aggregate telemetry retains per-leg wire counters; the
caller still reports two physical legs.

[`docs/performance-loop.md`](../../docs/performance-loop.md) defines the
measurement gates and the small representative live plans used for iterative
hot-path work. It is intentionally separate from the exhaustive matrix: a
performance claim starts with a reproducible sentinel, then earns broader
coverage.

When a plan is present, ordinary flags such as `--encryption` are fallback
values for axes omitted by the plan. Use repeatable `--axis NAME=VALUE[,VALUE...]`
to intentionally override a plan; names use the canonical plan spelling
(`runtime`, `recv-runtime`, `connect-concurrency`, and so on). Duplicate or
unknown override names are rejected. The effective override and execution
order are printed at startup.

Execution order defaults to the historical Cartesian order. `--order
interleaved` round-robins the outer axes and schedules repetitions in rounds,
which gives a broad picture early and reduces time/order confounding.
`--order random --seed N` applies a deterministic seeded shuffle; keep the
startup log with the result file because it records the order and seed. Both
non-default modes spread repeated cells across the run rather than executing
all repetitions adjacent.

The process that has the numbers writes them and the process that reports
them reads the same columns back. `report --format github-benchmark` also
produces the JSON consumed by benchmark-action, so result conversion does
not require a second parser.

## Output contract

Each process prints exactly one final `STATS` line to stdout (grep-able;
scripts key off it). The sender exits **1** if it never connected.

Single connection (legacy schema):

```
STATS role=caller|listener backend=<runtime> pkt_sent=N core_total=N sec_a=N sec_b=N \
rtt_ms=F elapsed_s=F cpu_user_ms=F cpu_sys_ms=F peak_rss_kb=N
```

Scale mode adds `connections=N throughput_pps=F`.

Field semantics differ by role (sender/receiver stats come straight from
the protocol core's `SenderStats` / `ReceiverStats`):

| Field | Caller (sender) | Listener (receiver) |
|---|---|---|
| `pkt_sent` | data payloads pushed into the core | data events received |
| `core_total` | `total_sent` | `total_received` |
| `sec_a` | retransmits | lost |
| `sec_b` | packets in loss list | duplicates |
| `rtt_ms` | — | RTT estimate |

CPU/RSS via `getrusage(RUSAGE_SELF)` (`cpu_stats.rs`) so backends compare
fairly on resource cost, not just throughput.

## Layout

```
src/
├── main.rs        CLI entry -> parse config, dispatch runtime
├── lib.rs         Cli/LossConfig parsing, ConnStats/Aggregate + STATS rendering,
│                  shared constants (1316 B payload, 8 Mbps default, pacing knobs)
├── driver.rs      minimal blocking single-connection UDP driver (interop proof;
│                  `drain_outputs` reused by sustained drivers)
├── cpu_stats.rs   getrusage-based CPU/RSS accounting, framework-agnostic
└── runtimes/      one adapter file per backend + mod.rs dispatch
                   (scaling-architecture table + measured knee live there)
```

## Measured scaling knee (loopback bakeoff, 8 Mbps/conn)

- **≤ 300 conns** — task-per-connection models win: best latency
  isolation, zero retransmits for tokio/smol/monoio/compio.
- **600 conns** — hierarchy inverts. mio's flat epoll loop is the only
  architecture that sustains full line-rate (sent == received, zero
  loss). Per-task wakeup cost dominates at this density; task-per-conn
  runtimes hit flow-window stalls (sender buffers ~8192 pkts × 1316 B × N
  when ACK turnaround lags — the source of their GB-scale RSS).

Per-backend improvement leads (batched reads, ACK-drain priority, SQ-ring
sizing) are catalogued in `src/runtimes/mod.rs`.

## Build notes

```sh
cargo build --release -p srt-bench   # links all six transports
RUST_LOG=debug ./target/release/srt-bench …   # tracing to stderr
```

## Result files

With `--out FILE`, a run appends one TSV row per role. Columns are
defined once in `harness::COLUMNS` and cover both the configuration (every
axis) and the measurements, so `report` can group by any subset:

```
runtime  encryption  role  ingress  promotion  cookie  batch  sock_buf  conns  connect_cc
bond  bitrate  rep  established  pkt_sent  core_total  sec_a  sec_b  rtt_ms
elapsed_s  cpu_user_ms  cpu_sys_ms  peak_rss_kb
```

TSV rather than JSON: no dependency to read or write, greppable, and it
opens in a spreadsheet. Files are appended to, because a sweep is many
independent processes with no knowledge of their siblings. Raw output
lands under `./scratch/` (gitignored).

Appends are protected by an inter-process file lock. The header check and the
complete row write happen under that lock, so concurrent listener/caller
children cannot concatenate headers or rows. Readers reject malformed or
wrong-width files instead of silently truncating them and allowing a bad
resume/report.

Roles are separate child processes rather than threads on purpose: CPU is
measured with `getrusage`, which is per-process, so running both in one
would bill the sender's cost to the listener.

Method rule for anything recorded: same measurement window only, >=3
reps, and the `--release` profile — `--profile quick` omits LTO and is
not measurement-grade.

glommio requires an io_uring-capable Linux kernel; selecting it elsewhere
exits 2 with a message.
