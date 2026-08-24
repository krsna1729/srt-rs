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

One binary, five subcommands: run a role, sweep a matrix of them, report on
the results, profile one pair, or inspect host capacity.

```
srt-bench runtime=<mio|tokio|smol|monoio|glommio|compio> \
  mode=<sender|receiver> <host?> <port> <duration_secs> <latency_ms> \
  [bitrate_bps] [--connections N] [--encryption plain|128|192|256]
  [--ingress …] [--promotion …]
  [--cookie-routing on|off] [--batch on|off] [--sock-buf …]
  [--connect-concurrency N] [--bond …] [--out FILE]
```

- Sender takes `<host>`; receiver doesn't. Defaults: bitrate 8 Mbps,
  connections 1.
- Connection *i* uses port+i on both sides.
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
```

Every axis is a comma-separated list; unspecified axes take one default
value. `encryption` selects plaintext or AES-128/AES-192/AES-256 using a
shared benchmark passphrase. A cell a runtime does not implement is skipped
and counted, so a gap in coverage reads as a gap rather than as a failure.

The exhaustive matrix is filtered after its raw cartesian product is built.
This removes combinations that cannot change behavior: promotion and cookie
routing outside `reuseport-multi`, batching outside mio's shared-socket
paths, and pinning outside glommio. It also removes bond-group requests larger
than half the connection population. One representative value is retained for
an inert axis, so a one-value custom plan remains runnable. The filter summary
is printed before the run and the reported cell count is the filtered count.

For the checked-in `full-matrix.plan`, the raw product is 1,769,472 cells and
the capability-aware product is 142,464 cells. The omitted combinations are
not protocol experiments: they either repeat an identical runtime behavior or
request more bond pairs than the cell can contain.

This replaced a 344-line `bench.sh` that wrapped 86 lines of inline
Python whose only job was re-parsing this binary's own stdout. The
schema then lived in two places and drifted — adding a column silently
broke the median table. Now the process that has the numbers writes them
and the process that reports them reads the same columns back.

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

Roles are separate child processes rather than threads on purpose: CPU is
measured with `getrusage`, which is per-process, so running both in one
would bill the sender's cost to the listener.

Method rule for anything recorded: same measurement window only, >=3
reps, and the `--release` profile — `--profile quick` omits LTO and is
not measurement-grade.

glommio requires an io_uring-capable Linux kernel; selecting it elsewhere
exits 2 with a message.
