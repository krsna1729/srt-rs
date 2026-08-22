# srt-bench

Standalone caller/listener binaries over
[`srt-protocol`](../srt-protocol) + [`srt-transport`](../srt-transport),
for wire-level interop testing and the six-runtime driver-framework
bake-off — without linking an application crate or libsrt.
`publish = false`.

One binary, **six runtime backends**, two roles:

| Backend | Execution model | Notes |
|---|---|---|
| `mio` | flat single-threaded epoll loop | only architecture sustaining line-rate at 600 conns (see below) |
| `tokio` | task-per-connection (`spawn_local` + `LocalSet`) | native `Sleep` timers |
| `smol` | task-per-connection (`async_executor::LocalExecutor`) | smol's own `block_on` needs `Send`; Conn timers are `!Send` |
| `monoio` | thread-per-core, completion-based | blocking recvs own their socket |
| `glommio` | thread-per-core (Linux-only, io_uring) | known listener starvation ≥300 conns — see `src/runtimes/glommio.rs` header |
| `compio` | completion-based | protocol task + never-cancelled reader task/channel per conn |

## Usage

```
srt-bench runtime=<mio|tokio|smol|monoio|glommio|compio> \
  mode=<sender|receiver> <host?> <port> <duration_secs> <latency_ms> \
  [bitrate_bps] [--connections N]
```

- Sender takes `<host>`; receiver doesn't. Defaults: bitrate 8 Mbps,
  connections 1.
- Connection *i* uses port+i on both sides.
- Loss mode and scale mode are the same code path per runtime — loss runs
  one connection, scale runs N; only the STATS schema differs.
- Receiver prints `LISTENING` when its sockets are bound.

### Orchestration scripts

```sh
./bakeoff.sh N_CONNECTIONS SECONDS   # all six runtimes back-to-back
./knee-sweep.sh 100 300 600 ...      # mio-only connection-count sweep
```

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

## Script behavior

`bakeoff.sh` / `knee-sweep.sh` run with `set -euo pipefail`, validate
arguments, probe for a free port before binding (bakeoff), and install a
cleanup trap that kills an orphaned receiver if the sender dies mid-run.
Raw per-process output lands under `./scratch/` (gitignored); caller exit
codes are surfaced — `rc=1` means never connected.

glommio requires an io_uring-capable Linux kernel; selecting it elsewhere
exits 2 with a message.
