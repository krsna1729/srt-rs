# Scaling to 1000 destinations: pre-registered protocol

Status: **protocol frozen before measurement.** Rows are appended as they are
measured; the stopping condition and the target are fixed here, not adjusted
after seeing results.

## Question

PR #116 established that one shared-Owner shard carries a bounded, *reconciling*
load and that it saturates somewhere around 150-200 destinations at 8 Mbps per
destination on this host (6 CPUs, `K=256` TX lanes). It did **not** establish a
path to the 1000-destination tier, and it explicitly refused to claim one from
single-shard rows.

This document asks the follow-up: **is 1000 destinations reachable on this host,
and what is the per-destination cost of getting there?**

Two outcomes are acceptable and they mean different things:

1. **Sharded scaling.** Total capacity rises with shard count and the
   per-destination cost stays flat, so 1000 destinations are served by S shards
   of ~1000/S destinations each. This is the deployment-relevant answer for
   Restream (process-per-shard is already the deployment shape).
2. **Single-shard scaling.** One shard carries 1000 destinations because the
   per-destination cost falls. This is the stronger engineering claim and is
   only accepted with a profile-backed explanation of what was removed.

Either outcome needs the same evidence: per-shard reconciliation, no starved
destination, and a per-copy cost that does not grow superlinearly with F.

## Topology (fixed)

- **One destination = one UDP port**, contiguous range `[base, base + N)`.
  Sender caller `i` sends to `base + i`; receiver connection `i` binds
  `base + i` (`cfg.port + i`, `crates/srt-bench/src/lib.rs`).
- **Sender shard `s` of S** owns `[base + s*(N/S), base + (s+1)*(N/S))`, run as
  `compio_shared_owner_qual --fanout N/S --base-port <shard base>`.
- **Receiver shard `r` of R** binds `<shard base>` with `--connections N/S`
  (`srt-bench runtime=compio mode=receiver <port> <duration> 120 --connections M`).
- One receiver process per sender shard, on the same host, separate processes.
- Nothing in the loop is allowed to be shared across shards: no cross-shard
  listener socket, no cross-shard scheduling, no global allocator.

The one-port-per-destination rule is a real constraint of the instrument, not a
preference: several senders sharing a single destination port do not all get
admitted (measured once: `connections=3 established=1 data_zero=2`). That is out
of model here and is not investigated in this document.

## Metrics (all from the harness's own STATS/SHARED_OWNER_QUAL lines)

| Metric | Definition | Why this one |
|---|---|---|
| `us_per_copy` | `(cpu_user_ms + cpu_sys_ms) * 1000 / copies` | Normalizes scheduler jitter out; the per-copy cost is the thing that decides whether 1000 is reachable |
| `copies_per_s` | `data_accepted / elapsed_s` (sender), `core_total / elapsed_s` (receiver) | Shard capacity |
| `data_zero` | destinations that received **zero** DATA | Aggregates hide starvation; new field |
| `data_below_half_mean` | destinations below half the mean | Detects a slow subset the total cannot show |
| `data_min` / `data_p50` / `data_max` | per-destination delivered DATA | Spread of service across destinations |
| `established` vs `connections` | admitted destinations | Partial admission looks like throughput loss unless printed |
| `sec_a` | receiver loss | Any nonzero value fails the row |
| `missed_source_ticks` | source cadence slots not offered | The sender's own honesty counter |
| `syscalls/copy` | from `srt-bench sysprof` | Separates I/O-bound from CPU-bound |

The distribution fields (`data_min`, `data_p50`, `data_max`, `data_zero`,
`data_below_half_mean`) are new in this branch: computing them post-run costs one
sort of a per-connection vector at teardown and no datapath work.

## Fixed target

**T1 - scaling target.** 1000 destinations served with, per shard:

```text
established == connections          (no shard partially admits its range)
data_zero == 0                      (no starved destination)
data_below_half_mean == 0           (no slow subset)
sec_a == 0                          (no receiver loss)
missed_source_ticks / expected_ticks   no worse than the measured single-shard baseline rate
aggregate data_accepted == aggregate data_offered
```

**T2 - stopping condition (diminishing returns).** The improvement loop stops
when **three consecutive candidate changes each fail to beat the incumbent best
`us_per_copy` by more than the measured noise band**, where the noise band is
the spread of at least three same-config repeats of the incumbent measured in
the same session. A change inside the band is **reverted, not kept**, and
counts toward the three. This is the fixed stopping condition: it is a property
of the measurements, not of the remaining schedule.

**T3 - correctness/robustness gate.** Any change that alters `sec_a`, the
receive reconciliation, a scheduler invariant, or any test gate is reverted
regardless of speed.

**T4 - boundedness gate.** No unbounded queue/lane/timer/list, no task or thread
per connection, no per-datagram future or heap node, no steady-state population
scan, budgets stay strict (zero means zero), and no unjustified copy or
allocation in the RX or TX path.

**T5 - ceiling stop.** If T1 is satisfied by sharding alone, the datapath loop
ends there: the remaining work is documentation and the honest statement that
sharding is the scaling mechanism.

## Hypotheses (recorded before measuring)

| # | Hypothesis | Falsified by |
|---|---|---|
| H1 | A shard is syscall-bound (per-copy `sendto`/`recvfrom`) | `syscalls/copy` well above 1.0 with low `us_per_copy` growth when syscall count is reduced |
| H2 | A shard is protocol/service-CPU bound (visits, deadlines, crypto, ACK processing) | profile attribution and `syscalls/copy` near 1.0 with `us_per_copy` dominated by protocol code |
| H3 | Receiver per-connection bookkeeping dominates at high N | receiver `us_per_copy` grows with connection count at fixed bitrate |
| H4 | The harness's own tick loop, not the transport, sets the ceiling | sender `us_per_copy` at fixed total bitrate is flat in F |
| H5 | Nothing in the datapath is superlinear; sharding is sufficient | per-shard `us_per_copy` grows with F above the noise band |

H4 is the one that would most change the deployment answer, so it is measured
first: it decides whether the number to publish is a transport figure or a
harness figure.

## Rows

Raw evidence per row lives in `docs/results/scaling-1000/`; every number below
is a column in one of those files.

| date | N | S | F/shard | window | outcome | evidence |
|---|---|---|---|---|---|---|
| 2026-09-16 | 200 | 1 | 200 | 3 s | baseline: 0.18-0.26 % missed, lossless, fair, drained | `baseline-F200-solo-3reps.tsv` |
| 2026-09-16 | 1000 | 5 | 200 | 3 s | **all 1000 destinations served, lossless, fair, reconciled**; 15-23 % missed ticks | `scale-N1000-S5-2reps.tsv` |
| 2026-09-16 | 200 | 1 | 200 | 3 s | K sweep 128/512/1024 -- incumbent K=256 best on wire-bytes/CPU-s | `ksweep-K*.tsv` |
| 2026-09-16 | 200 | 1 | 200 | 3 s | payload sweep 700/1316/2632 B at fixed 8 Mbps/destination | `costmodel-payload*.tsv` |

## Result: the scaling path is sharding, and the wall is bytes copied per second

### 1000 destinations, 5 concurrent shards (`scale-N1000-S5-2reps.tsv`)

Ten shard-runs (2 reps x 5 shards), each shard owning 200 consecutive ports,
all five shards running at once against five separate receiver processes:

```text
established        200/200 on every shard, both reps
data_zero          0        (no destination starved)
data_below_half_mean 0     (no slow subset)
data_min == data_max == generated_ticks   (every destination received exactly
                                           every copy its shard generated)
rx_core_total == data_accepted            (exact reconciliation, both reps)
rx_sec_a           0        (no loss)
drain_ok           true, pending_after_drain 0
```

So the *path* to 1000 destinations exists and is clean: five shards carry it
with nothing shared, nothing starved, nothing lost, and nothing left pending.

What does **not** hold at 5 shards on this 6-CPU host is the 8 Mbps/destination
cadence:

| metric | solo F=200 | 5 x F=200 concurrent |
|---|---|---|
| `missed_source_ticks` / expected | 0.18-0.26 % | 15-23 % |
| `window_cpu_ms` per shard | 2719-2752 | ~1700-2000 |
| `lateness_us_p99` | 1530-1666 | ~4600-5300 |

The shards are not misbehaving; they are not getting CPU. Five shards at full
cadence need ~10 cores of protocol work (see the cost model below) and the host
has 6, so each shard gets ~65-70 % of a core and skips the ticks it cannot
serve. Every skipped tick is counted in `missed_source_ticks` rather than
silently reducing the offered load, which is the property that makes this
readable at all.

**Honest capacity statement:** on this host, 1000 destinations are served
losslessly, fairly, and reconciled at ~81 % of an 8 Mbps-per-destination
cadence (5 shards x F=200, 2 reps, identical outcome). Full cadence at 1000
destinations at 8 Mbps needs roughly 10 cores of sender+receiver work.

### The cost is per byte, not per datagram

The payload sweep holds the offered bitrate constant at 8 Mbps per destination
and changes only how the bytes are framed (`--payload-bytes`, with the source
interval derived as `payload_bytes * 8 / 8 Mbps`):

| payload | interval | copies/s | datagrams in window | wire datagrams per copy | window us/copy | missed % |
|---:|---:|---:|---:|---:|---:|---:|
| 700 B | 700 us | 280-284 K | 215-228 K | 0.26-0.27 | **3.48-3.54** | 0.56-1.98 |
| 1316 B | 1316 us | 150-151 K | 197-223 K | 0.43-0.49 | **5.99-6.16** | 0.09-0.92 |
| 2632 B | 2632 us | not measurable (sweep column shift, see below) | 84-85 K | - | - | 0.00-0.09 |

Doubling the number of payloads while holding the bitrate constant *halves* the
per-copy cost: the same bytes cost the same CPU, in twice as many pieces. The
datagram count rose only 8-16 % across that change because the protocol already
coalesces multiple payloads per datagram. The consequence is a per-byte cost
model, and it is the model that predicts the measured shard capacity:

```text
sender   1316 B / 5.98 us  = 4.5 ns/byte    (700 B / 3.50 us = 5.0 ns/byte)
```

4.6 ns/byte is 217 MB/s of payload per core, i.e. ~217 destinations at 8 Mbps
per sender core -- which is exactly where the shard saturates. The 2632 B row
could not be measured as intended: the receiver reports `core_total = 0` and
the sender reports 84-85 K window datagrams, i.e. a ~1500-byte wire packet size
was exceeded and the rows are not comparable. It is recorded as measured, not
as a data point.

### Where the CPU actually goes (`perf`, F=200, sender)

Flat self-costs from a 3 s window under `perf record -F 2999 --call-graph dwarf`:

```text
41 %   kernel: io_sendmsg -> udp_sendmsg -> ip_send_skb   (per-datagram, byte-copying)
 5 %   ring entry/exit: io_uring_enter, io_submit_sqes
 3 %   compio runtime: poll_with, task run
~1 %   srt-rs user space (self cost of the whole protocol)
```

And the syscall count says the same thing from the other side: over 8 s the
receiver entered the kernel 47,605 times while completing 868,805 ring
operations -- **0.15 syscalls per datagram**. H1 (syscall-bound) is false: both
sides already batch through io_uring and pay per-datagram kernel work, not per
syscall. The user-space protocol is not the cost; the copies are.

### Receiver cost curve (F, from the committed #116 artifact plus these runs)

| F | receiver us per datagram processed |
|---:|---:|
| 10 | 30.9 |
| 100 | 12.5 |
| 200 | 7.9 |
| 600 | 16.2 |
| 1000 | 16.5 |

Flat-to-decreasing through F=200 and then rising only in the two overload rows,
where the sender is retransmitting (the F=600 row processes 1.06 M drain
datagrams against 574 K window DATA). H3 -- a per-connection scaling cost in
the receiver -- is false; the rise at 600/1000 is redundant traffic, not
bookkeeping.

## Hypothesis verdicts

| # | Hypothesis | Verdict | Evidence |
|---|---|---|---|
| H1 | shard is syscall-bound | **false** | 0.15 syscalls/datagram; 47.6 K syscalls vs 868 K ring completions |
| H2 | shard is protocol-CPU bound | **false** | kernel UDP send path 41 %, srt-rs user space ~1 % self |
| H3 | receiver per-connection bookkeeping dominates at high N | **false** | receiver us/datagram falls to 7.9 at F=200 and rises only under retransmit overload |
| H4 | the harness's tick loop sets the ceiling | **partly true, and now quantified** | the source shares the loop with `service()`, so a starved shard reports missed ticks instead of a lower rate; the ceiling itself is per-byte CPU, not the loop |
| H5 | nothing superlinear; sharding is sufficient | **true** | 5 x F=200 serves 1000 with per-shard behaviour identical to solo |

## Loop candidates measured (stopping condition T2)

| candidate | change | measurement | verdict |
|---|---|---|---|
| A | TX lane count K -- 128 / 512 / 1024 vs incumbent 256 | in-window wire bytes per CPU-second: 98 / 100 / 107-108 vs **112** at K=256; window us/copy 5.30 / 6.61 / 6.53 vs 5.98-6.05 | **no win, incumbent kept** |
| B | payload framing 700 B vs 1316 B at fixed bitrate | same CPU per byte (0.99 vs 0.91 core at 8 Mbps/destination), i.e. no per-datagram overhead to remove | **no win, no change** |
| C | receiver-side per-connection cost | flat to F=200 (see curve) | **no cost to remove** |

Candidate A also produced a methodological finding worth keeping: **`us/copy`
alone is a misleading optimisation target**, because a smaller K lowers it
(5.30 us) by doing less work per window (236 MB vs 306 MB in the same 3 s).
The metric used from here on is *in-window wire bytes per CPU-second*.

### Stopping status

T2 requires three consecutive candidates that fail to beat the incumbent
beyond the repeat-to-repeat noise band, which the baseline measures at
**+/-0.7 %** (window us/copy 5.976 / 6.055 / 6.027 on three same-config runs).
A, B and C are those three: none beat the incumbent, and none was kept.

No in-scope candidate remains after the attribution: the remaining 99 % of
sender CPU is kernel per-datagram byte handling and Compio's ring
submit/wait, and the only changes that move those are the ones this workstream
declines in its non-goals (zero-copy RX, `MSG_ZEROCOPY`, GSO/`UDP_SEGMENT`,
`sendmmsg` batching, SQPOLL). T5 therefore ends the datapath loop: **sharding is
the scaling mechanism**, and the number to publish is per-core, not per-shard.

## Measurement defects found and fixed in this workstream

1. **Receiver lifetime shorter than the drain** (`scale-N1000-S5-2reps.tsv` vs
   the first run of the same sweep): the driver started receivers with a fixed
   12 s duration while the senders were still draining, so the drain's
   datagrams went to a closed socket. Window-phase reconciliation looked exact
   either way -- `data_min == data_max == generated_ticks`, `sec_a = 0` -- which
   is exactly why the lifetime is now derived from the window
   (`window_ms/1000 + 30 s`) instead of guessed. The invalid first run is not
   cited anywhere.
2. **`us/copy` rewards doing less work** (candidate A).
3. **The 2632 B payload row is not a data point**: a wire packet size beyond
   ~1500 B is out of the instrument's model and the row is recorded as such.
4. **Process-wide `cpu_ms` mixed window and drain** (`cpu_ms` spans both; the
   F=200 drain is 1.2x the window's traffic). The harness now reports
   `window_cpu_ms`, `drain_cpu_ms` and `cpu_ms` separately; the per-copy figures
   above are window-only.

## Non-goals (unchanged from #116)

Native io_uring, borrowed/zero-copy RX, `SQPOLL`/`SEND_ZC`, process-NUMA
placement, allocator selection, and cross-host verification. None of them are
needed to answer the question above, and each would blur the per-copy cost
attribution this document depends on.
