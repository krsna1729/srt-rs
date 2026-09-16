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

| date | N | S | F/shard | R | outcome | evidence |
|---|---|---|---|---|---|---|
| - | - | - | - | - | protocol frozen | this commit |

## Non-goals (unchanged from #116)

Native io_uring, borrowed/zero-copy RX, `SQPOLL`/`SEND_ZC`, process-NUMA
placement, allocator selection, and cross-host verification. None of them are
needed to answer the question above, and each would blur the per-copy cost
attribution this document depends on.
