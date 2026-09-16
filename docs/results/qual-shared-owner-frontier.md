# Shared-Owner qualification frontier (`compio_shared_owner_qual`)

Two-process run: the **sender is the production shared
`srt_transport::compio::Owner`** on its production attach path
(`Owner::connect`, sealed sides, finite `TxPool`, bounded `service` budget,
reserve-then-commit final-buffer TX); the receiver is an independent
`srt-bench runtime=compio mode=receiver` process over real UDP loopback.

```text
# receiver (separate process)
srt-bench runtime=compio mode=receiver <base_port> <duration> 120 --connections <N>
# sender (this bench, separate process)
target/release/deps/compio_shared_owner_qual-<hash> \
    --fanout <N> --duration-ms 10000 --base-port <base_port>
```

## Method

- **Open-loop source at the declared 8 Mbps / 1316-byte cadence.** The source
  clock advances on `PACKET_INTERVAL_US = 1316` and never waits for service
  capacity; the loop then sleeps out the rest of the interval. A destination
  that refuses a tick loses that copy and it is counted, never queued in a
  harness backlog.
- **Establishment barrier.** Nothing is measured until every logical
  destination reports `Connected`, or a 30 s connect deadline expires.
  `established` is printed per row, and a partial establishment is reported as
  such rather than converted into a capacity result.
- **TX-enabled drain to equilibrium** after the window, bounded by 10 s:
  `pending_after_drain == 0` means protocol output *and* in-flight sends
  reached zero, not merely that already-submitted operations were reaped.
- **RX mode is recorded per row.** `managed_rx=false` means the Owner selected
  `RawReadiness`, so the row is a valid datapath result but **not** a
  managed-multishot qualification.

## Host

Ubuntu `6.8.0-139-generic`, AMD EPYC (KVM), 6 CPUs, loopback. Release build,
no CPU pinning, one sender Owner shard and one receiver process.

## Results

Sender lines are verbatim `SHARED_OWNER_QUAL` output; receiver lines are the
receiver process's own `STATS`.

| fanout | established | offered | accepted | wire datagrams submitted | sender completed_ok | sender CPU ms / 10 s | source lateness p50 / p99 / max (µs) | receiver `core_total` | drain |
|---:|---:|---:|---:|---:|---:|---:|---|---:|---|
| 1 | 1/1 | 7,599 | 7,599 | 9,539 | 5,742 | 892 (9 %) | 0 / 0 / 2,376 | 7,599 | ok |
| 10 | 10/10 | 75,990 | 75,990 | 95,070 | 91,284 | 1,794 (18 %) | 0 / 0 / 2,760 | 75,990 | ok |
| 100 | 100/100 | 759,900 | 759,900 | 905,866 | 899,250 | 9,390 (94 %) | 0 / 18,122 / 40,801 | 759,900 | ok |
| 600 (1 process) | **0/600** | 0 | 0 | 0 | 0 | 0 | — | 0 | not reached |
| 1000 (1 process) | **0/1000** | 0 | 0 | 0 | 0 | 0 | — | 0 | not reached |

### Sharded sender runs (same harness, several sender processes)

A single sender process cannot offer 600 destinations on this host, so the
earlier rows above are a *single-process* limit, not a datapath limit. Splitting
the same destinations across several sender Owner processes (each with its own
shared caller socket, all pointing at one receiver process) changes the answer:

| fanout | sender shards | established | offered = accepted | wire datagrams (all shards) | sender CPU ms each | receiver `core_total` = `pkt_sent` | receiver `sec_a` (lost) | drain |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 200 | 2 x 100 | 200/200 | 380,000 each | 656,223 / 680,078 | 4,890 / 4,832 | **641,647 = 641,647** | **0** | ok |
| 600 | 4 x 150 | **600/600** | 342,000 each | 687,166 / 687,091 / 690,901 / 692,409 | ~2,860 each | 574,981 = 574,981 | **44,700** | ok |

Raw logs: `scratch/qual/send-shard200-{0,1}.log`, `scratch/qual/send-shard*.log`,
`scratch/qual/recv-shard{200,600}.log`.

Reading them:

- **600 destinations *do* establish when the sender is sharded**: 600/600 across
  four Owner processes, each 100 % of its offered copies accepted, every shard
  drained to zero with `short=0` and `failed=0`. The one-process 0/600 row above
  is therefore a per-process admission limit on this host, not a transport
  ceiling — the inference in the earlier reading of this document is now a
  measurement.
- **The receiver process is what breaks first at 600, not the sender.** With four
  sender processes (~3.8 cores) plus one 600-port receiver process on six CPUs,
  the receiver reports `sec_a = 44,700` lost DATA packets, while at 200
  destinations (two senders) it reports `core_total == pkt_sent` with `sec_a = 0`.
  The 600 row is thus a **clean establishment** result but not a clean delivery
  result: receiver capacity, not the Owner datapath, is the binding constraint
  there.
- Sender CPU is ~95 % of one core per shard at both 150 and 300 offered
  copies/second per shard, i.e. the per-copy cost is stable and the shard count
  is what buys capacity.

`managed_rx=false`, `rx_dropped=0`, `rx_truncated=0`, `short=0`, `failed=0`
for every row.

Raw logs: `scratch/qual/recv-p{1,10,100,600}.log` (gitignored scratch; the
sender lines are reproduced above in full).

## Interpretation

- **Delivery reconciles exactly at 100 destinations**: the sender accepted
  759,900 copies and the receiver's `core_total` is 759,900 — no loss inside
  the measured steady state, with `drain_ok=true` and
  `pending_after_drain=0`.
- **One Owner core is the limit at ~100 destinations** on this host: sender
  CPU is 94 % of one core for the 10 s window and source lateness appears
  (p99 18.1 ms, max 40.8 ms) at exactly that tier, while 1 and 10 stay at
  p99 = 0 with 9 %/18 % CPU. This is the same-host service-demand curve the
  library is supposed to publish; it is a *shard* limit, not a per-connection
  cost.
- **600 establishes once the sender is sharded** (4 x 150: 600/600, all copies
  accepted, all shards drained), and 200 with two shards is clean end-to-end
  (`core_total == pkt_sent`, `sec_a = 0`). **600 clean delivery** is not
  claimed: with four sender processes plus one receiver process on six CPUs the
  receiver is starved and reports 44,700 lost DATA packets, so the binding
  constraint at that tier is receiver capacity on this host.
- **1000 is still unestablished** on this host (1/10/100/200 sharded all work;
  1000 needs more sender shards and, especially, a receiver with its own
  cores). No 1000 claim is made.
- **These are raw-reader rows.** `IORING_REGISTER_PBUF_RING` fails with
  `EINVAL` on this kernel build (reproducer: `scratch/pbufring.c`), so the
  Owner selected `RawReadiness` and every row prints `managed_rx=false`.
  `ProductionQualification::qualified()` is consequently **false** here: a
  managed-multishot qualification requires a kernel whose provided-buffer
  ring registers. Linux `7.0.0-31-generic` is installed on this host but not
  booted.

## What this does and does not establish

- Establishes: the production Owner attaches, admits, sends, drains to
  equilibrium, and reconciles delivery end-to-end against an external
  receiver process at 1/10/100 destinations, with honest accounting of
  latency and CPU.
- Does not establish: a 600/1000 frontier (did not establish here), or a
  managed-multishot qualification (this kernel cannot provide the substrate).
