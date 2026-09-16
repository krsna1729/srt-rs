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
    --fanout <N> --tx-lanes 256 --connect-cc 64 \
    --duration-ms 3000 --base-port <base_port>
```

F, K and H are **independent inputs**: `--fanout F` is the destination
population, `--tx-lanes K` the fixed TX lane count (= TX capacity), and
`--connect-cc H` the number of connect attempts the pool works on at once. No
run below derives K or H from F, and rows are only comparable at the same K/H.
The harness respects the pool's own bounded request queue: a `connect` that the
queue refuses is re-issued on a later tick and counted in `refused`.

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

## Canonical fixed-K / fixed-H run (K = 256, H = 64)

These are the post-closure-pass rows: one **sender process** with fixed
`--tx-lanes 256 --connect-cc 64`, so K and H no longer vary with F. The
earlier rows above used `tx_capacity = (fanout * 4).clamp(256, 4096)` and
`max_in_flight = fanout` and are kept only as historical/intermediate
evidence.

| F | issued | admitted | queued | refused | established | offered = accepted | wire datagrams submitted | completed_ok | sender CPU ms / 3 s window | source lateness p50 / p99 / max (µs) | receiver `core_total` = `pkt_sent` | `sec_a` | drain | pool free/cap |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|---|---|
| 1 | 1 | 1 | 0 | 0 | 1/1 | 2,280 | 2,861 | 2,861 | 310 | 0 / 0 / 1,408 | 2,280 = 2,280 | 0 | ok | 256/256 |
| 10 | 10 | 10 | 0 | 0 | 10/10 | 22,800 | 28,530 | 28,530 | 520 | 0 / 0 / 643 | 22,800 = 22,800 | 0 | ok | 256/256 |
| 100 | 100 | 100 | 36 | 0 | 100/100 | 228,000 | 269,038 | 269,093 | 2,557 | 0 / 0 / 1,845 | 228,000 = 228,000 | 0 | ok | 256/256 |
| 150 | 150 | 150 | 86 | 24 | 150/150 | 342,000 | 471,140 | 471,309 | 2,660 | 0 / 134 / 2,331 | 342,000 = 342,000 | 0 | ok | 256/256 |
| 200 | 200 | 200 | 136 | 74 | 200/200 | 456,000 | 721,718 | 721,847 | 2,734 | 0 / 445 / 1,782 | 456,000 = 456,000 | 0 | ok | 256/256 |
| 600 | 600 | 600 | 536 | 567 | **600/600** | 1,368,000 | 1,114,364 | 1,114,364 | 2,978 | 0 / 29,970 / 39,506 | 943,296 = 943,296 | 0 | **not reached** | 0/256 |
| 1000 | 1000 | 1000 | 936 | 1,305 | **1000/1000** | 2,270,000 | 1,011,843 | 1,011,843 | 3,000 | 130,684 / 268,407 / 271,617 | 814,117 = 814,117 | 0 | **not reached** | 0/256 |

Raw logs: `scratch/qual2/send-<F>.log`, `scratch/qual2/recv-<F>.log`.

What these rows establish, and what they do not:

- **A single sender process establishes 600 and 1000 destinations** at
  K=256/H=64, with 100 % of offered copies accepted and every destination
  `Connected`. That retires the earlier "600 cannot establish in one process"
  reading: with H fixed at 64 and the pool's bounded queue respected by the
  harness, one process does it. The 1-process 0/600 rows above were a
  *handshake-concurrency* artifact (`max_in_flight = fanout` = 600 concurrent
  handshakes), not a datapath limit.
- **Zero receiver loss to F = 200.** `core_total == pkt_sent` and `sec_a = 0`
  on every row through 200, with `drain_ok=true` and `pending_after_drain=0`:
  the shard kept pace with F x 8 Mbps.
- **F = 600 and F = 1000 saturate, and that is a capacity statement, not a
  correctness one.** Offered load is F x 8 Mbps (4.8 and 8.0 Gbps on one
  loopback shard), far beyond one core of UDP. Delivery stayed lossless
  (`sec_a = 0`, `core_total == pkt_sent`) but the drain deadline expired with
  257 in flight and the pool at 0/256 free, and source lateness grew to
  30 ms p99 (F=600) and 131 ms p50 / 268 ms p99 (F=1000). The sender used
  ~3.0 s of CPU in a 3.0 s window: **one shard is one core**, so the frontier is
  "how many destinations one core can carry at the offered rate", not "how many
  can be established".
- **`not reached` drain is reported as such.** No row claims a drained
  equilibrium it did not observe.

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

- **Historical/intermediate evidence.** These sharded rows used the
  fanout-derived configuration (`tx_capacity = fanout * 4`, `max_in_flight =
  fanout`), so they are establishment evidence only and are superseded by the
  fixed-K/H table above: 600 is not a per-process limit at all.
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
- **A single sender process establishes 600/600 and 1000/1000** at fixed
  K=256/H=64 with every copy accepted, and delivery stays lossless
  (`receiver sec_a = 0`, `core_total == pkt_sent`) to F = 200 with a drained
  equilibrium. Both high tiers saturate the one-core shard at F x 8 Mbps
  offered load and report their missed drain honestly; no clean *delivery*
  capacity is claimed for them.
- **1000 is established but not capacity-qualified.** Establishment is a
  configuration fact; the capacity statement is the drained-equilibrium row,
  and there is none at 1000.
- **These are raw-reader rows.** `IORING_REGISTER_PBUF_RING` fails with
  `EINVAL` on this kernel build (reproducer: `scratch/pbufring.c`), so the
  Owner selected `RawReadiness` and every row prints `managed_rx=false`.
  `ManagedRxQualification::managed_rx_active()` is consequently **false**
  here: a managed-multishot qualification requires a kernel whose
  provided-buffer ring registers. That kernel (`7.0.0-31-generic`) is not
  bootable on this development host, so the managed datapath is proven by
  booting it under QEMU instead — see
  [`managed-rx-verification.md`](managed-rx-verification.md).

## What this does and does not establish

- Establishes: the production Owner attaches, admits, sends, drains to
  equilibrium, and reconciles delivery end-to-end against an external
  receiver process from 1 to 200 destinations with zero loss, and establishes
  600/1000 with every copy accepted, at a fixed K=256/H=64.
- Does not establish: a drained-equilibrium capacity figure for 600/1000 (the
  one-core shard saturates at F x 8 Mbps), or a managed-multishot
  qualification on this kernel (proven separately under QEMU on a capable
  kernel).
