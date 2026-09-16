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
| 600 | **0/600** | 0 | 0 | 0 | 0 | 0 | — | 0 | not reached |
| 1000 | **0/1000** | 0 | 0 | 0 | 0 | 0 | — | 0 | not reached |

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
- **600 and 1000 did not establish** with one sender process and one receiver
  process on 6 CPUs: 0 of 600 and 0 of 1000 destinations reached `Connected`
  inside the 30 s barrier (the receiver's own log shows `established=0`). No
  600/1000 capacity claim is made from this host. Establishing those tiers
  needs sharding (multiple sender Owner processes and a receiver with its own
  capacity) plus a longer barrier, which is out of scope for a single 6-CPU
  loopback box.
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
