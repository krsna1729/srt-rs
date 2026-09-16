# Shared-Owner qualification (`compio_shared_owner_qual`)

Two-process run: the **sender is the production shared
`srt_transport::compio::Owner`** on its production attach path
(`Owner::connect`, sealed sides, finite `TxPool`, bounded `service` budget,
reserve-then-commit final-buffer TX); the receiver is an independent
`srt-bench runtime=compio mode=receiver` process over real UDP loopback.

```text
# receiver (separate process)
srt-bench runtime=compio mode=receiver <base_port> <duration> 120 --connections <N>
# sender (separate process)
target/release/deps/compio_shared_owner_qual-<hash> \
    --fanout <N> --tx-lanes 256 --connect-cc 64 \
    --duration-ms 3000 --base-port <base_port>
```

**F, K and H are independent inputs**: `--fanout F` is the destination
population, `--tx-lanes K` the fixed TX lane count (= TX capacity), and
`--connect-cc H` the number of connect attempts the pool works on at once.
Neither K nor H is derived from F, and the harness respects the pool's own
bounded request queue by re-issuing a refused connect on a later tick (counted
in `refused`). Rows are only comparable at the same K and H.

## Method

- **Wall-clock-anchored open-loop source.** Source deadlines are
  `epoch + n x interval`, and the SRT `Timestamp` handed to the protocol is
  `srt_epoch + wall_elapsed`. An overrunning service visit therefore cannot
  slow the source down, nor can protocol time drift from wall time — which is
  exactly when it would drift furthest. Every source interval in the window is
  either a generated tick or an explicitly counted `missed_source_ticks`, so
  the identity `expected_ticks == generated_ticks + missed_source_ticks` holds
  and a service-coupled shortfall can never look like a lower offered rate.
- **A destination that refuses a tick loses that copy** (counted in
  `data_accepted` vs `data_offered`), never queued in a harness backlog.
- **Establishment barrier, then a pre-measurement equilibrium drain**
  (`pre_window_drained`): nothing is measured until every destination is
  `Connected` and pre-window protocol/TX work has drained to zero, so no
  handshake or control completion can cross the window start.
- **The window and the drain are counted separately.** `inflight_at_window_end`
  is sampled at the end of the window, before any drain;
  `drain_submitted`/`drain_completed` count the post-window drain phase (bounded
  by 10 s), and window figures never include drain traffic. `cpu_ms` covers the
  window only.
- **RX mode is recorded per row.** `managed_rx=false` means the Owner selected
  `RawReadiness`, so the row is a valid datapath result but **not** a
  managed-multishot qualification.

## Canonical rows (K = 256, H = 64, one sender process)

Committed evidence for this exact table, with host/kernel/config provenance:
[`qual-shared-owner-fixed-kh-4db7f0d.json`](qual-shared-owner-fixed-kh-4db7f0d.json)
(SHA `4db7f0d`, kernel `6.8.0-139-generic`, 6 CPUs).

| F | established | pre-window drained | expected / generated / missed ticks | data offered = accepted | wire submitted (window) | missed ticks % | lateness p50 / p99 / max (µs) | drain | in-flight at window end | receiver DATA | receiver lost `sec_a` |
|---:|---:|---|---|---:|---:|---:|---|---|---:|---:|---:|
| 1 | 1/1 | yes | 2279 / 2265 / 13 | 2,265 | 2,842 | 0.6 % | 93 / 847 / 4,273 | ok | 1 | 2,265 | 0 |
| 10 | 10/10 | yes | 2279 / 2274 / 5 | 22,740 | 28,440 | 0.2 % | 125 / 689 / 3,861 | ok | 10 | 22,740 | 0 |
| 100 | 100/100 | yes | 2279 / 2233 / 46 | 223,300 | 234,279 | 2.0 % | 450 / 2,476 / 13,132 | ok | 256 | 223,300 | 0 |
| 150 | 150/150 | yes | 2279 / 2269 / 10 | 340,350 | 226,016 | 0.4 % | 520 / 1,759 / 4,196 | ok | 256 | 340,350 | 0 |
| 200 | 200/200 | yes | 2279 / 2267 / 12 | 453,400 | 197,005 | 0.5 % | 646 / 2,037 / 3,676 | ok | 256 | 453,400 | 0 |
| 600 | **600/600** | no | 2279 / 2199 / 80 | 1,319,400 = 1,319,400 | 80,290 | 3.5 % | 1,180 / 4,641 / 17,040 | **not reached** | 256 | 561,548 | 73 |
| 1000 | **1000/1000** | no | 2279 / 1871 / 408 | 1,871,000 = 1,871,000 | 12,162 | 17.9 % | 2,172 / 6,156 / 35,591 | **not reached** | 256 | 566,150 | 566 |

`short = 0`, `failed = 0`, `peer_local = 0`, `transient = 0`, `tx_failures_pending = 0`,
`rx_dropped = 0`, `rx_truncated = 0` on every row. Raw harness stdout for the
seven runs is reproduced verbatim in the JSON above; the runs also remain in
`scratch/qual5/` on the measuring host (gitignored).

What this establishes, and what it does not:

- **Establishment is a configuration fact and it holds at 1000 destinations
  from ONE sender process** at K=256/H=64, with 100 % of offered copies
  accepted. The one-process 0/600 rows in the superseded table below were a
  handshake-concurrency artifact of `max_in_flight = fanout`, not a datapath
  limit.
- **Delivery reconciles exactly through F=200**: every row reaches a drained
  equilibrium (`drain_ok`, `pending_after_drain = 0`) with the receiver
  reporting exactly `data_offered` DATA packets and zero loss (`sec_a = 0`),
  and p99 source lateness ≤ 2.5 ms.
- **F=600 and F=1000 are OVERLOAD rows, not capacity results.** The shard
  saturates: the source itself starts missing intervals (3.5 % at 600, 17.9 %
  at 1000 — the honest measure of "one core cannot carry F x 8 Mbps" on this
  host), the window's wire submissions collapse relative to accepted copies,
  the receiver loses 73 and 566 DATA packets, and the drain deadline expires
  with 256 sends still outstanding. No clean-delivery claim is made for either
  tier.
- **These are raw-reader rows.** `IORING_REGISTER_PBUF_RING` fails with
  `EINVAL` on this kernel build, so the Owner selected `RawReadiness` and every
  row prints `managed_rx=false`;
  `ManagedRxQualification::managed_rx_active()` is consequently false here. The
  managed datapath is proven separately by booting a capable kernel under QEMU
  — see [`managed-rx-verification.md`](managed-rx-verification.md).

### The measurement itself was a defect until this head

The rows above are the first canonical set whose source accounting is honest.
The earlier harness generated one tick per loop iteration and advanced protocol
time by a fixed 1316 us per iteration, so under overload a slow `service()` call
reduced the number of ticks generated instead of being counted as source
shortfall: F=1000 "offered" 2,058,000 copies where a true 3 s / 1316 us cadence
called for ~2,279 ticks x 1000 destinations, and protocol time diverged from
wall time by hundreds of milliseconds in exactly the overload case being
characterized. The fixed harness reports `expected_ticks`,
`generated_ticks`, and `missed_source_ticks`, and the identity
`expected == generated + missed` is what makes the F=600/F=1000 rows above
readable.

## Superseded / historical evidence

Kept for provenance only. **Both tables below were produced by harness builds
whose source accounting was service-coupled and whose counters mixed the
measurement window with the post-window drain; their `submitted` figures and
their "lossless" readings are not comparable with the canonical table above.**
The first table also used `tx_capacity = (fanout * 4).clamp(256, 4096)` and
`max_in_flight = fanout`, so its K and H varied with F.

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

- **Historical/intermediate evidence.** These sharded rows used the
  fanout-derived configuration (`tx_capacity = fanout * 4`, `max_in_flight =
  fanout`), so they are establishment evidence only and are superseded by the
  fixed-K/H table above: 600 is not a per-process limit at all.
- **The receiver process is what breaks first at 600, not the sender.** With four
  sender processes (~3.8 cores) plus one 600-port receiver process on six CPUs,
  the receiver reports `sec_a = 44,700` lost DATA packets, while at 200
  destinations (two senders) it reports `core_total == pkt_sent` with `sec_a = 0`.
  The 600 row is thus a clean establishment result but not a clean delivery
  result. (Historical reading, retained verbatim: with the corrected source
  accounting the canonical F=600 row above shows the binding constraint is the
  sender shard's own service capacity — 80 missed source ticks and 73 lost
  receiver DATA packets — rather than a two-process receiver limit.)
- Sender CPU is ~95 % of one core per shard at both 150 and 300 offered
  copies/second per shard, i.e. the per-copy cost is stable and the shard count
  is what buys capacity.

`managed_rx=false`, `rx_dropped=0`, `rx_truncated=0`, `short=0`, `failed=0`
for every row.

Raw logs: `scratch/qual/recv-p{1,10,100,600}.log` (gitignored scratch; the
sender lines are reproduced above in full).

## Deferred

- A drained-equilibrium capacity figure for 600/1000 destinations: on this host
  one Owner shard is CPU-bound well below F x 8 Mbps, and the honest next step
  is sharding on target hardware rather than more harness tuning.
- A managed-multishot qualification on this host (proven separately under
  QEMU on a capable kernel).
- Per-connection-scaling questions beyond establishment: the harness now
  separates window from drain, so a later qualification run can add a
  steady-state delivery-rate column without redefining the existing ones.
