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

- **Wall-clock-anchored source with explicit missed-deadline accounting.**
  Source deadlines are `epoch + n x interval`, and the SRT `Timestamp` handed
  to the protocol is `srt_epoch + wall_elapsed`, so an overrunning service
  visit cannot shift either clock. **This is not a fully independent producer**:
  it runs in the same loop as `owner.service()`, so a service overrun prevents
  ticks from being produced at all — those intervals are counted in
  `missed_source_ticks`, and the window close reconciles and **asserts**
  `expected == generated + missed` rather than merely documenting it. A
  separately paced producer is the stronger design for a target-hardware
  qualification run.
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

Committed evidence for this exact table — measured from a **clean checkout** of
the SHA it names, by the committed parser/generator (`cargo run --release -p
srt-bench --bin qual-evidence`), which keeps every field the harness prints —
[`qual-shared-owner-fixed-kh-503ef2f.json`](qual-shared-owner-fixed-kh-503ef2f.json)
(SHA `503ef2f`, `git_dirty: false`, kernel `6.8.0-139-generic`, 6 CPUs); it
carries every field the harness prints, plus the verbatim stdout line of sender
and receiver for each run.

| F | established | pre-window drained | expected / generated / missed ticks | missed ticks % | data offered = accepted | wire submitted (window) | lateness p50 / p99 / max (µs) | drain | in-flight at window end | receiver DATA | receiver lost `sec_a` |
|---:|---:|---|---|---:|---:|---:|---|---|---:|---:|---:|
| 1 | 1/1 | yes | 2279 / 2277 / 2 | 0.1 % | 2,277 | 2,856 | 95 / 678 / 1988 | ok | 2 | 2,277 | 0 |
| 10 | 10/10 | yes | 2279 / 2227 / 52 | 2.3 % | 22,270 | 27,906 | 137 / 2089 / 9645 | ok | 10 | 22,270 | 0 |
| 100 | 100/100 | yes | 2279 / 2238 / 41 | 1.8 % | 223,800 | 242,616 | 445 / 2229 / 7529 | ok | 256 | 223,800 | 0 |
| 150 | 150/150 | yes | 2279 / 2184 / 95 | 4.2 % | 327,600 | 187,780 | 598 / 3753 / 13921 | ok | 256 | 327,600 | 0 |
| 200 | 200/200 | yes | 2279 / 2270 / 9 | 0.4 % | 454,000 | 211,484 | 597 / 1823 / 4121 | ok | 256 | 454,000 | 0 |
| 600 | 600/600 | no | 2279 / 2166 / 113 | 5.0 % | 1,299,600 | 82,045 | 1173 / 4923 / 23293 | **not reached** | 256 | 574,213 | 0 |
| 1000 | 1000/1000 | no | 2279 / 1805 / 474 | 20.8 % | 1,805,000 | 10,101 | 2346 / 6098 / 27119 | **not reached** | 256 | 579,581 | 0 |

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
  and p99 source lateness ≤ 3.8 ms.

**Run-to-run spread is real and is not smoothed over.** The same commands on the
same host produced, for `missed_source_ticks` out of 2279: F=1: 0, 2, 13, 57;
F=10: 0, 44, 52; F=100: 1, 12, 41, 46; F=150: 7, 10, 16, 95; F=200: 0, 1, 9, 12;
F=600: 74, 82, 113; F=1000: 397, 474, 529. The producer shares this thread with
`owner.service()`, so much of that spread is host scheduling jitter rather than a
shard property — which is exactly the limitation the terminology above records,
and why a separately paced producer remains the stronger target-host design. Do
not read a single row, or a single three-second sample, as a capacity figure.
- **That is a reconciliation statement, not a sustained-capacity statement.**
  F=150 and F=200 reach zero outstanding only after a post-window drain phase
  far larger than their window traffic: they submit 187,780 and 211,484 wire
  datagrams inside the window and then drain 301,557 and 549,164 completions
  (301,301 and 548,908 newly submitted during the drain). Read as: "nothing is
  lost once the source stops, and the shard drains what it buffered", not
  "F=200 is sustainable at 8 Mbps per destination".
- **F=600 and F=1000 are OVERLOAD rows, not capacity results.** The shard
  saturates: the source itself misses 5.0 % and 20.8 % of its intervals (the
  honest measure of "one core cannot carry F x 8 Mbps" on this host), the
  window's wire submissions collapse to 82,045 and 10,101 against 1,299,600 and
  1,805,000 accepted copies, and the bounded run **never drains** (256 sends
  still outstanding at the deadline). The receiver reports no loss
  (`sec_a = 0`) but its DATA count, 574,213 and 579,581, does not reconcile with
  the offered copies — the comparison the delivered-everything reading of the
  earlier tables relied on. No clean-delivery claim is made for either tier.
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
  sender shard's own service capacity — 113 missed source ticks of 2279, wire
  submissions collapsing to 82,045 inside the window, and a bounded run that
  never drains — rather than a two-process receiver limit.)
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
