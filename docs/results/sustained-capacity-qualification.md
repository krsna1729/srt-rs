# Sustained SRT shard capacity: pre-registered qualification

Status: **protocol frozen before measurement**, for the follow-up to #117.

#117 established a burst result (1000 destinations admitted, served fairly,
eventually reconciled) and recorded sustained capacity as **not qualified**,
because several rows looked like capacity evidence and were not. This document
fixes the experiment that can qualify it.

## Question

What is the largest configuration that holds full cadence indefinitely?

```text
C(F) = maximum sustainable per-destination bitrate at fanout F
N(R) = maximum sustainable destinations at per-destination bitrate R
```

`C(F)` is the useful object, not "destinations per core". A single ratio cannot
say whether the frontier is set by total packet rate, total bitrate,
per-destination protocol work, or an interaction between them -- and those have
different deployment consequences.

## The methodological change: rate is an independent variable

Every row in #117 held the offer at 8 Mbps/destination and varied F, which can
only find the frontier by *failing* at it. The harness now takes
`--rate-mbps-per-dest` (`interval = payload_bytes * 8 / rate`, so payload size
and rate stay independent), and the qualification searches it:

```text
for each F:
    step/bisect the offered rate down (or up) until the gate passes
    record the largest passing rate as C(F)
```

The source cadence is a property of the offer and is anchored to wall time, not
to how far `Owner::service()` got; a tick the shard refuses is counted in
`missed_source_ticks` rather than queued, so the offer cannot be silently
reduced by a slow service loop.

## The gate (executable)

`cargo xtask qualify <sweep.tsv>` applies, requiring **all** of:

| condition | why |
|---|---|
| `generated_ticks / expected_ticks` >= 0.999 | the offer was held, not merely made |
| `established == fanout == rx_established` | the requested population existed, at both endpoints |
| `data_offered == generated_ticks * established` | every established destination was offered every generated tick |
| `data_accepted == data_offered` | the transport admitted the offer, not only the part it accepted |
| `data_accepted == rx_core_total` | accepted is not delivered |
| `data_zero == 0` | no destination starved |
| `data_below_half_mean == 0` | no slow subset |
| `sec_a == 0` | no reported loss |
| `drain_ok == true`, `pending_after_drain == 0` | equilibrium reached |
| `window_cpu_ms > 0`, `cpu_ms > 0` | the CPU accounting is real, not a stale zero |

Two more groups apply only when the run declares that it is canonical
(`--require-clean`), because they are claims about the artifact rather than about
the row's workload:

| canonical condition | why |
|---|---|
| `git_dirty == false`, `built_by_scaling == true` | the header's `git_sha` describes the binaries that actually ran |
| `pre_window_drained == true` | the window opened on a steady state, not on setup residue |
| `owner_faulted == false` | no dead TX lane, short/failed completion, or stopped RX task |
| `rx_duplicates`, `rx_sec_b` <= `tx_class_data_retx + drain_class_data_retx` | packet-level duplicates are the repairs that re-sent them |

And the repetition rule is the sweep's own hierarchy, not a row count: a
repetition passes only when **every** shard row in it passes, and a point
qualifies only when at least three repetitions exist and every one of them
passed. `cargo xtask scaling` writes one `ROW` per shard per repetition, so
`--shards 3 --reps 1` writes three passing rows and is still one repetition;
missing or duplicated shard rows, and whole missing repetitions, are malformed
evidence rather than a smaller experiment.

Necessary-but-insufficient conditions are deliberately excluded, because
treating them as sufficient is the specific error that produced #117's withdrawn
claim: `drain_ok` alone conserves a *cost* denominator and says nothing about
whether the cadence was held.

Applied to the merged evidence, the gate passes **0 of 10** rows in
`scale-N1000-S5-2reps.tsv` (cadence 0.76-0.85) and **0 of 2** in
`equilibrium-F100-10s.tsv` (cadence 0.87-0.97), which is the withdrawn capacity
claim reproduced as a failing test rather than as a paragraph. Rows measured
before the `cpu_ms` fix also fail on `cpu_ms=0`, which is correct: those
artifacts cannot support a cost claim.

## Run design

* length 30-60 s, so the offer is held far beyond the 3 s burst of #117;
* `>= 3` repetitions per configuration, and the reported figure is the median
  with the observed spread;
* per configuration, report `(F, offered bitrate/destination, delivered
  bitrate/destination, sender CPU, receiver CPU, lateness p50/p99/max)`;
* sender CPU over a matched logical interval, and receiver CPU given the same
  baseline treatment rather than process-lifetime accounting (the receiver
  currently reports cumulative CPU including its own handshake);
* the frontier is reported as the measured surface, never as an extrapolation
  from a cost ratio.

## Where the headroom is now measurable

`C_wire_floor = r x C_UDP_floor` is the cost of the same wire volume on the
measured efficient UDP floor, so the implementation gap is `C_SRT / C_wire_floor`
-- per operating point, not one global ratio:

```text
configuration        r     C_SRT     C_wire_floor (8.0 us)   headroom
F=50,   8 Mbps/dest  1.22   16.91         9.79 us            1.73x
F=100,  8 Mbps/dest  1.46   16.54        11.64 us            1.42x
F=200,  4 Mbps/dest  1.98   23.63        15.84 us            1.49x
F=200,  2 Mbps/dest  1.96   26.09        15.71 us            1.66x
```

So the reachable implementation gap is **~1.4-1.7x on passing configurations**,
and it varies with control amplification and operating point rather than being a
constant. Two consequences:

* the target for optimization is the gap between measured `C_SRT` and
  `r x UDP-floor`, not destinations per core;
* because `r` carries ~0.2-0.7 of excess above the protocol's control budget at
  some operating points, part of that gap may be *wire volume* rather than
  submission mechanics -- which is why wire classification comes before any
  transport change.

## The optimization ladder this feeds

The report's floor ladder (`docs/results/scaling-to-1000.md`) says where the
current implementation sits. This is the ladder of things that can move it,
ordered by how much of the SRT contract they preserve:

```text
  SPEC-COMPLIANT, peer-visible wire unchanged
  ────────────────────────────────────────────
  L7  application/session layout   shared source payload, one Owner for many
                                   logical callers, no machinery per destination
  L6  SRT control policy           Full ACK timer, Light vs Small ACK choice,
                                   ACKACK path, NAK range aggregation,
                                   retransmit prioritisation
  L5  packet scheduling/batching   generate all currently-due packets in one
                                   visit; batch across destinations; preserve
                                   SRT pacing deadlines
  L4  advanced UDP transport       TX: multi-SQE submit, sendmmsg, UDP GSO
                                   RX: multishot recv, recvmmsg, UDP GRO
  L3  packet-count reduction       largest negotiated/path-safe SRT payload,
                                   correct PMTU handling -- the only compliant
                                   lever that reduces the number of DATA
                                   datagrams rather than their submission cost
  ────────────────────────────────────────────
  L2  efficient UDP datagram floor            7.45-8.90 us/datagram (measured)
  L1  syscall / ring transition               0.264-0.875 us   (measured)
  L0  memory copy                             0.0186 us/1316 B (measured)

  ══════════════ SRT semantic boundary ══════════════
  stream coalescing / arbitrary packet merging  0.249-0.909 ms CPU/Mbit
  -- requires giving up per-packet sequencing and selective ARQ: a different
     protocol, not an optimization of this one
```

Two consequences for the experiment, both of which decide what is worth
building next:

1. **Control traffic is not the main lever.** The draft's ACK budget is ~0.28
   control packets per DATA packet (Full ACK ~10 ms, Light ACK ~1 per 64, only
   Full ACKs triggering ACKACKs), so it cannot explain the `r` of 1.68-1.93 seen
   on overloaded rows. The work there is to make each control *event* nearly
   free to schedule and encode, not to send fewer legal control packets.
2. **Cross-destination submission batching outranks same-destination GSO for
   this topology.** An Owner with hundreds of destinations has, at each service
   instant, one due packet per destination; those cannot be merged into one GSO
   super-datagram because the destination differs, but they can be submitted as
   one batch. GSO becomes valuable where same-peer packets become due together:
   retransmission bursts, high per-destination rates, and any pace tolerance
   that lets several packets for one destination ride together.

## Next decisive experiment: the terminal fence

The remaining conservation defect at K=256/512 is **not localized**. What the data
shows is that the deficits appear only during final reconciliation and always with
`sec_a = 0`; there is no time-series receiver conservation measurement, so nothing
yet places the missing payloads in the final flight. The fence is the experiment
that turns that from a strong hypothesis into a finding.

sender, after the measured window:

```text
last measured tick for peer P = T
    send ordinary measured DATA through T
    stop the measured source
    send FENCE(peer=P, final_tick=T)
        as an ordinary *later* SRT DATA message
        classified as diagnostic, never as workload
    continue servicing the sender

receiver, per peer:
    record the first observation of FENCE(P, T)
    snapshot measured DATA received through T, missing tick ids, sec_a, sec_b,
    duplicate measured DATA, fence receive time
    terminate and write STATS only after every fence (or a timeout)
```

Fence DATA and fence CPU stay **out of the capacity denominator**, but the fence
phase gets its own counters rather than being discarded: `fence_first_data`,
`fence_retx`, `measured_tail_retx_during_fence`, `fence_control`, and
`time_to_all_fences`. Then the outcomes separate cleanly:

```text
fence seen, deficit 0, no measured retx      -> receiver/stat snapshot or shutdown race
fence seen, deficit 0, measured retx appears -> the tail needed later sequence progress
fence seen, deficit remains                  -> delivery / drop / accounting defect
fence never seen                             -> the final-send lifecycle itself failed
```

The lifecycle is why this is worth doing: the sender currently services until
there is no in-flight or pending work, records stats and returns. There is no
receiver-confirmed end-of-stream watermark and no application-level final
acknowledgement, so TX completion can outrun remote observation and the protocol
can go quiescent before a later NAK or recovery opportunity exists.

## K is a sparse sensitivity axis, not a third sweep dimension

`C = C(F, R, K)` is the honest model, but a dense three-dimensional sweep would
replace measurement with bookkeeping. Once the fence is understood, pick a
production K -- 256 currently looks better than 512 on this host -- and treat K as
a sensitivity axis probed at a few frontier points (`K = 64, 128, 256, 512`). If
256 is consistently sufficient and 512 buys no capacity while occasionally
worsening cadence, K becomes a tuned implementation parameter instead of a
multiplier on every future experiment.

K=64 also shows K participating in two regimes rather than one: it accepts far
fewer payloads than offered (admission/backpressure capacity) *and* then fails to
deliver a substantial share of what it accepted, with receiver loss and duplicates
(recovery/service capacity). Wire classification is what will say which dominates
near the threshold.

## Order of work

1. **Finish the surface.** At least three repetitions per cell (most cells have
   one), a finer rate search (6 and 4 bracket the F=200 frontier; 4 is not shown
   to be maximal), and a probe above 12 Mbps/destination.
2. **Classify wire volume.** Split `r` into `r_data + r_ack + r_nak + r_retx +
   r_other` with receiver-side duplicate accounting, so control amplification and
   retransmission are separated from each other and from original DATA.
3. **Then cross-destination io_uring submit batching.** It attacks L5 directly,
   changes no SRT semantics, and is the strongest candidate for the multi-destination
   topology: at each service instant one packet per destination is due, which
   cannot merge into a GSO super-datagram but can share one submission.
4. **Then GRO on RX**, then selective same-destination GSO where the due set
   permits.

Every step is judged by the gate plus a declared lateness budget, not by
microseconds per datagram.

## GSO opportunity census (implementation notes)

The census comes before any GSO code, and two implementation details decide
whether it measures anything:

* **Do not text-log every emitted packet during the timed run.** F=50 at 8 Mbps
  already emits ~46 K wire packets/s, i.e. millions of records over 60 s, and
  formatting plus filesystem work would perturb the scheduling distribution being
  measured. Use a bench-only preallocated binary ring or online histograms and
  flush after the measurement.
* **Record `wire_len` and packet type, not only timing.** GSO requires compatible
  segmentation -- a 1316-byte DATA packet cannot share a batch with a short ACK or
  NAK -- so the census needs separate curves for first DATA, retransmission
  bursts, and homogeneous control packets. Fields: `peer`, `packet_type`,
  `wire_len`, `nominal_due_time`, `actual_submit_time`, `sequence_number`.

The theoretical DATA spacing makes the result falsifiable before it is run:

```text
1316-byte payload       spacing
 8 Mbps                 1316 us
12 Mbps                  877 us
20 Mbps                  526 us
25 Mbps                  421 us
50 Mbps                  211 us
```

So: no natural first-DATA GSO below ~1 ms at F=50 x 8 Mbps; a two-packet
opportunity becomes plausible around 500-600 us at 20 Mbps per destination; and a
250 us horizon could already produce 2-segment batches at 50 Mbps per destination.
A census that deviates strongly from those figures is itself the finding -- it
would mean the scheduler is bunching packets before pacing is deliberately relaxed.

## Next experiment matrix

Run each cell against the full gate, not against us per datagram:

```text
TX realization          1. current Owner
                        2. multi-SQE batched submit
                        3. sendmmsg reference
                        4. GSO where the same-peer due set permits

RX realization          A. current multishot
                        B. GRO
                        C. GRO + multishot where the kernel permits

packetization           payload size / negotiated MTU sweep (L3)
pacing                  strict due-only, +25 us, +50 us, +100 us batching horizon
```

Reported per cell: the gate verdict, `r`, sender CPU per delivered payload,
receiver CPU per delivered payload, lateness p50/p99/max, and retransmission
count. The pacing horizon is the cell most likely to be misread: batching packets
that are *not yet due* may look like a throughput win while it is really a
latency loan, so a cell only counts if it passes the gate **and** its lateness
distribution is reported next to it.

Target: approach stream-transport amortisation while the packet stream the peer
observes stays exactly SRT.

## Withdrawn: the first gate-backed surface (intermediate evidence)

**Superseded. Nothing in this section is a current claim**, and it is kept only
because the sequence is instructive: a "throughput PASS" that allowed a large
post-window drain was published as a frontier before stationarity was in the
gate.

Original table, withdrawn in full:

| configuration | rows | gate at the time | r | C_SRT us/payload | p99 |
|---|---:|---:|---:|---:|---:|
| F=50, 8 Mbps/dest | 2 | 2/2 | 1.22 | 16.91 | 5.3 ms |
| F=100, 8 Mbps/dest | 2 | 2/2 | 1.46 | 16.54 | 28.3 ms |
| F=100, 12 Mbps/dest | 1 | 0/1 | 1.51 | 15.12 | 5.4 ms |
| F=150, 8 Mbps/dest | 1 | 0/1 | 1.57 | 16.75 | 7.4 ms |
| F=200, 8 Mbps/dest | 2 | 0/2 | 1.55 | 22.20 | 40.6 ms |
| F=200, 6 Mbps/dest | 1 | 0/1 | 1.42 | 18.68 | 65.7 ms |
| F=200, 4 Mbps/dest | 1 | 1/1 | 1.98 | 23.63 | 12.6 ms |
| F=200, 2 Mbps/dest | 1 | 1/1 | 1.96 | 26.09 | 16.8 ms |

Why every "PASS" above is not a capacity point:

* the gate at the time had no stationarity condition, and the rows that passed
  it carried 33-76 % of their wire work **after** the source stopped -- F=200 at
  4 Mbps drained 1,060,611 datagrams against 443,469 submitted in-window;
* `r` in the table is whole-run amplification folded into a ten-second window,
  which produced a "150-162 K wire datagrams/s frontier" that the in-window
  numbers do not support (34.8-84.4 K/s);
* the contract behind them is **admission plus eventual delivery**, which is what
  the gate measured, not sustainable service.

The current surface, its gate and its remaining open items are in
`docs/results/capacity-surface/README.md`; the current K statement is below.

## A capacity point is qualified only when every required repetition passes

"Two of three rows pass" is useful evidence and it is not a qualified capacity
point. The rule, defined now so it cannot drift with the data:

```text
(F, R, K) is QUALIFIED  iff  every required repetition (>= 3) passes the
                             row-level gate: conservation, cadence >= 99.9 %,
                             stationarity within the declared bound, real CPU
                             accounting
```

## Pre-fix evidence: everything measured before the recovery fix

> **Every number in this section describes the transport *before*** the
> lost-flight-tail fix (`fix(protocol): recover a lost flight tail instead of
> stranding it` and `fix(protocol): arm and fire the sender's own loss
> timeout`). Read it as a measurement of a *known-buggy* sender, not as a
> statement about the current head.
>
> Why it still matters: the defect it was measuring is exactly a **lost
> payload** defect. A receiver cannot NAK a gap that no later sequence number
> exposes, so a lost tail was invisible to the receiver and permanent. That is a
> direct candidate explanation for this section's "loses 256 payloads" and
> "loses 55 payloads" rows, which were being read as transport saturation.
>
> This evidence is therefore *dispositioned*: it identified the region of
> interest (K=64 insufficient at F=50 x 8 Mbps), and its conservation failures
> are now attributed. It is not evidence about the current head, and no
> qualified capacity point is claimed from it.

### The surface as measured then

Under that rule, nothing measured so far is a qualified capacity point:

```text
F=50, R=8 Mbps, K=64     insufficient: 765-6,670 lost datagrams per 60 s window,
                         172-296 K undelivered payloads, duplicates on retransmit
F=50, R=8 Mbps, K=256    2 of 3 repetitions (rep 1 loses 256 payloads)
F=50, R=8 Mbps, K=512   1 of 3 (rep 1 misses 71 of 45 592 ticks -> cadence
                         0.99844 < 0.999, and loses 55 payloads; rep 3 loses 484)
```

So the strongest K statement available *at that head* was: **K=64 is demonstrably
insufficient for F=50 x 8 Mbps, and K=256 or K=512 remove the persistent
receiver-reported loss/duplicate regime seen at K=64, but neither is yet fully
qualified.** K=256 looked like the better production candidate of the two on this
host. The post-fix canonical run (see `docs/results/capacity-surface/README.md`)
replaces this statement. Its first result, on a clean tree at `5c7a0c3`
(preserved as the tag `qualification-evidence-5c7a0c3`), predates the RTO
formula/estimator, timer-priority and gate-semantics fixes this PR later added
and is kept only as historical post-tail-fix evidence:

```text
F=50, R=8 Mbps/dest, K=256, 3 x 60 s, two independent sweeps (historical, 5c7a0c3):
  sweep B   3 of 3 rows QUALIFIED (xtask qualify: cadence, conservation,
            stationarity, submission partition, fence, fault state,
            RX loss = 0; duplicates accounted)
  sweep A   2 of 3: one repetition's SOURCE missed 68 of 45 592 boundaries
            (cadence 0.998509 against the declared 0.999)

every row, both sweeps: conservation exact, sec_a = 0, no duplicates delivered,
f_drain ~0.35 %, drain_ok, pending_after_drain = 0, no send failures, no fault,
rx_mode = RawReadiness (managed_rx = false) -- so this qualifies the
readiness RX path on this host, not ManagedMultishot on a ring-capable substrate
```

The **final canonical run**, at the actual head this PR merges, is a single
clean-tree sweep rather than two (`docs/results/capacity-surface/README.md`,
"Result: the final canonical run"):

```text
F=50, R=8 Mbps/dest, K=256, 3 x 60 s, one clean-tree sweep (git_sha=b11067d):
  3 of 3 rows QUALIFIED (xtask qualify --require-fence --require-clean:
            admission -- the whole requested fanout established at both endpoints
            and every offered payload accepted --, cadence, conservation,
            stationarity, submission partition, fence -- with source-explained
            misses no longer conflated with transport loss --, fault state,
            RX loss = 0; packet duplicates bounded by the retransmissions that
            explain them, including the drain's)

every row: conservation exact, sec_a = 0, no duplicate payloads delivered,
data_offered == data_accepted == generated_ticks x fanout, owner_faulted = false,
built_by_scaling = true, driver = IoUring, compio = 0.19.2, f_drain ~0.37 %,
drain_ok, pending_after_drain = 0, pre_window_drained = true, no send failures,
no fault, rx_mode = RawReadiness (managed_rx = false)
```

The K=64/256/512 lines above are the pre-fix surface and their conservation
failures are what the recovery fix removed; the "K=256 looks like the better
production candidate" reading survives, now with conservation that actually
holds.

## Throughput pass and real-time pass are different claims

The bounded catch-up source replays wall-clock boundaries after `service()`
returns. That is a valid way to measure **throughput** capacity with a bounded
external backlog, and it is *not* proof that the dataplane serviced every source
event on time. The gate therefore now emits two verdicts:

A run can offer at full cadence, have every payload accepted, deliver all of it
eventually, and still not have kept up: it simply queues what it cannot transmit
and drains the backlog after the source stops. That is **admission plus eventual
drain**, and it passed every check built before this one. The gate now has four
verdicts in the reviewer's hierarchy:

```text
CONSERVATION PASS   accepted == delivered, no starvation, no loss, drained
ADMISSION PASS      conservation + cadence >= 99.9 % (the source offered its schedule)
SUSTAINED PASS      admission + stationarity: f_drain within a declared bound
REAL-TIME PASS      sustained + offer lateness within a declared budget
```

Thresholds are tri-state -- `Undeclared`, `Pass`, `Fail(reason)` -- and an
undeclared threshold is **not** a pass. Treating it as one would promote every
row to the strongest claim the moment a flag was forgotten, while the summary
text said no verdict was given. A declared threshold with zero rows meeting it
exits non-zero, because this is meant to be an executable gate rather than a
report.

The lateness metric is **offer lateness**: how late each boundary's `send_shared`
was attempted, sampled before `service()`. It says the source was punctual, not
that the dataplane was -- a payload admitted there can leave the socket much
later, so this alone cannot support a real-time claim. The field is named
`offer_lateness_us_{p50,p99,max}` for that reason. The value the batching and GSO
experiments will need is **first-transmission submit lateness**
(`source deadline -> send_shared -> first DATA submitted -> TX completion`),
because an optimization must not win by moving work from the source queue into
the SRT queue.

`f_drain = drain_submitted / (tx_submitted_wire + drain_submitted)` is the share
of wire work that happened after the source stopped, and the bound is *declared*
(`--drain-fraction-max`), not hardcoded, because the natural tail has to be
measured on an unquestionably underloaded configuration first. F=50 at 8 Mbps
measures **0.0 %**; every other configuration measures 33-76 %, i.e. 3.2-10.0 s of
post-window CPU per row.

Applied to the surface:

```text
qualify: 2 of 11 rows sustained, 4 admitted-but-not-sustained (--drain-fraction-max 0.050)
qualify: 0 of 11 rows also meet the 5000us lateness budget
```

**Two rows sustained, zero real-time.** The sustained rows are both F=50 at
8 Mbps. The admitted-but-not-sustained rows are F=100 at 8 Mbps (33 %/47 %),
F=200 at 2 Mbps (44 %) and F=200 at 4 Mbps (70 %); the remaining five fail
conservation outright (cadence, delivery, starvation, loss, or no equilibrium).

`f_drain` is an **interim** stationarity proxy, and a blunt one -- it is measured
after the fact, from how much cleanup remained once the source stopped. It works
here only because the separation is enormous (0.0 % versus 33-76 %). Once wire
classification lands, stationarity becomes a direct property of the running
system: sample `unsent_first_DATA(t)` or the oldest queued first-transmission
DATA age during the window and require no positive trend, rather than inferring
stationarity from the shutdown tail.

Two harness defects fixed alongside this, both found in review:

* the catch-up cap was not enforced as documented. Emitting up to 64 overdue
  boundaries and then only declaring the remainder lost when `offered + 64 <=
  passed` let a stall of 65-127 boundaries emit 64 and carry the rest to later
  visits -- so the effective cap exceeded the declared one, and a boundary
  documented as lost could still become `generated_ticks`. The policy now lives
  in `srt_bench::source_schedule::catch_up` with tests at exactly 64, 65, 127 and
  128 overdue boundaries, plus a sequence test asserting every elapsed boundary
  is accounted for exactly once. The `generated + missed == expected` assertion
  could not catch this, because delayed boundaries eventually became generated.
* missing wire counts defaulted to `0.0`, so malformed evidence produced
  `f_drain = 0` -- the strongest possible result. `tx_submitted_wire` and
  `drain_submitted` must now be present, finite and non-negative, and
  `--drain-fraction-max` must be a fraction in `0..=1`.

### Two `r`s, two jobs

```text
r_window = wire submitted during the source window / DATA generated during it
r_whole  = (window TX + drain TX) / eventually delivered DATA
```

`r_whole` is whole-work cost accounting. `r_window` describes sustainable
service, and `r_window < 1` is the backlog signature: fewer wire datagrams left
the shard than DATA arrived. F=50 at 8 Mbps has `r_window = r_whole = 1.224`;
F=100 at 8 Mbps has `r_window = 0.867` against `r_whole = 1.455`; F=200 at
4 Mbps has 0.584 against 1.980. Multiplying `r_whole` by a DATA rate -- which the
previous revision of this document did -- invents an instantaneous wire rate that
the shard never sustained.

None of this is the final qualification: most cells have one repetition where the
protocol asks for at least three, the rate search is coarse (6 and 4 bracket the
F=200 frontier), and no configuration has been probed above 12 Mbps/destination.
It is the first surface where every passing cell satisfies the gate
simultaneously, which the burst evidence never did.

## The source had to stop sharing its schedule with `service()`

Before this could produce anything, one harness defect had to go. The tick loop
advanced a `next_tick` deadline and offered exactly one tick per visit, so any
`service()` overrun consumed the following boundaries and *counted them as
missed source ticks*. That made the cadence condition unfalsifiable in the wrong
direction: `generated_ticks` measured the service loop's punctuality rather than
the shard's ability to accept the offer, and a harness that slept slightly too
long looked exactly like an overloaded transport. F=50 at 8 Mbps missed 12-19 %
of its ticks for that reason alone.

The loop now offers every boundary the visit has passed, each with its own
deadline-derived SRT timestamp, bounded by `MAX_TICK_CATCHUP = 64` so a stall
cannot become an unbounded burst; boundaries beyond the cap are counted as missed
exactly as before, so `generated + missed == expected` still holds over the
window. F=50 at 8 Mbps then measures cadence 1.0000 with zero missed ticks, and
both of its rows pass the gate. The offer is still made from the same thread as
`service()` -- a fully independent producer would need a second Owner -- but it
is no longer *consumed* by service progress, which is the property the gate
needs.

## Non-goals

No **performance** change in this PR, and no speculative batching. Candidate D
(pipelining and batched submission, the one hypothesis #117 left open) is
measured **against** this baseline once it exists, not before -- otherwise there
is no capacity-valid workload to measure it on.

One correctness change is in scope, because qualification exposed it: the sender
had no reachable loss timeout of its own, so a lost *suffix* of a flight was
stranded permanently (the receiver can only NAK a gap a later sequence number
exposes). That is a transport/protocol change and it is the reason the earlier
surfaces in this document are labelled pre-fix evidence. It is bounded to one
probe per expiry, it adds no queue and no allocation to the steady state, and it
is pinned by deterministic tests in both `srt-protocol` and `srt-transport`.
