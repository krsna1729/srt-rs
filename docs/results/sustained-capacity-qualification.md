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
| `data_accepted == rx_core_total` | accepted is not delivered |
| `data_zero == 0` | no destination starved |
| `data_below_half_mean == 0` | no slow subset |
| `sec_a == 0` | no reported loss |
| `drain_ok == true`, `pending_after_drain == 0` | equilibrium reached |
| `window_cpu_ms > 0`, `cpu_ms > 0` | the CPU accounting is real, not a stale zero |

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

## Non-goals

No transport changes in this PR. Candidate D (pipelining and batched
submission, the one hypothesis #117 left open) is measured **against** this
baseline once it exists, not before -- otherwise there is no capacity-valid
workload to measure it on.
