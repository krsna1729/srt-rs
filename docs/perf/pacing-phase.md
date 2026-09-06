# Sender pacing: phase loss under late service

## Summary

`SenderBuffer` derives a packet send period `P = wire_packet_size / MAXBW` and,
before this work, scheduled the next send one full period after the *actual*
send time. Any lateness in servicing the connection was therefore absorbed into
the interval and never repaid, so the achieved rate was `1/(P + lateness)`
rather than `1/P`.

Because no async runtime can wake at sub-millisecond resolution, `lateness` is
not small relative to `P` at live bitrates, and the deficit is first-order.

## Measured on `f216e02`

6-vCPU AMD EPYC, loopback, receiver CPUs 0-2 / sender 3-5, 15 s x 3 reps,
`--sock-buf 16m`. Source payload 8 Mbit/s = 759.9 packets/s = 1316 us between
payloads. `udp_rcvbuf_err` was zero in all 126 rows, so no cell is explained by
kernel receive pressure.

At **one connection**, where contention, receiver load and CPU are excluded by
construction (7-8% of one core):

| runtime | MAXBW | P (us) | offer | achieved interval |
|---|---|---|---|---|
| mio | 10 Mbit/s | 1065.6 | 67.8% | 1940 us |
| mio | 12 Mbit/s | 888.0 | 100.0% | 1316 us (source-limited) |
| mio | 16 Mbit/s | 666.0 | 100.0% | 1316 us (source-limited) |
| tokio | 10 Mbit/s | 1065.6 | 68.9% | 1911 us |
| tokio | 12 Mbit/s | 888.0 | 77.0% | 1708 us |
| tokio | 16 Mbit/s | 666.0 | 88.4% | 1488 us |

Controls:

- `fixed:100000000` (P = 106.6 us, pacing never binding) is 100.0% at 1 and 30
  connections on both runtimes.
- A 1 Mbit/s source is 100.0% in all 18 cells at every connection count and
  pacing arm: `P` (5328 / 8524 us) sits many service quanta below the 10528 us
  source interval, so neither quantization nor additive lateness can bind.
- Pacing *mode* is not a variable: `input-relative:25` (67.9%) and
  `fixed:10000000` (67.6%) are the same budget and the same result.

The two runtimes fail with different shapes. Mio's `epoll_wait` timeout is
rounded up to a whole millisecond, producing a staircase with a step measured
between 10.2 and 10.4 Mbit/s; Tokio shows a near-constant additive ~0.83 ms of
effective end-to-end sender wake/service latency on this path and no step. The
Tokio figure is a path measurement and is deliberately not attributed to the
timer wheel specifically: it folds timer quantization, executor wake latency,
`select!` processing and loop bookkeeping together.

At 200 connections the sender is at 175-215% CPU and a separate service
saturation regime dominates. That regime is **not** explained by the model
above and no claim is made about it here.

## Reference behaviour (libsrt 1.5.3)

Two independent observations, which agree.

**Black-box probe.** A standalone C program (not checked in) drove a libsrt
caller to a libsrt listener over loopback in normal live mode, set `SRTO_MAXBW`,
and sampled the sender's own `srt_bstats().pktSentTotal` at ~10 kHz, recording
every change; a jump of more than one between consecutive samples is a burst.
Measuring at the sender is deliberate: an earlier receiver-side revision was
discarded because it timed the receiver's wake/ACK cadence rather than the
pacer, reporting an effective period near zero against a nominal 2 ms. With a continuously backlogged sender the effective period matched the
configured one within 2.5% (`usPktSndPeriod` 2042 us, measured 2050 us against a
nominal 2000 us). After a genuine application idle gap of 2, 10 or 50 periods,
libsrt emitted **exactly one** immediate packet and then resumed strict period
spacing, gap-independent.

**Source behaviour.** libsrt does keep send-time debt: `CUDT::packData`
accumulates lateness relative to `m_tsNextSendTime` into `m_tdSendTimeDiff` and
subtracts it when scheduling the next packet, sending immediately and carrying
the remainder forward once the debt reaches a whole interval. It also clears
both `m_tsNextSendTime` and `m_tdSendTimeDiff` when `packUniqueData()` finds
nothing to send.

So the reference distinguishes two cases:

```text
sender queue stayed non-empty  ->  accumulate and repay debt, even past one interval
sender queue became empty      ->  discard debt, restart the schedule
```

The probe could only exercise the empty-queue branch; that is why it saw no
repayment. Both results are consistent.

## What this repository implements, and what it does not

`SrtConnection::send*()` materialises and queues a packet at call time. There is
no protocol-owned queue of *unsent application demand* whose continuous
occupancy the pacer could observe, so srt-rs cannot currently distinguish "the
runtime was late while data was waiting" from "the application had nothing to
send". Reproducing libsrt's full accumulated-debt semantics would require
introducing that demand state, which is an ownership change well beyond this
repair.

This work therefore implements a deliberately conservative approximation:

```text
preserve phase within the current pacing interval;
rebase the schedule after a whole interval has been missed.
```

Lateness below one period is repaid, which is the measured defect. Lateness of a
whole period or more discards the debt, which matches libsrt's empty-queue
branch but is *more conservative* than libsrt's non-empty-queue branch. Cells
whose service lateness exceeds one full period are consequently not repaired;
that is a known limitation of the approximation, not a correctness result. The
follow-up question -- whether srt-rs should expose enough demand/queue state to
reproduce the full debt semantics -- is left open deliberately.

## Scope note

`SrtConnection::send_message()` can fragment one application message into
several SRT packets and queues all fragments before invoking the pacing
bookkeeping once. That is a pre-existing per-packet-pacing question, orthogonal
to the single-packet 1316-byte workload measured here. It is not addressed by
this work, and the invariant below should not be read as covering every emitted
fragment.

## Result

Same host, same plan, same 15 s x 3 reps, `f216e02` vs the phase-preservation
commit. Raw rows: [before](../results/pacing-phase-before.tsv),
[after](../results/pacing-phase-after.tsv),
[boundary sweep](../results/pacing-quantum-after.tsv).

### The Mio defect is fully repaired

| N | arm | P (us) | before | after | achieved interval |
|---:|---|---:|---:|---:|---:|
| 1 | ir:25 | 1065.6 | 67.8% | **100.0%** | 1316 us (source-limited) |
| 30 | ir:25 | 1065.6 | 93.4% | **100.0%** | 1316 us |
| 30 | ir:50 | 888.0 | 96.5% | **100.0%** | 1316 us |
| 200 | ir:25 | 1065.6 | 77.4% | **96.2%** | 1368 us |
| 200 | ir:50 | 888.0 | 86.5% | **100.0%** | 1316 us |

The one-connection cell became source-limited exactly as predicted, and the
staircase is gone: `fixed:` arms at 10.2 / 10.4 / 10.6 / 10.9 Mbit/s, which
bracketed the millisecond step, are now uniformly 100.0% on Mio.

No cell exceeds its configured budget. The achieved interval is greater than or
equal to the pacing period in every one of the 40 cells measured, so the repair
bought rate without buying a burst. That is an aggregate rate bound; the
per-send guarantee that no instant can admit two packets is covered by the unit
tests, not by this campaign.

### Tokio improves everywhere, and two predictions were wrong

Predicted, from a model treating Tokio's service lateness as a constant ~0.83 ms:
`ir:25` and `ir:50` would reach ~100% (lateness below one period), and `ir:100`
would be unchanged near 88% (lateness above one period). Observed at N=1:

| arm | P (us) | before | predicted | **observed** |
|---|---:|---:|---:|---:|
| ir:25 | 1065.6 | 68.9% | ~100% | **87.6%** |
| ir:50 | 888.0 | 77.0% | ~100% | **87.4%** |
| ir:100 | 666.0 | 88.4% | unchanged | **96.2%** |

Both predictions failed, in opposite directions, and the cause is the same: the
constant-lateness model is wrong. Service lateness is a *distribution*
straddling the period, so each send independently falls into the preserve or the
rebase branch, and every arm gets a partial repair proportional to the fraction
of intervals landing below its period. That is why `ir:100` improved rather than
staying flat, and why `ir:25` improved without reaching 100%.

What bounds Tokio now is not phase. Post-fix achieved intervals of 1502 / 1505 /
1368 us correspond to 666 / 665 / 731 service visits per second, against the
760 packets per second the source offers. With one packet admitted per service
visit, sufficiency requires

```text
service_visit_rate >= min(source_rate, pacing_rate)
```

and Tokio on this path does not meet it, while Mio (about 1000 visits/s) does.
The residual Tokio deficit is therefore a service-rate limitation, not a pacing
defect, and closing it would require either a faster service loop or admitting
more than one packet per visit -- the accumulated-debt behaviour this repair
deliberately does not implement.

No regression appeared in any cell. The only negative movement is Tokio at 200
connections on `fixed:100000000` (94.8% -> 94.3%), a control where pacing never
binds, inside the noise of a cell already running at 215% CPU.

## Follow-up: issue #82 disposition

The residual Tokio service-visit deficit is tracked in
[#82](https://github.com/krsna1729/srt-rs/issues/82). Measured disposition:

- **A1** (per-connection Tokio tail-spin) is technically sufficient at N=1
  and **rejected on CPU economics at N=30**.
- **A2** (one high-resolution waiter per worker, no spin) is the challenger
  that must be tried before ownership changes. The reusable primitive lives
  in `srt-transport` as `HighResWaiter`; see [high-res-waiter.md](high-res-waiter.md).
- **Route B** (accumulated debt / multi-admit / `SrtConnection` ownership)
  remains untested and is not started by the A2 waiter.

