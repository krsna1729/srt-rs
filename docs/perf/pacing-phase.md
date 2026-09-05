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
