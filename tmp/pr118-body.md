Qualification harness, an executable gate, and — because the qualification exposed it — the transport correctness defect that the earlier surfaces were measuring without knowing it.

## Status

> **F=50 x 8 Mbps/destination x K=256 is QUALIFIED**: `cargo xtask qualify` reports 3 of 3 rows sustained on a clean-tree sweep at `5c7a0c3`, and 6 of 6 repetitions across two independent sweeps pass **every transport-side criterion** — exact conservation, stationarity ~0.35 % against a declared 1 %, a closed submission partition, a conserved terminal fence, no Owner fault, and no RX loss or duplicates. The only failures anywhere are *source* stalls (one repetition in one sweep missed 68 of 45 592 boundaries against the declared 0.999 cadence bound; the other sweep has none).

```text
(F, R, K) is QUALIFIED  iff every required repetition (>= 3) passes the row gate
                         (conservation, cadence >= 99.9 %, stationarity, real CPU,
                          submission partition, fence, fault state, RX loss/duplicates)
```

The headline change since the first draft of this PR: **there is a transport change in it.**
The end-of-run deficit this branch spent its history chasing was a real correctness gap,
and it is fixed. Everything measured before the fix is kept below, clearly labelled.

## The defect, and why only the sender could fix it

A receiver can only NAK a gap that a *later* sequence number exposes. A lost **suffix** of
a flight exposes none: `sec_a` stayed zero, the receiver reported no loss, and the payloads
were simply absent — while the sender's only retransmission trigger was NAK-fed, so nothing
ever asked for them again. That is exactly the shape the surfaces below recorded.

Deterministic reproduction (0.01 s, with a control that validates the harness):

```text
control (nothing dropped)   4 of 4 DATA packets delivered
lost final DATA packet      3 of 4, permanently stranded   <- before
                            4 of 4                          <- after
```

Fixed in two commits, deliberately split because the second is what makes the first real:

1. `fix(protocol): recover a lost flight tail instead of stranding it` — the recovery
   *action*: one probe of the newest sent packet, queued only when no selective recovery is
   already pending.
2. `fix(protocol): arm and fire the sender's own loss timeout` — the *trigger*. The old
   `TimerId::Retransmit` was only ever armed by the code that drains an already-filled NAK
   queue, so the action had no reachable trigger: a lost tail fills no queue. The timer is
   now split into `RetransmitContinue` (zero-delay continuation of queued work, no notion of
   loss) and `SenderRto` (a real timeout, `SRTT + 4*RTTVar + 2*COMM_SYN` with backoff,
   armed when DATA is *submitted* — not merely accepted — reset only on cumulative ACK
   **progress**, expiring into exactly one probe). TLPKTDROP age still comes from the
   original `sent_time`.

Differential reference: Robotweax/srt `983a6bd` (non-progress ACKs must not starve live tail
recovery) and `a02c308` (bound Live timeout recovery to one tail probe). No source copied;
recorded in `docs/differential-audit-robotweax.md` with what `srt-rs` did before and which
test now pins each decision.

**The trigger is load-bearing, and that is proven rather than asserted.** Disabling the
submission arming fails `a_flight_lost_in_full_is_recovered_by_the_submission_trigger`;
disabling fault detection fails the TX-lane regression at its fault assertion.
`crates/srt-transport/tests/tail_recovery.rs` drives the whole path through the real
`ManualTimerStore` and never calls `handle_timer` by hand.

## Submission accounting, gate, and contract

- **TX classification at the submission boundary.** `DatagramClass` is decided by the
  protocol at materialization and carried through `DatagramSlot::commit`; the Owner reports a
  per-visit partition with `sum(classes) == tx_packets_submitted` enforced by test.
- **First-transmission submit lateness** (`FirstSubmitLateness`: 100 x 100 µs histogram plus
  an exact maximum, reset-on-read), measured at lane handoff. It spans the deadline-to-wire
  path and therefore *includes* the source's own lateness; the difference between it and
  `offer_lateness` is the transport's own delay. Reported, and deliberately **not
  gated** — this project has not declared a real-time budget, and an ungated field must not
  read as a passing one.
- **`TxPoolSnapshot::high_water`** and **`Owner::rx_session_totals`** (SRT-level `lost` /
  `duplicates`, preserved for retired sessions through a per-table retired ledger).
- **`cargo xtask qualify` requires the row to be decomposable**
  (`sum(tx_class_*) == tx_class_total == tx_submitted_wire`), records the send-outcome
  counters, and accounts for the terminal fence
  (`data_accepted + fence payloads the receiver saw == rx_core_total`). Two schema gaps were
  fixed on the way: the sweep parser looked for `tx_pool_free`/`tx_pool_capacity` while the
  harness printed `tx_pool=free/capacity`, and the send-outcome counters were printed and
  never captured.
- **`SHARD_OVERLOAD_REASONS` was 4 while `ShardOverloadReason` had five variants**, so
  recording `OutputProtocolError` indexed past the array; the count now derives from the
  enum with a compile-time assertion.
- **`docs/owner-contract.md`**: the Owner's semantics frozen clause by clause with the test
  that pins each one, plus an explicit list of what stays unfrozen (pool and lane
  implementation, heaps, io_uring flags, batching).

## Result (`docs/results/capacity-surface/README.md`)

```text
sweep A: F50-r8-K256-postfix.tsv    sweep B: F50-r8-K256-postfix-b.tsv   (both 5c7a0c3, clean tree)

rep  cadence    missed  f_drain  conserved  retx  sec_a/sec_b  fences   missing_final   C_SRT  r_window
A1   0.999671      15   0.378 %  yes          0    0/0       50 -> 50    750 (15x50)     17.9   1.199
A2   0.998509      68   0.357 %  yes         50    0/50      50 -> 50   3400 (68x50)     17.2   1.217
A3   1.000000       0   0.368 %  yes          3    0/3       50 -> 50      0             17.6   1.212
B1   1.000000       0   0.375 %  yes          0    0/0       50 -> 50      0             17.3   1.219
B2   1.000000       0   0.340 %  yes          0    0/0       50 -> 50      0             17.2   1.218
B3   1.000000       0   0.347 %  yes          0    0/0       50 -> 50      0             15.1   1.233

every row: short/failed/peer_local/transient/tx_failures_pending = 0, drain_ok, pending_after_drain = 0
           rx_dropped = rx_truncated = 0, pool 256/256 free at the end, high_water = 256
```

`missing_final` is zero in four of six and, where it is not, equals
`missed_source_ticks x established` exactly with `missing_scatter_peers = 50`: whole ticks
the source never offered (`data_offered == generated_ticks x F`). Cost is unchanged
(`C_SRT` 15.1–17.9 µs/payload against the pre-fix 17.1–18.0; `r_window` ~1.20 both).

**One measurement defect found and fixed while producing this:** the first clean-tree
attempt showed 239 accepted-but-undelivered payloads with `retx = 0` and
`missing_suffix_peers = 32` — the old symptom. It was the harness ending the run at *TX*
quiescence: a lost suffix leaves nothing queued and nothing in flight, so the run declared
equilibrium before the sender's 500 ms timeout could expire, and nothing had failed. The
drain now keeps servicing for a bounded ARQ window (1.5 s of protocol time) after the stream
goes quiet, measured against DATA work alone, and only then declares the run finished.
`f_drain` now includes that window's control traffic (~10 K of 2.8 M) and is not comparable
with pre-fix rows on that field alone.

## Pre-fix evidence (kept, and labelled)

Every surface below was measured against a sender with **no reachable loss timeout**, so its
conservation failures are explained rather than merely recorded. `docs/results/` labels them
pre-fix: earlier 60 s surfaces, the K sweep, and the fence experiment, whose most valuable
output was the deficit's shape (exactly one TX pool depth, end of stream only, no mid-stream
signature).

```text
pre-fix configuration   gate   f_drain  r_window  r_whole  WIN wire k/s  DATA k/s
F=50,   8 Mbps/dest     2/3      0.0%    1.20      1.20       45.7        38.0
F=100,  8 Mbps/dest     0/2     33-47%   0.867     1.455       65.9        76.0
F=100, 12 Mbps/dest     0/1     43.6%    0.745     1.507       84.4       113.2
F=150,  8 Mbps/dest     0/1     65.7%    0.535     1.569       61.0       114.0
F=200,  8 Mbps/dest     0/2     42.8%    0.342     1.546       51.9       152.0
F=200,  6 Mbps/dest     0/1     75.9%    0.306     1.424       34.8       113.7
F=200,  4 Mbps/dest     0/1     70.5%    0.584     1.980       44.3        76.0
F=200,  2 Mbps/dest     0/1     44.4%    1.092     1.964       41.5        38.0
```

Two withdrawn frontier claims came from folding drain work into the source interval
("150–162 K wire datagrams/s", and "220 destinations/core" before it). The in-window rate
spans 34.8–84.4 K datagrams/s and does not rise with the offer: a higher offer buys a larger
backlog, not a faster wire rate.

## Harness changes (unchanged from the first draft)

- **Rate is an independent variable** (`--rate-mbps-per-dest`, interval derived).
- **Bounded catch-up source**, with the policy in `srt_bench::source_schedule::catch_up` and
  tests at exactly 64/65/127/128 overdue boundaries.
- **Offer lateness renamed as such** (`offer_lateness_us_{p50,p99,max}`): source punctuality,
  not dataplane punctuality.
- `rx_sec_b`, `offered_bps_per_dest`, receiver lifetime covering the drain with a grace
  period, plus the diagnostic terminal fence (`--identity --fence`).

## Verification

- `cargo xtask precommit` green at the final head.
- `cargo test --workspace --all-features`: 1383 tests, 0 failures, plus the new
  deterministic regressions (5 protocol-side timeout scenarios, 4 in
  `crates/srt-transport/tests/tail_recovery.rs`, the TX-lane fault containment, the
  telemetry partition and lateness rules).
- `cargo xtask qualify` on both committed sweeps, with the thresholds frozen *before*
  measuring (`docs/results/capacity-surface/README.md`).

## Explicitly out of scope

The wider differential audit of Robotweax/srt — Lite-ACK receive-window credit, immediate
window-reopen advertisement, control validation before liveness mutation, TSBPD drain before
terminal peer-close, TLPKTDROP sequence tombstones, transactional NAK processing, and
encrypted retransmission identity — is a **separate follow-up PR**, not this one. Candidate D
(pipelining and batched submission) is still measured *against* this baseline rather than in
it, and the GSO census remains a measurement to do first.
