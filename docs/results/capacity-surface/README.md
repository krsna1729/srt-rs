# Sustained-capacity surface (first gate-backed run)

Raw sweep output for `docs/results/sustained-capacity-qualification.md`, measured
with the bounded catch-up source (so `generated_ticks` reflects the offer, not the
service loop's punctuality) and judged by `cargo xtask qualify`.

```text
configuration        gate   f_drain  r_window  r_whole  WIN wire k/s  DATA k/s  p99 ms
F=50,   8 Mbps/dest  2/2      0.0%    1.224    1.224        46.5       38.0     5.3
F=100,  8 Mbps/dest  0/2     33-47%   0.867    1.455        65.9       76.0    28.3
F=100, 12 Mbps/dest  0/1     43.6%    0.745    1.507        84.4      113.2     5.4
F=150,  8 Mbps/dest  0/1     65.7%    0.535    1.569        61.0      114.0     7.4
F=200,  8 Mbps/dest  0/2     42.8%    0.342    1.546        51.9      152.0    40.6
F=200,  6 Mbps/dest  0/1     75.9%    0.306    1.424        34.8      113.7    65.7
F=200,  4 Mbps/dest  0/1     70.5%    0.584    1.980        44.3       76.0    12.6
F=200,  2 Mbps/dest  0/1     44.4%    1.092    1.964        41.5       38.0    16.8
```

**A row is only sustained if the work happens inside the source window.** That is
what `f_drain` measures: the share of wire datagrams submitted *after* the source
stopped. One configuration keeps pace in every repetition measured so far --
**F=50 at 8 Mbps, `f_drain = 0.0 %`, `r_window = r_whole ~= 1.20`** -- and under
the configuration-level rule below it is a **candidate operating point, not a
qualified capacity point**: the 60 s run qualifies 2 of 3 repetitions. Every other row
accepted more than it could transmit and emptied the difference during a drain
that cost 3.2-10.0 s of CPU, so those rows establish *admission plus eventual
delivery*, not sustainable service.

**`WIN wire k/s` is the in-window rate** (`tx_submitted_wire / window`), and it is
the only rate comparable to an offered rate. It spans 34.8-84.4 K datagrams/s and
does **not** rise with the offer: the shard's in-window submission rate is set by
its service rate, so a higher offer does not produce a higher sustained wire rate
-- it produces a larger backlog.

**Two `r`s, two jobs.** `r_window = tx_submitted_wire / (generated_ticks x F)` is
in-window wire submissions per offered DATA. It is an interpretable
**wire-amplification** ratio only for stationary rows, where the wire work for the
offered DATA has actually happened; below stationarity `r_window < 1` and it is
primarily a **service-completion** ratio -- fewer wire datagrams left the shard
than DATA arrived, and interpreting that as cheap wire cost would be a category
error. `r_whole = (tx_submitted_wire + drain_submitted) / rx_core_total` is
whole-work accounting and must never be multiplied by a DATA rate to produce an
instantaneous figure. F=50's `r_window = 1.20` is a genuine amplification figure
and matches the draft's ~0.28 control budget, which is exactly what a shard
keeping pace should measure.

`r` is `(tx_submitted_wire + drain_submitted) / rx_core_total`; `C_SRT` is
`(window_cpu_ms + drain_cpu_ms) * 1000 / rx_core_total`.

One repetition per configuration except `F=50, 8` and `F=100, 8` and `F=200, 8`,
which have two. The protocol asks for three or more; this is a first surface, not
the final qualification.

## The best current candidate operating point, not yet qualified

`F50-r8-clean.tsv` is the same configuration over a **60 s** window with 3
repetitions, and it is the run this surface's single sustained point rests on:

```text
rep  generated/missed  in-window wire/s  drain wire  r_window  accepted==delivered  offer p99
1    45592 / 0              45 698            41       1.203        NO (256 short)    10.3 ms
2    45586 / 6              45 679            50       1.202        yes               13.8 ms
3    45592 / 0              46 320             1       1.219        yes                4.6 ms
```

Three things it establishes, and one it does not:

* **The cadence holds over 60 s** (0-6 missed ticks of ~45 590) and the drain is
  now 1-50 datagrams, i.e. genuinely stationary, with `r_window ~= 1.20` matching
  the protocol's control budget.
* **`C_SRT` is 17.1-18.0 us per delivered payload** at this operating point.
* **The offer is not real-time**: p99 offer lateness is 4.6-13.8 ms against a
  5 ms budget.
* **Conservation is not perfect**: rep 1 ends 256 payloads short of accepted
  (99.9888 %), which is exactly the TX pool's 256 slots. A 10 s window did not
  expose this; 60 s did. Until that is explained, "F=50 at 8 Mbps is sustained"
  holds for 2 of 3 repetitions, and the shortest honest statement is: *F=50 at
  8 Mbps keeps pace with the offer over 60 s, with a conservation gap of one TX
  pool depth in one of three repetitions.*

Provenance: this artifact records `git_sha=ed64108 git_dirty=true`, where the
dirty state is the field-rename diff (`offer_lateness_*` in the sweep schema)
that was still uncommitted when it was measured. That is a naming change with no
effect on what was measured, but it is not a clean-tree artifact and the final
qualification must be regenerated from a clean commit rather than inheriting
this one.

## The 256-payload deficit: hypothesis and what would settle it

`F50-r8-clean.tsv` rep 1 is the only repetition that fails conservation, and the
numbers line up exactly:

```text
rep  accepted      receiver     deficit   in-flight at window end   drain done - sub
1    2 279 600     2 279 344        256    256  (= K, pool saturated)          256
2    2 279 300     2 279 300          0     88                                88
3    2 279 600     2 279 600          0    139                               139
```

The K sweep below retires the sharpest version of that reading, but the accounting
is still the reason to chase it: the deficit appears only at run end, and rows with
88 and 139 in flight at window close lost nothing -- those completions arrived
during the drain and the receiver counted them.

`tx_completed_ok` proves the transport I/O operation completed, not that the
remote receiver observed the DATA, so this is not yet attributable. It looks like
a final-flight lifecycle transition rather than steady-state loss: the run is
stationary throughout (drain of 1-50 datagrams), the deficit has no mid-stream
signature, and the receiver reports `sec_a = 0`. A missing *suffix* of a stream is
also special in a way a mid-stream hole is not -- with no later sequence number
arriving, the receiver need not have evidence the final sequence numbers ever
existed, whereas a hole in the middle is exposed by its successors.

The K sweep (`F50-r8-K64.tsv`, `F50-r8-K512.tsv`) tests that directly: if the
deficit is a final-flight phenomenon it should track the saturated pool depth, and
if it stays at 256 regardless of K it is something else.

### K sweep: end-of-run deficit hypothesis and K sensitivity

Same configuration (F=50, 8 Mbps/destination, 60 s), varying only the TX pool/lane
count. `sec_a` is receiver-reported loss, `sec_b` receiver-reported duplicates:

```text
K    rep  accepted    receiver    deficit   in-flight@end  drain done-sub  sec_a   sec_b
64    1   1 142 086     845 781    296 305        4                4        6 670    180
64    2   1 659 525   1 487 562    171 963       11               11          765    343
64    3   1 810 486   1 586 471    224 015        4                4        4 864    114
256   1   2 279 600   2 279 344        256      256              256            0      -
256   2   2 279 300   2 279 300          0       88               88            0      -
256   3   2 279 600   2 279 600          0      139              139            0      -
512   1   2 276 050   2 275 995         55       58               58            0      0
512   2   2 279 500   2 279 500          0      512              512            0      0
512   3   2 279 400   2 278 916        484      512              512            0      0
```

Three conclusions, one hypothesis retired, and one rule this section applies:

```text
(F, R, K) is QUALIFIED  iff every required repetition (>= 3) passes the row gate
```

Under that rule **nothing measured so far qualifies**, including the F=50 rows
immediately above and every row in the surface table. What follows are candidate
operating points and their failure modes, not qualified capacity points.

1. **The deficit is visible only at final reconciliation, and is not yet
   localized.** Every run that sustains the offer reports `sec_a = 0` and the
   shortfall appears only at run end, ranging from 0 to ~K -- so it is not a
   property of the offered rate. But the harness has no time-series receiver
   conservation measurement, so nothing here yet places the missing payloads in
   the final flight. "Tail artifact" is a hypothesis with strong support, not a
   finding; the terminal fence is what decides it.
2. **The `deficit == saturated in-flight` reading does not survive K.** It holds
   exactly at K=256 (256 of 256), approximately at K=512 rep 3 (484 of 512), and
   fails at K=512 rep 2 (512 in flight, zero deficit). The looser statement the
   three K=256 rows support -- *the deficit appears when the pool is saturated at
   the window boundary* -- also weakens: K=512 rep 2 is saturated and loses
   nothing, while K=512 rep 1 has only 58 in flight and loses 55. What survives is
   weaker still: **the deficit is observed only at final reconciliation, with no
   aggregate mid-stream loss signal**, and the fence experiment is required to
   determine whether the missing payloads actually belong to the final flight.
3. **K bounds whether the shard can sustain the workload at all, and neither K
   above the threshold is yet qualified.** K=64 cannot sustain F=50 at 8 Mbps:
   receiver loss of 765-6,670 datagrams per 60 s window and 172-296 K undelivered
   payloads, with duplicates appearing (`sec_b`) as the protocol retransmits. K=256
   removes that regime and qualifies **2 of 3** repetitions (rep 1 loses 256
   payloads); K=512 is weaker, qualifying **1 of 3** (rep 1 misses 71 of 45 592
   ticks, cadence 0.99844 < 0.999, and loses 55 payloads; rep 3 loses 484). So a
   capacity point is a `(F, rate, K)` triple rather than a `(F, rate)` pair, and
   the strongest current statement is: **K=64 is insufficient; K=256 and K=512
   remove the K=64 loss/duplicate regime but neither is fully qualified.** K=256
   is the better production candidate on this host.

The diagnostic that decides this is the terminal fence the reviewer proposed: a
measurement-only sentinel per destination, sent after the last measured tick,
that does not count toward `data_accepted`, `rx_core_total`, `r` or workload CPU.
A fence after the missing tail forces later sequence progress, which separates the
outcomes cleanly -- gap disappears with no retransmits (teardown/stats race), gap
disappears with ~K retransmits (the final flight really was lost and the fence
enabled recovery), gap remains after all fences (protocol bug), fence never
arrives (sender lifecycle).

## Terminal fence: A/B, and what the first runs say

Sender-side fence (one ordinary later DATA payload per destination after the
measured window, counted separately and excluded from every workload figure), run
as an A/B at F=50, 8 Mbps/destination, 60 s, 2 repetitions per arm:

```text
arm       rep  accepted    delivered  measured deficit  in-flight@end  drain  fence acc  sec_a  sec_b  missed
A no fence 1   2 279 600   2 279 600          0              50           0        -        0      0       0
A no fence 2   2 279 600   2 279 600          0             128           0        -        0      0       0
B fence    1   2 279 250   2 279 023        277 *           256          84       50        0      0       7
B fence    2   2 279 600   2 279 650          0 *            78          50       50        0      0       0
```

\* `rx_core_total` cannot distinguish fence payloads from measured DATA, so the
measured deficit is `accepted - (delivered - fence_accepted)`; rep 2's raw
`delivered` exceeds `accepted` by exactly the fence count, which is the arithmetic
confirming that accounting rather than a surplus.

What it establishes:

* **The fence is not a cure.** In the one repetition where the deficit appears
  (fence arm, rep 1: TX pool saturated at 256, 7 source ticks missed), **277
  payloads are still missing after all 50 fences were accepted**. That rules out
  the simplest lifecycle reading -- "the tail only needed later sequence progress
  to become visible" -- for this case, and moves it toward a delivery or
  accounting defect at the tail when the pool is saturated.
* **The fence arm conserved exactly in the repetition without saturation**, and
  the no-fence arm conserved in both of its repetitions, so the deficit remains
  intermittent rather than deterministic.
* `sec_a = 0` and `sec_b = 0` in both arms, so the missing payloads are not
  reported as loss or duplicates by the receiver; they are simply absent from its
  count.

Limits, stated rather than glossed: 2 repetitions per arm is far below the >= 3 the
protocol requires and the deficit appears in roughly one repetition in three, so
this is not yet a resolved experiment -- it is the first evidence that the
lifecycle hypothesis alone is insufficient. The next run needs more repetitions,
and receiver-side fence identification (so fence payloads are excluded by the
receiver rather than by arithmetic), plus the per-peer missing set the protocol
document calls for.

## Post-fix canonical run: thresholds frozen before measuring

The surfaces above were measured against a sender that had **no reachable loss
timeout of its own**, so a lost *suffix* of a flight was stranded permanently
(the receiver can only NAK a gap that a later sequence number exposes). Everything
on this page is therefore **pre-fix evidence**, and the "256-payload deficit"
analysis above is its most valuable output: the deficit is exactly one TX pool
depth, appears only at end of stream, and has no mid-stream signature.

This section was written **before** the run it describes, so the thresholds cannot
have been chosen to fit the result.

```text
head at declaration:     48e89fc (clean tree required at run time)
configuration:           F=50, 8 Mbps/dest, payload 1316 B (interval 1316 us),
                         K=256 TX lanes, H=64 connect concurrency, 1 sender process
window:                  60 s x 3 independent repetitions
diagnostics:             --identity --fence (tick-tagged payloads + terminal fence)

declared cadence        generated/expected >= 0.999
declared stationarity   f_drain <= 0.01
declared real-time      UNDECLARED (no budget claimed)
```

Acceptance for the run to be called a qualified capacity point (all three
repetitions, not "two of three"; one repetition passes only when every shard row
in it passes, and a shard count above one is what the `rep`/`shard` hierarchy
exists for):

```text
1. admission:    established == fanout == rx_established,
                 data_offered == generated_ticks x established,
                 data_accepted == data_offered
2. conservation: accepted == delivered (identity payloads, fence excluded)
3. cadence:      generated / expected >= 0.999
4. stationarity: f_drain <= 0.01
5. fence:        diag_fences_seen == fanout and
                 diag_missing_final == missed_source_ticks x rx_established
6. accounting:   sum(tx_class_*) == tx_class_total == tx_submitted_wire
7. fault:        owner_faulted == false; tx_failures_pending == 0
8. RX:           rx_lost == 0; diag_duplicate_payloads == 0, and the packet-level
                 counts (rx_duplicates, rx_sec_b) <= tx_class_data_retx + drain_class_data_retx
9. provenance:   git_dirty == false, built_by_scaling == true, pre_window_drained == true
                 (the canonical group, `--require-clean`)
```

`--drain-fraction-max 0.01` is a declared bound, not an inferred one: the pre-fix
steady configuration measured `f_drain = 0.0 %`, while every backlogged
configuration measured 33-76 %, so 1 % separates keeping pace from not keeping
pace by more than an order of magnitude on either side. Real time stays
undeclared: `first_submit_lateness_us_*` is reported, and the offer itself is
already known not to be punctual (p99 4.6-13.8 ms against a 5 ms budget), so a
real-time claim needs a source that is punctual before it can be about the
dataplane.

## Historical: the post-fix canonical run at 5c7a0c3 (superseded)

**Superseded by "Result: the final canonical run" below.** This section's sweeps
were measured against `sender_rto.rs` as it stood right after the tail-recovery
fix landed: `COMM_SYN_MICROS` was still 100 ms (initial RTO 500 ms, not the
corrected 320 ms), the `SenderRto` timer-action priority-insertion fix did not
exist yet, `FirstSubmitLateness` was still the single-tier 10 ms-range
histogram, and the fence/repetition/real-time gate semantics below were not
yet the ones `cargo xtask qualify` enforces today. None of that changes the
correctness claim this section still supports -- the lost-flight-tail defect
is fixed, and conservation is exact -- but this is no longer qualification
evidence for the code in this PR. Kept as historical post-tail-fix evidence
only; the tag `qualification-evidence-5c7a0c3` still resolves the exact tree
these numbers describe.

**Scope: this qualifies the RawReadiness receive path on this host.** Every row of
both sweeps records `rx_mode=Some(RawReadiness)` and `managed_rx=false` -- the
readiness reader, not the managed multishot consumer. The result below therefore
says nothing about `ManagedMultishot` on a substrate that can register a
provided-buffer ring; such a host needs its own sweep. The field is printed on
every row for exactly this reason, and a capacity number is only transferable
together with the RX path it was measured on.

The artifacts record the SHA they were measured at. That commit is preserved as
the tag `qualification-evidence-5c7a0c3`, because this branch's history was
consolidated before merge (the same tree content, with the fixup commits folded):
the only source change after the measurement is the test-only TLPKTDROP-age pin,
and everything else is documentation. A reader who wants the exact tree behind
these numbers should resolve that tag rather than a later SHA.

Two independent clean-tree sweeps of the frozen configuration and thresholds,
`git_sha=5c7a0c3 git_dirty=false` for both. Neither is a rerun-until-green: the
second was taken because the first showed a *source* stall, and reporting both is
what keeps a host property from being read as a transport one.

```text
sweep A: F50-r8-K256-postfix.tsv    sweep B: F50-r8-K256-postfix-b.tsv

rep  cadence    missed  f_drain  conserved  retx  sec_a/sec_b  fences   missing_final   fsub p99  offer p99  C_SRT  r_window
A1   0.999671      15   0.378 %  yes          0    0/0       50 -> 50    750 (15x50)     338 ms     16.1 ms   17.9   1.199
A2   0.998509      68   0.357 %  yes         50    0/50      50 -> 50   3400 (68x50)     371 ms      7.8 ms   17.2   1.217
A3   1.000000       0   0.368 %  yes          3    0/3       50 -> 50      0             271 ms      7.6 ms   17.6   1.212
B1   1.000000       0   0.375 %  yes          0    0/0       50 -> 50      0              82 ms      4.4 ms   17.3   1.219
B2   1.000000       0   0.340 %  yes          0    0/0       50 -> 50      0             117 ms      4.7 ms   17.2   1.218
B3   1.000000       0   0.347 %  yes          0    0/0       50 -> 50      0               2.7 ms    1.3 ms   15.1   1.233

every row: short/failed/peer_local/transient/tx_failures_pending = 0, drain_ok = true,
           pending_after_drain = 0, rx_dropped = rx_truncated = 0, tx pool 256/256 free
           at the end, tx_pool_high_water = 256, sum(tx_class_*) == tx_submitted_wire
conserved = data_accepted + fence payloads the receiver saw == rx_core_total, exactly
C_SRT     = window_cpu_ms * 1000 / data_accepted
```

**Sweep B is 3 of 3 under every frozen criterion** (`cargo xtask qualify`: "3 of 3
rows sustained"). Sweep A is 2 of 3: A2's source stalled long enough to miss 68 of
45 592 boundaries, and cadence is a *source* criterion that the declared 0.999
bound is meant to catch. Across both sweeps that is **six of six on every
transport-side criterion** -- conservation, stationarity, the submission
partition, the fence, fault state, and RX loss/duplicates -- and the only failures
are source stalls.

What each criterion actually showed:

* **Conservation is exact, six times out of six.** No "lost payload" row exists
  any more. The pre-fix surface on this page lost 765-6 670 datagrams per window
  at K=64 and 256 payloads in one of three repetitions at K=256; post-fix the
  receiver accounts for every payload the sender accepted, in every repetition of
  both sweeps. This is the defect the recovery change fixed, and it is the one
  claim this page was written to be able to make.
* **No unresolved loss anywhere, and duplicates are accounted**: `sec_a = 0` in
  all six rows, and `diag_duplicate_payloads = 0` (no payload was ever delivered
  twice). Four rows have zero duplicates; the two that do not (A2: `data_retx=50`,
  `sec_b=50`; A3: `data_retx=3`, `sec_b=3`) equal their retransmission probes
  exactly, so they are recovery traffic the receiver saw twice *at packet level*,
  not unexplained duplicate delivery. The executable gate requires `sec_a == 0`;
  it does not require `sec_b == 0`, because a duplicate packet is what a
  successful repair looks like from the receiver's side.
* **Stationarity holds at ~0.35 %** against the declared 1 %, i.e. ~10 K of
  2.8 M datagrams. That figure now *includes* a deliberate ARQ settle window after
  the source stops (see below), so it is not comparable with the pre-fix rows'
  50-52 datagrams on this field alone.
* **The fence is conserved in all six rows** (50 offered, 50 seen) and
  `diag_missing_final` is zero in four of six; in the other two it equals
  `missed_source_ticks x established` exactly (750 = 15x50, 3400 = 68x50) with
  `missing_scatter_peers = 50`, i.e. whole ticks the source never offered --
  `data_offered == generated_ticks x F` on every row.
* **Cost is unchanged**: `C_SRT` is 15.1-17.9 us per accepted payload against the
  pre-fix 17.1-18.0, and `r_window` is 1.199-1.233 against the pre-fix ~1.20. The
  recovery work this release adds costs nothing measurable in a lossless run.

### One measurement defect the last sweep found, and the fix

The first clean-tree attempt recorded a repetition with 239 accepted-but-undelivered
payloads, `retx = 0`, and `missing_suffix_peers = 32`. That is the *symptom* the
recovery change was written for, so it had to be explained rather than rerun away.
It was the harness, not the transport: a lost suffix leaves nothing queued and
nothing in flight -- every datagram was submitted and completed -- so the run
declared equilibrium the moment the TX path went quiet, which was *before* the
sender's timeout (500 ms at this measurement's `COMM_SYN_MICROS`, since
corrected to an initial 320 ms -- see "Result: the final canonical run" below)
had expired. Nothing had failed; the measurement simply ended before anything
could ask for the tail again.

The drain now keeps servicing for a bounded ARQ window (1.5 s of protocol time,
longer than the timeout plus the 26 ms RTT measured here) after the stream goes
quiet, measured against DATA work alone because the ACK/ACKACK cadence keeps the
TX path busy forever, and only then declares the run finished. After the fix, the
same configuration conserves in both sweeps. A run's equilibrium is now protocol
equilibrium, not TX quiescence.

Real time remains **undeclared**. The offer is not punctual (p99 1.3-16.1 ms
against the 5 ms budget the harness prints), and `first_submit_lateness` p99 --
the deadline-to-wire path, which includes that offer lateness -- is 2.7-371 ms.
Neither supports a real-time claim and neither is presented as one.

## Result: the final canonical run

This is the qualification evidence for the code that actually merges. It follows
the third review pass, which closed four closeout defects in the gate, the sweep
tooling, and the sender RTO:

* the gate now requires the offered workload to have been **admitted**
  (`established == fanout == rx_established`,
  `data_offered == generated_ticks * established`, `data_accepted ==
  data_offered`), so a shard that refuses part of its offer can no longer pass on
  "accepted == delivered" alone;
* qualification counts **repetitions, not rows**: `cargo xtask scaling` writes
  one `ROW` per shard per repetition, a repetition passes only when every shard
  row in it passes, and missing or duplicated shard rows are malformed evidence;
* `cargo xtask scaling` now **builds the children it benchmarks** and takes their
  paths from cargo's own artifact records, so the recorded `git_sha` describes
  the binaries that ran (`built_by_scaling=true`) instead of whatever was left in
  `target/`;
* the sender **reprograms its RTO from the instant a blind probe is actually
  submitted**, keeping the accumulated backoff, instead of firing the deadline
  the probe was queued under.

See `crates/xtask/src/qualify.rs`'s own tests for the gate semantics and
`docs/differential-audit-robotweax.md` for the RTO detail.

```text
head at measurement:  cbc58a2 (clean tree required at run time)
configuration:        F=50, 8 Mbps/dest, payload 1316 B, K=256 TX lanes,
                       H=64 connect concurrency, 1 sender process
window:                60 s x 3 independent repetitions, one clean-tree sweep
diagnostics:           --identity --fence (tick-tagged payloads + terminal fence)
command:               cargo xtask scaling --out F50-r8-K256-final.tsv \
                         --n 50 --shards 1 --reps 3 --window-ms 60000 \
                         --tx-lanes 256 --connect-cc 64 --payload-bytes 1316 \
                         --rate-mbps-per-dest 8 --fence true --identity true
gate:                  cargo xtask qualify F50-r8-K256-final.tsv \
                         --tolerance 0.999 --drain-fraction-max 0.01 \
                         --require-fence --require-clean
```

```text
artifact: F50-r8-K256-final.tsv
measured at: git_sha=cbc58a2 git_dirty=false build_profile=release built_by_scaling=true

rep  cadence    missed  f_drain  conserved  sec_b/retx  fences   missing_final  fsub p99  fsub max  C_SRT  r_window
1    0.999474      24   0.343 %  yes        194/194   50 -> 50   1200 (24x50)    122 ms    290.8 ms  18.2   1.210
2    1.000000       0   0.329 %  yes        106/106   50 -> 50      0            124 ms    204.0 ms  16.7   1.221
3    1.000000       0   0.348 %  yes        110/110   50 -> 50      0             45 ms    101.3 ms  17.0   1.215

every row: rx_mode = Some(RawReadiness) (managed_rx = false), owner_faulted = false,
           short/failed/peer_local/transient/tx_failures_pending = 0,
           drain_ok = true, pending_after_drain = 0, rx_lost = 0, rx_sec_a = 0,
           diag_duplicate_payloads = 0, pre_window_drained = true,
           data_offered == data_accepted == generated_ticks x 50,
           fence_offered = fence_accepted = rx_diag_fences_seen = 50 (== fanout),
           tx pool 256/256 free at the end, tx_pool_high_water = 256
conserved = data_accepted + fence payloads the receiver saw == rx_core_total, exactly
sec_b/retx = the receiver's packet-level duplicates against the sender's own window
             retransmissions (the drain submitted none, and rx_duplicates is 0)
C_SRT     = window_cpu_ms * 1000 / data_accepted (us/payload)
```

```text
qualify: 3 of 3 rows sustained, 0 admitted-but-not-sustained (--drain-fraction-max 0.010)
qualify: no --lateness-budget-us declared, so no real-time verdict
qualify: QUALIFIED (sustained)  F=50 rate=8000000 K=256 payload=1316 rx_mode=Some(RawReadiness)
         window_ms=60000 git_sha=cbc58a2 n=50 shards=1 reps=3  3/3
```

**Duplicates are accounted rather than merely unrequired.** The receiver's
packet-level duplicate count equals the sender's retransmission count exactly in
all three rows (194/194, 106/106, 110/110), which is the inequality the canonical
gate now enforces (`rx_sec_b <= tx_class_data_retx + drain_class_data_retx`), and
`diag_duplicate_payloads = 0` everywhere: no payload was ever delivered twice at
the application level. `rx_duplicates` (the sender's own caller socket, which has
nothing to receive in this topology) is 0 throughout.

**Rep 1's `missing_final=1200` is exactly `24 missed_source_ticks x 50
rx_established`** -- the source itself missed 24 of 45 592 boundaries (cadence
`0.999474`, inside the declared `0.999` tolerance) -- and the fence gate's job is
to tell that apart from transport loss rather than demand literal-zero missing.
It does: `unexpected_transport_missing = 0` on every row. This is the exact case
the fence-gate fix in this PR exists for: the historical section's `A1`/`A2` rows
hit the same shape and, before the fix, the executable gate had no way to say so
without either wrongly failing them or silently requiring 100 % source cadence.

**`first_submit_lateness` p99 is a real percentile, not `max` relabeled.** The
p99s here (122 ms, 124 ms, 45 ms) and the maxima (290.8 ms, 204.0 ms, 101.3 ms)
are clearly different values; under the old single-tier 10 ms-range histogram the
maxima would have landed in the same overflow bucket as everything else in the
tail. The two-tier histogram (100 us buckets to 10 ms, 1 ms buckets to 1 s) is
what makes that distinction possible.

**Host conditions, stated rather than hidden.** This is the same shared host as
the historical run, but its condition changed during the closeout: a preflight
probe -- an idle 1 ms loop with no benchmark running -- saw 20-300 ms vCPU stalls
in bursts, and every attempt taken while that was true failed *only* the
source-cadence criterion (94-233 missed boundaries of 45 592; 51 consecutive
100 s preflights found a stall above 50 ms and were not followed by a sweep). One
attempt also failed establishment, and the new admission identity is what caught
it (`established=39 != fanout=50`, `data_accepted=33720 != data_offered=2279600`)
instead of reporting a throughput number for a shard that had lost a fifth of its
population. The artifact above is the run taken once the host measured quiet
again (2 gaps above 80 ms over 180 s); rep 1's 24 missed boundaries are its
residue, and the higher `first_submit_lateness` (45-124 ms p99 against the
historical 11-39 ms) is the same noise. It is reported, not gated: real time stays
undeclared either way. Nothing here changes the transport-side result, which
passed in every row of every attempt.

**Conservation, fence, and RX-loss criteria are exact on all three rows**,
matching the historical run's result: the closeout tightened the *executable
gate's* semantics, the sweep's provenance, and the sender's RTO epoch, not the
transport correctness property the earlier run had already established. Cost is
unchanged within measurement noise (`C_SRT` 16.7-18.2 us/payload, `r_window`
1.210-1.221, against the historical 15.1-17.9 us/payload and ~1.20-1.23).

Real time remains **undeclared** here too -- no `--lateness-budget-us` was
supplied, and this run does not change that claim.
