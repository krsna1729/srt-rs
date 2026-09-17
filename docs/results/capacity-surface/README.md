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
