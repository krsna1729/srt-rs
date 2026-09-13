# SRT-600 qualification

The production decision loop is deliberately smaller than the exploratory
matrix. It uses ten fixed scenarios and keeps the shipped `srt-transport`
runtime on the dataplane. The benchmark runner supplies the environment and
records one row per scenario; `srt-bench qualify` validates and scores those
rows without creating another event loop.

Generate the immutable scenario corpus with:

```text
cargo run -p srt-bench -- qualify plan --out scratch/srt600-plan.tsv
```

The runner must produce a bounded measurement file with this exact header and
one row for each scenario:

```text
scenario	offered	delivered	correctness_failures	cpu_ms	p99_lateness_us	rss_kb	syscalls
```

Score a candidate against a known-good baseline:

```text
cargo run -p srt-bench -- qualify score scratch/srt600-baseline.tsv scratch/srt600-head.tsv
```

The score is admissible only when every scenario has zero correctness failures
and delivered/offered is at least 0.99. CPU time, p99 service lateness, RSS,
and syscall count are compared by a geometric mean of baseline/candidate
ratios. A candidate that regresses any metric by more than the configured noise
budget (3% by default) fails the whole qualification. Optional production LOC
penalty inputs are bounded and applied only after the correctness gate.

The corpus covers clean operation, 600-destination fan-out, loss/reorder,
burst loss, encrypted key rotation, one slow consumer, connect churn, relay
source-age preservation, libsrt interoperability, and bonded broadcast. The
runner should execute each case in a quiet pinned window and keep the full
matrix for exploratory diagnosis rather than promotion decisions.

Hidden mutation checks remain an evaluator concern: inject dropped send
suffixes, skipped timers, ownership violations, queue growth, payload-size
errors, duplicate ACKs, sequence-wrap errors, and slow-destination HOL blocking
after a candidate run. Accept an implementation round only when its tests kill
the agreed mutation set and the qualification score remains admissible.
