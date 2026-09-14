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

The plan specifies ten scenarios with logical destinations and derived legs:

```text
scenario	logical_destinations	physical_legs	active_data_legs	bond_mode	legs_per_destination	encryption	impairment	consumer
```

"600 destinations" counts logical Restream/SRT outputs, not physical SRT
legs. For unbonded scenarios, logical destinations equals physical legs and
active data legs (600). For 2-leg Broadcast, 600 logical destinations implies
1,200 physical legs and 1,200 active data legs; for 2-leg Backup, 600 logical
destinations implies 1,200 physical legs with 600 active data legs in steady state.
Calling both cases `connections = 600` is prohibited because DATA wire work scales
with active legs.

The runner must produce a bounded measurement file with this exact header and
one row for each scenario:

```text
scenario	workload_id	offered	offered_bytes	duration_ms	delivered	correctness_failures	cpu_ms	p99_lateness_us	rss_kb	syscalls
```

`workload_id` is a nonzero stable identifier for the complete frozen contract
(source rate and shape, runtime/topology including logical destinations and legs,
impairment, seed and repetitions). Baseline and candidate rows must use the same
ID, offered packet/byte counts, and duration; rows with missing or zero resource
metrics are rejected.
Score a candidate against a known-good baseline:

```text
cargo run -p srt-bench -- qualify score scratch/srt600-baseline.tsv scratch/srt600-head.tsv
```

The score is admissible only when every scenario has zero correctness failures
and delivered/offered is at least 0.99. CPU time, p99 service lateness, RSS,
and syscall count are compared by a geometric mean of baseline/candidate
ratios. A candidate that regresses any metric by more than the configured noise
budget (3% by default), or whose aggregate resource score is below 1, fails the
whole qualification. Optional production LOC penalty inputs are bounded and
applied only after the correctness gate.

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
