# Performance improvement loop

Performance work is an experiment, not a backlog category. A change earns
retention only when it improves a stated workload with reproducible evidence
and preserves protocol behaviour.

## Inner loop

1. State the hypothesis and the expected bottleneck before editing. Use the
   existing Criterion microbenchmark that contains the changed operation; add
   one if none exists.
2. Capture a before/after Criterion result with the same release build and
   host. An improvement must exceed measurement noise: use its 95% confidence
   interval and require at least a 3% median movement for a microbenchmark.
3. Run the relevant live sentinel below with five repetitions. Retain a change
   only when its median improves by at least 5%, delivery stays complete,
   teardown stays zero, and CPU/RSS/retransmits do not regress materially.
4. Attribute the result before making another change: use `perf stat` or
   `srt-bench sysprof` to distinguish useful work, scheduler wakeups, syscalls,
   cache misses, and lock contention. A flamegraph answers “where”; counters
   answer “how often.”
5. Run focused unit/property tests, then a wider plan only after a sentinel
   survives. Record both wins and null results in the change/commit message.

The host must be treated as part of the experiment: record the startup
diagnostics, keep CPU affinity and frequency conditions constant where
possible, and compare only samples from the same measurement window. Do not
interpret a shared-host outlier as an optimization.

## Fast live sentinels

The PR gate uses `docs/plans/ci-sentinels/`: one 600-connection, low-rate
admission cell and one lower-connection datapath-load cell. Both must satisfy
`srt-bench check-clean`. The higher-rate plans below are performance/stress
measurements and run nightly; they are not assumed to be clean on shared CI.

Each file is one deliberate cell, so its result is attributable. Run all four
for a general hot-path change; run the directly affected subset for a narrowly
scoped change.

```sh
cargo build --release -p srt-bench
for plan in docs/plans/perf-sentinels/*.plan; do
  target/release/srt-bench matrix --plan "$plan" --secs 3 --reps 5 \
    --order interleaved --seed 0 --out "scratch/$(basename "$plan" .plan).tsv"
done
```

| Sentinel | What it catches |
| --- | --- |
| `mio-pool-plain` | plain protocol + pooled epoll admission/egress at connection scale |
| `tokio-demux-aes256` | encrypted packet path plus one-socket SRT Socket-ID demultiplexing |
| `compio-pool-plain` | completion-driven I/O, reader-task/channel overhead, and pooled ingress |
| `tokio-broadcast` | inbound group admission, deduplication, and per-leg wire work |

These intentionally do not claim to cover every runtime/topology/encryption
interaction. A candidate that changes a shared component graduates to
`throughput-matrix.plan`; a topology, runtime, or bonding change also runs its
corresponding focused plan (`socket-topology-smoke.plan` or
`bonded-ingress.plan`).

## Canonical capacity campaign

Run the capacity campaign by composing the existing subcommands. `matrix`
executes the sweep and persists the pre-run prediction (`model_policy_rev`,
`model_policy_fingerprint`, `model_class_pre`, `model_reasons_pre`) into
every result row; `check-clean`, `validate`, and `report` then read the
same file. No meta-command sits above them: one benchmark workflow does
not need a second orchestrator to keep in sync with the result schema.
Run each checked-in capacity plan through `matrix`, then check, validate,
and report the same file. Build the release binary first:
`.cargo/config.toml` already supplies `-C target-cpu=x86-64-v3` along with
the mold linker and hardening link args, and a set `RUSTFLAGS` -- even an
empty one -- would replace that list wholesale, so unset it rather than
restating the target:

```sh
env -u RUSTFLAGS cargo build --release -p srt-bench

target/release/srt-bench matrix \
  --plan docs/plans/capacity-frontier-controlled.plan \
  --secs 30 --reps 3 --order interleaved --seed 0 \
  --out scratch/capacity-controlled.tsv

target/release/srt-bench check-clean scratch/capacity-controlled.tsv
target/release/srt-bench validate scratch/capacity-controlled.tsv
target/release/srt-bench report scratch/capacity-controlled.tsv
```

A rerun against the same `--out` resumes completed result pairs, and a
rerun with changed policy thresholds re-runs the affected cells rather
than reusing a prediction made under different thresholds.

Preserve this metadata with the raw TSV, report, and validation output:
the exact git SHA; plan and all flags; `rustc --version` and release flags;
CPU model; kernel; receiver and sender affinity; requested and effective
receive/send socket buffers; and the source of the host PPS/NIC envelope.
The Stage C results and scoped limits are in the
[issue #71 frontier evidence](results/issue71-frontier-evidence.md). The
subcommands do not classify, skip, reorder, mutate, or auto-tune cells
based on predictions.

## Benchmarks by decision

| Change area | First benchmark |
| --- | --- |
| per-packet protocol/encoding/crypto | `core_packet_loop` (plain and AES-128) |
| socket/runtime behavior | `core_packet_loop_io`, then a live sentinel and `sysprof` |
| loss/receive data structure | `receiver_loss_scan` and `receiver_tsbpd_scan` |
| collection substitution | `collection_tradeoffs`, then its production benchmark |
| admission, Socket ID, cookie, timer table | `admission_hardening`, then a pooled sentinel |
| group policy/requalification | `group_requalification`, then the bonded-ingress sentinel |

`Socket ID` and cookie changes are on an untrusted-input or routing boundary:
they require collision/adversarial tests and fuzz compilation in addition to
their benchmark. Never trade away source-address validation, uniqueness, or
bounded state merely to save a lookup.

`CallerTable` now owns direct and `SrtGroup`-backed logical sessions over one
application UDP socket. The bonded-ingress sentinel therefore exercises real
Broadcast fan-out or Backup selection on egress as well as receiver-side
admission/deduplication. Its identical-four-tuple topology remains a protocol
and scheduler test, not a path-diversity/failover test.
