# Issue #71 capacity frontier evidence

This records the Stage C campaign artifacts and the post-run prediction
validation required by SPEC. Capacity claims below are scoped to this host,
topology, and workload; they are not general SRT capacity claims.

## Provenance

- Campaign SHA at run time:
  cdc9cc2332210c1e7e1a85b832e27dd488ff1774.
- Base: f27ee5c89619d6050d3a3d76dc3745d85efa38df.
- Started: 2026-09-04T20:47:04+02:00.
- Ended: 2026-09-04T22:49:35+02:00 (2h02m).
- Controlled plan: [capacity-frontier-controlled.plan](../plans/capacity-frontier-controlled.plan).
- Deployment plan: [capacity-frontier-deployment.plan](../plans/capacity-frontier-deployment.plan).
- Raw artifacts: [controlled TSV](issue71-controlled.tsv),
  [deployment TSV](issue71-deployment.tsv).
- The local Stage C amend changed the plan commit to e70e73a; that is
  history repair after the campaign and is not the run SHA above.

The checked-in raw files contain 192 role rows for the controlled arm and 288
role rows for the deployment arm. They are retained instead of publishing
medians only.

## Exact commands

The orchestrator ran the following through
scratch/issue71/run-campaign.sh:

~~~text
target/release/srt-bench matrix \
  --plan docs/plans/capacity-frontier-controlled.plan \
  --secs 30 --reps 3 --order interleaved --seed 0 \
  --out scratch/issue71/campaign/controlled.tsv

target/release/srt-bench matrix \
  --plan docs/plans/capacity-frontier-deployment.plan \
  --secs 30 --reps 3 --order interleaved --seed 0 \
  --out scratch/issue71/campaign/deployment.tsv
~~~

After the join fix, validation was rebuilt and run as:

~~~text
cargo build -p srt-bench --release
target/release/srt-bench validate \
  scratch/issue71/campaign/controlled.tsv --format tsv
target/release/srt-bench validate \
  scratch/issue71/campaign/deployment.tsv --format tsv
~~~

The table-mode commands from the brief were also run against both files. The
TSV output has one row per cell repetition; the tables below aggregate three
repetitions per cell. Every prediction was `conditional`, so the validator
now reports `inconclusive` for all 96 controlled
pairs and all 144 deployment pairs, with zero incomplete pairs.

## Host, build, and envelope

- Host: 6-vCPU AMD EPYC, 12,247,552 kB total memory, one NUMA node,
  loopback only.
- Kernel: Linux 6.8.0-137-generic x86_64.
- Rust: rustc 1.96.0 (ac68faa20 2026-05-25).
- Release profile: opt-level=3, thin LTO, codegen-units=1,
  debug=1; no PGO.
- .cargo/config.toml: -C target-cpu=x86-64-v3, mold via clang, and
  relro/now linker hardening.
- Affinity: receiver 0-2, sender 3-5; controlled uses 3 workers on
  each side; deployment uses receiver workers 1, 2, 3 and a fixed Tokio
  sender with 3 workers.
- Socket request: sock-buf=16m (16,777,216 bytes).
- Kernel maxima: net.core.rmem_max=268435456,
  net.core.wmem_max=268435456.
- Live effective buffers recorded in both raw files: receive min/max
  33,554,432 bytes and send min/max 33,554,432 bytes. Pre-run effective
  buffers remained Unknown to the classifier; the live values were not fed
  backward.
- Host envelope source: Stage B's
  scratch/issue71/host-envelope-loopback.sh, reflected in
  scratch/issue71/stage-b-report.md. It supplied loopback NIC
  NotApplicable, configured loss/reorder zero, requested 16 MiB buffers,
  and deliberately left RTT, jitter, and host PPS capacity unknown.
- Concurrent monitor facts supplied with the campaign: UDP
  RcvbufErrors and InErrors deltas reported zero, available memory
  stayed near 9.6 GB, CPU idle was about 21--28%, and roughly 606 UDP
  sockets were in use.
- Caveat: the checked-in row telemetry contains nonzero per-cell UDP
  receive-buffer errors in some high-load deployment repetitions. Therefore
  the monitor summary does not establish absence of all kernel receive
  pressure; the canonical row-level clean predicate remains authoritative.

## Campaign totals

| arm | cells | repetitions | unclean pairs | clean cells |
|---|---:|---:|---:|---:|
| controlled | 32 | 96 | 51 | 13 |
| deployment, Mio receiver | 24 | 72 | 35 | 12 |
| deployment, Tokio receiver | 24 | 72 | 33 | 11 |
| deployment total | 48 | 144 | 68 | 23 |

The deployment table below reports both receiver runtimes separately, as the
checked-in plan sweeps them.

## Controlled arm

Median offer percentages and strict all-repetition verdicts:

| pacing | rt | conns | Mbit/s | offer% | verdict |
|---|---|---:|---:|---:|---|
| fixed:100000000 | mio | 30 | 1 | 100.0 | CLEAN |
| fixed:100000000 | mio | 200 | 1 | 100.0 | CLEAN |
| fixed:100000000 | mio | 600 | 1 | 100.0 | CLEAN |
| fixed:100000000 | mio | 1200 | 1 | 100.0 | CLEAN |
| fixed:100000000 | mio | 30 | 8 | 100.0 | CLEAN |
| fixed:100000000 | mio | 200 | 8 | 100.0 | unclean 1/3 |
| fixed:100000000 | mio | 600 | 8 | 46.4 | unclean 3/3 |
| fixed:100000000 | mio | 1200 | 8 | 16.9 | unclean 3/3 |
| fixed:100000000 | tokio | 30 | 1 | 100.0 | CLEAN |
| fixed:100000000 | tokio | 200 | 1 | 100.0 | CLEAN |
| fixed:100000000 | tokio | 600 | 1 | 100.0 | CLEAN |
| fixed:100000000 | tokio | 1200 | 1 | 80.3 | unclean 3/3 |
| fixed:100000000 | tokio | 30 | 8 | 98.4 | unclean 2/3 |
| fixed:100000000 | tokio | 200 | 8 | 81.4 | unclean 3/3 |
| fixed:100000000 | tokio | 600 | 8 | 32.4 | unclean 3/3 |
| fixed:100000000 | tokio | 1200 | 8 | 9.9 | unclean 3/3 |
| input-relative:25 | mio | 30 | 1 | 100.0 | CLEAN |
| input-relative:25 | mio | 200 | 1 | 100.0 | CLEAN |
| input-relative:25 | mio | 600 | 1 | 100.0 | CLEAN |
| input-relative:25 | mio | 1200 | 1 | 97.1 | unclean 2/3 |
| input-relative:25 | mio | 30 | 8 | 88.6 | unclean 3/3 |
| input-relative:25 | mio | 200 | 8 | 71.3 | unclean 3/3 |
| input-relative:25 | mio | 600 | 8 | 47.0 | unclean 3/3 |
| input-relative:25 | mio | 1200 | 8 | 16.6 | unclean 3/3 |
| input-relative:25 | tokio | 30 | 1 | 100.0 | CLEAN |
| input-relative:25 | tokio | 200 | 1 | 100.0 | CLEAN |
| input-relative:25 | tokio | 600 | 1 | 99.2 | unclean 1/3 |
| input-relative:25 | tokio | 1200 | 1 | 71.8 | unclean 3/3 |
| input-relative:25 | tokio | 30 | 8 | 66.3 | unclean 3/3 |
| input-relative:25 | tokio | 200 | 8 | 55.8 | unclean 3/3 |
| input-relative:25 | tokio | 600 | 8 | 34.0 | unclean 3/3 |
| input-relative:25 | tokio | 1200 | 8 | 10.7 | unclean 3/3 |

The controlled arm has 13 of 32 clean cells.

## Schema note

The raw TSVs persist the minimal prediction identity: `model_policy_rev`,
`model_policy_fingerprint`, `model_class_pre`, and `model_reasons_pre`.
Per-row derived scalars (packet rates, bitrate layers, BDP, headrooms,
horizons, utilizations, admission waves) are not copied into every role
row; they are recomputable from the plan via `srt-bench classify`, so
persisting them would buy schema width without buying auditability.
The `model_policy_fingerprint` column did not exist when the campaign ran.
The campaign predated policy forwarding and passed no policy flags, so
every row was produced under `ClassifierPolicy::default()`; the column was
backfilled with that policy's canonical fingerprint. No measured value was
altered, and the canonical clean predicate reports the same 51 of 96
controlled and 68 of 144 deployment unclean pairs before and after. The
column is additive metadata only: it records which policy content produced
a prediction, so a stored prediction cannot later be reinterpreted under a
different threshold set wearing the same revision label.

## Deployment arm summary

Grouped by `recv_runtime`, which is the axis this arm exists to sweep. An
earlier revision of this table grouped on the unscoped `runtime` column;
that column records the fixed Tokio *sender*, so both receiver runtimes
collapsed into one row set and produced impossible `6/6` verdicts against a
3-repetition campaign. A role-scoped dimension must not vanish from the
report.

| recv runtime | recv workers | conns | Mbit/s | offer% | verdict |
|---|---:|---:|---:|---:|---|
| mio | 1 | 30 | 1 | 100.0 | CLEAN |
| mio | 1 | 200 | 1 | 100.0 | CLEAN |
| mio | 1 | 600 | 1 | 100.0 | CLEAN |
| mio | 1 | 1200 | 1 | 99.9 | unclean 3/3 |
| mio | 1 | 30 | 8 | 100.0 | CLEAN |
| mio | 1 | 200 | 8 | 90.1 | unclean 3/3 |
| mio | 1 | 600 | 8 | 32.9 | unclean 3/3 |
| mio | 1 | 1200 | 8 | 14.3 | unclean 3/3 |
| mio | 2 | 30 | 1 | 100.0 | CLEAN |
| mio | 2 | 200 | 1 | 100.0 | CLEAN |
| mio | 2 | 600 | 1 | 100.0 | CLEAN |
| mio | 2 | 1200 | 1 | 100.0 | CLEAN |
| mio | 2 | 30 | 8 | 100.0 | CLEAN |
| mio | 2 | 200 | 8 | 96.4 | unclean 2/3 |
| mio | 2 | 600 | 8 | 37.7 | unclean 3/3 |
| mio | 2 | 1200 | 8 | 16.4 | unclean 3/3 |
| mio | 3 | 30 | 1 | 100.0 | CLEAN |
| mio | 3 | 200 | 1 | 100.0 | CLEAN |
| mio | 3 | 600 | 1 | 100.0 | CLEAN |
| mio | 3 | 1200 | 1 | 90.5 | unclean 3/3 |
| mio | 3 | 30 | 8 | 100.0 | unclean 1/3 |
| mio | 3 | 200 | 8 | 90.1 | unclean 3/3 |
| mio | 3 | 600 | 8 | 32.3 | unclean 3/3 |
| mio | 3 | 1200 | 8 | 11.6 | unclean 3/3 |
| tokio | 1 | 30 | 1 | 100.0 | CLEAN |
| tokio | 1 | 200 | 1 | 100.0 | CLEAN |
| tokio | 1 | 600 | 1 | 100.0 | CLEAN |
| tokio | 1 | 1200 | 1 | 83.7 | unclean 3/3 |
| tokio | 1 | 30 | 8 | 100.0 | CLEAN |
| tokio | 1 | 200 | 8 | 98.5 | unclean 3/3 |
| tokio | 1 | 600 | 8 | 30.8 | unclean 3/3 |
| tokio | 1 | 1200 | 8 | 12.3 | unclean 3/3 |
| tokio | 2 | 30 | 1 | 100.0 | CLEAN |
| tokio | 2 | 200 | 1 | 100.0 | CLEAN |
| tokio | 2 | 600 | 1 | 100.0 | CLEAN |
| tokio | 2 | 1200 | 1 | 100.0 | unclean 1/3 |
| tokio | 2 | 30 | 8 | 100.0 | CLEAN |
| tokio | 2 | 200 | 8 | 90.5 | unclean 3/3 |
| tokio | 2 | 600 | 8 | 35.5 | unclean 3/3 |
| tokio | 2 | 1200 | 8 | 13.9 | unclean 3/3 |
| tokio | 3 | 30 | 1 | 100.0 | CLEAN |
| tokio | 3 | 200 | 1 | 100.0 | CLEAN |
| tokio | 3 | 600 | 1 | 100.0 | CLEAN |
| tokio | 3 | 1200 | 1 | 86.3 | unclean 3/3 |
| tokio | 3 | 30 | 8 | 100.0 | unclean 1/3 |
| tokio | 3 | 200 | 8 | 90.3 | unclean 3/3 |
| tokio | 3 | 600 | 8 | 33.8 | unclean 3/3 |
| tokio | 3 | 1200 | 8 | 10.9 | unclean 3/3 |

23 of 48 deployment cells are clean: Mio receiver 12 of 24, Tokio
receiver 11 of 24.

Receiver workers=2
outperforms 3 in this workload, consistent with documented shared-pool
contention; this is not a reason to retune the classifier.

## Pacing probe

This supplied probe is not part of the 32/48 matrix cell counts:

| pacing (MAXBW/conn) | src_accepted | offer% | clean |
|---|---:|---:|---|
| input-relative:25 (10M) | 350,173 | 76.6 | no |
| fixed:10000000 (10M) | 350,173 | 76.8 | no |
| input-relative:50 (12M) | -- | 86.2 | no |
| input-relative:100 (16M) | 423,040 | 92.8 | no |
| fixed:100000000 (100M) | 455,262 | 99.9 | YES |

30x1M at input-relative:25 was clean; 30x4M was 92.3%. Sender CPU was
syscall-dominated (sys/user about 5x) at under one core total, RTT was
0.000 ms, with no retransmissions. Raising source backlog from 250 to 1000 ms
moved 8 Mbit/s offer only 76.6% to 80.3%, indicating sustained overload rather
than scheduling jitter.

## Prediction versus observation

Every pre-run prediction was:

Conditional with
expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,
host_pps_capacity_unknown.

The validator's `inconclusive` state means only that the prediction was not
falsifiable by this observation. It replaces an earlier `agreement` state,
which was actively misleading: `agreement` means only that an explicit
mismatch rule was
not triggered. Since Conditional is intentionally uncertainty-tolerant,
It is not a claim that the model predicted the observed bottleneck. Because
every campaign cell was `conditional`, the old vocabulary reported universal
agreement -- including for cells whose source offer collapsed below 20% --
which made the campaign non-falsifiable by construction.

The following tables are generated from the fixed validate --format tsv
output, grouped by cell and aggregated over three repetitions. The
limiting observed signal column is the validator explanation for every
unclean repetition.

### Controlled

| cell | predicted class | reasons | observed clean? | limiting observed signal | validation |
|---|---|---|---|---|---|
| `mio, fixed:100000000, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `mio, input-relative:25, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (1/3 reps clean) | source offer 84.0% < 99.0%; source goodput 84.0% < 99.0%; source overflow 435864<br>source offer 97.1% < 99.0%; source goodput 97.1% < 99.0%; source overflow 4028 | inconclusive |
| `mio, fixed:100000000, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 16.9% < 99.0%; source goodput 16.9% < 99.0%; source overflow 21840662<br>source offer 16.7% < 99.0%; source goodput 16.7% < 99.0%; source overflow 21871163<br>source offer 17.9% < 99.0%; source goodput 17.9% < 99.0%; source overflow 21543264 | inconclusive |
| `mio, input-relative:25, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 16.7% < 99.0%; source goodput 16.7% < 99.0%; caller UDP rcvbuf errors 1331; listener UDP rcvbuf errors 1331; source overflow 21882105<br>source offer 16.4% < 99.0%; source goodput 16.4% < 99.0%; source overflow 21967806<br>source offer 16.6% < 99.0%; source goodput 16.6% < 99.0%; source overflow 21906674 | inconclusive |
| `mio, fixed:100000000, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `mio, input-relative:25, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `mio, fixed:100000000, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (2/3 reps clean) | caller UDP rcvbuf errors 21289; listener UDP rcvbuf errors 21289 | inconclusive |
| `mio, input-relative:25, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 61.6% < 99.0%; source goodput 61.6% < 99.0%; source overflow 1599172<br>source offer 71.7% < 99.0%; source goodput 71.7% < 99.0%; source overflow 1139613<br>source offer 71.3% < 99.0%; source goodput 71.3% < 99.0%; source overflow 1156243 | inconclusive |
| `mio, fixed:100000000, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `mio, input-relative:25, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `mio, fixed:100000000, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `mio, input-relative:25, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 75.8% < 99.0%; source goodput 75.8% < 99.0%; source overflow 142834<br>source offer 88.6% < 99.0%; source goodput 88.6% < 99.0%; source overflow 55417<br>source offer 89.5% < 99.0%; source goodput 89.5% < 99.0%; source overflow 49151 | inconclusive |
| `mio, fixed:100000000, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `mio, input-relative:25, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `mio, fixed:100000000, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 46.4% < 99.0%; source goodput 46.4% < 99.0%; source overflow 6894710<br>source offer 46.1% < 99.0%; source goodput 46.1% < 99.0%; caller UDP rcvbuf errors 5061; listener UDP rcvbuf errors 5061; source overflow 6930776<br>source offer 49.3% < 99.0%; source goodput 49.3% < 99.0%; source overflow 6494952 | inconclusive |
| `mio, input-relative:25, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 46.6% < 99.0%; source goodput 46.6% < 99.0%; source overflow 6851403<br>source offer 47.0% < 99.0%; source goodput 47.0% < 99.0%; source overflow 6793455<br>source offer 47.9% < 99.0%; source goodput 47.9% < 99.0%; source overflow 6671372 | inconclusive |
| `tokio, fixed:100000000, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 76.2% < 99.0%; source goodput 76.2% < 99.0%; source overflow 707048<br>source offer 80.3% < 99.0%; source goodput 80.3% < 99.0%; source overflow 577604<br>source offer 85.4% < 99.0%; source goodput 85.4% < 99.0%; source overflow 416779 | inconclusive |
| `tokio, input-relative:25, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 71.0% < 99.0%; source goodput 71.0% < 99.0%; source overflow 879581<br>source offer 74.5% < 99.0%; source goodput 74.5% < 99.0%; source overflow 759332<br>source offer 71.8% < 99.0%; source goodput 71.8% < 99.0%; source overflow 854304 | inconclusive |
| `tokio, fixed:100000000, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 9.6% < 99.0%; source goodput 9.6% < 99.0%; source overflow 23807391<br>source offer 9.9% < 99.0%; source goodput 9.9% < 99.0%; source overflow 23741376<br>source offer 10.3% < 99.0%; source goodput 10.3% < 99.0%; source overflow 23637582 | inconclusive |
| `tokio, input-relative:25, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 9.9% < 99.0%; source goodput 9.9% < 99.0%; source overflow 23739033<br>source offer 11.2% < 99.0%; source goodput 11.2% < 99.0%; source overflow 23372505<br>source offer 10.7% < 99.0%; source goodput 10.7% < 99.0%; source overflow 23528750 | inconclusive |
| `tokio, fixed:100000000, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `tokio, input-relative:25, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `tokio, fixed:100000000, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 81.4% < 99.0%; source goodput 81.4% < 99.0%; source overflow 697648<br>source offer 79.2% < 99.0%; source goodput 79.2% < 99.0%; source overflow 797639<br>source offer 91.3% < 99.0%; source goodput 91.3% < 99.0%; source overflow 243370 | inconclusive |
| `tokio, input-relative:25, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 51.1% < 99.0%; source goodput 51.1% < 99.0%; source overflow 2079797<br>source offer 58.1% < 99.0%; source goodput 58.1% < 99.0%; source overflow 1757917<br>source offer 55.8% < 99.0%; source goodput 55.8% < 99.0%; source overflow 1864770 | inconclusive |
| `tokio, fixed:100000000, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `tokio, input-relative:25, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `tokio, fixed:100000000, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (1/3 reps clean) | source offer 88.9% < 99.0%; source goodput 88.9% < 99.0%; source overflow 53511<br>source offer 98.4% < 99.0%; source goodput 98.4% < 99.0%; source overflow 32 | inconclusive |
| `tokio, input-relative:25, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 60.0% < 99.0%; source goodput 60.0% < 99.0%; source overflow 251031<br>source offer 66.6% < 99.0%; source goodput 66.6% < 99.0%; source overflow 205846<br>source offer 66.3% < 99.0%; source goodput 66.3% < 99.0%; source overflow 207640 | inconclusive |
| `tokio, fixed:100000000, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `tokio, input-relative:25, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (2/3 reps clean) | source offer 92.5% < 99.0%; source goodput 92.5% < 99.0%; source overflow 72641 | inconclusive |
| `tokio, fixed:100000000, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 32.1% < 99.0%; source goodput 32.1% < 99.0%; source overflow 8835656<br>source offer 32.4% < 99.0%; source goodput 32.4% < 99.0%; source overflow 8792071<br>source offer 34.7% < 99.0%; source goodput 34.7% < 99.0%; source overflow 8481563 | inconclusive |
| `tokio, input-relative:25, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 32.2% < 99.0%; source goodput 32.2% < 99.0%; source overflow 8814429<br>source offer 34.3% < 99.0%; source goodput 34.3% < 99.0%; source overflow 8537478<br>source offer 34.0% < 99.0%; source goodput 34.0% < 99.0%; source overflow 8578027 | inconclusive |

### Deployment

| cell | predicted class | reasons | observed clean? | limiting observed signal | validation |
|---|---|---|---|---|---|
| `recv=mio/1 workers, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | listener torn down 141; source goodput 91.9% < 99.0%; delivery 92.0% < 99.9%; caller UDP rcvbuf errors 3366694; listener UDP rcvbuf errors 3366694<br>listener torn down 269; source goodput 93.0% < 99.0%; delivery 93.0% < 99.9%; caller UDP rcvbuf errors 2913858; listener UDP rcvbuf errors 2913858<br>listener torn down 126; source goodput 91.8% < 99.0%; delivery 92.4% < 99.9%; caller UDP rcvbuf errors 3653935; listener UDP rcvbuf errors 3653935 | inconclusive |
| `recv=mio/1 workers, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | listener torn down 372; source offer 14.3% < 99.0%; source goodput 12.7% < 99.0%; delivery 88.5% < 99.9%; caller UDP rcvbuf errors 4273569; listener UDP rcvbuf errors 4273569; source overflow 22530594<br>listener torn down 421; source offer 14.2% < 99.0%; source goodput 12.9% < 99.0%; delivery 90.9% < 99.9%; caller UDP rcvbuf errors 3987285; listener UDP rcvbuf errors 3987285; source overflow 22568629<br>listener torn down 168; source offer 19.8% < 99.0%; source goodput 18.3% < 99.0%; delivery 92.4% < 99.9%; caller UDP rcvbuf errors 4302984; listener UDP rcvbuf errors 4302984; source overflow 21030068 | inconclusive |
| `recv=mio/1 workers, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/1 workers, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 90.1% < 99.0%; source goodput 90.1% < 99.0%; source overflow 299377<br>source offer 93.1% < 99.0%; source goodput 93.1% < 99.0%; source overflow 164347<br>source offer 85.1% < 99.0%; source goodput 85.1% < 99.0%; source overflow 529730 | inconclusive |
| `recv=mio/1 workers, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/1 workers, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/1 workers, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/1 workers, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | listener torn down 167; source offer 26.6% < 99.0%; source goodput 28.3% < 99.0%; caller UDP rcvbuf errors 3666236; listener UDP rcvbuf errors 3666236; source overflow 9588074<br>listener torn down 348; source offer 32.9% < 99.0%; source goodput 32.6% < 99.0%; delivery 99.1% < 99.9%; caller UDP rcvbuf errors 2681894; listener UDP rcvbuf errors 2681894; source overflow 8720507<br>listener torn down 178; source offer 33.0% < 99.0%; source goodput 32.6% < 99.0%; delivery 98.8% < 99.9%; caller UDP rcvbuf errors 2678601; listener UDP rcvbuf errors 2678601; source overflow 8708463 | inconclusive |
| `recv=mio/2 workers, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/2 workers, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 16.3% < 99.0%; source goodput 16.3% < 99.0%; source overflow 21992058<br>source offer 16.4% < 99.0%; source goodput 16.4% < 99.0%; source overflow 21953420<br>source offer 16.7% < 99.0%; source goodput 16.7% < 99.0%; source overflow 21877225 | inconclusive |
| `recv=mio/2 workers, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/2 workers, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (1/3 reps clean) | source offer 87.8% < 99.0%; source goodput 87.8% < 99.0%; source overflow 407021<br>source offer 96.4% < 99.0%; source goodput 96.4% < 99.0%; source overflow 30154 | inconclusive |
| `recv=mio/2 workers, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/2 workers, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/2 workers, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/2 workers, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 36.0% < 99.0%; source goodput 36.0% < 99.0%; source overflow 8301331<br>source offer 37.8% < 99.0%; source goodput 37.8% < 99.0%; source overflow 8053778<br>source offer 37.7% < 99.0%; source goodput 37.7% < 99.0%; source overflow 8066876 | inconclusive |
| `recv=mio/3 workers, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 90.1% < 99.0%; source goodput 90.1% < 99.0%; caller UDP rcvbuf errors 309; listener UDP rcvbuf errors 309; source overflow 256761<br>source offer 93.6% < 99.0%; source goodput 93.6% < 99.0%; source overflow 135907<br>source offer 90.5% < 99.0%; source goodput 90.5% < 99.0%; source overflow 239988 | inconclusive |
| `recv=mio/3 workers, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 11.5% < 99.0%; source goodput 11.5% < 99.0%; source overflow 23306587<br>source offer 11.9% < 99.0%; source goodput 11.9% < 99.0%; source overflow 23191213<br>source offer 11.6% < 99.0%; source goodput 11.6% < 99.0%; source overflow 23262930 | inconclusive |
| `recv=mio/3 workers, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/3 workers, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 84.8% < 99.0%; source goodput 84.8% < 99.0%; source overflow 544101<br>source offer 90.1% < 99.0%; source goodput 90.1% < 99.0%; source overflow 297579<br>source offer 92.3% < 99.0%; source goodput 92.3% < 99.0%; source overflow 199262 | inconclusive |
| `recv=mio/3 workers, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/3 workers, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (2/3 reps clean) | source offer 98.2% < 99.0%; source goodput 98.2% < 99.0% | inconclusive |
| `recv=mio/3 workers, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=mio/3 workers, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 32.3% < 99.0%; source goodput 32.3% < 99.0%; source overflow 8807548<br>source offer 30.7% < 99.0%; source goodput 30.7% < 99.0%; source overflow 9024886<br>source offer 34.8% < 99.0%; source goodput 34.8% < 99.0%; source overflow 8462875 | inconclusive |
| `recv=tokio/1 workers, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | caller established 1199/1200; listener torn down 1; source offer 82.5% < 99.0%; source goodput 79.7% < 99.0%; delivery 96.6% < 99.9%; caller UDP rcvbuf errors 5003532; listener UDP rcvbuf errors 5003532; source overflow 518222<br>source offer 83.7% < 99.0%; source goodput 83.7% < 99.0%; caller UDP rcvbuf errors 4954228; listener UDP rcvbuf errors 4954228; source overflow 460003<br>listener torn down 1; source offer 85.4% < 99.0%; source goodput 85.7% < 99.0%; caller UDP rcvbuf errors 5080544; listener UDP rcvbuf errors 5080544; source overflow 411901 | inconclusive |
| `recv=tokio/1 workers, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | listener torn down 463; source offer 11.5% < 99.0%; source goodput 11.5% < 99.0%; caller UDP rcvbuf errors 4911225; listener UDP rcvbuf errors 4911225; source overflow 23306007<br>caller established 1197/1200; listener established 1199/1200; listener torn down 384; source offer 13.6% < 99.0%; source goodput 13.8% < 99.0%; caller UDP rcvbuf errors 4950485; listener UDP rcvbuf errors 4950485; source overflow 22653766<br>caller established 1192/1200; listener established 1196/1200; listener torn down 381; source offer 12.3% < 99.0%; source goodput 12.7% < 99.0%; caller UDP rcvbuf errors 4519078; listener UDP rcvbuf errors 4519078; source overflow 22911310 | inconclusive |
| `recv=tokio/1 workers, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/1 workers, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 96.2% < 99.0%; source goodput 96.2% < 99.0%; source overflow 32121<br>source offer 98.5% < 99.0%; source goodput 98.5% < 99.0%<br>source offer 98.9% < 99.0%; source goodput 98.9% < 99.0% | inconclusive |
| `recv=tokio/1 workers, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/1 workers, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/1 workers, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/1 workers, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 28.7% < 99.0%; source goodput 29.1% < 99.0%; caller UDP rcvbuf errors 2366348; listener UDP rcvbuf errors 2366348; source overflow 9303734<br>source offer 33.0% < 99.0%; source goodput 32.8% < 99.0%; delivery 99.5% < 99.9%; caller UDP rcvbuf errors 2000600; listener UDP rcvbuf errors 2000600; source overflow 8713664<br>source offer 30.8% < 99.0%; source goodput 30.7% < 99.0%; delivery 99.6% < 99.9%; caller UDP rcvbuf errors 2238878; listener UDP rcvbuf errors 2238878; source overflow 9005114 | inconclusive |
| `recv=tokio/2 workers, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (2/3 reps clean) | caller UDP rcvbuf errors 49788; listener UDP rcvbuf errors 49788 | inconclusive |
| `recv=tokio/2 workers, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 13.1% < 99.0%; source goodput 13.1% < 99.0%; caller UDP rcvbuf errors 11083; listener UDP rcvbuf errors 11083; source overflow 22859461<br>source offer 14.1% < 99.0%; source goodput 14.1% < 99.0%; caller UDP rcvbuf errors 51744; listener UDP rcvbuf errors 51744; source overflow 22576582<br>source offer 13.9% < 99.0%; source goodput 13.9% < 99.0%; caller UDP rcvbuf errors 15225; listener UDP rcvbuf errors 15225; source overflow 22636486 | inconclusive |
| `recv=tokio/2 workers, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/2 workers, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 90.5% < 99.0%; source goodput 90.5% < 99.0%; source overflow 282938<br>source offer 88.1% < 99.0%; source goodput 88.1% < 99.0%; source overflow 394268<br>source offer 96.2% < 99.0%; source goodput 96.2% < 99.0%; source overflow 23591 | inconclusive |
| `recv=tokio/2 workers, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/2 workers, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/2 workers, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/2 workers, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 35.4% < 99.0%; source goodput 35.4% < 99.0%; source overflow 8374241<br>source offer 34.6% < 99.0%; source goodput 34.6% < 99.0%; source overflow 8489635<br>source offer 36.6% < 99.0%; source goodput 36.6% < 99.0%; caller UDP rcvbuf errors 3634; listener UDP rcvbuf errors 3634; source overflow 8219129 | inconclusive |
| `recv=tokio/3 workers, conns=1200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 86.7% < 99.0%; source goodput 86.7% < 99.0%; source overflow 360218<br>source offer 85.3% < 99.0%; source goodput 85.3% < 99.0%; source overflow 407836<br>source offer 86.3% < 99.0%; source goodput 86.3% < 99.0%; source overflow 382398 | inconclusive |
| `recv=tokio/3 workers, conns=1200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 10.4% < 99.0%; source goodput 10.4% < 99.0%; source overflow 23610098<br>source offer 11.3% < 99.0%; source goodput 11.3% < 99.0%; source overflow 23361219<br>source offer 10.9% < 99.0%; source goodput 10.9% < 99.0%; caller UDP rcvbuf errors 1538; listener UDP rcvbuf errors 1538; source overflow 23463952 | inconclusive |
| `recv=tokio/3 workers, conns=200, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/3 workers, conns=200, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 81.0% < 99.0%; source goodput 81.0% < 99.0%; source overflow 713852<br>source offer 92.9% < 99.0%; source goodput 92.9% < 99.0%; source overflow 172970<br>source offer 90.3% < 99.0%; source goodput 90.3% < 99.0%; source overflow 291242 | inconclusive |
| `recv=tokio/3 workers, conns=30, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/3 workers, conns=30, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (2/3 reps clean) | source offer 99.0% < 99.0%; source goodput 99.0% < 99.0% | inconclusive |
| `recv=tokio/3 workers, conns=600, source=1M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | yes | none -- clean | inconclusive |
| `recv=tokio/3 workers, conns=600, source=8M` | `conditional` | `expected_rtt_unknown,rtt_variance_unknown,effective_socket_buffer_unknown,host_pps_capacity_unknown` | no (0/3 reps clean) | source offer 33.8% < 99.0%; source goodput 33.8% < 99.0%; source overflow 8598787<br>source offer 31.9% < 99.0%; source goodput 31.9% < 99.0%; source overflow 8860907<br>source offer 35.7% < 99.0%; source goodput 35.7% < 99.0%; source overflow 8334384 | inconclusive |

## Interpretation and model gaps

- **Pacing wall (largest gap):** input-relative:25 cells were merely
  Conditional, but 8 Mbit/s cells were unclean at every connection count
  and the probe showed only 92.8% at 2x MAXBW. The pacing-headroom equation
  uses nominal per-packet overhead of about 3.3% and does not model this
  sustained overload. This is a model gap and follow-up candidate, not a
  classifier retuning target.
- **Source/runtime bottleneck:** fixed-pacing high-rate cells show source
  offer, source goodput, and source_overflow failures. This is evidence of a
  benchmark/runtime bottleneck, especially at Tokio 200/600/1200 and at
  high deployment load; it does not establish a protocol limit.
- **Host/kernel signal:** some rows also report UDP receive-buffer errors,
  especially deployment. That is a host/kernel constraint signal in the row
  telemetry, while the supplied global monitor summary reported zero
  deltas. The evidence does not isolate the relative contribution of kernel
  queue pressure, scheduling, and source overload.
- **Worker-shape effect:** receiver workers=2 beating 3 is consistent with
  shared-pool contention. It is a runtime/benchmark topology observation,
  not a policy threshold.
- No observed mismatch requires declaring a missing model resource,
  threshold calibration, or protocol change proven. The available data
  supports the categories above and leaves causal attribution conditional.

## Issue #30 revalidation

Outcome B: current main is still not reproducibly clean at 200 connections x
8 Mbit/s.

- Mio, fixed 100 Mbit/s, 200x8M: 100.0% median offer, 2/3 repetitions
  fully clean.
- Tokio, fixed 100 Mbit/s, 200x8M: 81.4% median offer, 0/3 repetitions
  fully clean.
- Historical 72.8% delivery is materially improved in the Mio arm, but clean
  capacity is still not reproducible across repetitions/runtimes.
- #30 stays OPEN.
- No ReceiverBuffer optimization was implemented. Any follow-up must target
  the current measured bottleneck, not the old ReceiverBuffer profile.

## Scope and null results

No dataplane hot path, SRT pacing behavior, classifier threshold, autotuner,
PGO build, or production optimization was changed. The campaign does not
establish a general 30/200/600/1200 capacity claim, only the measured clean
cells under the host/topologies above.


