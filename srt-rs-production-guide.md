# srt-rs: production hardening and application integration

Prepared 2026-09-13. Audited repository: `/home/dev/srt-rs`.
Audited branch: `codex/bounded-correctness`.
Audited HEAD: `6397f6a` (the working tree also contains the source fixes listed below).

This document is now both the implementation specification and the current
status ledger. The source changes have been compiled and tested; the remaining
items below are explicit qualification or design work, not assumptions that the
existing implementation already satisfies them.

The user has chosen to retain the current stack. Do not restart on rosalyntg/srt-rs. The current core is a vendored shiguredo implementation with local changes. Preserve its attribution and useful functionality. The task is to repair misleading guarantees, finish the application-facing layer, and qualify bounded live fan-out.

The guide supports small-task execution, including by Luna. It cannot guarantee a model will solve every concurrency or cryptographic problem. Difficult cards specify review/escalation conditions; they must not become silent shortcuts.

## 1. The actual goal

Deliver a reviewable change set in the existing stack such that an application can:

- establish caller/listener SRT sessions using supported APIs;
- send and receive complete messages with explicit admission, backpressure, deadline and shutdown semantics;
- drive multiple sessions on explicitly owned shards without one slow destination stopping unrelated sessions;
- retain bounded application, transport, protocol and socket resources;
- use the supported encryption and Broadcast/Backup bonding paths;
- inspect effective configuration and useful per-connection/per-shard telemetry;
- reproduce correctness and performance evidence for a precisely stated workload envelope.

600 destinations is the target workload dimension, not a claim that any bitrate fits any CPU or NIC. No percentage-of-optimal claim is permitted without a defined comparator and measurements.

Completion means the required cards and release acceptance matrix pass. Writing APIs, compiling once, reporting a high coverage percentage, or changing documentation does not establish production readiness.

## 2. Authorization and benchmark protection

The original benchmark protection rule was **strictly read-only while
benchmarking runs; do not disturb it**. Implementation and validation are now
authorized by the user; keep the same rule for any future benchmark window.

There are three execution states:

| State | Allowed actions |
|---|---|
| READ_ONLY | Small source/config/Git reads and analysis. No repository edits, builds, tests, formatters, profilers, dependency installation, worktree creation, Git mutation or system/process changes. |
| IMPLEMENT | Only after the user authorizes implementation in the intended checkout/worktree. Make in-scope local edits; preserve unrelated work. Tests remain subject to host authorization. |
| VALIDATE | Only on a user-authorized idle host or separately provisioned validation host. Run the needed checks within its resource limits. |

A new worktree on the same benchmark host does **not** isolate CPU, caches, disk, memory bandwidth or NIC traffic. Do not treat it as permission to compile or test during measurements. Absence of a benchmark-looking process, elapsed time, or a saved checkbox is not approval. Once the user supplies authorization, record it and do not ask again for routine in-scope work.

Current protected checkout contains an unrelated untracked `gpt-6-astra-light.md`. Preserve it. Do not stash, reset, clean, overwrite or commit other people's changes.

If implementation is authorized, use the designated worktree. If a new worktree is useful and allowed, use a `codex/` branch. Source links in this guide point to the audited checkout; resolve their repository-relative paths inside the implementation worktree before editing.

No automatic commit, push, merge, tag, publication, deployment, system tuning or external messaging is authorized by this handoff. Prepare a concrete reviewable result first. Do not run release workflows or publish commands merely because they appear in source.

## 3. Repository map and what already exists

| Location | Actual responsibility |
|---|---|
| `crates/srt-protocol` (package `srt-proto`, library `srt_proto`) | Sans-I/O protocol, packet parsing, handshake, crypto, sender/receiver windows, message assembly, groups, injected timestamps, statistics. |
| `crates/srt-protocol/pbt` (package `pbt`) | Existing property tests. |
| `crates/srt-protocol/fuzz` | Existing libFuzzer targets; excluded from the main workspace. |
| `crates/srt-lifecycle` | Pure admission/routing/promotion decisions. Keep clocks, sockets and application policy services out. |
| `crates/srt-transport` | Native socket adapters, timers, batching, caller/admission tables, group drivers, configuration and transport telemetry. |
| `crates/srt-bench` | Workload generation, runtime experiments, process orchestration, source clocks, measurement and reporting. It must not remain the only implementation of a production event loop. |
| `crates/xtask`, `.github/workflows` | Developer/CI checks and release tooling. |

Useful current pieces include bounded output extraction, receive batching, explicit worker distribution in the benchmark, adaptive packet storage, cached AES schedules, admission limits, group logic, property tests and interop fixtures. Finish or reuse them before introducing replacements.

Important corrections to earlier broad claims:

1. Both the current core and rosalyntg's core are sans-I/O. This is not a unique local feature.
2. The current Tokio adapter has receive and output budget mechanisms. That does not bound all work inside a protocol callback.
3. Benchmark worker topology is not a finished production listener.
4. `PreparedListener` intentionally owns no event loop. Some configuration is only carried for an external owner to apply.
5. Reference-counted shared payloads still have atomic/lifetime costs. Publication once does not remove per-destination ARQ, encryption, pacing or wire work.
6. A slot ring used as a work queue is not a broadcast bus: every subscribed shard must observe every applicable publication.
7. A finite queue does not by itself isolate slow consumers.
8. Cached crypto performance does not imply cached secrets are erased on drop.
9. Task cancellation does not prove an owned-buffer send was never submitted to the kernel.
10. Runtime tests, interop tests and fuzz targets may skip or not execute under a broad command. Record what actually ran.
11. General-purpose operating systems provide variable scheduling delay. This project can qualify an operating envelope, not promise universal hard real-time behavior or invincibility.

## 3.1 Current source status

The following hardening work is implemented in the current working tree:

- finite receive and output work budgets in the benchmark and runtime paths;
- a 64-member group cap with round-robin lifecycle collection;
- bounded command, inbox, pending-send, age and shutdown policies in the Tokio facade;
- bounded retransmission visits and due/deadline scans;
- bounded receive scratch batches (`RecvBatch::MAX_CAPACITY`, 1024 slots;
  `MAX_BUF_LEN`, 65,536 bytes per slot);
- UTF-8-safe 512-byte caps for direct protocol handshake option strings;
- owner-local fixed-size shard telemetry (`ShardTelemetry`) for service time,
  deadline lateness, queue age/high-water and bounded overload outcomes;
- explicit caller-table capacity (`CallerTable::with_max_callers`, default 4096);
- hard 2^16 caps on caller-table and dense admission-slot capacities;
- hard 2^16 caps on caller-pool in-flight attempts and queued requests;
- application-owned publication remains outside the transport crate; any
  future fan-out layer must bound item, byte and age retention explicitly;
- fail-closed protocol event/output retention (`MAX_EVENT_QUEUE_ACTIONS`,
  `MAX_FLOW_WINDOW + 64`; `MAX_OUTPUT_QUEUE_ACTIONS`, 8192;
  `MAX_OUTPUT_QUEUE_BYTES`, 16 MiB);
- destination-specific send failure isolation, cancellation cleanup and
  bounded reaper grace ticks.

Validation already completed on this source includes protocol and transport
unit suites, full workspace tests, all-feature checks, Clippy with warnings as
errors, formatting and diff checks, every runtime feature build, MSRV checks,
packaging, dependency policy, fuzz-target builds/runs and AddressSanitizer.
The open work is:

1. qualify the runtime/ingress/egress/fan-out matrix on a quiet pinned host
   using a frozen workload contract;
2. run the native completion-runtime queue sentinel where io_uring is
   available, then perform the steady-state/soak window;
3. decide whether measured allocation pressure justifies a callback/sink API
   for `CallerTable` (the current API is bounded but allocates output vectors;
   the protocol still allocates each encoded packet, so a sink alone is not
   a zero-allocation path);
4. keep the per-card status headings and the detailed progress ledger
   synchronized with executed acceptance commands.

The bounded SRT-600 qualification tool now supplies the promotion gate
mechanics: `cargo run -p srt-bench -- qualify plan` emits the fixed ten-scenario
corpus and `qualify score BASE.tsv HEAD.tsv` checks correctness, noise and
geometric resource ratios. It validates runner output; it does not invent
product workload values or execute live traffic.

## 4. Rules for every implementation card

1. Read current source, applicable AGENTS.md and the nearest tests. If `.codegraph/` exists, use CodeGraph first for symbols/call paths; never initialize an index as part of this work. Use `rg` for omitted details or repositories without an index.
2. Revalidate the card's claim. Follow all callers of the changed behavior and sibling adapters. A disproved/stale finding gets evidence, not a forced patch.
3. State the behavioral contract and the smallest useful regression. Do not expose private reasoning; record the observable invariant and evidence.
4. Change one root cause. A card may be split into smaller checkpoints; each must leave a coherent diff. Do not add an abstraction solely to save a few repeated native-I/O lines.
5. Execute the focused check when allowed. A test command matching zero tests is not evidence. Do not modify production expectations to make a broken implementation pass.
6. Inspect the diff for acceptance ambiguity, new unbounded work, lifecycle leaks, hidden allocations, API drift and sibling divergence.
7. Record exact commands, outcomes, test counts, skips and remaining limits. Mark verified only when the acceptance criteria actually pass.
8. Move to the next dependency-ready card. Do not re-audit the entire repository on each continuation.

If a correct implementation requires an unproven unsafe reclamation scheme, unclear protocol semantics, an unresolved runtime cancellation contract, or a material change to the public contract, isolate the smallest question and seek review. Continue independent ready work. Do not declare the whole goal complete while a required question remains.

No new task framework, agent orchestrator, benchmark DSL, generic runtime trait, metrics service, or dependency is part of the default plan. Add a dependency only when the required behavior cannot reasonably reuse the codebase, stdlib, platform or an installed dependency; record the concrete reason and supported surface.

## 5. Required invariants

### I1. Admission has a linearization point

An application message has one of these dispositions:

- Rejected before admission: caller may retry; no retained fragments, sequence/message advance, crypto state commitment or queued output prefix remains.
- Accepted once: protocol owns the message; subsequent transport progress/failure must not be reported as a safe-to-retry rejection.
- Accepted followed by terminal failure: explicitly identify acceptance and failure so the application cannot unknowingly duplicate the message.

Cover `send`, `send_owned`, `send_shared`, both explicit-sequence variants, fragmented messages and group sends. Group success follows the existing documented logical group contract; do not silently change Broadcast into “all legs must accept.”

Prefer validation and wire preparation before irreversible admission. Do not clone the entire connection as rollback machinery or rewind cryptographic state ad hoc. If a post-admission failure cannot be eliminated, represent it explicitly.

### I2. Every output action has one owner and one disposition

Conceptually:

```text
protocol-owned -> pending/not-submitted -> submitted -> completed
                              |                |
                              |                +-> resolve actual runtime completion/cancellation
                              +-> safe retry while still owned
```

Only a known unsent datagram can be retried as unsent. A dropped future is not evidence of non-submission. Retain following timer actions and unsent batch suffixes in protocol order. SRT's own explicit retransmission is distinct from accidentally submitting the same output twice.

### I3. Bounded work covers the complete visit

Budget receive syscalls/datagrams, protocol-generated retransmissions, timer/session visits, output actions/packets/bytes and application delivery. A bounded `poll_output` loop cannot limit an earlier unbounded `handle_timer`.

For byte budgets, choose and document one of:
- strict cap, with configuration guaranteeing at least one supported datagram can fit; or
- a one-datagram progress allowance when nothing has been emitted yet.

Keep the existing deliberate first-packet allowance unless there is a reason to change it. Report exhaustion truthfully, including when the next packet does not fit remaining allowance. Do not silently clamp invalid zero budgets to a different public promise.

If readiness is edge-triggered, yielding before EAGAIN requires explicit rescheduling or rearming. “There will be another readiness edge” is not a valid assumption.

### I4. Deadlines retain meaning

A deadline is absolute in a chosen monotonic domain. Choose the minimum across direct sessions, groups, pacing and maintenance. Conversion to a relative wait happens at the driver boundary. Original source time survives relay buffering. Do not reuse a pre-await `now` as the observed arrival/service time after a long wait.

### I5. Resource bounds include lifetimes outside the ring

Bound bytes, items and age where relevant. Counting slots does not bound backing storage still retained by destination ARQ or application references. Bound half-open and established sessions, deferred admission, groups, output queues, message assembly, retry queues, publication retention, sockets and scratch.

### I6. Failures are isolated at the intended boundary

A malformed datagram, slow consumer, full output queue or failed group leg cannot prevent otherwise healthy siblings from making bounded progress. Record the local failure and perform required retirement/group transitions. Do not suppress fatal failures under the label “isolation.”

### I7. Configuration and evidence are truthful

Every supported setting is enforced by a named owner or documented as external policy. Unsupported requested combinations fail before service starts. Required benchmark fields cannot become success through NaN comparisons, missing-value defaults, mixed attempts or suppressed worker exits.

### I8. Secrets and protocol safety survive optimization

Retain cookie/source validation, bounded loss parsing, negotiated encryption rules, nonce/key/sequence semantics, secret redaction, key erasure and group deduplication. Avoid raw-pointer zeroization tests that read freed memory. Correctness changes do not require a speed improvement to be retained.

## 6. Target architecture and scope choices

Use the current crates; add no new production crate by default.

- Protocol: state machines, acceptance/fragmentation, bounded protocol work, deadlines as data, protocol statistics.
- Transport: owned drivers, native I/O, scheduling, admission/caller lifecycle, bounded transport queues and plain shard measurements.
- Lifecycle: pure routing and promotion decisions.
- Application/example: source publication, destination subscriptions, live expiry/disconnect policy, placement/affinity, tenant policy, exporters and alerts.
- Benchmark: source/load generation, impairment, measurement and experiment control.

Build a complete owner-driven path first, then a managed Tokio facade. One owner/driver per shard; do not introduce a hidden second runtime or a protocol task per connection as the high-density default. Preserve native implementations for the other runtimes and qualify them independently. Per-connection ergonomic handles are allowed to submit bounded control/application requests to the owning shard.

Proposed API behavior (names to follow existing naming conventions; these are not existing symbols):
- listener driver: progress, accept/reject, receive logical events, bounded send admission, next deadline, close;
- caller driver: connect deadline, accepted/rejected/failed outcome, message send/receive, stats, close;
- optional managed Tokio handle: async send/receive/close backed by its explicit driver;
- raw prepared sockets/core APIs stay available for custom ownership.

Start with methods; do not add a futures Stream/Sink dependency solely for appearances. An adapter can be added when it materially helps an actual consumer. Application examples must not depend on `srt-bench`.

First qualification includes caller/listener, plain/CTR/GCM as implemented and advertised, direct and Broadcast/Backup sessions, and the supported Linux native runtime paths. Rendezvous, additional platforms and new kernel fast paths remain explicit optional scope; do not claim them supported. IPv6 must either work along the chosen path or be rejected during preparation.

## 7. Execution order and status

Cards below form a dependency graph. Within a phase, choose the smallest ready card. Do not start later architectural changes merely to avoid a failing earlier correctness check.

Status vocabulary:
- TODO: not started.
- CONFIRMED: current-source claim reproduced/traced.
- IN_PROGRESS: one implementation checkpoint active.
- IMPLEMENTED_UNVERIFIED: edit exists; required validation has not run.
- VERIFIED: acceptance checks passed on recorded source.
- ALREADY_FIXED: current source and executed checks show no edit needed.
- DISPROVED: recorded source evidence disproves the claim; dependent work updated.
- BLOCKED: a named external prerequisite or design question prevents this card.
- DEFERRED_OPTIONAL: only for explicitly optional scope; never for an unresolved required invariant.

A source correction can remove an invalid task, but removing a required product behavior from scope needs the user's decision. Do not replace failures with ignored tests or weaker thresholds.

Read the common sections once, then read only the selected card, prerequisites, current touched source and relevant tests. The ledger is the resume point; previous conversation is not required.

## 8. Task index and implementation cards

| ID | Task | Phase | Prerequisites |
|---|---|---|---|
| [B00](#b00) | Establish the current baseline and execution boundary | Baseline | None |
| [E01](#e01) | Reject invalid benchmark and analyzer evidence | Evidence | B00 |
| [E02](#e02) | Use one attempt-aware pairing and metrics path | Evidence | E01 |
| [E03](#e03) | Preserve worker, child-process and timeout failures | Evidence | E01 |
| [E04](#e04) | Turn the codegen audit into an honest inventory | Evidence | B00 |
| [E05](#e05) | Remove timing assertions from ordinary correctness tests | Evidence | B00 |
| [S01](#s01) | Make explicit-sequence admission consistent | Protocol correctness | E05 |
| [S02](#s02) | Make core admission atomic or explicitly account for accepted failures | Protocol correctness | S01 |
| [S03](#s03) | Separate adapter admission from output progress | Transport correctness | S02 |
| [S04](#s04) | Retain readiness-driver output through cancellation | Transport correctness | S03 |
| [S05](#s05) | Resolve completion-runtime cancellation by submission state | Transport correctness | S03 |
| [T01](#t01) | Detect datagram truncation before parsing | Transport correctness | B00 |
| [T02](#t02) | Make receive limits and readiness continuation truthful | Transport correctness | T01 |
| [T03](#t03) | Report output exhaustion without stranded work | Transport correctness | B00 |
| [T04](#t04) | Isolate group-leg failures and refresh group state | Transport correctness | T01, T03 |
| [T05](#t05) | Choose the earliest deadline across all peer types | Transport correctness | B00 |
| [P01](#p01) | Bound retransmission generation inside the protocol | Bounded protocol work | S02, T03 |
| [P02](#p02) | Bound due-session service and preserve deadline fairness | Bounded protocol work | P01, T02, T05 |
| [K01](#k01) | Use one validated endpoint ownership plan | Configuration | B00 |
| [K02](#k02) | Carry effective capabilities and budgets into drivers | Configuration | K01, T02, T03 |
| [S06](#s06) | Explicitly erase cached crypto state | Protocol correctness | E05 |
| [P03](#p03) | Make packet/message size limits explicit and correct | Protocol correctness | S02 |
| [A01](#a01) | Move lifecycle truth out of benchmark event consumption | Application foundation | T04, T05 |
| [A02](#a02) | Make address-family support end-to-end | Application foundation | T01, K01 |
| [B01](#b01) | Remove the benchmark Mio readiness ceiling | Evidence | B00 |
| [B02](#b02) | Give benchmark Mio the same receive/timer contract | Evidence | B01, P02 |
| [D01](#d01) | Remove dead helpers and align documentation | Cleanup | K02, A01, S03 |
| [D02](#d02) | Reuse scratch without changing ownership or packet safety | Cleanup | S04, S05, T01, T04 |
| [A03](#a03) | Build a complete single-owner listener/caller driver | Application integration | S03, P02, K02, A01, A02, P03 |
| [A04](#a04) | Enforce connection, idle and resource policy at the owner | Application integration | A03 |
| [A05](#a05) | Add the managed Tokio application facade | Application integration | A04, S04 |
| [A06](#a06) | Complete native runtime parity incrementally | Application integration | A04, A05, S04, S05, F05 |
| [F01](#f01) | Preserve source age through relay APIs | Live fan-out | P03, A05 |
| [F02](#f02) | Implement or reuse a bounded publication bus for shards | Live fan-out | F01, A05 |
| [F03](#f03) | Implement destination isolation and live expiry policy | Live fan-out | F02, P02 |
| [F04](#f04) | Measure shard service, lateness and resource use | Live fan-out | F03 |
| [F05](#f05) | Close the complete application path predictably | Live fan-out | F03, A05 |
| [V00](#v00) | Freeze the workload and qualification contract | Qualification | E02, E03, B02 |
| [V01](#v01) | Extend deterministic network and lifecycle simulation | Qualification | S06, P03, P02, A01 |
| [V02](#v02) | Qualify native runtime features, interop and fuzz execution | Qualification | V01, A06, A02, S06 |
| [V03](#v03) | Run bounded-resource soak and steady-state qualification | Qualification | V00, V02, F04, F05, D02 |
| [D03](#d03) | Finish build, API, support and release documentation | Delivery | D01, A06, V02 |
| [Z01](#z01) | Perform final qualification review and delivery handoff | Delivery | E01, E02, E03, E04, E05, B02, D02, D03, S06, F05, V03 |

<a id="b00"></a>

### B00. Establish the current baseline and execution boundary

**Phase:** Baseline. **Prerequisites:** None. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [README.md:14](/home/dev/srt-rs/README.md:14), [rust-toolchain.toml:1](/home/dev/srt-rs/rust-toolchain.toml:1), [crates/srt-protocol/VENDOR.md:26](/home/dev/srt-rs/crates/srt-protocol/VENDOR.md:26).

**Implementation checkpoints:**

1. Record branch, full SHA, existing diff/untracked files, approved worktree and validation host. Current audited SHA is a reference, not permission to reset newer work.
2. Inventory current features and tests without running Cargo while READ_ONLY. Check whether relevant relay/publication code already exists on current or locally available branches using read-only Git/source inspection.
3. Create one progress ledger only after artifact/checkpoint writes are authorized; otherwise return the checkpoint in the conversation. Select the next ready card.

**Acceptance:** Baseline, permissions and protected artifacts are explicit. If implementation is not yet authorized, finish useful source mapping and leave implementation pending; do not pretend permission arrived.

**Checks after authorization:** `READ: git --no-optional-locks status --short --branch`; `READ: git rev-parse HEAD`; `READ: git diff --stat`.

<a id="e01"></a>

### E01. Reject invalid benchmark and analyzer evidence

**Phase:** Evidence. **Prerequisites:** B00. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-bench/src/harness.rs:343](/home/dev/srt-rs/crates/srt-bench/src/harness.rs:343), [crates/srt-bench/src/compare.rs:248](/home/dev/srt-rs/crates/srt-bench/src/compare.rs:248), [crates/xtask/src/reportcard.rs:221](/home/dev/srt-rs/crates/xtask/src/reportcard.rs:221).

**Implementation checkpoints:**

1. Inspect required fields for each schema/workload; distinguish optional legacy columns from required validity inputs.
2. Reject nonfinite values, invalid negative counts/durations, invalid zero denominators, missing required fields and malformed required analyzer metrics. Do not turn missing fields into zero loss/zero complexity.
3. Keep validity separate from clean-performance criteria: an intentionally bandwidth-constrained run can be valid but unclean.

**Acceptance:** Add regressions for NaN, positive/negative infinity, missing required fields, malformed metrics, negative counts and invalid denominators. They must produce invalid/error status and nonzero gate exits where applicable. Valid legacy optional fields remain supported.

**Checks after authorization:** `Q-BENCH-CLEAN`; `Q-BENCH-HARNESS`; `Q-BENCH-COMPARE`; `Q-XTASK`.

<a id="e02"></a>

### E02. Use one attempt-aware pairing and metrics path

**Phase:** Evidence. **Prerequisites:** E01. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-bench/src/harness.rs:862](/home/dev/srt-rs/crates/srt-bench/src/harness.rs:862), [crates/srt-bench/src/compare.rs:352](/home/dev/srt-rs/crates/srt-bench/src/compare.rs:352).

**Implementation checkpoints:**

1. Reuse the comparison module's cell/repetition/attempt identity; repair any discovered duplicate-role ambiguity instead of silently selecting a convenient row.
2. Compute the chosen delivery metric per complete paired attempt before summarization. Document whether a report is median-of-ratios or an explicitly weighted aggregate; do not accidentally divide unrelated role medians.
3. Make text/TSV/chart outputs consume the same canonical metrics and validity result.

**Acceptance:** Two partial attempts cannot form one complete run. Reused repetition numbers in different cells never cross-pair. Duplicated roles have an explicit policy. All report formats agree for the same fixture.

**Checks after authorization:** `Q-BENCH-HARNESS`; `Q-BENCH-COMPARE`; `Q-BENCH-CLEAN`.

<a id="e03"></a>

### E03. Preserve worker, child-process and timeout failures

**Phase:** Evidence. **Prerequisites:** E01. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-bench/src/lib.rs:2627](/home/dev/srt-rs/crates/srt-bench/src/lib.rs:2627), [.github/workflows/bench-nightly.yml:75](/home/dev/srt-rs/.github/workflows/bench-nightly.yml:75), [.github/workflows/bench-weekly.yml:39](/home/dev/srt-rs/.github/workflows/bench-weekly.yml:39).

**Implementation checkpoints:**

1. Propagate worker panic as failed run status rather than empty statistics.
2. Handle timeout exit status specifically. Preserve crashes, validation errors and unexpected nonzero exits even when retaining partial data.
3. Mark partial campaigns and chart only qualified comparable cells. Preserve useful raw data without giving the campaign a passing verdict.

**Acceptance:** Regression fixtures cover worker panic, missing role output, non-timeout child failure and expected campaign timeout. Expected timeout retains partial results but is not labeled complete. No workflow change is executed or published during this task.

**Checks after authorization:** `Q-BENCH-MATRIX`; `Q-BENCH-CLEAN`; `Q-BENCH-HARNESS`.

<a id="e04"></a>

### E04. Turn the codegen audit into an honest inventory

**Phase:** Evidence. **Prerequisites:** B00. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/xtask/src/audit.rs:211](/home/dev/srt-rs/crates/xtask/src/audit.rs:211), [docs/perf/x86-64-v3-pgo-audit.md:1](/home/dev/srt-rs/docs/perf/x86-64-v3-pgo-audit.md:1).

**Implementation checkpoints:**

1. Delete unconditional 'optimal' and 'all hot paths verified' conclusions.
2. Retain measured opcode counts and precisely describe what they establish. Missing/disassembly failures must remain failures.
3. Label historical manual assembly conclusions with their inspected commit/compiler/flags rather than implicitly applying them to HEAD.

**Acceptance:** The tool cannot claim algorithmic or whole-path optimality from aggregate opcode counts. Documentation distinguishes automated inventory from manual analysis. Do not add a replacement audit framework.

**Checks after authorization:** `Q-XTASK`; `REVIEW: inspect output formatting and error branches; codegen execution is optional until the qualification phase`.

<a id="e05"></a>

### E05. Remove timing assertions from ordinary correctness tests

**Phase:** Evidence. **Prerequisites:** B00. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-protocol/src/crypto.rs:1414](/home/dev/srt-rs/crates/srt-protocol/src/crypto.rs:1414), [crates/srt-protocol/benches/core_packet_loop.rs:1](/home/dev/srt-rs/crates/srt-protocol/benches/core_packet_loop.rs:1).

**Implementation checkpoints:**

1. Move the cached-vs-fresh cipher timing experiment into an existing appropriate Criterion benchmark or a narrowly scoped benchmark target.
2. Replace timing assertions with deterministic equivalence over keys, sizes and sequence values.
3. Do not weaken crypto correctness checks or automatically rerun benchmarks during this cleanup.

**Acceptance:** Normal protocol tests contain no pass/fail assertion based on cached_ns <= uncached_ns*1.05. Deterministic equivalence passes. Timing remains measurable when a performance window is authorized.

**Checks after authorization:** `Q-CRYPTO-UNIT`; `Q-CRYPTO`; `Q-CORE`.

<a id="s01"></a>

### S01. Make explicit-sequence admission consistent

**Phase:** Protocol correctness. **Prerequisites:** E05. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-protocol/src/srt_connection.rs:1127](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1127), [crates/srt-protocol/src/srt_connection.rs:1250](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1250), [crates/srt-protocol/src/srt_sender.rs:502](/home/dev/srt-rs/crates/srt-protocol/src/srt_sender.rs:502).

**Implementation checkpoints:**

1. Trace all owned/shared explicit-sequence callers, especially SrtGroup.
2. Reject a wrong explicit sequence before mutation in the shared path as in the owned path, or use a shared validation helper.
3. Ensure sender None is never silently translated to successful admission.

**Acceptance:** On a connected session, wrong sequence produces an explicit rejection, leaves next sequence/retention/output unchanged and preserves subsequent valid sending. Exercise wrap-adjacent sequence values and group callers.

**Checks after authorization:** `Q-CORE`; `Q-CONNECTION`; `Q-GROUP`.

<a id="s02"></a>

### S02. Make core admission atomic or explicitly account for accepted failures

**Phase:** Protocol correctness. **Prerequisites:** S01. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-protocol/src/srt_connection.rs:1151](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1151), [crates/srt-protocol/src/srt_connection.rs:1187](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1187), [crates/srt-protocol/src/srt_connection.rs:1250](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1250).

**Implementation checkpoints:**

1. Locate the current mutation-before-encrypt paths. Define the admission linearization point for one packet and a fragmented message.
2. Prefer checking/preparing fallible work before committing sender state. Reuse existing validation; add a minimal prepare/commit boundary only if needed. Do not clone whole protocol state or rewind nonces/counters to fake rollback.
3. If a post-admission failure remains possible, expose acceptance in the outcome and make terminal handling explicit. Keep existing callers from treating it as an ordinary rejection.
4. Use a narrow deterministic test hook only if real failure preconditions cannot be constructed; keep it out of the normal production surface.

**Acceptance:** Owned/shared, explicit sequence and multi-fragment sends satisfy I1. A rejected message leaves no output prefix or retained fragment; accepted-then-failed outcomes cannot be retried as unaccepted. Review crypto/group effects before promotion.

**Checks after authorization:** `Q-CORE`; `Q-CONNECTION`; `Q-PROP-MESSAGE`; `Q-PROP-SENDER`; `Q-GROUP`.

<a id="s03"></a>

### S03. Separate adapter admission from output progress

**Phase:** Transport correctness. **Prerequisites:** S02. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/runtimes/tokio.rs:179](/home/dev/srt-rs/crates/srt-transport/src/runtimes/tokio.rs:179), [crates/srt-transport/src/runtimes/compio.rs:97](/home/dev/srt-rs/crates/srt-transport/src/runtimes/compio.rs:97), [crates/srt-transport/src/runtimes/smol.rs:138](/home/dev/srt-rs/crates/srt-transport/src/runtimes/smol.rs:138), [crates/srt-transport/src/runtimes/monoio.rs:105](/home/dev/srt-rs/crates/srt-transport/src/runtimes/monoio.rs:105), [crates/srt-transport/src/runtimes/glommio.rs:136](/home/dev/srt-rs/crates/srt-transport/src/runtimes/glommio.rs:136).

**Implementation checkpoints:**

1. Apply the core admission contract to every native adapter and all callers that retry/count sends.
2. Represent pacing-not-due, queue-full, closed/invalid input, accepted, and later driver failure without Result<(),()> ambiguity.
3. Do not solve this merely by ignoring all drain errors: preserve the error for driver service/terminal reporting. Reuse a small shared outcome type or pure helper where useful.

**Acceptance:** Force output budget exhaustion and send failure after admission. A caller following the public API neither duplicates accepted data nor loses the transport error. All adapters follow the same semantic contract.

**Checks after authorization:** `Q-TRANSPORT-BATCH`; `Q-TRANSPORT-CALLER`; `Q-FEATURES`; `Q-BENCH-SOURCE`.

<a id="s04"></a>

### S04. Retain readiness-driver output through cancellation

**Phase:** Transport correctness. **Prerequisites:** S03. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed).

**Read first:** [crates/srt-transport/src/runtimes/tokio.rs:58](/home/dev/srt-rs/crates/srt-transport/src/runtimes/tokio.rs:58), [crates/srt-transport/src/runtimes/smol.rs:49](/home/dev/srt-rs/crates/srt-transport/src/runtimes/smol.rs:49), [crates/srt-transport/src/batch.rs:273](/home/dev/srt-rs/crates/srt-transport/src/batch.rs:273), [crates/srt-transport/src/caller.rs:1197](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:1197).

**Implementation checkpoints:**

1. For readiness paths, avoid taking owned pending outputs into disposable local storage before writable readiness awaits.
2. Keep pending work and following timer actions driver-owned. Advance ownership only according to known syscall completion/unsent suffix.
3. Extend current batch-ordering tests and use a minimal controllable readiness boundary for cancellation tests.

**Acceptance:** Cancel before readiness, after readiness and after partial batch send. Each accepted syscall prefix is accounted once; the unsent suffix and timer actions remain ordered and serviceable. No busy retry loop appears.

**Checks after authorization:** `Q-TRANSPORT-BATCH`; `Q-FEATURES`; `NEW: focused Tokio/Smol cancellation regression; record its exact target and executed count`.

<a id="s05"></a>

### S05. Resolve completion-runtime cancellation by submission state

**Phase:** Transport correctness. **Prerequisites:** S03. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/runtimes/compio.rs:40](/home/dev/srt-rs/crates/srt-transport/src/runtimes/compio.rs:40), [crates/srt-transport/src/runtimes/monoio.rs:40](/home/dev/srt-rs/crates/srt-transport/src/runtimes/monoio.rs:40), [crates/srt-transport/src/runtimes/glommio.rs:59](/home/dev/srt-rs/crates/srt-transport/src/runtimes/glommio.rs:59).

**Implementation checkpoints:**

1. Read the actual pinned runtime implementation/documentation for owned-buffer send and cancellation before changing ownership.
2. Model NotSubmitted, Submitted and Completed as needed by the actual runtime. Keep the operation alive under the owner or use a documented cancellation completion result.
3. Do not install a drop guard that blindly requeues a buffer whose datagram may already have been submitted.
4. Handle one runtime per checkpoint; use native operations, not an invented common I/O trait.

**Acceptance:** Cover cancellation before submission, while pending, after kernel completion before observation, error completion and following timer actions. No output disappears or is duplicated by uncertain retry. If submission/completion ownership cannot be established, leave the card blocked for review; do not declare cancellation-safe.

**Checks after authorization:** `Q-FEATURES`; `NEW: one deterministic/runtime-specific completion ownership test per affected adapter`; `Q-TRANSPORT-BATCH`.

<a id="t01"></a>

### T01. Detect datagram truncation before parsing

**Phase:** Transport correctness. **Prerequisites:** B00. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-transport/src/socket_io.rs:159](/home/dev/srt-rs/crates/srt-transport/src/socket_io.rs:159), [crates/srt-transport/src/socket_io.rs:281](/home/dev/srt-rs/crates/srt-transport/src/socket_io.rs:281), [crates/srt-transport/src/batch.rs:23](/home/dev/srt-rs/crates/srt-transport/src/batch.rs:23).

**Implementation checkpoints:**

1. Inspect returned message flags and length. Reject or separately report truncated datagrams; do not pass a truncated prefix as a complete packet.
2. Preserve service of other datagrams in a successful batch. Avoid treating one malformed datagram as a socket-wide failure.
3. Keep buffer size and supported maximum datagram contract consistent; do not merely allocate the maximum UDP size everywhere.

**Acceptance:** Oversized datagram followed by valid datagram cannot cause prefix delivery, panic or loss of the valid sibling. Counters identify truncation. Test exact-capacity and smaller datagrams too.

**Checks after authorization:** `Q-TRANSPORT-BATCH`; `NEW: loopback datagram truncation regression in existing transport tests`.

<a id="t02"></a>

### T02. Make receive limits and readiness continuation truthful

**Phase:** Transport correctness. **Prerequisites:** T01. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-transport/src/batch.rs:202](/home/dev/srt-rs/crates/srt-transport/src/batch.rs:202), [crates/srt-transport/src/runtimes/tokio.rs:233](/home/dev/srt-rs/crates/srt-transport/src/runtimes/tokio.rs:233), [crates/srt-transport/src/runtimes/smol.rs:1](/home/dev/srt-rs/crates/srt-transport/src/runtimes/smol.rs:1).

**Implementation checkpoints:**

1. Limit each syscall batch to the remaining datagram budget. If a documented batch-granular API is retained, expose that explicitly rather than claiming an exact maximum.
2. Specify zero-budget behavior at public construction; do not hide invalid settings through max(1).
3. Preserve queued work after a budget yield on readiness runtimes; prove it is rescheduled even without a fresh edge.

**Acceptance:** Budgets 1,31,32,33,64 behave as specified, with no skipped datagrams and no starvation after yielding. Repeated ready input cannot indefinitely suppress timers.

**Checks after authorization:** `Q-TRANSPORT-BATCH`; `Q-FEATURES`; `Q-WAITER`.

<a id="t03"></a>

### T03. Report output exhaustion without stranded work

**Phase:** Transport correctness. **Prerequisites:** B00. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-transport/src/caller.rs:876](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:876), [crates/srt-transport/src/caller.rs:1150](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:1150), [crates/srt-transport/src/caller.rs:1197](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:1197).

**Implementation checkpoints:**

1. Set a non-drained status when the next packet cannot fit the remaining allowance even though counters are below their numeric caps.
2. Preserve the intentional first-datagram progress allowance or replace it with validated strict-cap configuration; document the choice.
3. Verify ready-queue reenqueuing and timer-action ordering after budget yields.

**Acceptance:** Two 1332-byte packets under a 2000-byte allowance emit one then report exhaustion with one retained. A packet larger than the whole byte allowance never becomes a permanent silent stall. Drained means no known pending work for that operation's scope.

**Checks after authorization:** `Q-TRANSPORT-CALLER`; `Q-TRANSPORT-BATCH`.

<a id="t04"></a>

### T04. Isolate group-leg failures and refresh group state

**Phase:** Transport correctness. **Prerequisites:** T01, T03. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/group_conn.rs:453](/home/dev/srt-rs/crates/srt-transport/src/group_conn.rs:453), [crates/srt-transport/src/runtimes/tokio.rs:495](/home/dev/srt-rs/crates/srt-transport/src/runtimes/tokio.rs:495).

**Implementation checkpoints:**

1. Collect per-leg failure outcomes while continuing bounded service for healthy legs. Distinguish malformed packet, temporary backpressure and terminal leg failure.
2. Ensure group refresh/retirement happens even when a leg fails.
3. Keep existing logical Broadcast/Backup semantics and surface total group failure honestly.

**Acceptance:** A failing first leg cannot prevent a healthy later leg from sending/receiving or transitioning. Test sustained malformed input, socket failure, temporary full sender window and all-legs-failed behavior.

**Checks after authorization:** `Q-GROUP`; `Q-TRANSPORT-GROUP`; `Q-PROP-GROUP`.

<a id="t05"></a>

### T05. Choose the earliest deadline across all peer types

**Phase:** Transport correctness. **Prerequisites:** B00. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-transport/src/admission.rs:1968](/home/dev/srt-rs/crates/srt-transport/src/admission.rs:1968).

**Implementation checkpoints:**

1. Take the minimum of direct-peer and group deadlines, including the no-deadline cases.
2. Check that expired deadlines return an immediate service indication and that units/domains agree.
3. Keep this change independent from wider scheduler rewrites.

**Acceptance:** Direct due at 10 and group due at 20 yields 10; reverse order yields 10; either population empty and both empty have documented behavior. No wall-clock sleeps are needed.

**Checks after authorization:** `Q-TRANSPORT-ADMISSION`.

<a id="p01"></a>

### P01. Bound retransmission generation inside the protocol

**Phase:** Bounded protocol work. **Prerequisites:** S02, T03. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-protocol/src/srt_connection.rs:966](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:966), [crates/srt-protocol/src/srt_connection.rs:2106](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:2106), [crates/srt-protocol/src/srt_sender.rs:712](/home/dev/srt-rs/crates/srt-protocol/src/srt_sender.rs:712).

**Implementation checkpoints:**

1. Introduce the minimum resumable processing boundary so one NAK/timer callback does not encrypt/queue the entire retained window in one visit.
2. Preserve pending retransmission membership, ordering rules and eventual service. Coordinate protocol generation and transport output budgets.
3. Keep compact bounded NAK-range validation. Do not expand adversarial ranges into unbounded intermediate work.

**Acceptance:** A maximum supported loss window requires bounded work per invocation and completes over later visits. Healthy siblings continue service. No retransmission is silently lost, repeatedly re-added forever, or generated faster than the documented recovery policy allows.

**Checks after authorization:** `Q-CORE`; `Q-PROP-SENDER`; `Q-BOUNDS`; `Q-CONNECTION`.

<a id="p02"></a>

### P02. Bound due-session service and preserve deadline fairness

**Phase:** Bounded protocol work. **Prerequisites:** P01, T02, T05. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/caller.rs:782](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:782), [crates/srt-transport/src/admission.rs:1968](/home/dev/srt-rs/crates/srt-transport/src/admission.rs:1968), [crates/srt-transport/src/due_index.rs:1](/home/dev/srt-rs/crates/srt-transport/src/due_index.rs:1), [crates/srt-transport/src/dense_due_index.rs:1](/home/dev/srt-rs/crates/srt-transport/src/dense_due_index.rs:1).

**Implementation checkpoints:**

1. Budget due-session/timer visits before protocol work rather than collecting/firing every due session first.
2. Retain resumable due work; service ready input, deadlines, pending output and application requests fairly.
3. Reuse existing deadline indexes. Do not add another scheduler representation unless existing indexes cannot express the required contract.

**Acceptance:** Hundreds of simultaneous deadlines and one continuously readable peer cannot starve a quiet due connection. Every yield exposes remaining work and schedules another visit. Record worst observed visit work in deterministic tests.

**Checks after authorization:** `Q-TRANSPORT-CALLER`; `Q-TRANSPORT-ADMISSION`; `Q-WAITER`.

<a id="k01"></a>

### K01. Use one validated endpoint ownership plan

**Phase:** Configuration. **Prerequisites:** B00. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/config.rs:1150](/home/dev/srt-rs/crates/srt-transport/src/config.rs:1150), [crates/srt-transport/src/config.rs:1211](/home/dev/srt-rs/crates/srt-transport/src/config.rs:1211), [crates/srt-transport/src/config.rs:1660](/home/dev/srt-rs/crates/srt-transport/src/config.rs:1660), [crates/srt-transport/src/config.rs:1833](/home/dev/srt-rs/crates/srt-transport/src/config.rs:1833), [crates/srt-bench/src/lib.rs:614](/home/dev/srt-rs/crates/srt-bench/src/lib.rs:614).

**Implementation checkpoints:**

1. Resolve Auto first with the necessary topology/ownership context, then validate the effective combination.
2. Make listener, caller and benchmark inputs use one canonical resolver, retaining lightweight conversions for compatibility.
3. Reject Shared plus effective promotion/connected-tuple behavior that can steal traffic; do not solve it by silently ignoring explicitly requested behavior.

**Acceptance:** Table-driven tests cover Auto/explicit promotion, Shared/Exclusive, every topology and supported capability set. Shared Auto cannot resolve to forbidden promotion. Constructors and benchmark validation agree.

**Checks after authorization:** `Q-TRANSPORT-CONFIG`; `Q-BENCH-SOURCE`; `Q-REUSEPORT`.

<a id="k02"></a>

### K02. Carry effective capabilities and budgets into drivers

**Phase:** Configuration. **Prerequisites:** K01, T02, T03. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/config.rs:1327](/home/dev/srt-rs/crates/srt-transport/src/config.rs:1327), [crates/srt-transport/src/runtimes/tokio.rs:325](/home/dev/srt-rs/crates/srt-transport/src/runtimes/tokio.rs:325), [crates/srt-transport/src/runtimes/compio.rs:154](/home/dev/srt-rs/crates/srt-transport/src/runtimes/compio.rs:154), [crates/srt-bench/src/lib.rs:807](/home/dev/srt-rs/crates/srt-bench/src/lib.rs:807).

**Implementation checkpoints:**

1. Describe actual batching support for the selected driver path, not only the runtime's general nature.
2. Store configured default output/receive settings in constructed drivers or require them explicitly on every drive; default wrappers must not silently replace them.
3. Propagate fallible session setters. Remove task_scheduler if it has no necessary behavior.
4. Expose the effective settings without secrets.

**Acceptance:** Construct a driver with a distinctive budget and verify actual work honors it. Unsupported explicit settings fail preparation; supported Tokio batching is not rejected solely because runtime != Mio. Invalid benchmark session values fail visibly.

**Checks after authorization:** `Q-TRANSPORT-CONFIG`; `Q-FEATURES`; `Q-BENCH-SOURCE`.

<a id="s06"></a>

### S06. Explicitly erase cached crypto state

**Phase:** Protocol correctness. **Prerequisites:** E05. **Initial status:** TODO. **Current status:** VERIFIED (ALREADY_FIXED, evidence added).

**Read first:** [crates/srt-protocol/Cargo.toml:35](/home/dev/srt-rs/crates/srt-protocol/Cargo.toml:35), [crates/srt-protocol/src/crypto.rs:181](/home/dev/srt-rs/crates/srt-protocol/src/crypto.rs:181), [crates/srt-protocol/src/crypto.rs:392](/home/dev/srt-rs/crates/srt-protocol/src/crypto.rs:392).

**Implementation checkpoints:**

1. Inspect resolved aes/aes-gcm/aes-kw/ctr feature contracts from their pinned source. Explicitly request required zeroization features rather than relying on unrelated feature unification.
2. Cover schedule/key replacement during rotation as well as context drop. Preserve redacted Debug.
3. Do not read freed allocations to test erasure. Use supported trait/feature assertions, source review and deterministic crypto/rotation checks.

**Acceptance:** The standalone protocol feature graph requests the zeroization needed for all cached sensitive state. Encryption and rotation vectors still pass. Document residual application-owned copies accurately.

**Checks after authorization:** `Q-CRYPTO-UNIT`; `Q-CRYPTO`; `Q-PROP-CRYPTO`; `Q-CORE`; `VALIDATE ONLY: cargo tree -p srt-proto -e features`.

<a id="p03"></a>

### P03. Make packet/message size limits explicit and correct

**Phase:** Protocol correctness. **Prerequisites:** S02. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-protocol/src/srt_connection.rs:394](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:394), [crates/srt-protocol/src/srt_connection.rs:1110](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1110), [crates/srt-protocol/src/srt_connection.rs:1146](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1146), [crates/srt-transport/src/config.rs:2213](/home/dev/srt-rs/crates/srt-transport/src/config.rs:2213).

**Implementation checkpoints:**

1. Verify the pinned SRT MSS/MTU negotiation semantics from primary specification/reference source before changing constants. Write down whether each limit counts IP, UDP, SRT header, crypto tag and payload.
2. Derive and enforce effective payload limits for scalar and fragmented sends. Preserve all-or-explicitly-accepted message admission from S02.
3. Expose maximum supported message/payload sizes and reject impossible settings before service.

**Acceptance:** Test below/exactly/above limits, small negotiated MSS, CTR/GCM, empty and multi-fragment messages. No UDP oversized output or incorrect 'negotiated' claim remains. Rejected inputs preserve admission invariants.

**Checks after authorization:** `Q-CONNECTION`; `Q-BOUNDS`; `Q-PROP-MESSAGE`; `Q-CRYPTO`; `Q-INTEROP`.

<a id="a01"></a>

### A01. Move lifecycle truth out of benchmark event consumption

**Phase:** Application foundation. **Prerequisites:** T04, T05. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/admission.rs:1984](/home/dev/srt-rs/crates/srt-transport/src/admission.rs:1984), [crates/srt-transport/src/admission.rs:2075](/home/dev/srt-rs/crates/srt-transport/src/admission.rs:2075), [crates/srt-transport/src/admission.rs:2448](/home/dev/srt-rs/crates/srt-transport/src/admission.rs:2448).

**Implementation checkpoints:**

1. Update lifecycle/start/terminal state once inside transport when the event occurs or is canonically handled, regardless of which consumer reads it.
2. Make poll_events and legacy benchmark drain observe the same state without double-accounting or consuming each other's required notifications.
3. Move stream duration/deadline and benchmark success counters into the adapter where feasible; preserve public compatibility deliberately.

**Acceptance:** A consumer using only production poll_events sees correct started/connected/closed counts for direct and bonded sessions. Legacy bench behavior remains correct without duplicate transitions.

**Checks after authorization:** `Q-TRANSPORT-ADMISSION`; `Q-BENCH-SOURCE`; `Q-TRANSPORT-GROUP`.

<a id="a02"></a>

### A02. Make address-family support end-to-end

**Phase:** Application foundation. **Prerequisites:** T01, K01. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/config.rs:2063](/home/dev/srt-rs/crates/srt-transport/src/config.rs:2063), [crates/srt-transport/src/socket_io.rs:307](/home/dev/srt-rs/crates/srt-transport/src/socket_io.rs:307), [crates/srt-transport/src/socket_io.rs:333](/home/dev/srt-rs/crates/srt-transport/src/socket_io.rs:333).

**Implementation checkpoints:**

1. Trace family support for configured listener/caller sockets, receive address conversion, demux, promotion and send batching.
2. Implement IPv6 for the paths declared supported, or reject unsupported combinations before binding/starting them. Do not silently skip packets whose address conversion failed.
3. Document the support matrix at path granularity; keep IPv4 behavior unchanged.

**Acceptance:** Each advertised family completes a loopback exchange and source validation; unsupported paths fail early with a clear configuration error. IPv6 socket construction alone is not a passing test.

**Checks after authorization:** `Q-TRANSPORT-CONFIG`; `Q-TRANSPORT-BATCH`; `NEW: per-family loopback exchange; explicitly record host IPv6 availability`.

<a id="b01"></a>

### B01. Remove the benchmark Mio readiness ceiling

**Phase:** Evidence. **Prerequisites:** B00. **Initial status:** TODO. **Current status:** VERIFIED.

**Read first:** [crates/srt-bench/src/runtimes/mio.rs:697](/home/dev/srt-rs/crates/srt-bench/src/runtimes/mio.rs:697).

**Implementation checkpoints:**

1. Replace the fixed 4096-entry touched array and silent event skipping with storage matching configured local drivers, or existing ready-index machinery.
2. Reuse storage between polls instead of allocating proportional to connections every wake.
3. Validate token/driver bounds explicitly; unrelated invalid tokens must not address another session.

**Acceptance:** Indices 4095,4096 and the highest configured local index are serviced or explicitly rejected by configuration, never silently ignored. Test bookkeeping without opening thousands of sockets unless a scale run is specifically authorized.

**Checks after authorization:** `Q-BENCH-MIO`; `Q-BENCH-MATRIX`.

<a id="b02"></a>

### B02. Give benchmark Mio the same receive/timer contract

**Phase:** Evidence. **Prerequisites:** B01, P02. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-bench/src/runtimes/mio.rs:739](/home/dev/srt-rs/crates/srt-bench/src/runtimes/mio.rs:739), [crates/srt-bench/src/runtimes/mio.rs:785](/home/dev/srt-rs/crates/srt-bench/src/runtimes/mio.rs:785).

**Implementation checkpoints:**

1. Use the bounded receive mechanism and proper readiness continuation in the measurement driver.
2. Service due timers independently of whether that connection received traffic or global polling went idle.
3. Keep benchmark changes scoped to measurement correctness; do not silently change source rate, pacing policy or workload during a before/after comparison.

**Acceptance:** One continuously active connection cannot starve another connection's deadline. The configured receive budget applies to this path. Existing source accounting remains unchanged.

**Checks after authorization:** `Q-BENCH-MIO`; `Q-BENCH-SOURCE`; `Q-WAITER`.

<a id="d01"></a>

### D01. Remove dead helpers and align documentation

**Phase:** Cleanup. **Prerequisites:** K02, A01, S03. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-bench/src/runtimes/mod.rs:122](/home/dev/srt-rs/crates/srt-bench/src/runtimes/mod.rs:122), [crates/srt-transport/README.md:32](/home/dev/srt-rs/crates/srt-transport/README.md:32), [crates/srt-transport/src/handoff.rs:1](/home/dev/srt-rs/crates/srt-transport/src/handoff.rs:1), [crates/srt-protocol/README.md:25](/home/dev/srt-rs/crates/srt-protocol/README.md:25), [crates/srt-transport/src/runtimes/tokio.rs:1](/home/dev/srt-rs/crates/srt-transport/src/runtimes/tokio.rs:1).

**Implementation checkpoints:**

1. Remove the always-true ingress support check and unreachable error after real capability validation is established.
2. Recheck all Conn::tick/TickResult callsites, including public consumers if known. Remove or deprecate unused benchmark-like convenience loops, not the required explicit drive API.
3. Correct NativeTimer/is_ready/HashMap timer descriptions, !Send-timer handoff rationale, group/API behavior, crypto capabilities and obsolete allocation claims.
4. Keep Handoff/WorkerMessage, useful native runtime adapters and specialized windows unless a separate evidence-backed decision replaces them.

**Acceptance:** No documented symbol is invented/nonexistent. No active caller is removed accidentally. Examples and docs describe actual ownership and supported behavior. Do not add a test for a spelling-only edit.

**Checks after authorization:** `Q-DOCS`; `Q-FEATURES`; `REVIEW: source/documentation and callsite consistency`.

<a id="d02"></a>

### D02. Reuse scratch without changing ownership or packet safety

**Phase:** Cleanup. **Prerequisites:** S04, S05, T01, T04. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/caller.rs:1197](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:1197), [crates/srt-transport/src/batch.rs:273](/home/dev/srt-rs/crates/srt-transport/src/batch.rs:273), [crates/srt-transport/src/group_conn.rs:367](/home/dev/srt-rs/crates/srt-transport/src/group_conn.rs:367), [crates/srt-transport/src/group_conn.rs:461](/home/dev/srt-rs/crates/srt-transport/src/group_conn.rs:461).

**Implementation checkpoints:**

1. Remove fresh drain/report/batch scratch allocations where an existing owner can reuse capacity. Handle one allocation site per checkpoint.
2. Account the group's eager 2 MiB receive scratch separately from protocol and socket memory. Resize or share only with the complete-datagram contract and owner lifetimes preserved.
3. Keep any reuse change that reduces demonstrated allocation/footprint while preserving behavior; if a proposed complexity does not earn its cost, record a measured retain decision.

**Acceptance:** Allocation/footprint evidence names workload and ownership. No shared scratch survives an await in a way that allows simultaneous mutation. Truncation/cancellation tests still pass. No unsafe buffer pool or global lock is introduced to chase a count.

**Checks after authorization:** `Q-TRANSPORT-BATCH`; `Q-TRANSPORT-GROUP`; `Q-ALLOC`; `PERF WINDOW: focused allocation/footprint comparison for the changed path`.

<a id="a03"></a>

### A03. Build a complete single-owner listener/caller driver

**Phase:** Application integration. **Prerequisites:** S03, P02, K02, A01, A02, P03. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/config.rs:1950](/home/dev/srt-rs/crates/srt-transport/src/config.rs:1950), [crates/srt-transport/src/admission.rs:1](/home/dev/srt-rs/crates/srt-transport/src/admission.rs:1), [crates/srt-transport/src/caller.rs:1](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:1), [crates/srt-transport/src/runtimes/mio.rs:1](/home/dev/srt-rs/crates/srt-transport/src/runtimes/mio.rs:1).

**Implementation checkpoints:**

1. First checkpoint: a single Mio owner drives one caller/listener pair using current prepared sockets, tables and injected times. Expose progress, events, send admission, deadlines and orderly close. Readiness/completion cancellation cards gate the respective async runtimes, not this independent Mio path.
2. Second checkpoint: service multiple sessions with the same bounded scheduler and logical handles. No application code copied from bench is required for correctness.
3. Keep runtime-specific socket readiness native. Shared pure scheduling/output contracts may be reused; do not introduce a dynamic runtime abstraction.
4. Add a minimal production-facing example under srt-transport/examples using only transport/protocol and its chosen runtime.

**Acceptance:** An example application connects, sends known messages, receives them and closes using supported APIs, including error handling. Multiple sessions survive one stalled peer. The example does not import srt-bench. New API/target names are documented once implemented.

**Checks after authorization:** `Q-TRANSPORT-ADMISSION`; `Q-TRANSPORT-CALLER`; `Q-FEATURES`; `NEW: public-API direct session integration and example compile/run`.

<a id="a04"></a>

### A04. Enforce connection, idle and resource policy at the owner

**Phase:** Application integration. **Prerequisites:** A03. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/config.rs:1546](/home/dev/srt-rs/crates/srt-transport/src/config.rs:1546), [crates/srt-transport/src/config.rs:1618](/home/dev/srt-rs/crates/srt-transport/src/config.rs:1618), [crates/srt-transport/src/config.rs:2090](/home/dev/srt-rs/crates/srt-transport/src/config.rs:2090).

**Implementation checkpoints:**

1. Apply configured attempt deadline and max_in_flight to a real caller pool; distinguish one connection's deadline from the pool's admission wait.
2. Enforce established idle timeout separately from half-open TTL and graceful-close deadline.
3. Track admission, promoted/caller sockets and effective buffer settings. Clearly distinguish requested socket-buffer limits, OS effective values and measured memory.
4. Return effective configuration and failure reasons; do not retain advertised no-op knobs.

**Acceptance:** A fake-clock pool never exceeds its concurrency limit; stalled attempts expire and release permits. Idle sessions retire without affecting healthy ones. Promotion/caller socket costs cannot bypass the declared resource policy.

**Checks after authorization:** `Q-TRANSPORT-CONFIG`; `Q-TRANSPORT-ADMISSION`; `Q-TRANSPORT-CALLER`; `NEW: fake-clock pool/idle/resource-policy tests`.

<a id="a05"></a>

### A05. Add the managed Tokio application facade

**Phase:** Application integration. **Prerequisites:** A04, S04. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/runtimes/tokio.rs:1](/home/dev/srt-rs/crates/srt-transport/src/runtimes/tokio.rs:1), [crates/srt-transport/Cargo.toml:32](/home/dev/srt-rs/crates/srt-transport/Cargo.toml:32).

**Implementation checkpoints:**

1. Expose ergonomic async connect/accept/send-message/receive-message/close methods backed by an explicit owner driver, one per shard.
2. Make startup/shutdown and driver task lifetime explicit. Bounded handles may send commands to the owner; never await one full peer queue in the shared demux loop.
3. Enable only Tokio features actually needed, such as sync/macros if used. Avoid a new futures dependency or hidden extra runtime just to provide a facade.
4. Keep the owner-driven integration available for applications that already run an executor/reactor.

**Acceptance:** A Tokio-only consumer builds with only the Tokio transport feature and uses no benchmark internals. Cancellation, receiver drop, driver failure and graceful close have documented outcomes; one slow consumer does not block another.

**Checks after authorization:** `Q-FEATURE-TOKIO`; `NEW: Tokio public facade integration tests`; `NEW: Tokio caller/listener examples compile/run`.

<a id="a06"></a>

### A06. Complete native runtime parity incrementally

**Phase:** Application integration. **Prerequisites:** A04, A05, S04, S05, F05. **Initial status:** TODO.

**Read first:** [crates/srt-transport/src/runtimes/smol.rs:1](/home/dev/srt-rs/crates/srt-transport/src/runtimes/smol.rs:1), [crates/srt-transport/src/runtimes/monoio.rs:1](/home/dev/srt-rs/crates/srt-transport/src/runtimes/monoio.rs:1), [crates/srt-transport/src/runtimes/glommio.rs:1](/home/dev/srt-rs/crates/srt-transport/src/runtimes/glommio.rs:1), [crates/srt-transport/src/runtimes/compio.rs:1](/home/dev/srt-rs/crates/srt-transport/src/runtimes/compio.rs:1).

**Implementation checkpoints:**

1. Reuse public behavioral contracts and tests, keeping native readiness/completion handling.
2. Finish one runtime at a time: isolated feature build, direct session, slow-consumer isolation, cancellation and shutdown. Include Mio and Tokio in the final matrix.
3. State any adapter that is experimental/unqualified explicitly; do not claim full runtime completion from all-features compilation.

**Acceptance:** Each runtime in the supported release matrix passes equivalent contract scenarios under its actual runtime. Unavailable kernel/runtime prerequisites remain explicit blockers for that matrix entry, not silent skips.

**Checks after authorization:** `Q-FEATURES`; `NEW: same contract scenario per native runtime`; `Q-TRANSPORT-CONCURRENCY`.

<a id="f01"></a>

### F01. Preserve source age through relay APIs

**Phase:** Live fan-out. **Prerequisites:** P03, A05. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-protocol/src/srt_connection.rs:1110](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1110), [crates/srt-protocol/src/srt_connection.rs:1376](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1376), [crates/srt-bench/src/source.rs:1](/home/dev/srt-rs/crates/srt-bench/src/source.rs:1).

**Implementation checkpoints:**

1. Define message metadata that preserves original source time/age separately from packet arrival, release and current service time. Reuse current timestamp-bearing events where possible.
2. Make clock-domain conversion explicit at ingress; ensure rollover handling remains protocol-correct.
3. Implement the relay example with preserved metadata, not timestamp=now at every forwarding hop.

**Acceptance:** Injected delays before and after publication increase observed age instead of resetting it. Monotonic conversion, timestamp wrap and multi-fragment messages retain correct semantics.

**Checks after authorization:** `Q-CONNECTION`; `Q-PROP-MESSAGE`; `NEW: delayed relay source-age regression`.

<a id="f02"></a>

### F02. Implement or reuse a bounded publication bus for shards

**Phase:** Live fan-out. **Prerequisites:** F01, A05. **Initial status:** TODO. **Current status:** DEFERRED (application-owned; transport reference removed).

**Read first:** [crates/srt-bench/src/queue.rs:1](/home/dev/srt-rs/crates/srt-bench/src/queue.rs:1), [crates/srt-bench/src/lib.rs:2598](/home/dev/srt-rs/crates/srt-bench/src/lib.rs:2598), [crates/srt-transport/src/handoff.rs:1](/home/dev/srt-rs/crates/srt-transport/src/handoff.rs:1).

**Implementation checkpoints:**

1. First inspect current/local branch source for an existing relay/broadcast implementation. Reuse it if its semantics fit; do not wholesale cherry-pick unrelated branch work.
2. Specify single publication of each source item, one logical cursor per subscribed shard, complete-message lag reporting, subscription lifetime and bounded item/byte/age retention.
3. A work-stealing SPMC queue is not broadcast. Each applicable shard must see each item. Per-destination acceptance cursors remain inside that shard; advancing a shard cursor must not discard a still-needed destination disposition.
4. Prefer a proven safe implementation. If only a locked reference implementation can be established, label it as a reference and leave any claimed lock-free target unqualified. Do not write unreviewed atomic-pointer reclamation.

**Current decision:** The former `srt-transport::PublicationBus` reference implementation was removed from the default transport surface because no runtime or benchmark consumer uses it. The eventual implementation belongs in the application/restream layer, where media type, expiry, destination placement and shard topology are known. Preserve this contract when that layer is implemented: one publication per transformed item, one cursor per applicable shard, explicit lag, bounded item/byte/age retention, and no claim of lock-free progress without an algorithm and reclamation review.

**Acceptance:** Multiple shards each observe their publications; stalled shard lag is explicit; producer progress and memory stay bounded; safe references outlive overwritten slots. Stress wrap, unsubscribe, resubscribe and source close.

**Checks after authorization:** `NEW: deterministic publication/cursor/lag tests`; `NEW: concurrency model/stress checks appropriate to the actual implementation`; `REVIEW: ownership, publication linearization and memory reclamation`.

<a id="f03"></a>

### F03. Implement destination isolation and live expiry policy

**Phase:** Live fan-out. **Prerequisites:** F02, P02. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-transport/src/caller.rs:1](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:1), [crates/srt-protocol/src/srt_sender.rs:1](/home/dev/srt-rs/crates/srt-protocol/src/srt_sender.rs:1), [crates/srt-bench/src/scheduling.rs:1](/home/dev/srt-rs/crates/srt-bench/src/scheduling.rs:1).

**Implementation checkpoints:**

1. Keep protocol state, pending acceptance and pacing per destination inside its owner shard.
2. Bound destination/shard application retention by bytes, items and age. On expiry, drop complete unadmitted messages or disconnect according to explicit application policy.
3. Treat accepted SRT packets separately: use protocol-correct late-drop/retirement handling, never overwrite ARQ slots without bookkeeping.
4. Bound both normal service and recovery bursts. No shared owner awaits one destination's queue capacity.

**Acceptance:** One stalled destination, one stalled shard and overload followed by recovery all preserve healthy-peer progress and memory bounds. No partial messages or duplicate admission. Drops/disconnects/gaps are reported at the correct logical destination.

**Checks after authorization:** `NEW: source->publication->shards->destinations deterministic isolation tests`; `Q-GROUP`; `Q-TRANSPORT-CALLER`; `Q-PROP-MESSAGE`.

<a id="f04"></a>

### F04. Measure shard service, lateness and resource use

**Phase:** Live fan-out. **Prerequisites:** F03. **Initial status:** TODO. **Current status:** VERIFIED in source and deterministic tests; instrumentation-overhead perf window remains open.

**Read first:** [crates/srt-transport/src/telemetry.rs:1](/home/dev/srt-rs/crates/srt-transport/src/telemetry.rs:1), [crates/srt-transport/src/batch.rs:118](/home/dev/srt-rs/crates/srt-transport/src/batch.rs:118), [crates/srt-bench/src/scheduling.rs:1](/home/dev/srt-rs/crates/srt-bench/src/scheduling.rs:1), [crates/srt-protocol/src/stats.rs:1](/home/dev/srt-rs/crates/srt-protocol/src/stats.rs:1).

**Implementation checkpoints:**

1. Extend existing reports/snapshots with intended deadline, observed service time, lateness, work/budget exhaustion, queue bytes/age and overload reasons.
2. Use owner-local counters and bounded histograms. Export periodic snapshots; do not add global per-packet atomics or unbounded StreamID labels.
3. Keep shard sizing/admission thresholds, placement, exporters and alert policy in the application. Count unique backing allocations separately from reference handles and per-destination crypto/ARQ storage.

**Acceptance:** Fake-clock tests put known lateness into expected buckets. Counters reconcile accepted/rejected/expired/failed outcomes without double-counting. Collection has bounded storage and measured overhead.

**Checks after authorization:** `NEW: deterministic telemetry reconciliation tests`; `Q-TRANSPORT-CALLER`; `PERF WINDOW: instrumentation enabled/disabled overhead`.

<a id="f05"></a>

### F05. Close the complete application path predictably

**Phase:** Live fan-out. **Prerequisites:** F03, A05. **Initial status:** TODO. **Current status:** VERIFIED by the existing managed-facade shutdown/reclamation and group-failure tests; a dedicated close-with-pending-send public test remains useful follow-up coverage.

**Read first:** [crates/srt-protocol/src/srt_connection.rs:1407](/home/dev/srt-rs/crates/srt-protocol/src/srt_connection.rs:1407), [crates/srt-transport/src/caller.rs:946](/home/dev/srt-rs/crates/srt-transport/src/caller.rs:946), [crates/srt-bench/src/shutdown.rs:1](/home/dev/srt-rs/crates/srt-bench/src/shutdown.rs:1).

**Implementation checkpoints:**

1. Stop new admission/publication, process or deliberately expire pending application work, request protocol close and drain up to an application-selected deadline.
2. Resolve/cancel owned I/O by S05's contract, release tasks/handles/sockets and emit final statistics.
3. Keep failover/close/consumer-drop races explicit. Do not copy benchmark process termination as the library's shutdown implementation.

**Acceptance:** Clean close, close with pending sends, lost shutdown response, caller cancellation, destination removal and group-leg loss terminate within the selected policy and release all owned resources. Final outcomes account for accepted work.

**Checks after authorization:** `Q-CONNECTION`; `Q-GROUP`; `Q-TRANSPORT-CALLER`; `NEW: public API shutdown/resource lifetime tests`.

<a id="v00"></a>

### V00. Freeze the workload and qualification contract

**Phase:** Qualification. **Prerequisites:** E02, E03, B02. **Initial status:** TODO. **Current status:** BLOCKED (qualification inputs).

**Read first:** [docs/bench-capacity-frontier.md:1](/home/dev/srt-rs/docs/bench-capacity-frontier.md:1), [docs/performance-loop.md:62](/home/dev/srt-rs/docs/performance-loop.md:62), [docs/plans/ci-sentinels/admission-scale.plan:1](/home/dev/srt-rs/docs/plans/ci-sentinels/admission-scale.plan:1), [docs/plans/ci-sentinels/datapath-load.plan:1](/home/dev/srt-rs/docs/plans/ci-sentinels/datapath-load.plan:1).

**Implementation checkpoints:**

1. Fill the workload table in section 10 from actual application requirements and existing benchmark plans. Distinguish one source with 600 egresses from 600 independent sources.
2. Name supported runtime/platform/topology/encryption/group combinations, host resources and validation limits.
3. Specify delivery, lateness, memory, recovery and instrumentation-overhead thresholds before comparing implementations. If deployment values are missing, ask once with the minimum bundled fields and continue independent correctness work.

**Acceptance:** An explicit, versioned workload/threshold record exists. Illustrative or CI-smoke values are not relabeled as production requirements. Missing performance prerequisites keep performance qualification pending.

**Checks after authorization:** `REVIEW: workload/threshold completeness and feasibility calculations`.

<a id="v01"></a>

### V01. Extend deterministic network and lifecycle simulation

**Phase:** Qualification. **Prerequisites:** S06, P03, P02, A01. **Initial status:** TODO. **Current status:** VERIFIED (Opus-reviewed, amended).

**Read first:** [crates/srt-protocol/tests/test_srt_connection.rs:1](/home/dev/srt-rs/crates/srt-protocol/tests/test_srt_connection.rs:1), [crates/srt-protocol/pbt/tests/prop_connection.rs:1](/home/dev/srt-rs/crates/srt-protocol/pbt/tests/prop_connection.rs:1), [crates/srt-protocol/pbt/tests/prop_group.rs:1](/home/dev/srt-rs/crates/srt-protocol/pbt/tests/prop_group.rs:1), [crates/srt-protocol/fuzz/fuzz_targets/fuzz_connection_feed.rs:1](/home/dev/srt-rs/crates/srt-protocol/fuzz/fuzz_targets/fuzz_connection_feed.rs:1).

**Implementation checkpoints:**

1. Reuse existing test harnesses and injected timestamps. Add a minimal event queue only if current helpers cannot express delay/loss/service stalls.
2. Exercise caller/listener handshake, accepted messages, loss/reorder/duplication, delayed timers, key rotation, time/sequence wrap, close and group failure.
3. Retain historical failing seeds/minimized traces. Check invariants and content/sequence outcomes, not merely no panic.
4. Keep the simulator independent of real sleeping and runtime scheduling; test native I/O separately.

**Acceptance:** Every known correctness defect has a reproducible regression. Stateful scenarios make real connected progress before mutation/failure injection. Stored seeds reproduce failures and pass after repair.

**Checks after authorization:** `Q-CORE`; `Q-CONNECTION`; `Q-CRYPTO`; `Q-GROUP`; `Q-PROP-CONNECTION`; `Q-PROP-MESSAGE`; `Q-PROP-SENDER`; `Q-PROP-CRYPTO`; `Q-PROP-GROUP`.

<a id="v02"></a>

### V02. Qualify native runtime features, interop and fuzz execution

**Phase:** Qualification. **Prerequisites:** V01, A06, A02, S06. **Initial status:** TODO. **Current status:** VERIFIED (local gates; native sentinel unavailable).

**Read first:** [.github/workflows/ci.yml:47](/home/dev/srt-rs/.github/workflows/ci.yml:47), [crates/srt-bench/tests/libsrt_interop.rs:1](/home/dev/srt-rs/crates/srt-bench/tests/libsrt_interop.rs:1), [crates/srt-protocol/fuzz/Cargo.toml:1](/home/dev/srt-rs/crates/srt-protocol/fuzz/Cargo.toml:1), [docs/dependency-exceptions.md:1](/home/dev/srt-rs/docs/dependency-exceptions.md:1).

**Implementation checkpoints:**

1. Build/check every supported runtime feature separately; test each relevant native contract, including cancellation, truncation, boundedness and shutdown.
2. Record libsrt/tool versions and required cases actually executed. Developer-friendly skip behavior may remain, but required release qualification must fail if prerequisites or cases are missing.
3. Run relevant existing fuzz targets with bounded time and preserve useful corpora. A successful informational fuzz-build step is not proof of successful fuzz compilation or execution.
4. Revalidate documented dependency exceptions against the current pinned graph and authoritative advisories. Do not extend exceptions to claim a clean production surface.

**Acceptance:** The feature/interop/fuzz matrix records pass/fail/executed/skipped and environment details. Required skips are blockers. Protocol MSRV and transport MSRV remain independently checked.

**Checks after authorization:** `Q-FEATURES`; `Q-MSRV`; `Q-INTEROP`; `Q-BONDED`; `Q-COMPIO-QUEUE`; `Q-FUZZ`.

<a id="v03"></a>

### V03. Run bounded-resource soak and steady-state qualification

**Phase:** Qualification. **Prerequisites:** V00, V02, F04, F05, D02. **Initial status:** TODO. **Current status:** BLOCKED (qualification inputs).

**Read first:** [docs/performance-loop.md:1](/home/dev/srt-rs/docs/performance-loop.md:1), [docs/bench-queue-inventory.md:1](/home/dev/srt-rs/docs/bench-queue-inventory.md:1), [docs/cpu-budget.md:1](/home/dev/srt-rs/docs/cpu-budget.md:1), [crates/srt-bench/src/harness.rs:1](/home/dev/srt-rs/crates/srt-bench/src/harness.rs:1).

**Implementation checkpoints:**

1. Use the frozen workload and valid paired results. Separate ramp-up, steady state, impairment/recovery and shutdown.
2. Measure useful delivered source bytes, per-shard lateness/queue age, CPU/service cost, unique retained memory, RSS, descriptors, retransmission and drop reasons.
3. Include stalled destination, stalled shard, burst input, loss/reorder, group failover and overload removal. Exercise long lifetime and use virtual-time tests for impractically slow wrap boundaries.
4. Compare a saved baseline and candidate under the same compiler/flags/host/workload. Retain correctness fixes regardless of speed; accept optional performance changes only with justified evidence.

**Acceptance:** All frozen correctness/resource/SLO limits pass, including recovery and tail service behavior. Report uncertainty, repetitions, exclusions and skips. Unavailable dedicated host or missing SLO leaves this card pending; never extrapolate from loopback to external-network production capacity.

**Checks after authorization:** `PERF WINDOW ONLY: selected existing plans plus actual one-source relay workload`; `PERF WINDOW ONLY: focused before/after measurements`; `REVIEW: all terms in memory/service accounting reconciled`.

<a id="d03"></a>

### D03. Finish build, API, support and release documentation

**Phase:** Delivery. **Prerequisites:** D01, A06, V02. **Initial status:** TODO.

**Read first:** [.cargo/config.toml:9](/home/dev/srt-rs/.cargo/config.toml:9), [README.md:249](/home/dev/srt-rs/README.md:249), [crates/srt-transport/README.md:194](/home/dev/srt-rs/crates/srt-transport/README.md:194), [.github/workflows/release.yml:24](/home/dev/srt-rs/.github/workflows/release.yml:24), [crates/srt-transport/Cargo.toml:1](/home/dev/srt-rs/crates/srt-transport/Cargo.toml:1), [crates/srt-lifecycle/Cargo.toml:1](/home/dev/srt-rs/crates/srt-lifecycle/Cargo.toml:1).

**Implementation checkpoints:**

1. Document actual native toolchain requirements for workspace/runtime builds, keeping the pure protocol claim accurately scoped.
2. Provide a normal supported consumer build and explicit benchmark flags. Preserve historical benchmark metadata; do not silently compare changed CPU/link/profile settings.
3. Document public API, config defaults/effective values, ownership, cancellation, backpressure, payload sizing, secrets, unsupported cases and shutdown.
4. Compile public examples under their selected features. Prepare package/MSRV/dependency/release checks for the intended surface; do not publish or change maintainer identity/attribution.

**Acceptance:** A fresh consumer can follow docs without importing benchmark internals. Every supported feature/path has accurate status. Release candidates are reviewable and no external publication occurred.

**Checks after authorization:** `Q-DOCS`; `Q-FEATURES`; `Q-MSRV`; `Q-PACKAGE`; `REVIEW: examples/support matrix/API compatibility`.

<a id="z01"></a>

### Z01. Perform final qualification review and delivery handoff

**Phase:** Delivery. **Prerequisites:** E01, E02, E03, E04, E05, B02, D02, D03, S06, F05, V03. **Initial status:** TODO.

**Read first:** [.github/workflows/ci.yml:33](/home/dev/srt-rs/.github/workflows/ci.yml:33), [SECURITY.md:74](/home/dev/srt-rs/SECURITY.md:74), [docs/performance-loop.md:1](/home/dev/srt-rs/docs/performance-loop.md:1).

**Implementation checkpoints:**

1. Review the complete diff against invariants I1-I8 and the coverage crosswalk. Re-run only tests affected by later edits, then the required broader final gates once.
2. Verify each required card's evidence names current source/commands/results and every required matrix entry actually executed.
3. Prepare a concise delivery report: changed behavior, compatibility/migration, executed validation, operating envelope, residual limitations and deployment/release steps requiring separate authorization.
4. If goal tooling exists, follow its actual status rules. Do not mark the goal complete because tokens/time are low or because only documentation remains easy.

**Acceptance:** All required cards are VERIFIED/ALREADY_FIXED or legitimately DISPROVED with updated dependencies. Required product behavior, tests and workload qualification are not deferred. No unsupported invincibility/optimality/lock-free or cross-platform claims. No commit/push/publish/deploy unless separately authorized.

**Checks after authorization:** `Q-FINAL`; `REVIEW: current source and every required acceptance matrix entry`.

## 9. Validation command catalogue

**Every Cargo, compiler, formatter, linter, test, fuzz, example, profiler and benchmark command below is forbidden on the protected benchmark host until its execution is authorized.** A narrow test can still compile the entire benchmark runtime dependency tree.

Commands are existing package/target names unless explicitly marked NEW. Run from the authorized implementation checkout. Prefer `--locked` after intentional manifest/lockfile changes are resolved. Do not run a broad dependency update to make a focused change compile.

A command filter can legitimately match zero tests. Read its reported executed count; zero is not validation. If a target/module moves, locate it in current source and update the ledger rather than inventing a successful command.

| Check ID | Command / meaning |
|---|---|
| Q-CORE | `cargo test -p srt-proto --lib srt_connection::tests` |
| Q-CONNECTION | `cargo test -p srt-proto --test test_srt_connection` |
| Q-CRYPTO-UNIT | `cargo test -p srt-proto --lib crypto::tests` — after E05 removes the timing assertion |
| Q-CRYPTO | `cargo test -p srt-proto --test test_crypto` |
| Q-GROUP | `cargo test -p srt-proto --test test_srt_group` |
| Q-BOUNDS | `cargo test -p srt-proto --test packet_window_boundary_validation` |
| Q-ALLOC | `cargo test -p srt-proto --test allocation_guard`; extend only where it measures the changed path |
| Q-PROP-CONNECTION | `cargo test -p pbt --test prop_connection` |
| Q-PROP-MESSAGE | `cargo test -p pbt --test prop_message` |
| Q-PROP-SENDER | `cargo test -p pbt --test prop_sender` |
| Q-PROP-CRYPTO | `cargo test -p pbt --test prop_crypto` |
| Q-PROP-GROUP | `cargo test -p pbt --test prop_group` |
| Q-TRANSPORT-BATCH | `cargo test -p srt-transport --lib batch::tests` |
| Q-TRANSPORT-CONFIG | `cargo test -p srt-transport --lib config::tests` |
| Q-TRANSPORT-CALLER | `cargo test -p srt-transport --lib caller::tests` |
| Q-TRANSPORT-ADMISSION | `cargo test -p srt-transport --lib admission::tests` |
| Q-TRANSPORT-GROUP | `cargo test -p srt-transport --all-features --lib group_conn_tests` |
| Q-TRANSPORT-CONCURRENCY | `cargo test -p srt-transport --test concurrency_contract` |
| Q-WAITER | `cargo test -p srt-transport --test high_res_waiter` — live Linux timers/sockets |
| Q-REUSEPORT | `cargo test -p srt-transport --test reuseport_rehash` — live Linux socket behavior |
| Q-BENCH-CLEAN | `cargo test -p srt-bench --test check_clean_exit_status` |
| Q-BENCH-MATRIX | `cargo test -p srt-bench --test matrix_exit_status` |
| Q-BENCH-SOURCE | `cargo test -p srt-bench --test source_bandwidth_semantics` |
| Q-BENCH-HARNESS | `cargo test -p srt-bench --lib harness::` |
| Q-BENCH-COMPARE | `cargo test -p srt-bench --lib compare::` |
| Q-BENCH-MIO | `cargo test -p srt-bench --lib runtimes::mio::` — add the card's regression in that module if no matching coverage exists |
| Q-BENCH-SRT600 | `cargo test -p srt-bench --lib qualification::`; generate the corpus with `cargo run -p srt-bench -- qualify plan` and score paired output with `qualify score BASE.tsv HEAD.tsv` |
| Q-XTASK | `cargo test -p xtask` — add narrow parser/output regressions in existing modules where needed |
| Q-FEATURE-TOKIO | `cargo check -p srt-transport --no-default-features --features tokio` |
| Q-FEATURES | Run `cargo check -p srt-transport --no-default-features`, then the same command with one `--features` value at a time: `mio`, `tokio`, `smol`, `monoio`, `glommio`, `compio`; run matching native tests after each affected implementation |
| Q-DOCS | `cargo xtask doc`; also compile each new example under its documented feature. Inspect current xtask scope first. |
| Q-MSRV | Existing protocol check: `cargo +1.93.0 check -p srt-proto --all-targets --locked`; separately qualify transport on its declared 1.96 toolchain. Installing toolchains is not a read-only action. |
| Q-INTEROP | `cargo test -p srt-bench --test libsrt_interop -- --nocapture` — external libsrt prerequisites and actual executed cases required |
| Q-BONDED | `cargo test -p srt-bench --test bonded_smoke` — live I/O |
| Q-COMPIO-QUEUE | `cargo test -p srt-bench --test datapath_queue_bounds -- --ignored --nocapture` — explicit Linux/io_uring live sentinel |
| Q-FUZZ | In `crates/srt-protocol/fuzz`: `cargo +nightly fuzz build`, then the relevant existing target, e.g. `cargo +nightly fuzz run fuzz_connection_feed -- -max_total_time=60 -timeout=5 -dict=fuzz.dict`. Record actual completion and corpus/seed; choose targets from the current manifest. |
| Q-PACKAGE | `cargo xtask package` after checking its current scope; this is packaging/dry-run validation, never permission to publish |
| Q-FINAL | `cargo xtask ci` once the focused gates pass; inspect current implementation and run required separate interop/fuzz/MSRV/runtime qualification too |

Command cautions:

- Protocol directory `srt-protocol` is package **`srt-proto`** (library crate `srt_proto`).
- The workspace toolchain is 1.96.0; protocol declares 1.93. Transport declares 1.96.
- `srt-bench` enables all runtime dependencies even when the test filter is narrow.
- Avoid routine `cargo test --all-targets`: Criterion targets use `harness = false` and can execute benchmark binaries. `cargo check --all-targets` compiles rather than runs, but still consumes resources.
- Fix E05 before relying on broad protocol unit tests as a stable correctness gate.
- Interop tests may skip unavailable tools/features. Record expected and actual case execution; release qualification must not silently skip required coverage.
- The reviewed xtask CI command includes an informational fuzz-build step. An overall success is not evidence that informational work passed.
- Preserve benchmark flag semantics: setting `RUSTFLAGS` replaces the configured list. Record target CPU, linker, profile, compiler and relevant environment. Do not solve a build issue by silently changing the measured baseline.
- Run targeted checks once after the relevant change. Broaden or repeat when dependencies changed, a failure appears or final qualification requires it.

## 10. Workload and mathematical acceptance contract

Fill this table before performance qualification. Values are product inputs, not facts an agent should invent.

| Input | Required record |
|---|---|
| Source topology | One source fan-out, independent sources, or mixed; destinations per source |
| Destination target | Start with the user's 600-destination target; record connection/group-leg distinction |
| Source rate | Payload bits/second per source, average and maximum burst |
| Message shape | Typical/max bytes, fragmentation, application timestamp meaning |
| Encryption | Plain/CTR/GCM, key size, rotation requirement |
| Bonding | None/Broadcast/Backup; physical legs versus logical destinations |
| Network envelope | RTT, jitter, loss, reorder, MTU/address family, NIC/link budget |
| Delivery policy | Lossless bounded backpressure or live expiry/disconnect behavior; tolerated intentional drops |
| Latency contract | Source-age deadline, service-lateness threshold, percentile and maximum criteria |
| Resource limits | Per-shard/connection queue bytes/items, retention age, total memory, descriptors, socket budgets |
| Host envelope | CPU/core allocation, runtime, kernel, NIC, affinity policy and allowed validation host |
| Failure/recovery | Slow destination/shard duration, overload duration, failover and shutdown deadlines |
| Evidence | Warmup/steady/recovery windows, repetitions, soak duration, noise/overhead acceptance |

### 10.1 Work cannot disappear through sharding

For a common payload of L bytes at source payload rate r bits/s:

```text
source packets per second p ≈ r / (8 L)
ordinary unicast data transmissions per second ≈ N p
```

This excludes retransmissions, control traffic, fragmentation differences and extra active bonded legs. Publishing once saves distribution overhead; it does not eliminate N protocol/wire sends.

Illustration only: at 1 Mbit/s and 1316-byte packets, p is about 95 packets/s; 600 destinations require about 57,000 ordinary data transmissions/s before overhead. This is arithmetic, not a measured capacity claim or the user's production bitrate.

### 10.2 Service budget and slack

For each shard s and interval T, define:
- C_s(T): processing time required by arrivals, due timers, output and recovery work;
- J_s(T): time unavailable due to scheduling/interference;
- R_s(T): reserved margin for supported bursts and variability.

A useful admission requirement is:

```text
C_s(T) + J_s(T) + R_s(T) <= T
slack_s(T) = T - C_s(T) - J_s(T)
lateness(event) = max(0, service_start - intended_deadline)
```

Evaluate relevant short service windows as well as long averages. This is an operating-envelope check, not a sufficient proof of all real-time deadlines. Do not add independently measured p99 components and call the sum a p99 guarantee; measure combined service behavior or use justified deterministic bounds.

Model destinations using observed work (packet rate, encryption, loss and active legs), not a universal fixed destinations-per-worker number. Load balancing should not migrate hot connections without an ownership-transfer design and evidence.

### 10.3 Queue conservation and age

For each queue, maintain:

```text
occupancy_next = occupancy + admitted - consumed - expired - explicitly_failed
0 <= occupancy <= configured_capacity
```

Use consistent units for packet, message and byte counters. For sustained arrivals exceeding service, a finite queue necessarily reaches a limit: the system must reject, backpressure, expire or disconnect according to policy. No buffer size removes that requirement.

Q/p is approximately the source-time span retained by Q fixed-size packets from a steady source. It is not a general delivery-delay guarantee; service stalls and bursts change waiting time. Measure oldest-item age directly.

### 10.4 Memory accounting

```text
M_total =
    M_publication_backings
  + sum(M_worker_scratch)
  + sum(M_connection_ARQ + M_application_retention + M_metadata)
  + M_socket_resources
  + M_runtime_overhead
```

Count shared backing allocations once, handles separately where material, and per-destination ciphertext separately. Overwriting ring slots does not free backing storage while another owner retains it. Socket buffer requests, kernel-effective settings, allocated capacity and observed RSS are different quantities.

### 10.5 Lock-free claims

Single-owner mutable connection state avoids sharing that state; it does not make all kernel/runtime/refcount behavior lock-free. A broadcast bus may share immutable payloads and publication/cursor metadata. State exactly which component and progress property is established.

For a lock-free bus claim, review publication ordering, overwrite/reclamation safety, stalled-reader behavior, ABA/wrap handling and bounded memory. A mutex-free source listing or a stress test alone is insufficient. If that claim cannot be established, report the narrower implemented contract and retain the missing target in qualification status.

## 11. Final acceptance matrix

Every row must name the actual feature combination, test/result artifact, source SHA and outcome.

| Requirement | Minimum evidence |
|---|---|
| Admission | Owned/shared/sequence/fragmented/group variants obey I1, including post-admission failures |
| Output ownership | Cancellation before/during/after submission; known accepted prefix, retained unsent suffix, timer ordering |
| Datagram integrity | Truncation, size limits, address-family behavior and malformed sibling isolation |
| Bounded service | Nonmultiple receive budgets, output allowance, all-due timers, retransmission burst, quiet-peer fairness |
| Configuration | Every advertised knob has effective behavior or explicit external owner; invalid combinations reject early |
| Lifecycle | Production-only consumer gets correct direct/group state; stale handles, removal and close tested |
| Crypto | Deterministic vectors/rotation/negotiation pass; relevant cached state erasure features explicit |
| Application API | Caller/listener/relay examples work through supported public API without benchmark internals |
| Fan-out | Actual one-source distribution, shard cursors, slow destination/shard, age limits, recovery and message integrity |
| Resource stability | Queue/backing-memory/descriptors/tasks remain within declared limits through churn and soak |
| Runtime parity | Separate features and actual native execution; required kernel/runtime cases not skipped |
| Interop | Required libsrt cases execute in both directions for declared features |
| Measurement | Invalid input cannot pass; complete attempt pairing; child failures and partial campaigns explicit |
| Performance | Frozen workload's delivery/lateness/resource/recovery limits pass with stated uncertainty |
| Documentation/release | Supported surfaces, MSRV, examples, dependency policy, migration and package checks agree with source |

A failed required row prevents a complete production-readiness claim. A missing validation environment is a pending qualification, not an implementation success.

## 12. Cleanup and defect coverage crosswalk

The prior audit labels are retained here so no finding disappears during execution.

| Audit item | Meaning | Cards |
|---|---|---|
| C1 | Hard-coded optimality claims | E04 |
| C2 | Duplicate attempt/metric aggregation | E02 |
| C3 | Always-true capability check | D01, K02 |
| C4 | Competing canonical config paths | K01 |
| C5 | Inert/externally carried knobs | K02, A04 |
| C6 | Benchmark lifecycle in library | A01 |
| C7 | Unused tick convenience loops | D01, A03 |
| C8 | Duplicated acceptance policy | S02, S03 |
| C9 | Per-visit scratch collections | D02 |
| C10 | Eager 2 MiB group scratch | D02, T01 |
| C11 | Timed crypto unit assertion | E05 |
| C12 | Stale timer/ownership docs | D01 |
| C13 | Stale core allocation/crypto docs | D01 |
| C14 | Build/toolchain claims and benchmark defaults | D03 |
| C15 | Nonfinite/missing evidence passes | E01 |
| C16 | Worker panic hidden as empty output | E03 |
| C17 | Non-timeout failures swallowed | E03 |
| C18 | Missing analyzer metrics become zero | E01 |
| C19 | Ignored fallible session setters | K02 |
| R1 | Accepted payload reported rejected | S02, S03 |
| R2 | Shared explicit sequence silently rejected | S01 |
| R3 | Async cancellation loses output | S04, S05 |
| R4 | Datagram truncation ignored | T01 |
| R5 | One group leg stops later service | T04 |
| R6 | Wrong mixed-peer minimum deadline | T05 |
| R7 | Receive cap overshoot | T02 |
| R8 | Drained status with pending output | T03 |
| R9 | Unbounded protocol/timer generation | P01, P02 |
| R10 | Auto ownership validation bypass | K01 |
| R11 | Capabilities/budgets disconnected from driver | K02 |
| R12 | Cached crypto zeroization not guaranteed | S06 |
| R13 | Payload/MSS contract incomplete | P03 |
| R14 | Production/benchmark lifecycle differs | A01 |
| R15 | IPv6 construction/batch mismatch | A02 |
| Additional benchmark defects | 4096 ceiling, unbounded receive, quiet timer starvation | B01, B02 |
| Additional acceptance correction | Core mutation precedes fallible encryption, including message prefixes | S02 |
| Additional cancellation correction | Blind requeue can duplicate submitted owned I/O | S05 |

## 13. Resume ledger and per-card evidence

Use one small Markdown ledger, not a new tracking application. Suggested location after implementation authorization: `docs/production-progress.md` inside the implementation worktree; if writing there is not authorized, keep an external artifact/conversation checkpoint. Do not write it into the protected checkout by accident.

```markdown
# Production progress
Guide version: 2026-09-13 / audit `6397f6a` (working tree hardening follows)
Working repository:
Working branch / HEAD:
Protected checkout:
Implementation authorization:
Validation host and authorization:
Allowed resource/time limits:
Workload contract:
Current card:
Next dependency-ready card:
Required blockers:
Last passed broad gate and source:
Unrelated changes to preserve:

| Card | Status | Current source/diff | Regression/evidence | Remaining |
|---|---|---|---|---|

## Current checkpoint
- Observed trigger and contract:
- Exact files/symbols/callers:
- Smallest edit:
- Checks executed, counts, skips and outcomes:
- Checks not executed and why:
- Next concrete action:
```

Before context compaction or ending an unfinished turn, update this checkpoint. On resume, read it, inspect current Git state and touched files, and continue the next action. Do not rebuild the entire plan or rerun completed checks absent a relevant change.

Per-card closeout:
1. User-visible behavior changed.
2. Exact source locations and compatibility impact.
3. Regression scenario and actual command output summary.
4. Any measured performance/resource result with workload and uncertainty.
5. Remaining required work; next card.

After two unsuccessful local attempts at the same nontrivial design, collect a minimal failing trace and request a focused review rather than repeatedly expanding the patch. Continue independent ready cards. Do not use this rule to abandon routine debugging or to mark a required card complete.

## 14. Optional performance experiments after correctness

These are hypotheses, not promised improvements or required features. Reuse existing benchmarks and keep only measured wins under the frozen operating envelope.

- Reuse scratch/capacity in the actual hot path.
- Reduce refcount churn while preserving publication lifetime.
- Compare retained ciphertext with re-encryption under key rotation and GCM semantics.
- Tune packet/message batching against lateness rather than throughput alone.
- Compare deadline indexing/ready queues using actual due density.
- Tune shard placement/NUMA locality using application deployment controls.
- Compare payload layout and cache behavior only after attribution identifies them.
- Evaluate PGO or additional ISA tuning with explicit build provenance.
- Consider GSO/GRO, registered buffers, io_uring batching or zero-copy only when syscall/copy cost is measured and cancellation/lifetime complexity is justified.

Do not reopen the decision to replace the stack or add every runtime/strategy Cartesian combination to each inner loop.

## 15. Sources and interpretation

Source links on each card refer to current local files at the audited snapshot; line numbers are navigation hints and must be refreshed on newer source. The strongest evidence is the implementation and its executed regression on the implementation branch.

Existing project guides to reuse:
- [Transport API and configuration](/home/dev/srt-rs/crates/srt-transport/README.md)
- [Admission policy](/home/dev/srt-rs/docs/listener-admission-policy.md)
- [Performance loop](/home/dev/srt-rs/docs/performance-loop.md)
- [Queue inventory](/home/dev/srt-rs/docs/bench-queue-inventory.md)
- [Security policy](/home/dev/srt-rs/SECURITY.md)
- [Vendor provenance](/home/dev/srt-rs/crates/srt-protocol/VENDOR.md)
- [Dependency exception policy](/home/dev/srt-rs/docs/dependency-exceptions.md)

Prompt structure follows the general practice of supplying concrete scope, reproduction and verification, as described in [OpenAI's Codex prompting documentation](https://learn.chatgpt.com/docs/prompting). The short launcher plus per-card context also follows [OpenAI's prompting guidance](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-5.6) on stating constraints once and defining autonomy boundaries. These sources support the handoff structure; they do not establish that Luna can guarantee completion or prove SRT correctness.
