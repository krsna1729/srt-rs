# Production progress
Guide version: 2026-09-10 / audit 860fc5180219629dca833511fb3075b3aa83d8ce
Working repository: /home/dev/srt-rs
Working branch / HEAD: codex/b00-baseline / 8f38c1f (see git log for ledger commit)
Protected checkout: none — host idle at setup (only codegraph MCP server running); prior benchmark protection lifted by user authorization below
Implementation authorization: user 2026-09-10 — "cleanup local. get latest origin/main. take a look at prompt and production guide md files placed. achieve it with a proper commits and PR strategy."
Validation host and authorization: same host authorized for implementation AND validation (no benchmark process observed at setup); perf-window work still needs explicit per-run confirmation
Allowed resource/time limits: host envelope to be recorded under V00; default to focused checks, no broad suites per edit
Workload contract: PENDING (V00) — 600-destination target dimension; source rate, message shape, encryption, bonding, latency/resource limits all unfilled
Current card: B00 (IN_PROGRESS) — baseline and execution boundary
Next dependency-ready card: E05 (timing-free crypto tests) alongside E01/E04/T01/T03/T05/K01/B01 — all B00-gated and mutually independent
Required blockers: none for evidence/correctness waves; V00 needs user workload fields; S05 may need runtime-implementation review; V02/V03 need interop/fuzz hosts and frozen workload
Last passed broad gate and source: none on this branch yet; origin/main tip 8f38c1f merged via Q-FINAL in PR #93
Unrelated changes to preserve:
- `gpt-6-astra-light.md` (untracked, 300 KB, unrelated per guide §2) — never commit/stash/overwrite
- `srt-rs-agent-prompt.md`, `srt-rs-production-guide.md` (untracked handoff specs) — working copies only, not for main history
- `feat/srt-bench-relay-use-cases` (129 commits ahead of origin/main, base 63d617e) — active relay experiment, relevant to F02; do not delete; reuse selectively, no wholesale cherry-pick
- stashes `pr90-executor` and `contabo-wip-before-pr86` (2026-09-06) — pre-merge WIP, kept as-is pending per-card inspection
- deleted as superseded (squash-merged, remote branches gone): contabo-pr86-a2, pr-90-ack-coalesce, feat/config-canonical-knobs; prunable worktree /tmp/srt-audit-20260907 removed; local main fast-forwarded 0797e06 → 8f38c1f

| Card | Status | Current source/diff | Regression/evidence | Remaining |
|---|---|---|---|---|
| B00 | IN_PROGRESS | this ledger only | READ: status/rev-parse/diff-stat on 8f38c1f | commit ledger, select E05+E01 first |
| E01 | TODO | harness.rs:343, compare.rs:248, reportcard.rs:221 | needs Q-BENCH-CLEAN/HARNESS/COMPARE, Q-XTASK | invalid-evidence regressions |
| E02 | TODO | harness.rs:862, compare.rs:352 (needs E01) | needs Q-BENCH-* | attempt-aware pairing |
| E03 | TODO | bench lib.rs:2627, bench workflows (needs E01) | needs Q-BENCH-MATRIX/CLEAN/HARNESS | failure preservation |
| E04 | TODO | xtask audit.rs:211 | needs Q-XTASK + output review | honest codegen inventory |
| E05 | TODO | protocol crypto.rs:1414 | needs Q-CRYPTO-UNIT/CRYPTO, Q-CORE | move timing assert to bench |
| S01 | TODO | needs E05 | needs Q-CORE/CONNECTION/GROUP | explicit-sequence parity |
| S02 | TODO | needs S01 | needs Q-CORE/CONNECTION/PROP-MESSAGE/PROP-SENDER/GROUP | admission linearization |
| S03 | TODO | needs S02 | needs Q-TRANSPORT-BATCH/CALLER, Q-FEATURES, Q-BENCH-SOURCE | adapter admission vs progress |
| S04 | TODO | needs S03 | needs Q-TRANSPORT-BATCH, Q-FEATURES + NEW cancel regression | readiness-output retention |
| S05 | TODO | needs S03 | needs Q-FEATURES + NEW per-runtime ownership test | completion-runtime ownership |
| T01 | TODO | socket_io.rs:159,281, batch.rs:23 | needs Q-TRANSPORT-BATCH + NEW truncation regression | truncation detection |
| T02 | TODO | needs T01 | needs Q-TRANSPORT-BATCH, Q-FEATURES, Q-WAITER | receive budgets/continuation |
| T03 | TODO | caller.rs:876,1150,1197 | needs Q-TRANSPORT-CALLER/BATCH | output exhaustion reporting |
| T04 | TODO | needs T01, T03 | needs Q-GROUP, Q-TRANSPORT-GROUP, Q-PROP-GROUP | group-leg isolation |
| T05 | TODO | admission.rs:1968 | needs Q-TRANSPORT-ADMISSION | earliest deadline |
| P01 | TODO | needs S02, T03 | needs Q-CORE/PROP-SENDER/BOUNDS/CONNECTION | bounded retransmission |
| P02 | TODO | needs P01, T02, T05 | needs Q-TRANSPORT-CALLER/ADMISSION, Q-WAITER | bounded due-session service |
| K01 | TODO | config.rs (canonical resolver; #93 landed 8f38c1f — revalidate) | needs Q-TRANSPORT-CONFIG, Q-BENCH-SOURCE, Q-REUSEPORT | confirm Auto/Shared table |
| K02 | TODO | needs K01, T02, T03 | needs Q-TRANSPORT-CONFIG, Q-FEATURES, Q-BENCH-SOURCE | capabilities/budgets to drivers |
| S06 | TODO | needs E05 | needs Q-CRYPTO-UNIT/CRYPTO, Q-PROP-CRYPTO, Q-CORE, cargo-tree | crypto zeroization features |
| P03 | TODO | needs S02 | needs Q-CONNECTION/BOUNDS/PROP-MESSAGE/CRYPTO, Q-INTEROP | size-limit contract |
| A01 | TODO | needs T04, T05 | needs Q-TRANSPORT-ADMISSION, Q-BENCH-SOURCE, Q-TRANSPORT-GROUP | lifecycle truth in transport |
| A02 | TODO | needs T01, K01 | needs Q-TRANSPORT-CONFIG/BATCH + NEW family loopback | IPv6 end-to-end or reject |
| B01 | TODO | bench runtimes/mio.rs:697 | needs Q-BENCH-MIO/MATRIX | remove 4096 ceiling |
| B02 | TODO | needs B01, P02 | needs Q-BENCH-MIO/SOURCE, Q-WAITER | Mio receive/timer parity |
| D01 | TODO | needs K02, A01, S03 | needs Q-DOCS, Q-FEATURES + review | dead helpers/docs |
| D02 | TODO | needs S04, S05, T01, T04 | needs Q-TRANSPORT-BATCH/GROUP, Q-ALLOC + perf window | scratch reuse |
| A03 | TODO | needs S03, P02, K02, A01, A02, P03 | needs Q-TRANSPORT-ADMISSION/CALLER, Q-FEATURES + NEW API test | owner listener/caller driver |
| A04 | TODO | needs A03 | needs Q-TRANSPORT-* + NEW policy tests | pool/idle/resource policy |
| A05 | TODO | needs A04, S04 | needs Q-FEATURE-TOKIO + NEW facade tests/examples | managed Tokio facade |
| A06 | TODO | needs A04, A05, S04, S05, F05 | needs Q-FEATURES, Q-TRANSPORT-CONCURRENCY + NEW per-runtime | runtime parity, one at a time |
| F01 | TODO | needs P03, A05 | needs Q-CONNECTION/PROP-MESSAGE + NEW age regression | source age through relay |
| F02 | TODO | needs F01, A05 (inspect relay branch first) | needs NEW bus tests + REVIEW reclamation | bounded publication bus |
| F03 | TODO | needs F02, P02 | needs NEW isolation tests, Q-GROUP/CALLER/PROP-MESSAGE | destination isolation/expiry |
| F04 | TODO | needs F03 | needs NEW telemetry tests + perf window | shard lateness/resources |
| F05 | TODO | needs F03, A05 | needs Q-CONNECTION/GROUP/CALLER + NEW shutdown tests | predictable close |
| V00 | TODO | needs E02, E03, B02 + user inputs | REVIEW workload completeness | frozen workload contract |
| V01 | TODO | needs S06, P03, P02, A01 | needs Q-CORE/CONNECTION/CRYPTO/GROUP + all Q-PROP-* | deterministic simulation |
| V02 | TODO | needs V01, A06, A02, S06 | needs Q-FEATURES/MSRV/INTEROP/BONDED/COMPIO-QUEUE/FUZZ | runtime/interop/fuzz matrix |
| V03 | TODO | needs V00, V02, F04, F05, D02 (perf window only) | REVIEW accounting | soak/steady-state |
| D03 | TODO | needs D01, A06, V02 | needs Q-DOCS/FEATURES/MSRV/PACKAGE + review | release docs |
| Z01 | TODO | needs E01,E02,E03,E04,E05,B02,D02,D03,S06,F05,V03 | Q-FINAL + full-matrix review | final handoff, no publish |

## Current checkpoint
- Observed trigger and contract: B00 — record SHA/branch/diff/authorization; inventory features/tests read-only; select next ready cards.
- Exact files/symbols/callers: git state only + this ledger; no source edits. Audited SHA 860fc51 superseded by inspected newer main 8f38c1f (#91 treat-failed-probes + #93 canonical knobs both merged).
- Smallest edit: this ledger file; zero code changes.
- Checks executed, counts, skips and outcomes: `git fetch origin --prune`; `git switch main && git pull --ff-only` (0797e06→8f38c1f, 41 files); `git branch -D` ×3 superseded; `git worktree prune`; `git status --porcelain -b` (clean + 3 untracked specs); `ps` (no bench processes). No Cargo run — implementation-validation host confirmed idle first.
- Checks not executed and why: Q-* gates — no code changed yet; relay-branch content survey deferred to F02.
- Next concrete action: commit this ledger on codex/b00-baseline, open PR #1 (B00, docs-only), then start E05+E01 on fresh codex/ branches off updated main.
