# Production progress
Guide version: 2026-09-10 / audit 860fc5180219629dca833511fb3075b3aa83d8ce
Working repository: /home/dev/srt-rs
Working branch / HEAD: codex/evidence-e01-e05-b01 (retargeted onto main after PR #94 merged as f56d00b), rebased directly onto main / see git log
Protected checkout: none — host idle at setup (only codegraph MCP server running); prior benchmark protection lifted by user authorization below
Implementation authorization: user 2026-09-10 — "cleanup local. get latest origin/main. take a look at prompt and production guide md files placed. achieve it with a proper commits and PR strategy."
Validation host and authorization: same host authorized for implementation AND validation (no benchmark process observed at setup); perf-window work still needs explicit per-run confirmation
Allowed resource/time limits: host envelope to be recorded under V00; default to focused checks, no broad suites per edit
Workload contract: PENDING (V00) — 600-destination target dimension; source rate, message shape, encryption, bonding, latency/resource limits all unfilled
Current card: Evidence wave 1 COMPLETE (E01, E02, E03, E04, E05, B01 VERIFIED); PR #94 (B00) merged to main; PR #95 (this wave) retargeted onto main — B02 explicitly deferred, blocked on P02
Next dependency-ready card: S01 (E05 done) — one phase per PR from here: next PR is the Protocol correctness phase (S01, S02, S06, P03, in that dependency order, one commit per card), each phase PR reviewed (incl. an Opus 5 pass) and ponytail-checked before opening
Required blockers: B02 needs P02 (bounded due-session service); V00 needs user workload fields; S05 may need runtime-implementation review; V02/V03 need interop/fuzz hosts and frozen workload
Last passed broad gate and source: cargo xtask precommit (fmt/clippy/reportcard/doc/typos) green on rebased tip; compare::/harness::/runtimes::mio unit tests (54+20+4) green; E05 Q-CRYPTO-UNIT/CRYPTO + srt_connection::tests green on db369db
Unrelated changes to preserve:
- `gpt-6-astra-light.md` (untracked, 300 KB, unrelated per guide §2) — never commit/stash/overwrite
- `srt-rs-agent-prompt.md`, `srt-rs-production-guide.md` (untracked handoff specs) — working copies only, not for main history
- `feat/srt-bench-relay-use-cases` (129 commits ahead of origin/main, base 63d617e) — active relay experiment, relevant to F02; do not delete; reuse selectively, no wholesale cherry-pick
- stashes `pr90-executor` and `contabo-wip-before-pr86` (2026-09-06) — pre-merge WIP, kept as-is pending per-card inspection
- deleted as superseded (squash-merged, remote branches gone): contabo-pr86-a2, pr-90-ack-coalesce, feat/config-canonical-knobs; prunable worktree /tmp/srt-audit-20260907 removed; local main fast-forwarded 0797e06 → 8f38c1f
| B00 | VERIFIED | docs/production-progress.md @ 11db555, PR #94 | READ: status/rev-parse/diff-stat on 8f38c1f | merged to main @ f56d00b |
| E01 | VERIFIED | compare.rs read_field 3-state (Missing/Invalid/Valid) backs required_count/required_identity and the new positive_or (logical_streams never falls back on a present-but-invalid/zero value on either role; only an absent legacy column defers). source_streams uses the separate positive_from (caller-only, with fallback to logical_streams) — the CI bench-sentinel job (first real exercise of this code on `main`; it never ran while this PR targeted codex/b00-baseline) caught that positive_or's two-role veto rejected every real pair, because the harness always writes a listener's source_streams column as `0` (structural: a listener has no source streams of its own), which positive_or misread as corrupt evidence | Q-BENCH-CLEAN 4, Q-BENCH-COMPARE 21 (incl. corrupt_shared_values_veto_fallback, listener_structural_zero_source_streams_does_not_veto), Q-BENCH-HARNESS 32, Q-XTASK 7, matrix 12, capacity 27, source 5 — all pass; fmt+clippy+precommit clean; both docs/plans/ci-sentinels/*.plan reproduced locally and pass check-clean | none |
| E02 | VERIFIED | compare RepSlot/group_records_by_cell reuse in harness report+chart @ 1937e18; incomplete_reps counts once per ambiguous slot (CellSummary::duplicate_rows tracks surplus rows separately); chart_point excludes a point (returns None) on non-finite/negative pkt_sent or non-finite/non-positive elapsed_s instead of defaulting either to 0.0 | report_tests 6 (incl. a malformed-elapsed pair), compare tests incl. duplicate_rows_count_once_as_incomplete, lib 168-170, matrix/capacity/source green | none |
| E03 | VERIFIED | lib.rs resume_unwind + torn fixtures @ c1c1dc8; workflows capture `timeout`'s exit via `status=0; ... || status=$?` (bash -e otherwise kills the script on exit 124 before status is read), weekly's `timeout 2h30m` corrected to the valid GNU duration `150m`, and chart-update steps gated on `steps.<sweep>.outcome == 'success'` in addition to `partial != 'true'` so a genuine crash can no longer publish to the trend | panic test, torn lib+binary, matrix 12 green; YAML_OK; workflows not executed per card (still forbidden) | none |
| E04 | VERIFIED | xtask audit.rs counted/manual(pinned) + doc provenance @ 74cfc01 | Q-XTASK 7 (2 new); codegen execution deferred to qualification per card | none |
| E05 | VERIFIED | crypto.rs equivalence matrix, timing test deleted @ db369db | Q-CRYPTO-UNIT 19 (0 ignored), Q-CRYPTO 5, srt_connection::tests 40 | none |
| B01 | VERIFIED | mio.rs Vec<bool> served table + serve_ready_due @ db8ec10 | Q-BENCH-MIO 4 (1 new); Events cap kept (mio re-reports; noted) | none |
| B02 | TODO (blocked on P02) | — | — | needs P01+T02+T05 first |
| S01 | TODO | needs E05 (done) | Q-CORE/CONNECTION/GROUP | explicit-sequence parity |
| S02 | TODO | needs S01 | Q-CORE/CONNECTION/PROP-MESSAGE/PROP-SENDER/GROUP | admission linearization |
| S03 | TODO | needs S02 | Q-TRANSPORT-BATCH/CALLER, Q-FEATURES | adapter admission vs progress |
| S04 | TODO | needs S03 | Q-TRANSPORT-BATCH, Q-FEATURES + NEW cancel regression | readiness-output retention |
| S05 | TODO | needs S03 | Q-FEATURES + NEW per-runtime ownership test | completion-runtime ownership |
| T01 | TODO | B00-gated | Q-TRANSPORT-BATCH + NEW truncation regression | truncation detection |
| T02 | TODO | needs T01 | Q-TRANSPORT-BATCH, Q-FEATURES, Q-WAITER | receive budgets/continuation |
| T03 | TODO | B00-gated | Q-TRANSPORT-CALLER/BATCH | output exhaustion reporting |
| T04 | TODO | needs T01, T03 | Q-GROUP, Q-TRANSPORT-GROUP, Q-PROP-GROUP | group-leg isolation |
| T05 | TODO | B00-gated | Q-TRANSPORT-ADMISSION | earliest deadline |
| P01 | TODO | needs S02, T03 | Q-CORE/PROP-SENDER/BOUNDS/CONNECTION | bounded retransmission |
| P02 | TODO | needs P01, T02, T05 | Q-TRANSPORT-CALLER/ADMISSION, Q-WAITER | bounded due-session service |
| K01 | TODO | B00-gated (#93 landed — revalidate) | Q-TRANSPORT-CONFIG, Q-BENCH-SOURCE, Q-REUSEPORT | confirm Auto/Shared table |
| K02 | TODO | needs K01, T02, T03 | Q-TRANSPORT-CONFIG, Q-FEATURES, Q-BENCH-SOURCE | capabilities/budgets to drivers |
| S06 | TODO | needs E05 (done) | Q-CRYPTO-UNIT/CRYPTO, Q-PROP-CRYPTO, Q-CORE | crypto zeroization features |
| P03 | TODO | needs S02 | Q-CONNECTION/BOUNDS/PROP-MESSAGE/CRYPTO, Q-INTEROP | size-limit contract |
| A01 | TODO | needs T04, T05 | Q-TRANSPORT-ADMISSION, Q-BENCH-SOURCE, Q-TRANSPORT-GROUP | lifecycle truth in transport |
| A02 | TODO | needs T01, K01 | Q-TRANSPORT-CONFIG/BATCH + NEW family loopback | IPv6 end-to-end or reject |
| D01 | TODO | needs K02, A01, S03 | Q-DOCS, Q-FEATURES + review | dead helpers/docs |
| D02 | TODO | needs S04, S05, T01, T04 | Q-TRANSPORT-BATCH/GROUP, Q-ALLOC + perf window | scratch reuse |
| A03 | TODO | needs S03, P02, K02, A01, A02, P03 | Q-TRANSPORT-ADMISSION/CALLER, Q-FEATURES + NEW API test | owner listener/caller driver |
| A04 | TODO | needs A03 | Q-TRANSPORT-* + NEW policy tests | pool/idle/resource policy |
| A05 | TODO | needs A04, S04 | Q-FEATURE-TOKIO + NEW facade tests/examples | managed Tokio facade |
| A06 | TODO | needs A04, A05, S04, S05, F05 | Q-FEATURES, Q-TRANSPORT-CONCURRENCY + NEW per-runtime | runtime parity, one at a time |
| F01 | TODO | needs P03, A05 | Q-CONNECTION/PROP-MESSAGE + NEW age regression | source age through relay |
| F02 | TODO | needs F01, A05 (inspect relay branch first) | NEW bus tests + REVIEW reclamation | bounded publication bus |
| F03 | TODO | needs F02, P02 | NEW isolation tests, Q-GROUP/CALLER/PROP-MESSAGE | destination isolation/expiry |
| F04 | TODO | needs F03 | NEW telemetry tests + perf window | shard lateness/resources |
| F05 | TODO | needs F03, A05 | Q-CONNECTION/GROUP/CALLER + NEW shutdown tests | predictable close |
| V00 | TODO | needs E02, E03, B02 + user inputs | REVIEW workload completeness | frozen workload contract |
| V01 | TODO | needs S06, P03, P02, A01 | Q-CORE/CONNECTION/CRYPTO/GROUP + all Q-PROP-* | deterministic simulation |
| V02 | TODO | needs V01, A06, A02, S06 | Q-FEATURES/MSRV/INTEROP/BONDED/COMPIO-QUEUE/FUZZ | runtime/interop/fuzz matrix |
| V03 | TODO | needs V00, V02, F04, F05, D02 (perf window only) | REVIEW accounting | soak/steady-state |
| D03 | TODO | needs D01, A06, V02 | Q-DOCS/FEATURES/MSRV/PACKAGE + review | release docs |
| Z01 | TODO | needs E01,E02,E03,E04,E05,B02,D02,D03,S06,F05,V03 | Q-FINAL + full-matrix review | final handoff, no publish |

## Current checkpoint
- Observed trigger and contract: Evidence wave 1 finished; all six cards verified against delivered source with executed focused checks. Two independent reviews of PR #95 caught three real regressions before merge, folded into the E01/E02/E03 commits above rather than left as a follow-up patch: `timeout`+`status=$?` was unreachable under Actions' default `bash -e` (an expected time-box or a genuine crash both skipped `partial=true` and reached the chart-update step); weekly's `timeout 2h30m` was not a valid GNU duration; and the `logical_streams`/`source_streams` legacy fallback conflated "column absent" with "column present but invalid/zero", letting a corrupt stream count silently become `conns`. Two minor accompanying fixes: `chart_point` now excludes a point instead of defaulting invalid `pkt_sent`/`elapsed_s` to 0.0, and `incomplete_reps` counts once per ambiguous slot instead of once per duplicate row.
- Exact files/symbols/callers: crates/srt-bench/src/{compare.rs,harness.rs,lib.rs}, tests/{check_clean_exit_status.rs,matrix_exit_status.rs}, crates/srt-protocol/src/crypto.rs, crates/xtask/src/{audit.rs,reportcard.rs}, docs/perf/x86-64-v3-pgo-audit.md, .github/workflows/bench-{nightly,weekly}.yml. Classifier None-path, summarize incomplete-path, and adjacent suites (capacity/matrix/source/harness) re-verified, no regressions.
- Smallest edit: none pending — wave commits (E05 through the ledger) rebased directly onto main after PR #94 merged; see git log for exact SHAs.
- Checks executed, counts, skips and outcomes: see per-card rows above. Full `cargo xtask precommit` (fmt/clippy/reportcard/doc/typos) green on the rebased tip. Transport/protocol suites untouched by this wave (no transport/protocol behavior changed except crypto unit tests) — Q-TRANSPORT-*/Q-PROP-* deferred to the waves that touch them. Interop/fuzz/MSRV untouched (V02); full precommit/interop/fuzz otherwise left to CI (this PR now targets `main`, where `ci.yml` triggers).
- Checks not executed and why: workflow runs (card forbids execution/publication during task); codegen audit execution (optional until qualification); perf-window measurements (none — idle-host unit/integration tests only).
- Next concrete action: confirm exact-head CI green on `main`-targeted #95, then merge (rebase) both PRs. From here, one phase per PR: next is Protocol correctness (S01, S02, S06, P03), one commit per card, with an Opus 5 review and a ponytail-review pass before opening each phase's PR.
