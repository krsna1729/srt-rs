# srt-rs execution goal and agent prompt

Companion guide: [srt-rs-production-guide.md](/home/dev/srt-rs/srt-rs-production-guide.md)

These are instructions to hand to an implementation agent. They do not by
themselves start a goal or authorize work. Follow the user's current
authorization and preserve any active benchmark protection.

## Goal text

> Make the existing krsna1729/srt-rs stack production-ready for its declared workload and application-friendly, following the companion guide's required cards and acceptance matrix. Repair acceptance/cancellation/size/deadline/configuration/resource invariants; remove misleading evidence and unnecessary complexity; complete supported caller/listener and sharded live-relay APIs; qualify the retained native runtimes, encryption and bonding with actual regression, interop and steady-state evidence. Preserve the selected stack and unrelated work. Finish with a reviewable change set and an honest qualification report. Do not claim completion while a required implementation, test or workload gate remains pending, and do not publish or deploy.

## Copy-paste agent prompt

```text
Use /home/dev/srt-rs/srt-rs-production-guide.md as the self-contained execution specification. You do not need the previous conversation.

Goal: complete the guide's required cards and acceptance matrix in the existing krsna1729/srt-rs stack. Keep the stack. Favor small root-cause fixes and existing primitives. Preserve security, protocol semantics, native runtime ownership and compatibility.

Authority:
- Follow the user's current authorization. The initial audit protected an active benchmark; this session later authorized implementation and validation. A newly active benchmark window still takes precedence for the affected host.
- Do not infer permission to edit/build/test from this file, elapsed time, process inspection or a new worktree. A worktree on the benchmark host still interferes with measurement.
- If the user has now explicitly authorized implementation and validation in a suitable environment, record that authorization and proceed without asking again for ordinary in-scope work.
- Preserve unrelated edits/untracked files. Do not reset, clean, stash or overwrite them.
- Do not commit, push, merge, tag, publish, deploy, change host settings, install hooks or message external systems without separate authorization.

Start:
1. Read guide sections 1-7, the task index, and any existing progress ledger.
2. Record current branch, SHA, diff, authorized worktree and validation host. The audited baseline is `6397f6a`; the working tree contains additional boundedness hardening, and newer source wins after inspection.
3. Read applicable AGENTS.md. Use CodeGraph first if the checkout already has an index; otherwise use rg/source reads. Never create or rebuild indexes as part of this task.
4. In READ_ONLY mode, revalidate the next ready card and prepare its exact regression/patch plan, then report that implementation remains pending. Do not run Cargo or change files.
5. In authorized implementation mode, start the smallest dependency-ready card and carry it through validation.

Work loop:
- Keep one card/checkpoint active. Read that card, its prerequisites, current touched source, callers and nearest tests.
- Confirm the reported trigger. If already fixed or disproved, record concrete evidence; do not manufacture a patch.
- State the observable contract. Write the smallest meaningful regression for a real behavior change, then implement the root-cause fix across affected callers.
- Split large cards into coherent checkpoints. Do not combine unrelated cleanup, runtime redesign and protocol changes.
- Validate with the guide's focused existing targets. NEW tests/APIs in the guide are proposals: implement them before invoking them. Check executed counts; zero tests or skipped required interop cases are not passes.
- Persist accepted/submitted/completed I/O state correctly. Never blindly retry an owned-buffer send just because its future was cancelled.
- Never return a retryable rejection for already-admitted data. Core encryption/message admission must be accounted before adapting wrapper errors.
- Bound generation, timer visits and delivery as well as socket output. Keep byte-budget progress and readiness continuation explicit.
- Keep benchmark validity/attempt pairing/failure handling repaired before accepting performance conclusions.
- Use the fixed SRT-600 corpus for promotion decisions: `cargo run -p srt-bench -- qualify plan` defines the ten scenarios and `qualify score BASE.tsv HEAD.tsv` enforces the correctness, noise and geometric resource gates. Keep the exhaustive matrix for diagnosis; do not optimize matrix size as a product goal.
- Iterate from the accepted candidate: run the immutable qualification corpus, apply the hidden mutation set, accept only a Pareto improvement, then regenerate workload seeds and continue. If a required workload input or quiet host is unavailable, record qualification as blocked instead of inventing numbers.
- Review the diff, update the ledger with exact checks/outcomes/skips, then continue to the next ready card.

Efficiency and uncertainty:
- Reuse current crates, tables, tests, snapshots and runtime mechanisms.
- No new orchestration framework, benchmark DSL, general runtime trait or speculative feature.
- Do not rerun broad suites after every edit. Use focused checks, then final required gates; rerun when later changes invalidate evidence.
- For an unresolved cancellation contract, protocol rule or unsafe reclamation design, obtain primary source/review and leave that card explicitly pending. Continue independent ready cards.
- Ask only for missing product/environment constraints that actually block a required step. Bundle the minimum missing workload fields; retain all prior answers.
- A fast model is not a reason to weaken tests, remove features, hide errors, add blanket exceptions or call unverified work complete.

Checkpoint:
Use one Markdown progress ledger as specified in guide section 13. Before compaction or ending an unfinished turn, record current card, exact source, last check, blockers and next concrete action. Resume from it without restarting the audit. Another worker may be active; do not revert their edits or overwrite overlapping work.

Completion:
All required cards and matrix rows must be verified against the delivered source, or legitimately disproved with requirements preserved. Missing runtime/host/SLO/interop evidence means qualification is pending. Optional experiments can be declined with evidence; required behavior cannot be silently deferred.
If goal tools are available, obey their actual status rules. Do not mark complete because time/tokens are low. Report: changes, compatibility, executed validation, operating envelope, remaining limitations and reviewable files. No claims of invincibility, universal optimality or complete lock-free behavior without proof.
```

## Implementation launch when the user is ready

Submit the prompt above together with a statement that reflects the actual environment. For example, **only if true**:

> Benchmark protection is lifted for the designated implementation and validation environment. Implement the guide in an isolated worktree, preserve the original checkout and unrelated work, and run the required local validation there within the available host resources. Continue through the required cards without repeated permission checks. Do not commit, push, publish, deploy or change system settings.

If benchmarks must continue on the original host, provide a separately authorized validation host/workspace instead. Source-only investigation can continue while that is arranged.

Do not paste a claim that the host is idle unless it is actually true. The launch statement is the user's authorization, not an inference an agent may make from this document.

## Resume prompt

```text
Continue the srt-rs production goal from the existing progress ledger and working diff. Preserve the recorded authorization and constraints. Recheck current SHA/touched files, finish the next concrete checkpoint, validate it, update the ledger, and proceed to the next dependency-ready card. Do not restart the whole audit or mark unexecuted checks as passed.
```

## Focused review prompt for difficult cards

```text
Review only card <ID>, its changed source and acceptance evidence against the companion guide. Be read-only. Check the actual callers and state transitions, especially acceptance linearization, submitted-I/O ownership, remaining bounded work, crypto/sequence state and healthy-sibling progress. Return concrete defects or an evidence-backed pass; identify unexecuted required cases. Do not propose a wider rewrite or alter the code.
```

The prompt deliberately stays short relative to the guide: one task card supplies the detail for each implementation step. The structure follows [OpenAI's prompting documentation](https://learn.chatgpt.com/docs/prompting); this is not a guarantee of any model's success.
