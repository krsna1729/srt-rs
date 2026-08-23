# Plan: split sender/receiver configuration in srt-bench

Status: **plan, not implemented**. Motivated by the 2026-08-23 max-push
campaign: the `workers` knob applies to both roles at once, which both hid
the sender-side wall (workers=1 starved the caller at ≥300 conns) and
produced a false collapse (workers≥3 on pooled ingress breaks the *listener*
side while the sender would have benefited). The roles need independent
topology knobs.

## Problem

1. `matrix` builds ONE `common` argv from the cell and passes it to both
   spawned roles (`harness.rs`, receiver/sender `Command` assembly). No way
   to express "listener: shared-pool:4 with 1 worker" + "caller: 4 worker
   shards".
2. `--workers N` flows into both processes' `run_workers`; on pooled
   ingress the listener side misbehaves with N>2 (measured: 22% delivery at
   400–650 conns), so the useful sender range is unreachable through matrix.
3. Semantically, `--ingress` is a *listener* concept. The caller-side
   analogue (per-conn connected sockets vs K shared send sockets) doesn't
   exist as a knob; today the sender silently mirrors whatever the cell says.
   The mixed-runtime hand-run proved per-role control works at the process
   level — only the matrix layer lacks it.

## Design

### Flag scoping

Follow the existing `--recv-cpus`/`--send-cpus` precedent:

- Every topology axis gets optional role prefixes: `--recv-*` and
  `--send-*`. Unprefixed = apply to both (backward compatible).
  - `--recv-ingress`, `--send-ingress`
  - `--recv-workers`, `--send-workers`
  - promotion/cookie-routing/batch stay listener-relevant; sender copies are
    accepted but ignored (documented), matching current behavior where the
    sender parses-and-discards them.
- Add the missing caller-side concept explicitly:
  - `--send-egress = per-conn | pool:K` — per-conn connected UDP socket per
    connection (today's implicit behavior) vs K shared send sockets with
    app-level dispatch. `pool:K` is new surface for a future experiment;
    plan the flag now so the schema doesn't churn twice.
- Single-role invocation (`runtime=… mode=…`) keeps working unchanged; it
  already accepts the plain flags. Prefixed forms resolve to their unprefixed
  meaning when the role matches.

### Matrix expansion and schema

- `axis()` gains a scope tag: `Both | RecvOnly | SendOnly`. Expansion takes
  the cartesian product of Both ∪ RecvOnly (→ receiver argv) and Both ∪
  SendOnly (→ sender argv). Total cells = product over Both × RecvOnly ×
  SendOnly axes; print the count up front as today.
- `harness::COLUMNS`: role-scoped values land in role-prefixed columns
  (`recv_ingress`, `send_workers`, …) only when they diverge from the Both
  value; simplest correct rule: **always write role-resolved values** into
  the prefixed columns and keep the legacy unprefixed column populated with
  the Both value for continuity. One-time schema bump; `report` treats
  missing columns as defaults so old TSVs still report.
- Pairing/delivery math: caller/listener rows already join on cell+rep.
  The cell identity hash MUST include the role-scoped values, otherwise
  resume (`read_results`) will skip genuinely different cells. Delivery%
  stays cross-row (offer%/good% columns already expose sender-side
  shortfalls, which is exactly what per-role divergence makes common).

### Port allocation

Unchanged: connection *i* uses port+*i* on both sides for `per-port`;
pooled strategies bind one/few ports. Role-splitting does not alter socket
placement, only how each side structures its loops.

### CPU pinning interplay

`--recv-cpus`/`--send-cpus` compose with the new knobs: the natural full
expression is e.g.

```
srt-bench matrix \
  --recv-ingress=shared-pool:4 --recv-workers=1 --recv-cpus=0-2 \
  --send-ingress=pool:2        --send-workers=3 --send-cpus=3-5 \
  --promotion=all --connections=450 --bitrate=8000000 …
```

## Expected experiments this unlocks (from measured baselines)

1. **Fix the false collapse**: shared-pool:4, recv-workers=1 +
   send-workers=3/4 at 400–650 conns — tests whether sender sharding alone
   recovers offer% where combined sharding broke the listener.
2. **1200×8 stretch**: sender fully scaled (workers≈cores−listener budget)
   against the known-good 1-worker pooled listener; quantifies the true
   per-thread cadence ceiling without listener interference.
3. **Egress shape**: `--send-egress=pool:K` vs per-conn at the 450×8 knee —
   precursor to the GSO/TXTIME work (batching wants few big send sockets).
4. **Cross-runtime matrix**: `--runtimes` becomes splittable the same way
   (`--recv-runtime=tokio --send-runtime=mio,glommio`) — formalizes the
   ad-hoc mixed-pair probe that showed glommio ≈ tokio per-thread send rate.

## Verification plan (when implemented)

- Byte-compat: re-run one baseline cell (25 conns, unprefixed flags); rows
  must be identical modulo new columns.
- Regression: reproduce the workers=3 pooled-listener collapse, then show
  recv-workers=1/send-workers=3 restores listener health.
- Resume correctness: interrupt a divergent-cell sweep, restart, confirm no
  cell is skipped or duplicated.
- `report --by` across the new columns on an old and a new TSV.

## Non-goals

- No change to protocol crates, transport adapters, or measurement
  methodology; this is harness surface only.
- No daemon/aggregator model — one child process per role per cell stays.
