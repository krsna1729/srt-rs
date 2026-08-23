# Split sender/receiver configuration

Status: **implemented** (`eb28251`). This file kept its original framing
for the record; the correction below matters more than the plan did.

## What was built

Every topology axis can be scoped to a role:

- Unprefixed (`--ingress`, `--workers`) applies to both roles and keeps
  them in lockstep. Cell count unchanged, backward compatible.
- `--recv-x` / `--send-x`, or a `[recv]` / `[send]` section in a plan
  file, makes that axis independent for that role — a real cartesian
  product between the two sides.
- Plan files also set `cpus` per role. They parsed before and were
  silently ignored.
- Result rows record both roles' values, so one row states the whole cell
  and resume can tell apart two cells that differ only on the far side.

See [`asymmetric-roles.plan`](asymmetric-roles.plan) for the shape.

## Correction: "pooled ingress breaks when workers>2" was not a bug

The original motivation recorded a measured collapse — `shared-pool:K`
delivering 22% at 400–650 connections once `workers` went above 2 — and
called it a harness bug worth filing. It reproduces exactly, and the
diagnosis was wrong.

`shared-pool:K` binds K *ports* served on **one thread**. That is
documented and deliberate: it is the single-threaded control that
isolates "fewer wakeups from fewer sockets" from `ReuseportMulti`'s
"kernel-level demux". One thread is therefore also a hard ceiling.

What changed was the sender. At `workers=1` it offered 55% of target and
one listener core coped. At 2 it offered 97% and one core was exactly at
its limit. At 3 the receive queue overflowed, so the protocol saw no gap
to NAK, ACKs stopped, and the sender flow-window-stalled — which pushed
`offer%` down too. The result reads as a collapse rather than as a
ceiling, which is why it looked like a bug.

It was confirmed against contention by putting the roles on disjoint CPU
sets, where oversubscription cannot be the explanation:

| send workers | good% | rcvbuf drops | listener cores |
|---|---|---|---|
| 2 | 94.1 | 0 | 1.00 |
| 3 | 13.1 | 1,678,663 | 1.00 |

The listener never exceeds one core at any K. So the fix is capacity, not
correctness: `--workers` now deals the K pool sockets across that many OS
threads in all six adapters, with `workers = 1` still meaning one thread
so the control survives. At 400×8 Mbps:

| recv workers | good% | rcvbuf drops | listener cores |
|---|---|---|---|
| 1 | 13.6 | 1,604,302 | 1.00 |
| 2 | 99.9 | 0 | 1.95 |
| 3 | 100.0 | 0 | 2.16 |

3.2 Gbps at 100% delivery, 18 ms RTT. mio, tokio and smol clear it;
glommio and compio do not, which is their own per-datagram io_uring
limit, not this.

## Consequence for the published comparisons

The [baseline](../baseline-2026-08-23.md) concluded that `shared-pool` was
the strongest general choice and that the reuseport strategies "cost more
CPU and deliver no better". That comparison was never CPU-fair:
`shared-pool` was using **one** core while `reuseport-multi:K` used K. It
survived only because the load generator was itself single-threaded and
could not offer enough to expose the difference. Both halves of that
finding need re-measuring now that either side can be scaled deliberately.

## Still open

- `--batch` is read only by `mio`; the other five adapters ignore it, so
  sweeping it across all runtimes doubles the cell count and changes
  nothing for five of six. Either scope the axis to mio or implement
  batched sends elsewhere (see the upstream asks in the porting notes).
- `--send-egress=per-conn|pool:K` is still not a knob: the sender always
  uses one connected socket per connection. This is the precursor to any
  GSO/`sendmmsg` work on the send side.
