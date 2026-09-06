# A2 high-resolution transport waiter

Reusable worker-level scheduling wait for the residual Tokio service-visit
deficit filed as [#82](https://github.com/krsna1729/srt-rs/issues/82).
This is **code only**: N=1/30/200 quiet-host measurement campaigns are
deferred.

## Disposition (issue comments are authoritative)

```text
A1  Tokio per-connection tail-spin
      N=1  technically sufficient
      N=30 rejected on CPU economics
      STATUS: disproven

A2  shared/sharded high-resolution transport scheduling
      one waiter per worker
      epoll_pwait2 (nanosecond timeout) or absolute timerfd
      absolute CLOCK_MONOTONIC deadlines
      service every due connection after a single wake
      no spin tail
      STATUS: challenger (this crate); N=30 scratch passed where A1 died;
              N>=200 not yet validly measured

B   coarse wake + accumulated entitlement / multi-admit
      STATUS: untested — do not start here
```

A1 paid overlapping spin cost per Tokio task. A2 amortizes one precise wait
across staggered deadlines so connection count becomes a benefit rather than
a cost. The scratch challenger already showed N=1/30 at full source rate,
with N=30 at *lower* CPU than Tokio spends while falling short. That scratch
is not merged; this document describes the production primitive.

## API shape

`srt_transport::HighResWaiter<K>` is owned by one worker. Connections are
sharded onto workers; no shared dataplane state is required.

```text
worker:
    register each connection socket
    recompute each absolute CLOCK_MONOTONIC deadline
    wait once   — epoll_pwait2(timespec) or absolute timerfd
    service EVERY key that is due, and every ready socket
```

`DeadlineHeap<K>` is the next-deadline index (min-heap with lazy stale
deletion). The measured scratch scanned linearly; a heap is what a
production worker uses.

Mio and Tokio `Conn` expose:

- `schedule_wait(now)` — binding delay of pacing vs protocol timers
- `schedule_on(&mut waiter, key, now)` — register the socket and arm the
  absolute deadline

Callers then `waiter.wait(&mut due, &mut ready)` and service every due key.
One packet per service visit remains the contract.

## How this differs from A1

| | A1 | A2 |
|---|---|---|
| Wait owner | each connection / Tokio task | one waiter per worker |
| Precision | tail-spin after coarse `sleep` | `epoll_pwait2` / absolute `timerfd` |
| CPU at N=30 | collapsed (tasks starve each other) | scratch: full rate, *lower* CPU than Tokio |
| Spin | yes (the rejected mechanism) | no |

`tokio::time::sleep` plus `TAIL_SPIN` is A1. It must not be reintroduced as
the way to buy sub-millisecond waits at scale.

## What is deliberately deferred

- Quiet-host N=1/30/200 timing campaigns and matrix sweeps
- Route B accumulated debt, multi-admit, and `SrtConnection` ownership
- Forcing completion runtimes (Monoio/Compio/Glommio) onto this waiter
- Host-contention policy (#83) and batched UDP I/O (#73)

Those compose later. A2 exists to answer whether precise shared waiting
repairs ordinary steady-state throughput without debt semantics.
