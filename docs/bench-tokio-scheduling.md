# Tokio receive and outbound scheduling evidence

This is the narrow [#36](https://github.com/krsna1729/srt-rs/issues/36) gate.
There are two questions, and they are answered to different degrees.

- **Receive quantum.** `--recv-rounds` bounds one readiness service, and a
  fixed histogram records 10 ms maintenance-tick lateness. Swept below, with
  the delivery and cost metrics alongside, so the tradeoff is visible rather
  than asserted.
- **Outbound `WouldBlock` policy.** `--would-block retain|drop` selects
  whether the unsent tail is kept or discarded. Retained work is now bounded
  and instrumented, which is a real safety improvement — but see
  [What is *not* settled](#what-is-not-settled) before treating the policy
  choice as decided.

Both are first-class matrix axes (`recv-rounds`, `would-block`), so their
setting is part of a cell's recorded identity and can be swept from a plan.

## Receive-round sweep

Release build, `tokio` + `shared-pool:4` ingress (the path the receive
instrumentation actually lives on), 1 Mbit/s source per connection with
`srt-bandwidth=input-relative:25`, 6 s per cell, **3 reps per cell, medians
below**. 45 cells, all completed; the matrix exited 0, so every required child
succeeded and recorded its row.

| conns | cap | offer% | good% | deliv% | CPU ms | dgram/syscall | p95 (us) | p99 (us) | max (us) |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 16 | 1 | 100.0 | 100.0 | 100.0 | 1806 | 4.39 | 4,096 | 7,786 | 13,593 |
| 16 | 4 | 100.0 | 100.0 | 100.0 | 2251 | 4.46 | 4,096 | 8,192 | 17,342 |
| 16 | **8** | 100.0 | 100.0 | 100.0 | 1727 | 4.10 | 2,048 | 4,096 | 12,708 |
| 16 | 16 | 100.0 | 100.0 | 100.0 | 2103 | 4.26 | 4,096 | 7,496 | 11,187 |
| 16 | 32 | 100.0 | 100.0 | 100.0 | 1220 | 4.38 | 2,048 | 4,096 | 5,843 |
| 64 | 1 | 99.4 | 99.4 | 100.0 | 4731 | 4.81 | 4,096 | 16,384 | 20,380 |
| 64 | 4 | 100.0 | 100.0 | 100.0 | 5116 | 5.50 | 4,096 | 8,192 | 17,852 |
| 64 | **8** | 100.0 | 100.0 | 100.0 | 3808 | 4.97 | 4,096 | 4,096 | 11,991 |
| 64 | 16 | 100.0 | 100.0 | 100.0 | 4077 | 5.09 | 4,096 | 16,384 | 19,511 |
| 64 | 32 | 100.0 | 100.0 | 100.0 | 4640 | 5.16 | 8,192 | 65,536 | 69,926 |
| 200 | 1 | 100.0 | 100.0 | 100.0 | 9030 | 4.23 | 4,096 | 8,192 | 12,924 |
| 200 | 4 | 99.9 | 99.9 | 100.0 | 8941 | 4.30 | 4,096 | 16,384 | 26,300 |
| 200 | **8** | 100.0 | 100.0 | 100.0 | 9161 | 4.21 | 4,096 | 16,384 | 39,228 |
| 200 | 16 | 98.5 | 98.5 | 100.0 | 9216 | 5.08 | 8,192 | 16,384 | 27,477 |
| 200 | 32 | 97.7 | 97.7 | 100.0 | 9012 | 4.47 | 8,192 | 32,768 | 54,457 |

Every cell recorded **zero** UDP receive-buffer drops, zero retransmissions,
zero source-backlog overflow, zero datapath-queue overflow and zero local
drops, and established every connection on both sides. `p95`/`p99` are
bucket upper bounds clamped to the measured maximum — see
[reading-results.md](reading-results.md).

### What the data says

1. **Delivery does not depend on the receive quantum.** `deliv%` is 100.0 in
   all fifteen cells. Whatever the cap costs, it is not costing packets.
2. **The largest caps are the only ones that fall short.** The three cells
   below 100% offer at 200 connections are caps 16 and 32 (98.5%, 97.7%);
   cap 32 also has the worst tail lateness at both 64 (max 69.9 ms) and 200
   (max 54.5 ms) connections. Draining harder does starve timers, mildly, and
   only at the top of the range.
3. **Syscall efficiency barely moves.** `datagrams/syscall` spans 4.10–5.50
   with no clean ordering by cap, so the efficiency argument for a larger
   quantum does not show up at these densities. That was the main reason to
   consider raising it, and the data does not support it.
4. **8 is never the worst.** At 16 connections it ties the best p99; at 64 it
   has the best p99 (4,096 us) and the lowest CPU (3,808 ms); at 200 it holds
   100% offer while 16 and 32 do not.

**Conclusion: `--recv-rounds 8` is retained, now with evidence.** It is not
shown to be *optimal* — the differences between 4, 8 and 16 are within the
run-to-run spread on a shared 6-core host — but it is the only value that is
never worst at any tested density, and nothing in the sweep argues for moving
it. No adaptive policy is warranted: no fixed value behaved unacceptably.

### Caveats

- One 6-core host, sender and listener sharing it. Any receiver-side setting
  that changes receiver CPU also changes what is left for the sender, so
  differences of a percent or two in `offer%` should not be read as caused by
  the cap.
- Three reps per cell. Enough to see the cap-32 tail, not enough to separate
  4 from 8 from 16.
- 1 Mbit/s per connection. A higher per-connection rate exercises the sender
  loop rather than the receive quantum (see below).

### A finding this sweep produced by accident

The first attempt at this sweep used `--ingress per-port`, which has **no
receive instrumentation at all** — every lateness and datagrams/syscall figure
came back zero. The second attempt was run against a build in which the
outbound retry queue capped its *input* batch, so a pooled listener at 200
connections silently discarded ~250,000 acknowledgements and the whole table
read 63–91% offer. Both were caught before any number here was published; the
queue bug is described in
[bench-queue-inventory.md](bench-queue-inventory.md#where-the-bound-is-enforced).

Separately, at 8 Mbit/s per connection the per-connection Tokio sender cannot
offer its configured source rate (roughly 50–63% at 16–200 connections),
because that path emits at most one packet per wakeup and the wakeup rate
becomes the binding constraint. That is a sender-loop limitation the source
clock made visible for the first time; it is unrelated to the receive quantum
and is left as a follow-up.

## Outbound `WouldBlock` policy

### What is settled

Retained output is bounded and observable. It used to be an unbounded
`VecDeque` in mio's shared sender and a fixed 4,096 in Tokio's; it is now one
`RetryQueue` with a workload-derived capacity, and `retry_*` plus
`local_dropped` are in every result row. A clean cell requires
`local_dropped = 0`. `retain` and `drop` are explicit, recorded policies
rather than an implicit behaviour.

### What is *not* settled

**Issue #36's actual policy question — is retaining the tail better than
dropping it and letting SRT recover? — is not answered here, and this PR does
not close that half of the issue.**

Across all 90 rows of the receive-round sweep, plus a dedicated retain/drop
comparison, the kernel returned `WouldBlock` **zero times**.

The comparison was deliberately hostile to the sender: `tokio`, 150
connections of 4 Mbit/s through **one** shared-egress UDP socket with
`SO_SNDBUF` forced down to 32 KB, listener on `shared-pool:1` with a 16 MB
receive buffer, 3 reps per arm. Medians:

| metric | retain | drop |
|---|---:|---:|
| `would_block` | **0** | **0** |
| retry capacity (per queue) | 14,212 | 14,212 |
| retry high-water | **0** | **0** |
| retry overflow | 0 | 0 |
| `local_dropped` | 0 | 0 |
| offer% / good% | 93.8 | 89.7 |
| deliv% | 100.0 | 100.0 |
| caller retransmits / loss-list | 0 / 0 | 0 / 0 |
| listener rcvbuf drops | 139,295 | 130,839 |
| CPU ms | 8,547 | 8,865 |

The retry queue's high-water mark is **zero**: the socket accepted everything
offered on every single flush, so the queue never held a datagram across a
tick and the two policies had nothing to be different about. That is true even
though the cell is genuinely overloaded — the listener dropped ~130k datagrams
in the kernel receive queue. Inbound saturates long before outbound
backpressures.

The offer% gap between the arms (93.8 vs 89.7) is therefore **not** a policy
effect and must not be read as one; with the mechanism unexercised it is host
noise on an overloaded shared box.

Answering it properly needs a workload that reliably induces outbound
`WouldBlock`. A small `SO_SNDBUF` is not enough (above); the next thing to try
is a rate-limited link via `--link-rate` with a short `txqueuelen`, so the
qdisc backpressures the socket rather than absorbing the burst — which needs
the netem namespace and therefore privileges CI does not always have. Only then
does a comparison on retransmissions, loss-list occupancy, delivery and
recovery latency mean anything. That is tracked as a follow-up rather than
claimed here.

The unit and integration tests do prove the *mechanism*: under a synthetic
`WouldBlock`, `retain` keeps the exact unsent tail and `drop` discards it and
counts what it discarded; retained work never exceeds capacity; and trimming
keeps the oldest datagrams so retention cannot reorder protocol output.
