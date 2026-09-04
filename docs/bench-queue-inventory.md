# Benchmark queue inventory

Every queue reachable from `srt-bench` is classified by what can feed it.
Packet-rate queues have a hard capacity independent of run duration and report
high-water/full/drop counters. Finite lifecycle queues retain their simpler
channel, but "finite because the run ends" is not a bound — each one below
states the arithmetic upper bound on its occupancy.

## How packet-rate capacities are chosen

Packet queues are sized by a **horizon**, not a constant:

```
capacity = horizon_ms/1000 × peers_per_socket × (source_bps ÷ 8 ÷ 1316)
           clamped to [64, 65536]
```

A bare `4096` was a hidden workload constant: at 8 Mbit/s with 1316-byte
payloads it is roughly five seconds of one stream's data, and at 250 kbit/s
well over a minute — the same number meaning wildly different amounts of
buffering from cell to cell, and none of it interpretable. A horizon is bounded
by *rate and fan-in*, never by run duration, and says something a reader can
act on: "this queue may absorb a quarter second of the load aimed at it before
the harness itself is what is behind."

Both horizons are configurable (`--datapath-queue-horizon-ms`,
`--outbound-retry-horizon-ms`) and default to 250 ms.

`peers_per_socket` is **one** notion, deliberately, because both directions
travel through the same socket: a listener's is `ceil(conns / K)` for a pooled
or reuseport socket and 1 for per-port, and a sender's is `conns` for shared
egress and 1 for per-connection. Deriving it from an unrelated topology knob is
not a theoretical risk — sizing the listener's outbound queue from `egress`
under-provisioned it ~50× at 200 connections and dropped ~250,000
acknowledgements, and sizing a shared-egress sender's inbox from `ingress` was
the same mistake pointing the other way. Both are now one helper.

It over-provisions a promoted per-connection socket on a pooled listener, which
is the safe direction and keeps capacity uniform across the process — which is
what makes a single `capacity_per_queue` worth reporting.

## Reading the scopes

A process owns many of these queues at once, so every reported figure names its
scope. Merging per-queue snapshots and publishing the maximum under a name like
"high water" reads as process state while meaning "the worst any single queue
got" — and at 1000 connections those are very different claims.

| column | scope |
|---|---|
| `datapath_q_cap_per_queue` | one queue |
| `datapath_q_count` | how many queues exist |
| `datapath_q_total_cap` | the whole benchmark-owned buffer pool |
| `datapath_q_peak_depth_max` | the deepest any **single** queue got |
| `datapath_q_peak_depth_sum` | the **sum of every queue's own peak** — an upper bound on what the harness ever held at once, not a measured simultaneous total |
| `retry_cap_per_queue` / `retry_count` / `retry_total_cap` / `retry_peak_depth_max` | the same, for retained outbound work |

`datapath_q_peak_depth_sum` is an upper bound rather than a measurement on
purpose. A true running total needs a process-global counter updated on every
enqueue and dequeue — two contended atomics on the per-packet path of a tool
whose entire job is measuring that path. The bound answers the question that
matters ("could the harness have been accumulating across many queues?") for
free, and a benchmark that pays to measure itself is measuring the wrong thing.

## Packet-rate and buffer queues

| queue | class | capacity | full policy / evidence |
|---|---|---|---|
| `SourceClock::pending` | source backlog | source packets in `source_backlog_ms` (250 ms), minimum 8 | O(1) counter; excess increments `src_overflow` |
| Compio connection reader inboxes | packet datapath | horizon rule | reject newest without blocking; `datapath_q_*` |
| Compio shared-sender/listener inboxes | packet datapath | horizon rule | reject newest without blocking; `datapath_q_*` |
| Monoio acceptor reader inbox | packet datapath | horizon rule | reject newest; replaces the previous silent drop-oldest safety net |
| Glommio acceptor reader inbox | packet datapath | horizon rule | reject newest; replaces the previous silent drop-oldest safety net |
| Compio/Monoio receive-buffer recycle channels | buffer recycle | same capacity as the associated inbox, so it can never exceed the buffer pool it returns to | discard a returned spare when full; the reader reuses/allocates a buffer, so no packet result is hidden |
| Tokio shared-socket retained output | outbound retry | horizon rule, outbound horizon | retain (default) or explicit drop on `WouldBlock`; `retry_*` and `local_dropped` |
| Mio shared-sender retained output | outbound retry | horizon rule, outbound horizon | same bounded `RetryQueue` as Tokio's; previously an unbounded `VecDeque` that each tick extended and drained only until the socket yielded, so any sustained shortfall accumulated for the rest of the run with nothing in the row to say so |
| Transport `Conn::pending_outputs` | outbound retry | `OutputDrainBudget` (64 default) per drain | retained on `WouldBlock`; protocol-order invariant preserved |

## Lifecycle and control queues, with their arithmetic bounds

These keep their simpler unbounded channel. Adding synchronisation to a queue
that cannot receive at packet rate would cost throughput to make a spelling say
"bounded", so instead each states the number it cannot exceed.

| queue | class | upper bound on total items | why |
|---|---|---|---|
| Runtime `WorkerMessage` channels | connection lifecycle/control | `conns × ceil(CONNECT_TIMEOUT / handshake_retry_interval) + conns + workers` | The first term is the worst-case handshake traffic routed between acceptors: a connection can retry at most once per `handshake_retry_interval` (default 250 ms per `DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS`) for at most `CONNECT_TIMEOUT` (25 s), so ≤ 100 messages per connection; the second is at most one ownership handoff per connection; the third is one completion message per worker. At 1200 connections and 4 workers that is ≤ 121 204 messages over the whole run, and it cannot grow with run duration because the connect window is fixed. |
| `ConnectLimiter` FIFO/waiter map | connection lifecycle | `2 × logical_streams` | At most one live waiter per stream plus at most one tombstone left by a cancelled waiter; each tombstone is skipped once and discarded. |
| `SharedSender::pending_start` | connection lifecycle | `logical_streams` | One entry per configured stream, removed when admission starts it. |
| `SharedSender::dirty_ready` | control/readiness | `logical_streams` | The `dirty` flag deduplicates, so a stream cannot be queued twice. |
| `SharedSender` deadline/scratch collections | control/timer | `3 × logical_streams` | At most one live deadline per stream per `AppDeadlineKind`; replacement removes the previous indexed deadline. |
| Harness listener-ready channel | control | 1 | One marker or one EOF result per child. |

## Where the bound is enforced

`RetryQueue` is two-phase on purpose: `append` takes a whole tick's generated
output, and the capacity bound is applied inside `flush_with`, *after* the
socket has had its chance at it.

Bounding on the way in instead looks safer and is worse: it discards datagrams
the socket was never offered and would have accepted. At 200 connections a
pooled listener generates far more than one queue-depth of acknowledgements per
tick, and the input cap threw ~250,000 of them away without a single
`WouldBlock` to explain where they went. What must be bounded is what the socket
*refused*, which is what persists across ticks; a burst the socket takes is not
a backlog. Transient occupancy is therefore one tick's generation (bounded by
the connection count); steady-state occupancy is bounded by `capacity`.
`retry_peak_depth_max` is recorded after the trim, so it measures retained depth
against the capacity it is printed beside. A debug assertion catches an `append`
that is not followed by a flush.

## What a clean cell requires

- `src_overflow = 0` — the source was serviced.
- `datapath_q_dropped = 0` — no packet queue rejected work for want of capacity.
- `local_dropped = 0` — the harness discarded no outbound datagram locally.
  (`retry_overflow` is one *reason* inside that total, not a second loss to add
  to it.)

`datapath_q_disconnected` is reported but deliberately **not** part of the
predicate: a send to an already-gone consumer is a shutdown-ordering fact, not
evidence the queue was too small, and folding the two together would make an
ordinary teardown race read as overload.

`datapath_q_cap_per_queue = 0` means the runtime path has no benchmark-owned
packet queue at all.

## Known limitation

Zero overflow does not by itself prove queue *stability*. A finite-duration cell
can accumulate a large standing backlog without ever reaching capacity — a queue
that starts at 0 and ends at 3000 against a capacity of 4096 has zero overflow
and is not stable capacity. `datapath_q_peak_depth_sum` makes that visible,
but the harness does not yet record start/end depth or a backlog slope. That
belongs with the capacity classifier (#71), and until it exists, read a large
peak total depth as a warning even when overflow is zero.

## Evidence

The unit and property tests in `queue.rs` force every bounded queue to capacity
and verify state never grows beyond it, that a full queue is visible and
nonblocking, that a disconnected consumer is counted apart from a capacity
rejection, and that merging keeps per-queue and aggregate scopes distinct. `scheduling.rs`
additionally proves that work the socket accepts is never dropped however far it
exceeds capacity, that what the socket refuses is bounded and counted, and that
trimming keeps the oldest datagrams so retention cannot reorder protocol output.
`tests/datapath_queue_bounds.rs` drives the same through a live runtime.
