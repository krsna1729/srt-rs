# srt-rs closeout scope (PR 1 of four)

Goal: finish `srt-rs` as a trustworthy shard engine, on the existing #118 branch,
without broadening it. This is the audit of what already exists, what is missing,
and what "done" means. It is deliberately **not** a plan for GSO, native io_uring,
a simulator, allocator experiments, new pooling, or more capacity-surface work --
all of that is post-cutover.

## What already exists (audited at `d005f9f`)

| Needed by Restream | Present | Where |
|---|---|---|
| `OwnerFault` typed state | yes | `runtimes/compio.rs:1745`, `Owner::fault()` |
| Fixed TX lanes + finite pool | yes | `TxPool`, `TxPoolSnapshot { capacity, free, exhaustions }` |
| Service budget | yes | `OwnerServiceBudget` (`max_tx_packets`, ...) |
| Bounded `service()` | yes | `Owner::service(now, budget)` |
| Managed RX + mode reporting | yes | `rx_mode()`, `rx_substrate()`, `OwnerRxMode`, `RxModePolicy` |
| No task/thread per connection | yes | the only `spawn` sites are the per-*socket* managed-RX loops (`spawn_managed_rx_loop`, `spawn_managed_rx_task`) |
| Backlog observability | partial | `due_index_snapshot()` (caller table), `tx_in_flight()`, `has_pending_work()` |
| RX counters | partial | `rx_stats()` gives socket-level dropped/truncated; SRT-level loss/duplicates live in receiver stats |
| Failure containment | partial | `OwnerFault` exists; TX-lane death must be proven to surface and stop admission |

So the architecture the four-PR plan requires on the srt-rs side -- one Owner per
shard, bounded service, fixed lanes, managed RX, no per-connection machinery -- is
**already the shape of the code**. The closeout is therefore correctness, a small
amount of telemetry, and freezing the contract, not a rewrite.

## Work item 1 (blocker): settle the conservation question

The intermittent deficit is the only correctness question open, and it must be
settled here rather than in a new instrumentation project.

1. **Receiver-recognized fence payloads with identity.** Today the fence is a
   differently-sized payload the *sink cannot distinguish*, so exclusion happens
   by arithmetic in the analysis and the receiver cannot snapshot at fence
   observation. Change the fence payload to carry a magic prefix plus
   `{peer_id, final_tick}`, and teach the receiver (in `srt-bench`, the
   `mode=receiver` path) to:
   * exclude fence payloads from `core_total` / `data_events`;
   * record per-peer `data_at_fence` -- the measured DATA count **at the moment
     the fence for that peer is observed**;
   * report the per-peer missing set (which tick ids never arrived), since only
     that distinguishes a suffix from a scatter.
2. **Repeat the A/B at ~10 repetitions per arm** (fence / no fence) at
   `F=50, R=8 Mbps, K=256, 60 s`. The current evidence is 2 per arm against a
   deficit that appears in roughly one run in three, which is not enough to
   establish a base rate.
3. **Classify with the four-branch table** already in the protocol document:
   snapshot race / tail needed later sequence progress / delivery-accounting
   defect / final-send lifecycle failure. The existing result (fence arm rep 1:
   277 payloads still missing after all 50 fences were accepted, pool saturated)
   already makes branch 1 insufficient on its own.
4. **Fix it if real.** If the deficit survives fences with `sec_a = 0`, it is a
   transport or accounting defect and belongs in the transport with a regression
   test that fails before the fix.

## Work item 2: the telemetry Restream needs, and no more

Exposure only; no new mechanics.

* **TX by class**: `tx_packets_submitted` is one aggregate. Split it at the point
  where the class is still known: `tx_data_first`, `tx_data_retx`,
  `tx_control_ack`, `tx_control_ackack`, `tx_control_nak`, `tx_control_other`.
  This is also what makes `r` decomposable instead of inferred.
* **First-submit lateness**: `scheduled_deadline -> first submission` per packet,
  p50/p99/max. This is the real-time metric the batching work will be judged by;
  offer lateness (already instrumented) is not it.
* **Pool pressure**: add `high_water` to `TxPoolSnapshot` (occupancy peak, not
  just instantaneous `free`), alongside the existing `exhaustions`.
* **RX loss/duplicates at the Owner**: surface SRT-level loss and duplicates
  (`total_lost`, `total_duplicates`) through the Owner's stats, not only through
  the bench receiver.
* **`OwnerFault` reachability**: prove with a test that a dead fixed TX lane
  surfaces as `OwnerFault`, stops new admission, and does not continue at silently
  reduced capacity.

## Work item 3: freeze the production contract

Pin the public surface Restream will build on, in one place, with a doc comment
stating what is guaranteed:

```text
Owner, OwnerServiceBudget, OwnerFault
TxPool, TxPoolSnapshot
OwnerRxMode, RxModePolicy, ManagedRxSubstrate, OwnerRxStats
ProductionRuntimeConfig, production_runtime_builder
due_index_snapshot, has_pending_work
```

No behaviour change: this is naming and documenting what is already stable, so
PR 2 has a contract to hold to.

## Work item 4: one clean canonical baseline

`F=50, R=8 Mbps/destination, K=256, 60 s, >= 3 repetitions`, from a **clean commit**
(artifact `git_dirty=false`), with every row passing the row-level gate. Every
artifact currently recorded as evidence for this operating point is
`git_dirty=true` because the harness was being changed while it ran; that is fine
for diagnosis and not fine as the baseline PR 2 pins to.

## Done means

* accepted DATA is conserved across the run, or the residual deficit is explained
  and attributed with a test;
* one Owner supports many callers, with zero tasks or threads per connection;
* every queue, pool and timer structure is finite, with its bound stated;
* a clean reproducible baseline exists and passes the gate on every repetition;
* the contract above is frozen and documented.

## Explicitly out of scope here

GSO, native io_uring, `srt-sim`, allocator comparisons, hugepages, NUMA media
replication, generic memory-pool frameworks, and further capacity-surface
exploration. Those are post-cutover, and the four-PR plan keeps them there.
