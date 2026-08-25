# CPU budget: what the benchmarks are actually measuring

Short version: until now the benchmarks controlled CPU **implicitly and
by accident**. They are now explicit (`--cpus`, `--pin`), and the budget
is recorded in every result row. This changes how the existing numbers
should be read — not what they say, but what they are evidence *of*.

## 1. Nothing is compute-bound

Measured across six runtimes at 512 connections on a 6-core host:

| runtime | mean CPU utilisation, 6 cores |
|---|---|
| glommio | 28.2% |
| mio | 27.6% |
| smol | 22.3% |
| monoio | 17.4% |
| compio | 16.9% |
| tokio | 14.8% |

**Nothing exceeds 30%.** Every ranking produced so far is therefore about
**per-thread efficiency and scheduling latency**, not about throughput
ceilings or how well a runtime uses many cores. Adding cores would not
have moved these numbers; the bottleneck is serialisation inside
individual threads.

That reframes several earlier findings. When four runtimes delivered ~53%
without `--promotion=all`, the machine was mostly idle — the shared
listener loop was serialising work that no amount of CPU could unblock.
The fix was structural, and the utilisation numbers say so independently.

## 2. How parallelism was being set

Not by core count. By our own knobs, and only those:

| runtime | executor model in srt-bench | threads |
|---|---|---|
| mio | one `Poll` per acceptor thread | K (or 1+W) |
| tokio | `new_current_thread` + `LocalSet` per thread | K |
| smol | `async_executor::LocalExecutor` per thread | K |
| monoio | `RuntimeBuilder` per thread | K |
| glommio | `LocalExecutorBuilder` per thread | K |
| compio | `Runtime` per thread | K |

Three things follow, and they were all accidental:

1. **No runtime detects the core count.** `srt_lifecycle::worker_count()`
   exists for exactly this and the bench never called it. Parallelism is
   whatever `--ingress reuseport-multi:K` says.

2. **tokio's multi-threaded scheduler is never exercised.** Every
   backend, tokio included, gets K *single-threaded* executors. That is
   deliberate — `Conn` holds `!Send` native timers, which is why
   `LocalSet` is used — but it means these results say nothing about
   tokio's work-stealing scheduler, which is what most applications
   actually run.

3. **Thread-per-core runtimes were tested unpinned.** glommio's
   `LocalExecutorBuilder::default()` is `Placement::Unbound`, and monoio
   was likewise free-floating. Both are designed around an executor
   *owning* a CPU, with its io_uring and caches local to it. Letting the
   scheduler migrate them tests them outside their own model — and
   glommio was the worst performer in every sweep.

Point 3 is a genuine confound, not a footnote. It is a plausible partial
explanation for glommio's results, and it was not a controlled variable.

## 3. Is the uniform model fair?

It has one real virtue: **every runtime gets the same parallelism
structure**, so differences are attributable to its I/O machinery rather
than to how many threads it decided to spawn. That is what makes the
comparison a comparison.

The cost is that runtimes whose value proposition *is* their threading
model are measured with that model neutralised. glommio and monoio are
the clear cases. tokio is a subtler one in the other direction: it is
being run in a mode that is not how it is usually deployed.

Both are now expressible rather than assumed:

```sh
# Same CPU set for both roles.
srt-bench matrix --cpus 0-3 ...

# Disjoint sets: give the listener four cores, the load generator two,
# so they cannot take cores back from each other.
srt-bench matrix --recv-cpus 0-3 --send-cpus 4-5 ...

# Let thread-per-core runtimes own their CPUs (glommio Placement::Fixed).
srt-bench matrix --pin on ...
```

The spec is a **set**, not a count: `0-3`, `0,2,4`, `0-1,4-5`. A count
would be worse than useless here — "give each side 4 CPUs" starting from
zero places both on the same cores and has them fight. Empty (the
default) leaves the inherited mask alone; `--pin off` (default) leaves
placement unbound. The resulting CPU count and the pin setting are
columns in the result TSV, so a run states its own budget.

Per-role sets matter because the two roles are not symmetric. Only one
side is usually the bottleneck, and giving it more cores is pointless if
the load generator simply expands to use them. Isolating them also
removes the largest remaining source of run-to-run variance once
utilisation is high.

## 4. Recommendation

- **Record the budget always.** A benchmark that does not state its CPU
  allocation is not comparable across machines. This is now automatic.
- **Constrain deliberately when comparing.** `--cpus N` makes runs
  reproducible on a different host, and stops a 6-core and a 64-core
  result from being silently mixed.
- **Treat `--pin` as an axis, not a default.** Pinning helps
  thread-per-core designs and can hurt others; sweeping it is the way to
  find out rather than picking a side.
- **Isolate the roles when running hot.** `--recv-cpus` / `--send-cpus`
  put them on disjoint cores. At <30% utilisation the contention is
  minor; at saturation it is the dominant confound, because the load
  generator and the thing under test are competing for the same cores.

## 5. What is still not controlled

- **Sender/receiver co-residency**, unless `--recv-cpus`/`--send-cpus`
  are set. They still share memory bandwidth and last-level cache even
  when pinned apart.
- **Shared tenancy.** The host is a shared VPS; other tenants are noise
  that `--cpus` does not remove.
- **NUMA.** Single-socket here, so not a factor; it would be on a bigger
  machine.
- **Record the run conditions.** Keep raw output in the local, gitignored
  `scratch/` directory and record the host, CPU allocation, runtime, and
  benchmark revision alongside any result shared outside the checkout.
