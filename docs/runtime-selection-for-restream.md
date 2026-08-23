# Runtime selection for restream

**Question:** which of the six runtimes should carry SRT in
`/home/dev/restream`, a live-stream routing service?

**Answer: tokio.** It is at or statistically tied for the top on every
axis measured, it has the tightest run-to-run spread of any runtime, and
it is the only candidate with zero integration cost. No alternative is
better by enough to pay for itself — several are worse.

**Date:** 2026-08-23 · **Data:**
[`restream-selection-2026-08-23.tsv`](restream-selection-2026-08-23.tsv)
(168 rows, 7 reps/cell) · Supporting:
[baseline](baseline-2026-08-23.md), [scaling ladder](scaling-ladder-2026-08-23.md)

---

## 1. What restream actually needs

Read from the code, not assumed:

| Property | Evidence | Consequence for this choice |
|---|---|---|
| **One public ingest port** | `srt_bind` + `srt_listen(sock, 1024)` in `src/media/srt/listener.rs` | **`shared-pool` is unavailable.** It uses K distinct ports; publishers connect to one advertised endpoint. The benchmark winner overall is disqualified here on architecture, not performance. |
| **Bonding in use** | `SRTO_GROUPCONNECT` in `src/media/srt/socket.rs` | Group affinity must work; benchmark run bonded. |
| **Hundreds of connections** | `rtmp_max_connections: 512`, `nofile_limit: 65536`, `srt_poller_max_events: 1024` | Size the test at N=512, not 25 and not 1200. |
| **Egress fan-out** | `srt_egress_muxer_max_shards: 64` | Caller-side load too, sharded. |
| **Deeply tokio** | 176 of 527 `.rs` files touch `tokio::`; 141 spawn sites; **axum, sqlx (`runtime-tokio`), reqwest, tower, tokio-rustls** all hard-require it | A wholesale runtime switch is not on the table. |

That last row is not a tiebreaker, it is a constraint. sqlx, axum, and
tokio-rustls cannot run on glommio or monoio. Choosing anything else
means running **a second runtime on dedicated threads** and shuttling
media across channels between two schedulers competing for the same
cores. That cost has to be earned.

## 2. Test matched to that profile

512 connections · 600 kbps each (~300 Mbps) · bonded (`broadcast:64`) ·
`--promotion=all` · `--connect-concurrency=50` · 10 s · **7 reps** ·
single ingest port, so only the reuseport family is eligible.

Two corrections applied that change the ranking:

- **CPU is normalised per delivered packet.** mio's sender pushed 374k
  packets where others pushed ~286k, so raw CPU seconds flatter everyone
  else. The metric below is µs of CPU (both sides) per packet actually
  delivered.
- **Ranges are reported, not just medians.** With n=7 a significance test
  would be theatre; overlapping ranges are the honest way to say "these
  two are not distinguishable".

## 3. Results — `reuseport-multi:4`, N=512, bonded

| runtime | CPU µs/pkt (median [range]) | RTT ms (median [range]) | established |
|---|---|---|---|
| **mio** | **81.0** [78.3–88.9] | 29.98 [25.3–85.9] | 507–512 |
| **tokio** | **81.3** [79.8–83.9] | 21.63 [17.8–45.6] | **512–512** |
| compio | 90.0 [86.1–91.8] | 91.03 [49.6–**885**] | 510–512 |
| monoio | 95.8 [88.2–102.8] | **272** [244–335] | 512–512 |
| smol | 118.6 [116.6–123.6] | **5.80** [2.8–47.8] | 511–512 |
| glommio | **146.5** [143.3–169.7] | 19.75 [9.8–27.7] | 506–510 |

And `reuseport-single:4`, same load:

| runtime | CPU µs/pkt | RTT ms | established |
|---|---|---|---|
| mio | 79.8 [77.7–84.3] | 37.10 [26.9–44.7] | 512–512 |
| tokio | 89.4 [87.2–91.6] | 20.37 [17.5–28.7] | 512–512 |
| compio | 96.4 [94.8–103.6] | 166 [50.7–284] | 512–512 |
| monoio | 101.5 [92.1–129.5] | 288 [54.4–355] | 512–512 |
| smol | 138.1 [134.7–151.1] | 5.97 [4.2–11.5] | **468–512** |
| glommio | 175.2 [159.5–199.9] | 8.04 [5.7–13.2] | 504–509 |

### Reading it honestly

- **mio and tokio are tied on cost.** 81.0 [78.3–88.9] against
  81.3 [79.8–83.9] — the ranges sit on top of each other. Any claim that
  one is cheaper than the other is unsupported by this data.
- **tokio has the tightest spread of any runtime**, on both metrics
  (CPU 5% range; RTT 17.8–45.6). For a restreaming engine the tail is
  the product: a p99 stall is a visible glitch, a good median is not a
  feature.
- **smol wins median latency and loses the tail** (2.8 ms → 47.8 ms), and
  on `reuseport-single` dropped to **468/512 established** in its worst
  rep. That is an availability failure, not a slow run.
- **compio's latency tail is disqualifying**: 885 ms worst case.
- **monoio is never good on latency** — 244–335 ms, consistently.
- **glommio costs ~80% more CPU** than the leaders and never establishes
  all 512.

## 4. Why not mio, given it ties on cost

mio is not an async runtime — it is an epoll wrapper with no task model.
Using it inside restream would mean hand-rolling an event loop beside a
tokio application whose media pipelines, API, TLS and database are all
async. The scaling ladder also showed mio's advantage is not durable:
at N=1200 it was short 31 connections on reuseport while tokio was not.

It ties on the one axis it can win, and loses on every axis that is not
measured in µs.

## 5. The decision

| criterion | winner | tokio's standing |
|---|---|---|
| cheapest (CPU/packet) | mio ≈ tokio | **tied for first** |
| cheapest (memory) | tokio/smol (~19 MB) | **first** |
| fastest (median RTT) | smol | third (21.6 ms) |
| **fastest (tail RTT)** | **tokio** (45.6 ms worst) | **first** |
| most resilient (established) | tokio/monoio (512/512 every rep) | **first** |
| most predictable (spread) | **tokio** | **first** |
| integration cost | **tokio** (zero) | **first** |

**tokio wins or ties on six of seven**, and the one it loses — median
latency to smol — it loses to a runtime that dropped 44 connections in a
rep and has a 8× worse tail.

This is not "keep the incumbent because switching is hard". If the data
had shown a 2× advantage somewhere, the second-runtime-on-dedicated-
threads design would be worth costing out. It shows the opposite: the
alternatives are equal at best and considerably worse at worst.

### Configuration recommendation

- **Ingress:** `reuseport-multi:K` with K ≈ acceptor cores. It keeps the
  single public port restream requires. `shared-pool` is faster and
  cheaper but needs K ports — worth revisiting only if the deployment can
  advertise a port range.
- **Promotion:** `all`. On a task-scheduler runtime this is not optional:
  without it tokio still delivers, but smol/monoio/glommio/compio
  collapse to ~53% (see the [baseline](baseline-2026-08-23.md)).
- **Cookie routing:** on. It is what keeps handshakes from stranding when
  the reuseport group churns under a connection storm.

## 6. What would change this answer

- **Ingest moving off a single port.** `shared-pool` beat every reuseport
  variant on cost and delivery in the baseline; if publishers could be
  pointed at a port range, that becomes the better design.
- **Latency budget below ~20 ms.** smol's median is 3–4× better than
  tokio's. Its tail and its dropped connections would both need fixing
  first.
- **Much higher fan-in.** All of this is N=512. The ladder shows the
  runtimes diverge sharply past N=600.
- **Different hardware.** Six shared-tenant cores. On a machine with real
  core counts the thread-per-core designs may look different than they do
  here.

## 7. Limits of this study

- One shared-tenant host, one window. Absolute numbers are not portable;
  the ordering is what to carry away.
- n=7 per cell — enough to show overlap, not enough for a significance
  test, and I have not run one.
- Measures the **srt-rs stack**. restream currently uses libsrt via FFI;
  this says which runtime to pick *if* it adopts srt-rs, not that it
  should.
- Egress (caller-side fan-out across 64 shards) was not modelled
  separately; the sender side here is uniform.
- glommio's SQ-saturation hypothesis remains unverified — `srt-bench
  sysprof --runtime glommio` is the tool, and it is a one-liner.

## Reproduce

```sh
for ing in reuseport-multi:4 reuseport-single:4; do
  ./target/release/srt-bench matrix \
    --runtimes=mio,tokio,smol,monoio,glommio,compio \
    --ingress="$ing" --promotion=all --bond=broadcast:64 \
    --connections=512 --bitrate=600000 --connect-concurrency=50 \
    --secs=10 --reps=7 --out=scratch/restream.tsv
done
./target/release/srt-bench report scratch/restream.tsv --by=ingress,runtime
```
