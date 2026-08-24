# srt-transport

Shared adapter plumbing between [`srt-protocol`](../srt-protocol)
(sans-I/O) and runtime-specific I/O. Per-runtime `Conn` structs behind
feature flags; `publish = false` — workspace-internal glue, not a
standalone product.

## Charter: this crate owns *things*

The dividing line against [`srt-lifecycle`](../srt-lifecycle) is
ownership, not subject matter. Both crates deal with admission:

* **lifecycle takes values and returns decisions.** No sockets, no
  clocks, no protocol objects; time is passed in.
* **transport owns things.** Live `SrtConnection`s, their timers, file
  descriptors, counters.

So the admission peer table lives here, even though the promotion rule it
consults lives there. This crate depends on lifecycle (mechanism uses
policy); lifecycle never depends on this one.

```
   srt-bench ──► srt-transport ──► srt-lifecycle ──► srt-protocol
                      │                                   ▲
                      └───────────────────────────────────┘
```

## What's inside

Three layers:

1. **Shared utilities** (always compiled, no runtime deps)
   - `NativeTimer` — `Pin<Box<dyn Future<Output = ()>>>`, the common shape
     of every async runtime's per-connection timer.
   - `is_ready(&mut NativeTimer)` — noop-waker poll; the one pattern that
     is genuinely identical across all five async runtimes.
   - `ManualTimerStore` — `HashMap<TimerId, Timestamp>` with O(n) scan on
     fire. The correct primitive for mio (no timer wheel) and the explicit
     fallback elsewhere.
   - `DueIndex<K>` — a lazy-deletion deadline heap for shared loops that
     own many connections. Per-connection timer maps stay small; the index
     prevents a separate O(peers) scan just to find which maps are due.
   - `OutputDrainBudget` / `OutputDrainReport` — explicit per-tick action,
     packet, and byte limits shared by all six output pumps. Send failures
     are returned and unsent datagrams remain queued in protocol order.
   - `SrtStackConfig` — validated protocol, admission, output-drain, cookie
     routing, and socket-buffer defaults for consuming applications.

2. **Admission machinery** (always compiled, runtime-neutral, does no I/O
   of its own — the caller performs every send)
   - `PeerTable` / `AdmissionPeer` — the peers one acceptor is servicing
     off its shared listener socket, from first datagram until the
     connection is promoted, relocated, or retired. Mints each
     connection's SYN cookie, applies cookie routing, and answers
     `all_terminal()`.
   - `poll_outbound()` uses a ready queue plus `DueIndex` to service only
     peers with input/output work or a due timer.
   - `poll_events()` returns unmodified `AdmissionEvent`s (including data
     payloads) for production consumers. `drain_events()` is the legacy
     benchmark adapter that folds those events into counters and promotion
     timing.
   - `Handoff` / `WorkerMessage` — the acceptor-to-worker protocol. A
     `Handoff` carries a plain `std::net::UdpSocket` plus a bare
     `SrtConnection` because both are `Send`, whereas every runtime's own
     `Conn` holds a `!Send` timer future. The cross-thread move is
     correct *by construction*: the type has no field a `!Send` timer
     could occupy.
   - `IngressTelemetry` — promotion/routing plus invalid-input, cookie,
     capacity, authorization, and half-open-expiry counters, defined once
     so two backends' output means the same thing.

3. **Per-runtime `Conn`** (feature-gated): wraps an `SrtConnection`
   + that runtime's UDP socket + its native timer. Each exposes the same
   small verb set: `fire_expired`, `drain_outputs`, `send_paced`,
   `recv_with_timeout` (async runtimes also get a combined `tick`).

## Feature flags

| Feature | Runtime | Timer inside Conn | I/O model |
|---|---|---|---|
| `mio` | raw epoll, no task model | `ManualTimerStore` + `poll_timeout()` | readiness |
| `tokio` | current-thread + tasks | native `Pin<Box<Sleep>>` | readiness |
| `smol` | async-executor tasks | `smol::Timer` future | readiness |
| `monoio` | thread-per-core | io_uring kernel timeouts | completion (owned buffers) |
| `glommio` | thread-per-core (Linux-only) | `glommio::timer` wheel | completion, shared SQ ring |
| `compio` | single runtime | `compio::time::sleep` | completion (owned buffers) |

Features are additive: enable exactly the ones your binary links.

```toml
[dependencies]
srt-transport = { path = "crates/srt-transport", features = ["tokio"] }
```

## Design: deliberately no lowest-common-denominator trait

A shared `trait Conn` spanning readiness-based (mio/smol/tokio) and
completion-based (monoio/glommio/compio) execution would force an LCD API
that defeats the point of comparing the runtimes on their own terms.
Instead each `Conn` uses its runtime's idiomatic primitives directly, and
"swappable" is achieved at the **binary/CLI level**: `srt-bench` selects a
backend by argument, not by trait object. Same rationale as
[`crates/srt-bench/README.md`](../srt-bench/README.md).

## Usage sketch (mio)

```rust
use srt_transport::mio_transport::Conn;

let mut conn = Conn::new(srt_connection, mio_socket);
let report = conn.drain_outputs_bounded(now, Default::default())?;
// A BudgetExhausted/Backpressured report means yield and service it again;
// unsent datagrams remain queued in order.
let timeout = conn.poll_timeout(Duration::from_millis(20), now);
// poll.poll(&mut events, Some(timeout)); ... feed datagrams to conn.conn
conn.fire_expired(now);                        // service due timers
```

Async runtimes instead offer `Conn::tick(&mut buf, &payload, now)` —
one event-loop iteration: fire timers → recv → drain outputs → send all
paced packets → return `io::Result<TickResult>`. Every adapter also exposes
`drain_outputs_bounded`; a budget or backpressure yield retains the tail.

## Application configuration

```rust
use std::time::Duration;
use srt_transport::{OutputDrainBudget, SrtStackConfig};

let mut stack = SrtStackConfig::default();
stack.connection.socket_id = 0x1000_0001;
stack.connection.tsbpd_delay = 200;
stack.connection.max_bandwidth_bytes_per_sec = Some(25_000_000);
stack.connection.flow_window_packets = 16_384;
stack.connection.receive_buffer_packets = 16_384;
stack.admission.max_peers = 8_192;
stack.admission.half_open_timeout = Duration::from_secs(5);
stack.output_drain = OutputDrainBudget::new(128, 64, 512 * 1024);

stack.validate()?;
let caller = stack.caller()?;
let peers = stack.peer_table()?;
let admission = stack.admission_options();
let socket = stack.bind_reuseport(9000)?;
# Ok::<(), std::io::Error>(())
```

The benchmark's runtime, ingress topology, worker count, CPU pinning,
promotion mode, connect concurrency, bonding workload, and network impairment
knobs are intentionally excluded: those choose deployment architecture or
generate a workload; they are not properties of an SRT connection stack.

## Consumers

- [`srt-bench`](../srt-bench) — enables **all six features** and builds
  one adapter binary per runtime for the bake-off.
- Application code should pick one feature and depend on only that
  module (`srt_transport::<runtime>_transport::Conn`).
