# srt-transport

Shared adapter plumbing between [`srt-protocol`](../srt-protocol)
(sans-I/O) and runtime-specific I/O. Per-runtime `Conn` structs behind
feature flags; `publish = false` — workspace-internal glue, not a
standalone product.

## What's inside

Two layers:

1. **Shared utilities** (always compiled, no runtime deps)
   - `NativeTimer` — `Pin<Box<dyn Future<Output = ()>>>`, the common shape
     of every async runtime's per-connection timer.
   - `is_ready(&mut NativeTimer)` — noop-waker poll; the one pattern that
     is genuinely identical across all five async runtimes.
   - `ManualTimerStore` — `HashMap<TimerId, Timestamp>` with O(n) scan on
     fire. The correct primitive for mio (no timer wheel) and the explicit
     fallback elsewhere.

2. **Per-runtime `Conn`** (feature-gated): wraps an `SrtConnection`
   + that runtime's UDP socket + its native timer. Each exposes the same
   small verb set: `fire_expired`, `drain_outputs`, `send_paced`,
   `recv_with_timeout` (async runtimes also get a combined `tick`).

## Feature flags

| Feature | Runtime | Timer inside Conn | I/O model |
|---|---|---|---|
| `mio` (default) | raw epoll, no task model | `ManualTimerStore` + `poll_timeout()` | readiness |
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
conn.drain_outputs(now);                       // flush pending packets + timers
let timeout = conn.poll_timeout(Duration::from_millis(20), now);
// poll.poll(&mut events, Some(timeout)); ... feed datagrams to conn.conn
conn.fire_expired(now);                        // service due timers
```

Async runtimes instead offer `Conn::tick(&mut buf, &payload, now)` —
one event-loop iteration: fire timers → recv → drain outputs → send all
paced packets → return `TickResult { sent, events }`.

## Consumers

- [`srt-bench`](../srt-bench) — enables **all six features** and builds
  one adapter binary per runtime for the bake-off.
- Application code should pick one feature and depend on only that
  module (`srt_transport::<runtime>_transport::Conn`).
