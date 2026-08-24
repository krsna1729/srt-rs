# srt-transport

Application-facing configuration and adapter plumbing between
[`srt-protocol`](../srt-protocol) (sans-I/O) and runtime-specific I/O.
Per-runtime `Conn` structs are feature-gated; the configuration, admission,
socket preparation, and lifecycle surfaces are runtime-neutral.

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
   - `SessionConfig`, `TransportConfig`, `AdmissionConfig`, `CallerConfig`,
     and `ListenerConfig` — layered application configuration with capability-
     checked `Auto` policies, profiles, typed units, and raw escape hatches.
   - `SrtStackConfig` — retained low-level compatibility surface for existing
     consumers; new applications should use the layered types above.

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
     so two backends' output means the same thing. `snapshot()` returns a
     plain exporter-friendly `IngressTelemetrySnapshot`; `report()` is only
     the human-readable view.

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
srt-transport = { git = "https://github.com/shiguredo/srt-rs", rev = "<audited-commit>", features = ["tokio"] }
```

Use a pinned revision until the runtime crates pass the separate crates.io
publication gate. Path dependencies are equivalent for workspace consumers.

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
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Duration;
use srt_transport::{
    Bandwidth, BatchingPolicy, EncryptionConfig, ListenerConfig,
    PromotionPolicy, SessionConfig, TransportProfile,
};

let mut session = SessionConfig::default();
session.set_latency(Duration::from_millis(120))?;
session.set_bandwidth(Bandwidth::BitsPerSecond(
    NonZeroU64::new(100_000_000).unwrap(),
));
session.set_encryption(Some(EncryptionConfig::new("production secret")));
session.set_stream_id(Some("publish/live".to_owned()));

let listener = ListenerConfig::builder("0.0.0.0:9000".parse()?)
    .session(session)
    .profile(TransportProfile::HighDensity)
    .configure_transport(|transport| {
        // Presets are ordinary configs: override any decision.
        transport.promotion = PromotionPolicy::Bonded;
        transport.batching = BatchingPolicy::MaxDatagrams(
            NonZeroUsize::new(32).unwrap(),
        );
    })
    .configure_admission(|admission| {
        admission.limits.max_peers = 8_192;
        admission.limits.max_half_open_peers = 1_024;
        admission.limits.max_peers_per_ip = 256;
    })
    .build()?;

// Inside a Tokio runtime. The returned prepared policy owns no event loop:
// use the supplied sockets/PeerTable directly or compose your own workers.
let runtime_listener = srt_transport::tokio_transport::bind_listener(&listener)?;
let peers = runtime_listener.prepared.peer_table();
let admission = runtime_listener.prepared.admission_options();
```

### Per-StreamID listener policy

The listener sees the caller's claimed StreamID in CONCLUSION, after cookie
validation but before KM processing. A cached resolver can select a tenant
passphrase and other handshake policy atomically:

```rust
use shiguredo_srt::KeyLength;
use srt_transport::{
    AdmissionResolution, ListenerEncryptionConfig, ListenerPeerPolicy,
    PolicyOverride, RejectionReason,
};

let outcome = peers.admit_with_resolver(
    peer,
    datagram,
    now,
    &admission,
    worker_index,
    worker_count,
    &telemetry,
    |request| {
        let Some(user) = request
            .access_control
            .as_ref()
            .and_then(|access| access.user_name())
        else {
            return AdmissionResolution::Reject {
                reason: RejectionReason::BAD_REQUEST,
            };
        };
        let Some(passphrase) = cached_tenant_passphrase(user) else {
            return AdmissionResolution::Defer;
        };
        AdmissionResolution::Configure(ListenerPeerPolicy {
            encryption: PolicyOverride::Set(Some(
                ListenerEncryptionConfig::new(passphrase, KeyLength::Aes128)
                    .expect("validated secret store entry"),
            )),
            ..ListenerPeerPolicy::default()
        })
    },
);
```

StreamID and access-control fields remain application claims; successful KM
proves possession of the selected shared credential, not general identity.
Resolvers run synchronously and should perform only bounded cached work.
`Defer` leaves the peer's original hard TTL unchanged. Multiple policy sources
can compose with `ListenerPeerPolicy::overlay`; `Inherit` never erases a
lower-priority decision. `admit_with_connection_hook` exposes
`&mut SrtConnection` in the same guarded window for future or
application-specific protocol controls;
`admit_with_authorizer` remains the raw rejection-code compatibility API.
Reuseport loops can use `admit_and_forward_with_resolver` so only the worker
that owns the half-open peer performs credential resolution.

The ten reusable benchmark controls are represented: latency, bandwidth,
group/bond metadata, promotion, cookie routing, socket buffers, ingress
topology, receive batching, workers, and caller-pool concurrency. The 15-second
attempt deadline and bounded output drain are advanced controls. CPU affinity,
connection count/workload generation, link impairment, run duration,
repetitions, and result paths remain application/deployment concerns.

`Auto` is resolved against `RuntimeFlavor`/`TransportCapabilities` and the
result is exposed as `ResolvedTransportConfig`; an explicitly requested
unsupported mechanism is an error, never a silent no-op. Applications with a
custom executor can pass `RuntimeFlavor::Custom`. Consumers that need more
control can mutate the complete raw `ConnectionOptions`, use the returned
`std::net::UdpSocket`s, instantiate any runtime `Conn` directly, or bypass the
builders entirely. Those are supported composition points, not private
implementation details.

## Consumers

- [`srt-bench`](../srt-bench) — enables **all six features** and builds
  one adapter binary per runtime for the bake-off.
- Application code should pick one feature and depend on only that
  module (`srt_transport::<runtime>_transport::Conn`).
