# srt-lifecycle

Runtime-neutral SRT admission, affinity, and ownership policy.
`publish = false`, `unsafe_code = "forbid"`.

The crate deliberately stops at the **lifecycle boundary**: it owns the
logical identity and assignment invariants that a listener and its worker
pool must agree on, and nothing else — no sockets, clocks, threads, event
loops, media delivery, or authorization.

The rule, stated as a test you can apply to any candidate addition:

> **This crate takes values and returns decisions. It never owns things.**

Time is a parameter (`is_terminal(…, now, …)`), never read from a clock;
wire bytes are decoded by [`srt-protocol`](../srt-protocol)
(`peek_handshake`) and only *interpreted* here. Anything that would hold
a live `SrtConnection`, a timer store, or an fd belongs in
[`srt-transport`](../srt-transport) instead — which is exactly where the
admission peer table lives, calling back into the policy defined here.

```
        decisions (this crate)          things (srt-transport)
        ──────────────────────          ──────────────────────
        WorkerRouter                    PeerTable / AdmissionPeer
        decide_promotion()              ManualTimerStore
        cookie_for_worker()             Handoff / WorkerMessage
        is_terminal()                   IngressTelemetry
        handshake_identity()            per-runtime Conn
```

## Problem it solves

An SRT listener fronting a multi-worker service must answer, from the
*first handshake datagram alone*, two questions before any protocol state
exists:

1. **Which logical publisher is this?** A bonding group arrives as N
   independent physical legs; they must be recognized as one publisher.
2. **Which worker owns this leg?** All legs of one group must land on the
   same worker, or bonded failover/broadcast breaks.

Both answers are decodable straight off the wire (handshake CONCLUSION +
StreamID + GROUP extension), which is exactly what this crate does.

## API

### Wire decoding (pre-admission)

```rust
use srt_lifecycle::{handshake_identity, handshake_route,
                    group_extension_from_packet};

// Full identity: phase + StreamID + GROUP affinity
let id: Option<HandshakeIdentity> = handshake_identity(&datagram);
// HandshakeIdentity { is_conclusion, stream_id, group: Option<GroupAffinity> }

// Cheap variants when you only need routing / group metadata
let route: Option<(bool, Option<GroupAffinity>)> = handshake_route(&datagram);
let (ext, sid) = group_extension_from_packet(&datagram).unwrap();
```

`GroupAffinity { group_id, stream_id, extension }` →
`logical_key()` gives the stable `LogicalGroupKey { group_id, stream_id }`
used to pin legs together. `normalize_stream_id()` is applied only at
this one boundary so wire-format variations don't split one publisher in
two.

### Worker assignment

```rust
use srt_lifecycle::{WorkerRouter, RoutingMode, worker_count};

let n = worker_count(requested, available_parallelism); // clamped 1..=cores
let mut router = WorkerRouter::new(n);

let worker = router.assign(transport_key, group_affinity, RoutingMode::LeastTuples);
router.release(&transport_key); // returns Some(LogicalGroupKey) when its last leg left
```

- Generic over `K: Eq + Hash + Clone` — *your* transport key shape (peer
  socket tuple, tuple+socket-ID, …); the policy never imposes one
  runtime's key on another.
- `assign` preserves existing owners: same tuple → same worker; new tuple
  with an already-pinned `LogicalGroupKey` → the group's worker.
- `RoutingMode::RoundRobin` or `LeastTuples` for unaffiliated tuples.

### Promotion ladder

Once a connection reaches `Connected`, something has to decide whether it
gets its own connected socket. That decision used to live as six
hand-written copies inside the runtime adapters, which is how their
telemetry silently drifted apart. It is policy, so it lives here:

```rust
use srt_lifecycle::{decide_promotion, Promotion, PromotionDecision, RoutingMode};

let decision = decide_promotion(
    Promotion::Bonded,   // mode
    peer,                // transport key
    group,               // Option<GroupAffinity> from the handshake
    worker_index,
    &mut router,
    RoutingMode::LeastTuples,
);
match decision {
    PromotionDecision::StayOnListener => {}          // shared listener keeps it
    PromotionDecision::PromoteHere    => { /* own socket, this worker */ }
    PromotionDecision::RelocateTo(w)  => { /* own socket, hand to w */ }
}
```

The modes nest — `Never ⊂ Relocate ⊂ Bonded ⊂ All` — and that nesting is
a property test, not a convention: widening the mode can only ever grow
the set of promoted connections.

Under `Never` the router is not consulted at all, so affinity state stays
empty and legs remain wherever the kernel hashed them. That is the
diagnostic control which says what affinity plus relocation actually buy.

### SYN-cookie routing

With several acceptors on one SO_REUSEPORT port, the kernel can rehash a
flow *between* its INDUCTION and CONCLUSION, stranding the handshake on
an acceptor that holds no cookie state for it. The listener chooses the
cookie and the caller echoes it, which makes the cookie the one field on
the wire able to carry listener-chosen routing data through a handshake:

```rust
let cookie = cookie_for_worker(worker_index, peer_entropy);   // low byte = owner
let owner  = worker_from_cookie(observed_cookie, worker_count); // Option<usize>
```

`None` means "no usable routing information" — handle it locally rather
than dropping it.

## Position in the stack

```
handshake datagram ──► srt-lifecycle (admit? which worker?)
                              │ worker index
                              ▼
              per-worker event loop owns srt-transport::Conn
                              │ drives
                              ▼
                srt-protocol::SrtConnection state machine
```

Consumed by listener/worker code in this workspace's harness binaries;
the protocol crate itself has no dependency on it.

## Tests

```sh
cargo test -p srt-lifecycle   # unit tests live in src/lib.rs
```
