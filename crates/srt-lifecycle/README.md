# srt-lifecycle

Runtime-neutral SRT admission, affinity, and ownership policy.
`publish = false`, `unsafe_code = "forbid"`.

The crate deliberately stops at the **lifecycle boundary**: it owns the
logical identity and assignment invariants that a listener and its worker
pool must agree on, and nothing else — no sockets, clocks, threads, event
loops, media delivery, or authorization.

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
