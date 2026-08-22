# srt-rs

Pure-Rust SRT (Secure Reliable Transport) workspace: a sans-I/O protocol
core, runtime-specific transport adapters, a runtime-neutral admission
policy layer, and an executable benchmark harness that compares six async /
polling runtimes against each other on real loopback UDP traffic.

No C toolchain, no libsrt linkage — the entire stack is Rust
(`rust-toolchain.toml` pins 1.96.0).

## Crates

| Crate | Path | Role |
|---|---|---|
| [`shiguredo_srt`](crates/srt-protocol) | `crates/srt-protocol` | Sans-I/O SRT protocol core: handshake (v4/v5), encryption, ACK/NAK/TSBPD, bonding groups, StreamID access control |
| [`srt-transport`](crates/srt-transport) | `crates/srt-transport` | Per-runtime UDP adapter `Conn` structs (feature-gated: mio/tokio/smol/monoio/glommio/compio) |
| [`srt-lifecycle`](crates/srt-lifecycle) | `crates/srt-lifecycle` | Runtime-neutral admission, group affinity, and worker routing policy |
| [`srt-bench`](crates/srt-bench) | `crates/srt-bench` | Caller/listener binaries + bake-off harness across all six runtimes |

Inside `crates/srt-protocol`: [`pbt/`](crates/srt-protocol/pbt)
(proptest suites, workspace member) and
[`fuzz/`](crates/srt-protocol/fuzz) (libFuzzer decode targets, excluded
from the workspace; needs `cargo-fuzz` + nightly).

## Architecture

```
                 ┌──────────────────────────────────────────┐
   UDP sockets   │  srt-bench / your application            │
 ──────────────► │  runtime event loop                      │
 ◄────────────── │  (mio epoll · tokio · smol · monoio ·    │
                 │   glommio · compio io_uring)             │
                 └───────────────┬──────────────────────────┘
                                 │ srt-transport: per-runtime Conn
                                 │ fire_expired / drain_outputs / send_paced
                 ┌───────────────▼──────────────────────────┐
                 │  srt-protocol (shiguredo_srt)            │
                 │  SrtConnection: sans-I/O state machine   │
                 │  feed_recv_buf() → poll_event/poll_output│
                 └──────────────────────────────────────────┘
```

The protocol core performs **zero I/O**: callers feed datagrams in
(`feed_recv_buf`) and drain packets/events out (`poll_output`,
`poll_event`). Time is injected as `Timestamp` (µs since session start).
This makes the core testable without sockets and lets every runtime drive
it with its own native primitives — see `crates/srt-transport/README.md`
for why there is deliberately no lowest-common-denominator abstraction.

`srt-lifecycle` sits beside the data plane: listeners use it to decide
*which worker owns which incoming tuple* before any protocol state exists
(StreamID/GROUP decoding straight off the wire datagram).

## Quick start

```sh
# Unified harness: three modes
./bench.sh bakeoff 300 8      # all six runtimes at one density
./bench.sh knee 100 300 600   # mio-only connection-count sweep
REPS=3 ./bench.sh baseline 300 8   # 3 reps, median table (same-window rule)

# Direct invocation (one process per role; connection *i* lives on port+i):
srt-bench runtime=mio mode=receiver 12000 13 120 --connections 4
srt-bench runtime=tokio mode=sender 127.0.0.1 12000 8 120 --connections 4
```

Each side prints exactly one `STATS role=… backend=… …` line; the sender
exits 1 if it never connected. Field-by-field meaning:
[`crates/srt-bench/README.md`](crates/srt-bench/README.md).

## Testing

```sh
cargo test -p shiguredo_srt      # unit + integration + doctests
cargo test -p pbt                # property-based tests (proptest)
cargo test -p srt-lifecycle
cargo bench -p shiguredo_srt     # criterion: core packet loop, loss/tsbpd scans
```

Fuzzing (decode paths must never panic on attacker input — they already
caught one real overflow, see `crates/srt-protocol/VENDOR.md`):

```sh
cd crates/srt-protocol/fuzz
cargo +nightly fuzz run fuzz_packet_decode    -- -max_total_time=60
cargo +nightly fuzz run fuzz_handshake_decode -- -max_total_time=60
```


## Licensing

Workspace code is Apache-2.0 ([LICENSE](LICENSE), mirrored in each crate
directory). Third-party dependency licenses are audited in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) and enforced by
`cargo deny check licenses` ([deny.toml](deny.toml)) — currently clean:
every registry package in `Cargo.lock` resolves to a permitted permissive
term.

Benchmark scripts write all raw output under `scratch/` (gitignored) —
never `/tmp` — so concurrent runs on shared machines don't clobber each
other or leak artifacts outside the repo.

## Notes

- `.cargo/config.toml` caps parallel rustc jobs at 8 (OOM guard on shared
  machines) and selects the `mold` linker. Override jobs with
  `CARGO_BUILD_JOBS=N`.
- `crates/srt-protocol/VENDOR.md` documents provenance (git-subtree import
  of [shiguredo/srt-rs](https://github.com/shiguredo/srt-rs)), every local
  patch applied on top, and how to pull future upstream commits.
- glommio backend is Linux-only (io_uring); other runtimes are portable.
