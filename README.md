# srt-rs

[![CI](https://github.com/krsna1729/srt-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/krsna1729/srt-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/shiguredo_srt.svg)](https://crates.io/crates/shiguredo_srt)
[![docs.rs](https://docs.rs/shiguredo_srt/badge.svg)](https://docs.rs/shiguredo_srt)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

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
| [`srt-transport`](crates/srt-transport) | `crates/srt-transport` | Mechanism: per-runtime UDP adapters, bonded caller and opt-in logical-ingress groups, admission peer table, handoff message types, socket helpers, and ingress telemetry |
| [`srt-lifecycle`](crates/srt-lifecycle) | `crates/srt-lifecycle` | Policy: worker routing, group affinity, promotion ladder, SYN-cookie codec, terminal-state rule |
| [`srt-bench`](crates/srt-bench) | `crates/srt-bench` | Caller/listener binaries + bake-off harness across all six runtimes |

Inside `crates/srt-protocol`: [`pbt/`](crates/srt-protocol/pbt)
(proptest suites, workspace member) and
[`fuzz/`](crates/srt-protocol/fuzz) (libFuzzer decode targets, excluded
from the workspace; needs `cargo-fuzz` + nightly).

## Architecture

Four crates, layered so that dependencies only ever point downward:

```
  ┌──────────────────────────────────────────────────────────────┐
  │ srt-bench          event loops · recv/send primitives ·      │
  │ (application)      task spawning · CLI · matrix & reporting  │
  └───────────┬──────────────────────────────────┬───────────────┘
              │                                  │
  ┌───────────▼──────────────────┐   ┌───────────▼───────────────┐
  │ srt-transport  (MECHANISM)   │──►│ srt-lifecycle  (POLICY)   │
  │                              │   │                           │
  │ owns things:                 │   │ owns no state:            │
  │  · PeerTable / AdmissionPeer │   │  · WorkerRouter           │
  │  · ManualTimerStore          │   │  · decide_promotion()     │
  │  · Handoff / WorkerMessage   │   │  · cookie_for_worker()    │
  │  · IngressTelemetry          │   │  · is_terminal()          │
  │  · bind_reuseport, recvmmsg  │   │  · handshake identity     │
  │  · per-runtime Conn (feature)│   │                           │
  └───────────┬──────────────────┘   └───────────┬───────────────┘
              │                                  │
  ┌───────────▼──────────────────────────────────▼───────────────┐
  │ srt-protocol (shiguredo_srt)        sans-I/O state machine   │
  │ SrtConnection · feed_recv_buf() → poll_output()/poll_event() │
  │ handshake · encryption · ACK/NAK/TSBPD · bonding · StreamID  │
  └──────────────────────────────────────────────────────────────┘
```

The split between the middle two crates is the load-bearing one:

* **srt-lifecycle takes values and returns decisions.** It owns no
  sockets, no clocks, and no protocol objects — time is passed *in*
  (`is_terminal(now, …)`), which is why its rules are testable without
  any I/O at all.
* **srt-transport owns things.** Live `SrtConnection`s, their timers, the
  fds. That is why the admission peer table lives there and not beside
  the policy it calls.

The protocol core performs **zero I/O**: callers feed datagrams in
(`feed_recv_buf`) and drain packets/events out (`poll_output`,
`poll_event`). Time is injected as `Timestamp` (µs since session start).
This makes the core testable without sockets and lets every runtime drive
it with its own native primitives — see `crates/srt-transport/README.md`
for why there is deliberately no lowest-common-denominator abstraction.
Consuming applications start from the layered `SessionConfig`,
`TransportConfig`, `AdmissionConfig`, `ListenerConfig`, and `CallerConfig`
surfaces. They include capability-resolved topology, batching, worker,
promotion, caller-pool, socket-budget, and cookie-routing policy alongside the
protocol settings. Presets remain freely overrideable, and raw
`ConnectionOptions`, prepared standard sockets, `PeerTable`, lifecycle policy,
and each runtime-native `Conn` stay public as supported escape hatches.

### Listener ingress strategies

A listener can accept many callers four different ways. All four are
implemented on all six runtimes, so a sweep compares *strategies* rather
than reporting where coverage happens to exist.

```
  per-port              shared-pool:K          reuseport-multi:K      reuseport-single:W
  ────────              ─────────────          ─────────────────      ──────────────────
  N sockets             K sockets              1 port, K sockets      1 port, K sockets
  N ports               K ports                SO_REUSEPORT           SO_REUSEPORT
  1 conn each           many conns each        kernel hashes flows    1 acceptor thread
                        no SO_REUSEPORT        acceptor == worker     + W worker threads

  :12345 ─ c0           :12345 ┬ c0 c4 c8      :12345 ┬ [acc0] ─┐     :12345 ─ [acceptor]
  :12346 ─ c1           :12346 ┼ c1 c5 c9             ├ [acc1] ─┤              │ promotes
  :12347 ─ c2           :12347 ┼ c2 c6 …              ├ [acc2] ─┼─ peers       │ every conn
  :…     ─ …            :12348 ┴ c3 c7                └ [acc3] ─┘              ▼
                                                                         [w0] [w1] [w2]
```

`--promotion` then decides which connections get their own connected
socket once they reach `Connected`. The modes nest:

```
  Never  ⊂  Relocate  ⊂  Bonded  ⊂  All
  │         │            │          │
  │         │            │          └─ every connection
  │         │            └───────────── every bonded leg
  │         └────────────────────────── only bonded legs whose group
  │                                     owner is another worker
  └──────────────────────────────────── nothing; affinity abandoned
```

Promotion buys independent scheduling and costs socket churn plus
SO_REUSEPORT group perturbation. Which way that trades is
**runtime-dependent** — measured, not assumed — which is the entire
reason `srt-bench` exists.

## Library quick start

Pin an audited repository revision and enable only the runtime used by the
application:

```toml
[dependencies]
srt-transport = { git = "https://github.com/krsna1729/srt-rs", rev = "<commit>", features = ["tokio"] }
```

```rust
use std::time::Duration;
use srt_transport::{ListenerConfig, TransportProfile};

let listener = ListenerConfig::builder("0.0.0.0:9000".parse()?)
    .latency(Duration::from_millis(120))?
    .profile(TransportProfile::HighDensity)
    .build()?;

// Call inside the selected runtime. The prepared policy, sockets, PeerTable,
// raw ConnectionOptions, and Conn constructors remain available for custom
// event loops or ownership models.
let listener = srt_transport::tokio_transport::bind_listener(&listener)?;
```

See [`crates/srt-transport/README.md`](crates/srt-transport/README.md) for
layering, profiles, capability resolution, admission limits, and escape hatches.
Listeners that select credentials, authorization, or GROUP policy from an
incoming StreamID should start with
[`docs/listener-admission-policy.md`](docs/listener-admission-policy.md). It
documents the exact pre-CONCLUSION hook window, composable typed overrides,
reuseport ownership, deferral, rejection, telemetry, and raw escape hatches.

## Benchmark quick start

`srt-bench` is one binary: it runs a role, orchestrates a sweep of them,
and reports on the results. There is no shell harness to keep in sync.

```sh
# Sweep a matrix. One child process per role per cell; results append to TSV.
srt-bench matrix --runtimes mio,tokio,smol,monoio,glommio,compio \
  --ingress per-port,shared-pool:4,reuseport-multi:4,reuseport-single:4 \
  --encryption plain,128,192,256 --connections 25 --reps 3 \
  --out scratch/base.tsv

# Median table, grouped by whichever dimensions answer your question.
srt-bench report scratch/base.tsv --by ingress,runtime

# Syscall / io_uring attribution for one pair (needs `perf`).
srt-bench sysprof --runtime glommio --connections 150

# A single run, either role (connection *i* lives on port+i for per-port):
srt-bench runtime=mio mode=receiver 12000 13 120 --connections 4
srt-bench runtime=tokio mode=sender 127.0.0.1 12000 8 120 --connections 4
```

Each side prints one `STATS role=… backend=… …` line, and with `--out`
also appends a row to a TSV whose columns are defined once in
`harness::COLUMNS` — the process that has the numbers writes them, so no
downstream tool re-parses stdout. Field meanings:
[`crates/srt-bench/README.md`](crates/srt-bench/README.md).

Benchmark results are intentionally local: `--out` writes raw TSVs under the
gitignored `scratch/` directory. See [`docs/performance-loop.md`](docs/performance-loop.md),
[`docs/cpu-budget.md`](docs/cpu-budget.md), and [`docs/reading-results.md`](docs/reading-results.md)
for reproducible runs and result interpretation.

## Testing

```sh
cargo test -p shiguredo_srt      # unit + integration + doctests
cargo test -p pbt                # property-based tests (proptest)
cargo test -p srt-lifecycle
cargo test -p srt-transport --all-features
cargo bench -p shiguredo_srt     # criterion: core packet loop, loss/tsbpd scans
cargo bench -p srt-transport     # admission limits and deadline/index tradeoffs
```

Fuzzing (decode paths must never panic on attacker input — they already
caught one real overflow, see `crates/srt-protocol/VENDOR.md`):

```sh
cd crates/srt-protocol/fuzz
cargo +nightly fuzz run fuzz_packet_decode    -- -max_total_time=60
cargo +nightly fuzz run fuzz_handshake_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_connection_feed  -- -max_total_time=60
cargo +nightly fuzz run fuzz_admission         -- -max_total_time=60
```

The stateful targets first establish a valid caller/listener pair and then drive
structured packet, timer, send, and drain action sequences. `fuzz.dict` seeds
SRT control/handshake fields; `fuzz_admission` additionally varies source
populations, capacity, routing, authorization, expiry, and malformed traffic.
Minimized corpora are retained under each target's `fuzz/corpus/` directory for
release runs.


## Licensing

Workspace code is Apache-2.0 ([LICENSE](LICENSE), mirrored in each crate
directory). Third-party dependency licenses are audited in
[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) and enforced by
`cargo deny check licenses` ([deny.toml](deny.toml)) — currently clean:
every registry package in `Cargo.lock` resolves to a permitted permissive
term.

Benchmarks write all raw output under `scratch/` (gitignored) — never
`/tmp` — so concurrent runs on shared machines don't clobber each other
or leak artifacts outside the repo.

## Notes

- `.cargo/config.toml` caps parallel rustc jobs at 8 (OOM guard on shared
  machines), selects the `mold` linker, and sets
  `-C target-cpu=x86-64-v3` so measurements exercise the instruction set
  the host actually has. Override jobs with `CARGO_BUILD_JOBS=N`. Never
  set `RUSTFLAGS` when building for measurement: a set value — even an
  empty one — *replaces* that list rather than merging with it.
- `--release` is the measurement profile (LTO, `codegen-units=1`, debug
  line tables for `perf`). `cargo build --profile quick` is the same
  optimisation level without LTO for a ~4x faster edit-compile loop; it
  is **not** valid for recorded numbers.
- `crates/srt-protocol/VENDOR.md` documents provenance (git-subtree import
  of [shiguredo/srt-rs](https://github.com/shiguredo/srt-rs)), every local
  patch applied on top, and how to pull future upstream commits.
- glommio backend is Linux-only (io_uring); other runtimes are portable.
