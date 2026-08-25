# shiguredo_srt

Sans-I/O SRT (Secure Reliable Transport) protocol implementation — the
protocol core of this workspace. Vendored from
[shiguredo/srt-rs](https://github.com/shiguredo/srt-rs) (`develop`,
commit `6779cdd`, 2026-08-16) via `git subtree`; see
[VENDOR.md](VENDOR.md) for provenance, every local patch applied on top,
the pure-Rust crypto swap, and upstream-pull instructions.

The crate performs **no I/O and owns no clocks**: it is a buffer-driven
state machine. Callers feed received datagrams in, drain packets to send
and events out, and drive timers explicitly. This makes the entire SRT
protocol testable, benchmarkable, and fuzzable with zero sockets.

## Module map

| Module | Contents |
|---|---|
| `srt_connection` | `SrtConnection` — the central state machine (handshake, encryption, keepalive, ACK/NAK scheduling, inactivity timeout) |
| `srt_handshake` | Caller-listener handshake v4/v5: INDUCTION → CONCLUSION, extensions (HS, KM, SID, GROUP, congestion), reject reasons |
| `srt_packet` | Wire format: `DataPacket` / `ControlPacket` decode/encode (F-bit dispatch, 16-byte header) |
| `srt_receiver` | `ReceiverBuffer`: reordering, loss list, TSBPD delivery, ACK/NAK generation, RTT estimation, `ReceiverStats` |
| `srt_sender` | `SenderBuffer`: flow window, congestion window, pacing (`time_until_send`), retransmit queue, `SenderStats` |
| `srt_group` | Bonding groups: `SrtGroup` with Broadcast / Backup modes, member lifecycle, group-level send/receive |
| `crypto` | `CryptoContext`: PBKDF2-HMAC-SHA1 KEK derivation, AES Key Wrap SEK exchange, AES-CTR payload encryption; key material is redacted in `Debug` and zeroized on drop |
| `stream_id` | StreamID + `#!::k=v,…` access-control parsing (`AccessControl`, `StreamType`, `StreamMode`) |
| `buf`, `error`, `time` | Checked big-endian read/write cursor helpers, `Error`/`ErrorKind` with backtrace capture, `Timestamp` (µs, injected) |

Handshake attempts default to libsrt-compatible 250 ms request spacing
with non-early jitter and a 3 s deadline for the complete induction plus
conclusion exchange. Applications needing different bounds can call
`SrtConnection::set_handshake_timing(retry_interval_micros,
timeout_micros)` before starting or admitting a connection.

## Core API

```rust
use shiguredo_srt::{
    ConnectionOptions, ConnectionEvent, ConnectionOutput,
    ConnectionState, SrtConnection, TimerId, Timestamp,
};

let mut conn = SrtConnection::new_caller(ConnectionOptions {
    socket_id: 0x1000_0001,
    stream_id: Some("#!::r=live/stream1".into()),
    ..Default::default() // tsbpd_delay=120ms, AES-128, flow window 8192 pkts
});
conn.connect(Timestamp::from_micros(0))?;

loop {
    // 1. feed any UDP datagrams you received
    conn.feed_recv_buf(&datagram, now)?;

    // 2. fire timers the connection asked for
    conn.handle_timer(TimerId::Ack, now)?;

    // 3. drain wire output -> UDP sendto
    while let Some(out) = conn.poll_output() {
        match out {
            ConnectionOutput::SendPacket(bytes) => { /* sock.send(&bytes) */ }
            ConnectionOutput::SetTimer { id, duration_micros } => { /* schedule */ }
            ConnectionOutput::ClearTimer { id } => { /* cancel */ }
        }
    }

    // 4. consume application events
    while let Some(ev) = conn.poll_event() {
        match ev {
            ConnectionEvent::Connected => break,
            ConnectionEvent::DataReceived { payload, .. } => { /* deliver */ }
            ConnectionEvent::StateChanged(_) | ConnectionEvent::Error(_)
            | ConnectionEvent::Disconnected { .. }
            | ConnectionEvent::KeyRefreshNeeded { .. } => {}
        }
    }
}
```

When `passphrase` is set on a caller, a fresh salt and stream encryption key
are generated from the operating system CSPRNG unless the application supplies
them explicitly. Explicit keys consisting entirely of zero bytes are rejected.
Do not log or persist `ConnectionOptions`: its `Debug` implementation redacts
the passphrase and SEK, and the connection zeroizes its owned copies after the
handshake and on drop. See [SECURITY.md](SECURITY.md) for the protocol threat
model, including SRT's lack of payload authentication.

Sending: `can_send_with_pacing(now)` / `time_until_send(now)` gate
`send(payload, now)`; `send_with_sequence` pins an explicit sequence
number; `set_packet_send_period` caps rate. Listeners may apply policy
mid-handshake via `set_listener_policy(passphrase, key_length,
tsbpd_delay, flow_window, rcvbuf)` — mirrors libsrt's accept hook. The guarded
listener setters work only after INDUCTION has created a listening connection
and before CONCLUSION is processed. Full-stack applications should normally
enter that window through `srt_transport::PeerTable::admit_with_resolver`,
which preserves cookie validation, rejection delivery, deferral bounds, and
admission telemetry; see the
[`listener admission guide`](../../docs/listener-admission-policy.md).
Telemetry: `stats()` returns a non-clearing, direction-aware connection
snapshot with cumulative loss/retransmit/drop/undecrypt and ACK/NAK counters,
instantaneous rates, RTT, capacity, pacing, and exact queue occupancy.
`ConnectionStats::interval_since` derives interval counts and rates using the
caller's elapsed duration, keeping the sans-I/O core independent of a wall
clock. The older `sender_stats()` / `receiver_stats()` accessors remain
available. Field semantics and the Restream/libSRT mapping are documented in
[TELEMETRY.md](TELEMETRY.md).

## Interop status

Wire-compatible with real libsrt, verified both directions including
encrypted payload exchange (byte-exact known payload through AES-CTR) —
details and evidence in [VENDOR.md](VENDOR.md#crypto-backend-pure-rust-rustcrypto-stack-not-aws-lc-rs).
Control packets carry libsrt's 4-byte zero padding so Wireshark's SRT
dissector stays happy (`LIBSRT_COMPAT_PADDING` in `srt_connection.rs`).

## Testing

```sh
cargo test -p shiguredo_srt   # unit + integration + doctests
cargo bench -p shiguredo_srt  # criterion benches:
                              #   core_packet_loop      per-packet CPU cost, zero I/O
                              #   core_packet_loop_io   same over real loopback UDP
                              #   receiver_loss_scan    O(n)->O(1) loss-list fix regression guard
                              #   receiver_tsbpd_scan   TSBPD delivery-scan cost
cargo test -p pbt             # property-based suites, one per core module
```

`tests/allocation_guard.rs` asserts steady-state per-packet allocation
count stays **bounded and flat** (not zero — `BTreeMap` storage is a
deliberate, measured tradeoff documented in that file's header).

Fuzz targets under [`fuzz/`](fuzz/) (`cargo-fuzz`, nightly): decode paths
and stateful connection input must never panic on attacker input. Run record and the panic they already
caught: [VENDOR.md § Fuzzing](VENDOR.md#fuzzing).

## Local patches on the vendored code

Every behavioral deviation from upstream is tagged `// local patch
(crates/srt-protocol/VENDOR.md, …)` at the call site. Highlights: crypto
key redaction/zeroization (upstream 0049/0050), no default-zero crypto
salt (0052), CONFIG-bit set for SID/congestion extensions (found by live
capture vs. libsrt), handshake reject-reason decoding (was silently
swallowing rejections), i32 overflow panic found by fuzzing. Full table +
upstream-pull workflow: [VENDOR.md](VENDOR.md). Public rustdoc was also
translated from Japanese to English throughout — recorded separately in
[VENDOR.md § Documentation language](VENDOR.md#documentation-language)
since it isn't a behavioral patch and touches too many lines per file to
tag individually.

## Licensing

Apache-2.0 ([LICENSE](LICENSE)); the workspace root carries the same
license plus a third-party audit
([THIRD-PARTY-LICENSES.md](../../THIRD-PARTY-LICENSES.md),
[deny.toml](../../deny.toml)) — `cargo deny check licenses` passes with
zero warnings, superseding the manual-only audit noted in VENDOR.md.
