# Live Interop Validation vs libsrt (srt-live-transmit / srt-file-transmit)

Real-socket cross-validation of this workspace's protocol core against the
reference implementation, run 2026-08-25. libsrt built from source at
`master` (1.5.6, encryption enabled); Rust side driven through
`shiguredo_srt` with a purpose-built listener/caller (`/tmp/srt-interop/rxbin`)
plus `srt-bench` for sustained-rate runs.

Test payload: 5,000,000 random bytes (`md5 ac4f9de38cec18157125f66d5b5455f4`),
chunked by srt-live-transmit at 1316 B (3,800 packets).

## Results

| # | Direction | Mode | Crypto | Loss | Result |
|---|---|---|---|---|---|
| A | libsrt → Rust | live (LiveCC) | plain | 0 % | **PASS** — md5 identical, 3800/3800 packets |
| B | Rust → libsrt | live, bench sender @8 Mbps | plain | 0 % | **PASS** — 4546 pkts sent, received stream byte-pattern exact (all `0x42`) |
| C | libsrt → Rust | live | AES-128, shared passphrase | 0 % | **PASS** — md5 identical after decryption |
| D | Rust → libsrt | live | AES-128 | 0 % | **PASS** — decrypted content pattern-exact on libsrt side |
| E | libsrt → Rust | live | AES-256 | 0 % | **PASS** — md5 identical |
| F | libsrt → Rust | live | plain | 2 % | **PASS** — full ARQ recovery, md5 identical (deployment-guide "good network" tier) |
| G | libsrt → Rust | live | plain | 5 % | **PASS** — md5 identical at latency=500 ms |
| H | Rust caller → libsrt listener, wrong passphrase | — | AES-128 mismatched | 0 % | **PASS** — libsrt rejects `1010 Incorrect passphrase` (BADSECRET); Rust caller surfaces `HandshakeRejected: reason=10`, does not hang, does not accept plaintext. Positive control with right passphrase connects. |
| I | StreamID propagation and authorization | live | — | 0 % | **PASS** — StreamID completes the real-libsrt handshake; a real libsrt caller is also accepted and rejected by the Rust listener's policy. Stock `srt-live-transmit` does not expose an allow-list policy. |

### Partial recovery under extreme loss (expected behavior)

At **15 % random loss / latency=1500 ms**, delivery was 3541/3800 packets
(93 %); the missing ~7 % were dropped as too-late on the receiver and matched
by sender-side drops. This is TLPKTDROP operating as specified (draft §4.6):
packets whose retransmission cannot beat the play deadline are sacrificed to
hold latency constant. Not a defect; at that loss rate the deployment guide's
own table demands latency ≥ RTT×8–13 plus high bandwidth overhead, which a
lossy single-socket proxy at ~0.9 Mbps input cannot provide.

## Tooling notes (for reproduction)

- `srt-live-transmit` treats an input URI with a host as **caller** mode;
  listener mode needs explicit `?mode=listener` (`SrtInterpretMode`,
  `apps/socketoptions.cpp:30`).
- Its FILE-source epoll fails on `<` pipe stdin in this environment ("Failed
  to add FILE source to poll") — feed via `udp://` source or a regular file.
- `srt-file-transmit` defaults to FileCC; against this live-only core it must
  be given `transtype=live`… but then its `sendfile2` API trips libsrt's own
  "LiveCC: invalid API use" guard. Use `srt-live-transmit` for interop with a
  live-mode peer.
- Handshake packet from the crafted-python probe must be the full 64-byte
  frame (16 header + 48 CIF incl. 16-byte peer IP).

## Interpretation

- Both handshake directions, KMREQ/KMRSP key exchange, AES-128/256 CTR
  payload encryption/decryption, ACK/NAK recovery under real loss, TSBPD
  delivery ordering, TLPKTDROP bounds, reject-reason propagation, StreamID
  propagation/authorization, and broadcast bonding behave correctly against
  the reference implementation. StreamID authorization remains an application
  policy; the interop suite supplies the policy-bearing Rust listener harness.
- The historical compliance findings mentioned in the original manual notes
  (latency negotiation, induction validation, and pacing) are fixed; see
  [`VENDOR.md`](../crates/srt-protocol/VENDOR.md#protocol-compliance-remediation)
  for their regression evidence. The matching defaults used here are therefore
  a baseline rather than a limitation.

## Automation plan: capture these tests in `crates/srt-bench/tests/libsrt_interop.rs`

The manual session above now maps onto a repeatable baseline in the interop
suite. It keeps skip-if-absent gating via `command_available` for developer
machines, while CI installs `srt-tools` and runs the suite in its dedicated
`libsrt-interop` job.

Implemented and verified against the installed libsrt 1.5.3 package:

- libsrt live caller → Rust listener: plain, AES-128, AES-256, byte exact.
- Rust live caller → libsrt listener: plain, AES-128, and AES-256, byte exact.
- libsrt file caller → Rust listener: retained as a separate FileCC wire
  check. Debian sid's libsrt 1.5.6 can return non-zero after printing `File
  sent` and `Buffers flushed` when this bounded test listener closes; the test
  therefore requires byte-exact received data and those completion markers
  before accepting that version-specific exit status.
- The live caller uses a loopback UDP source rather than `file://con`:
  `srt-live-transmit` cannot reliably poll piped stdin in this environment.
  Each child has an explicit timeout plus a bounded reaping path.

### Coverage gap: manual session vs. current file

| Manual test | In file today | Captured as |
|---|---|---|
| A. libsrt→Rust plain live (byte-exact) | ✔ `libsrt_live_transmit_caller_sends_udp_to_rust_listener` | automated |
| B. Rust caller → libsrt listener | ✔ `rust_live_caller_sends_stream_to_libsrt_listener` | automated |
| C/D. AES-128 both directions | ✔ two live tests | automated |
| E. AES-256 both directions | ✔ two live tests | automated |
| F/G. ARQ recovery under 5 % loss | ✔ `libsrt_caller_recovers_payload_under_5pct_loss` and `rust_caller_recovers_payload_under_5pct_loss` | automated in normal CI, both directions |
| J. KM refresh | ✔ `rust_live_caller_refreshes_key_with_libsrt_listener` and `libsrt_live_caller_refreshes_key_with_rust_listener` | automated in both directions; each crosses a real new-SEK boundary without a 2²⁵-packet transfer |
| H. Wrong-passphrase rejection + reason propagation | ✔ `rust_live_caller_wrong_passphrase_is_rejected_by_libsrt_listener` | automated (positive control is the AES-128 reverse-direction test) |
| I. StreamID propagation and authorization | ✔ propagation plus `libsrt_caller_obeys_rust_stream_id_policy` | automated; real libsrt caller is both accepted and rejected by the Rust listener policy |
| K. Broadcast bonding | ✔ `libsrt_broadcast_group_interoperates_with_rust_listener` and `rust_broadcast_group_interoperates_with_libsrt_listener` | automated in the bonding-enabled Debian sid image; both group-caller directions establish two physical legs and deliver one logical payload |
| L. INPUTBW/OHEADBW | ✔ `rust_input_bandwidth_caller_sends_stream_to_libsrt_listener` and `libsrt_input_bandwidth_caller_sends_stream_to_rust_listener` | automated byte-exact live delivery in both directions; the exact source-rate plus overhead pacing calculation is unit-tested |

### Helper status

1. `send_to_libsrt_listener` is the mirror-image helper: it starts a real
   `srt-live-transmit` listener and drives a Rust caller through
   `srt_bench::driver`. Independent caller/listener encryption options make
   the wrong-passphrase assertion possible; the caller also accepts a
   StreamID.
2. `lossy_udp_proxy_thread` is a std-only, fixed-forward A→B and learned-return
   B→A proxy. It deterministically drops every twentieth DATA packet while
   preserving control traffic, so handshake and NAK behavior stay observable.
3. The loss cases use several 1 KB packets and a trailing marker after the
   last intentionally dropped packet, so that final loss is observable as a
   NAK rather than an ambiguous end-of-stream gap.
4. Binary discovery stays `command_available` on PATH — no build-directory
   probing.
5. `libsrt_bonded_caller.c` and `libsrt_bonded_listener.c` are intentionally
   small C fixtures over libsrt's public group API. `srt-live-transmit` exposes `groupconnect`, but its
   single-client listener closes its accept socket after the first connection,
   so it cannot serve as the independent two-leg group peer this test needs.
   Its group-aware listener accepts the mirror group once, after which libsrt
   attaches later physical legs in the background and the fixture reads the
   logical stream with `srt_recvmsg2(group_id, ...)`. Its 15-second bounded
   delivery window accommodates that asynchronous attachment on loaded CI
   runners. The accepted group is switched to nonblocking receive before
   polling: libsrt's blocking group receive holds the group lock and would
   otherwise delay background attachment of the second leg. The fixture then
   confirms two mirror members before reading; the Rust caller primes once a
   leg is live and separately proves its two-leg broadcast selection.

### Loss-recovery gate

All follow existing conventions: skip-with-note when prereqs are missing,
byte-exact assertion style, driver-event context in assert messages.

| Test name | Asserts |
|---|---|
| `libsrt_caller_recovers_payload_under_5pct_loss` | proxy at 0.05, negotiated 500 ms latency, byte equality after recovery (F/G) |
| `rust_caller_recovers_payload_under_5pct_loss` | same proxy and latency in the inverse topology; trailing packet makes the final forced loss NAK-observable |

### Gating and runtime budget

- The completed negative-encryption and StreamID-propagation cases use the
  same auto-skip gating as the existing tests; each is bounded and the suite
  stays green on machines without libsrt on PATH.
- The loss test uses a deterministic every-twentieth-DATA-packet proxy and is
  part of the normal interop suite. Its bounded 15-second driver deadline
  makes a failed recovery diagnostic rather than an unbounded CI delay.
- The KM-refresh tests exercise both implementations as the refresher: Rust
  seeds its test-only counter immediately before the normal 2²⁵-packet
  boundary, while libsrt uses its documented tiny test cadence. Both send real
  encrypted packets through the peer without changing production timing.
- Distro `srt-tools` packages expose the group declarations but compile
  bonding out. The cached Debian sid image rebuilds the current sid source
  with `ENABLE_BONDING=ON`; its native image-validation workflow sets
  `SRT_REQUIRE_BONDING=1`, making the group test a required gate rather than
  a local-machine assumption.
- A bonded Rust caller becomes media-ready only after a bounded transport
  `drive` pass promotes completed handshakes into `active_legs`. The native
  listener independently waits for two *connected* mirror members, then uses
  the public `SRT_MSGCTRL` member-state array and an `SRT_LIVE_MAX_PLSIZE`
  receive buffer required by libsrt's live-mode API.
- FileCC remains out of scope (`transtype=file` congestion-control mismatch
  against this live-only core; see tooling notes above).

### Local bonding validation without containers

Docker is a CI implementation detail, not a developer prerequisite. The
shared test is always the same Cargo invocation:

```sh
cargo test -p srt-bench --test libsrt_interop \
  broadcast_group_interoperates
```

With ordinary distro `srt-tools`, that one scenario reports a skip: Ubuntu
and Debian sid ship the public group declarations but compile the feature out.
All other interop scenarios remain runnable with the usual `srt-tools`
installation.

To exercise the bonding scenario locally, install a bonding-enabled libsrt in
any user-writable prefix; no Docker daemon or root installation is required.
The only requirements are a C compiler, CMake, the TLS development package
used by libsrt, and libsrt built with `-DENABLE_BONDING=ON`. For example, from
an unpacked libsrt source tree:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_BONDING=ON -DENABLE_TESTING=OFF -DUSE_ENCLIB=openssl-evp
cmake --build build
cmake --install build --prefix "$HOME/.local"

export PATH="$HOME/.local/bin:$PATH"
export CPATH="$HOME/.local/include${CPATH:+:$CPATH}"
export LIBRARY_PATH="$HOME/.local/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$HOME/.local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
SRT_REQUIRE_BONDING=1 cargo test -p srt-bench --test libsrt_interop \
  libsrt_broadcast_group_interoperates_with_rust_listener -- --exact
```

`SRT_REQUIRE_BONDING=1` turns the known capability skip into a failure. CI
uses that same switch in the cached sid image; developers opt into it only
when they have installed a capable library.

### Risks / decisions taken

1. **stdin-epoll flake**: this sandbox saw "Failed to add FILE source to
   poll" when piping stdin to `srt-live-transmit`. The implemented forward
   tests therefore use the `udp://`-source pattern proven in this session;
   do not reintroduce piped stdin for live sources.
2. **StreamID authorization**: `srt-live-transmit` accepts any StreamID; its
   `streamid=` URI option is not an allow-list. The interop suite therefore
   drives the public Rust `PeerTable` listener policy against a real libsrt
   caller, verifying both allowed delivery and `UNAUTHORIZED` rejection before
   `Connected`. The sample tool logs that rejection but exits zero, so the test
   asserts the wire diagnostic and listener state rather than its exit code.
3. **External-process scheduling**: Rust-owned endpoints bind `127.0.0.1:0`
   and retain that socket; black-box listeners retry only an immediate
   startup failure. Dynamic ports prevent cross-connection, but they do not
   make libsrt's process-global initialization and teardown independent. The
   interop binary therefore serializes only its real-libsrt cases; ordinary
   unit, property, and loom tests remain parallel.

The automated suite is the reproducible form of the manual results. On a
developer machine without the optional tools and development library, the
corresponding scenarios skip; the CI image explicitly requires bonding.
