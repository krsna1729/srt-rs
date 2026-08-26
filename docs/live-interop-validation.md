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
| I | StreamID propagation | live | — | 0 % | **PASS** — a Rust caller with a StreamID completes the real-libsrt handshake. Application-level authorization was validated only with the manual listener harness; stock `srt-live-transmit` does not expose an allow-list policy. |

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
  delivery ordering, TLPKTDROP bounds, reject-reason propagation, and
  StreamID propagation all behave correctly against the reference
  implementation. StreamID authorization remains an application policy and
  needs a listener harness that exposes that policy.
- Findings H1 (latency not negotiated to max), H2 (induction magic not
  validated), M6 (pacing header term) remain valid but did not impede any
  interop scenario above — both sides defaulted to equal latency here.

## Automation plan: capture these tests in `crates/srt-bench/tests/libsrt_interop.rs`

The manual session above now maps onto a repeatable baseline in the interop
suite. It keeps skip-if-absent gating via `command_available` for developer
machines, while CI installs `srt-tools` and runs the suite in its dedicated
`libsrt-interop` job.

Implemented and verified against the installed libsrt 1.5.3 package:

- libsrt live caller → Rust listener: plain, AES-128, AES-256, byte exact.
- Rust live caller → libsrt listener: plain and AES-128, byte exact.
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
| E. AES-256 forward | ✔ `libsrt_live_caller_aes256_to_rust_listener` | automated |
| F/G. ARQ recovery under 5 % loss | ✔ `libsrt_caller_recovers_payload_under_5pct_loss` | automated, ignored by default |
| H. Wrong-passphrase rejection + reason propagation | ✔ `rust_live_caller_wrong_passphrase_is_rejected_by_libsrt_listener` | automated (positive control is the AES-128 reverse-direction test) |
| I. StreamID propagation | ✔ `rust_live_caller_with_stream_id_connects_to_libsrt_listener` | automated; `srt-live-transmit` has no listener-side authorization hook |

### Helper status

1. `send_to_libsrt_listener` is the mirror-image helper: it starts a real
   `srt-live-transmit` listener and drives a Rust caller through
   `srt_bench::driver`. Independent caller/listener encryption options make
   the wrong-passphrase assertion possible; the caller also accepts a
   StreamID.
2. `lossy_udp_proxy_thread` is a std-only, fixed-forward A→B and learned-return
   B→A proxy. It deterministically drops every twentieth DATA packet while
   preserving control traffic, so handshake and NAK behavior stay observable.
3. `test_payload_bytes(n)` sizes the loss case at 120 KB (120 source packets),
   enough to exercise several retransmissions without a long runtime.
4. Binary discovery stays `command_available` on PATH — no build-directory
   probing.

### Loss-recovery gate

All follow existing conventions: skip-with-note when prereqs are missing,
byte-exact assertion style, driver-event context in assert messages.

| Test name | Asserts |
|---|---|
| `libsrt_caller_recovers_payload_under_5pct_loss` | proxy at 0.05, negotiated 500 ms latency, byte equality after recovery (F/G) |

### Gating and runtime budget

- The completed negative-encryption and StreamID-propagation cases use the
  same auto-skip gating as the existing tests; each is bounded and the suite
  stays green on machines without libsrt on PATH.
- The loss test is timing-sensitive under CI load, so it is marked `#[ignore]` with the
  invocation documented in place
  (`cargo test -p srt-bench --test libsrt_interop -- --ignored`), keeping
  standard cargo semantics instead of custom env parsing.
- Out of scope, recorded here rather than attempted: KM-refresh live check
  (needs 2²⁵ packets), bonding-group interop (the sample apps expose no
  usable group-caller mode), and the FileCC direction (`transtype=file`
  congctl mismatch against this live-only core; see tooling notes above).

### Risks / decisions taken

1. **stdin-epoll flake**: this sandbox saw "Failed to add FILE source to
   poll" when piping stdin to `srt-live-transmit`. The implemented forward
   tests therefore use the `udp://`-source pattern proven in this session;
   do not reintroduce piped stdin for live sources.
2. **StreamID authorization**: `srt-live-transmit` accepts any StreamID; its
   `streamid=` URI option is not an allow-list. Keep authorization coverage in
   an application-level listener harness rather than asserting a false
   property of the stock tool.
3. **Port collisions under parallel test threads**: `free_port()` retains a
   narrow TOCTOU gap for the caller/listener helpers. The loss proxy itself
   binds its ephemeral port directly; an allocation race elsewhere fails fast
   rather than silently connecting the test to a wrong peer.

Once implemented: verify both ways — binaries present (full pass) and
absent (all skipped, zero failures) — then point this document's Results
table at the automated suite as the reproducible form of the manual run.
