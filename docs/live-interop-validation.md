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
| I | StreamID access control: libsrt listener requires `streamid=mypass/stream1` | — | — | 0 % | **PASS** — correct SID connects; wrong SID never completes (libsrt ignores unknown-SID callers) |

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
  StreamID-based admission all behave correctly against the reference
  implementation.
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
  check.
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
| F/G. ARQ recovery under 2 %/5 % loss | ✖ | new (proxy) |
| H. Wrong-passphrase rejection + reason propagation | ✖ | new (+positive control) |
| I. StreamID accept / wrong-SID | ✖ | new ×2 |

### Shared-helper extensions

1. **Generalize `receive_from_libsrt_caller`**: add optional
   `ConnectionOptions` overrides — `passphrase`, `key_length` — appended to
   the caller URI as `&passphrase=…&pbkeylen=16|24|32`. Existing two call
   sites unchanged (new params defaulted).
2. **New helper `send_to_libsrt_listener`** (mirror image): spawns
   `srt-live-transmit -q "srt://:<port>?mode=listener[&passphrase=…]"
   file://con > out_file`, drives a Rust *caller* through a caller-side loop
   (connect → paced sends → collect events). `driver::run` cannot pace sends
   from `on_connect` without blocking its recv loop, so this is a ~60-line
   sibling modeled on the probe-caller used in the manual session. Returns
   `(connected, libsrt_stdout_bytes, stderr)`.
3. **New helper `lossy_udp_proxy_thread(listen, forward_to, loss_rate)`**:
   std-only thread, two bound sockets, fixed-forward A→B and learned-return
   B→A, seeded PRNG for determinism. Replaces the ad-hoc python proxy; no
   tokio needed.
4. **Payload sizing**: add `test_payload_bytes(n)`; loss tests use ~400 KB
   (≈300 packets) so recovery is exercised without 30-second runtimes.
5. Binary discovery stays `command_available` on PATH — no build-directory
   probing.

### Remaining tests (4)

All follow existing conventions: skip-with-note when prereqs are missing,
byte-exact assertion style, driver-event context in assert messages.

| # | Test name | Asserts |
|---|---|---|
| 1 | `rust_caller_wrong_passphrase_rejected_with_reason` | driver event contains `reason=10` (BADSECRET), `connected == false`; plus positive-control right-passphrase connect in the same test (H) |
| 2 | `rust_caller_stream_id_accepted_by_libsrt_listener` | connected with matching `streamid` (I-accept) |
| 3 | `rust_caller_wrong_stream_id_never_connects` | `!connected` within bounded deadline, no panic (I-reject) |
| 4 | `libsrt_caller_recovers_payload_under_5pct_loss` | proxy at 0.05, latency=250 ms, byte equality after recovery (F/G) |

### Gating and runtime budget

- Tests 1–3: same auto-skip gating as existing; each ≤ ~15 s. The suite
  stays green on machines without libsrt on PATH.
- Test 8 (loss): timing-sensitive under CI load — mark `#[ignore]` with the
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
2. **Negative-timeout asserts** (wrong-SID "never connects") stay short
   (≤10 s) so skip-laden local runs stay fast.
3. **Port collisions under parallel test threads**: `free_port()` has a
   TOCTOU gap; the loss test binds three ports up-front and passes handles
   into the proxy thread to close the race.

Once implemented: verify both ways — binaries present (full pass) and
absent (all skipped, zero failures) — then point this document's Results
table at the automated suite as the reproducible form of the manual run.
