# VENDOR.md — shiguredo/srt-rs import

This crate (`shiguredo_srt`) is a vendored import of
[`shiguredo/srt-rs`](https://github.com/shiguredo/srt-rs), imported via
`git subtree` so future upstream commits can be pulled in with a normal
merge rather than a manual re-copy. It was selected for its pure-Rust,
sans-I/O protocol core and existing handshake, encryption, StreamID, and
bonding support. Current compatibility and verification status is documented
in this file, the crate [README](README.md), and the root
root [README](../../README.md) and [SECURITY.md](../../SECURITY.md).

## Contents

- [Provenance](#provenance)
- [What was trimmed from the upstream tree](#what-was-trimmed-from-the-upstream-tree)
- [Local patches](#local-patches)
- [Protocol compliance remediation](#protocol-compliance-remediation)
- [Intentional compatibility differences](#intentional-compatibility-differences)
- [Documentation language](#documentation-language)
- [Crypto backend: pure-Rust RustCrypto stack, not aws-lc-rs](#crypto-backend-pure-rust-rustcrypto-stack-not-aws-lc-rs)
- [Fuzzing](#fuzzing)
- [Pulling future upstream commits](#pulling-future-upstream-commits)
- [Import-time upstream issue snapshot](#import-time-upstream-issue-snapshot)
- [License and dependency audit](#license-and-dependency-audit)

## Provenance

- Upstream: <https://github.com/shiguredo/srt-rs>
- Branch: `develop` (this is upstream's actively-developed default branch,
  confirmed via `git remote show origin` — not `main`, which lags behind)
- Commit at import: `6779cdddb7cd3233032e06538243715d50df3d0b`
  (2026-08-16 10:53:50 +0900)
- License: Apache-2.0 (upstream `LICENSE`, matching the workspace license)
- Import method: `git subtree add --prefix=crates/srt-protocol
  shiguredo-srt 6779cddd... --squash`

**A note on the commit choice, since `develop` moved again within the same
session this was vendored in:** between first reading this repo
(`5a8aa3b`, 00:04) and the actual import (`6779cdd`, 10:53), 20 commits
landed on `develop`, and the import-time HEAD commit's own message reads
*"0049-0069 の polish をやり直すため一度元に戻す"* ("reverting once to
redo the 0049-0069 polish"). This looked concerning until checked directly:
`git diff 5a8aa3b 6779cdd --stat -- src/ crates/` is **empty** — the entire
20-commit batch touched only `issues/*.md` tracking files, never `src/`.
The "revert" was to issue-tracker paperwork, not code. `6779cdd` was chosen
deliberately after confirming this, not blindly as "whatever's newest."

## What was trimmed from the upstream tree

Removed from the vendored copy (not needed by this repo, and would otherwise
need separate Cargo workspace-member wiring to avoid breaking `cargo build
--workspace`):

- `crates/c-api/` — C FFI bindings for other languages to call this crate.
  this repo consumes it as a normal Rust dependency; irrelevant here.
- `examples/srt_caller/`, `examples/srt_listener/` — upstream's own demo
  binaries. This workspace drives the same protocol core through its transport
  adapters and benchmark binaries instead.

Also removed entirely (`git rm`, not `--cached` — not present on disk in
this checkout, retrievable from the `shiguredo-srt` remote or the subtree-
add commit's history if needed): upstream's own `README.md`, `CHANGES.md`,
`issues/` (open + closed ticket files), `AGENTS.md`, `CLAUDE.md`,
`.markdownlint.jsonc`, `Makefile`, `canary.py`, `prek.toml`,
`refs/srt/draft-sharabayko-srt.md` — not because they're not useful
(the import review used several of them), but to keep this subtree focused on
the code and tests that form the dependency. Rewriting vendored upstream
content to follow a different repository's documentation layout would also
fight future `subtree pull`s. Read the omitted material directly from the live
upstream repo
(<https://github.com/shiguredo/srt-rs/tree/develop>) or from disk in this
checkout when reconstructing an import — they are upstream artifacts, not part
of this crate's published documentation contract.

**Kept, and wired into this repo's root workspace** (`Cargo.toml`
`members`): `pbt/` (property-based tests, one per core module; extend these
rather than duplicating them). `fuzz/` is kept but stays
`exclude`d from the main workspace (matches upstream's own original
`Cargo.toml`; `cargo fuzz` tooling handles it separately, avoiding
nightly-toolchain requirements leaking into the main build).

The vendored crate's own `[workspace]` block (which listed the four paths
above) was removed from `crates/srt-protocol/Cargo.toml` — a crate cannot
both be a member of this repo's root workspace and declare its own separate
workspace. `pbt/Cargo.toml`'s `shiguredo_srt = { path = "../" }` dependency
still resolves correctly regardless of which workspace root is in effect.

## Local patches

Applied directly on top of the squashed import commit, each tagged
`// local patch (crates/srt-protocol/VENDOR.md, upstream issue
NNNN)` at the call site so a future `git subtree pull` merge — or a
maintainer just reading the diff — can tell local patches apart from
vendored code, and recognize when an upstream fix has made a local patch
redundant:

| Issue | Severity (upstream's own label) | Fix |
|---|---|---|
| [0049](https://github.com/shiguredo/srt-rs/blob/develop/issues/0049-bug-fix-crypto-context-debug-leaks-secret-keys.md) | Critical | `CryptoContext` had `#[derive(Debug)]`, printing raw `kek`/`sek_even`/`sek_odd` key bytes via `{:?}`/`dbg!()`. Replaced with a manual `Debug` impl that redacts those three fields (`src/crypto.rs`). |
| [0050](https://github.com/shiguredo/srt-rs/blob/develop/issues/0050-bug-fix-crypto-context-drop-not-zeroize-secret-keys.md) | Critical | `Vec<u8>`'s default `Drop` frees `kek`/`sek_even`/`sek_odd` without zeroing — key material could linger in freed heap memory. Added a `Drop` impl that zeroes all three (`src/crypto.rs`). |
| [0052](https://github.com/shiguredo/srt-rs/blob/develop/issues/0052-bug-fix-crypto-salt-default-all-zero.md) | High | `handle_handshake_caller` defaulted an unset `crypto_salt` to `[0u8; 16]`, making PBKDF2 derive the same KEK from the same passphrase every time (defeats rainbow-table resistance). It now generates a fresh salt from the OS CSPRNG. An omitted SEK is likewise generated per connection instead of silently becoming an all-zero key; explicit all-zero SEKs are rejected. The listener derives both values from the peer's KMREQ. (`src/srt_connection.rs`, `src/crypto.rs`). |
| *(not upstream-tracked — found here, via live capture against real libsrt, not from upstream's own issue list)* | Critical for StreamID-dependent features | `add_sid_extension`/`add_congestion_extension` wrote the extension bytes correctly but never set the `CONFIG` bit (`0x0004`) in `extension_field`. Real libsrt gates its own extension-scanning loop on that exact bit (confirmed at `srtcore/core.cpp:2925,12433`) and always sets it itself when adding a SID/congestion extension (`core.cpp:1708`). Without the fix: a Rust caller's StreamID was correctly encoded on the wire (verified via `tcpdump` — packet size delta matched the StreamID length exactly) but a real libsrt listener silently never looked for it. This crate's own `test_sid_extension_basic` didn't catch it because it only round-trips through this crate's own `decode()`, which doesn't gate on the flag either — only a real cross-implementation test surfaces this class of bug. Fixed in `src/srt_handshake.rs`; added `test_sid_extension_sets_config_flag`/`test_congestion_extension_sets_config_flag` regression tests. Live-verified fixed against real libsrt in both directions (Rust caller → libsrt listener and libsrt caller → Rust listener). |
| *(not upstream-tracked — missing capability, not a regression)* | Critical — silently swallowed all rejections | Reject-reason handling didn't exist at all. Real libsrt encodes a rejected handshake as `1000 + SRT_REJECT_REASON` in the wire's handshake-type field (`srtcore/handshake.h`'s `URQFailure`); `HandshakeType::from_u32` only recognized 5 fixed success values and hard-errored on anything else, so `decode()` failed on any real rejection response with a generic "unknown handshake type" error, and separately `handle_handshake_caller`'s match had a silent `_ => {}` catch-all with no arm for a decoded rejection at all — a caller connecting to a passphrase-enforcing listener without one would just hang until its own handshake timeout, with the actual reason never surfacing anywhere. Added a `Rejected` sentinel variant, a `reject_reason: Option<i32>` field on `HandshakePacket`, a `new_rejection` constructor, and a proper `HandshakeType::Rejected` match arm in `handle_handshake_caller` that surfaces the reason via `Error::handshake_rejected`. The initially deferred listener-side decision point is now wired through `SrtConnection::reject` and `srt_transport::PeerTable::{admit_with_authorizer, admit_with_resolver, admit_with_connection_hook}`; typed per-peer policy is applied after cookie validation and before CONCLUSION/KM processing. Live-verified against a real libsrt listener with `SRTO_PASSPHRASE` set, connected to by a Rust caller with none: libsrt's own log reported `rsp(REJECT): 1011 - Password required or unexpected`; the Rust caller independently decoded and reported `reason=11` — the exact same value (`1011 - 1000 = 11 = SRT_REJ_UNSECURE`), confirmed byte-for-byte against real libsrt, not just self-consistent. `src/srt_handshake.rs`, `src/srt_connection.rs`; regression tests there and in `pbt/tests/prop_handshake.rs` (two existing property tests, `test_handshake_type_from_u32_invalid` and `test_decode_invalid_handshake_type`, encoded the *old* behavior as their spec and had to be narrowed to the true-invalid `[2,999]` range, plus new complementary tests for the now-valid `>=1000` range). |
| *(this repo's bug, introduced by the reject-reason patch above, not upstream's)* | Panic on adversarial input — found by `cargo fuzz run fuzz_handshake_decode`, within the first few thousand of 12M+ iterations | `decode()`'s `handshake_type_raw as i32 - 1000` panicked ("attempt to subtract with overflow") for any `handshake_type_raw >= 0x8000_0000` — casting such a value to `i32` already lands near `i32::MIN`, and subtracting 1000 more underflows `i32`'s range. No real libsrt peer sends a value that large, but `decode()` must never panic on attacker-controlled input; this is exactly what the malformed-input release fuzz gate exists to catch, and it did on the first run. Fixed by widening to `i64` (cannot overflow for any `u32` input) before narrowing to the public `i32` field. Found the same class of bug by code review in `encode()`'s mirror-image addition (`1000 + reject_reason` overflowing for `reject_reason` near `i32::MAX`) and fixed it the same way, proactively — the fuzzer only exercises `decode()`, not `encode()`. `src/srt_handshake.rs`; regression tests `test_decode_adversarial_huge_handshake_type_does_not_panic` and `test_encode_extreme_reject_reason_does_not_panic`. See [Fuzzing](#fuzzing) below for the full run record. |
| *(not upstream-tracked — transport compatibility and fan-in hardening)* | High under fan-in | Handshake retry timing used a five-retry approximation whose effective deadline reset on the induction-to-conclusion transition; its symmetric jitter could also schedule a request before the nominal cadence. The connection now defaults to libsrt's 250 ms minimum request spacing, adds jitter only after that minimum, and enforces one configurable 3 s deadline across the complete attempt. Listener success also clears the handshake timer, matching the caller path. `src/srt_connection.rs`; unit, integration, and property regressions cover the timing bounds and whole-attempt deadline. |
| [0054](https://github.com/shiguredo/srt-rs/blob/develop/issues/0054-bug-fix-ackack-condition-too-loose.md) | (upstream: not labeled; spec-compliance) | `handle_ack` sent an ACKACK for any received ACK with `control_info.len() >= 16`, but the spec (draft-sharabayko-srt.md `#ctrl-pkt-ack`) only allows acknowledging Full ACK (28-byte CIF) receipt, not Small ACK (16-byte CIF). This implementation only ever produces 4-byte or 28-byte ACKs today, so the two thresholds behave identically now — but `>= 16` would send a spec-violating ACKACK the moment a peer (or a future local Small ACK) uses the 16-byte form. Changed to `>= 28`. `src/srt_connection.rs`. |
| [0056](https://github.com/shiguredo/srt-rs/blob/develop/issues/0056-bug-fix-conclusion-kmreq-silent-failure.md) | (upstream: not labeled; defensive-only, not a live bug per upstream's own analysis) | `send_conclusion_request`'s `wrap_sek` failure was silently swallowed via `if let Ok(...)`. Cannot currently fail given today's invariants (KEK/SEK lengths are validated earlier), but the KM refresh path (`provide_new_sek` → `start_pre_announce`) already propagates the same error class via `?` — this was the one exceptional silent-drop. Changed `send_conclusion_request` to return `Result<(), Error>` and propagate. `src/srt_connection.rs`. |
| [0057](https://github.com/shiguredo/srt-rs/blob/develop/issues/0057-bug-fix-encode-le-words-utf8-boundary.md) | Data loss (upstream: not labeled) | `encode_le_words` (used by `add_sid_extension`/`add_congestion_extension`) truncated at a raw byte offset when a string exceeded the 512-byte extension limit. If that offset landed mid-UTF-8-character, the result was invalid UTF-8, which then failed `decode_le_words`'s `String::from_utf8` on the peer side — silently losing the entire StreamID rather than just the truncated tail. Switched to `str::floor_char_boundary` (stable since Rust 1.91, workspace MSRV 1.93). `src/srt_handshake.rs`; regression test `test_sid_extension_truncates_on_a_utf8_char_boundary` (171 × "あ" = 513 bytes, truncation point lands mid-character). |
| [0075](https://github.com/shiguredo/srt-rs/blob/develop/issues/0075-bug-fix-available-buffer-flow-control.md) | Missing feature (upstream: not labeled) | `handle_ack` parsed a Full ACK's `available_buffer` field (receiver's free buffer capacity) and stored it for telemetry via `record_peer_feedback`, but never fed it to `SenderBuffer::set_flow_window` — which existed but had no caller. Receive-window flow control described by the spec never actually engaged; the sender's flow window stayed fixed at its handshake-negotiated value regardless of how full the peer's receive buffer got. Wired `handle_ack` to call `sender.set_flow_window(available_buffer_packets.min(self.options.flow_window_packets))` — clamped to the negotiated window (not applied directly, unlike upstream's proposed fix) so a buggy or adversarial peer advertising an inflated `available_buffer` can only ever shrink the sender's effective window, never grow it past what was already negotiated. `src/srt_connection.rs`. |

**Already independently covered, cross-referenced but not separately patched:**
upstream opened several more issues (0053, 0055, 0058–0061, 0070–0074) after
this crate's import; `git log --oneline 6779cdd..develop -- src/ crates/` is
empty as of this check (2026-08-25) — none of them have landed in upstream's
own code yet either, only in `issues/*.md` write-ups. Cross-checked all of
them against this fork's current code:

- **0055** (loss_list `Vec` → `HashSet`, O(n) retains under load) — already
  `FxHashSet` here, tagged inline as upstream issue 0055.
- **0058** (`add_millis`'s `millis * 1000` overflowing `u64`) — already
  `saturating_mul` here (`src/time.rs`), now tagged inline.
- **0070** (`ConnectionOptions`'s `#[derive(Debug)]` leaking
  passphrase/SEK) — already a manual redacting `Debug` impl here
  (`src/srt_connection.rs`), now tagged inline. Same class of issue as 0049,
  one layer up the public API.
- **0072** (omitted `crypto_sek` silently defaulting to an all-zero key) —
  covered by this fork's existing 0052 patch above, which already generates
  a fresh SEK from the OS CSPRNG when omitted and rejects an explicit
  all-zero SEK. Design differs from upstream's own proposed fix for 0072
  (hard error requiring the caller to always supply a SEK) — both close the
  same security hole, by different means; not reconciled, just noted.
- **0073** (`find_deliverable_seq`'s full `loss_list` scan) — already the
  `loss_list_min` circular-minimum cache here (`src/srt_receiver.rs`),
  tagged inline as upstream issue 0073.
- **0074** (one crafted packet forcing ~2^30 `loss_list` entries) — this
  fork found and fixed the identical bug independently, via its own
  fuzzing/pathology work rather than by reading this upstream issue; now
  cross-tagged inline in `src/srt_receiver.rs`'s existing gap-size guard.

Not applicable: 0053/0071 (`crates/c-api`, excluded from this vendor import
entirely — see [What was trimmed](#what-was-trimmed-from-the-upstream-tree));
0060/0061 (pure cosmetic refactors, no behavior change).

The crypto fixes include regression tests that prove independently-created
encrypted callers emit different handshake material, explicit zero SEKs are
rejected, and secret-bearing configuration is redacted. All tests across the crate (unit +
integration + property-based + doctests) pass after these patches —
verified via `cargo test -p shiguredo_srt` and `cargo test -p pbt`.

## Protocol compliance remediation

The completed line-by-line protocol review is summarized here as durable local
patch guidance. The executable cross-implementation scenarios are in
[`docs/live-interop-validation.md`](../../docs/live-interop-validation.md).

| Area | Local behavior and regression evidence |
|---|---|
| Handshake negotiation and admission | Conclusion handling takes the maximum local/peer TSBPD proposal and gates optional live features on mutually advertised flags. A caller rejects a non-SRT-magic or non-v5 induction response. GROUP is emitted only in CONCLUSION; unknown group types round-trip to policy instead of being erased. Covered by `handshake_negotiates_the_larger_latency_for_both_peers`, `caller_rejects_induction_response_without_srt_magic`, `caller_rejects_legacy_induction_response`, and handshake wire tests. |
| TSBPD timing | The receiver has a libsrt-style drift tracer; a listener stamps its session clock before handshake responses, so the caller derives the correct time base. The 60-second wrap endpoint follows libsrt's inclusive boundary. Covered by drift, `listener_conclusion_response_carries_session_timestamp`, and `wrapping_period_ends_at_libsrt_inclusive_upper_boundary` tests. |
| ACK/NAK and shutdown lifecycle | Full ACK numbers start at one. An ACKACK suppresses periodic ACKs only after confirming the latest Full ACK, including reordered ACKACK protection; the receiver still reports a reopened buffer window. Oversized loss reports are clamped, local disconnect flushes ready TSBPD data, and Closing retransmits SHUTDOWN within its bounded timeout. Covered by receiver, close-state, parser, and property tests. |
| Sender pacing and idle traffic | Packet pacing accounts for the 16-byte SRT header and schedules the next send from the actual send time, preventing an idle backlog from bursting. `INPUTBW` plus `OHEADBW` support maps a known source rate and 5–100% retransmission allowance to the effective pacing ceiling; explicit `MAXBW` retains libsrt precedence. Keepalives require outbound idleness. Covered by `test_packet_pacing_includes_srt_header_bytes`, `test_pacing_no_catch_up_burst_after_idle_gap`, `input_bandwidth_reserves_configured_overhead_for_retransmission`, and real-libsrt live interop. |
| Key refresh | `KeyRefreshNeeded` is emitted once per refresh cycle and rearmed only after `provide_new_sek` begins pre-announcement. A refresh KMREQ without a local crypto context receives `KMRSP(NOSECRET)` immediately. Covered by `key_refresh_needed_is_emitted_once_until_sek_is_provided` and `refresh_kmreq_without_crypto_gets_nosecret_response`. The draft-vs-libsrt refresh cadence remains the intentional difference documented below. |
| Bonded group admission | A pending group leg is retained until its handshake creates the sender buffer, then aligned when it becomes active; adding a late caller leg to an already active group no longer fails prematurely. Covered by `late_pending_member_waits_for_handshake_before_sequence_alignment` and two-way real-libsrt broadcast interop in `libsrt_broadcast_group_interoperates_with_rust_listener` and `rust_broadcast_group_interoperates_with_libsrt_listener`. |
| Explicit live-only scope | `DROPREQ`, `PEERERROR`, and congestion warnings decode but do not affect the live-only API: TTL-driven, multi-packet message delivery and FileCC are not exposed. Rendezvous remains unsupported; caller/listener is the supported topology. This is deliberate scope, not silent packet-decoding loss. |

Future changes in these areas require the focused protocol suite, property
suite, transport/lifecycle suites where applicable, and the dedicated libsrt
interop suite. If an upstream subtree pull supplies equivalent behavior,
retain the regression tests and replace the local implementation rather than
silently dropping the compatibility guarantee.

**Why patch locally instead of waiting for upstream:** this code carries real
stream encryption. All three are
small, mechanical, exactly-as-upstream-specified fixes (each issue file
already states the precise design direction) — the cost of patching now is
low and the cost of shipping with an open, self-identified Critical crypto
bug is not a tradeoff worth making for the sake of staying byte-identical
to upstream.

## Intentional compatibility differences

### Key-material refresh cadence

`KM_REFRESH_PERIOD` is `2^25` packets and `KM_PRE_ANNOUNCE_PERIOD` is 4,000
packets. Those are the SRT draft §6.1.6 recommendation and are kept as the
library defaults. libsrt instead ships operational defaults of `2^24` and
4,096 respectively (`HAICRYPT_DEF_KM_REFRESH_RATE` and
`HAICRYPT_DEF_KM_PRE_ANNOUNCE`).

Key refresh is independently scheduled in each direction, so this difference
does not change the wire format or prevent interoperation with libsrt. It does
mean an operator comparing packet-count logs will see this implementation
refresh half as often. Treat the constants as an intentional draft-aligned
default, not a claim of byte-for-byte libsrt operational behavior.

## Documentation language

Upstream's public rustdoc (`///`/`//!`) was written primarily in Japanese —
consistent with Shiguredo's own origin, but not with the rest of this
workspace (`srt-transport`/`srt-lifecycle`, written fresh here, are English
throughout) and not readable by most of the crates.io/docs.rs audience this
crate is being published to. Translated to English ahead of the open-source
release: `buf.rs`, `crypto.rs`, `error.rs`, `srt_connection.rs`,
`srt_handshake.rs`, `srt_packet.rs`, `srt_receiver.rs`, `srt_sender.rs`,
`stream_id.rs`, `time.rs` (`srt_group.rs` was already English — it just
lacked doc comments on 22 public items, also added). Every public item now
has an English doc comment; `cargo doc` output is 100% English.

This is not tagged with the per-line `// local patch (...)` marker the table
above uses — it touches doc comments pervasively throughout each file rather
than a handful of call sites, so a line-by-line marker isn't practical.
Recorded here instead, at the file level.

**Implication for `subtree pull`:** a future pull will likely surface merge
conflicts on any doc comment upstream also touches (most commonly if
upstream itself edits that Japanese text). Resolve by re-translating
upstream's updated text to English rather than reverting to Japanese, to
keep the crate's public docs consistently English. Internal (non-doc, `//`)
implementation comments were deliberately left as-is in the larger files and
may still contain Japanese — out of scope for this pass, since they don't
appear in rustdoc output; revisit if that inconsistency matters later.

## Crypto backend: pure-Rust RustCrypto stack, not aws-lc-rs

The vendored crate originally depended on `aws-lc-rs`, which pulls in
`aws-lc-sys` — a `cmake`+C-compiler native build step at compile time.
That's exactly the native-toolchain dependency this migration exists to remove:
the protocol core should not reintroduce libsrt's C/C++ build chain through its
crypto backend. Replaced
with pure-Rust [RustCrypto](https://github.com/RustCrypto) crates —
**all audited crates, no hand-rolled crypto primitives**:

| Primitive | Crate(s) |
|---|---|
| KEK derivation (PBKDF2-HMAC-SHA1) | `pbkdf2` + `sha1` |
| SEK wrap/unwrap (AES Key Wrap, RFC 3394) | `aes-kw` |
| Payload encryption (AES-CTR) | `ctr` + `aes`, driven via the `cipher` crate's traits |

**A real trap worth naming, since it's what made hand-rolling AES-CTR/
AES-KW look necessary in an earlier draft of this patch:** pinning older
`hmac`/`sha1`/`pbkdf2` (the versions that happen to line up with commonly-
seen tutorial examples) alongside current `ctr`/`aes-kw` pulls in **two
incompatible generations of the `cipher`/`aes` traits simultaneously**
(`cipher 0.4`/`aes 0.8` vs `cipher 0.5`/`aes 0.9`) — and it still compiles,
because Cargo allows multiple versions of the same crate to coexist across
separate parts of the dependency graph. It just means the AES-CTR path and
the AES-KW path end up on incompatible cipher-trait generations with no
single consistent `aes::Aes128`/`Aes256` type usable across both — which
is genuinely awkward, and an understandable reason to reach for hand-rolled
mode-of-operation code instead of untangling it. The actual fix is simpler:
bump `hmac`/`sha1`/`pbkdf2` to their current versions (`0.13`/`0.11`/`0.13`
at the time of this patch) so everything resolves onto one consistent
generation. Verified directly (a scratch `cargo build` with only these
deps) before applying this patch — single `aes`/`cipher` version each, no
duplicates.

**Live-verified against real libsrt, both directions, with actual encrypted
data exchange — not just handshake completion**, using Rust and native test
caller/listener binaries configured with the same passphrase and known payload:

- Rust caller (new crypto stack) → real libsrt listener: libsrt received
  and decrypted `"the quick brown fox jumps over the lazy dog 0123456789"`
  byte-for-byte correctly.
- Real libsrt caller → Rust listener (new crypto stack): same payload,
  same byte-exact match, other direction.

This is strong evidence by construction: AES-CTR is a keystream XOR — any
error in KEK derivation, SEK unwrap, or counter-block construction would
produce garbage ciphertext/plaintext, not a byte-exact match. A wrong
implementation essentially cannot pass this test by accident.

The existing `tests/test_crypto.rs` known-answer tests (independent
counter-block construction, byte-placement regression checks — see that
file's own header comment for why round-trip tests alone can't catch a
counter-block placement bug) were updated to call `ctr`/`aes` directly
instead of `aws_lc_rs`, preserving their original purpose: an
independently-reconstructed encryption path to compare against
`CryptoContext::encrypt`'s own output, not a like-for-like restatement of
the same code under test.

`aws-lc-sys`'s `cmake`+C-compiler build requirement (previously the
`aws-lc-rs` era's caveat in this section) no longer applies —
`crates/srt-protocol` now has zero native build dependencies.

## Fuzzing

The vendored crate ships four `libFuzzer` targets under `fuzz/`:
`fuzz_packet_decode`, `fuzz_handshake_decode`, the stateful
`fuzz_connection_feed`, and the transport admission target `fuzz_admission`.
The fuzz package is excluded from the main
workspace (`exclude = ["crates/srt-protocol/fuzz"]` in the root
`Cargo.toml`) and needing its own empty `[workspace]` table (see the
comment in `fuzz/Cargo.toml`) plus `cargo-fuzz` and a nightly toolchain,
neither installed by default in a fresh environment:

```sh
cargo install cargo-fuzz --locked   # once
cd crates/srt-protocol/fuzz
cargo +nightly fuzz run fuzz_packet_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_handshake_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_connection_feed  -- -max_total_time=60
cargo +nightly fuzz run fuzz_admission        -- -max_total_time=60
```

**Run record:** `fuzz_packet_decode` — clean across two runs (12.5M then
18.5M executions, ~31M total, zero crashes). `fuzz_handshake_decode` —
**found a real panic within the first few thousand of its first 12M+
executions** (see the [Local patches](#local-patches) table above for the
bug and fix), then clean for a further 8.75M executions after the fix.
This is the malformed-input evidence the release gate is intended to produce,
and it did its job on the first real run. CI runs bounded smokes for all four
targets; retained minimized corpora under `fuzz/corpus/` seed later runs.

## Pulling future upstream commits

```sh
git fetch shiguredo-srt develop
git subtree pull --prefix=crates/srt-protocol shiguredo-srt develop --squash
```

This performs a real merge against the squashed import history, so local
patches (above) will show as ordinary merge conflicts if upstream touches
the same lines — most likely because upstream fixed the same issue
themselves, in which case prefer upstream's version and drop the local
patch. Re-run `cargo test -p shiguredo_srt -p pbt` after any pull, and
re-check the trimmed paths above (`crates/c-api`, `examples/`) in case
upstream reintroduces them — re-remove or reconsider case by case.

If the `shiguredo-srt` remote isn't configured in a fresh clone:

```sh
git remote add shiguredo-srt https://github.com/shiguredo/srt-rs.git
```

## Import-time upstream issue snapshot

At import time, `issues/` (open) vs. `issues/closed/` showed 27 closed
issues and roughly 20 open ones on `develop`, numbered up to `0069`. Only
0049/0050/0052 (above) were patched — they were the ones with direct,
concrete security implications identified at import. The original watch list
also named 0051, 0056, 0059, and 0066. This paragraph is provenance, not the
current project backlog: KM negotiation now fails closed, receive/flight
windows are bounded and configurable, and current release status is maintained
in the root [README](../../README.md) and [SECURITY.md](../../SECURITY.md).
Re-check upstream `issues/closed/` and every local patch after any
`subtree pull`; prefer an upstream fix and remove the local patch when the
behavior and regression coverage are equivalent.

## License and dependency audit

The original import used a manual dependency review. The repository now runs
`cargo deny check` in its root release gates, with policy and any review-dated
exceptions documented in `deny.toml` and
[`docs/dependency-exceptions.md`](../../docs/dependency-exceptions.md).

**Current state (post crypto-backend swap, see above):** dependencies are
`aes`, `aes-kw`, `cipher`, `ctr`, `hmac`, `pbkdf2`, `sha1`, plus their own
transitive deps (`cmov`, `cpubits`, `ctutils`, `digest`, `inout`, and
`typenum`/`generic-array`/`hybrid-array` already shared with this repo's
existing dependency tree), all pure Rust, all from crates.io. All license
expressions resolve to a term already in `deny.toml`'s `[licenses] allow`
list (MIT, Apache-2.0 both appear across this set). No GPL/copyleft term.
**Zero native (C/C++) build dependencies** — confirmed via a clean `cargo
build` with no `cc`/`cmake`/`jobserver` compilation step, unlike the
`aws-lc-rs` era below.

**Historical note (no longer applicable, kept for context):** the original
`aws-lc-rs` dependency pulled in `aws-lc-sys`, which built a C library via
`cmake` at compile time — a new native-build-tooling requirement (cmake +
a C compiler) separate from and in addition to this repo's existing
FFmpeg/libsrt static-build toolchain. This was the direct motivation for
the crypto backend swap documented above; it no longer applies.
