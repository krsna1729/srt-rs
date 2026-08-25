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

The crypto fixes include regression tests that prove independently-created
encrypted callers emit different handshake material, explicit zero SEKs are
rejected, and secret-bearing configuration is redacted. All tests across the crate (unit +
integration + property-based + doctests) pass after these patches —
verified via `cargo test -p shiguredo_srt` and `cargo test -p pbt`.

**Why patch locally instead of waiting for upstream:** this code carries real
stream encryption. All three are
small, mechanical, exactly-as-upstream-specified fixes (each issue file
already states the precise design direction) — the cost of patching now is
low and the cost of shipping with an open, self-identified Critical crypto
bug is not a tradeoff worth making for the sake of staying byte-identical
to upstream.

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
