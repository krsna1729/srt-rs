# VENDOR.md — shiguredo/srt-rs import

This crate (`shiguredo_srt`) is a vendored import of
[`shiguredo/srt-rs`](https://github.com/shiguredo/srt-rs), imported via
`git subtree` so future upstream commits can be pulled in with a normal
merge rather than a manual re-copy. See
[`../../docs/srt-pure-rust-plan.md`](../../docs/srt-pure-rust-plan.md)
(decision D1) for why this crate specifically, and
[`../../docs/agent-guidance/quality/srt-bonding-wire-spec-2026-08-16.md`](../../docs/agent-guidance/quality/srt-bonding-wire-spec-2026-08-16.md)
for the bonding-specific source verification done against it.

## Contents

- [Provenance](#provenance)
- [What was trimmed from the upstream tree](#what-was-trimmed-from-the-upstream-tree)
- [Local patches](#local-patches)
- [Crypto backend: pure-Rust RustCrypto stack, not aws-lc-rs](#crypto-backend-pure-rust-rustcrypto-stack-not-aws-lc-rs)
- [Fuzzing](#fuzzing)
- [Pulling future upstream commits](#pulling-future-upstream-commits)
- [Known open upstream issues, not yet patched locally](#known-open-upstream-issues-not-yet-patched-locally)
- [License and dependency audit](#license-and-dependency-audit)

## Provenance

- Upstream: <https://github.com/shiguredo/srt-rs>
- Branch: `develop` (this is upstream's actively-developed default branch,
  confirmed via `git remote show origin` — not `main`, which lags behind)
- Commit at import: `6779cdddb7cd3233032e06538243715d50df3d0b`
  (2026-08-16 10:53:50 +0900)
- License: Apache-2.0 (upstream `LICENSE`, matches this repo's MIT
  license with no conflict either direction)
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
  binaries. this repo's interop binaries live in the sibling
  `crates/srt-interop` crate instead (Phase 3 onward).

Also removed entirely (`git rm`, not `--cached` — not present on disk in
this checkout, retrievable from the `shiguredo-srt` remote or the subtree-
add commit's history if needed): upstream's own `README.md`, `CHANGES.md`,
`issues/` (open + closed ticket files), `AGENTS.md`, `CLAUDE.md`,
`.markdownlint.jsonc`, `Makefile`, `canary.py`, `prek.toml`,
`refs/srt/draft-sharabayko-srt.md` — not because they're not useful
(several are cited directly in this file and in
[`srt-bonding-wire-spec-2026-08-16.md`](../../docs/agent-guidance/quality/srt-bonding-wire-spec-2026-08-16.md)),
but because `git ls-files '*.md'` picked up 74 of them at import time, and
`scripts/check/docs.mjs` requires every tracked Markdown file in the whole
repo to be linked from `docs/README.md` with this repo's doc conventions
(a `Contents` H2, no SVG badge links — upstream's `README.md` has crates.io/
docs.rs/license SVG badges, which trip the "no SVG" rule meant for
architecture diagrams). Rewriting vendored upstream content to satisfy a
different project's doc-lint conventions isn't worth doing, and would fight
future `subtree pull`s (upstream will keep writing its own README/CHANGES
its own way). Read them directly from the live upstream repo
(<https://github.com/shiguredo/srt-rs/tree/develop>) or from disk in this
checkout — they're real files, just not tracked or doc-indexed by this repo.

**Kept, and wired into this repo's root workspace** (`Cargo.toml`
`members`): `pbt/` (property-based tests, one per core module — Phase 3/4
should extend these, not duplicate them). `fuzz/` is kept but stays
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
| [0052](https://github.com/shiguredo/srt-rs/blob/develop/issues/0052-bug-fix-crypto-salt-default-all-zero.md) | High | `handle_handshake_caller` defaulted an unset `crypto_salt` to `[0u8; 16]`, making PBKDF2 derive the same KEK from the same passphrase every time (defeats rainbow-table resistance). Now returns `Error::crypto_error(...)` instead of defaulting (`src/srt_connection.rs`). The listener side was already safe — it derives salt from the peer's KMREQ, never invents its own. |
| *(not upstream-tracked — found here, via live capture against real libsrt, not from upstream's own issue list)* | Critical for StreamID-dependent features | `add_sid_extension`/`add_congestion_extension` wrote the extension bytes correctly but never set the `CONFIG` bit (`0x0004`) in `extension_field`. Real libsrt gates its own extension-scanning loop on that exact bit (confirmed at `srtcore/core.cpp:2925,12433`) and always sets it itself when adding a SID/congestion extension (`core.cpp:1708`). Without the fix: a Rust caller's StreamID was correctly encoded on the wire (verified via `tcpdump` — packet size delta matched the StreamID length exactly) but a real libsrt listener silently never looked for it. This crate's own `test_sid_extension_basic` didn't catch it because it only round-trips through this crate's own `decode()`, which doesn't gate on the flag either — only a real cross-implementation test surfaces this class of bug. Fixed in `src/srt_handshake.rs`; added `test_sid_extension_sets_config_flag`/`test_congestion_extension_sets_config_flag` regression tests. Live-verified fixed against real libsrt in both directions (Rust caller → libsrt listener and libsrt caller → Rust listener), see `crates/srt-interop/`. |
| *(not upstream-tracked — missing capability, not a regression)* | Critical — silently swallowed all rejections | Reject-reason handling didn't exist at all. Real libsrt encodes a rejected handshake as `1000 + SRT_REJECT_REASON` in the wire's handshake-type field (`srtcore/handshake.h`'s `URQFailure`); `HandshakeType::from_u32` only recognized 5 fixed success values and hard-errored on anything else, so `decode()` failed on any real rejection response with a generic "unknown handshake type" error, and separately `handle_handshake_caller`'s match had a silent `_ => {}` catch-all with no arm for a decoded rejection at all — a caller connecting to a passphrase-enforcing listener without one would just hang until its own handshake timeout, with the actual reason never surfacing anywhere. Added a `Rejected` sentinel variant, a `reject_reason: Option<i32>` field on `HandshakePacket`, a `new_rejection` constructor (Listener-side emission — not yet wired into `SrtConnection`'s public API; that requires an access-control decision point that doesn't exist yet, deferred to Phase 6/7's Driver work), and a proper `HandshakeType::Rejected` match arm in `handle_handshake_caller` that surfaces the reason via `Error::handshake_rejected`. Live-verified against a real libsrt listener with `SRTO_PASSPHRASE` set, connected to by a Rust caller with none: libsrt's own log reported `rsp(REJECT): 1011 - Password required or unexpected`; the Rust caller independently decoded and reported `reason=11` — the exact same value (`1011 - 1000 = 11 = SRT_REJ_UNSECURE`), confirmed byte-for-byte against real libsrt, not just self-consistent. `src/srt_handshake.rs`, `src/srt_connection.rs`; regression tests there and in `pbt/tests/prop_handshake.rs` (two existing property tests, `test_handshake_type_from_u32_invalid` and `test_decode_invalid_handshake_type`, encoded the *old* behavior as their spec and had to be narrowed to the true-invalid `[2,999]` range, plus new complementary tests for the now-valid `>=1000` range). |
| *(this repo's bug, introduced by the reject-reason patch above, not upstream's)* | Panic on adversarial input — found by `cargo fuzz run fuzz_handshake_decode`, within the first few thousand of 12M+ iterations | `decode()`'s `handshake_type_raw as i32 - 1000` panicked ("attempt to subtract with overflow") for any `handshake_type_raw >= 0x8000_0000` — casting such a value to `i32` already lands near `i32::MIN`, and subtracting 1000 more underflows `i32`'s range. No real libsrt peer sends a value that large, but `decode()` must never panic on attacker-controlled input regardless — this is exactly what the malformed-input fuzz corpus requirement in `docs/srt-pure-rust-plan.md` Phase 3 exists to catch, and it did, on the very first fuzz run. Fixed by widening to `i64` (cannot overflow for any `u32` input) before narrowing to the public `i32` field. Found the same class of bug by code review in `encode()`'s mirror-image addition (`1000 + reject_reason` overflowing for `reject_reason` near `i32::MAX`) and fixed it the same way, proactively — the fuzzer only exercises `decode()`, not `encode()`. `src/srt_handshake.rs`; regression tests `test_decode_adversarial_huge_handshake_type_does_not_panic` and `test_encode_extreme_reject_reason_does_not_panic`. See [Fuzzing](#fuzzing) below for the full run record. |

Fixing the crypto issues required updating 4 existing integration tests
(`tests/test_srt_connection.rs`) that relied on the old implicit-zero-salt
default to now explicitly set `crypto_salt`, matching how a real caller
must use the API post-patch. All tests across the crate (unit +
integration + property-based + doctests) pass after these patches —
verified via `cargo test -p shiguredo_srt` and `cargo test -p pbt`.

**Why patch locally instead of waiting for upstream:** this code will
eventually carry real customer stream encryption (Phase 5). All three are
small, mechanical, exactly-as-upstream-specified fixes (each issue file
already states the precise design direction) — the cost of patching now is
low and the cost of shipping with an open, self-identified Critical crypto
bug is not a tradeoff worth making for the sake of staying byte-identical
to upstream.

## Crypto backend: pure-Rust RustCrypto stack, not aws-lc-rs

The vendored crate originally depended on `aws-lc-rs`, which pulls in
`aws-lc-sys` — a `cmake`+C-compiler native build step at compile time.
That's exactly the kind of native-toolchain dependency this whole migration
exists to move away from (see `docs/srt-pure-rust-plan.md`'s own framing:
replacing libsrt's heavy native build chain with a pure-Rust one). Replaced
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
data exchange — not just handshake completion**, using
`crates/srt-interop`'s caller/listener (extended with `[passphrase]`
support and a known test payload) against `test/native/srt-interop-{caller,
listener}.c` (extended with `SRTO_PASSPHRASE` and the same known payload):

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

The vendored crate ships two `libFuzzer` targets under `fuzz/`
(`fuzz_packet_decode`, `fuzz_handshake_decode`) — excluded from the main
workspace (`exclude = ["crates/srt-protocol/fuzz"]` in the root
`Cargo.toml`) and needing its own empty `[workspace]` table (see the
comment in `fuzz/Cargo.toml`) plus `cargo-fuzz` and a nightly toolchain,
neither installed by default in a fresh environment:

```sh
cargo install cargo-fuzz --locked   # once
cd crates/srt-protocol/fuzz
cargo +nightly fuzz run fuzz_packet_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_handshake_decode -- -max_total_time=60
```

**Run record:** `fuzz_packet_decode` — clean across two runs (12.5M then
18.5M executions, ~31M total, zero crashes). `fuzz_handshake_decode` —
**found a real panic within the first few thousand of its first 12M+
executions** (see the [Local patches](#local-patches) table above for the
bug and fix), then clean for a further 8.75M executions after the fix.
This is exactly the malformed-input corpus proof
`docs/srt-pure-rust-plan.md` Phase 3 calls for, and it did its job on the
first real run — worth re-running (with a longer `-max_total_time`, and
ideally the corpus this session generated under `fuzz/corpus/`, gitignored
and not committed) before Phase 4 builds further on top of the wire-format
layer.

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

## Known open upstream issues, not yet patched locally

At import time, `issues/` (open) vs. `issues/closed/` showed 27 closed
issues and roughly 20 open ones on `develop`, numbered up to `0069`. Only
0049/0050/0052 (above) were patched — they were the ones with direct,
concrete security implications for this repo's actual use. Others worth a
look before Phase 5 (crypto) or Phase 4 (data plane) land, not yet
triaged in depth here: 0051 (`should_pre_announce` duplicate key-refresh
event), 0056 (`CONCLUSION` KMREQ silent failure), 0059 (receiver buffer has
no explicit limit — a potential resource-exhaustion vector worth checking
against this repo's `SRTO_RCVBUF`-equivalent tuning), 0066 (retransmit
timer not reset after handling). Re-check `issues/closed/` after any
`subtree pull` — some of these may already be resolved by the time Phase 3
onward actually reads this list again.

## License and dependency audit

`cargo-deny` is not installed in the environment this vendoring was done
in, so this was checked manually — **re-run `cargo deny check` in an
environment that has it before this lands in a release build.**

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
