# Third-Party Licenses

This workspace is Apache-2.0 (see [`LICENSE`](LICENSE)). It depends on
crates.io packages carrying their own licenses; the standard
MIT / Apache-2.0 dual licenses cover the large majority and are not
itemized here. This file records the **non-standard license terms in the
dependency graph** so redistribution can be evaluated at a glance.

License inventory method: `license` fields read from every registry
package resolved in `Cargo.lock` (271 packages). Regenerate after major
dependency changes — or better, run `cargo deny check licenses`
(configured by [`deny.toml`](deny.toml)).

## Permissive, non-MIT/Apache terms

| License | Crates | Reachable from |
|---|---|---|
| MPL-2.0+ (file-level copyleft) | `bitmaps` 3.2.1 | `glommio` |
| Zlib | `nanorand` 0.7.0 | `flume` ← `glommio`, `monoio` |
| Zlib | `slotmap` 1.0.7 | `compio-executor` ← `compio` |
| BSD-3-Clause | `instant` 0.1.13 | `fastrand` ← nearly everything async |
| Unlicense OR MIT | `memchr`, `byteorder`, `aho-corasick`, `winapi-util`, `same-file`, `walkdir` | tracing-subscriber, regex, walkdir |
| MIT OR Zlib OR Apache-2.0 | `miniz_oxide` | backtrace |
| 0BSD OR MIT OR Apache-2.0 | `adler2` | backtrace |
| BSD-2-Clause OR Apache-2.0 OR MIT | `zerocopy`, `zerocopy-derive` | ahash, zerocopy users |
| Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | `rustix`, `linux-raw-sys`, `wasi`, `wasip2`, `wit-bindgen` | mio/polling socket stacks |

All of the above are permissive and compatible with an Apache-2.0
distribution. Notes on the three that most often trigger review:

- **MPL-2.0** (`bitmaps`) is file-level copyleft only: changes to those
  files must be shared, but linking/combining does not infect this
  codebase.
- **Zlib** (`nanorand`, `slotmap`) requires retaining the copyright
  notice in redistributions — satisfied by shipping this file plus the
  upstream notice text.
- **BSD-3-Clause** (`instant`) carries a non-endorsement clause; no
  promotion rights are exercised by this project.

## LGPL option, not selected

`r-efi` is licensed `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; the
dependency chain uses it under the dual MIT/Apache-2.0 grant. No LGPL
obligations apply.

## Vendored code

`crates/srt-protocol` is a vendored import of
[shiguredo/srt-rs](https://github.com/shiguredo/srt-rs) under
Apache-2.0 — see [VENDOR.md](crates/srt-protocol/VENDOR.md) for
provenance and local patches.

## Audit status

`cargo-deny` was unavailable when the vendored import landed (noted in
[VENDOR.md § License audit](crates/srt-protocol/VENDOR.md#license-and-dependency-audit)).
The manual audit above supersedes it; re-run
`cargo deny check licenses` in CI before any release build.
