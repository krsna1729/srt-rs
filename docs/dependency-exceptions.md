# Dependency security exceptions

Last reviewed: 2026-08-24. Next mandatory review: 2026-11-24 or before any
release that publishes a runtime adapter, whichever comes first.

The published `shiguredo_srt` protocol crate has no known RustSec advisory.
Two unmaintained transitive crates are present only because this workspace also
builds six benchmark runtime backends:

| Advisory | Path | Exposure | Exit condition |
| --- | --- | --- | --- |
| RUSTSEC-2025-0167 (`bitmaps`, unsound) | `glommio 0.9` | Unpublished Linux benchmark/adapter only | Upgrade to a maintained compatible glommio release or remove this backend |
| RUSTSEC-2026-0247 (`bitmaps`, unmaintained) | `glommio 0.9` | Same as above | Same as above |
| RUSTSEC-2025-0057 (`fxhash`, unmaintained) | `monoio 0.2.4` | Unpublished Linux benchmark/adapter only | Upgrade when monoio replaces `fxhash`, patch upstream, or remove this backend |

RUSTSEC-2025-0167 (`bitmaps`) is an **unsoundness** advisory, not merely an
unmaintained notice: `TryFrom<&[u8]>` creates invalid `bool` values,
constituting undefined behavior in safe code. The crate is archived and no
patched version exists. The community glommio fork still depends on
`bitmaps = "3.2"`, so git-pinning does not resolve it. Our code never calls
`bitmaps` directly; the exposure is confined to glommio's internal allocator
in an unpublished, `#[cfg(target_os = "linux")]`-gated benchmark adapter.

RUSTSEC-2025-0057 (`fxhash`) is an unmaintained notice with no known
memory-safety defect.

`deny.toml` sets `unsound = "all"` and ignores exactly these three IDs, so any
**new** unsoundness or vulnerability advisory in the graph still fails CI. The
yanked `spin 0.9.8` is transitive through `flume` for glommio, monoio, and
compio. Cargo-deny reports it visibly; no compatible lockfile-only update
exists. Publishing any adapter is blocked until its tree is advisory- and
yank-free.
