# Dependency security exceptions

Last reviewed: 2026-08-24. Next mandatory review: 2026-11-24 or before any
release that publishes a runtime adapter, whichever comes first.

The published `shiguredo_srt` protocol crate has no known RustSec advisory.
Two unmaintained transitive crates are present only because this workspace also
builds six benchmark runtime backends:

| Advisory | Path | Exposure | Exit condition |
| --- | --- | --- | --- |
| RUSTSEC-2026-0247 (`bitmaps`) | `glommio 0.9` | Unpublished Linux benchmark/adapter only | Upgrade to a maintained compatible glommio release or remove this backend |
| RUSTSEC-2025-0057 (`fxhash`) | `monoio 0.2.4` | Unpublished Linux benchmark/adapter only | Upgrade when monoio replaces `fxhash`, patch upstream, or remove this backend |

Both advisories are maintenance-status notices, not known memory-safety or
remote-execution defects. `deny.toml` ignores exactly these IDs so any new
advisory still fails CI. The yanked `spin 0.9.8` is transitive through `flume`
for glommio, monoio, and compio. Cargo-deny reports it visibly; no compatible
lockfile-only update exists. Publishing any adapter is blocked until its tree
is advisory- and yank-free.
