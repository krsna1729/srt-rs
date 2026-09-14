# Dependency security exceptions

Last reviewed: 2026-09-14.

The published `srt-proto` protocol crate and all supported workspace crates
(`srt-lifecycle`, `srt-transport`, `srt-bench`) currently have **zero known
RustSec advisories**.

Following the runtime matrix reduction to `mio`, `tokio`, and `compio`, all
prior advisory exceptions (RUSTSEC-2025-0167, RUSTSEC-2026-0247, and
RUSTSEC-2025-0057) associated with glommio and monoio have been eliminated.
`deny.toml` has `ignore = []` and enforces `unsound = "all"`.
