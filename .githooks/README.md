# Local Git hooks

This directory is opt-in because Git does not version `core.hooksPath`.
Enable the repository's pre-commit checks once per clone:

```sh
cargo xtask install-hooks
```

The hook runs `cargo xtask precommit` (fmt, clippy, rustdoc, typos) for
staged Rust changes. CI remains the required source of truth.
