# Local Git hooks

This directory is opt-in because Git does not version `core.hooksPath`.
Enable the repository's pre-commit checks once per clone:

```sh
git config core.hooksPath .githooks
```

The hook runs rustfmt, clippy, and the fast protocol/property suites for
staged Rust changes. CI remains the required source of truth.
