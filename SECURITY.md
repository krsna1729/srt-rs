# Security policy

## Supported versions

This project is pre-1.0. Security fixes are made on the current default branch
and the newest published `shiguredo_srt` release. Older canary releases are not
maintained.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** flow in the repository Security
tab. Do not open a public issue for an undisclosed vulnerability. Include the
affected version or commit, a minimal reproducer or packet capture where safe,
the expected impact, and whether the issue is remotely reachable. Maintainers
will acknowledge a complete report within seven days and coordinate disclosure
after a fix is available.

## Protocol threat model

`shiguredo_srt` parses attacker-controlled UDP datagrams. Applications must
assume that source addresses can be spoofed and that packets may be duplicated,
reordered, truncated, replayed, or intentionally malformed. The transport
admission layer bounds half-open state and rejects malformed traffic before
allocating a peer; consumers should retain those defaults, apply per-source
network rate limits, and authorize the authenticated StreamID before accepting
a connection.

SRT's standard passphrase mode provides confidentiality using AES-CTR and key
exchange compatibility with libsrt. It does **not** provide cryptographic
integrity or peer authentication: ciphertext is malleable, and possession of a
shared passphrase is not an identity. Use a strong unique passphrase, protect
the surrounding network where integrity matters, and put an authenticated
protocol inside the SRT payload when tamper detection or endpoint identity is
required. Never reuse an explicitly supplied salt/SEK pair across sessions.
Callers that omit them use fresh operating-system randomness.

Secrets are redacted from `ConnectionOptions` debug output and connection-owned
passphrase/SEK buffers are zeroized after handshake use and on drop. Rust and
the allocator can still copy application-owned strings before transfer; avoid
logging, cloning, swapping, or crash-dumping secret-bearing process memory.

The sans-I/O core is single-owner: mutating operations require `&mut self`.
Runtime adapters may move a connection between workers, but must not drive one
connection concurrently from multiple tasks. Treat all configured resource
limits as security controls, not throughput hints.

## Security checks

Root CI runs strict linting, the complete test/property suite, documentation and
package checks, dependency policy, full-history secret scanning, Miri smoke
tests, AddressSanitizer, coverage enforcement, and bounded fuzz smoke tests.
Dependency-policy exceptions are documented in
[`docs/dependency-exceptions.md`](docs/dependency-exceptions.md).
