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
admission layer rejects malformed traffic before allocating a peer and
independently bounds total, half-open, established, and per-source-IP state.
Consumers should retain or tighten those defaults, add network-level packet-
rate limits for volumetric attacks, and resolve policy from the StreamID/group
identity before accepting a connection. StreamID is a caller-controlled claim,
not authenticated identity. A per-StreamID passphrase can validate possession
of that tenant credential during KM, but authorization decisions should be
confirmed or bound to an authenticated protocol inside the SRT payload when
identity matters.

SRT's standard passphrase mode provides confidentiality using AES-CTR and key
exchange compatibility with libsrt. It does **not** provide cryptographic
integrity or peer authentication: ciphertext is malleable, and possession of a
shared passphrase is not an identity. Use a strong unique passphrase, protect
the surrounding network where integrity matters, and put an authenticated
protocol inside the SRT payload when tamper detection or endpoint identity is
required. Never reuse an explicitly supplied salt/SEK pair across sessions.
Callers that omit them use fresh operating-system randomness.
The layered transport facade likewise generates nonzero socket IDs and initial
sequence numbers unless raw `ConnectionOptions` explicitly override them.

Secrets are redacted from configuration debug output. Connection-owned
passphrase/SEK buffers are zeroized after handshake use and on drop; layered
`SessionConfig` and shared-listener admission templates also zeroize their
owned passphrase/salt/SEK storage on replacement or drop. Rust and the allocator
can still copy application-owned strings before transfer; avoid logging,
cloning, swapping, or crash-dumping secret-bearing process memory.

Listener admission resolvers execute in the CONCLUSION packet path. Use a
bounded local/cache lookup and populate remote credential data asynchronously
outside the resolver. `AdmissionResolution::Defer` deliberately does not
refresh the original half-open deadline; retain a tight capacity/TTL policy so
cache misses and hostile StreamIDs cannot retain state indefinitely. Avoid
revealing whether a tenant, resource, or credential exists through overly
specific rejection codes or timing differences.

Encryption negotiation is fail-closed: an encrypted caller cannot establish an
unencrypted listener session, and a listener requiring encryption cannot accept
a CONCLUSION without KMREQ. The listener returns a protocol KM error and retires
the terminal half-open peer after the response is drained.

The sans-I/O core is single-owner: mutating operations require `&mut self`.
Runtime adapters may move a connection between workers, but must not drive one
connection concurrently from multiple tasks. Treat all configured resource
limits and the aggregate listener socket-memory budget as security controls,
not throughput hints. An explicit unsupported transport mechanism fails
validation rather than silently weakening the requested policy.

## Security checks

Root CI runs strict linting, the complete test/property suite, documentation and
package checks, dependency policy, full-history secret scanning, Miri smoke
tests, AddressSanitizer, coverage enforcement, and bounded fuzz smoke tests.
Dependency-policy exceptions are documented in
[`docs/dependency-exceptions.md`](docs/dependency-exceptions.md).
