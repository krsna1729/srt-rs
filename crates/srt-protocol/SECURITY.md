# Security considerations

The workspace security and disclosure policy is maintained in
[`../../SECURITY.md`](../../SECURITY.md). This copy is included in the
published crate so consumers receive the important protocol constraints.

- Every datagram is untrusted input. Enforce admission and traffic limits in
  the I/O layer around this sans-I/O state machine.
- SRT passphrase encryption uses AES-CTR and does not authenticate ciphertext
  or identify a peer. Use an authenticated inner protocol when integrity or
  identity is required.
- Omitted caller salt and SEK values are generated with the operating-system
  CSPRNG. Never reuse an explicitly supplied salt/SEK pair between sessions.
- Secret configuration is redacted from `Debug`; connection-owned secret
  buffers are zeroized after use and on drop. Application-owned copies remain
  the application's responsibility.
- A connection has one mutable driver. Do not concurrently drive the same
  `SrtConnection` from multiple tasks.

Report vulnerabilities privately through GitHub's **Report a vulnerability**
flow for <https://github.com/krsna1729/srt-rs>.
