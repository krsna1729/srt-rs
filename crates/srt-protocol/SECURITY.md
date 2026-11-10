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
- Both encrypted roles establish independent transmit keys through standard
  runtime KMREQ/KMRSP before announcing application readiness. Drive control
  output and timers until `ConnectionEvent::Connected`; handshake state alone
  is not a send-readiness signal. Early peer DATA remains receive-window
  bounded and is delivered only after that event. A delayed KM confirmation
  after terminal close is rejected and cannot announce readiness.
- Reflection protection remembers the four most recently retired transmit
  keys independently of receive-key history. This is bounded hardening, not
  unlimited replay protection or peer authentication.
- Secret configuration is redacted from `Debug`; connection-owned secret
  buffers are zeroized after use and on drop. Application-owned copies remain
  the application's responsibility.
- A connection has one mutable driver. Do not concurrently drive the same
  `SrtConnection` from multiple tasks.

Report vulnerabilities privately through GitHub's **Report a vulnerability**
flow for <https://github.com/krsna1729/srt-rs>.
