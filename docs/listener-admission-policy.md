# Listener admission and per-StreamID policy

This guide is the application contract for selecting listener policy from an
incoming SRT handshake. Use it when one listening address serves several
tenants, resources, credentials, or bonding groups.

The recommended entry point is
`srt_transport::PeerTable::admit_with_resolver`. It provides typed policy,
bounded deferral, rejection codes, telemetry, and a guarded raw escape hatch
without moving application policy into the sans-I/O protocol core.

## Where the decision happens

SRT listener admission is a two-packet handshake:

1. `INDUCTION` creates bounded half-open state and returns a listener-generated
   SYN cookie. It does not carry StreamID.
2. `CONCLUSION` echoes that cookie and carries StreamID, GROUP, and KM
   extensions.
3. `PeerTable` validates capacity, ownership, and the cookie, then decodes one
   `AdmissionRequest`.
4. The application resolver accepts, configures, rejects, or defers the peer.
5. Only after that result is applied does `SrtConnection::feed_recv_buf`
   interpret CONCLUSION and process KM.

This is the same timing boundary as Haivision SRT's
[`srt_listen_callback`](https://github.com/Haivision/srt/blob/fcae57145c000a9e7b72aa777adb8f85c2463242/docs/API/API-functions.md#srt_listen_callback):
CONCLUSION has arrived but has not yet been interpreted, so a passphrase chosen
from StreamID participates in KM processing for that connection.

`AdmissionRequest` contains:

- `peer`: the UDP source address;
- `claimed_identity`: handshake phase, claimed StreamID, GROUP affinity, and
  SYN cookie;
- `handshake`: the decoded handshake for advanced policy; and
- `access_control`: the parsed `#!::k=v,...` StreamID convention, when valid.

Every field remains untrusted. The cookie was issued by the listener and is
exact-matched against retained half-open state, but it carries guessable worker
routing metadata and is not an authentication primitive. Treat StreamID as a
routing or credential-selection claim, not authenticated identity. A
successful KM exchange proves possession of the selected shared passphrase; it
does not prove a person, account, or endpoint identity.

Handshake v4 cannot carry StreamID or other extensions. A resolver that
requires StreamID should reject a request where it is absent instead of
silently selecting a default tenant.

## Recommended resolver

Start from a prepared listener so the session template and transport/admission
mechanisms are validated together. Resolve only the fields that differ for one
peer:

```rust
use shiguredo_srt::{KeyLength, Timestamp};
use srt_transport::{
    AdmissionResolution, IngressTelemetry, ListenerConfig,
    ListenerEncryptionConfig, ListenerPeerPolicy, PolicyOverride,
    RejectionReason, RuntimeFlavor,
};

let listener = ListenerConfig::builder("0.0.0.0:9000".parse()?).build()?;
let prepared = listener.prepare(RuntimeFlavor::Tokio)?;
let mut peers = prepared.peer_table();
let admission = prepared.admission_options();
let telemetry = IngressTelemetry::new();

// Called by the application's UDP receive loop for each datagram.
let outcome = peers.admit_with_resolver(
    peer,
    &datagram,
    Timestamp::from_micros(elapsed_micros),
    &admission,
    worker_index,
    worker_count,
    &telemetry,
    |request| {
        let Some(user) = request
            .access_control
            .as_ref()
            .and_then(|access| access.user_name())
        else {
            return AdmissionResolution::Reject {
                reason: RejectionReason::BAD_REQUEST,
            };
        };

        // Populate this cache outside the receive loop. The resolver is
        // synchronous and must remain bounded.
        let Some(passphrase) = cached_tenant_passphrase(user) else {
            return AdmissionResolution::Defer;
        };

        let encryption = ListenerEncryptionConfig::new(
            passphrase,
            KeyLength::Aes128,
        )
        .expect("credential cache contains validated SRT passphrases");

        AdmissionResolution::Configure(ListenerPeerPolicy {
            encryption: PolicyOverride::Set(Some(encryption)),
            ..ListenerPeerPolicy::default()
        })
    },
);
```

`ListenerPeerPolicy` can override encryption, latency, bandwidth, flow control,
and GROUP metadata. Every field defaults to `PolicyOverride::Inherit`, which
retains the prepared listener value. `PolicyOverride::Set(None)` deliberately
disables an inherited optional value; it is not the same as `Inherit`.

Policy can be assembled in independent layers. Apply lower-priority defaults
first and higher-priority decisions last:

```rust
let mut policy = service_policy;
policy.overlay(tenant_policy);
policy.overlay(resource_policy);
AdmissionResolution::Configure(policy)
```

Only `Set` values replace an earlier layer, so a component that does not own a
setting cannot accidentally reset it. Validation and application happen before
protocol input. Invalid typed policy fails closed with an internal-error
rejection and increments `policy_errors`.

## Resolver outcomes

| Result | Effect |
|---|---|
| `Accept` | Process CONCLUSION with the prepared listener policy unchanged. |
| `Configure(policy)` | Validate and atomically apply explicit per-peer overrides, then process CONCLUSION. |
| `Reject { reason }` | Queue a rejection response, mark the half-open peer terminal, and never establish it. |
| `Defer` | Retain the untouched half-open peer for a retransmitted CONCLUSION; do not extend its original hard expiry. |

Continue draining `PeerTable::poll_outbound` after `Rejected` or a terminal KM
failure so the queued protocol response reaches the caller before the peer is
retired.

Use `Defer` only for a cache miss that another task is already resolving. It is
not an invitation to perform database or network I/O in the packet path. The
half-open capacity limit and timeout remain active, so repeated misses cannot
retain state forever.

`RejectionReason` exposes standard application meanings and
`RejectionReason::application(0..=999)` for the SRT user range 2000-2999.
Prefer coarse responses such as `UNAUTHORIZED` or `FORBIDDEN`; detailed
differences can disclose whether a tenant or resource exists. The raw
`AdmissionDecision` API remains available when an integration must preserve an
existing numeric wire contract. See Haivision's
[rejection-code registry](https://github.com/Haivision/srt/blob/fcae57145c000a9e7b72aa777adb8f85c2463242/docs/API/rejection-codes.md).

## Reuseport and worker ownership

For a single acceptor or shared listener loop, call `admit_with_resolver`
directly. For several `SO_REUSEPORT` acceptors, call
`admit_and_forward_with_resolver`.

The latter first routes a rehashed CONCLUSION back to the acceptor that owns
its half-open cookie state. Only that owner invokes the resolver. Credentials
and resolved policy therefore stay local instead of crossing worker channels.
A forwarded worker must run the same resolver when it handles the forwarded
`WorkerMessage::Handshake`.

## Telemetry contract

Export `IngressTelemetry::snapshot()` from the same shared counter instance
passed to admission. The snapshot uses independent relaxed atomic loads: each
field is a safe cumulative counter, but the full snapshot is not a
cross-counter transaction.

| Counter | Operational meaning |
|---|---|
| `policy_requests` | Valid-cookie CONCLUSION attempts presented to policy, including retransmissions. |
| `policy_configurations` | Typed per-peer configurations successfully applied. Plain `Accept` is not included. |
| `policy_deferred` | Attempts retained without feeding CONCLUSION or refreshing expiry. |
| `policy_rejections` | Application policy rejections. |
| `policy_errors` | Invalid/out-of-state policy produced by the application; sustained nonzero values indicate a configuration bug. |
| `credential_failures` | KM failed after policy selected a credential, or encryption negotiation otherwise failed closed. |
| `expired_half_open` | Incomplete peers removed after their hard inactivity bound. |
| `invalid_cookies` / `cookie_route_failures` | Cookie validation failures and failed cross-worker delivery. |
| capacity-drop counters | Total, half-open, established, and per-source limits shedding load. |

These are attempt counters, not unique-connection counters. Export rates or
deltas rather than attaching an unbounded StreamID label. Never put StreamID,
passphrases, or parsed access-control fields into logs or metric labels unless
the application has explicitly sanitized and bounded them.

Use `report()` only for a uniform human-readable shutdown line. Metrics and
control planes should consume `snapshot()` so field names and units remain
stable.

## Escape hatches and composition boundary

Choose the narrowest surface that fits:

| Need | API |
|---|---|
| Listener-wide validated defaults | `ListenerConfig` / `SessionConfig` / `AdmissionConfig` |
| Per-peer typed policy | `admit_with_resolver` + `ListenerPeerPolicy` |
| Existing raw rejection callback | `admit_with_authorizer` |
| Protocol control not modeled in typed policy | `admit_with_connection_hook` |
| Fully custom listener loop | prepared sockets + public `PeerTable` methods |
| Fully custom sans-I/O integration | `SrtConnection` guarded listener setters |

`admit_with_connection_hook` receives both `&AdmissionRequest` and
`&mut SrtConnection` in the same post-cookie, pre-CONCLUSION window. The
connection reference cannot escape the closure, and guarded setters reject use
after the listener leaves `Listening`. The hook may combine raw setters with a
typed `AdmissionResolution`; it must not feed the datagram itself, retain the
connection reference, or perform unbounded work.

At the protocol layer, `set_listener_encryption`, `set_listener_latency`,
`set_listener_bandwidth`, `set_listener_flow_control`,
`set_listener_group_extension`, and the combined `set_listener_policy` are the
supported raw controls. Applications are not forced through the facade, but
the facade remains the safer default because it validates typed units,
composes overlays, accounts telemetry, and preserves admission ordering.

## Security checklist

- Keep resolver work local, cached, deterministic, and bounded.
- Validate cache entries before they enter the packet path; SRT passphrases
  must be 10-79 bytes for interoperability.
- Keep total, half-open, established, per-source, and socket-memory limits
  enabled.
- Treat `Defer` volume and half-open expiry as abuse signals.
- Use unique tenant credentials, but do not treat them as general identity.
- Put an authenticated protocol inside SRT when integrity or endpoint identity
  matters; SRT's AES-CTR payload encryption is malleable.
- Avoid tenant-enumerating rejection details and timing differences.
- Do not log secret-bearing configuration or unsanitized StreamID claims.

The workspace-wide threat model and disclosure process are in
[`SECURITY.md`](../SECURITY.md). Haivision's StreamID conventions and access
control model are described in its pinned
[access-control guide](https://github.com/Haivision/srt/blob/fcae57145c000a9e7b72aa777adb8f85c2463242/docs/features/access-control.md).
