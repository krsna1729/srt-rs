# Connection telemetry

`SrtConnection::stats()` returns a copyable, non-clearing `ConnectionStats`
snapshot. It follows the accumulated/interval/instantaneous model described by
[libsrt's statistics API](https://github.com/Haivision/srt/blob/master/docs/API/statistics.md),
while using Rust names with explicit units instead of reproducing the
`SRT_TRACEBSTATS` C ABI.

```rust
use std::time::Duration;

# use shiguredo_srt::SrtConnection;
# fn sample(connection: &SrtConnection) {
let first = connection.stats();
// The application waits using its own runtime and clock.
let second = connection.stats();
let one_second = second.interval_since(&first, Duration::from_secs(1));

if let Some(sender) = one_second.sender {
    // SRT datagram bytes, including its header and retransmissions.
    let mbps = sender.srt_bytes_sent.per_second.map(|bytes| bytes * 8.0 / 1_000_000.0);
    let _ = mbps;
}
# }
```

Snapshots do not read or retain a wall clock and never reset counters. Each
`CounterDelta` contains an optional interval count and per-second rate. Both
are `None` if a counter regressed, which detects accidentally comparing
different connections or a reset. A zero elapsed duration retains the count
but produces no rate.

## Measurement semantics

- `total_sent` and `total_bytes_sent` count unique original packets and their
  payload. `total_data_packets_sent` includes retransmissions.
- `total_srt_bytes_sent` counts every emitted SRT DATA datagram, including its
  16-byte SRT header and retransmissions. `total_srt_bytes_received` does the
  same for received datagrams, including duplicates. These deliberately omit
  the caller-owned IP/UDP layer. A transport that needs libSRT-compatible
  network bytes adds 28 bytes per IPv4 datagram or 48 bytes per IPv6 datagram.
- `total_received` and `total_bytes_received` count unique packets accepted for
  delivery and their SRT datagram bytes. Retransmitted packets that arrive
  first are unique; every packet bearing the retransmit flag is also counted
  by `total_retransmitted`.
- Sender `total_lost` counts a sequence number when a peer NAK newly schedules
  it for retransmission. Repeated NAKs do not recount a sequence while it is
  already queued; a later loss after retransmission is a new loss occurrence.
- Receiver `total_lost` counts newly detected missing sequence numbers.
  `total_dropped` is the subset later abandoned by TLPKTDROP.
- `payload_bytes_in_buffer` is exact. Available buffer capacity is exact in
  packets and includes DATA already delivered into the bounded application
  event queue but not yet polled. Thus a stalled application reduces the
  advertised SRT receive window instead of growing an unbounded payload queue.
  `available_buffer_bytes` is `None` because this core configures packet
  capacity, so inventing a byte capacity would be misleading.
- Peer measurements are `None` until a full ACK has been received. Peer link
  capacity in bytes per second is derived from its packet-capacity estimate
  and measured wire bytes per packet.

## Restream quality mapping

The following mapping covers the fields currently sampled by Restream's SRT
ingest and egress quality collectors:

| Restream/libSRT family | `shiguredo_srt` source |
| --- | --- |
| `msRTT` | receiver `rtt`; sender `peer_rtt_micros` |
| `mbpsSendRate` | sender interval `srt_bytes_sent.per_second`, plus transport-layer overhead when exact libSRT parity is required |
| `mbpsRecvRate` | receiver `receiving_rate_bytes_per_second`, or receiver interval `srt_bytes_received.per_second`, plus transport-layer overhead when required |
| `mbpsBandwidth` | receiver `link_capacity_bytes_per_second`; sender `peer_link_capacity_bytes_per_second` |
| send/receive TSBPD delay | direction `tsbpd_delay_micros` |
| send/receive buffer time | `buffer_span_micros` in the respective direction |
| loss, retransmit, drop, undecrypt | cumulative direction fields and their `interval_since` deltas |
| ACK/NAK | `total_acks_received`, `total_naks_received`, `total_acks_sent`, `total_naks_sent` |
| buffered bytes | exact `payload_bytes_in_buffer` |
| available buffer | `available_buffer_packets`; byte availability is explicitly `None` |
| flight, flow, congestion windows | sender `packets_in_flight`, `flow_window_packets`, `congestion_window_packets` |

Unlike `srt_bistats(clear = 1)`, sampling cannot mutate transport state. This
makes independent metrics consumers safe: each can retain its own previous
snapshot and sampling interval.

## Bonded transport

`srt_transport::GroupConnectionStats` and ingress
`PeerTable::bonded_stats()` expose both views needed for a bonded session:
`logical_*` is the ordered, deduplicated media stream, while `wire_*` is the
sum across physical legs. Do not replace either with the other: logical
delivery measures publisher health, while wire counters, leg state, RTT, loss,
and retransmits diagnose a failing path. Sender-side and receiver-side loss
remain separate fields because they measure different observations.
