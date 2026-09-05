# Capacity classifier and observed frontier

This document publishes the deterministic capacity/deployment model from
`crates/srt-bench/src/model.rs` and the first Issue #71 frontier campaign.
The measured results are in [issue71-frontier-evidence.md](results/issue71-frontier-evidence.md),
with the complete role-level inputs and observations in
[controlled TSV](results/issue71-controlled.tsv) and
[deployment TSV](results/issue71-deployment.tsv).

All capacity statements are scoped to the measured host, CPU topology,
runtime, pacing policy, connection count, source workload, and duration.

## Model boundary

The classifier is pure and pre-run. It consumes typed workload, protocol,
network, host, and admission inputs; it does not open sockets or read
post-run observations. Result rows persist the input-derived class, reason
codes, derived quantities, and policy revision as `model_class_pre`,
`model_reasons_pre`, and `model_policy_rev`.

Unknown and not-applicable are distinct:

| state | meaning |
|---|---|
| Known | A configured or measured value is available. |
| Unknown | The value matters but no defensible value was supplied. |
| NotApplicable | The resource does not apply to the topology, such as a physical NIC on loopback. |

Zero is a real value. It is not a replacement for Unknown.

## Equations and units

The model keeps application payload, SRT DATA, UDP/IP, and physical-link
rates separate. Rates are bits per second unless named otherwise; packet rates
are packets per second; windows are packets; socket horizons are seconds;
latency and margins are milliseconds.

### Workload and packet rates

~~~text
source_pps_per_stream = source_bps_per_stream / (8 * payload_bytes)
source_pps_total      = source_pps_per_stream * source_streams
physical_data_pps     = source_pps_total * bond_physical_multiplier
payload_bps           = source_bps_per_stream * source_streams
~~~

For an unbonded or backup topology the physical multiplier is one. Broadcast
bonding multiplies physical traffic by physical_connections /
logical_streams, while the source workload is still counted once per
independent source stream.

The protocol DATA packet size is the implementation SRT header constant plus
payload bytes, with the encryption tag added for encrypted DATA. The pacing
packet size is the SRT header plus payload, because pacing is expressed in
the configured SRT bandwidth layer.

### Pacing

The configured bandwidth policy resolves to a byte-per-second pacing rate.
Payload capacity is then:

~~~text
pacing_payload_capacity_bps
    = pacing_bytes_per_second / pacing_packet_bytes
      * payload_bytes * 8
pacing_headroom_bps = pacing_payload_capacity_bps - source_bps_per_stream
~~~

Source rate and SRT pacing are independent inputs. A source above a known
pacing envelope is a diagnostic configuration; it is not silently skipped.

### Retransmission and control traffic

For independent expected loss p, where 0 <= p < 1:

~~~text
retransmission_factor = 1 / (1 - p)
retransmission_excess  = retransmission_factor - 1
expected_data_pps      = physical_data_pps * retransmission_factor
~~~

This is a geometric expectation, not a complete SRT loss/reorder proof.

Control PPS is explicit rather than a fixed percentage:

~~~text
full_ack_pps      = physical_connections / ack_interval
ack_pps_per_leg   = max(1 / ack_interval,
                        data_pps_per_leg / light_ack_interval_packets)
ack_pps           = physical_connections * ack_pps_per_leg
light_ack_pps     = max(ack_pps - full_ack_pps, 0)
ackack_pps        = full_ack_pps
keepalive_pps     = physical_connections / keepalive_interval
nak_pps           = physical_data_pps * expected_loss, when periodic NAK is on
control_pps       = ack_pps + ackack_pps + keepalive_pps + nak_pps
~~~

The control bitrate uses the actual SRT header and control payload constants
for light ACK, full ACK, ACKACK, NAK, and keepalive packets. If loss is
unknown, NAK and total control PPS are Unknown rather than fabricated.

### BDP, recovery, and buffers

~~~text
srt_data_bps          = expected_data_pps * srt_data_packet_bytes * 8
bdp_bytes             = srt_data_bps * expected_rtt_seconds / 8
bdp_packets           = bdp_bytes / srt_data_packet_bytes
required_window       = ceil(bdp_packets)

guarded_rtt           = expected_rtt + rtt_jitter
one_repair_margin_ms  = tsbpd_latency_ms - guarded_rtt_ms
repair_rounds         = tsbpd_latency_ms / guarded_rtt_ms

socket_horizon_seconds = 8 * socket_buffer_bytes / ingress_bitrate_bps
admission_waves        = ceil(physical_connections / connect_cc)
~~~

Flow and receive windows are packet counts, so the required packet window is
compared against each EFFECTIVE window, after the protocol's own
normalization: `SrtConnection` clamps the flow window into
`[MIN_FLOW_WINDOW_PACKETS, MAX_FLOW_WINDOW]` and then clamps the receive
window to at most the flow window, so a requested 0, 1 or 31 all run as 32.
The configured and effective values are both reported. Requested and
effective socket
buffers produce separate horizons; a request is not treated as proof of the
effective value.

When capacities are supplied, the resource ratios are:

~~~text
host_pps_utilization = predicted_packet_work_pps / host_pps_capacity
nic_utilization      = applicable_nic_wire_bps / nic_capacity_bps
estimated_max_resource_utilization = max(host_pps_utilization, nic_utilization)
~~~

Loopback has no physical NIC bottleneck, so NIC utilization is
NotApplicable there.

## Classes, policy, and reason catalogue

The four top-level classes are exactly:

| class | semantics |
|---|---|
| ProductionCandidate | No known hard limit, no diagnostic reason, and all required policy margins are known and satisfied. |
| Conditional | No known hard impossibility, but a required input is unknown or a margin is conditional. |
| DiagnosticControl | The requested experiment intentionally exceeds a protocol/policy envelope and remains useful diagnostically. |
| ExceedsEnvelope | A known mathematical or resource hard limit is exceeded. |

Reason severity is separate from the English explanation:

| reason code | severity | meaning |
|---|---|---|
| `nic_wire_rate_unknown` | conditional | Link framing overhead was not supplied, so a physical NIC's wire rate cannot be derived. Supply `--nic-link-overhead-bytes`, or state `--nic=loopback`. |
| `payload_exceeds_protocol_mtu` | hard | SRT header plus PLAINTEXT payload exceeds `DEFAULT_MTU`. The GCM tag is deliberately excluded: the core applies `max_payload_size = DEFAULT_MTU - SRT_HEADER_SIZE` regardless of cipher mode and appends the tag afterwards, so including it would claim a limit stricter than the implementation enforces. This matches what the core enforces: `SrtConnection` derives `max_payload_size = DEFAULT_MTU - SRT_HEADER_SIZE`. |
| `payload_exceeds_ipv4_mtu_envelope` | hard | The same packet also carrying IPv4 and UDP headers exceeds a 1500-byte IPv4 path. A deployment envelope, not protocol truth: the core will emit this packet, but a real IPv4 path would fragment it. |
| `reorder_impact_unmodeled` | conditional | Reorder is unknown, or known nonzero. Nothing downstream models its effect, so a known nonzero value must not read as more certain than an unknown one. |
| `bond_leg_distribution_unknown` | conditional | Physical traffic per leg cannot be derived for this bond mode, so per-leg window and control estimates stay Unknown rather than averaging. |
| `source_exceeds_pacing_envelope` | diagnostic | Source workload is above the resolved pacing payload capacity. |
| `protocol_overhead_exceeds_pacing_headroom` | diagnostic | Expected transport overhead cannot fit the pacing headroom. |
| `window_below_bdp_requirement` | hard | An effective packet window -- after protocol normalization, not as configured -- cannot hold the BDP requirement. |
| `window_headroom_low` | conditional | Effective window headroom is below the explicit policy margin. |
| `recovery_margin_insufficient` | conditional | Guarded RTT leaves less repair margin than policy requires. |
| `expected_rtt_unknown` | conditional | RTT is needed but was not supplied. |
| `rtt_variance_unknown` | conditional | RTT jitter is needed but was not supplied. |
| `expected_loss_unknown` | conditional | Loss is needed but was not supplied. |

| `control_rate_uncertain` | conditional | The aggregate control PPS estimate is not bounded. Either the expected loss state is unknown, or leg activity is not modelled -- a Backup bond sends on one leg at a time, so its per-leg peak is not a distribution. |
| `effective_socket_buffer_unknown` | conditional | Requested buffers do not establish effective buffers. |
| `socket_buffer_horizon_low` | conditional | Effective buffer horizon is below policy. |
| `host_pps_capacity_unknown` | conditional | Host packet-processing capacity was not supplied. |
| `predicted_packet_work_unknown` | conditional | Packet work could not be compared with a known host capacity. |
| `host_pps_headroom_low` | conditional | Known host PPS utilization reaches the policy ceiling. |
| `host_pps_capacity_exceeded` | hard | Predicted packet work exceeds known host PPS capacity. |
| `nic_capacity_unknown` | conditional | An applicable physical NIC capacity was not supplied. |

| `nic_headroom_low` | conditional | Known NIC utilization reaches the policy ceiling. |
| `nic_capacity_exceeded` | hard | Predicted wire rate exceeds known NIC capacity. |
| `expected_control_rate_high` | conditional | Control PPS exceeds an explicitly configured policy ceiling. |
| `admission_waves_high` | conditional | Admission waves exceed an explicitly configured ceiling. More waves means LOWER handshake concurrency and a slower ramp, which is a timing caveat rather than a capacity limit. |

Encryption key length and cipher mode are separate inputs. `--encryption`
selects AES-128/192/256; it does not select GCM. `Encryption::apply_to` sets
`key_length` and the passphrase only, and `ConnectionOptions` defaults to
`CipherMode::Ctr`, which appends no authentication tag. Only `--cipher-mode
gcm` adds `GCM_TAG_LEN` to the modelled DATA packet.

`nic_wire_bps` is the AGGREGATE of forward DATA and reverse control at the
link layer. Utilization is deliberately NOT derived from it: a conventional
NIC is full duplex, so each endpoint is charged the larger of its own
transmit and receive directions rather than their sum. Reading
`nic_utilization` as `nic_wire_bps / nic_capacity` would therefore not
reproduce the reported value.

Socket-buffer horizons are computed from datagram bytes crossing the socket
-- SRT header, payload, any tag, IP/UDP headers, multiplied by the expected
retransmission factor -- not from application payload bytes, because the
buffer being modelled is the UDP socket buffer.

Protocol truths include implementation packet sizes and timer cadences.
Mathematical limits include MTU, window, and known capacity exceedance.
Classifier policy includes headroom margins and optional control/admission
ceilings. The default revision is
`stage-a-v1-no-unvalidated-margin`: it does not invent a production margin
from folklore, so the campaign cells remain Conditional when RTT, jitter,
effective buffers, or host PPS are unknown.

Two reason codes from the issue's illustrative list are deliberately absent,
recorded here rather than left as a silent deviation. `LossRecoveryHeadroomLow`
would duplicate existing coverage: an insufficient repair budget is already
`RecoveryMarginInsufficient`, and an unquantified loss expectation is already
`ExpectedLossUnknown`, so a third overlapping code would make two reasons fire
for one condition. `AdmissionConcurrencyLow` has no capacity meaning here: a
small `connect_cc` only increases `admission_waves`, which the model derives
and reports, and slower admission is not a capacity risk -- only an unusually
high concurrency is, which a `max_connect_concurrency` policy would cover if
evidence ever justified one. Both can
be added if evidence shows a condition neither existing code expresses.

## Observed frontier

The campaign used 30, 200, 600, and 1200 physical connections, 1 and 8
Mbit/s per source, three 30-second repetitions, interleaved order, seed 0,
release, and disjoint receiver 0-2 / sender 3-5 CPU sets.

| arm | cells | clean cells | observed result |
|---|---:|---:|---|
| controlled, Mio and Tokio, both pacing arms | 32 | 13 | Low-rate fixed and paced cells are clean; 8 Mbit/s cells cross the source/runtime wall. |
| deployment, Mio receiver | 24 | 12 | Two receiver workers outperform three in this shared-pool workload. |
| deployment, Tokio receiver | 24 | 11 | 200 x 8 Mbit/s remains unclean in every repetition. |

The strict clean predicate requires all repetitions to establish the expected
roles, avoid teardown, offer and goodput at least 99%, delivery at least
99.9%, and record zero UDP receive-buffer, source-backlog, datapath-queue,
and local retry/drop overflow. A cell that starts near zero and grows toward a
queue limit is not called stable capacity.

The most important model gap is pacing. The classifier rated
input-relative:25 cells Conditional because the nominal overhead equation
leaves headroom, but the observed 8 Mbit/s paced cells were unclean at every
connection count. The supplied pacing probe reached only 92.8% at 2x MAXBW.
This is recorded as a follow-up model candidate; the classifier was not
retuned to these rows.

## Issue #30

The current outcome is B: capacity is still not reproducibly clean. Mio at
200 x 8 Mbit/s with fixed 100 Mbit/s reached 100.0% median offer with 2/3
repetitions fully clean; Tokio reached 81.4% median offer with 0/3 clean.
Issue #30 stays open. No ReceiverBuffer optimization belongs here; a future
optimization must target the current measured bottleneck rather than the old
ReceiverBuffer profile.

The evidence does not establish a general 1200-connection claim, a universal
runtime ranking, or a protocol defect. See the
[full evidence and prediction table](results/issue71-frontier-evidence.md)
for the observed signals, null results, and monitoring caveat.
