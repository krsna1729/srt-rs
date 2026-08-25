# SRT Spec Compliance Review

Line-by-line evaluation of this workspace against:

- **Spec**: [draft-sharabayko-srt](https://haivision.github.io/srt-rfc/draft-sharabayko-srt.txt) (IETF draft, expired 2024-07-11; still the normative protocol description)
- **Reference implementation**: [Haivision/srt](https://github.com/Haivision/srt) `master` (`srtcore/`, `haicrypt/`, incl. `docs/features`), cross-checked at specific symbols cited below
- **Deployment Guide**: SRT Alliance *SRT Protocol Deployment Guide* (2026-05-20 ed., `SRT-ID-DG-00`)
- **Recent libsrt fixes** swept for known-bug overlap: #3317/#3345 (KMREQ CVE class), #3319 (KMRSP length), #3320 (DROPREQ OOB), #3322/#3324 (LOSSREPORT range OOB), #3323 (rogue CMD MSG)

Scope reviewed: every file under `crates/srt-protocol/src/` (~10k lines), admission/policy paths of `crates/srt-transport/src/lib.rs` + `config.rs`, and `crates/srt-lifecycle`. Review date: 2026-08-25.

---

## Verdict

Wire format, handshake framing, crypto, and timing constants are **conformant and in most cases byte-verified against libsrt**. The behavioral deviations identified below have been remediated or explicitly documented; the review is green as of 2026-08-25.

The focused protocol suite, property suite, transport suite, lifecycle suite,
and the dedicated libsrt interop suite are required checks for this review.

### Resolution matrix

| Finding | Resolution | Regression evidence |
|---|---|---|
| H1 | Negotiate the maximum TSBPD delay and mutually gate live capabilities. | `1c52f9a`, handshake unit tests |
| H2 | Reject invalid magic and legacy induction responses. | `decc48e`, caller-state unit tests |
| H3 | Port libsrt's ACKACK-sampled drift tracer and dynamic delivery timing. | `8bd7502`, 1,000-sample unit tests |
| M4 | Emit GROUP only in CONCLUSION. | `9b6d1b7`, handshake wire test |
| M5 | Preserve unknown GROUP type bytes and reject unsupported modes explicitly. | `a80f356`, transport admission tests |
| M6 | Include the SRT header in live packet pacing. | `8616f4b`, sender unit test |
| M7 | Document draft-aligned KM refresh defaults. | `380d9c6` |
| L8 | Start Full ACK numbering at one. | `7d50514`, receiver unit test |
| L9 | Send keepalives only after outbound idle time. | `4587535`, timer unit test |
| L10 | Verified conformant: Small ACK remains an optional receiver choice. | Existing codec/connection coverage |
| L11 | Flush local TSBPD delivery on disconnect. | `84f7303`, close unit test |
| L12 | Retry SHUTDOWN while closing, bounded by the 5-second close timeout. | `8729b9b`, unit test and `8348eae` fuzz coverage |
| L13 | Verified conformant documented wrap-range tradeoff. | Existing receiver tests |
| L14 | Clamp oversized loss lists rather than discard the whole NAK. | `6dc9def`, parser unit test |
| L15 | Document caller/listener-only topology; rendezvous is unsupported. | `e0964f1` |

---

## Findings

### H1. Latency negotiation not performed (spec §4.4) — High, interop

Spec §4.4: *"The latency for a connection will be established as the maximum value of latencies proposed by the initiator and responder."* libsrt implements exactly this (`core.cpp:2398`):

```c
int maxdelay = std::max(m_iTsbPdDelay_ms, peer_decl_latency);
m_iTsbPdDelay_ms = maxdelay;
```

This fork: `HsExtensionData { recv_tsbpd_delay, send_tsbpd_delay }` is parsed by
`HandshakePacket::get_hs_extension()` (`srt_handshake.rs:524`) but **no production code calls it** —
`handle_handshake_caller` / `handle_handshake_listener` never read the peer's proposal. Each side runs its own
`options.tsbpd_delay` unmodified.

Consequence: a caller demanding 500 ms against a listener configured 120 ms runs the listener at 120 ms —
late packets, TLPKTDROP churn. This silently breaks the Deployment Guide's latency model
(§Latency / RTT-multiplier, pp. 49–52), which presumes auto-negotiation to the max.
Same gap applies to SRT-flag capability checking: TSBPD/TLPKTDROP/PERIODICNAK are unilaterally assumed.

Fix shape: in both Conclusion handlers, take `max(local, peer_recv_delay)` into `options.tsbpd_delay`
before `init_buffers`; gate TLPKTDROP/PERIODICNAK behavior on peer flags.

### H2. Induction-response magic/version never validated (spec §4.3.1.2.1 MUST) — Medium

Spec: *"The Extension Flags field MUST contain the magic value 0x4A17. If it does not, the connection MUST be
rejected with rejection reason SRT_REJ_ROGUE."* Also: HS Version 4 response ⇒ MAY reject with `SRT_REJ_VERSION`.

`srt_connection.rs:1239-1290` (caller's `Induction` arm) consumes `syn_cookie` / `socket_id` and proceeds
straight to CONCLUSION — no check of `hs.extension_field == SRT_MAGIC_CODE` (`SRT_MAGIC_CODE` is defined at
`srt_handshake.rs:80`, used only when *sending*) nor `version == 5`. A legacy-UDT or rogue listener response is
accepted. Two-line fix in the Induction arm.

### H3. Drift tracer absent (spec §4.5.1 `+Drift`, §4.7) — Medium for long sessions

`PktTsbpdTime = TsbpdTimeBase + PKT_TIMESTAMP + TsbpdDelay` is implemented with **Drift ≡ 0**
(`srt_receiver.rs:607-623`). The draft's §4.7 rationale ("drift may accumulate over many days to a point where
the sender or receiver buffers will overflow or deplete") and libsrt's `DriftTracer` (sampled per packet count,
applied into `m_tsTsbPdTimeBase`) have no counterpart.

Everything else in the wrap machinery is faithful — start at `MAX_TIMESTAMP − 30 s`, end on delivery of a
timestamp in the (30 s, 60 s) interval, then `TsbpdTimeBase += MAX_TIMESTAMP + 1`
(`srt_receiver.rs:39-46, 597-623, 741-750`) — matching `CTsbpdTime::updateBaseTime`
(`tsbpd_time.cpp`, `TSBPD_WRAP_PERIOD = 30·10⁶`) exactly. Multi-day streams will slowly skew buffer occupancy.

### M4. GROUP extension attached to INDUCTION request (spec §4.3.1.1.1 MUST) — Low/Medium

*"There MUST be no HS extensions"* in the Induction Request. `send_induction_request` adds
`add_group_extension(group)` when configured (`srt_connection.rs:1849-1859`). Benign today (peers don't parse
induction extensions) but non-conformant; move GROUP attach to CONCLUSION only (which
`send_conclusion_request` already does).

### M5. Unknown group types silently erase membership metadata — Low

`GroupType::from_u8` accepts only 0/1/2 (`srt_handshake.rs:144-151`), so `get_group_extension()` returns
`None` for libsrt *balancing (3)* / *multicast (4)* legs instead of surfacing "unknown type N". The listener
then answers without GROUP and the leg falls out of the peer's group. Return the raw type byte and let policy
reject explicitly (`BAD_MODE`), mirroring how reject-reasons were fixed.

### M6. Pacing period omits the 16-byte SRT header (spec §5.1.2 step 2) — Low

Draft: `PKT_SND_PERIOD = PktSize × 10⁶ / MAX_BW` where *"Calculate SRT packet size (PktSize) as the sum of
average payload size (AvgPayloadSize) and SRT header size"*. libsrt: `congctl.cpp:179-181`,
`pktsize = m_zSndAvgPayloadSize + m_zHeaderSize`.

Rust (`srt_sender.rs:320-324`): `period = 10⁶ × avg_payload / bw` — no header term ⇒ wire rate overshoots
`MAX_BW` by ~1 % (16/1456). One-line fix. Note the AvgPayloadSize IIR length (128, `AVG_PAYLOAD_SIZE_IIR_LEN`)
deliberately follows libsrt's `avg_iir<128>` rather than the draft's literal 7/8 EWMA — correct choice, worth a
comment either way.

### M7. KM refresh constants follow the draft text, not libsrt's shipped defaults — Info

Rust: `KM_REFRESH_PERIOD = 2^25`, `KM_PRE_ANNOUNCE_PERIOD = 4000` (`crypto.rs:195-198`) = spec §6.1.6
recommendation, with the pre-announce → switch → decommission state machine correctly ordered (verified incl.
post-switch counter reset). libsrt actually ships `HAICRYPT_DEF_KM_REFRESH_RATE = 0x1000000` (**2²⁴**) and
`HAICRYPT_DEF_KM_PRE_ANNOUNCE = 0x1000` (**4096**) (`haicrypt/haicrypt.h:81-83`). Refresh is self-governed per
direction so no interop break — but anyone diffing against libsrt logs sees refresh at half the packet count.
Document or make configurable.

### L8–L15. Recorded deviations (each verified, none load-bearing)

| # | Item | Evidence |
|---|---|---|
| L8 | First Full ACK carries acknowledgement number **2**; spec §3.2.4 says "starting from 1" — `ack_number` initialized to 1 then pre-incremented before first send. Echo/ACKACK consistency unaffected; cosmetic. | `srt_receiver.rs:438,893` |
| L9 | Keepalive sent unconditionally every 1 s; libsrt sends only after a 1 s idle gap since last send of *any* packet (`COMM_KEEPALIVE_PERIOD_US` + `m_tsLastSndTime` gate). Spec §3.2.3 says "after a certain timeout from the last time any packet was sent." Cost: +40 B/s during active streaming; harmless but non-conformant to the letter. | `srt_connection.rs:771-780` vs `core.cpp:12294` |
| L10 | No Small-ACK form (16-B CIF). Spec permits receiver's choice ("It is up to the receiver"); Light-64p + Full-10 ms is conformant. The ACKACK gate correctly keys on ≥28 B CIF, so a peer-originated Small ACK won't get a spurious ACKACK (the VENDOR.md patch for upstream issue 0054 already fixed that hazard). | `srt_connection.rs:1560-1572` |
| L11 | `handle_shutdown` flushes the TSBPD buffer by disabling TSBPD then delivering everything immediately — reasonable interpretation; spec doesn't define shutdown-buffer interaction. Asymmetry: local `disconnect()` sends Shutdown and moves to Closing but never flushes its own receiver if the peer never answers. Minor. | `srt_connection.rs:1606-1618, 1008-1013` |
| L12 | `Closing` state has no retransmission path — after `disconnect()`, only a peer Shutdown or the 5 s inactivity timer ends it; no SHUTDOWN retransmit (libsrt retransmits Shutdown until acked-by-keepalive/data, `core.cpp:4717`). A lost Shutdown datagram leaves both sides up until the Rust side's own timeout — acceptable, just slower than libsrt. | `ConnectionState::Closing` has no handler anywhere |
| L13 | NAK range compression can split one logical range crossing the seq-wrap boundary into two ranges (documented at `srt_receiver.rs:931-941`) — correct decision, since circular sort isn't well-defined; costs ≤1 extra wire word. Matches draft Appendix A semantics. | accepted tradeoff, documented inline |
| L14 | `parse_loss_list` rejects NAK packets whose expanded list exceeds `flight_capacity_packets` entries with an `Err` → whole datagram dropped as invalid. DoS-safe (the bound is right), but libsrt clamps instead of erroring; a legitimate extreme-loss burst larger than the flow window would be discarded wholesale. Consider processing the first N entries. | `srt_connection.rs:2144-2188` |
| L15 | Rendezvous mode (§4.3.2) not implemented — WAVEAHAND/AGREEMENT decode exists (`HandshakeType` variants), nothing drives the state machine. Spec marks caller-listener as the required path; rendezvous matters for NAT-to-NAT dialing (Deployment Guide firewall scenarios assume one side reachable). If full parity is a goal this is the largest missing feature; otherwise document as out of scope. | grep: no rendezvous state machine |

---

## Verified-conformant highlights

- **Wire codecs byte-exact**: data header bit layout (F/PP/O/KK/R/msgno with `0x03FF_FFFF` masks), control
  dispatch table, HSv5 field order, extension TLV with 4-byte-word lengths + zero padding, SID/congestion
  stored as little-endian words with UTF-8-boundary truncation, KM message layout incl. `Sign=0x2029`,
  SLen/KLen encoding, KK even/odd values.
- **Crypto**: PBKDF2-HMAC-SHA1 ×2048 over `LSB(64,Salt)` = `salt[8..16]` (`crypto.rs:418-424`) = spec §6.2.1
  exactly; AES-KW RFC 3394; AES-CTR counter block = `MSB(112,Salt)` ⊕ `PktSeqNo << 96` with a 16-bit block
  counter — matches haicrypt construction, and the crate's known-answer test reconstructs it independently.
  KK alternation, key redaction, zeroization on drop/replacement all present. Notably **not** vulnerable to
  the recent libsrt KMREQ CVE class (#3317/#3345): `KmMessage::decode` bounds-checks salt/key lengths and
  `update_sek` swaps via owned `Vec` — no fixed-size stack buffers anywhere on the KM path.
- **ACK/NAK machinery**: Full-28B / Light-4B split, ACK number tracking with bounded timestamp map, RTT EWMA
  7/8–1/8 and RTTVar 3/4–1/4 with initial 100 ms / 50 ms (spec §4.10 verbatim), NAKInterval
  `(RTT + 4·RTTVar)/2` with 20 ms floor, immediate NAK on gap detection plus periodic re-report,
  wire loss-list range encoding/compression.
- **TLPKTDROP**: 1.25× latency threshold with 1 s floor on both sides (`srt_receiver.rs:983`,
  `srt_sender.rs:570`) = spec §4.6 recommendation verbatim; sender-side monotonic forward scan matches libsrt
  `CSndBuffer::dropLateData`; fake-ACK semantics implemented via expected-seq advance; receiver-side drop
  estimation uses next-received-packet delivery time (errs high side, documented).
- **TSBPD time base**: computed as `T_NOW − HSREQ_TIMESTAMP` at Conclusion receipt on both roles
  (`srt_connection.rs:1343,1479`) = spec §4.5.1.1; wrap-period handling matches `CTsbpdTime`.
- **Admission layer**: cookie-routed fan-in across SO_REUSEPORT acceptors, half-open/per-IP/per-state caps,
  pre-CONCLUSION policy hook window mirroring libsrt's accept hook, rejection delivery with reason codes —
  engineering beyond the spec's scope.

---

## Deployment Guide cross-check

- Default latency 120 ms ✓ (`ConnectionOptions::default()` = `SRT_LIVE_DEF_LATENCY_MS` = guide minimum-latency row).
- Default payload 1316 ✓ (`DEFAULT_MESSAGE_PAYLOAD` = `SRT_LIVE_DEF_PLSIZE`, MPEG-TS aligned).
- Passphrase length validated 10–79 bytes for interop ✓ (`config.rs:246-250`).
- **H1 breaks the guide's core workflow**: the guide's latency procedure assumes negotiated-max latency end to
  end; with H1 open, operators must set identical latency manually on both ends.
- Bandwidth Overhead % / INPUTBW modes (guide §Bandwidth Overhead, pp. 54+): only a static MAXBW_SET equivalent
  exists (`max_bandwidth_bytes_per_sec`); INPUTBW/OVERHEAD estimation (spec §5.1.1 modes 2–3) absent —
  acceptable for a sans-I/O protocol core, list as a config-layer gap.

---

## Completion note

The original priority order was executed in interop-impact order, with the
close-state and malformed-input follow-ups included before declaring the
review green. The remaining work is ongoing breadth expansion of the live
interop suite, tracked in `live-interop-validation.md`; it is not an open
spec-compliance deviation.
