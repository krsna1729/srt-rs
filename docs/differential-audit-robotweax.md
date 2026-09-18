# Differential audit: Robotweax/srt

Reference: [Robotweax/srt](https://github.com/Robotweax/srt).

This repository's protocol core is a vendored import of
[shiguredo/srt-rs](https://github.com/shiguredo/srt-rs) (`crates/srt-protocol`,
see [VENDOR.md](../crates/srt-protocol/VENDOR.md)), and its interoperability
target is the SRT specification
(`draft-sharabayko-srt`) plus pinned Haivision libsrt behaviour. Robotweax/srt is
**neither**: it is a third, independently developed SRT implementation whose
changelog documents several SRT failure modes in the same terms this repository
has hit independently.

It is therefore used as a *differential reference*: read it to find out whether a
failure mode we measured is real, whether anyone else considered it worth fixing,
and what evidence they had. It is never a compatibility authority, and no
Robotweax source is copied. Every entry below records what `srt-rs` did before,
what changed, and which `srt-rs` test now pins the decision, so a shared
mechanism cannot become untraceable folklore.

Robotweax is an **independent differential reference, not upstream**. Where
this file says a behaviour is "reference-compatible" it means compatible with
the draft and with pinned Haivision libsrt; Robotweax is cited only as the
implementation that measured the same failure mode independently.

Entries are added as changes land. This file covers the transport correctness
change in PR #118 and the differential hardening pass that followed it.

## Reference revisions

```text
srt-rs audit base:
  ee2faab77753258247a0f1619388cdaa2efd7001

Robotweax differential reference:
  ce3d36f77c567b69c0429f7f8aea6d9717d91045
```

Pinned Haivision source used as the interoperability authority for this pass:
`Haivision/srt` **v1.5.7**, commit `899348d8318eb9a3c5a5b6ec43c4a1114288773a`.
Remote line references below are to that revision. The interop suite itself runs
against whatever `srt-tools` is installed (1.5.3 in the qualification image);
the source references are what the behaviour was read out of.

Robotweax has no `v0.2.1`/`v0.2.2` tags in its history: their changelog text is
squashed into the root import commit `2c88fae`, so those two releases are cited
by `CHANGELOG.md` line numbers rather than by tag.

---

## Sender retransmission timeout for a lost flight tail

| | |
|---|---|
| Reference | Robotweax `983a6bd` ("prevent non-progress ACKs from starving live tail recovery"), `a02c308` ("bound periodic-NAK Live timeout recovery to one tail probe") |
| Mandated by the spec? | The sender retransmission timeout itself, yes: `draft-sharabayko-srt` defines it directly as `RTO = RTT + 4*RTTVar + 2*SYN` (continuous form: `RTO = RexmitCount * (RTT + 4*RTTVar + 2*SYN) + SYN`), with `SYN` the spec's 10 ms control-packet synchronization interval. What is *not* spec-mandated is this module's choice to double the whole quantity per consecutive expiry rather than implement `RexmitCount` literally -- that is an explicit implementation deviation, tracked below. |
| Observed in libsrt? | No — libsrt has no sender-side DATA retransmission timer at all (its retransmission is entirely NAK-driven), so there is no libsrt formula to match. This is independent of the spec question above: the spec defines the formula, libsrt simply does not implement it. |
| `srt-rs` before | A lost *suffix* of a flight was stranded permanently. The sender's only retransmission trigger was a NAK, and a receiver can only NAK a gap that a *later* sequence number exposes: a missing tail exposes none, so no loss was ever reported while the payload was simply absent. |
| Identified by | This repository's own sustained-capacity qualification work: an intermittent end-of-run conservation deficit that the fence/identity instrumentation localised to a lost final DATA datagram — and then reproduced deterministically (`4 of 4` delivered with nothing dropped, `3 of 4` with the final datagram withheld). |
| What changed | `crates/srt-protocol/src/sender_rto.rs` (new): a real sender timeout following the spec's `RTT + 4*RTTVar + 2*SYN` formula (initial value 320 ms, from the receiver's own 100 ms/50 ms starting RTT/RTTVar and the 10 ms `SYN`/`COMM_SYN` interval), with exponential backoff of the whole quantity per consecutive expiry -- an explicit deviation from the draft's `RexmitCount` continuous-timeout term, not a compatibility claim. `RTT`/`RTTVar` are this sender's own §4.10 estimator state (`SenderBuffer::sender_rtt_micros`/`sender_rtt_var_micros`), smoothed by the same EWMA the receiver half of this crate already uses for its own raw round-trip samples, with each Full ACK's reported RTT folded in as one more sample rather than substituted outright. `TimerId::SenderRto` is armed when a DATA datagram is actually submitted to the transport, reset only on cumulative ACK *progress*, and on expiry queues exactly one retransmission of the newest submitted packet — and only when no selective recovery is already pending *and* no earlier blind probe from this epoch is still waiting to actually leave the protocol (`SenderRto::probe_pending`), so a probe stuck behind blocked TX capacity cannot be queued a second time. The probe's *submission* also reprograms the epoch: `SenderRto::rearm` restarts the measurement from the instant the probe actually left the protocol, preserving the accumulated backoff, because a probe that sat behind blocked TX capacity until the end of its backed-off interval would otherwise fire microseconds after going out and permit a second blind probe with no elapsed-time evidence behind it — the timeout measures time after DATA is sent, and until the probe leaves, none has been. `TimerId::SenderRto`'s own set/clear actions are queued ahead of any pending datagram output, so the timer store sees an arm/rearm/clear immediately rather than stuck behind a TX-capacity-blocked flight. The old `TimerId::Retransmit` (a zero-delay continuation of an already-filled NAK queue, carrying no notion of loss or elapsed time) was renamed `TimerId::RetransmitContinue` to keep the two mechanisms distinguishable. |
| Where the two references agree | Non-progress ACKs must not reset the timeout (`983a6bd`), and Live-mode timeout recovery must be bounded to one tail probe rather than a whole-flight replay (`a02c308`). Both are pinned here by tests. Robotweax is credited for these two recovery *policies*, not for the existence of a sender retransmission timeout, its base formula, or its RTT estimator -- all three come from the spec, independently of Robotweax. |
| Where this implementation differs | The *backoff* policy is this repository's own: the spec's continuous-timeout term (`RexmitCount * (...) + SYN`) is not implemented literally, in favor of doubling the whole `RTT + 4*RTTVar + 2*SYN` quantity per expiry, capped at [`MAX_RTO_MICROS`](../crates/srt-protocol/src/sender_rto.rs). The base formula and the RTT/RTTVar estimator (§4.10 EWMA smoothing of the peer's Full-ACK report as an input sample) both follow the draft. The reference reaches its recovery policy from its Live periodic-NAK path; `srt-rs` reaches it from an ordinary elapsed-time timer with backoff. |
| Pinned by | `crates/srt-protocol/src/sender_rto.rs` (estimator, backoff, ceiling, `probe_pending`, `RtoArm`, `rearm`; `rearm_returns_the_backed_off_interval_and_keeps_the_backoff`); `crates/srt-protocol/src/srt_sender.rs` (`sender_rtt_is_smoothed_not_replaced_by_raw_peer_feedback`, `submission_reports_which_rto_event_it_is`); `crates/srt-protocol/src/srt_connection.rs` (`a_lost_final_data_packet_is_recovered_by_the_sender`, `a_lost_three_packet_tail_is_recovered_by_one_probe_plus_nak`, `a_non_progress_ack_storm_still_reaches_the_tail_timeout`, `an_unsubmitted_packet_is_never_selected_by_the_timeout`, `an_expiry_with_selective_recovery_pending_does_not_widen_it`, `a_flight_lost_in_full_is_recovered_by_the_submission_trigger`, `a_fully_acknowledged_flight_disarms_the_sender_timeout`); `crates/srt-transport/tests/tail_recovery.rs` (`the_rto_arm_is_not_stranded_behind_the_rest_of_the_flight`, `ack_progress_updates_the_timer_even_with_data_still_queued`, `a_blocked_probe_is_never_queued_twice`, `a_probe_submitted_late_rearms_a_whole_backed_off_interval`, and the same tail-recovery property through the real `ManualTimerStore`). |

---

## Receive-window credit across Light ACKs

| | |
|---|---|
| Reference | Robotweax `09c852b4` ("Preserve receive-window credit across Lite ACKs"), `src/compat/transport_runtime.cpp` (window assignment and the new Lite debit); `tests/test_compat_runtime.cpp` `compat_runtime_lite_ack_consumes_live_receive_window_credit` and its three siblings. |
| Haivision evidence | libsrt does the same thing in the pinned source: a lite ACK debits the window by exactly the acknowledged progress (`srtcore/core.cpp` `processCtrlAck`: `m_iFlowWindowSize -= CSeqNo::seqoff(m_iSndLastAck, ackdata_seqno)`), and a full ACK replaces it with the advertised value (`m_iFlowWindowSize = ackdata[ACKD_BUFFERLEFT]`). Admission is `cwnd = min(m_iFlowWindowSize, m_iCongestionWindow)` versus `getFlightSpan()` (`core.cpp` `packUniqueData`). |
| `srt-rs` before | `SenderBuffer::flow_window` was one mutable integer that conflated three different quantities: the handshake-negotiated window, the peer's most recently advertised free-buffer count, and the LIVE-mode congestion policy (which mirrored it). A Full ACK overwrote it; a Light ACK left the old advertisement in place while still advancing the cumulative ACK and shrinking the flight, so the previously advertised credit could be spent a second time. |
| What changed | The two quantities are now separate fields. `negotiated_window` is fixed at construction (our configured window capped by the peer's handshake flight-flag size, which was previously decoded and discarded). `peer_window_end` is an absolute 31-bit-exclusive sequence boundary that a current Small/Full ACK moves to `ack_seq + advertised_free` and a Light ACK cannot move at all. Admission is the distance from `next_seq` to that end, additionally capped by what is left of the negotiated window; `remaining_window_packets()` is the one place both bounds are expressed. `SenderStats::flow_window_packets` reports the negotiated value (which is what its own doc comment always said), and `available_buffer_packets` reports the remaining credit. |
| Where this implementation differs | Two deliberate divergences, both stricter: (1) the advertised free-buffer value is clamped to the negotiated window, whereas libsrt and Robotweax both take a current advertisement verbatim -- an inflated or hostile advertisement must not enlarge the sender past what was agreed at handshake; (2) the negotiated ceiling is the smaller of the two peers' declarations, whereas libsrt starts only from the peer's flight-flag size. |
| Note on the audit brief | The brief's illustrative regression ("send 4; Full ACK advances by 2, advertises 2 free; sender may send exactly 2") does not match either reference: with the boundary `ack_seq + 2` and `next_seq` already at `ack_seq + 2`, the flight is at the boundary and the reference admits **0** (Robotweax's own four Lite-ACK tests assert exactly that, `tests/test_compat_runtime.cpp`). The regressions implemented here assert the reference-verified numbers, and the sequence that does discriminate the defect is a Light ACK that advances the cumulative ACK while the flight is non-empty -- the case the old code let through and the new one does not. |
| Pinned by | `crates/srt-protocol/src/srt_sender.rs`: `light_ack_cannot_recycle_receive_window_credit`, `peer_window_end_wraps_at_the_31_bit_boundary`, `a_zero_advertisement_closes_new_data_but_not_retransmission`, `an_oversized_advertisement_cannot_enlarge_the_negotiated_window`; `crates/srt-protocol/src/srt_connection.rs`: `light_ack_cannot_overrun_stale_receive_window_credit` (wire-format Light vs Full ACK, stale Full ACK, reopen). |

## A reopened zero receive window is advertised immediately

| | |
|---|---|
| Reference | Robotweax main: `control_timer_immediately_advertises_reopened_receive_window`, `session_reopens_a_full_receive_window_after_application_delivery`. |
| Haivision evidence | libsrt keeps the same exception: a freed receive buffer sets `bNeedFullAck` (`srtcore/core.cpp` `sendCtrl(UMSG_ACK)`), so the periodic ACK is not suppressed while the advertised window is stale. |
| `srt-rs` before | `ReceiverBuffer::should_send_ack` already knew that a changed available-buffer value justifies a Full ACK, but the connection only ever acted on it at the next ACK tick, and `release_data_reservation` only decremented application backlog. The peer stayed stopped for up to a full ACK interval after the application had freed the buffer. |
| What changed | The zero->positive transition (`last advertised == 0`, current available `> 0`) is now detected where application capacity is released, marks `receive_window_reopen_pending`, and queues a zero-duration `TimerId::Ack` deadline. One flag coalesces a burst of releases into one urgent advertisement; a periodic ACK that slips in first leaves the flag set, so the reopened window is only cleared once a Small/Full ACK has actually carried it. The cumulative ACK position is untouched: application capacity moving must not fabricate delivery progress. Nonzero->larger changes keep the ordinary cadence. |
| Pinned by | `crates/srt-protocol/src/srt_connection.rs`: `a_reopened_receive_window_is_advertised_without_more_data` (fills the window, advertises zero, consumes one delivered item, proves a Full ACK carrying the reopened window is emitted with no further DATA), `a_burst_of_application_releases_coalesces_into_one_urgent_ack`. |

## Peer liveness only after semantic validation

| | |
|---|---|
| Reference | Robotweax 0.2.2 (`CHANGELOG.md:114-116`, `:120-124`; `tests/test_compat_runtime.cpp` `compat_runtime_rejects_malformed_controls_without_refreshing_liveness`, `compat_runtime_rejects_malformed_key_controls_without_state_or_liveness`). |
| Haivision evidence | libsrt encodes every no-argument control with exactly one zero word (`srtcore/packet.cpp` `CPacket::pack`'s `m_extra_pad`, for ACKACK, KEEPALIVE, SHUTDOWN, CGWARNING and PEERERROR) and always gives DROPREQ two sequence words, ACK at least its cumulative position, and NAK a word-aligned loss list. |
| `srt-rs` before | `feed_recv_buf` refreshed `last_recv_time` as soon as a datagram decoded and matched the destination socket id -- before any type-specific handling. A truncated ACK took the explicit `if pkt.control_info.len() < 4 { return Ok(()) }` path, an ACKACK naming an ACK this side never sent was ignored, and a KMRSP body was never decoded at all: all of them counted as valid peer activity, and an otherwise silent peer could be kept alive indefinitely. |
| What changed | Peer activity is now recorded only after the packet has been accepted by its own handler. A control packet's information field must be word-aligned and nonempty; the five no-argument controls must carry at most the canonical zero word; DROPREQ must be exactly two sequence words; ACKACK must name an ACK number this side actually assigned; KMRSP is decoded like KMREQ; DROPREQ sequence values are validated before the receiver is touched. An undecryptable DATA body (bad GCM tag, invalid key selector, plaintext on an encrypted connection) therefore also cannot refresh liveness or advance reliability state, because the decryption happens before the receiver sees the packet. |
| Where this implementation differs | Robotweax rejects an *empty* no-argument control payload; `srt-rs` accepts both the canonical four-zero-word form and the empty form. The draft specifies these fields as empty, libsrt's decoder imposes no size rule for them, and an empty no-argument control cannot carry anything hostile -- rejecting it would trade interoperability for nothing. A nonzero padding word, a surplus word, or an unaligned length is rejected, as the brief requires, and that is what the hostile tests inject. |
| Pinned by | `crates/srt-protocol/src/srt_connection.rs`: `malformed_controls_cannot_refresh_liveness_or_state` (ACK, NAK, ACKACK, KEEPALIVE, SHUTDOWN, DROPREQ and both key-management commands, each rejected with `last_recv_time` and `stats()` unchanged, with a canonical KEEPALIVE as the positive control), `undecryptable_data_cannot_refresh_liveness_or_advance_reliability` (bad GCM tag, invalid key selector, unencrypted DATA on an encrypted connection, plus the authentic datagram as the positive control). |

## Peer SHUTDOWN drains buffered TSBPD data

| | |
|---|---|
| Reference | Robotweax 0.2.1 (`CHANGELOG.md:171-172`, `docs/release-notes-0.2.1.md:53-58`; `tests/test_compat_runtime.cpp` `compat_runtime_drains_tsbpd_message_after_peer_shutdown`, `tests/test_compat_epoll.cpp` `compat_epoll_drains_tsbpd_data_before_peer_shutdown_error`). |
| Haivision evidence | libsrt's peer-close path is a readiness transition, not a receive-path teardown: a SHUTDOWN closes the peer's send half while `srt_recvmsg` keeps returning what the receive buffer already holds. |
| `srt-rs` before | `handle_shutdown` disabled TSBPD, flushed whatever the receiver would release immediately, and emitted `Disconnected { PeerShutdown }` in the same call. It could not truncate (everything was flushed first), but it achieved that by violating playout timing: a message whose deadline had not arrived was delivered early, and any payload that did not fit the bounded application queue was stranded behind the terminal event. |
| What changed | Peer shutdown is now `peer_shutdown_pending`: the peer's send half is closed and no further DATA is accepted, while already-buffered DATA keeps its TSBPD deadline and surfaces normally. The terminal event is emitted only once the receiver holds nothing deliverable, the reassembler holds no partial message, and no `DataReceived` event is still queued for the application -- checked on the ACK tick, after each application poll, and when the SHUTDOWN itself arrives. Duplicate SHUTDOWNs are ignored; a fragmented message that can never complete is bounded by the ordinary inactivity timer, and TLPKTDROP now also retires a partial message whose first fragment has fallen behind the receive frontier, so a legitimate expiry still ends the connection. |
| Where this implementation differs | A DATA packet arriving after the peer's SHUTDOWN is rejected rather than buffered. That follows the brief ("no new peer DATA is accepted") and the invariant that only accepted transitions prove liveness; it also means a reordered packet that was sent before the SHUTDOWN is not delivered. libsrt is more permissive here; no reference test covers the reordering case, and the alternative (accepting DATA after a terminal-pending close) reopens the truncation the change exists to prevent. |
| Pinned by | `crates/srt-protocol/src/srt_connection.rs`: `peer_shutdown_drains_tsbpd_data_before_the_terminal_event` (future deadline, duplicate SHUTDOWN, one-microsecond-before and at-deadline ticks, terminal not overtaking a queued payload), `peer_shutdown_delivers_every_buffered_deadline_before_the_terminal_event` (three deadlines, application queue temporarily full), `tlpktdrop_retires_an_incomplete_message_before_the_terminal_event`, `data_after_peer_shutdown_is_rejected`. |

## TLPKTDROP keeps bounded sequence tombstones

| | |
|---|---|
| Reference | Robotweax `include/robotweax/srt/send_buffer.hpp:148-150`: "Expired messages remain as lightweight sequence tombstones until cumulative ACK. A repeated NAK can therefore trigger DROPREQ again." (`SendBuffer::Slot`, `src/send_buffer.cpp` `discard_slot(slot, retain_drop_marker=true)`). |
| Haivision evidence | libsrt answers a loss report for a position that already expired by sending DROPREQ for the message range (`srtcore/core.cpp` `extractCleanRexmitPacket`: `CSndBuffer::READ_DROP` -> `sendCtrl(UMSG_DROPREQ, ...)`), which is only possible while the send buffer still knows the range. |
| `srt-rs` before | `drop_expired` removed the packets outright and advanced `oldest_unacked` past them. A NAK for a dropped sequence then matched nothing, so the peer kept the range and never received DROPREQ: the drop was invisible on the wire. |
| What changed | A dropped message becomes a tombstone: the media payload is released, the key-generation stamp with it, and the sequence identity (with its message number and contiguous tombstone run) stays in the same paged window until the cumulative ACK retires it. Tombstones occupy window span but no flow credit and no payload accounting, are never DATA-retransmitted, and answer a repeated NAK with the same DROPREQ -- regenerated from the window's own contents by expanding the NAKed sequence over its message run, so no per-entry range storage is added. One report can queue at most `MAX_DROPREQ_PER_NAK` (16) repeated DROPREQs, so a single datagram cannot be amplified into unbounded control traffic. |
| Pinned by | `crates/srt-protocol/src/srt_sender.rs`: `a_dropped_packet_leaves_a_tombstone_until_the_ack`, `a_dropped_fragmented_message_expands_from_any_fragment`, `tombstones_survive_sequence_wrap_and_retire_on_the_ack`, `an_all_tombstone_window_stays_bounded_and_backpressures`; `crates/srt-protocol/src/srt_connection.rs`: `a_repeated_nak_for_a_dropped_message_is_answered_with_drop_req`. |

## NAK processing is all-or-none

| | |
|---|---|
| Reference | Robotweax validates the complete requested retransmission range before applying any mutation (`docs/protocol-edge-cases.md:66-69`; `include/robotweax/srt/send_buffer.hpp:114-116`: "Every current packet must already have appeared on the wire, or be a retained tombstone for a previously dropped message"). |
| Haivision evidence | libsrt treats a loss report as evidence derived from packets it did receive, and its own sender only ever accepts retransmission requests naming positions inside the retained send span. |
| `srt-rs` before | `handle_nak` parsed the compact ranges and then queued intersections incrementally, so an impossible or future element was silently ignored instead of invalidating the request, and the parser itself clamped a dense range to the caller's entry budget -- a valid prefix could smuggle an impossible tail past the only validation that existed. |
| What changed | Two phases, with no mutation between them. Every requested position must still be retained here and, if live, must have actually been transmitted: a position this sender accepted but never submitted is invisible to a receiver, and a future or already-retired one is not network loss. The total requested span is bounded by the negotiated window, and the parser no longer truncates a range (it returns ranges as ranges). Only after all of that does the commit queue DATA retransmissions for live packets and repeated DROPREQs for tombstones. |
| Pinned by | `crates/srt-protocol/src/srt_sender.rs`: `a_nak_is_applied_whole_or_not_at_all` (valid prefix + future tail, never-submitted position, live position, idempotent repeat, oversized span), `a_nak_range_that_crosses_the_wrap_is_valid`; `crates/srt-protocol/src/srt_connection.rs`: `a_dense_loss_list_is_returned_as_one_untruncated_range`, `a_loss_list_of_ranges_and_singles_parses_completely`. The partial-prefix regression was verified by mutation: with the validation phase removed, the valid prefix is queued and the test fails. |

## Encrypted retransmission identity

| | |
|---|---|
| Reference | Robotweax main: retransmission "reuses the immutable protected packet selected on first send; it does not re-encrypt old plaintext under a newer key" (`SendBuffer::preserve_protected_payload`, the retained header key selector). |
| Haivision evidence (the authority here) | libsrt does the same, in two steps of the pinned source: at first send the key-flag bits are OR'd into the block's message-number field and remembered (`CSndBuffer::readData`, `src/buffer_snd.cpp:325-346`), and the retransmission path re-reads that block (`CSeqNo`-indexed `readData`, `srtcore/core.cpp` `extractCleanRexmitPacket`) and sends it without calling the cipher again, because "the payload is already encrypted" and "the proper flag value is already stored". |
| `srt-rs` before | The send buffer retained plaintext only, and every retransmission ran `crypto.reserve_tx_stamp()` again: it consumed a *new* first-transmission counter value and encrypted under whatever key generation was current. After a rotation, a retransmission of an old packet therefore went out under the new key generation -- a different protected packet from the one the receiver had already seen part of, and a second counter value for a packet that had already spent one. |
| What changed | The first transmission's `TxCryptoStamp` is recorded on the retained packet and reused by `encrypt_with_stamp`/`encrypt_gcm_with_stamp` on retransmission, so the ciphertext (and the GCM tag) is reproduced exactly without advancing the logical counter. Because CTR and GCM are both deterministic in (key generation, sequence, IV/AAD), reproducing the stamp is sufficient: no second copy of the media is retained. The key-retirement check now counts retained unacknowledged packets per generation alongside queued-but-unmaterialized datagrams, so a generation cannot be decommissioned while a retained packet still has to be reproduced under it; the ACK and TPKTDROP release that dependency. |
| Where this implementation differs | Representation only. libsrt overwrites the block with the protected bytes and Robotweax stores the protected packet; `srt-rs` stores the plaintext plus the stamp and reproduces the protected bytes deterministically, which the differential test proves is byte-identical for both cipher modes. No divergence in observable wire behaviour. |
| Pinned by | `crates/srt-protocol/tests/test_srt_connection.rs`: `a_retransmission_keeps_the_first_transmission_crypto_identity` (CTR and GCM: key selector, protected payload and full datagram identity across a completed rotation, with the counter pushed past the decommission boundary), `a_retransmission_does_not_advance_the_first_transmission_crypto_counter`. Both were verified by mutation: reserving a fresh stamp fails the identity assertion (Even -> Odd), and dropping the retained-stamp dependency makes the retransmission under the retired generation fail outright. |

## Evaluated and deferred (not part of this pass)

The wider Robotweax scan was evaluated; these items are deliberately *not* ported,
and are recorded here rather than left as ambiguous TODOs:

* **UDP socket buffer readback.** Already substantially implemented in
  `srt-transport::socket_io` (`getsockopt`, effective min/max accounting); no
  second subsystem is needed.
* **Robotweax's empty-buffer micro-optimizations.** These need local profiling
  evidence on this repository's own workload before they are worth carrying.
* **TSBPD drift slew.** It changes timing semantics and deserves its own
  reference qualification, not a drive-by port.
* **Bounded causal tracing.** Belongs to future diagnostics/Oracle work.
* **Out of scope entirely:** generic C API, FileCC breadth, FEC expansion,
  Windows work, allocators, GSO/GRO, native `io_uring`, NUMA, generic pooling.
* **The Robotweax-vs-`srt-rs` production challenger.** It becomes useful only
  once Restream consumes the merged Owner on `redevelop`, where both
  implementations can be compared against the real 1,000-output topology
  instead of an artificial library-only setup.
