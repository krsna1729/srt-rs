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

Entries are added as changes land. This file currently covers the transport
correctness change in PR #118; the wider Robotweax audit is a separate PR.

---

## Sender retransmission timeout for a lost flight tail

| | |
|---|---|
| Reference | Robotweax `983a6bd` ("prevent non-progress ACKs from starving live tail recovery"), `a02c308` ("bound periodic-NAK Live timeout recovery to one tail probe") |
| Mandated by the spec? | The sender retransmission timeout itself, yes: `draft-sharabayko-srt` defines it directly as `RTO = RTT + 4*RTTVar + 2*SYN` (continuous form: `RTO = RexmitCount * (RTT + 4*RTTVar + 2*SYN) + SYN`), with `SYN` the spec's 10 ms control-packet synchronization interval. What is *not* spec-mandated is this module's choice to double the whole quantity per consecutive expiry rather than implement `RexmitCount` literally -- that is an explicit implementation deviation, tracked below. |
| Observed in libsrt? | No — libsrt has no sender-side DATA retransmission timer at all (its retransmission is entirely NAK-driven), so there is no libsrt formula to match. This is independent of the spec question above: the spec defines the formula, libsrt simply does not implement it. |
| `srt-rs` before | A lost *suffix* of a flight was stranded permanently. The sender's only retransmission trigger was a NAK, and a receiver can only NAK a gap that a *later* sequence number exposes: a missing tail exposes none, so no loss was ever reported while the payload was simply absent. |
| Identified by | This repository's own sustained-capacity qualification work: an intermittent end-of-run conservation deficit that the fence/identity instrumentation localised to a lost final DATA datagram — and then reproduced deterministically (`4 of 4` delivered with nothing dropped, `3 of 4` with the final datagram withheld). |
| What changed | `crates/srt-protocol/src/sender_rto.rs` (new): a real sender timeout following the spec's `RTT + 4*RTTVar + 2*SYN` formula (initial value 320 ms, from the receiver's own 100 ms/50 ms starting RTT/RTTVar and the 10 ms `SYN`/`COMM_SYN` interval), with exponential backoff of the whole quantity per consecutive expiry -- an explicit deviation from the draft's `RexmitCount` continuous-timeout term, not a compatibility claim. `RTT`/`RTTVar` are this sender's own §4.10 estimator state (`SenderBuffer::sender_rtt_micros`/`sender_rtt_var_micros`), smoothed by the same EWMA the receiver half of this crate already uses for its own raw round-trip samples, with each Full ACK's reported RTT folded in as one more sample rather than substituted outright. `TimerId::SenderRto` is armed when a DATA datagram is actually submitted to the transport, reset only on cumulative ACK *progress*, and on expiry queues exactly one retransmission of the newest submitted packet — and only when no selective recovery is already pending *and* no earlier blind probe from this epoch is still waiting to actually leave the protocol (`SenderRto::probe_pending`), so a probe stuck behind blocked TX capacity cannot be queued a second time. `TimerId::SenderRto`'s own set/clear actions are queued ahead of any pending datagram output, so the timer store sees an arm/rearm/clear immediately rather than stuck behind a TX-capacity-blocked flight. The old `TimerId::Retransmit` (a zero-delay continuation of an already-filled NAK queue, carrying no notion of loss or elapsed time) was renamed `TimerId::RetransmitContinue` to keep the two mechanisms distinguishable. |
| Where the two references agree | Non-progress ACKs must not reset the timeout (`983a6bd`), and Live-mode timeout recovery must be bounded to one tail probe rather than a whole-flight replay (`a02c308`). Both are pinned here by tests. Robotweax is credited for these two recovery *policies*, not for the existence of a sender retransmission timeout, its base formula, or its RTT estimator -- all three come from the spec, independently of Robotweax. |
| Where this implementation differs | The *backoff* policy is this repository's own: the spec's continuous-timeout term (`RexmitCount * (...) + SYN`) is not implemented literally, in favor of doubling the whole `RTT + 4*RTTVar + 2*SYN` quantity per expiry, capped at [`MAX_RTO_MICROS`](../crates/srt-protocol/src/sender_rto.rs). The base formula and the RTT/RTTVar estimator (§4.10 EWMA smoothing of the peer's Full-ACK report as an input sample) both follow the draft. The reference reaches its recovery policy from its Live periodic-NAK path; `srt-rs` reaches it from an ordinary elapsed-time timer with backoff. |
| Pinned by | `crates/srt-protocol/src/sender_rto.rs` (estimator, backoff, ceiling, `probe_pending`); `crates/srt-protocol/src/srt_sender.rs` (`sender_rtt_is_smoothed_not_replaced_by_raw_peer_feedback`); `crates/srt-protocol/src/srt_connection.rs` (`a_lost_final_data_packet_is_recovered_by_the_sender`, `a_lost_three_packet_tail_is_recovered_by_one_probe_plus_nak`, `a_non_progress_ack_storm_still_reaches_the_tail_timeout`, `an_unsubmitted_packet_is_never_selected_by_the_timeout`, `an_expiry_with_selective_recovery_pending_does_not_widen_it`, `a_flight_lost_in_full_is_recovered_by_the_submission_trigger`, `a_fully_acknowledged_flight_disarms_the_sender_timeout`); `crates/srt-transport/tests/tail_recovery.rs` (`the_rto_arm_is_not_stranded_behind_the_rest_of_the_flight`, `ack_progress_updates_the_timer_even_with_data_still_queued`, `a_blocked_probe_is_never_queued_twice`, and the same tail-recovery property through the real `ManualTimerStore`). |
