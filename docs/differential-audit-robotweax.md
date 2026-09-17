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
correctness change in PR #116; the wider Robotweax audit is a separate PR.

---

## Sender retransmission timeout for a lost flight tail

| | |
|---|---|
| Reference | Robotweax `983a6bd` ("prevent non-progress ACKs from starving live tail recovery"), `a02c308` ("bound periodic-NAK Live timeout recovery to one tail probe") |
| Mandated by the spec? | No. The SRT specification's sender-side recovery is NAK-driven; it defines no sender DATA timeout. |
| Observed in libsrt? | No — libsrt has no sender-side DATA retransmission timer either. This is an independent design in both implementations. |
| `srt-rs` before | A lost *suffix* of a flight was stranded permanently. The sender's only retransmission trigger was a NAK, and a receiver can only NAK a gap that a *later* sequence number exposes: a missing tail exposes none, so no loss was ever reported while the payload was simply absent. |
| Identified by | This repository's own sustained-capacity qualification work: an intermittent end-of-run conservation deficit that the fence/identity instrumentation localised to a lost final DATA datagram — and then reproduced deterministically (`4 of 4` delivered with nothing dropped, `3 of 4` with the final datagram withheld). |
| What changed | `crates/srt-protocol/src/sender_rto.rs` (new): a real sender timeout, `SRTT + 4*RTTVar + 2*COMM_SYN` with exponential backoff, base measurements taken from the peer's Full-ACK feedback. `TimerId::SenderRto` is armed when a DATA datagram is actually submitted to the transport, reset only on cumulative ACK *progress*, and on expiry queues exactly one retransmission of the newest submitted packet — and only when no selective recovery is already pending. The old `TimerId::Retransmit` (a zero-delay continuation of an already-filled NAK queue, carrying no notion of loss or elapsed time) was renamed `TimerId::RetransmitContinue` to keep the two mechanisms distinguishable. |
| Where the two references agree | Non-progress ACKs must not reset the timeout (`983a6bd`), and Live-mode timeout recovery must be bounded to one tail probe rather than a whole-flight replay (`a02c308`). Both are pinned here by tests. |
| Where this implementation differs | The timeout *formula* is this repository's own (the reference's constants are not a compatibility rule, and there is no libsrt formula to match). The reference reaches the same recovery from its Live periodic-NAK path; `srt-rs` reaches it from an ordinary elapsed-time timer with backoff. |
| Pinned by | `crates/srt-protocol/src/sender_rto.rs` (estimator, backoff, ceiling); `crates/srt-protocol/src/srt_connection.rs` (`a_lost_final_data_packet_is_recovered_by_the_sender`, `a_lost_three_packet_tail_is_recovered_by_one_probe_plus_nak`, `a_non_progress_ack_storm_still_reaches_the_tail_timeout`, `an_unsubmitted_packet_is_never_selected_by_the_timeout`, `an_expiry_with_selective_recovery_pending_does_not_widen_it`, `a_flight_lost_in_full_is_recovered_by_the_submission_trigger`, `a_fully_acknowledged_flight_disarms_the_sender_timeout`); `crates/srt-transport/tests/tail_recovery.rs` (the same property through the real `ManualTimerStore`). |
