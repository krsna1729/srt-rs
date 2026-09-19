//! SRT send buffer.
//!
//! Manages holding sent packets and retransmitting them.
//!
//! ## Features
//!
//! - Buffering sent packets (retained until ACKed)
//! - Retransmit queue management via NAK
//! - Buffer release via ACK
//! - Send window management

use std::collections::{BTreeSet, VecDeque};

use crate::sender_packet_window::SenderPacketWindow;

use bytes::Bytes;

use crate::crypto_impl::{KeyFlag, TxCryptoStamp};
use crate::sender_rto::{INITIAL_RTT_VAR_MICROS, INITIAL_SRTT_MICROS, RtoArm, SenderRto};
use crate::srt_handshake::MAX_FLOW_WINDOW;
use crate::srt_packet::{DataHeader, PacketPosition, SRT_HEADER_SIZE, sequence_less_than};
use crate::srt_receiver::LossRange;
use crate::time::Timestamp;

const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
const STALE_RETRANSMIT_COMPACT_THRESHOLD: usize = 1_024;

/// Upper bound on repeated-DROPREQ responses to one peer loss report.
///
/// A NAK can name a whole window, and every name inside a dropped message
/// maps to one DROPREQ; without a ceiling a single datagram could be
/// amplified into thousands of control datagrams. Capping is safe because a
/// DROPREQ is idempotent: a peer that still needs one NAKs again.
const MAX_DROPREQ_PER_NAK: usize = 16;

/// "No configured limit" default max bandwidth, matching libsrt's own
/// `BW_INFINITE` (`srtcore/common.h`): 1 Gbps expressed in bytes/sec. Live
/// mode always paces off *some* bandwidth figure -- there is no "pacing
/// disabled" state in real SRT live mode, just a very generous default.
pub const DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 1_000_000_000 / 8;

/// Optimistic initial payload-size estimate for the pacing average, before
/// any real packets have been sent -- matches libsrt's `LiveCC` constructor
/// initializing `m_zSndAvgPayloadSize` to `maxPayloadSize()` (1500 MTU - 44
/// bytes IP/UDP/SRT overhead = 1456) rather than 0, so the first computed
/// pacing period isn't artificially tiny.
const INITIAL_AVG_PAYLOAD_SIZE_BYTES: f64 = 1456.0;

/// IIR averaging window for the payload-size estimate feeding the pacing
/// formula, matching libsrt's `avg_iir<128>` (`srtcore/congctl.cpp`,
/// `srtcore/utilities.h`): `avg = (avg * (LEN - 1) + new) / LEN`.
const AVG_PAYLOAD_SIZE_IIR_LEN: f64 = 128.0;

/// Retained sent-packet entry.
///
/// Strips fields that are redundant with the BTreeMap key (`sequence_number`)
/// or connection-wide state (`dest_socket_id`), and fields that are constant
/// in the buffer (`encryption_flag` = 0, `retransmitted` = false).
/// Saves 16 bytes per retained packet vs storing a full `DataPacket`.
#[derive(Debug, Clone)]
struct SentPacket {
    position: PacketPosition,
    order_flag: bool,
    message_number: u32,
    timestamp: u32,
    payload: Bytes,
    sent_time: Timestamp,
    retransmit_count: u32,
    /// The cryptographic reservation this packet's FIRST transmission used.
    ///
    /// Retransmission reproduces the first transmission's protected bytes
    /// when it reuses this stamp: same key generation, same sequence-derived
    /// counter, so the same ciphertext (and, under GCM, the same tag) comes
    /// out without retaining a second copy of the payload. That is what both
    /// references do -- libsrt stores the first transmission's key-flag bits
    /// with the block and re-reads the already-encrypted payload
    /// (`CSndBuffer::readData`, `core.cpp` `packLostData`), and Robotweax
    /// keeps the protected packet selected on first send. Released with the
    /// media on TLPKTDROP, because a tombstone is never transmitted again.
    crypto_stamp: Option<TxCryptoStamp>,
    /// Whether this entry is a TLPKTDROP tombstone: the message was given up
    /// as too late, so its media payload has been released and it must never
    /// be DATA-retransmitted. What remains is the identity a repeated NAK
    /// needs -- the sequence, the message number, and the surrounding
    /// tombstone run that regenerates DROPREQ -- until the cumulative ACK
    /// retires it.
    dropped: bool,
    /// Whether this packet's FIRST datagram has actually left the protocol for
    /// the transport.
    ///
    /// Retention in this buffer only means the packet was *accepted* by the
    /// sender (see `push_impl`); a datagram still waiting for TX capacity has
    /// not been transmitted at all. Only a submitted packet may be selected for
    /// a timeout retransmission, because retransmitting one that has never been
    /// sent would duplicate a transmission that is still pending, not repair a
    /// loss. Distinct from `sent_time`, which is the TLPKTDROP message age and
    /// is deliberately never rewritten by a retransmission.
    submitted: bool,
    /// Whether the DROPREQ covering this tombstone has actually left the
    /// protocol for the transport. Meaningless while `dropped` is false.
    ///
    /// A peer can only have learned of this drop once the DROPREQ that
    /// reports it actually reached the wire -- queuing it is not enough, for
    /// the same reason queuing DATA is not enough for `submitted`. This is
    /// the other half of what makes a position ACK-justified: see
    /// `SenderBuffer::justified_frontier`.
    drop_notified: bool,
}

/// A message dropped by sender-side TLPKTDROP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedMessage {
    pub message_number: u32,
    pub first_seq: u32,
    pub last_seq: u32,
}

/// A peer loss report named a position this sender cannot corroborate: never
/// sent, already retired, or accepted but never actually submitted to the
/// wire. Carries no data -- see [`SenderBuffer::handle_nak_ranges`]'s doc
/// comment for exactly what triggers it and why the whole report is
/// rejected rather than just the offending position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidNak;

/// Send buffer.
#[derive(Debug)]
pub struct SenderBuffer {
    /// Sent packets in a direct paged sequence window.
    packets: SenderPacketWindow<SentPacket>,

    /// Loss list (packets reported via NAK).
    loss_list: VecDeque<u32>,

    /// Queue entries invalidated by ACK/TLPKTDROP and awaiting lazy removal.
    stale_retransmits: usize,

    /// The oldest un-ACKed sequence number.
    oldest_unacked: u32,

    /// The next send sequence number.
    next_seq: u32,

    /// The next message number.
    next_msg: u32,

    /// Handshake-negotiated static flow window, in packets.
    ///
    /// Fixed for the lifetime of the connection: the peer's advertised
    /// receive capacity (`SRT_FLOW_WINDOW` in the handshake, when it sent
    /// one) clamped to this sender's own configured maximum. Immutable
    /// because it is the ceiling, not a running balance: no ACK may enlarge
    /// the sender past it.
    negotiated_window: u32,

    /// Absolute 31-bit-exclusive end of the peer's advertised receive
    /// window, in sequence space.
    ///
    /// A Full/Small ACK moves it to `ack_seq + advertised_free`; a Lite ACK
    /// advances the cumulative ACK but *cannot* move it. Keeping the credit
    /// as a sequence boundary rather than as a reusable count is the whole
    /// point: when a Lite ACK advances the cumulative ACK, the distance from
    /// `next_seq` to this fixed end shrinks with it, so the acknowledged
    /// flight's slots are not handed out a second time. Initialized to the
    /// handshake window's end so a sender may fill its negotiated window
    /// before the first ACK advertisement arrives (libsrt starts from the
    /// peer's flight flag size the same way, `core.cpp` `m_iFlowWindowSize`).
    peer_window_end: u32,

    /// Latency (microseconds).
    latency_us: u64,
    /// Packet send interval (microseconds).
    packet_send_period: u64,
    /// Instant at which the next paced send becomes eligible.
    ///
    /// This is a *deadline*, not a record of the last send. It was previously
    /// named `last_send_time`, which described neither its value nor its use.
    next_send_due: Option<Timestamp>,
    packet_send_period_overridden: bool,
    /// When set, a late send keeps the ideal slot even if that slot is already
    /// in the past, so a caller looping while eligible can repay missed
    /// periods. Default off preserves the idle-gap contract (exactly one
    /// immediate packet after silence). See `record_send_time`.
    repay_pacing_debt: bool,
    /// Total packets sent.
    total_sent: u64,
    /// Total bytes sent.
    total_bytes_sent: u64,
    /// SRT datagram bytes emitted, including SRT headers and retransmissions.
    total_srt_bytes_sent: u64,
    /// Retransmitted SRT datagram bytes, including SRT headers.
    total_retransmitted_srt_bytes: u64,
    /// Moving average of the sent payload size (bytes, for pacing calculation).
    avg_payload_size: f64,
    /// Maximum bandwidth (bytes/sec, equivalent to `SRTO_MAXBW`, for pacing calculation).
    max_bandwidth_bytes_per_sec: u64,
    /// Total retransmits (cumulative, equivalent to libsrt's `pktRetransTotal`).
    /// Kept separately from the sum of `retransmit_count` across entries
    /// currently in `packets` -- once an ACKed packet is removed from
    /// `packets`, the fact that it was retransmitted must not be lost (in a
    /// low-RTT environment the ACK arrives very shortly after a
    /// retransmission, so a live-scan approach would wrongly report
    /// "retransmission succeeded, but total_retransmits is nearly 0").
    total_retransmits: u64,
    /// Packets declared lost by peer NAKs (cumulative).
    total_lost: u64,
    /// Retained, unacknowledged packets whose first transmission used each
    /// key generation. A generation cannot be decommissioned while one of
    /// its packets is still retained: a retransmission has to be able to
    /// reproduce that packet's protected bytes.
    retained_tx_even: u32,
    retained_tx_odd: u32,
    /// Retained tombstones (dropped entries not yet retired by the
    /// cumulative ACK). They occupy window span but no flow-window credit
    /// and no payload accounting. (Reuses the slot the never-read
    /// `max_buffer_size` field occupied, so inline state does not grow for
    /// it.)
    dropped_retained: u32,
    /// Locally discarded packets that exceeded the TLPKTDROP deadline.
    total_dropped: u64,
    /// Payload bytes in locally discarded TLPKTDROP packets.
    total_bytes_dropped: u64,
    /// Valid ACK control packets received from the peer.
    total_acks_received: u64,
    /// NAK control packets received from the peer.
    total_naks_received: u64,
    /// Most recent measurements advertised by a compatible non-Light peer
    /// ACK (any size `validate_ack_shape` accepts that carries RTT
    /// feedback, not only the draft's own Full ACK), kept unsmoothed for
    /// telemetry -- distinct from `sender_rtt_micros`/`sender_rtt_var_micros`,
    /// which is this sender's own further-smoothed estimate used for the
    /// RTO calculation (see [`Self::record_peer_feedback`]).
    peer_feedback: Option<PeerFeedback>,
    /// This sender's own smoothed RTT estimate, in microseconds, per the SRT
    /// draft's §4.10 RTT estimation: the peer's own (already smoothed) RTT
    /// report is folded in as one more sample, exactly like the receiver
    /// half of this crate already smooths its own raw ACKACK round-trip
    /// samples (`SrtReceiver::handle_ackack`). Distinct from
    /// `PeerFeedback::rtt_micros`, which is the peer's raw, unsmoothed-by-us
    /// report. Initialized to [`INITIAL_SRTT_MICROS`], the same starting
    /// value used before any compatible ACK feedback arrives.
    sender_rtt_micros: u32,
    /// This sender's own smoothed RTT variance estimate, in microseconds,
    /// updated alongside `sender_rtt_micros`. Initialized to
    /// [`INITIAL_RTT_VAR_MICROS`].
    sender_rtt_var_micros: u32,
    /// The newest sequence number whose first datagram has actually been
    /// submitted to the transport, if any.
    ///
    /// The per-packet `submitted` flag is the truth; this is the O(1) ceiling
    /// the timeout probe starts from, so the common case never walks the
    /// window. First transmissions leave the protocol in sequence order, so it
    /// only moves forward within one sequence epoch.
    newest_submitted: Option<u32>,
    /// Sender retransmission-timeout epoch (see [`crate::sender::SenderRto`]).
    rto: SenderRto,
    /// Round-robin service position for the [`MAX_DROPREQ_PER_NAK`]
    /// anti-amplification cap.
    ///
    /// A repeated NAK covering the same loss range always finds the same
    /// tombstoned messages in the same order; without rotating which ones
    /// get served, a range spanning 17+ tombstoned messages would let the
    /// peer see only the first 16 no matter how many times it repeats the
    /// NAK, and could never advance its cumulative ACK past them. This
    /// counts total tombstones served across calls, used only as a rotating
    /// offset into whatever tombstone list the current call finds. `u16`
    /// wraps at exactly [`crate::srt_handshake::MAX_FLOW_WINDOW`] (65,536),
    /// the largest a negotiated window (and so the largest a distinct
    /// tombstone count) can ever be, so every residue is still reachable.
    dropreq_cursor: u16,
    /// Count of retained entries that are both submitted and not (yet)
    /// tombstoned -- i.e. still outstanding DATA a peer could legitimately
    /// still be holding.
    ///
    /// `newest_submitted` alone cannot answer "is anything outstanding":
    /// TLPKTDROP can tombstone a submitted entry without moving that
    /// ceiling, so a naive `newest_submitted` vs `oldest_unacked` comparison
    /// keeps reporting a flight that no longer exists once every submitted
    /// position has been given up. Incremented exactly once per sequence on
    /// its first live submission, decremented on ACK retirement or
    /// TLPKTDROP, reset on resync.
    live_submitted_count: u32,
    /// The exclusive end of the contiguous prefix (from `oldest_unacked`) a
    /// peer could legitimately have cumulatively ACKed.
    ///
    /// A position is ACK-justified once the peer could actually have learned
    /// about it: either its DATA first transmission, or (for a tombstone)
    /// the DROPREQ that reports it, has crossed the same submission boundary
    /// (`poll_output_into`) -- queuing either one is not enough. `next_seq`
    /// (merely *accepted*) is the wrong bound for this: #118 established
    /// accepted and submitted are different states. This is also not simply
    /// `max(newest_submitted, dropped_end) + 1`: TLPKTDROP can purge a
    /// queued-but-unsubmitted DATA datagram and replace it with a DROPREQ
    /// that itself has not gone out yet, leaving a live-but-not-yet-justified
    /// hole *behind* a later submitted sequence. The frontier only advances
    /// through a genuinely contiguous justified run starting at
    /// `oldest_unacked`, so such a hole correctly blocks it. Advanced
    /// incrementally by `advance_justified_frontier` whenever a submission
    /// or a DROPREQ crossing could extend it, so checking an incoming ACK is
    /// always O(1) and advancing it is amortized O(1) per position over the
    /// window's lifetime.
    justified_frontier: u32,
    /// Test-only instrumentation: number of times `tombstone_range` has
    /// actually walked a run, to pin its O(1)-per-distinct-run amortized
    /// cost against a regression back to O(run length) per requested
    /// position.
    #[cfg(test)]
    tombstone_range_calls: std::cell::Cell<u32>,
}

#[derive(Debug, Clone, Copy)]
struct PeerFeedback {
    rtt_micros: u32,
    rtt_variance_micros: u32,
    available_buffer_packets: u32,
    /// Rate/link telemetry, present only once a peer ACK has actually
    /// carried a rate section (24 bytes or larger). A 16-byte Small ACK
    /// updates RTT/RTTVar/window but carries no rate section at all, so it
    /// must leave whatever rate snapshot is already here untouched rather
    /// than replacing it with zeros -- see [`SenderBuffer::record_peer_feedback`].
    rate_feedback: Option<PeerRateFeedback>,
}

/// A peer ACK's rate/link telemetry, present only in a 24-byte-or-larger
/// (reference-Full or draft Full) ACK. Fully replaced, not merged, by each
/// ACK that carries one: mixing a new 24-byte snapshot's packet/link rates
/// with a stale byte-rate left over from an earlier 28-byte ACK would
/// misrepresent the peer's own report.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerRateFeedback {
    pub(crate) receiving_rate_packets_per_second: u32,
    pub(crate) link_capacity_packets_per_second: u32,
    /// Only a 28/32-byte ACK carries this field. A 24-byte ACK has no
    /// explicit byte-rate at all -- `None` here means exactly that absence,
    /// never a fabricated zero.
    pub(crate) receiving_rate_bytes_per_second: Option<u32>,
}

impl SenderBuffer {
    /// Create a new send buffer.
    ///
    /// In LIVE mode, the congestion window tracks the flow window (no
    /// TCP-style AIMD growth) -- real libsrt's `LiveCC` does the same, with
    /// `m_dMaxCWndSize = flowWindowSize()`, `m_dCWndSize = m_dMaxCWndSize`;
    /// actual send control is handled by pacing (`packet_send_period`)
    /// instead (`srtcore/congctl.cpp`).
    pub fn new(initial_seq: u32, flow_window: u32, latency_ms: u16) -> Self {
        let flow_window = flow_window.clamp(1, MAX_FLOW_WINDOW);
        let mut buf = Self {
            packets: SenderPacketWindow::new(flow_window),
            loss_list: VecDeque::new(),
            stale_retransmits: 0,
            oldest_unacked: initial_seq,
            next_seq: initial_seq,
            next_msg: 1,
            negotiated_window: flow_window,
            peer_window_end: initial_seq.wrapping_add(flow_window) & SEQUENCE_MASK,
            latency_us: latency_ms as u64 * 1000,
            packet_send_period: 0,
            next_send_due: None,
            packet_send_period_overridden: false,
            repay_pacing_debt: false,
            total_sent: 0,
            total_bytes_sent: 0,
            total_srt_bytes_sent: 0,
            total_retransmitted_srt_bytes: 0,
            avg_payload_size: INITIAL_AVG_PAYLOAD_SIZE_BYTES,
            max_bandwidth_bytes_per_sec: DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC,
            total_retransmits: 0,
            total_lost: 0,
            retained_tx_even: 0,
            retained_tx_odd: 0,
            dropped_retained: 0,
            total_dropped: 0,
            total_bytes_dropped: 0,
            total_acks_received: 0,
            total_naks_received: 0,
            peer_feedback: None,
            sender_rtt_micros: INITIAL_SRTT_MICROS,
            sender_rtt_var_micros: INITIAL_RTT_VAR_MICROS,
            newest_submitted: None,
            rto: SenderRto::new(),
            dropreq_cursor: 0,
            live_submitted_count: 0,
            justified_frontier: initial_seq,
            #[cfg(test)]
            tombstone_range_calls: std::cell::Cell::new(0),
        };
        buf.recompute_packet_send_period();
        buf
    }

    /// Get the next sequence number.
    pub fn next_sequence_number(&self) -> u32 {
        self.next_seq
    }

    /// The highest cumulative ACK position a peer could legitimately report,
    /// justified by actual submission to the transport rather than mere
    /// acceptance.
    ///
    /// [`Self::next_sequence_number`] is the *accepted* frontier: it
    /// advances the instant this sender assigns a sequence number, before
    /// the datagram has necessarily left the protocol for the transport. A
    /// peer can only acknowledge what it actually learned about, and it
    /// cannot have received data still sitting behind this sender's own TX
    /// capacity -- nor learned of a drop whose DROPREQ has not gone out yet.
    /// See the `justified_frontier` field's own doc comment.
    #[must_use]
    pub fn max_justified_ack_position(&self) -> u32 {
        self.justified_frontier
    }

    /// Advance `justified_frontier` through as much of the
    /// contiguous ACK-justified prefix (starting from wherever it already
    /// is) as is now available.
    ///
    /// Called after anything that can extend justification -- a DATA
    /// submission or a DROPREQ crossing the transport boundary. A live,
    /// unsubmitted entry (never dropped, `submitted` still false) or a
    /// tombstone whose DROPREQ has not yet gone out both stop the walk,
    /// exactly where the peer's own knowledge would stop. Because the
    /// frontier only ever moves forward and this is the only place it does,
    /// the total work across the window's lifetime is bounded by the number
    /// of positions that ever exist in it, not by the number of times an ACK
    /// is checked.
    fn advance_justified_frontier(&mut self) {
        while sequence_less_than(self.justified_frontier, self.next_seq) {
            // `submitted` is a historical fact -- the peer may already have
            // received this DATA before TLPKTDROP later turned the retained
            // entry into a tombstone, and tombstoning it does not make the
            // peer forget. So a position stays justified through that
            // transition on `submitted` alone; `drop_notified` only has to
            // carry justification for a position whose DATA was *never*
            // submitted.
            let justified = match self.packets.get(self.justified_frontier) {
                Some(entry) => entry.submitted || (entry.dropped && entry.drop_notified),
                None => false,
            };
            if !justified {
                break;
            }
            self.justified_frontier = self.justified_frontier.wrapping_add(1) & SEQUENCE_MASK;
        }
    }

    /// Record that the DROPREQ covering `[first_seq, last_seq]` has actually
    /// left the protocol for the transport, and advance
    /// `justified_frontier` through whatever that newly justifies.
    ///
    /// Mirrors [`Self::note_data_submitted`]'s materialization boundary:
    /// queuing a DROPREQ is not enough, for the same reason queuing DATA
    /// is not enough -- a peer cannot have learned of either until it
    /// actually crossed the wire. Bounded by the dropped message's own
    /// fragment count (one DROPREQ range names one message), not by the
    /// window.
    pub(crate) fn note_dropreq_submitted(&mut self, first_seq: u32, last_seq: u32) {
        let mut sequence = first_seq & SEQUENCE_MASK;
        let last = last_seq & SEQUENCE_MASK;
        loop {
            if let Some(entry) = self.packets.get_mut(sequence) {
                entry.drop_notified = true;
            }
            if sequence == last {
                break;
            }
            sequence = sequence.wrapping_add(1) & SEQUENCE_MASK;
        }
        self.advance_justified_frontier();
    }

    pub(crate) fn synchronize_next_sequence_number(&mut self, sequence_number: u32) -> bool {
        if !self.packets.is_empty() {
            return false;
        }
        self.next_seq = sequence_number & 0x7FFF_FFFF;
        self.oldest_unacked = self.next_seq;
        self.retained_tx_even = 0;
        self.retained_tx_odd = 0;
        self.peer_window_end = self.next_seq.wrapping_add(self.negotiated_window) & SEQUENCE_MASK;
        self.loss_list.clear();
        self.packets.clear();
        self.stale_retransmits = 0;
        self.newest_submitted = None;
        self.dropreq_cursor = 0;
        self.live_submitted_count = 0;
        self.justified_frontier = self.next_seq;
        true
    }

    /// Get the next message number.
    pub fn next_message_number(&self) -> u32 {
        self.next_msg
    }

    /// Remaining new-DATA credit, in packets: the distance from the next
    /// unset sequence to the peer's advertised window end, capped by what is
    /// left of the handshake-negotiated window.
    ///
    /// The two are separate quantities on purpose. The boundary is the
    /// peer's advertised receive capacity, expressed absolutely so a Lite
    /// ACK cannot recycle credit; the negotiated window is this sender's
    /// own ceiling, so a peer advertising an implausibly large free buffer
    /// cannot push the flight past what was agreed at handshake.
    pub fn remaining_window_packets(&self) -> u32 {
        if !sequence_less_than(self.next_seq, self.peer_window_end) {
            // The flight already reaches (or has passed) the advertised end:
            // no credit, not a wrapped-around large distance.
            return 0;
        }
        let to_end = self.peer_window_end.wrapping_sub(self.next_seq) & SEQUENCE_MASK;
        to_end.min(
            self.negotiated_window
                .saturating_sub(self.packets_in_flight()),
        )
    }

    /// Record the cryptographic reservation a packet's first transmission
    /// will use.
    pub fn note_data_stamp(&mut self, sequence: u32, stamp: Option<TxCryptoStamp>) {
        let Some(stamp) = stamp else {
            return;
        };
        let Some(entry) = self.packets.get_mut(sequence) else {
            return;
        };
        if entry.crypto_stamp.is_some() {
            return;
        }
        entry.crypto_stamp = Some(stamp);
        self.count_retained_stamp(stamp.key_flag, true);
    }

    /// The cryptographic reservation recorded for a retained packet.
    ///
    /// `None` covers both "no longer retained" and "sent in the clear": a
    /// retransmission of a plaintext packet needs no key generation either
    /// way.
    pub fn data_stamp(&self, sequence: u32) -> Option<TxCryptoStamp> {
        self.packets
            .get(sequence)
            .and_then(|entry| entry.crypto_stamp)
    }

    /// Retained packets per key generation: even, then odd.
    pub fn retained_stamps(&self) -> (u32, u32) {
        (self.retained_tx_even, self.retained_tx_odd)
    }

    fn count_retained_stamp(&mut self, key_flag: KeyFlag, add: bool) {
        let counter = match key_flag {
            KeyFlag::Even => &mut self.retained_tx_even,
            KeyFlag::Odd => &mut self.retained_tx_odd,
        };
        if add {
            *counter = counter.saturating_add(1);
        } else {
            *counter = counter.saturating_sub(1);
        }
    }

    /// The peer's advertised receive-window end (31-bit, exclusive).
    pub fn peer_window_end(&self) -> u32 {
        self.peer_window_end
    }

    /// The handshake-negotiated static flow window, in packets.
    pub fn negotiated_window(&self) -> u32 {
        self.negotiated_window
    }

    /// Whether sending is possible (checks window size only).
    pub fn can_send(&self) -> bool {
        self.retained_span() < self.packets.window_size()
            && self.packets_in_flight() < self.negotiated_window
            && sequence_less_than(self.next_seq, self.peer_window_end)
    }

    /// Whether an entire multi-packet message fits in the current windows.
    /// Partial messages are never admitted because their missing `Last`
    /// packet cannot be repaired by a later API call.
    pub fn can_send_message(&self, packet_count: usize) -> bool {
        u32::try_from(packet_count).is_ok_and(|count| count <= self.remaining_window_packets())
    }

    /// Whether sending is possible, including packet pacing.
    pub fn can_send_with_pacing(&self, now: Timestamp) -> bool {
        if !self.can_send() {
            return false;
        }

        // Check packet pacing.
        if self.packet_send_period > 0
            && let Some(due) = self.next_send_due
            && now.as_micros() < due.as_micros()
        {
            return false;
        }

        true
    }

    /// Time to wait until the next send is possible (microseconds).
    ///
    /// Returns 0 if sending is possible right now.
    pub fn time_until_send(&self, now: Timestamp) -> u64 {
        if !self.can_send() {
            // Return a longer wait time when the buffer is full.
            return 100_000; // 100ms
        }

        if self.packet_send_period == 0 {
            return 0;
        }

        if let Some(due) = self.next_send_due
            && now.as_micros() < due.as_micros()
        {
            return due.as_micros() - now.as_micros();
        }

        0
    }

    /// Set the packet send interval (microseconds).
    pub fn set_packet_send_period(&mut self, period: u64) {
        self.packet_send_period = period;
        self.packet_send_period_overridden = true;
    }

    /// Repay missed pacing slots on the next `record_send_time`.
    ///
    /// Canonical owner is `srt_transport::SessionConfig::set_pacing`;
    /// production code must go through it. Direct use is reserved for
    /// unit harnesses (benches, fuzz) that measure the mechanism itself.
    pub fn set_repay_pacing_debt(&mut self, repay: bool) {
        self.repay_pacing_debt = repay;
    }

    /// Drop leftover send-time debt (libsrt empty-queue). Call when demand
    /// has gone idle so a later resume admits exactly one immediate packet.
    pub fn discard_idle_pacing_debt(&mut self, now: Timestamp) {
        self.repay_pacing_debt = false;
        let period = self.packet_send_period;
        if period == 0 {
            return;
        }
        let Some(due) = self.next_send_due else {
            return;
        };
        let now_us = now.as_micros();
        if due.as_micros() <= now_us {
            self.next_send_due = Some(Timestamp::from_micros(now_us.saturating_add(period)));
        }
    }

    /// Advance the pacing schedule after a send.
    ///
    /// The schedule is a sequence of ideal slots one period apart. Servicing is
    /// never exactly on time, so the question is what a late send does to the
    /// phase of that sequence:
    ///
    /// ```text
    /// lateness < period   keep the phase:   next due = previous due + period
    /// lateness >= period  rebase the phase: next due = now + period
    ///                    (or keep the phase when repay_pacing_debt is set)
    /// ```
    ///
    /// The first branch is the repair. Previously every send rebased from the
    /// actual send time, so a runtime that could not wake more precisely than
    /// its scheduling quantum lost that quantum on *every* packet and achieved
    /// `1/(period + lateness)` instead of `1/period`. Since no async runtime
    /// wakes at sub-millisecond resolution, that deficit is first-order at live
    /// bitrates: an 8 Mbit/s source paced at 10 Mbit/s measured 67.8% of its
    /// offered payload on a single idle connection.
    ///
    /// The rebase branch is the idle-gap contract verified against libsrt
    /// 1.5.3: after genuine silence, exactly one packet may go immediately.
    /// libsrt itself *does* repay whole-period debt while the sender queue
    /// stays non-empty. `repay_pacing_debt` is that switch: the caller tells
    /// the pacer that application data is still waiting. Default off matches
    /// the empty-queue / idle path. See `docs/perf/pacing-phase.md`.
    ///
    /// With the flag off, both branches leave the deadline strictly after
    /// `now`, so a caller looping while eligible cannot drain more than one
    /// packet per instant. With the flag on, a deadline may land at or before
    /// `now` so missed slots can be repaid in the same visit.
    pub fn record_send_time(&mut self, now: Timestamp) {
        let period = self.packet_send_period;
        if period == 0 {
            self.next_send_due = Some(now);
            return;
        }
        self.next_send_due = Some(Timestamp::from_micros(
            self.next_due_after_send(now, period),
        ));
    }

    fn next_due_after_send(&self, now: Timestamp, period: u64) -> u64 {
        let now_us = now.as_micros();
        let next_slot = self
            .next_send_due
            .map(|due| due.as_micros().saturating_add(period));
        if self.repay_pacing_debt {
            // At most one extra packet at this instant. Full libsrt debt
            // would emit every missed slot here; with N=600 pumped in one
            // park that is an incast, not a repair.
            match next_slot {
                Some(next) if next > now_us => next,
                Some(_) => now_us,
                None => now_us.saturating_add(period),
            }
        } else {
            next_slot
                .filter(|&next| next > now_us)
                .unwrap_or_else(|| now_us.saturating_add(period))
        }
    }

    /// Number of live packets in flight.
    ///
    /// TLPKTDROP tombstones are excluded: the peer has already been told (or
    /// is about to be told) that those sequences are dropped, so they hold no
    /// receive-window space on its side. They still occupy window span --
    /// that bound is [`Self::retained_span`].
    pub fn packets_in_flight(&self) -> u32 {
        (self.packets.len() as u32).saturating_sub(self.dropped_retained)
    }

    /// Retained entries, tombstones included: the window's own storage bound.
    pub fn retained_span(&self) -> u32 {
        self.packets.len() as u32
    }

    /// Number of packets in the buffer.
    pub fn packets_in_buffer(&self) -> usize {
        self.packets_in_flight() as usize
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Whether there are packets needing retransmission.
    pub fn has_retransmit(&self) -> bool {
        self.packets.has_retransmit_queued()
    }

    /// Queue one probe retransmission of the newest packet that was actually
    /// submitted to the transport.
    ///
    /// A receiver can only name a loss it has evidence for, and a missing
    /// *suffix* of a flight provides none: no later sequence number arrives to
    /// expose the gap, so no NAK is generated, `sec_a` stays zero, and the
    /// payload is simply absent. NAK-driven recovery therefore cannot repair a
    /// lost flight tail on its own, and the sender's retransmission timer is the
    /// last party that can notice.
    ///
    /// Probing the newest *submitted* packet is the narrow answer: its arrival
    /// both repairs a lost tail directly and gives the receiver later sequence
    /// evidence, which is what exposes any older gaps to ordinary selective
    /// recovery. Replaying the whole unacknowledged flight instead would amplify
    /// an outage on every timeout, which is why this queues exactly one packet.
    ///
    /// A packet that was accepted by the sender but is still waiting for TX
    /// capacity is not eligible: it has never been on the wire, so
    /// retransmitting it would not repair a loss. The search therefore starts
    /// at the newest submitted sequence and steps down over any retained slot
    /// that has not been submitted (or is already queued). Normal operation
    /// ends the walk after one step, because the newest submitted packet is
    /// also the newest retained one.
    ///
    /// Returns the sequence queued, or `None` if nothing was eligible.
    /// Callers must only use this when no selective retransmission is already
    /// pending, so a NAK-driven recovery in progress is never widened by the
    /// timer -- and must record the returned sequence as a pending probe
    /// (see [`crate::sender_rto::SenderRto::probe_pending`]) until it is
    /// confirmed to have actually left the protocol, so a probe still sitting
    /// behind blocked TX capacity is never queued a second time.
    pub fn queue_retransmission_of_newest_submitted(&mut self) -> Option<u32> {
        let newest = self.newest_submitted?;
        let mut ceiling = newest;
        loop {
            let (sequence, eligible) =
                self.packets
                    .last_occupied_before(ceiling.wrapping_add(1))
                    .map(|(sequence, entry)| (sequence, entry.submitted && !entry.dropped))?;
            // Walked back past the flight: everything at or below here has
            // been acknowledged and is no longer a candidate.
            if !sequence_less_than(self.oldest_unacked, sequence.wrapping_add(1)) {
                return None;
            }
            if eligible && !self.packets.retransmit_queued_contains(sequence) {
                self.packets.queue_loss_range(
                    sequence,
                    sequence,
                    |_| true,
                    |sequence| {
                        self.loss_list.push_back(sequence);
                    },
                );
                return Some(sequence);
            }
            ceiling = sequence.wrapping_sub(1);
        }
    }

    /// Record that a DATA datagram actually left the protocol for the
    /// transport, and report whether that submission started a new sender-RTO
    /// epoch.
    ///
    /// Callers must only pass datagrams the transport has irrevocably accepted
    /// (reserved TX capacity already held), because everything downstream --
    /// probe eligibility, the epoch, TLPKTDROP age -- then treats the packet as
    /// having been on the wire.
    ///
    /// Returns what the caller must do with `TimerId::SenderRto`. An epoch
    /// already running is never restarted by an ordinary submission: a busy
    /// sender would otherwise postpone its own timeout indefinitely while one
    /// early packet stayed stranded. Only cumulative ACK progress restarts it,
    /// and only an empty flight disarms it. The one exception is the pending
    /// blind probe finally crossing this boundary: its deadline has to be
    /// measured from *this* instant, so the caller reprograms the epoch (keeping
    /// the accumulated backoff) rather than leaving the old one to fire
    /// immediately after the probe went out.
    pub fn note_data_submitted(&mut self, sequence: u32) -> RtoArm {
        if let Some(entry) = self.packets.get_mut(sequence) {
            // Only a live entry's first submission adds outstanding flight:
            // a caller materializing a queued datagram whose sequence has
            // since been dropped is a race `purge_stale_queued_data` (the
            // connection layer) is meant to close before this is ever
            // reached, but counting it here regardless would be wrong twice
            // over -- once for double-counting a retransmission, and once
            // for treating a tombstone as outstanding.
            if !entry.submitted && !entry.dropped {
                self.live_submitted_count = self.live_submitted_count.saturating_add(1);
            }
            entry.submitted = true;
        }
        if self
            .newest_submitted
            .is_none_or(|newest| sequence_less_than(newest, sequence))
        {
            self.newest_submitted = Some(sequence);
        }
        self.advance_justified_frontier();
        let probe_submitted = self.rto.confirm_probe_submitted(sequence);
        if !self.rto.is_armed() {
            return RtoArm::Start;
        }
        if probe_submitted {
            return RtoArm::Rearm;
        }
        RtoArm::Nothing
    }

    /// Whether anything that was actually submitted is still both
    /// unacknowledged and live (not tombstoned by TLPKTDROP).
    ///
    /// `newest_submitted` vs `oldest_unacked` alone cannot answer this:
    /// TLPKTDROP can tombstone every submitted entry without moving either
    /// boundary, which would otherwise leave the RTO timer probing a flight
    /// that no longer exists -- the `live_submitted_count` field this reads
    /// is kept accurate for exactly that reason.
    #[must_use]
    pub fn has_outstanding_submitted_data(&self) -> bool {
        self.live_submitted_count > 0
    }

    /// Whether `sequence` is still outstanding (not yet acknowledged).
    #[must_use]
    fn is_outstanding(&self, sequence: u32) -> bool {
        sequence_less_than(self.oldest_unacked, sequence.wrapping_add(1))
    }

    /// Whether `sequence` is still a live, un-tombstoned retained entry --
    /// i.e. still eligible to leave the protocol as a DATA datagram.
    ///
    /// False for a sequence already retired by the cumulative ACK (no
    /// longer retained at all) and for one TLPKTDROP has tombstoned
    /// (retained only as dropped identity, media already released). Used to
    /// keep a DATA output queued behind blocked TX capacity from
    /// materializing after the sender itself has already given up on it or
    /// the peer has already acknowledged it.
    #[must_use]
    pub fn is_live(&self, sequence: u32) -> bool {
        self.packets
            .get(sequence)
            .is_some_and(|entry| !entry.dropped)
    }

    /// Sequence of a blind RTO probe queued for retransmission but not yet
    /// confirmed to have actually left the protocol -- see
    /// [`SenderRto::probe_pending`]. Self-heals a stale marker left over from
    /// a probed sequence that was acknowledged through some other path
    /// (ordinary delivery, a differently-triggered retransmission) without
    /// ever crossing this timer's own submission boundary, or that TLPKTDROP
    /// tombstoned while the probe was still sitting behind blocked TX
    /// capacity: neither can legitimately clear via
    /// [`SenderRto::confirm_probe_submitted`], so both are dropped here
    /// instead of permanently blocking every future probe.
    #[must_use]
    pub fn rto_probe_pending(&mut self) -> Option<u32> {
        if let Some(sequence) = self.rto.probe_pending()
            && (!self.is_outstanding(sequence) || !self.is_live(sequence))
        {
            self.rto.confirm_probe_submitted(sequence);
        }
        self.rto.probe_pending()
    }

    /// Record that a blind probe of `sequence` was just queued.
    pub fn rto_set_probe_pending(&mut self, sequence: u32) {
        self.rto.set_probe_pending(sequence);
    }

    /// The oldest un-acknowledged sequence number.
    #[must_use]
    pub fn oldest_unacked_sequence(&self) -> u32 {
        self.oldest_unacked
    }

    /// Current base timeout from the peer's most recent compatible ACK
    /// feedback.
    #[must_use]
    pub fn rto_base_timeout_micros(&self) -> u64 {
        // This sender's own smoothed estimate (see `record_peer_feedback`),
        // never the peer's raw report directly -- it is already initialized
        // to the same starting constants `SenderRto::base_timeout_micros`
        // would otherwise fall back to, so there is no "no compatible ACK
        // feedback yet" case left to express with `None`.
        SenderRto::base_timeout_micros(Some((self.sender_rtt_micros, self.sender_rtt_var_micros)))
    }

    /// Start a fresh RTO epoch, returning the timeout to program.
    pub fn rto_start(&mut self) -> u64 {
        self.rto.start(self.rto_base_timeout_micros())
    }

    /// Reprogram the RTO epoch from the instant the pending blind probe was
    /// actually submitted, returning the timeout to program.
    ///
    /// Distinct from [`Self::rto_start`]: this preserves the accumulated
    /// backoff, because a submission is not ACK progress.
    pub fn rto_rearm(&mut self) -> u64 {
        self.rto.rearm(self.rto_base_timeout_micros())
    }

    /// Stop the RTO epoch: nothing submitted is outstanding any more.
    pub fn rto_stop(&mut self) {
        self.rto.stop();
    }

    /// Record an RTO expiry, returning the backed-off timeout to program.
    pub fn rto_expire(&mut self) -> u64 {
        self.rto.expire(self.rto_base_timeout_micros())
    }

    /// Whether an RTO epoch is running.
    #[must_use]
    pub fn rto_is_armed(&self) -> bool {
        self.rto.is_armed()
    }

    /// Consecutive RTO expiries without cumulative ACK progress.
    #[must_use]
    pub fn rto_backoffs(&self) -> u32 {
        self.rto.backoffs()
    }

    /// Apply a Full/Small ACK's advertised receive window.
    ///
    /// `ack_seq` is the ACK's cumulative position (the receiver's next
    /// expected sequence) and `advertised_free` is the free receive-buffer
    /// size it carries, in packets. The result is an absolute boundary, not
    /// a reusable balance: `ack_seq + advertised_free`. A later Lite ACK
    /// advances `ack_seq` without moving this value, so the flight it
    /// acknowledges consumes credit instead of restoring it.
    ///
    /// The advertised value is clamped to the handshake-negotiated window:
    /// libsrt and Robotweax both take a current advertisement verbatim, but
    /// an inflated or hostile advertisement must not enlarge the sender past
    /// what was agreed at handshake. Callers must only pass an ACK that
    /// actually advanced the cumulative position (see
    /// [`Self::handle_ack`]'s callers); a stale or duplicate ACK must not
    /// reopen a closed window.
    pub fn set_peer_window(&mut self, ack_seq: u32, advertised_free: u32) {
        if ack_seq & !SEQUENCE_MASK != 0 {
            return;
        }
        let free = advertised_free.min(self.negotiated_window);
        self.peer_window_end = ack_seq.wrapping_add(free) & SEQUENCE_MASK;
    }

    /// Set the maximum bandwidth (equivalent to `SRTO_MAXBW`, bytes/sec).
    /// Immediately recomputes the pacing interval (equivalent to libsrt's
    /// `LiveCC::setMaxBW` -> `updatePktSndPeriod`, `srtcore/congctl.cpp`).
    /// If `bytes_per_sec` is 0, falls back to
    /// `DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC`, matching libsrt.
    pub fn set_max_bandwidth(&mut self, bytes_per_sec: u64) {
        self.max_bandwidth_bytes_per_sec = if bytes_per_sec == 0 {
            DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC
        } else {
            bytes_per_sec
        };
        self.packet_send_period_overridden = false;
        self.recompute_packet_send_period();
    }

    /// Set source-relative pacing from `SRTO_INPUTBW` and `SRTO_OHEADBW`.
    /// The explicit maximum-bandwidth mode takes precedence at connection
    /// setup; this method is used only when no maximum is configured.
    pub fn set_input_bandwidth(&mut self, input_bytes_per_sec: u64, overhead_percent: u8) {
        self.max_bandwidth_bytes_per_sec =
            input_bytes_per_sec.saturating_mul(100 + u64::from(overhead_percent)) / 100;
        self.packet_send_period_overridden = false;
        self.recompute_packet_send_period();
    }

    /// Update the moving average of the sent payload size (equivalent to
    /// libsrt's `LiveCC::updatePayloadSize`; called on every real send).
    fn record_sent_payload_size(&mut self, size: usize) {
        self.avg_payload_size = (self.avg_payload_size * (AVG_PAYLOAD_SIZE_IIR_LEN - 1.0)
            + size as f64)
            / AVG_PAYLOAD_SIZE_IIR_LEN;
        if !self.packet_send_period_overridden {
            self.recompute_packet_send_period();
        }
    }

    /// Compute the packet send interval from the average wire packet size and
    /// maximum bandwidth (equivalent to libsrt's
    /// `LiveCC::updatePktSndPeriod`, `srtcore/congctl.cpp`).
    fn recompute_packet_send_period(&mut self) {
        let wire_packet_size = self.avg_payload_size + SRT_HEADER_SIZE as f64;
        let period_us = 1_000_000.0 * wire_packet_size / self.max_bandwidth_bytes_per_sec as f64;
        self.packet_send_period = period_us.round() as u64;
    }

    /// Add a payload to the buffer and produce header + payload for wire encoding.
    pub fn push(
        &mut self,
        payload: Vec<u8>,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
    ) -> Option<(DataHeader, Bytes)> {
        self.push_with_sequence(payload, timestamp, dest_socket_id, now, self.next_seq)
    }

    /// Push a packet using an externally coordinated sequence number.
    pub fn push_with_sequence(
        &mut self,
        payload: Vec<u8>,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
        sequence_number: u32,
    ) -> Option<(DataHeader, Bytes)> {
        self.push_impl(
            Bytes::from(payload),
            timestamp,
            dest_socket_id,
            now,
            sequence_number,
        )
    }

    /// Push with a shared payload — the fan-out path.
    pub fn push_shared(
        &mut self,
        payload: Bytes,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
    ) -> Option<(DataHeader, Bytes)> {
        self.push_shared_with_sequence(payload, timestamp, dest_socket_id, now, self.next_seq)
    }

    /// Push shared payload with an externally coordinated sequence number.
    pub fn push_shared_with_sequence(
        &mut self,
        payload: Bytes,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
        sequence_number: u32,
    ) -> Option<(DataHeader, Bytes)> {
        self.push_impl(payload, timestamp, dest_socket_id, now, sequence_number)
    }

    fn push_impl(
        &mut self,
        retained: Bytes,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
        sequence_number: u32,
    ) -> Option<(DataHeader, Bytes)> {
        if !self.can_send() || sequence_number != self.next_seq {
            return None;
        }

        let message_number = self.next_msg;
        let payload_len = retained.len();
        let wire_payload = retained.clone();

        self.packets
            .insert(
                sequence_number,
                SentPacket {
                    position: PacketPosition::Single,
                    order_flag: false,
                    message_number,
                    timestamp,
                    payload: retained,
                    sent_time: now,
                    retransmit_count: 0,
                    crypto_stamp: None,
                    dropped: false,
                    submitted: false,
                    drop_notified: false,
                },
            )
            .expect("alias-free live span checked by can_send");

        let header = DataHeader {
            sequence_number,
            position: PacketPosition::Single,
            order_flag: false,
            retransmitted: false,
            message_number,
            timestamp,
            dest_socket_id,
        };

        self.total_sent += 1;
        self.total_bytes_sent += payload_len as u64;
        self.total_srt_bytes_sent = self
            .total_srt_bytes_sent
            .saturating_add((payload_len + SRT_HEADER_SIZE) as u64);
        self.record_sent_payload_size(payload_len);

        self.next_seq = self.next_seq.wrapping_add(1) & 0x7FFF_FFFF;
        self.next_msg = self.next_msg.wrapping_add(1) & 0x03FF_FFFF;

        Some((header, wire_payload))
    }

    /// Split a large message and send it.
    pub fn push_message(
        &mut self,
        payload: &[u8],
        max_payload_size: usize,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
    ) -> Vec<(DataHeader, Bytes)> {
        if max_payload_size == 0 {
            return Vec::new();
        }
        let total_chunks = payload.len().div_ceil(max_payload_size);
        if !self.can_send_message(total_chunks) {
            return Vec::new();
        }
        let mut results = Vec::with_capacity(total_chunks);

        for (i, chunk) in payload.chunks(max_payload_size).enumerate() {
            let position = match (i, total_chunks) {
                (0, 1) => PacketPosition::Single,
                (0, _) => PacketPosition::First,
                (n, total) if n == total - 1 => PacketPosition::Last,
                _ => PacketPosition::Middle,
            };

            let retained = Bytes::copy_from_slice(chunk);
            let chunk_len = retained.len();
            let wire_payload = retained.clone();

            self.packets
                .insert(
                    self.next_seq,
                    SentPacket {
                        position,
                        order_flag: true,
                        message_number: self.next_msg,
                        timestamp,
                        payload: retained,
                        sent_time: now,
                        retransmit_count: 0,
                        crypto_stamp: None,
                        dropped: false,
                        submitted: false,
                        drop_notified: false,
                    },
                )
                .expect("alias-free live span checked by can_send");

            let header = DataHeader {
                sequence_number: self.next_seq,
                position,
                order_flag: true,
                retransmitted: false,
                message_number: self.next_msg,
                timestamp,
                dest_socket_id,
            };

            self.total_sent += 1;
            self.total_bytes_sent += chunk_len as u64;
            self.total_srt_bytes_sent = self
                .total_srt_bytes_sent
                .saturating_add((chunk_len + SRT_HEADER_SIZE) as u64);
            self.record_sent_payload_size(chunk_len);

            self.next_seq = self.next_seq.wrapping_add(1) & 0x7FFF_FFFF;
            results.push((header, wire_payload));
        }

        if !results.is_empty() {
            self.next_msg = self.next_msg.wrapping_add(1) & 0x03FF_FFFF;
        }

        results
    }

    /// Push a packet and mark its datagram as actually transmitted.
    ///
    /// The window/ACK/NAK mechanics tests need the state a real sender has
    /// once `poll_output_into` has materialized a datagram: a peer's loss
    /// report is only credible for positions that were on the wire, and the
    /// loss-report path now rejects reports naming positions that were not.
    #[cfg(test)]
    pub fn push_submitted(
        &mut self,
        payload: Vec<u8>,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
    ) -> Option<(DataHeader, Bytes)> {
        let pushed = self.push(payload, timestamp, dest_socket_id, now)?;
        self.note_data_submitted(pushed.0.sequence_number);
        Some(pushed)
    }

    /// Get a packet to retransmit.
    ///
    /// `entry.sent_time` is left at its original send time and never
    /// updated (the same intent as libsrt's `CSndBuffer::Block::m_tsOriginTime`
    /// -- see `srtcore/buffer_snd.h`/`.cpp`. Rewriting it to the current time
    /// on every retransmit would make TLPKTDROP non-monotonic in sequence
    /// order: a retransmitted old packet would be "rejuvenated" and could end
    /// up expiring after a newer packet that was never retransmitted. That
    /// also defeats TLPKTDROP's purpose -- cleanly giving up once the
    /// delivery deadline passes, to bound latency -- since a packet
    /// retransmitted repeatedly would then never expire.)
    pub fn pop_retransmit(&mut self, dest_socket_id: u32) -> Option<(DataHeader, Bytes)> {
        while let Some(seq) = self.loss_list.pop_front() {
            if let Some(entry) = self.packets.pop_retransmit_slot(seq) {
                if entry.dropped {
                    // A tombstone answers a repeated NAK with DROPREQ, never
                    // with DATA: its payload is gone and the peer has been
                    // told this message is dropped.
                    self.stale_retransmits = self.stale_retransmits.saturating_sub(1);
                    continue;
                }
                entry.retransmit_count += 1;
                self.total_retransmits += 1;
                let wire_bytes = (entry.payload.len() + SRT_HEADER_SIZE) as u64;
                self.total_srt_bytes_sent = self.total_srt_bytes_sent.saturating_add(wire_bytes);
                self.total_retransmitted_srt_bytes = self
                    .total_retransmitted_srt_bytes
                    .saturating_add(wire_bytes);

                return Some((
                    DataHeader {
                        sequence_number: seq,
                        position: entry.position,
                        order_flag: entry.order_flag,
                        retransmitted: true,
                        message_number: entry.message_number,
                        timestamp: entry.timestamp,
                        dest_socket_id,
                    },
                    entry.payload.clone(),
                ));
            }
            self.stale_retransmits = self.stale_retransmits.saturating_sub(1);
        }
        None
    }

    /// Process an ACK and release the buffer.
    ///
    /// `ack_seq` is the next expected sequence number (everything below it is ACKed).
    pub fn handle_ack(&mut self, ack_seq: u32) {
        self.total_acks_received = self.total_acks_received.saturating_add(1);
        self.discard_acked(ack_seq);
    }

    /// Discard acknowledged packets without recording a peer ACK. This is
    /// used by local sequence reconciliation paths.
    pub(crate) fn discard_acked(&mut self, ack_seq: u32) {
        if ack_seq & !SEQUENCE_MASK != 0 {
            return;
        }

        let ack_distance = ack_seq.wrapping_sub(self.oldest_unacked) & SEQUENCE_MASK;
        let in_flight_span = self.next_seq.wrapping_sub(self.oldest_unacked) & SEQUENCE_MASK;
        if ack_distance == 0 || ack_distance > in_flight_span {
            return;
        }

        let mut stale_count = 0;
        let mut tombstones_discarded = 0;
        let mut live_submitted_discarded = 0u32;
        let mut released_stamps = Vec::new();
        self.packets.discard_acked_prefix(
            self.oldest_unacked,
            ack_seq,
            |entry: &SentPacket, was_retransmit_queued| {
                if was_retransmit_queued {
                    stale_count += 1;
                }
                if entry.dropped {
                    tombstones_discarded += 1;
                } else {
                    if entry.submitted {
                        live_submitted_discarded += 1;
                    }
                    if let Some(stamp) = entry.crypto_stamp {
                        released_stamps.push(stamp.key_flag);
                    }
                }
            },
        );
        self.stale_retransmits = self.stale_retransmits.saturating_add(stale_count);
        self.dropped_retained = self.dropped_retained.saturating_sub(tombstones_discarded);
        self.live_submitted_count = self
            .live_submitted_count
            .saturating_sub(live_submitted_discarded);
        for key_flag in released_stamps {
            self.count_retained_stamp(key_flag, false);
        }

        self.oldest_unacked = ack_seq;
        // The frontier must never trail what the peer has just confirmed --
        // the connection layer already rejects any ACK beyond it, so this is
        // a consistency floor rather than a normal advance path (a resync
        // that rebases `oldest_unacked` ahead of a stale `justified_frontier`
        // is the one caller-reachable case).
        if sequence_less_than(self.justified_frontier, self.oldest_unacked) {
            self.justified_frontier = self.oldest_unacked;
        }
        self.compact_stale_retransmits();
    }

    /// Process a NAK and add to the loss list.
    ///
    /// Test-only convenience wrapper for single-sequence loss lists.
    #[cfg(test)]
    pub fn handle_nak(&mut self, lost_sequences: &[u32]) {
        let ranges: Vec<LossRange> = lost_sequences
            .iter()
            .map(|&sequence| LossRange {
                first_seq: sequence,
                last_seq: sequence,
            })
            .collect();
        let _ = self.handle_nak_ranges(&ranges);
    }

    /// Validate one requested loss range against the retained window,
    /// recording any tombstoned message it touches.
    ///
    /// `known_run` caches the most recently discovered tombstone run's
    /// `(first, last)` bounds so that a NAK naming a broad range spanning
    /// one heavily fragmented dropped message does not re-walk that whole
    /// run for every position inside it -- `tombstone_range` itself is
    /// O(run length), and the old per-position call made a range spanning
    /// most of the negotiated window O(run^2). `seen_starts` catches the
    /// rarer case of two different requested ranges in the same report
    /// both landing on the same run, which the cache above cannot: an
    /// O(log D) lookup keyed by each run's first sequence, where D is the
    /// number of distinct runs found so far (bounded by the negotiated
    /// window). Together this keeps the whole validation at O(requested
    /// span + D log D) rather than the O(N^2) a linear rescan of
    /// `tombstones` per position gave a report naming many one-packet
    /// tombstoned messages.
    fn validate_loss_range(
        &self,
        loss: &LossRange,
        tombstones: &mut Vec<(u32, u32)>,
        seen_starts: &mut BTreeSet<u32>,
        known_run: &mut Option<(u32, u32)>,
    ) -> Result<(), InvalidNak> {
        let mut sequence = loss.first_seq & SEQUENCE_MASK;
        let last_seq = loss.last_seq & SEQUENCE_MASK;
        loop {
            let within_known_run = known_run.is_some_and(|(first, last)| {
                !sequence_less_than(sequence, first) && !sequence_less_than(last, sequence)
            });
            if !within_known_run {
                *known_run = None;
                match self.packets.get(sequence) {
                    None => {
                        // Never sent, already acknowledged, or outside the
                        // retained span: not a loss this receiver could have
                        // observed.
                        return Err(InvalidNak);
                    }
                    Some(entry) if entry.dropped => {
                        let message_number = entry.message_number;
                        if let Some(range) = self.tombstone_range(sequence, message_number) {
                            *known_run = Some(range);
                            if seen_starts.insert(range.0) {
                                tombstones.push(range);
                            }
                        }
                    }
                    Some(entry) if !entry.submitted => {
                        // Accepted but never on the wire: the peer cannot have
                        // measured it as lost.
                        return Err(InvalidNak);
                    }
                    Some(_) => {}
                }
            }
            if sequence == last_seq {
                return Ok(());
            }
            sequence = sequence.wrapping_add(1) & SEQUENCE_MASK;
        }
    }

    /// Validate a peer loss report completely, then commit it: either every
    /// requested position is a credible report and the whole NAK is applied,
    /// or nothing is.
    ///
    /// A loss report is evidence a receiver can only produce from what it has
    /// seen: a position it never received *while a later position arrived*.
    /// So every requested sequence must still be retained here, and each live
    /// one must have actually been transmitted -- a sequence this sender
    /// accepted but never submitted is invisible to the peer, and a future or
    /// already-retired sequence is not network loss. Any component that fails
    /// means the whole report is rejected, so a valid prefix cannot smuggle
    /// an impossible tail into the retransmission queue.
    ///
    /// Live positions are queued for DATA retransmission; tombstoned ones
    /// (messages already given up as too late) are returned for a repeated
    /// DROPREQ, capped per report so one NAK cannot be amplified into
    /// unbounded control traffic.
    ///
    /// Validation walks the requested ranges against the window, bounded by
    /// the negotiated window: no expanded sequence list is built.
    pub fn handle_nak_ranges(
        &mut self,
        loss_ranges: &[LossRange],
    ) -> Result<Vec<DroppedMessage>, InvalidNak> {
        let mut requested_span = 0u32;
        for loss in loss_ranges {
            let first_seq = loss.first_seq & SEQUENCE_MASK;
            let last_seq = loss.last_seq & SEQUENCE_MASK;
            let count = (last_seq.wrapping_sub(first_seq) & SEQUENCE_MASK).saturating_add(1);
            if count > self.negotiated_window {
                return Err(InvalidNak);
            }
            requested_span = requested_span.saturating_add(count);
            if requested_span > self.negotiated_window {
                return Err(InvalidNak);
            }
        }

        // Phase 1: validate everything before touching any state, including
        // `total_naks_received`: an impossible report is not evidence the
        // peer is alive and playing by the protocol, so it must not be
        // banked as one.
        let mut tombstones: Vec<(u32, u32)> = Vec::new();
        let mut seen_starts: BTreeSet<u32> = BTreeSet::new();
        let mut known_run: Option<(u32, u32)> = None;
        for loss in loss_ranges {
            self.validate_loss_range(loss, &mut tombstones, &mut seen_starts, &mut known_run)?;
        }

        // Phase 2: commit. Only a validated report reaches here, so this is
        // the one place `total_naks_received` is allowed to move.
        self.total_naks_received = self.total_naks_received.saturating_add(1);
        for loss in loss_ranges {
            self.queue_loss_range(loss.first_seq, loss.last_seq);
        }

        if tombstones.is_empty() {
            return Ok(Vec::new());
        }
        // Rotate the start of service by however many tombstones have been
        // served in total: a range that never shrinks (the peer keeps
        // repeating the same NAK) then serves a different window of
        // messages each time instead of stalling on the same first
        // `MAX_DROPREQ_PER_NAK`. See `dropreq_cursor`'s doc comment.
        let start = (self.dropreq_cursor as usize) % tombstones.len();
        tombstones.rotate_left(start);
        let served: Vec<DroppedMessage> = tombstones
            .into_iter()
            .take(MAX_DROPREQ_PER_NAK)
            .map(|(first_seq, last_seq)| DroppedMessage {
                message_number: self
                    .packets
                    .get(first_seq)
                    .map_or(0, |entry| entry.message_number),
                first_seq,
                last_seq,
            })
            .collect();
        self.dropreq_cursor = self.dropreq_cursor.wrapping_add(served.len() as u16);
        Ok(served)
    }

    /// Queue retained, live, transmitted packets intersecting one loss range.
    fn queue_loss_range(&mut self, first_seq: u32, last_seq: u32) {
        let packets = &mut self.packets;
        let loss_list = &mut self.loss_list;
        let total_lost = &mut self.total_lost;
        packets.queue_loss_range(
            first_seq & SEQUENCE_MASK,
            last_seq & SEQUENCE_MASK,
            |entry: &SentPacket| !entry.dropped,
            |sequence| {
                loss_list.push_back(sequence);
                *total_lost = total_lost.saturating_add(1);
            },
        );
    }

    fn compact_stale_retransmits(&mut self) {
        if self.stale_retransmits <= STALE_RETRANSMIT_COMPACT_THRESHOLD {
            return;
        }
        let packets = &self.packets;
        self.loss_list
            .retain(|&sequence| packets.retransmit_queued_contains(sequence));
        self.stale_retransmits = 0;
    }

    /// Retain measurements carried by the most recent compatible non-Light
    /// ACK, and fold the peer's reported RTT into this sender's own
    /// smoothed estimate.
    ///
    /// The draft's §4.10 RTT estimation is defined at whichever node is doing
    /// the estimating, from its own raw round-trip samples; a receiver's
    /// `rtt_micros` report is itself already smoothed at the receiver. This
    /// sender does not get raw round-trip samples of its own (it never sees a
    /// timestamp echo the way ACKACK gives the receiver one), so the input to
    /// its own §4.10 smoothing is the peer's report, treated as one more
    /// sample rather than substituted wholesale -- otherwise every such ACK
    /// would simply replace the sender's RTO input with whatever the peer
    /// last measured, which is exactly the smoothing the draft specifies
    /// against. `peer_feedback` keeps the raw, unsmoothed-by-us report for
    /// telemetry; `sender_rtt_micros`/`sender_rtt_var_micros` is what the RTO
    /// actually consumes.
    ///
    /// `rate_feedback` is `None` when this particular ACK carried no rate
    /// section at all (a 16-byte Small ACK): the previous rate snapshot, if
    /// any, is preserved rather than zeroed. When `Some`, it *replaces* the
    /// previous snapshot wholesale -- a 24-byte ACK's absent byte-rate must
    /// not be backfilled from an older 28-byte ACK's, since that would
    /// misrepresent this report as carrying a field it does not have.
    pub(crate) fn record_peer_feedback(
        &mut self,
        rtt_micros: u32,
        rtt_variance_micros: u32,
        available_buffer_packets: u32,
        rate_feedback: Option<PeerRateFeedback>,
    ) {
        let rate_feedback = rate_feedback.or_else(|| {
            self.peer_feedback
                .and_then(|previous| previous.rate_feedback)
        });
        self.peer_feedback = Some(PeerFeedback {
            rtt_micros,
            rtt_variance_micros,
            available_buffer_packets,
            rate_feedback,
        });
        if rtt_micros > 0 {
            // Smooth with EWMA: RTT = 7/8 * RTT + 1/8 * sample -- the same
            // estimator `SrtReceiver::handle_ackack` uses for its own raw
            // samples. `rtt_micros` is an untrusted peer's raw `u32` ACK
            // field (any value is wire-legal), and multiplying an already
            // large smoothed estimate by 7 in `u32` can overflow -- a debug
            // panic, or a silent wraparound in release that corrupts the RTO
            // estimator with an artificially tiny value. Both terms are
            // widened to `u64` before combining; the combined average of two
            // `u32` values is always itself `<= u32::MAX`, so narrowing back
            // is exact, never truncating.
            let new_rtt = (7 * u64::from(self.sender_rtt_micros) + u64::from(rtt_micros)) / 8;
            self.sender_rtt_micros =
                u32::try_from(new_rtt).expect("EWMA average of two u32 values fits in u32");
            // RTTVar = 3/4 * RTTVar + 1/4 * |RTT - sample|, same widening
            // reasoning (`diff` is itself already bounded by `u32::MAX`).
            let diff = self.sender_rtt_micros.abs_diff(rtt_micros);
            let new_var = (3 * u64::from(self.sender_rtt_var_micros) + u64::from(diff)) / 4;
            self.sender_rtt_var_micros =
                u32::try_from(new_var).expect("EWMA average of two u32 values fits in u32");
        }
    }

    /// Drop expired messages (TLPKTDROP), replacing them with tombstones.
    ///
    /// Scans in sequence order from `oldest_unacked` toward `next_seq`. When
    /// an expired packet is found, every packet sharing its `message_number`
    /// becomes a tombstone together (SRT spec: "the entire message is
    /// dropped"). Returns one `DroppedMessage` per message dropped *in this
    /// call*, so the connection answers with DROPREQ once per drop.
    ///
    /// The tombstone keeps only what a repeated NAK needs; the media payload
    /// is released here. `oldest_unacked` deliberately does not advance: the
    /// peer has not acknowledged these sequences, and until it does they are
    /// what a repeated NAK is matched against. They retire on the cumulative
    /// ACK, exactly like live packets.
    pub fn drop_expired(&mut self, now: Timestamp) -> Vec<DroppedMessage> {
        let threshold = (self.latency_us * 125 / 100).max(1_000_000);

        let mut messages = Vec::new();
        let mut seq = self.oldest_unacked;
        while sequence_less_than(seq, self.next_seq) {
            match self.packets.get(seq) {
                Some(entry) => {
                    if entry.dropped {
                        seq = seq.wrapping_add(1) & 0x7FFF_FFFF;
                        continue;
                    }
                    let elapsed = now.as_micros().saturating_sub(entry.sent_time.as_micros());
                    if elapsed <= threshold {
                        break;
                    }
                    messages.push(self.drop_expired_message(&mut seq));
                }
                None => {
                    seq = seq.wrapping_add(1) & 0x7FFF_FFFF;
                }
            }
        }

        self.compact_stale_retransmits();

        messages
    }

    /// Turn one expired message into tombstones, reporting its range.
    fn drop_expired_message(&mut self, seq: &mut u32) -> DroppedMessage {
        let message_number = self
            .packets
            .get(*seq)
            .expect("expired message starts at a buffered packet")
            .message_number;
        let first_seq = *seq;
        let mut last_seq = first_seq;

        loop {
            let mut just_dropped = false;
            let mut was_live_submitted = false;
            let released_stamp = self.packets.get_mut(*seq).and_then(|entry| {
                if entry.dropped {
                    return None;
                }
                self.total_dropped = self.total_dropped.saturating_add(1);
                self.total_bytes_dropped = self
                    .total_bytes_dropped
                    .saturating_add(entry.payload.len() as u64);
                // The media is what occupancy is measured in; the sequence
                // identity is what the peer's repeated NAK is matched against.
                entry.payload = Bytes::new();
                was_live_submitted = entry.submitted;
                entry.dropped = true;
                just_dropped = true;
                // A tombstone is never transmitted again, so its key
                // generation is no longer a live dependency.
                entry.crypto_stamp.take()
            });
            if just_dropped {
                if let Some(stamp) = released_stamp {
                    self.count_retained_stamp(stamp.key_flag, false);
                }
                self.dropped_retained = self.dropped_retained.saturating_add(1);
                if was_live_submitted {
                    // This entry was still outstanding flight until now: the
                    // RTO estimator (`has_outstanding_submitted_data`) and
                    // any pending blind probe (`rto_probe_pending`) must stop
                    // treating it as such.
                    self.live_submitted_count = self.live_submitted_count.saturating_sub(1);
                }
                if self.packets.cancel_retransmit(*seq) {
                    // The queued loss-list entry is now answered by DROPREQ,
                    // not by a retransmission.
                    self.stale_retransmits += 1;
                }
                last_seq = *seq;
            }
            let next = seq.wrapping_add(1) & 0x7FFF_FFFF;
            if !sequence_less_than(next, self.next_seq) {
                *seq = next;
                break;
            }
            if self
                .packets
                .get(next)
                .is_some_and(|entry| entry.message_number == message_number)
            {
                *seq = next;
            } else {
                *seq = next;
                break;
            }
        }

        DroppedMessage {
            message_number,
            first_seq,
            last_seq,
        }
    }

    /// The inclusive sequence range of the tombstone run containing
    /// `sequence`, if that sequence is a tombstone of the given message.
    ///
    /// A dropped message's fragments stay contiguous in sequence space
    /// (fragments are assigned consecutively and nothing is renumbered), so
    /// expanding from the NAKed sequence recovers exactly the range DROPREQ
    /// must name -- no per-entry range storage, and no way for the range to
    /// drift from the window's own contents.
    fn tombstone_range(&self, sequence: u32, message_number: u32) -> Option<(u32, u32)> {
        #[cfg(test)]
        self.tombstone_range_calls
            .set(self.tombstone_range_calls.get().saturating_add(1));
        if self
            .packets
            .get(sequence)
            .is_none_or(|entry| !entry.dropped || entry.message_number != message_number)
        {
            return None;
        }
        let mut first = sequence;
        // Walk outward one sequence at a time, bounded by the retained span.
        let mut steps = 0u32;
        while steps < self.packets.window_size() {
            let candidate = first.wrapping_sub(1) & SEQUENCE_MASK;
            match self.packets.get(candidate) {
                Some(entry) if entry.dropped && entry.message_number == message_number => {
                    first = candidate;
                }
                _ => break,
            }
            steps += 1;
        }
        let mut last = sequence;
        steps = 0;
        while steps < self.packets.window_size() {
            let candidate = last.wrapping_add(1) & SEQUENCE_MASK;
            match self.packets.get(candidate) {
                Some(entry) if entry.dropped && entry.message_number == message_number => {
                    last = candidate;
                }
                _ => break,
            }
            steps += 1;
        }
        Some((first, last))
    }

    #[cfg(test)]
    fn tombstone_range_calls(&self) -> u32 {
        self.tombstone_range_calls.get()
    }

    /// Get the send time of the oldest packet in the buffer.
    pub fn oldest_packet_time(&self) -> Option<Timestamp> {
        self.packets
            .first_occupied_from(self.oldest_unacked)
            .map(|(_, e)| e.sent_time)
    }

    /// Number of pages currently allocated in the sender packet window.
    pub fn allocated_pages(&self) -> usize {
        self.packets.allocated_pages()
    }

    /// Total heap bytes owned by the sender packet window.
    pub fn sender_window_heap_bytes(&self) -> usize {
        self.packets.heap_bytes()
    }

    /// Get statistics.
    pub fn stats(&self) -> SenderStats {
        // Count by retransmit count. This is deliberately a live snapshot of
        // only packets currently in the buffer -- the distribution of "how
        // many times has each packet currently in the buffer been
        // retransmitted," a different metric from the cumulative total.
        let mut retransmits_once = 0u32;
        let mut retransmits_twice = 0u32;
        let mut retransmits_many = 0u32;
        // Accumulated in the histogram's own pass. The buffer runs to the
        // flow window (8192 packets by default) and this is sampled
        // periodically per connection, so a second walk of the same map is
        // a whole extra traversal per sample for one `sum()`.
        let mut payload_bytes_in_buffer = 0u64;
        for entry in self.packets.values() {
            payload_bytes_in_buffer += entry.payload.len() as u64;
            match entry.retransmit_count {
                1 => retransmits_once += 1,
                2 => retransmits_twice += 1,
                n if n >= 3 => retransmits_many += 1,
                _ => {}
            }
        }
        let oldest_time = self
            .packets
            .first_occupied_from(self.oldest_unacked)
            .map(|(_, e)| e.sent_time);
        let newest_time = self
            .packets
            .last_occupied_before(self.next_seq)
            .map(|(_, e)| e.sent_time);
        let buffer_span_micros = oldest_time.zip(newest_time).map_or(0, |(oldest, newest)| {
            newest.as_micros().saturating_sub(oldest.as_micros())
        });
        let peer = self.peer_feedback;

        SenderStats {
            packets_in_buffer: self.packets.len() as u32,
            payload_bytes_in_buffer,
            packets_in_loss_list: self.packets.retransmit_queued_count(),
            available_buffer_packets: self.remaining_window_packets(),
            available_buffer_bytes: None,
            flow_window_packets: self.negotiated_window,
            congestion_window_packets: self.negotiated_window,
            packets_in_flight: self.packets_in_flight(),
            buffer_span_micros,
            tsbpd_delay_micros: self.latency_us,
            packet_send_period_micros: self.packet_send_period,
            max_bandwidth_bytes_per_second: self.max_bandwidth_bytes_per_sec,
            peer_rtt_micros: peer.map(|feedback| feedback.rtt_micros),
            peer_rtt_variance_micros: peer.map(|feedback| feedback.rtt_variance_micros),
            peer_available_buffer_packets: peer.map(|feedback| feedback.available_buffer_packets),
            peer_receiving_rate_packets_per_second: peer
                .and_then(|feedback| feedback.rate_feedback)
                .map(|rate| rate.receiving_rate_packets_per_second),
            peer_link_capacity_packets_per_second: peer
                .and_then(|feedback| feedback.rate_feedback)
                .map(|rate| rate.link_capacity_packets_per_second),
            // Requires the peer's own measured bytes-per-packet (the
            // 28/32-byte byte-rate field): a 24-byte ACK's rate snapshot has
            // no such field, so there is nothing honest to derive here --
            // `None`, not a fabricated zero from treating the absent field
            // as 0.
            peer_link_capacity_bytes_per_second: peer
                .and_then(|feedback| feedback.rate_feedback)
                .and_then(|rate| {
                    let byte_rate = rate.receiving_rate_bytes_per_second?;
                    let packet_rate = u64::from(rate.receiving_rate_packets_per_second);
                    (packet_rate > 0).then(|| {
                        u64::from(rate.link_capacity_packets_per_second)
                            .saturating_mul(u64::from(byte_rate))
                            / packet_rate
                    })
                }),
            peer_receiving_rate_bytes_per_second: peer
                .and_then(|feedback| feedback.rate_feedback)
                .and_then(|rate| rate.receiving_rate_bytes_per_second),
            total_retransmits: self.total_retransmits,
            total_sent: self.total_sent,
            total_data_packets_sent: self.total_sent.saturating_add(self.total_retransmits),
            total_bytes_sent: self.total_bytes_sent,
            total_srt_bytes_sent: self.total_srt_bytes_sent,
            total_retransmitted_srt_bytes: self.total_retransmitted_srt_bytes,
            total_lost: self.total_lost,
            total_dropped: self.total_dropped,
            total_bytes_dropped: self.total_bytes_dropped,
            total_acks_received: self.total_acks_received,
            total_naks_received: self.total_naks_received,
            retransmits_once,
            retransmits_twice,
            retransmits_many,
        }
    }
}

/// Sender statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SenderStats {
    /// Number of packets in the buffer.
    pub packets_in_buffer: u32,
    /// Exact payload-byte occupancy of the local send buffer.
    pub payload_bytes_in_buffer: u64,
    /// Number of packets in the loss list.
    pub packets_in_loss_list: u32,
    /// Remaining local flow-window capacity, in packets.
    pub available_buffer_packets: u32,
    /// Byte capacity is unavailable because the send-buffer limit is packets.
    pub available_buffer_bytes: Option<u64>,
    /// Negotiated local flow window, in packets.
    pub flow_window_packets: u32,
    /// Current local congestion window, in packets.
    pub congestion_window_packets: u32,
    /// Packets sent but not yet cumulatively acknowledged.
    pub packets_in_flight: u32,
    /// Time span between oldest and newest buffered packets.
    pub buffer_span_micros: u64,
    /// Configured sender TSBPD delay.
    pub tsbpd_delay_micros: u64,
    /// Current pacing period between original packet sends.
    pub packet_send_period_micros: u64,
    /// Configured maximum pacing bandwidth.
    pub max_bandwidth_bytes_per_second: u64,
    /// RTT advertised by the peer's most recent compatible non-Light ACK
    /// feedback (any ACK size `validate_ack_shape` accepts that carries
    /// RTT/RTTVar/window: 16, 24, 28, or 32 bytes -- not only the draft's
    /// own 28-byte Full ACK).
    pub peer_rtt_micros: Option<u32>,
    /// RTT variance from the same feedback as `peer_rtt_micros`.
    pub peer_rtt_variance_micros: Option<u32>,
    /// Peer receive-buffer availability from the same feedback as
    /// `peer_rtt_micros`.
    pub peer_available_buffer_packets: Option<u32>,
    /// Peer receive rate from the most recent ACK that carried a rate
    /// section (24 bytes or larger). A 16-byte Small ACK carries no rate
    /// section at all, so it leaves this at whatever a previous
    /// rate-carrying ACK reported; `None` until the first one arrives.
    pub peer_receiving_rate_packets_per_second: Option<u32>,
    /// Peer link-capacity estimate, from the same rate-carrying ACK as
    /// `peer_receiving_rate_packets_per_second`.
    pub peer_link_capacity_packets_per_second: Option<u32>,
    /// Peer link-capacity estimate converted using its measured wire bytes
    /// per packet. `None` whenever `peer_receiving_rate_bytes_per_second`
    /// is `None` -- a 24-byte ACK's rate section has no byte-rate field to
    /// derive this from, and that absence is never backfilled with a
    /// fabricated zero or a stale value from an earlier 28-byte ACK.
    pub peer_link_capacity_bytes_per_second: Option<u64>,
    /// Peer byte receive rate. Only a 28/32-byte ACK carries this field;
    /// `None` if the most recent rate-carrying ACK was the 24-byte form (or
    /// no rate-carrying ACK has arrived yet), never a fabricated zero.
    pub peer_receiving_rate_bytes_per_second: Option<u32>,
    /// Total retransmit count.
    pub total_retransmits: u64,
    /// Unique original DATA packets emitted.
    pub total_sent: u64,
    /// All emitted DATA packets, including retransmissions.
    pub total_data_packets_sent: u64,
    /// Payload bytes in unique original DATA packets.
    pub total_bytes_sent: u64,
    /// All emitted SRT datagram bytes, including SRT headers and retransmissions.
    ///
    /// This deliberately excludes IP and UDP headers, which belong to the
    /// caller-owned transport and vary between IPv4 and IPv6.
    pub total_srt_bytes_sent: u64,
    /// Retransmitted SRT datagram bytes, including SRT headers.
    pub total_retransmitted_srt_bytes: u64,
    /// Packets declared lost by peer NAKs.
    pub total_lost: u64,
    /// Packets locally discarded after their TLPKTDROP deadline.
    pub total_dropped: u64,
    /// Payload bytes in locally discarded packets.
    pub total_bytes_dropped: u64,
    /// Valid ACK control packets received.
    pub total_acks_received: u64,
    /// NAK control packets received.
    pub total_naks_received: u64,
    /// Packets retransmitted once.
    pub retransmits_once: u32,
    /// Packets retransmitted twice.
    pub retransmits_twice: u32,
    /// Packets retransmitted 3 or more times.
    pub retransmits_many: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete rate snapshot, as only a 28/32-byte ACK can report.
    fn full_rate_feedback() -> Option<PeerRateFeedback> {
        Some(PeerRateFeedback {
            receiving_rate_packets_per_second: 1_000,
            link_capacity_packets_per_second: 2_000,
            receiving_rate_bytes_per_second: Some(1_500_000),
        })
    }

    fn dropped_seqs(messages: &[DroppedMessage]) -> Vec<u32> {
        let mut seqs = Vec::new();
        for m in messages {
            let mut s = m.first_seq;
            loop {
                seqs.push(s);
                if s == m.last_seq {
                    break;
                }
                s = s.wrapping_add(1) & 0x7FFF_FFFF;
            }
        }
        seqs
    }

    #[test]
    fn test_sender_buffer_new() {
        let buf = SenderBuffer::new(1000, 8192, 120);
        assert_eq!(buf.next_sequence_number(), 1000);
        assert!(buf.can_send());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_sender_buffer_push() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        let packet = buf.push(vec![1, 2, 3], 100, 12345, now);
        assert!(packet.is_some());
        let (hdr, _) = packet.expect("送信パケットは Some になる想定");
        assert_eq!(hdr.sequence_number, 1000);
        assert_eq!(buf.next_sequence_number(), 1001);
        assert_eq!(buf.packets_in_flight(), 1);
    }

    #[test]
    fn fragmented_message_is_all_or_nothing_at_window_boundary() {
        let mut buf = SenderBuffer::new(1000, 2, 120);
        let now = Timestamp::default();
        let before_sequence = buf.next_sequence_number();
        let before_message = buf.next_message_number();
        let packets = buf.push_message(&[7; 9], 4, 100, 1, now);
        assert!(packets.is_empty());
        assert_eq!(buf.packets_in_flight(), 0);
        assert_eq!(buf.next_sequence_number(), before_sequence);
        assert_eq!(buf.next_message_number(), before_message);
    }

    #[test]
    fn test_sender_buffer_ack() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        // 3 パケット送信
        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);

        assert_eq!(buf.packets_in_flight(), 3);

        // ACK 1002 = パケット 1000, 1001 を ACK
        buf.handle_ack(1002);
        assert_eq!(buf.packets_in_flight(), 1);
    }

    /// The receive-window credit regression: a Light ACK advances the
    /// cumulative acknowledgement but carries no advertisement, so the
    /// flight it acknowledges must not come back as fresh credit.
    ///
    /// Reference behaviour: libsrt debits its flow window by exactly the
    /// acknowledged progress on a lite ACK (`srtcore/core.cpp`
    /// `processCtrlAck`: `m_iFlowWindowSize -= CSeqNo::seqoff(m_iSndLastAck,
    /// ackdata_seqno)`), which is the same contract as Robotweax commit
    /// `09c852b4` ("Preserve receive-window credit across Lite ACKs"). Both
    /// keep the credit anchored at the cumulative position, i.e. exactly the
    /// absolute `ack_seq + advertised_free` boundary `peer_window_end`
    /// tracks. Before this change the stale advertisement was compared
    /// against a flight that an ACK had just shrunk, so the acknowledged
    /// slots were handed out a second time.
    #[test]
    fn light_ack_cannot_recycle_receive_window_credit() {
        let now = Timestamp::from_micros(0);
        let mut buf = SenderBuffer::new(1_000, 4, 120);
        assert_eq!(buf.peer_window_end(), 1_004);
        assert_eq!(buf.remaining_window_packets(), 4);

        // Receiver free window = 4: the whole advertised window is usable.
        for _ in 0..4 {
            assert!(buf.push(vec![1], 1, 1, now).is_some());
        }
        assert!(!buf.can_send(), "the advertised window is full");

        // All four delivered, and a Full ACK at 1004 advertising 4 free
        // reopens the window.
        buf.handle_ack(1_004);
        buf.set_peer_window(1_004, 4);
        assert_eq!(buf.remaining_window_packets(), 4);
        for _ in 0..4 {
            assert!(buf.push(vec![1], 1, 1, now).is_some());
        }
        assert!(!buf.can_send());

        // A Light ACK advances the cumulative ACK by two and advertises
        // nothing. The two packets it acknowledges are gone from the flight,
        // but the peer freed no receive space with them: the sender may send
        // nothing more until a Small/Full ACK says otherwise.
        buf.handle_ack(1_006);
        assert_eq!(buf.packets_in_flight(), 2);
        assert_eq!(buf.remaining_window_packets(), 0);
        assert!(!buf.can_send());
    }

    #[test]
    fn a_small_or_full_ack_reopens_exactly_what_it_advertises() {
        let now = Timestamp::from_micros(0);
        let mut buf = SenderBuffer::new(1_000, 4, 120);
        for _ in 0..4 {
            assert!(buf.push(vec![1], 1, 1, now).is_some());
        }
        // Two delivered, two still held: the advertised credit is what the
        // window reopens by, and no more.
        buf.handle_ack(1_002);
        buf.set_peer_window(1_002, 2);
        assert_eq!(buf.remaining_window_packets(), 0);

        buf.set_peer_window(1_004, 2);
        assert_eq!(buf.remaining_window_packets(), 2);
        assert!(buf.push(vec![1], 1, 1, now).is_some());
        assert!(buf.push(vec![1], 1, 1, now).is_some());
        assert!(!buf.can_send());
    }

    #[test]
    fn peer_window_end_wraps_at_the_31_bit_boundary() {
        let now = Timestamp::from_micros(0);
        let mut buf = SenderBuffer::new(0x7FFF_FFFE, 4, 120);
        // 0x7FFFF_FFE + 4 crosses 0x7FFF_FFFF into 0x0000_0002.
        assert_eq!(buf.peer_window_end(), 2);

        for _ in 0..4 {
            assert!(buf.push(vec![1], 1, 1, now).is_some());
        }
        assert_eq!(buf.next_sequence_number(), 2);
        assert!(
            !buf.can_send(),
            "the flight fills the window across the wrap"
        );

        // Three of the four are acknowledged across the wrap; a current
        // advertisement of four then leaves room for the remaining position.
        buf.handle_ack(1);
        buf.set_peer_window(1, 4);
        assert_eq!(buf.peer_window_end(), 5);
        assert_eq!(buf.remaining_window_packets(), 3);
        for _ in 0..3 {
            assert!(buf.push(vec![1], 1, 1, now).is_some());
        }
        assert_eq!(buf.next_sequence_number(), 5);
        assert!(!buf.can_send());
    }

    #[test]
    fn a_zero_advertisement_closes_new_data_but_not_retransmission() {
        let now = Timestamp::from_micros(0);
        let mut buf = SenderBuffer::new(0, 8, 120);
        buf.push_submitted(vec![1], 1, 1, now);
        buf.push_submitted(vec![2], 1, 1, now);
        buf.handle_nak(&[0]);

        // The receiver is full: cumulative ACK at 0, zero free space.
        buf.set_peer_window(0, 0);
        assert_eq!(buf.peer_window_end(), 0);
        assert_eq!(buf.remaining_window_packets(), 0);
        assert!(!buf.can_send());

        // Requested retransmission stays eligible while the window is shut
        // (libsrt exempts retransmissions from the flow-window gate the same
        // way, `core.cpp` `packACK`/`packUniqueData`).
        let (header, _) = buf
            .pop_retransmit(1)
            .expect("a NAKed packet is retransmitted despite the closed window");
        assert_eq!(header.sequence_number, 0);
    }

    #[test]
    fn an_oversized_advertisement_cannot_enlarge_the_negotiated_window() {
        let now = Timestamp::from_micros(0);
        let mut buf = SenderBuffer::new(1_000, 4, 120);
        buf.set_peer_window(1_000, u32::MAX);
        assert_eq!(buf.peer_window_end(), 1_004);
        assert_eq!(buf.remaining_window_packets(), 4);
        for _ in 0..4 {
            assert!(buf.push(vec![1], 1, 1, now).is_some());
        }
        assert!(!buf.can_send());
    }

    #[test]
    fn test_sender_buffer_nak() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        buf.push_submitted(vec![1], 100, 1, now);
        buf.push_submitted(vec![2], 100, 1, now);
        buf.push_submitted(vec![3], 100, 1, now);

        // パケット 1001 を損失報告
        buf.handle_nak(&[1001]);
        assert!(buf.has_retransmit());

        // 再送パケットを取得
        let retransmit = buf.pop_retransmit(1);
        assert!(retransmit.is_some());
        let (hdr, _) = retransmit.expect("再送パケットは Some になる想定");
        assert_eq!(hdr.sequence_number, 1001);
        assert!(hdr.retransmitted);
    }

    #[test]
    fn dense_and_wrapped_nak_ranges_queue_only_retained_packets() {
        let now = Timestamp::default();
        let mut dense = SenderBuffer::new(0, 8_192, 120);
        for sequence in 0..8_192 {
            assert!(
                dense
                    .push_submitted(vec![sequence as u8], 1, 1, now)
                    .is_some()
            );
        }
        dense
            .handle_nak_ranges(&[LossRange {
                first_seq: 0,
                last_seq: 8_191,
            }])
            .unwrap();
        assert_eq!(dense.stats().packets_in_loss_list, 8_192);
        for expected in 0..8_192 {
            assert_eq!(dense.pop_retransmit(1).unwrap().0.sequence_number, expected);
        }

        let mut wrapped = SenderBuffer::new(0x7FFF_FFFD, 8, 120);
        for _ in 0..6 {
            assert!(wrapped.push_submitted(vec![1], 1, 1, now).is_some());
        }
        wrapped
            .handle_nak_ranges(&[LossRange {
                first_seq: 0x7FFF_FFFE,
                last_seq: 1,
            }])
            .unwrap();
        let queued = std::iter::from_fn(|| wrapped.pop_retransmit(1))
            .map(|(header, _)| header.sequence_number)
            .collect::<Vec<_>>();
        assert_eq!(queued, [0x7FFF_FFFE, 0x7FFF_FFFF, 0, 1]);
    }

    /// S01: `push_with_sequence`/`push_shared_with_sequence` reject any
    /// sequence that doesn't equal `next_seq`, including immediately
    /// across the 31-bit wraparound boundary -- a plain equality check,
    /// so wrap-adjacent values need no special-casing, but must still be
    /// exercised since they are exactly where an off-by-one in the
    /// comparison would first show up.
    #[test]
    fn explicit_sequence_mismatch_near_wraparound_is_rejected_on_both_paths() {
        let now = Timestamp::default();
        let mut owned = SenderBuffer::new(0x7FFF_FFFF, 32, 120);
        assert!(
            owned.push_with_sequence(vec![1], 1, 1, now, 0).is_none(),
            "next_seq is 0x7FFFFFFF, not the post-wrap 0"
        );
        assert_eq!(
            owned.next_sequence_number(),
            0x7FFF_FFFF,
            "rejection leaves next_seq unchanged"
        );
        assert!(
            owned
                .push_with_sequence(vec![1], 1, 1, now, 0x7FFF_FFFF)
                .is_some(),
            "the actual next_seq is accepted"
        );
        assert_eq!(
            owned.next_sequence_number(),
            0,
            "accepted send wraps next_seq to 0"
        );

        let mut shared = SenderBuffer::new(0x7FFF_FFFF, 32, 120);
        let payload = Bytes::from_static(b"x");
        assert!(
            shared
                .push_shared_with_sequence(payload.clone(), 1, 1, now, 0)
                .is_none(),
            "shared path rejects the same pre-wrap mismatch"
        );
        assert_eq!(shared.next_sequence_number(), 0x7FFF_FFFF);
        assert!(
            shared
                .push_shared_with_sequence(payload, 1, 1, now, 0x7FFF_FFFF)
                .is_some()
        );
        assert_eq!(shared.next_sequence_number(), 0);
    }

    #[test]
    fn acked_stale_queue_entries_do_not_retransmit_or_hide_live_entries() {
        let mut buf = SenderBuffer::new(0, 32, 120);
        let now = Timestamp::default();
        for _ in 0..3 {
            buf.push_submitted(vec![1], 1, 1, now);
        }
        buf.handle_nak(&[0, 1]);
        buf.handle_ack(1);

        assert_eq!(buf.stats().packets_in_loss_list, 1);
        assert_eq!(buf.pop_retransmit(1).unwrap().0.sequence_number, 1);
        assert!(buf.pop_retransmit(1).is_none());
    }

    #[test]
    fn stale_slot_reuse_cannot_clear_a_new_retransmit() {
        let mut buf = SenderBuffer::new(0, 32, 120);
        let now = Timestamp::default();
        buf.push_submitted(vec![0], 1, 1, now);
        buf.handle_nak(&[0]);
        buf.handle_ack(1);
        // A cumulative ACK on its own releases the acknowledged flight but
        // grants no new credit; only a Small/Full advertisement moves the
        // peer's window end. Apply the same advertisement the connection
        // would, so the refill below is the refill a real peer's ACK allows.
        buf.set_peer_window(1, 32);
        for sequence in 1..=32 {
            assert!(
                buf.push_submitted(vec![sequence as u8], 1, 1, now)
                    .is_some()
            );
        }
        buf.handle_nak(&[32]);

        assert_eq!(buf.pop_retransmit(1).unwrap().0.sequence_number, 32);
        assert!(buf.pop_retransmit(1).is_none());
    }

    #[test]
    fn sequence_synchronization_rebases_retransmit_membership() {
        let mut buf = SenderBuffer::new(0, 32, 120);
        buf.push_submitted(vec![0], 1, 1, Timestamp::default());
        buf.handle_nak(&[0]);
        buf.handle_ack(1);
        assert!(buf.packets.is_empty());

        assert!(buf.synchronize_next_sequence_number(1_000));
        assert!(buf.loss_list.is_empty());
        assert_eq!(buf.stale_retransmits, 0);
        assert!(
            buf.push_submitted(vec![1], 1, 1, Timestamp::default())
                .is_some()
        );
        buf.handle_nak(&[1_000]);

        assert_eq!(buf.pop_retransmit(1).unwrap().0.sequence_number, 1_000);
    }

    #[test]
    fn tlpktdrop_clears_retransmit_membership() {
        let mut buf = SenderBuffer::new(0, 32, 10);
        buf.push_submitted(vec![1], 1, 1, Timestamp::default());
        buf.handle_nak(&[0]);

        assert_eq!(
            dropped_seqs(&buf.drop_expired(Timestamp::from_micros(1_000_001))),
            [0]
        );
        assert!(!buf.has_retransmit());
        assert!(buf.pop_retransmit(1).is_none());
    }

    #[test]
    fn sender_window_is_lazy_and_bounded_at_maximum_window() {
        let inline_bytes = size_of::<SenderBuffer>();
        let window = SenderPacketWindow::<SentPacket>::new(65_536);
        assert_eq!(window.allocated_pages(), 0);
        eprintln!("SenderBuffer inline bytes: {inline_bytes}");
        eprintln!(
            "maximum sender window directory bytes: {}",
            window.heap_bytes()
        );
        // The protocol-correctness pass added two counters (retained packets
        // per key generation, so a generation cannot be retired while one of
        // its packets still needs retransmitting) -- a deliberate, bounded
        // increase, not drift. A later pass added `dropreq_cursor` (widened
        // to `u16` to cover the full 65,536-position window) and
        // `live_submitted_count` (a `u32`, since that same window can hold
        // exactly that many outstanding entries) -- another deliberate,
        // bounded increase: both fix real correctness gaps (fair DROPREQ
        // service at full window size, and an RTO estimator that must not
        // keep treating a TLPKTDROP-tombstoned entry as outstanding flight).
        // A third pass added `justified_frontier` (a `u32`): another
        // deliberate, bounded increase fixing a real correctness gap (a
        // cumulative ACK must be justified by contiguous submission or
        // DROPREQ delivery, not merely by the highest sequence ever
        // submitted, which TLPKTDROP purging a queued-but-unsubmitted DATA
        // datagram could otherwise strand behind a hole).
        assert!(inline_bytes <= 344);
        assert_eq!(window.heap_bytes(), 8_320);
    }

    #[test]
    fn stale_retransmit_queue_is_compacted_at_a_bounded_threshold() {
        let mut buf = SenderBuffer::new(0, 2_048, 120);
        for _ in 0..2_048 {
            buf.push_submitted(vec![1], 1, 1, Timestamp::default());
        }
        buf.handle_nak(&(0..2_048).collect::<Vec<_>>());
        buf.handle_ack(2_048);

        assert!(buf.loss_list.is_empty());
        assert_eq!(buf.stale_retransmits, 0);
        assert!(!buf.has_retransmit());
    }

    /// `stats().total_retransmits` must stay accurate after the
    /// retransmitted packet is later ACKed and purged from `packets` --
    /// it used to be computed by summing `retransmit_count` across
    /// currently-buffered packets only, so a fast ACK (as happens at low
    /// RTT) made a
    /// successfully-recovered retransmission disappear from the stat
    /// entirely once its packet left the buffer.
    #[test]
    fn test_total_retransmits_survives_ack_purge() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        buf.push_submitted(vec![1], 100, 1, now);
        buf.push_submitted(vec![2], 100, 1, now);
        buf.push_submitted(vec![3], 100, 1, now);

        buf.handle_nak(&[1001]);
        let retransmit = buf.pop_retransmit(1);
        assert!(retransmit.is_some());
        assert_eq!(buf.stats().total_retransmits, 1);

        // ACK past every buffered packet, including the one just
        // retransmitted -- it is now fully purged from `packets`.
        buf.handle_ack(1003);
        assert_eq!(buf.packets_in_flight(), 0);

        // The retransmission genuinely happened; the stat must still say so.
        assert_eq!(buf.stats().total_retransmits, 1);
    }

    #[test]
    fn test_sequence_less_than() {
        assert!(sequence_less_than(100, 200));
        assert!(!sequence_less_than(200, 100));
        assert!(!sequence_less_than(100, 100));

        // ラップアラウンド
        assert!(sequence_less_than(0x7FFF_FFFE, 1));
    }

    #[test]
    fn test_packet_pacing() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);

        // 初期状態: パケットペーシングなし
        assert!(buf.can_send());
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(0)));
        assert_eq!(buf.time_until_send(Timestamp::from_micros(0)), 0);

        // パケット送信間隔を設定 (1000 マイクロ秒 = 1ms)
        buf.set_packet_send_period(1000);

        // 送信時刻を記録
        buf.record_send_time(Timestamp::from_micros(0));

        // 直後は送信不可
        assert!(buf.can_send()); // ウィンドウのみのチェックは可
        assert!(!buf.can_send_with_pacing(Timestamp::from_micros(500))); // ペーシングで不可
        assert_eq!(buf.time_until_send(Timestamp::from_micros(500)), 500);

        // 1000μs 後は送信可能
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(1000)));
        assert_eq!(buf.time_until_send(Timestamp::from_micros(1000)), 0);
    }

    /// Replaces `test_packet_pacing_after_late_wakeup_reschedules_full_period`,
    /// which asserted the defect: it required a wakeup 500us past the slot to
    /// push the next deadline to 2500 rather than 2000, so lateness was
    /// absorbed instead of repaid. Within one period the phase is now kept.
    #[test]
    fn pacing_sub_period_lateness_keeps_the_schedule_phase() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.record_send_time(Timestamp::from_micros(0));

        // Serviced 500us past the 1000us slot.
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(1500)));
        buf.record_send_time(Timestamp::from_micros(1500));

        // The slot after that is still 2000, not 2500: the ideal schedule did
        // not move, so the lateness is not paid for twice.
        assert!(!buf.can_send_with_pacing(Timestamp::from_micros(1999)));
        assert_eq!(buf.time_until_send(Timestamp::from_micros(1999)), 1);
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(2000)));
    }

    /// The defect's cumulative form, and the reason it was first-order rather
    /// than a rounding curiosity: a runtime that is consistently a little late
    /// used to lose that lateness on every single packet.
    ///
    /// 100 sends each serviced 300us past a 1000us slot must still occupy
    /// exactly 99 periods. The old rule rebased from the actual send time and
    /// produced a 1300us cadence, i.e. ~30ms of drift over this window and a
    /// 23% rate loss that never recovered.
    #[test]
    fn pacing_repeated_sub_period_lateness_does_not_accumulate_drift() {
        const PERIOD: u64 = 1000;
        const LATENESS: u64 = 300;
        const SENDS: u64 = 100;

        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(PERIOD);
        buf.record_send_time(Timestamp::from_micros(0));

        let mut sent_at = Vec::new();
        for slot in 1..=SENDS {
            let due = slot * PERIOD;
            // The deadline is exactly the ideal slot every time.
            assert_eq!(buf.time_until_send(Timestamp::from_micros(due - 1)), 1);
            let serviced = due + LATENESS;
            assert!(buf.can_send_with_pacing(Timestamp::from_micros(serviced)));
            buf.record_send_time(Timestamp::from_micros(serviced));
            sent_at.push(serviced);
        }

        let span = sent_at[sent_at.len() - 1] - sent_at[0];
        assert_eq!(
            span,
            (SENDS - 1) * PERIOD,
            "cadence drifted from the period"
        );
    }

    /// The preserve/rebase boundary is exclusive, and pinned on both sides:
    /// lateness strictly below one period keeps the phase, lateness of exactly
    /// one period or more rebases. Off-by-one here decides whether a caller
    /// can ever drain two packets at one instant.
    #[test]
    fn pacing_phase_boundary_is_exclusive_at_one_period() {
        const PERIOD: u64 = 1000;
        for (lateness, expected_due) in [(999u64, 2000u64), (1000, 3000), (1001, 3001)] {
            let mut buf = SenderBuffer::new(1000, 8192, 120);
            buf.set_packet_send_period(PERIOD);
            buf.record_send_time(Timestamp::from_micros(0));

            let serviced = PERIOD + lateness;
            buf.record_send_time(Timestamp::from_micros(serviced));

            assert!(
                !buf.can_send_with_pacing(Timestamp::from_micros(expected_due - 1)),
                "lateness {lateness}: eligible before {expected_due}"
            );
            assert!(
                buf.can_send_with_pacing(Timestamp::from_micros(expected_due)),
                "lateness {lateness}: not eligible at {expected_due}"
            );
        }
    }

    /// `record_sent_payload_size` recomputes `packet_send_period` from the IIR
    /// payload average during the push, so the period can change between the
    /// eligibility check and this bookkeeping. A shrinking period must not be
    /// able to place the next deadline at or before `now`, which would let a
    /// caller looping while eligible drain a burst.
    #[test]
    fn pacing_period_change_never_yields_a_deadline_in_the_past() {
        for (first, second, serviced, expected_due) in [
            // Shrink far below the elapsed lateness: rebase from now.
            (1000u64, 200u64, 1500u64, 1700u64),
            // Grow: the preserved phase is still ahead, so it is kept.
            (1000, 5000, 1500, 6000),
        ] {
            let mut buf = SenderBuffer::new(1000, 8192, 120);
            buf.set_packet_send_period(first);
            buf.record_send_time(Timestamp::from_micros(0));

            buf.set_packet_send_period(second);
            buf.record_send_time(Timestamp::from_micros(serviced));

            assert!(
                !buf.can_send_with_pacing(Timestamp::from_micros(serviced)),
                "{first}->{second}: immediately eligible again after the send"
            );
            assert!(buf.can_send_with_pacing(Timestamp::from_micros(expected_due)));
            assert!(!buf.can_send_with_pacing(Timestamp::from_micros(expected_due - 1)));
        }
    }

    /// Spec §5.1.2: PKT_SND_PERIOD is the minimum inter-packet interval,
    /// so an idle gap must be repaid at paced rate, not as an instant
    /// burst. After N periods of silence, exactly one packet may go
    /// immediately; each further send waits a full period from `now`.
    #[test]
    fn test_pacing_no_catch_up_burst_after_idle_gap() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);

        // Last send at t=0, then 10 periods of silence.
        buf.record_send_time(Timestamp::from_micros(0));
        let now = Timestamp::from_micros(10_000);

        assert!(buf.can_send_with_pacing(now));
        buf.record_send_time(now); // first resumed send

        // The next nine sends are spaced a full period apart - no burst.
        for expected in 1..=3u64 {
            let due = 10_000 + expected * 1000;
            assert!(!buf.can_send_with_pacing(Timestamp::from_micros(due - 1)));
            assert!(buf.can_send_with_pacing(Timestamp::from_micros(due)));
            buf.record_send_time(Timestamp::from_micros(due));
        }
    }

    /// Reference contract, verified against libsrt 1.5.3 (see
    /// `docs/perf/pacing-phase.md`): when the sender is serviced exactly on
    /// time, the emitted cadence is exactly the configured period. This holds
    /// before and after the phase-preservation change and pins the case that
    /// must not move.
    #[test]
    fn pacing_exact_service_holds_the_configured_period() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.record_send_time(Timestamp::from_micros(0));

        for slot in 1..=10u64 {
            let due = slot * 1000;
            assert!(!buf.can_send_with_pacing(Timestamp::from_micros(due - 1)));
            assert!(buf.can_send_with_pacing(Timestamp::from_micros(due)));
            buf.record_send_time(Timestamp::from_micros(due));
        }
    }

    /// Reference contract: after a genuine idle gap libsrt admits exactly one
    /// immediate packet and then resumes period spacing, independent of how
    /// long the gap was. Probed at gaps of 2, 10 and 50 periods against
    /// libsrt 1.5.3, all gap-independent.
    ///
    /// This is the property that forbids a catch-up burst, and it must survive
    /// any change to late-service handling.
    #[test]
    fn pacing_post_idle_resume_admits_exactly_one_immediate_packet() {
        for gap_periods in [2u64, 10, 50] {
            let mut buf = SenderBuffer::new(1000, 8192, 120);
            buf.set_packet_send_period(1000);
            buf.record_send_time(Timestamp::from_micros(0));

            let resume = gap_periods * 1000;
            assert!(buf.can_send_with_pacing(Timestamp::from_micros(resume)));
            buf.record_send_time(Timestamp::from_micros(resume));

            // Exactly one: the very next microsecond must already be refused,
            // however long the gap was.
            assert!(
                !buf.can_send_with_pacing(Timestamp::from_micros(resume + 1)),
                "gap of {gap_periods} periods admitted a second immediate packet"
            );
        }
    }

    /// Structural invariant behind "at most one immediate send": recording a
    /// send must never leave a deadline at or before the recorded instant, so
    /// a caller looping while eligible cannot drain a burst. Checked across
    /// on-time, sub-period-late and multi-period-late service.
    #[test]
    fn pacing_deadline_is_always_strictly_in_the_future() {
        for lateness in [0u64, 1, 300, 999, 1000, 1001, 9_999] {
            let mut buf = SenderBuffer::new(1000, 8192, 120);
            buf.set_packet_send_period(1000);
            buf.record_send_time(Timestamp::from_micros(0));

            let now = Timestamp::from_micros(1000 + lateness);
            assert!(buf.can_send_with_pacing(now));
            buf.record_send_time(now);
            assert!(
                !buf.can_send_with_pacing(now),
                "lateness {lateness} left the connection immediately eligible again"
            );
        }
    }

    /// Route B: while application demand remains, whole-period lateness is
    /// repaid so a frozen-`now` loop can emit the missed slots. Two periods
    /// late admits two packets at the same instant; the third waits.
    #[test]
    fn pacing_repays_whole_period_lateness_while_demand_remains() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.set_repay_pacing_debt(true);
        buf.record_send_time(Timestamp::from_micros(0));

        let now = Timestamp::from_micros(2500);
        let mut admitted = 0u32;
        while buf.can_send_with_pacing(now) {
            buf.record_send_time(now);
            admitted += 1;
            assert!(admitted <= 4, "repay unbounded at frozen now");
        }
        assert_eq!(admitted, 2);
        assert!(!buf.can_send_with_pacing(now));
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(3500)));
    }

    /// A long stall with demand still waiting must not drain every missed
    /// slot at one frozen `now` — that is an incast when many connections
    /// share a park. One extra packet per instant is the 600x8 lever
    /// (1.9 ms visits vs a 1.065 ms period); the rest waits for later visits.
    #[test]
    fn pacing_repay_is_bounded_to_one_extra_packet_per_instant() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.set_repay_pacing_debt(true);
        buf.record_send_time(Timestamp::from_micros(0));

        let now = Timestamp::from_micros(10_000);
        let mut admitted = 0u32;
        while buf.can_send_with_pacing(now) {
            buf.record_send_time(now);
            admitted += 1;
            assert!(admitted <= 4, "bounded repay unbounded at frozen now");
        }
        assert_eq!(admitted, 2);
    }

    /// Clearing demand after the queue empties must restore the idle-gap
    /// contract: leftover debt is discarded, so a later resume is one packet
    /// rather than a catch-up burst of the missed periods.
    #[test]
    fn pacing_discard_idle_debt_restores_one_immediate_packet() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.set_repay_pacing_debt(true);
        buf.record_send_time(Timestamp::from_micros(0));

        let catch_up = Timestamp::from_micros(2500);
        assert!(buf.can_send_with_pacing(catch_up));
        buf.record_send_time(catch_up);
        buf.discard_idle_pacing_debt(catch_up);

        assert!(
            !buf.can_send_with_pacing(catch_up),
            "idle discard left a past deadline"
        );

        let resume = Timestamp::from_micros(10_000);
        assert!(buf.can_send_with_pacing(resume));
        buf.record_send_time(resume);
        assert!(
            !buf.can_send_with_pacing(resume),
            "post-idle resume admitted a second immediate packet"
        );
    }

    /// Demand-off (the default) must still refuse a second packet after a
    /// multi-period gap; this is the same contract as
    /// `pacing_post_idle_resume_admits_exactly_one_immediate_packet`.
    #[test]
    fn pacing_demand_off_does_not_repay_an_idle_gap() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.record_send_time(Timestamp::from_micros(0));

        let now = Timestamp::from_micros(2500);
        let mut admitted = 0u32;
        while buf.can_send_with_pacing(now) {
            buf.record_send_time(now);
            admitted += 1;
            assert!(admitted <= 2, "idle path burst");
        }
        assert_eq!(admitted, 1);
    }

    /// Clearing the demand bit without discarding leftover debt leaves a
    /// deadline at `now` eligible — the remaining-pending path, so the next
    /// visit can still emit the extra packet.
    #[test]
    fn pacing_clearing_demand_without_discard_keeps_a_due_at_now() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.set_repay_pacing_debt(true);
        buf.record_send_time(Timestamp::from_micros(0));

        let now = Timestamp::from_micros(2500);
        assert!(buf.can_send_with_pacing(now));
        buf.record_send_time(now);
        buf.set_repay_pacing_debt(false);
        assert!(
            buf.can_send_with_pacing(now),
            "remaining demand lost the extra slot"
        );
    }

    #[test]
    fn test_packet_pacing_includes_srt_header_bytes() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_max_bandwidth(2_000_000);
        buf.record_send_time(Timestamp::from_micros(0));

        assert!(buf.time_until_send(Timestamp::from_micros(735)) > 0);
        assert_eq!(buf.time_until_send(Timestamp::from_micros(736)), 0);
    }

    #[test]
    fn input_bandwidth_reserves_configured_overhead_for_retransmission() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_input_bandwidth(1_000_000, 25);

        assert_eq!(buf.stats().max_bandwidth_bytes_per_second, 1_250_000);
        buf.record_send_time(Timestamp::from_micros(0));
        assert!(buf.time_until_send(Timestamp::from_micros(1177)) > 0);
        assert_eq!(buf.time_until_send(Timestamp::from_micros(1178)), 0);
    }

    #[test]
    fn test_handle_ack_wrap_around() {
        // BTreeMap の自然順とシーケンス番号順が一致しないラップアラウンド境界のテスト
        // take_while では途中で停止しラップ前のパケットが取りこぼされるが、
        // filter であれば全要素が巡回され正しく削除される
        let mut buf = SenderBuffer::new(0x7FFF_FFFD, 8192, 120);
        let now = Timestamp::from_micros(0);

        // 0x7FFF_FFFD, 0x7FFF_FFFE, 0x7FFF_FFFF (ラップ前)
        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);
        // 0, 1, 3 (ラップ後, 3 は ACK されずに残る)
        buf.push(vec![4], 100, 1, now);
        buf.push(vec![5], 100, 1, now);
        buf.push(vec![6], 100, 1, now);

        assert_eq!(buf.packets_in_flight(), 6);

        // ACK 2: 0, 1, 0x7FFF_FFFD, 0x7FFF_FFFE, 0x7FFF_FFFF が削除対象
        // BTreeMap 順: [0, 1, 3, 0x7FFF_FFFD, 0x7FFF_FFFE, 0x7FFF_FFFF]
        // take_while の場合: 0, 1 まで処理し 3 で停止 → ラップ前が残る
        // filter の場合: 全巡回 → ラップ前も削除される
        buf.handle_ack(2);
        assert_eq!(buf.packets_in_flight(), 1);
    }

    /// A sender whose peer has stopped ACKing must not grow without bound.
    ///
    /// This is the shape that produced 12 MB of resident memory *per
    /// connection* in the 600-connection bandwidth ladder: the receiver
    /// falls behind, ACKs dry up, `oldest_unacked` stops advancing, and the
    /// send buffer fills to the full flow window. TLPKTDROP is what is
    /// supposed to bound it -- the buffer should settle at roughly one
    /// drop-threshold worth of data (1 s floor), not at `flow_window`.
    #[test]
    fn buffer_stays_bounded_when_peer_stops_acking() {
        const BPS: u64 = 4_000_000;
        const PAYLOAD: usize = 1316;
        const FLOW_WINDOW: u32 = 8192;

        let mut buf = SenderBuffer::new(0, FLOW_WINDOW, 120);
        buf.set_max_bandwidth(BPS / 8);

        let mut high_water = 0u32;
        // 30 s of virtual time in 1 ms steps, never delivering an ACK.
        for ms in 0..30_000u64 {
            let now = Timestamp::from_micros(ms * 1000);
            while buf.can_send_with_pacing(now) {
                if buf.push(vec![0u8; PAYLOAD], ms as u32, 1, now).is_none() {
                    break;
                }
                buf.record_send_time(now);
            }
            // The ACK timer runs every 10 ms and is what drives TLPKTDROP.
            if ms % 10 == 0 {
                let _ = buf.drop_expired(now);
            }
            high_water = high_water.max(buf.packets_in_flight());
        }

        // One second of 4 Mbps is ~380 packets. Allow generous slack for the
        // 1.25x threshold and burst granularity, but nothing close to the
        // 8192-packet flow window.
        assert!(
            high_water < 2000,
            "send buffer reached {high_water} packets (flow window {FLOW_WINDOW}); \
             TLPKTDROP is not bounding it"
        );
    }

    #[test]
    fn test_drop_expired_threshold_1s_floor() {
        // latency_ms = 10 (10ms) の場合、1.25 * 10_000 = 12_500 < 1_000_000 なので
        // 閾値は 1_000_000 (1 秒) になる。
        let mut buf = SenderBuffer::new(0, 8192, 10);
        let send_time = Timestamp::from_micros(0);
        buf.push(vec![1], 100, 1, send_time);

        // elapsed = 1_000_000 は閾値と等しいので drop されない (> 判定)
        let now = Timestamp::from_micros(1_000_000);
        let dropped = buf.drop_expired(now);
        assert!(dropped.is_empty(), "等号では drop されないはず");

        // elapsed = 1_000_001 は閾値を超えるので drop される
        let now = Timestamp::from_micros(1_000_001);
        let dropped = buf.drop_expired(now);
        assert_eq!(
            dropped_seqs(&dropped),
            vec![0],
            "閾値超過で drop されるはず"
        );
    }

    /// TLPKTDROP age is the message's ORIGINAL send time. A retransmission --
    /// NAK-driven or the sender's own timeout probe -- must not push that
    /// deadline out, or recovery work would extend the life of data the
    /// receiver has already given up on.
    #[test]
    fn retransmission_does_not_extend_the_tlpktdrop_lifetime() {
        let mut buf = SenderBuffer::new(0, 8192, 10);
        let send_time = Timestamp::from_micros(0);
        buf.push(vec![1], 100, 1, send_time);
        assert_eq!(
            buf.note_data_submitted(0),
            RtoArm::Start,
            "first submission starts an epoch"
        );
        assert!(
            buf.queue_retransmission_of_newest_submitted().is_some(),
            "the probe queues the newest submitted packet"
        );

        // Unchanged deadline: not dropped at exactly one second (the `>` rule),
        // dropped one microsecond later, exactly as without the retransmission.
        assert!(
            buf.drop_expired(Timestamp::from_micros(1_000_000))
                .is_empty(),
            "a retransmission must not age the message"
        );
        assert_eq!(
            dropped_seqs(&buf.drop_expired(Timestamp::from_micros(1_000_001))),
            vec![0],
            "the original send time still decides TLPKTDROP"
        );
    }

    /// The three events a submission can be: the first one after an empty flight
    /// starts an epoch, an ordinary one while an epoch runs changes nothing, and
    /// the pending blind probe actually going out reprograms the epoch.
    #[test]
    fn submission_reports_which_rto_event_it_is() {
        let now = Timestamp::from_micros(0);
        let mut buf = SenderBuffer::new(0, 8192, 10);
        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);

        assert_eq!(buf.note_data_submitted(0), RtoArm::Start);
        // The connection arms the epoch when it sees `Start`; only then is there
        // a running epoch for an ordinary submission to leave alone.
        buf.rto_start();
        assert_eq!(
            buf.note_data_submitted(1),
            RtoArm::Nothing,
            "an ordinary submission must not restart a running epoch"
        );

        assert_eq!(buf.queue_retransmission_of_newest_submitted(), Some(1));
        buf.rto_set_probe_pending(1);
        assert_eq!(
            buf.note_data_submitted(0),
            RtoArm::Nothing,
            "a submission that is not the pending probe must not reprogram anything"
        );
        assert_eq!(
            buf.note_data_submitted(1),
            RtoArm::Rearm,
            "the pending probe crossing the submission boundary reprograms the epoch"
        );
    }

    #[test]
    fn test_drop_expired_threshold_125pct() {
        // latency_ms = 1000 (1000ms) の場合、1.25 * 1_000_000 = 1_250_000 > 1_000_000 なので
        // 閾値は 1_250_000 になる。
        let mut buf = SenderBuffer::new(0, 8192, 1000);
        let send_time = Timestamp::from_micros(0);
        buf.push(vec![1], 100, 1, send_time);

        // elapsed = 1_250_000 は閾値と等しいので drop されない (> 判定)
        let now = Timestamp::from_micros(1_250_000);
        let dropped = buf.drop_expired(now);
        assert!(dropped.is_empty(), "等号では drop されないはず");

        // elapsed = 1_250_001 は閾値を超えるので drop される
        let now = Timestamp::from_micros(1_250_001);
        let dropped = buf.drop_expired(now);
        assert_eq!(
            dropped_seqs(&dropped),
            vec![0],
            "閾値超過で drop されるはず"
        );
    }

    #[test]
    fn test_drop_expired_threshold_boundary() {
        // latency_ms = 800 の場合、1.25 * 800_000 = 1_000_000 = max(1_000_000, 1_000_000) = 1_000_000
        // 閾値はちょうど 1_000_000 になる (1 秒下限と 1.25 倍側の境界)。
        let mut buf = SenderBuffer::new(0, 8192, 800);
        let send_time = Timestamp::from_micros(0);
        buf.push(vec![1], 100, 1, send_time);

        // elapsed = 1_000_000 は閾値と等しいので drop されない
        let now = Timestamp::from_micros(1_000_000);
        let dropped = buf.drop_expired(now);
        assert!(dropped.is_empty(), "境界値の等号では drop されないはず");

        // elapsed = 1_000_001 は閾値を超えるので drop される
        let now = Timestamp::from_micros(1_000_001);
        let dropped = buf.drop_expired(now);
        assert_eq!(
            dropped_seqs(&dropped),
            vec![0],
            "境界値の超過で drop されるはず"
        );
    }

    #[test]
    fn test_retransmit_does_not_postpone_tlpktdrop() {
        // 回帰テスト: pop_retransmit が sent_time を今の時刻へ書き換えて
        // いた頃は、再送を繰り返すパケットが TLPKTDROP の対象から永遠に
        // 逃れられてしまっていた (libsrt の m_tsOriginTime は再送では
        // 更新されない -- 参照: pop_retransmit のドキュメント)。
        let mut buf = SenderBuffer::new(0, 8192, 10); // 閾値は 1 秒床
        let send_time = Timestamp::from_micros(0);
        buf.push_submitted(vec![1], 100, 1, send_time);

        buf.handle_nak(&[0]);
        // 元の送信からほぼ 1 秒経った時点で再送を試みる。
        let retransmitted = buf.pop_retransmit(1);
        assert!(retransmitted.is_some());

        // 元の送信から 1_000_001us -- 再送直後からはまだ 100_001us しか
        // 経っていないが、TLPKTDROP は元の送信時刻を基準にするべき。
        let now = Timestamp::from_micros(1_000_001);
        let dropped = buf.drop_expired(now);
        assert_eq!(
            dropped_seqs(&dropped),
            vec![0],
            "再送しても元の送信時刻基準の期限切れ判定は変わらないはず"
        );
    }

    #[test]
    fn test_drop_expired_advances_oldest_unacked_like_handle_ack() {
        // drop_expired は handle_ack と同じ「まだ生きている先頭パケット」
        // 境界を共有するべき -- 片方だけが進むと、その境界より前に穴が
        // 残ってしまう。
        let mut buf = SenderBuffer::new(0, 8192, 10);
        buf.push(vec![1], 100, 1, Timestamp::from_micros(0));
        buf.push(vec![2], 100, 1, Timestamp::from_micros(0));
        buf.push(vec![3], 100, 1, Timestamp::from_micros(2_000_000));

        // 先頭 2 パケットだけ期限切れ、3 番目はまだ新しい。
        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped_seqs(&dropped), vec![0, 1]);
        assert_eq!(buf.packets_in_flight(), 1);

        // ACK 2 は既に drop_expired で消えた分をカバーするだけの no-op に
        // なるはずで、seq=2 (まだ生きている) には影響しない。
        buf.handle_ack(2);
        assert_eq!(buf.packets_in_flight(), 1);

        // seq=2 (シーケンス番号としては 2) を最終的に ACK すれば空になる。
        buf.handle_ack(3);
        assert_eq!(buf.packets_in_flight(), 0);
        assert!(buf.is_empty());
    }

    /// A TLPKTDROP drop keeps the sequence identity (so a repeated NAK is
    /// still answered) and releases the media.
    #[test]
    fn a_dropped_packet_leaves_a_tombstone_until_the_ack() {
        let now = Timestamp::default();
        let mut buf = SenderBuffer::new(0, 32, 10);
        buf.push_submitted(vec![1; 100], 1, 1, now)
            .expect("admitted");

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len(), 1);
        assert_eq!((dropped[0].first_seq, dropped[0].last_seq), (0, 0));
        assert_eq!(buf.retained_span(), 1, "the tombstone still holds span");
        assert_eq!(buf.packets_in_flight(), 0, "but no flight credit");
        let stats = buf.stats();
        assert_eq!(stats.payload_bytes_in_buffer, 0, "the media is released");
        assert_eq!(stats.total_bytes_dropped, 100);
        assert_eq!(stats.total_dropped, 1);

        // A repeated NAK for the dropped sequence is answered with DROPREQ
        // again -- the peer either lost the first one or has not removed the
        // range yet -- and never with a retransmission of released media.
        let repeated = buf
            .handle_nak_ranges(&[LossRange {
                first_seq: 0,
                last_seq: 0,
            }])
            .unwrap();
        assert_eq!(repeated.len(), 1);
        assert_eq!((repeated[0].first_seq, repeated[0].last_seq), (0, 0));
        assert_eq!(buf.stats().packets_in_loss_list, 0);
        assert!(buf.pop_retransmit(1).is_none());

        // The cumulative ACK is what retires it.
        buf.handle_ack(1);
        assert_eq!(buf.retained_span(), 0);
        assert!(buf.can_send());
    }

    /// `submitted` is a historical fact: a peer that already received a
    /// sequence's DATA does not forget it just because TLPKTDROP later
    /// turns the same retained entry into a tombstone. The justified
    /// frontier must advance through such an entry on `submitted` alone,
    /// without waiting for its (separately queued) DROPREQ to also be
    /// notified.
    #[test]
    fn justified_frontier_survives_tlpktdrop_of_an_already_submitted_entry() {
        let now = Timestamp::default();
        let mut buf = SenderBuffer::new(0, 32, 10);
        buf.push_submitted(vec![1], 1, 1, now).expect("admitted");
        assert_eq!(
            buf.max_justified_ack_position(),
            1,
            "submission alone justifies it"
        );

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len(), 1, "the same entry is now also a tombstone");
        assert_eq!(
            buf.max_justified_ack_position(),
            1,
            "TLPKTDROP tombstoning an already-submitted entry must not un-justify it"
        );
    }

    /// A fragmented message drops as one unit and expands back to its whole
    /// range from any NAKed fragment inside it.
    #[test]
    fn a_dropped_fragmented_message_expands_from_any_fragment() {
        let now = Timestamp::default();
        let mut buf = SenderBuffer::new(0, 32, 10);
        buf.push_message(&[0u8; 10], 4, 1, 1, now);
        assert_eq!(buf.retained_span(), 3, "10 bytes in 4-byte fragments");

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len(), 1, "one drop per message");
        assert_eq!((dropped[0].first_seq, dropped[0].last_seq), (0, 2));

        // The message number is shared by every fragment, so naming the
        // middle one recovers the whole DROPREQ range.
        let repeated = buf
            .handle_nak_ranges(&[LossRange {
                first_seq: 1,
                last_seq: 1,
            }])
            .unwrap();
        assert_eq!(repeated.len(), 1);
        assert_eq!((repeated[0].first_seq, repeated[0].last_seq), (0, 2));
        assert_eq!(repeated[0].message_number, dropped[0].message_number);

        // And one cumulative ACK retires all three tombstones.
        buf.handle_ack(3);
        assert_eq!(buf.retained_span(), 0);
    }

    #[test]
    fn tombstones_survive_sequence_wrap_and_retire_on_the_ack() {
        let now = Timestamp::default();
        let mut buf = SenderBuffer::new(0x7FFF_FFFE, 32, 10);
        for _ in 0..3 {
            buf.push_submitted(vec![7], 1, 1, now).expect("admitted");
        }
        assert_eq!(buf.next_sequence_number(), 1);

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len(), 3);
        assert_eq!(buf.retained_span(), 3);

        // A range that crosses 0x7FFF_FFFF -> 0 names two of the three
        // dropped messages (each `push` is its own message), so each gets its
        // own DROPREQ.
        let across_the_wrap = buf
            .handle_nak_ranges(&[LossRange {
                first_seq: 0x7FFF_FFFE,
                last_seq: 0x7FFF_FFFF,
            }])
            .unwrap();
        assert_eq!(across_the_wrap.len(), 2);
        assert_eq!(
            across_the_wrap
                .iter()
                .map(|message| (message.first_seq, message.last_seq))
                .collect::<Vec<_>>(),
            [(0x7FFF_FFFE, 0x7FFF_FFFE), (0x7FFF_FFFF, 0x7FFF_FFFF)]
        );
        let past_the_wrap = buf
            .handle_nak_ranges(&[LossRange {
                first_seq: 0,
                last_seq: 0,
            }])
            .unwrap();
        assert_eq!(past_the_wrap.len(), 1);
        assert_eq!(past_the_wrap[0].first_seq, 0);

        // The ACK that crosses the wrap retires every tombstone.
        buf.handle_ack(1);
        assert_eq!(buf.retained_span(), 0);
        assert_eq!(buf.packets_in_flight(), 0);
    }

    /// Worst case: every retained position becomes a tombstone. Memory stays
    /// where it was, and the window backpressures instead of growing.
    #[test]
    fn an_all_tombstone_window_stays_bounded_and_backpressures() {
        let now = Timestamp::default();
        const WINDOW: u32 = 32;
        let mut buf = SenderBuffer::new(0, WINDOW, 10);
        for _ in 0..WINDOW {
            buf.push_submitted(vec![1; 64], 1, 1, now)
                .expect("admitted");
        }
        let allocated_before = buf.allocated_pages();
        let heap_before = buf.sender_window_heap_bytes();

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len() as u32, WINDOW, "one drop per message");
        assert_eq!(buf.retained_span(), WINDOW);
        assert_eq!(buf.packets_in_flight(), 0);
        assert_eq!(buf.stats().payload_bytes_in_buffer, 0);
        // One report cannot be amplified without bound: the DROPREQ batch is
        // capped, and repeating the request produces the same bounded work.
        let answered = buf
            .handle_nak_ranges(&[LossRange {
                first_seq: 0,
                last_seq: WINDOW - 1,
            }])
            .unwrap();
        assert_eq!(answered.len(), MAX_DROPREQ_PER_NAK);
        assert_eq!(
            buf.handle_nak_ranges(&[LossRange {
                first_seq: 0,
                last_seq: WINDOW - 1,
            }])
            .unwrap()
            .len(),
            MAX_DROPREQ_PER_NAK
        );

        // No room for new DATA until the peer acknowledges: the span bound is
        // what the window has instead of an unbounded tombstone list.
        assert!(!buf.can_send());
        assert!(buf.push(vec![1], 1, 1, now).is_none());
        assert_eq!(buf.allocated_pages(), allocated_before);
        assert_eq!(buf.sender_window_heap_bytes(), heap_before);

        // The ACK retires every tombstone. It does not by itself grant new
        // credit -- that is the advertised window's job (see
        // `light_ack_cannot_recycle_receive_window_credit`).
        buf.handle_ack(WINDOW);
        assert_eq!(buf.retained_span(), 0);
        assert!(!buf.can_send());
        buf.set_peer_window(WINDOW, 32);
        assert!(buf.can_send(), "the advertised window reopens the flight");
    }

    /// A NAK range spanning more tombstoned messages than
    /// `MAX_DROPREQ_PER_NAK` allows must not stall on the same lexically
    /// first messages forever: repeating the identical NAK has to eventually
    /// serve every tombstone, not just the first 16 every time.
    #[test]
    fn a_repeated_broad_nak_fairly_serves_every_tombstone_over_time() {
        let now = Timestamp::default();
        const MESSAGES: u32 = 17;
        let mut buf = SenderBuffer::new(0, MESSAGES + 8, 10);
        for _ in 0..MESSAGES {
            buf.push_submitted(vec![1], 1, 1, now).expect("admitted");
        }
        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len() as u32, MESSAGES, "one tombstone per message");

        let mut ever_served: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for _ in 0..(MESSAGES as usize).div_ceil(MAX_DROPREQ_PER_NAK) + 1 {
            let served = buf
                .handle_nak_ranges(&[LossRange {
                    first_seq: 0,
                    last_seq: MESSAGES - 1,
                }])
                .unwrap();
            assert_eq!(
                served.len(),
                MAX_DROPREQ_PER_NAK,
                "the anti-amplification cap still holds every round"
            );
            ever_served.extend(served.iter().map(|msg| msg.first_seq));
        }
        assert_eq!(
            ever_served.len() as u32,
            MESSAGES,
            "every tombstoned message must eventually be represented by a DROPREQ"
        );
    }

    /// The same fairness property at a scale that would have overflowed the
    /// round-robin cursor's original `u8` representation (256 tombstones):
    /// 300 one-packet tombstoned messages must all eventually be served,
    /// not just the first 256.
    #[test]
    fn a_repeated_broad_nak_fairly_serves_three_hundred_tombstones() {
        let now = Timestamp::default();
        const MESSAGES: u32 = 300;
        let mut buf = SenderBuffer::new(0, MESSAGES + 64, 10);
        for _ in 0..MESSAGES {
            buf.push_submitted(vec![1], 1, 1, now).expect("admitted");
        }
        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len() as u32, MESSAGES, "one tombstone per message");

        let mut ever_served: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for _ in 0..(MESSAGES as usize).div_ceil(MAX_DROPREQ_PER_NAK) + 1 {
            let served = buf
                .handle_nak_ranges(&[LossRange {
                    first_seq: 0,
                    last_seq: MESSAGES - 1,
                }])
                .unwrap();
            assert_eq!(served.len(), MAX_DROPREQ_PER_NAK);
            ever_served.extend(served.iter().map(|msg| msg.first_seq));
        }
        assert_eq!(
            ever_served.len() as u32,
            MESSAGES,
            "every one of 300 tombstoned messages must eventually be served"
        );
    }

    /// A NAK naming a single heavily fragmented tombstoned message must walk
    /// that run exactly once, not once per requested position inside it.
    /// Before the `known_run` cache in `validate_loss_range`, a NAK spanning
    /// an M-packet dropped message called `tombstone_range` (itself O(run
    /// length)) M times, making one control datagram cost O(M^2).
    #[test]
    fn a_nak_spanning_one_huge_fragmented_tombstone_walks_the_run_once() {
        let now = Timestamp::default();
        const FRAGMENTS: u32 = 20_000;
        let mut buf = SenderBuffer::new(0, FRAGMENTS + 64, 10);
        let payload = vec![0u8; FRAGMENTS as usize];
        let pushed = buf.push_message(&payload, 1, 1, 1, now);
        assert_eq!(pushed.len() as u32, FRAGMENTS);
        for (header, _) in &pushed {
            buf.note_data_submitted(header.sequence_number);
        }

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len(), 1, "one drop for the whole message");
        assert_eq!(dropped[0].first_seq, 0);
        assert_eq!(dropped[0].last_seq, FRAGMENTS - 1);

        let calls_before = buf.tombstone_range_calls();
        let served = buf
            .handle_nak_ranges(&[LossRange {
                first_seq: 0,
                last_seq: FRAGMENTS - 1,
            }])
            .unwrap();
        assert_eq!(
            served.len(),
            1,
            "one DROPREQ for the one tombstoned message"
        );
        assert_eq!(
            buf.tombstone_range_calls() - calls_before,
            1,
            "the whole run must be discovered with exactly one tombstone_range walk, \
             not one per requested position inside it"
        );
    }

    /// The same amortized cost holds for many distinct one-packet
    /// tombstones named by one broad NAK: `tombstone_range` runs exactly
    /// once per distinct tombstoned message, never re-walking one already
    /// discovered by an earlier position in the same report.
    #[test]
    fn a_nak_spanning_many_one_packet_tombstones_walks_each_run_once() {
        let now = Timestamp::default();
        const MESSAGES: u32 = 5_000;
        let mut buf = SenderBuffer::new(0, MESSAGES + 64, 10);
        for _ in 0..MESSAGES {
            buf.push_submitted(vec![1], 1, 1, now).expect("admitted");
        }
        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len() as u32, MESSAGES);

        let calls_before = buf.tombstone_range_calls();
        let _ = buf.handle_nak_ranges(&[LossRange {
            first_seq: 0,
            last_seq: MESSAGES - 1,
        }]);
        assert_eq!(
            buf.tombstone_range_calls() - calls_before,
            MESSAGES,
            "each one-packet tombstone must be discovered exactly once"
        );
    }

    /// A peer loss report is applied whole or not at all.
    #[test]
    fn a_nak_is_applied_whole_or_not_at_all() {
        let now = Timestamp::default();
        let mut buf = SenderBuffer::new(0, 32, 120);
        for _ in 0..4 {
            buf.push_submitted(vec![1], 1, 1, now).expect("admitted");
        }

        // Valid prefix, impossible tail: the whole report is rejected, and
        // the valid-looking prefix leaves no retransmission behind.
        let rejected = buf.handle_nak_ranges(&[
            LossRange {
                first_seq: 0,
                last_seq: 0,
            },
            LossRange {
                first_seq: 1_000,
                last_seq: 1_000,
            },
        ]);
        assert!(rejected.is_err());
        assert_eq!(buf.stats().packets_in_loss_list, 0);
        assert!(buf.pop_retransmit(1).is_none());

        // A position this sender accepted but never transmitted is not a loss
        // a peer could have observed.
        buf.push(vec![9], 1, 1, now);
        let rejected = buf.handle_nak_ranges(&[LossRange {
            first_seq: 4,
            last_seq: 4,
        }]);
        assert!(rejected.is_err());
        assert_eq!(buf.stats().packets_in_loss_list, 0);

        // A live, transmitted position is retransmitted.
        let dropped = buf
            .handle_nak_ranges(&[LossRange {
                first_seq: 2,
                last_seq: 2,
            }])
            .unwrap();
        assert!(dropped.is_empty());
        assert_eq!(buf.pop_retransmit(1).expect("queued").0.sequence_number, 2);

        // A repeated valid report is idempotent.
        let _ = buf.handle_nak_ranges(&[LossRange {
            first_seq: 1,
            last_seq: 1,
        }]);
        let queued = buf.stats().packets_in_loss_list;
        let _ = buf.handle_nak_ranges(&[LossRange {
            first_seq: 1,
            last_seq: 1,
        }]);
        assert_eq!(buf.stats().packets_in_loss_list, queued);

        // A report that names more positions than the negotiated window is
        // impossible, not merely large.
        let rejected = buf.handle_nak_ranges(&[LossRange {
            first_seq: 0,
            last_seq: 1 << 20,
        }]);
        assert!(rejected.is_err());
    }

    /// A range crossing the 31-bit wrap is valid where it is logically inside
    /// the window.
    #[test]
    fn a_nak_range_that_crosses_the_wrap_is_valid() {
        let now = Timestamp::default();
        let mut buf = SenderBuffer::new(0x7FFF_FFFE, 32, 120);
        for _ in 0..3 {
            buf.push_submitted(vec![1], 1, 1, now).expect("admitted");
        }

        let dropped = buf
            .handle_nak_ranges(&[LossRange {
                first_seq: 0x7FFF_FFFF,
                last_seq: 0,
            }])
            .unwrap();
        assert!(dropped.is_empty());
        assert_eq!(buf.stats().packets_in_loss_list, 2);
        assert_eq!(
            buf.pop_retransmit(1).expect("queued").0.sequence_number,
            0x7FFF_FFFF
        );
        assert_eq!(buf.pop_retransmit(1).expect("queued").0.sequence_number, 0);
    }

    #[test]
    fn telemetry_counts_loss_retransmit_and_exact_srt_bytes() {
        let mut buf = SenderBuffer::new(10, 32, 10);
        buf.push_submitted(vec![1, 2, 3, 4], 0, 1, Timestamp::from_micros(0));

        buf.handle_nak(&[10]);
        buf.handle_nak(&[10]);
        let stats = buf.stats();
        assert_eq!(stats.total_naks_received, 2);
        assert_eq!(stats.total_lost, 1, "a queued loss is not counted twice");
        assert_eq!(stats.total_srt_bytes_sent, 20);

        assert!(buf.pop_retransmit(1).is_some());
        let stats = buf.stats();
        assert_eq!(stats.total_retransmits, 1);
        assert_eq!(stats.total_retransmitted_srt_bytes, 20);
        assert_eq!(stats.total_srt_bytes_sent, 40);
        assert_eq!(stats.total_data_packets_sent, 2);

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped_seqs(&dropped), vec![10]);
        let stats = buf.stats();
        assert_eq!(stats.total_dropped, 1);
        assert_eq!(stats.total_bytes_dropped, 4);
        assert_eq!(stats.payload_bytes_in_buffer, 0);
    }

    #[test]
    fn drop_expired_drops_entire_message() {
        let mut buf = SenderBuffer::new(0, 8192, 10);
        let now = Timestamp::from_micros(0);
        let packets = buf.push_message(&[0xAB; 3000], 1400, 100, 1, now);
        assert_eq!(packets.len(), 3);

        // A fresh packet that should survive.
        buf.push(vec![99], 200, 1, Timestamp::from_micros(2_000_000));

        let dropped = buf.drop_expired(Timestamp::from_micros(1_000_001));
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].message_number, 1);
        assert_eq!(dropped[0].first_seq, 0);
        assert_eq!(dropped[0].last_seq, 2);
        assert_eq!(buf.packets_in_flight(), 1);
    }

    #[test]
    fn push_message_with_zero_payload_limit_fails_closed() {
        let mut buf = SenderBuffer::new(0, 32, 10);
        let packets = buf.push_message(b"application supplied data", 0, 0, 1, Timestamp::default());
        assert!(packets.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn telemetry_retains_latest_full_ack_feedback() {
        let mut buf = SenderBuffer::new(0, 64, 120);
        buf.record_peer_feedback(5_000, 500, 60, full_rate_feedback());

        let stats = buf.stats();
        assert_eq!(stats.peer_rtt_micros, Some(5_000));
        assert_eq!(stats.peer_available_buffer_packets, Some(60));
        assert_eq!(stats.peer_link_capacity_bytes_per_second, Some(3_000_000));
    }

    /// SRT draft §4.10: the RTO's RTT input is this sender's own smoothed
    /// estimate, with the peer's report folded in as one sample -- never a
    /// direct replacement. `stats().peer_rtt_micros` (telemetry) reflects the
    /// raw report immediately; `rto_base_timeout_micros()` must not.
    #[test]
    fn sender_rtt_is_smoothed_not_replaced_by_raw_peer_feedback() {
        let mut buf = SenderBuffer::new(0, 64, 120);
        assert_eq!(
            buf.rto_base_timeout_micros(),
            SenderRto::base_timeout_micros(None),
            "before any compatible ACK feedback, the RTO base uses the same initial constants"
        );

        buf.record_peer_feedback(20_000, 1_000, 60, full_rate_feedback());
        assert_eq!(
            buf.stats().peer_rtt_micros,
            Some(20_000),
            "telemetry keeps the raw, unsmoothed report"
        );
        // One report must not overwrite the sender's own estimate outright:
        // a sudden change moves the variance term first (correctly, per
        // Jacobson's algorithm, that alone can widen the timeout before it
        // narrows), so the only property checked here is that it is not the
        // same value a direct substitution would produce.
        let after_one = buf.rto_base_timeout_micros();
        assert_ne!(
            after_one,
            SenderRto::base_timeout_micros(Some((20_000, 1_000))),
            "one report must not overwrite the sender's own estimate outright"
        );

        // Repeated identical RTT reports converge the sender's own RTT
        // estimate toward what the peer keeps reporting (20 ms), and its
        // variance estimate toward zero (the reported RTT never varies) --
        // note the peer's reported `rtt_variance_micros` is deliberately not
        // itself part of the input; the draft derives variance from the RTT
        // residual, not by taking the peer's own variance figure directly.
        // The base timeout should settle near `rtt + 2*SYN = 40 ms`.
        for _ in 0..50 {
            buf.record_peer_feedback(20_000, 1_000, 60, full_rate_feedback());
        }
        let converged = buf.rto_base_timeout_micros();
        assert!(
            (35_000..=45_000).contains(&converged),
            "converged={converged} must settle near 40 ms (20 ms RTT + 2x10 ms SYN, \
             variance driven toward 0 by the constant reported RTT)"
        );
    }

    /// An untrusted peer's ACK RTT/RTTVar feedback is a raw `u32` field --
    /// any value is wire-legal. Repeatedly feeding values near `u32::MAX`
    /// must never overflow the EWMA arithmetic (a debug/Miri panic, or a
    /// silent release-mode wraparound that corrupts the estimator with an
    /// artificially tiny value), and the resulting RTO base timeout must
    /// stay bounded by `MAX_RTO_MICROS` throughout.
    #[test]
    fn rtt_ewma_never_overflows_on_near_u32_max_peer_feedback() {
        let mut buf = SenderBuffer::new(0, 64, 120);
        for _ in 0..8 {
            buf.record_peer_feedback(u32::MAX - 1, u32::MAX - 1, 60, full_rate_feedback());
            let timeout = buf.rto_base_timeout_micros();
            assert!(
                timeout <= crate::sender_rto::MAX_RTO_MICROS,
                "RTO base timeout {timeout} must stay bounded by MAX_RTO_MICROS"
            );
        }
        assert!(
            buf.rto_base_timeout_micros() >= 1_000_000,
            "a near-u32::MAX RTT report must drive the estimate up, not wrap it to something tiny"
        );

        // A subsequent run of small, legitimate reports must still be able
        // to pull the (now very large) estimate back down through the same
        // overflow-safe arithmetic.
        for _ in 0..200 {
            buf.record_peer_feedback(20_000, 1_000, 60, full_rate_feedback());
        }
        let recovered = buf.rto_base_timeout_micros();
        assert!(
            recovered <= crate::sender_rto::MAX_RTO_MICROS,
            "recovered={recovered} must still be bounded"
        );
    }
}
