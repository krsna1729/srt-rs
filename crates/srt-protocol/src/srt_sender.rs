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

use std::collections::{BTreeMap, VecDeque};

use crate::srt_packet::{DataPacket, PacketPosition, SRT_HEADER_SIZE, sequence_less_than};
use crate::time::Timestamp;

/// "No configured limit" default max bandwidth, matching libsrt's own
/// `BW_INFINITE` (`srtcore/common.h`): 1 Gbps expressed in bytes/sec. Live
/// mode always paces off *some* bandwidth figure -- there is no "pacing
/// disabled" state in real SRT live mode, just a very generous default.
const DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC: u64 = 1_000_000_000 / 8;

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
    payload: Vec<u8>,
    sent_time: Timestamp,
    retransmit_count: u32,
}

/// A message dropped by sender-side TLPKTDROP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedMessage {
    pub message_number: u32,
    pub first_seq: u32,
    pub last_seq: u32,
}

/// Send buffer.
#[derive(Debug)]
pub struct SenderBuffer {
    /// Sent packets (sequence_number -> SentPacket).
    packets: BTreeMap<u32, SentPacket>,

    /// Loss list (packets reported via NAK).
    loss_list: VecDeque<u32>,

    /// The oldest un-ACKed sequence number.
    oldest_unacked: u32,

    /// The next send sequence number.
    next_seq: u32,

    /// The next message number.
    next_msg: u32,

    /// Flow window size.
    flow_window: u32,

    /// Congestion window size.
    congestion_window: u32,

    /// Maximum buffer size (packets).
    #[expect(dead_code)]
    max_buffer_size: u32,

    /// Latency (microseconds).
    latency_us: u64,
    /// Packet send interval (microseconds).
    packet_send_period: u64,
    /// Last packet send time.
    last_send_time: Option<Timestamp>,
    packet_send_period_overridden: bool,
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
    /// Locally discarded packets that exceeded the TLPKTDROP deadline.
    total_dropped: u64,
    /// Payload bytes in locally discarded TLPKTDROP packets.
    total_bytes_dropped: u64,
    /// Valid ACK control packets received from the peer.
    total_acks_received: u64,
    /// NAK control packets received from the peer.
    total_naks_received: u64,
    /// Most recent measurements advertised by a full peer ACK.
    peer_feedback: Option<PeerFeedback>,
}

#[derive(Debug, Clone, Copy)]
struct PeerFeedback {
    rtt_micros: u32,
    rtt_variance_micros: u32,
    available_buffer_packets: u32,
    receiving_rate_packets_per_second: u32,
    link_capacity_packets_per_second: u32,
    receiving_rate_bytes_per_second: u32,
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
        let mut buf = Self {
            packets: BTreeMap::new(),
            loss_list: VecDeque::new(),
            oldest_unacked: initial_seq,
            next_seq: initial_seq,
            next_msg: 1,
            flow_window,
            congestion_window: flow_window,
            max_buffer_size: 8192,
            latency_us: latency_ms as u64 * 1000,
            packet_send_period: 0,
            last_send_time: None,
            packet_send_period_overridden: false,
            total_sent: 0,
            total_bytes_sent: 0,
            total_srt_bytes_sent: 0,
            total_retransmitted_srt_bytes: 0,
            avg_payload_size: INITIAL_AVG_PAYLOAD_SIZE_BYTES,
            max_bandwidth_bytes_per_sec: DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC,
            total_retransmits: 0,
            total_lost: 0,
            total_dropped: 0,
            total_bytes_dropped: 0,
            total_acks_received: 0,
            total_naks_received: 0,
            peer_feedback: None,
        };
        buf.recompute_packet_send_period();
        buf
    }

    /// Get the next sequence number.
    pub fn next_sequence_number(&self) -> u32 {
        self.next_seq
    }

    pub(crate) fn synchronize_next_sequence_number(&mut self, sequence_number: u32) -> bool {
        if !self.packets.is_empty() {
            return false;
        }
        self.next_seq = sequence_number & 0x7FFF_FFFF;
        self.oldest_unacked = self.next_seq;
        true
    }

    /// Get the next message number.
    pub fn next_message_number(&self) -> u32 {
        self.next_msg
    }

    /// Whether sending is possible (checks window size only).
    pub fn can_send(&self) -> bool {
        let in_flight = self.packets_in_flight();
        in_flight < self.flow_window && in_flight < self.congestion_window
    }

    /// Whether an entire multi-packet message fits in the current windows.
    /// Partial messages are never admitted because their missing `Last`
    /// packet cannot be repaired by a later API call.
    pub fn can_send_message(&self, packet_count: usize) -> bool {
        let available = self
            .flow_window
            .min(self.congestion_window)
            .saturating_sub(self.packets_in_flight());
        u32::try_from(packet_count).is_ok_and(|count| count <= available)
    }

    /// Whether sending is possible, including packet pacing.
    pub fn can_send_with_pacing(&self, now: Timestamp) -> bool {
        if !self.can_send() {
            return false;
        }

        // Check packet pacing.
        if self.packet_send_period > 0
            && let Some(last_time) = self.last_send_time
            && now.as_micros() < last_time.as_micros()
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

        if let Some(last_time) = self.last_send_time
            && now.as_micros() < last_time.as_micros()
        {
            return last_time.as_micros() - now.as_micros();
        }

        0
    }

    /// Set the packet send interval (microseconds).
    pub fn set_packet_send_period(&mut self, period: u64) {
        self.packet_send_period = period;
        self.packet_send_period_overridden = true;
    }

    /// Record the send time.
    ///
    /// The next send is due one full pacing period after this one's actual
    /// send time — matching libsrt, which stores the actual time at each
    /// transmission (`m_tsLastSndTime.store(currtime)`, `core.cpp:1131`).
    ///
    /// This is the R8 burst fix: the previous slot-arithmetic version
    /// (`stale_slot + period`) left `last_send_time` in the past after any
    /// idle gap, so every subsequent call returned 0 and the whole paused
    /// backlog burst out back-to-back instead of at MAX_BW. Spec §5.1.2
    /// defines PKT_SND_PERIOD as the *minimum* allowed inter-packet
    /// interval, which actual-send-time bookkeeping enforces by
    /// construction.
    pub fn record_send_time(&mut self, now: Timestamp) {
        self.last_send_time = Some(match (self.last_send_time, self.packet_send_period) {
            (_, period) if period > 0 => {
                Timestamp::from_micros(now.as_micros().saturating_add(period))
            }
            _ => now,
        });
    }

    /// Number of packets in flight.
    pub fn packets_in_flight(&self) -> u32 {
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
        !self.loss_list.is_empty()
    }

    /// Set the congestion window.
    pub fn set_congestion_window(&mut self, cwnd: u32) {
        self.congestion_window = cwnd;
    }

    /// Set the flow window (the congestion window tracks it too; see the
    /// comment on [`Self::new`] for LIVE mode's behavior).
    pub fn set_flow_window(&mut self, flow_window: u32) {
        self.flow_window = flow_window;
        self.congestion_window = flow_window;
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

    /// Add a payload to the buffer and produce a send packet.
    pub fn push(
        &mut self,
        payload: Vec<u8>,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
    ) -> Option<DataPacket> {
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
    ) -> Option<DataPacket> {
        if !self.can_send() {
            return None;
        }

        if sequence_number != self.next_seq {
            return None;
        }

        let message_number = self.next_msg;
        let payload_len = payload.len();

        // Store stripped payload in the buffer (no seq/dest_socket_id/flags).
        self.packets.insert(
            sequence_number,
            SentPacket {
                position: PacketPosition::Single,
                order_flag: false,
                message_number,
                timestamp,
                payload: payload.clone(),
                sent_time: now,
                retransmit_count: 0,
            },
        );

        let packet = DataPacket {
            sequence_number,
            position: PacketPosition::Single,
            order_flag: false,
            encryption_flag: 0,
            retransmitted: false,
            message_number,
            timestamp,
            dest_socket_id,
            payload,
        };

        // Update statistics.
        self.total_sent += 1;
        self.total_bytes_sent += payload_len as u64;
        self.total_srt_bytes_sent = self
            .total_srt_bytes_sent
            .saturating_add((payload_len + SRT_HEADER_SIZE) as u64);
        self.record_sent_payload_size(payload_len);

        // Advance the sequence number and message number.
        self.next_seq = self.next_seq.wrapping_add(1) & 0x7FFF_FFFF;
        self.next_msg = self.next_msg.wrapping_add(1) & 0x03FF_FFFF;

        Some(packet)
    }

    /// Split a large message and send it.
    pub fn push_message(
        &mut self,
        payload: &[u8],
        max_payload_size: usize,
        timestamp: u32,
        dest_socket_id: u32,
        now: Timestamp,
    ) -> Vec<DataPacket> {
        // `slice::chunks(0)` panics. This is a public, application-supplied
        // sizing knob, so an invalid value must fail closed rather than take
        // down the process. Returning no packets matches the existing
        // backpressure behaviour of this convenience API.
        if max_payload_size == 0 {
            return Vec::new();
        }
        let chunks: Vec<&[u8]> = payload.chunks(max_payload_size).collect();
        let total_chunks = chunks.len();
        if !self.can_send_message(total_chunks) {
            return Vec::new();
        }
        let mut packets = Vec::with_capacity(total_chunks);

        for (i, chunk) in chunks.into_iter().enumerate() {
            let position = match (i, total_chunks) {
                (0, 1) => PacketPosition::Single,
                (0, _) => PacketPosition::First,
                (n, total) if n == total - 1 => PacketPosition::Last,
                _ => PacketPosition::Middle,
            };

            let chunk_payload = chunk.to_vec();
            let chunk_len = chunk_payload.len();

            self.packets.insert(
                self.next_seq,
                SentPacket {
                    position,
                    order_flag: true,
                    message_number: self.next_msg,
                    timestamp,
                    payload: chunk_payload.clone(),
                    sent_time: now,
                    retransmit_count: 0,
                },
            );

            let packet = DataPacket {
                sequence_number: self.next_seq,
                position,
                order_flag: true,
                encryption_flag: 0,
                retransmitted: false,
                message_number: self.next_msg,
                timestamp,
                dest_socket_id,
                payload: chunk_payload,
            };

            self.total_sent += 1;
            self.total_bytes_sent += chunk_len as u64;
            self.total_srt_bytes_sent = self
                .total_srt_bytes_sent
                .saturating_add((chunk_len + SRT_HEADER_SIZE) as u64);
            self.record_sent_payload_size(chunk_len);

            self.next_seq = self.next_seq.wrapping_add(1) & 0x7FFF_FFFF;
            packets.push(packet);
        }

        // Advance the message number once, for the next message.
        if !packets.is_empty() {
            self.next_msg = self.next_msg.wrapping_add(1) & 0x03FF_FFFF;
        }

        packets
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
    pub fn pop_retransmit(&mut self, dest_socket_id: u32) -> Option<DataPacket> {
        while let Some(seq) = self.loss_list.pop_front() {
            if let Some(entry) = self.packets.get_mut(&seq) {
                entry.retransmit_count += 1;
                self.total_retransmits += 1;
                let wire_bytes = (entry.payload.len() + SRT_HEADER_SIZE) as u64;
                self.total_srt_bytes_sent = self.total_srt_bytes_sent.saturating_add(wire_bytes);
                self.total_retransmitted_srt_bytes = self
                    .total_retransmitted_srt_bytes
                    .saturating_add(wire_bytes);

                return Some(DataPacket {
                    sequence_number: seq,
                    position: entry.position,
                    order_flag: entry.order_flag,
                    encryption_flag: 0,
                    retransmitted: true,
                    message_number: entry.message_number,
                    timestamp: entry.timestamp,
                    dest_socket_id,
                    payload: entry.payload.clone(),
                });
            }
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
        // Remove every packet with a sequence number less than ack_seq.
        // BTreeMap::retain doesn't need to collect the keys to remove into a
        // temporary Vec first -- it drops unneeded entries in place (avoiding
        // an allocation on every ACK).
        self.packets
            .retain(|&seq, _| !sequence_less_than(seq, ack_seq));

        // Also remove from the loss list.
        self.loss_list
            .retain(|&seq| !sequence_less_than(seq, ack_seq));

        // Update oldest_unacked.
        if sequence_less_than(self.oldest_unacked, ack_seq) {
            self.oldest_unacked = ack_seq;
        }
    }

    /// Process a NAK and add to the loss list.
    pub fn handle_nak(&mut self, lost_sequences: &[u32]) {
        self.total_naks_received = self.total_naks_received.saturating_add(1);
        for &seq in lost_sequences {
            // Only add packets that are still in the buffer.
            if self.packets.contains_key(&seq) && !self.loss_list.contains(&seq) {
                self.loss_list.push_back(seq);
                self.total_lost = self.total_lost.saturating_add(1);
            }
        }
    }

    /// Retain measurements carried by the most recent full ACK.
    pub(crate) fn record_peer_feedback(
        &mut self,
        rtt_micros: u32,
        rtt_variance_micros: u32,
        available_buffer_packets: u32,
        receiving_rate_packets_per_second: u32,
        link_capacity_packets_per_second: u32,
        receiving_rate_bytes_per_second: u32,
    ) {
        self.peer_feedback = Some(PeerFeedback {
            rtt_micros,
            rtt_variance_micros,
            available_buffer_packets,
            receiving_rate_packets_per_second,
            link_capacity_packets_per_second,
            receiving_rate_bytes_per_second,
        });
    }

    /// Remove expired packets (TLPKTDROP), dropping entire messages.
    ///
    /// Scans in sequence order from `oldest_unacked` toward `next_seq`.
    /// When an expired packet is found, all packets sharing its
    /// `message_number` are removed together (SRT spec: "the entire message
    /// is dropped"). Returns one `DroppedMessage` per message removed.
    pub fn drop_expired(&mut self, now: Timestamp) -> Vec<DroppedMessage> {
        let threshold = (self.latency_us * 125 / 100).max(1_000_000);

        let mut dropped_seqs = Vec::new();
        let mut messages = Vec::new();
        let mut seq = self.oldest_unacked;
        while sequence_less_than(seq, self.next_seq) {
            match self.packets.get(&seq) {
                Some(entry) => {
                    let elapsed = now.as_micros().saturating_sub(entry.sent_time.as_micros());
                    if elapsed <= threshold {
                        break;
                    }
                    let msg_num = entry.message_number;
                    let msg_first_seq = seq;
                    // Drop this packet and any remaining fragments of the same message.
                    let mut msg_last_seq = seq;
                    loop {
                        if let Some(removed) = self.packets.remove(&seq) {
                            self.total_dropped = self.total_dropped.saturating_add(1);
                            self.total_bytes_dropped = self
                                .total_bytes_dropped
                                .saturating_add(removed.payload.len() as u64);
                            dropped_seqs.push(seq);
                            msg_last_seq = seq;
                        }
                        let next = seq.wrapping_add(1) & 0x7FFF_FFFF;
                        if !sequence_less_than(next, self.next_seq) {
                            seq = next;
                            break;
                        }
                        match self.packets.get(&next) {
                            Some(e) if e.message_number == msg_num => {
                                seq = next;
                            }
                            _ => {
                                seq = next;
                                break;
                            }
                        }
                    }
                    messages.push(DroppedMessage {
                        message_number: msg_num,
                        first_seq: msg_first_seq,
                        last_seq: msg_last_seq,
                    });
                }
                None => {
                    seq = seq.wrapping_add(1) & 0x7FFF_FFFF;
                }
            }
        }

        if sequence_less_than(self.oldest_unacked, seq) {
            self.oldest_unacked = seq;
        }

        self.loss_list.retain(|s| !dropped_seqs.contains(s));

        messages
    }

    /// Get the send time of the oldest packet in the buffer.
    pub fn oldest_packet_time(&self) -> Option<Timestamp> {
        self.packets.values().next().map(|e| e.sent_time)
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
        let buffer_span_micros = self
            .packets
            .values()
            .next()
            .zip(self.packets.values().next_back())
            .map_or(0, |(oldest, newest)| {
                newest
                    .sent_time
                    .as_micros()
                    .saturating_sub(oldest.sent_time.as_micros())
            });
        let peer = self.peer_feedback;

        SenderStats {
            packets_in_buffer: self.packets.len() as u32,
            payload_bytes_in_buffer,
            packets_in_loss_list: self.loss_list.len() as u32,
            available_buffer_packets: self.flow_window.saturating_sub(self.packets.len() as u32),
            available_buffer_bytes: None,
            flow_window_packets: self.flow_window,
            congestion_window_packets: self.congestion_window,
            packets_in_flight: self.packets_in_flight(),
            buffer_span_micros,
            tsbpd_delay_micros: self.latency_us,
            packet_send_period_micros: self.packet_send_period,
            max_bandwidth_bytes_per_second: self.max_bandwidth_bytes_per_sec,
            peer_rtt_micros: peer.map(|feedback| feedback.rtt_micros),
            peer_rtt_variance_micros: peer.map(|feedback| feedback.rtt_variance_micros),
            peer_available_buffer_packets: peer.map(|feedback| feedback.available_buffer_packets),
            peer_receiving_rate_packets_per_second: peer
                .map(|feedback| feedback.receiving_rate_packets_per_second),
            peer_link_capacity_packets_per_second: peer
                .map(|feedback| feedback.link_capacity_packets_per_second),
            peer_link_capacity_bytes_per_second: peer.and_then(|feedback| {
                let packet_rate = u64::from(feedback.receiving_rate_packets_per_second);
                (packet_rate > 0).then(|| {
                    u64::from(feedback.link_capacity_packets_per_second)
                        .saturating_mul(u64::from(feedback.receiving_rate_bytes_per_second))
                        / packet_rate
                })
            }),
            peer_receiving_rate_bytes_per_second: peer
                .map(|feedback| feedback.receiving_rate_bytes_per_second),
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
    /// RTT advertised by the peer's most recent full ACK.
    pub peer_rtt_micros: Option<u32>,
    /// RTT variance advertised by the peer's most recent full ACK.
    pub peer_rtt_variance_micros: Option<u32>,
    /// Peer receive-buffer availability from the most recent full ACK.
    pub peer_available_buffer_packets: Option<u32>,
    /// Peer receive rate from the most recent full ACK.
    pub peer_receiving_rate_packets_per_second: Option<u32>,
    /// Peer link-capacity estimate from the most recent full ACK.
    pub peer_link_capacity_packets_per_second: Option<u32>,
    /// Peer link-capacity estimate converted using its measured wire bytes per packet.
    pub peer_link_capacity_bytes_per_second: Option<u64>,
    /// Peer byte receive rate from the most recent full ACK.
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
        let pkt = packet.expect("送信パケットは Some になる想定");
        assert_eq!(pkt.sequence_number, 1000);
        assert_eq!(buf.next_sequence_number(), 1001);
        assert_eq!(buf.packets_in_flight(), 1);
    }

    #[test]
    fn fragmented_message_is_all_or_nothing_at_window_boundary() {
        let mut buf = SenderBuffer::new(1000, 2, 120);
        buf.set_congestion_window(2);
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

    #[test]
    fn test_sender_buffer_nak() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        let now = Timestamp::from_micros(0);

        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);

        // パケット 1001 を損失報告
        buf.handle_nak(&[1001]);
        assert!(buf.has_retransmit());

        // 再送パケットを取得
        let retransmit = buf.pop_retransmit(1);
        assert!(retransmit.is_some());
        let pkt = retransmit.expect("再送パケットは Some になる想定");
        assert_eq!(pkt.sequence_number, 1001);
        assert!(pkt.retransmitted);
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

        buf.push(vec![1], 100, 1, now);
        buf.push(vec![2], 100, 1, now);
        buf.push(vec![3], 100, 1, now);

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

    #[test]
    fn test_packet_pacing_after_late_wakeup_reschedules_full_period() {
        let mut buf = SenderBuffer::new(1000, 8192, 120);
        buf.set_packet_send_period(1000);
        buf.record_send_time(Timestamp::from_micros(0));

        // A late wakeup (500us past the slot) must not shorten the next
        // interval: the next send is due a full period after `now`, not
        // after the stale slot. This is the R8 burst fix - the old
        // behavior (next slot at slot+period) allowed sub-period spacing
        // after any gap and, over long idles, unbounded back-to-back
        // bursts.
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(1500)));
        buf.record_send_time(Timestamp::from_micros(1500));
        assert!(!buf.can_send_with_pacing(Timestamp::from_micros(2499)));
        assert_eq!(buf.time_until_send(Timestamp::from_micros(2499)), 1);
        assert!(buf.can_send_with_pacing(Timestamp::from_micros(2500)));
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
        buf.push(vec![1], 100, 1, send_time);

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

    #[test]
    fn telemetry_counts_loss_retransmit_and_exact_srt_bytes() {
        let mut buf = SenderBuffer::new(10, 32, 10);
        buf.push(vec![1, 2, 3, 4], 0, 1, Timestamp::from_micros(0));

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
        buf.record_peer_feedback(5_000, 500, 60, 1_000, 2_000, 1_500_000);

        let stats = buf.stats();
        assert_eq!(stats.peer_rtt_micros, Some(5_000));
        assert_eq!(stats.peer_available_buffer_packets, Some(60));
        assert_eq!(stats.peer_link_capacity_bytes_per_second, Some(3_000_000));
    }
}
