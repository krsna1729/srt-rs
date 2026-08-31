//! SRT receive buffer.
//!
//! Manages reordering of received packets and ACK/NAK generation.
//!
//! ## Features
//!
//! - Packet ordering (reordering buffer)
//! - Duplicate packet detection
//! - Loss detection and NAK generation
//! - ACK generation (periodic ACK / Light ACK)
//! - TSBPD (Time-based Packet Delivery)
//! - Receiving rate / link capacity estimation

use bytes::Bytes;
use rustc_hash::FxHashSet;
use std::collections::BTreeMap;

#[cfg(test)]
use std::cell::Cell;

use crate::error::Error;
use crate::srt_handshake::{DEFAULT_FLOW_WINDOW, MAX_FLOW_WINDOW};
use crate::srt_packet::{
    DataPacket, PacketPosition, SRT_HEADER_SIZE, sequence_greater_than, sequence_less_than,
};
use crate::time::Timestamp;

/// Light ACK send interval (packets).
const LIGHT_ACK_INTERVAL: u32 = 64;

/// Sequence numbers are carried in the low 31 bits of each wire word.
const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;

/// Periodic ACK interval (microseconds).
const ACK_INTERVAL_US: u64 = 10_000; // 10ms

/// Maximum number of entries kept for tracking ACK send times.
const MAX_ACK_TIMESTAMPS: usize = 16;
const _: () = assert!(MAX_ACK_TIMESTAMPS.is_power_of_two());

/// Number of samples used for Link Capacity estimation.
const LINK_CAPACITY_SAMPLES: usize = 16;
const _: () = assert!(LINK_CAPACITY_SAMPLES.is_power_of_two());

/// Number of ACKACK samples used to estimate TSBPD clock drift.
///
/// This matches libsrt's `TSBPD_DRIFT_MAX_SAMPLES`.
const TSBPD_DRIFT_MAX_SAMPLES: u32 = 1_000;
/// Maximum drift carried into the TSBPD time base per sample window.
///
/// This matches libsrt's `TSBPD_DRIFT_MAX_VALUE`.
const TSBPD_DRIFT_MAX_US: i64 = 5_000;

fn sequence_in_range(first_seq: u32, distance: u32, sequence: u32) -> bool {
    sequence.wrapping_sub(first_seq) & SEQUENCE_MASK <= distance
}

/// Circular loss membership for one negotiated receive window.
///
/// Storage is allocated on the first loss. Data words are followed by a
/// summary bitmap whose set bits identify nonzero data words.
#[derive(Debug)]
struct LossBitmap {
    storage: Vec<u64>,
    word_count: u32,
    window_size: u32,
    base_seq: u32,
    len: u32,
}

impl LossBitmap {
    fn new(base_seq: u32, window_size: u32) -> Self {
        Self {
            storage: Vec::new(),
            word_count: 0,
            window_size,
            base_seq,
            len: 0,
        }
    }

    fn ensure_storage(&mut self) {
        if !self.storage.is_empty() {
            return;
        }
        let capacity = self
            .window_size
            .max(64)
            .checked_next_power_of_two()
            .expect("receive window must fit the 31-bit sequence comparison domain")
            as usize;
        self.word_count = (capacity / 64) as u32;
        let word_count = self.word_count as usize;
        self.storage.resize(word_count + word_count.div_ceil(64), 0);
    }

    fn capacity_mask(&self) -> usize {
        self.word_count as usize * 64 - 1
    }

    fn offset(&self, seq: u32) -> Option<u32> {
        let offset = seq.wrapping_sub(self.base_seq) & SEQUENCE_MASK;
        (offset < self.window_size).then_some(offset)
    }

    fn bit_index(&self, seq: u32) -> usize {
        seq as usize & self.capacity_mask()
    }

    fn remove(&mut self, seq: u32) -> bool {
        if self.storage.is_empty() || self.offset(seq).is_none() {
            return false;
        }
        let index = self.bit_index(seq);
        let word_index = index / 64;
        let bit = 1u64 << (index % 64);
        let old = self.storage[word_index];
        if old & bit == 0 {
            return false;
        }
        let new = old & !bit;
        self.storage[word_index] = new;
        if new == 0 {
            self.storage[self.word_count as usize + word_index / 64] &=
                !(1u64 << (word_index % 64));
        }
        self.len -= 1;
        true
    }

    fn mutate_contiguous_range(&mut self, mut seq: u32, mut count: u32, insert: bool) -> u32 {
        let mut changed = 0;
        while count != 0 {
            let index = self.bit_index(seq);
            let word_index = index / 64;
            let bit_offset = index % 64;
            let chunk = count.min((64 - bit_offset) as u32);
            let mask = (u64::MAX >> (64 - chunk)) << bit_offset;
            let old = self.storage[word_index];
            let new = if insert { old | mask } else { old & !mask };
            changed += if insert {
                (!old & mask).count_ones()
            } else {
                (old & mask).count_ones()
            };
            self.storage[word_index] = new;
            let summary = self.word_count as usize + word_index / 64;
            let summary_bit = 1u64 << (word_index % 64);
            if old == 0 && new != 0 {
                self.storage[summary] |= summary_bit;
            } else if old != 0 && new == 0 {
                self.storage[summary] &= !summary_bit;
            }
            seq = seq.wrapping_add(chunk) & SEQUENCE_MASK;
            count -= chunk;
        }
        if insert {
            self.len += changed;
        } else {
            self.len -= changed;
        }
        changed
    }

    fn insert_range(&mut self, first_seq: u32, count: u32) -> u32 {
        if count == 0 {
            return 0;
        }
        let Some(offset) = self.offset(first_seq) else {
            return 0;
        };
        if count > self.window_size - offset {
            return 0;
        }
        self.ensure_storage();
        self.mutate_contiguous_range(first_seq, count, true)
    }

    #[cfg(test)]
    fn insert(&mut self, seq: u32) -> bool {
        self.insert_range(seq, 1) == 1
    }

    fn remove_range(&mut self, first_seq: u32, count: u32) -> u32 {
        if count == 0 || self.storage.is_empty() {
            return 0;
        }
        let offset = first_seq.wrapping_sub(self.base_seq) & SEQUENCE_MASK;
        if offset < self.window_size {
            return self.mutate_contiguous_range(
                first_seq,
                count.min(self.window_size - offset),
                false,
            );
        }

        let until_base = SEQUENCE_MASK - offset + 1;
        if count <= until_base {
            return 0;
        }
        self.mutate_contiguous_range(
            self.base_seq,
            (count - until_base).min(self.window_size),
            false,
        )
    }

    #[cfg(test)]
    fn contains(&self, seq: &u32) -> bool {
        if self.storage.is_empty() || self.offset(*seq).is_none() {
            return false;
        }
        let index = self.bit_index(*seq);
        self.storage[index / 64] & (1u64 << (index % 64)) != 0
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn len(&self) -> usize {
        self.len as usize
    }

    fn set_base(&mut self, base_seq: u32) {
        self.base_seq = base_seq;
    }

    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        let base_seq = self.base_seq;
        let window_size = self.window_size;
        let word_count = self.word_count as usize;
        let mask = word_count.saturating_mul(64).saturating_sub(1);
        let base_index = base_seq as usize & mask;
        self.storage[..word_count]
            .iter()
            .copied()
            .enumerate()
            .flat_map(move |(word_index, word)| {
                std::iter::successors((word != 0).then_some(word), |word| {
                    let next = *word & (*word - 1);
                    (next != 0).then_some(next)
                })
                .map(move |word| word_index * 64 + word.trailing_zeros() as usize)
            })
            .filter_map(move |index| {
                let offset = index.wrapping_sub(base_index) & mask;
                (offset < window_size as usize)
                    .then_some(base_seq.wrapping_add(offset as u32) & SEQUENCE_MASK)
            })
    }

    fn for_each_numeric_run(&self, mut emit: impl FnMut(u32, u32)) {
        if self.is_empty() {
            return;
        }
        // A fixed stack sort preserves the measured sparse-loss fast path;
        // word-native run extraction wins once there are more than eight bits.
        if self.len <= 8 {
            let mut losses = [0; 8];
            let len = self.len();
            for (slot, loss) in losses.iter_mut().zip(self.iter()) {
                *slot = loss;
            }
            losses[..len].sort_unstable();
            let mut start = losses[0];
            let mut end = start;
            for &loss in &losses[1..len] {
                if loss == end + 1 {
                    end = loss;
                } else {
                    emit(start, end);
                    start = loss;
                    end = loss;
                }
            }
            emit(start, end);
            return;
        }
        const SEQUENCE_MODULUS: u64 = 1 << 31;
        let numeric_end = u64::from(self.base_seq) + u64::from(self.window_size);
        if numeric_end > SEQUENCE_MODULUS {
            self.for_each_run_segment(0, (numeric_end - SEQUENCE_MODULUS) as u32, &mut emit);
            self.for_each_run_segment(
                self.base_seq,
                (SEQUENCE_MODULUS - u64::from(self.base_seq)) as u32,
                &mut emit,
            );
        } else {
            self.for_each_run_segment(self.base_seq, self.window_size, &mut emit);
        }
    }

    fn for_each_run_segment(&self, mut seq: u32, mut count: u32, emit: &mut impl FnMut(u32, u32)) {
        let mut pending = None;
        while count != 0 {
            let index = self.bit_index(seq);
            let word_index = index / 64;
            let bit_offset = index % 64;
            let chunk = count.min((64 - bit_offset) as u32);
            let chunk_mask = (u64::MAX >> (64 - chunk)) << bit_offset;
            let mut bits = self.storage[word_index] & chunk_mask;
            while bits != 0 {
                let run_bit = bits.trailing_zeros();
                let run_len = (!(bits >> run_bit)).trailing_zeros();
                let run_start = seq + (run_bit as usize - bit_offset) as u32;
                let run_end = run_start + run_len - 1;
                if let Some((pending_start, pending_end)) = pending {
                    if pending_end + 1 == run_start {
                        pending = Some((pending_start, run_end));
                    } else {
                        emit(pending_start, pending_end);
                        pending = Some((run_start, run_end));
                    }
                } else {
                    pending = Some((run_start, run_end));
                }
                let run_mask = (u64::MAX >> (64 - run_len)) << run_bit;
                bits &= !run_mask;
            }
            seq += chunk;
            count -= chunk;
        }
        if let Some((start, end)) = pending {
            emit(start, end);
        }
    }

    fn next_nonzero_word(&self, start: usize, end: usize) -> Option<usize> {
        if start >= end || self.storage.is_empty() {
            return None;
        }
        let word_count = self.word_count as usize;
        let summaries = &self.storage[word_count..];
        let first_summary = start / 64;
        for (summary_index, &summary) in summaries.iter().enumerate().skip(first_summary) {
            if summary_index * 64 >= end {
                break;
            }
            let bits = if summary_index == first_summary {
                summary & (u64::MAX << (start % 64))
            } else {
                summary
            };
            if bits != 0 {
                let word_index = summary_index * 64 + bits.trailing_zeros() as usize;
                return (word_index < end).then_some(word_index);
            }
        }
        None
    }

    fn first(&self) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        let mask = self.capacity_mask();
        let start = self.base_seq as usize & mask;
        let start_word = start / 64;
        let start_bit = start % 64;
        let suffix = self.storage[start_word] & (u64::MAX << start_bit);
        let index = if suffix != 0 {
            start_word * 64 + suffix.trailing_zeros() as usize
        } else if let Some(word) = self.next_nonzero_word(start_word + 1, self.word_count as usize)
        {
            word * 64 + self.storage[word].trailing_zeros() as usize
        } else if let Some(word) = self.next_nonzero_word(0, start_word) {
            word * 64 + self.storage[word].trailing_zeros() as usize
        } else {
            let prefix_mask = (1u64 << start_bit).wrapping_sub(1);
            let prefix = self.storage[start_word] & prefix_mask;
            start_word * 64 + prefix.trailing_zeros() as usize
        };
        let offset = index.wrapping_sub(start) & mask;
        Some(self.base_seq.wrapping_add(offset as u32) & SEQUENCE_MASK)
    }
}

/// A bounded, windowed clock-drift estimator used by TSBPD.
///
/// After each sample window, excess drift is folded into the time base and
/// the remainder stays as the current delivery-time offset. This is the same
/// algorithm used by libsrt's `DriftTracer`.
#[derive(Debug, Default)]
struct TsbpdDriftTracer {
    drift_us: i64,
    overdrift_us: i64,
    drift_sum_us: i64,
    sample_count: u32,
}

impl TsbpdDriftTracer {
    fn update(&mut self, sample_us: i64) -> bool {
        self.drift_sum_us = self.drift_sum_us.saturating_add(sample_us);
        self.sample_count = self.sample_count.saturating_add(1);
        self.overdrift_us = 0;

        if self.sample_count < TSBPD_DRIFT_MAX_SAMPLES {
            return false;
        }

        self.drift_us = self.drift_sum_us / i64::from(self.sample_count);
        self.drift_sum_us = 0;
        self.sample_count = 0;

        if self.drift_us.unsigned_abs() > TSBPD_DRIFT_MAX_US as u64 {
            self.overdrift_us = self.drift_us.signum() * TSBPD_DRIFT_MAX_US;
            self.drift_us -= self.overdrift_us;
        }

        true
    }

    fn drift_us(&self) -> i64 {
        self.drift_us
    }

    fn overdrift_us(&self) -> i64 {
        self.overdrift_us
    }
}

/// Maximum timestamp value (32-bit).
const MAX_TIMESTAMP: u64 = 0xFFFF_FFFF;

/// TSBPD wraparound period: begins 30 seconds before MAX_TIMESTAMP is reached.
const WRAPPING_PERIOD_START: u64 = MAX_TIMESTAMP - 30_000_000;

/// TSBPD wraparound period: ends once the timestamp is within this range.
const WRAPPING_PERIOD_END_MIN: u64 = 30_000_000;

/// TSBPD wraparound period: the inclusive upper bound at which the timestamp
/// ends the period, matching libsrt's `CTsbpdTime::updateBaseTime`.
const WRAPPING_PERIOD_END_MAX: u64 = 60_000_000;

/// Tracks ACK send times and acknowledged positions (for RTT calculation
/// and ACK suppression).
#[derive(Debug)]
struct AckTimestampTracker {
    valid: u16,
    entries: Option<Box<[AckTimestamp; MAX_ACK_TIMESTAMPS]>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct AckTimestamp {
    ack_number: u32,
    acked_seq: u32,
    send_time: Timestamp,
}

impl AckTimestampTracker {
    fn new() -> Self {
        Self {
            valid: 0,
            entries: None,
        }
    }

    /// Record an ACK send time and the sequence position it acknowledged.
    fn record(&mut self, ack_number: u32, send_time: Timestamp, acked_seq: u32) {
        let index = ack_number as usize & (MAX_ACK_TIMESTAMPS - 1);
        let entries = self
            .entries
            .get_or_insert_with(|| Box::new([AckTimestamp::default(); MAX_ACK_TIMESTAMPS]));
        entries[index] = AckTimestamp {
            ack_number,
            acked_seq,
            send_time,
        };
        self.valid |= 1 << index;
    }

    fn get(&self, ack_number: u32) -> Option<&AckTimestamp> {
        let index = ack_number as usize & (MAX_ACK_TIMESTAMPS - 1);
        let entries = self.entries.as_ref()?;
        ((self.valid & (1 << index)) != 0 && entries[index].ack_number == ack_number)
            .then(|| &entries[index])
    }

    /// Get an ACK's send time.
    fn get_send_time(&self, ack_number: u32) -> Option<Timestamp> {
        self.get(ack_number).map(|entry| entry.send_time)
    }

    /// Get the sequence position an ACK acknowledged.
    fn get_acked_seq(&self, ack_number: u32) -> Option<u32> {
        self.get(ack_number).map(|entry| entry.acked_seq)
    }
}

/// Receiving rate estimator.
#[derive(Debug)]
struct ReceivingRateEstimator {
    /// Last packet arrival time.
    last_packet_time: Option<Timestamp>,
    /// Sum of arrival intervals (microseconds).
    interval_sum: u64,
    /// Number of samples.
    sample_count: u32,
    /// Bytes received (current measurement period).
    bytes_received: u64,
    /// Measurement period start time.
    period_start: Timestamp,
    /// Estimated receiving rate (packets/sec).
    estimated_packet_rate: u32,
    /// Estimated receiving rate (bytes/sec).
    estimated_byte_rate: u32,
}

impl ReceivingRateEstimator {
    fn new(start_time: Timestamp) -> Self {
        Self {
            last_packet_time: None,
            interval_sum: 0,
            sample_count: 0,
            bytes_received: 0,
            period_start: start_time,
            estimated_packet_rate: 0,
            estimated_byte_rate: 0,
        }
    }

    /// Call on packet receipt.
    fn on_packet_received(&mut self, now: Timestamp, packet_size: usize) {
        // Calculate the arrival interval.
        if let Some(last_time) = self.last_packet_time {
            let interval = now.as_micros().saturating_sub(last_time.as_micros());
            // Only count plausible intervals (1us - 1sec).
            if interval > 0 && interval < 1_000_000 {
                self.interval_sum += interval;
                self.sample_count += 1;
            }
        }
        self.last_packet_time = Some(now);
        self.bytes_received += packet_size as u64;
    }

    /// Calculate rates and reset the statistics.
    fn calculate_rates(&mut self, now: Timestamp) -> (u32, u32) {
        let elapsed = now
            .as_micros()
            .saturating_sub(self.period_start.as_micros());

        // Calculate packets/sec.
        let packet_rate = if self.sample_count > 0 && self.interval_sum > 0 {
            let avg_interval = self.interval_sum / self.sample_count as u64;
            1_000_000u64.checked_div(avg_interval).unwrap_or(0) as u32
        } else {
            0
        };

        // Calculate bytes/sec.
        let byte_rate = (self.bytes_received * 1_000_000)
            .checked_div(elapsed)
            .unwrap_or(0) as u32;

        // Smooth with EWMA (7/8 * old + 1/8 * new).
        if packet_rate > 0 {
            if self.estimated_packet_rate == 0 {
                self.estimated_packet_rate = packet_rate;
            } else {
                self.estimated_packet_rate =
                    (self.estimated_packet_rate as u64 * 7 / 8 + packet_rate as u64 / 8) as u32;
            }
        }

        if byte_rate > 0 {
            if self.estimated_byte_rate == 0 {
                self.estimated_byte_rate = byte_rate;
            } else {
                self.estimated_byte_rate =
                    (self.estimated_byte_rate as u64 * 7 / 8 + byte_rate as u64 / 8) as u32;
            }
        }

        // Reset the statistics.
        self.interval_sum = 0;
        self.sample_count = 0;
        self.bytes_received = 0;
        self.period_start = now;

        (self.estimated_packet_rate, self.estimated_byte_rate)
    }
}

/// Link capacity estimator (Packet Pair Technique).
#[derive(Debug)]
struct LinkCapacityEstimator {
    /// Last packet arrival time.
    last_packet_time: Option<Timestamp>,
    /// Packet Pair arrival intervals in oldest-overwrite order.
    intervals: Option<Box<[u64; LINK_CAPACITY_SAMPLES]>>,
    next_interval: u8,
    interval_count: u8,
    /// Estimated link capacity (packets/sec).
    estimated_capacity: u32,
}

impl LinkCapacityEstimator {
    fn new() -> Self {
        Self {
            last_packet_time: None,
            intervals: None,
            next_interval: 0,
            interval_count: 0,
            estimated_capacity: 0,
        }
    }

    /// Call on packet receipt.
    fn on_packet_received(&mut self, now: Timestamp) {
        if let Some(last_time) = self.last_packet_time {
            let interval = now.as_micros().saturating_sub(last_time.as_micros());

            // Only record plausible intervals (1us - 100ms).
            if (1..100_000).contains(&interval) {
                let intervals = self
                    .intervals
                    .get_or_insert_with(|| Box::new([0; LINK_CAPACITY_SAMPLES]));
                intervals[self.next_interval as usize] = interval;
                self.next_interval = (self.next_interval + 1) & (LINK_CAPACITY_SAMPLES as u8 - 1);
                self.interval_count = self
                    .interval_count
                    .saturating_add(1)
                    .min(LINK_CAPACITY_SAMPLES as u8);
            }
        }
        self.last_packet_time = Some(now);
    }

    /// Calculate the link capacity.
    fn calculate_capacity(&mut self) -> u32 {
        let Some(intervals) = self.intervals.as_ref() else {
            return self.estimated_capacity;
        };

        // Get the minimum interval (Packet Pair Technique).
        // Use the median of the bottom 25% to reduce noise.
        let mut sorted = **intervals;
        let sample_count = self.interval_count as usize;
        sorted[..sample_count].sort_unstable();
        let quartile_idx = sample_count / 4;
        let min_interval = sorted[quartile_idx];

        if let Some(capacity) = 1_000_000u64.checked_div(min_interval).map(|v| v as u32) {
            // Smooth with EWMA.
            if self.estimated_capacity == 0 {
                self.estimated_capacity = capacity;
            } else {
                self.estimated_capacity =
                    (self.estimated_capacity as u64 * 7 / 8 + capacity as u64 / 8) as u32;
            }
        }

        self.estimated_capacity
    }
}

/// Strips fields redundant with the packet-map key (`sequence_number`) or
/// already consumed before insertion (`dest_socket_id`, `encryption_flag`,
/// `retransmitted`). Saves 16 bytes per retained packet.
#[derive(Debug, Clone)]
struct ReceivedPacket {
    position: PacketPosition,
    order_flag: bool,
    message_number: u32,
    timestamp: u32,
    payload: Bytes,
    recv_time: Timestamp,
}

/// ACK information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckPacket {
    /// ACK sequence number (the next expected packet).
    pub ack_seq: u32,
    /// RTT (microseconds).
    pub rtt: u32,
    /// RTT variance (microseconds).
    pub rtt_var: u32,
    /// Available buffer size (packets).
    pub available_buffer: u32,
    /// Receiving rate (packets/sec).
    pub receiving_rate: u32,
    /// Estimated link capacity (packets/sec).
    pub link_capacity: u32,
    /// Receiving rate (bytes/sec).
    pub recv_rate: u32,
    /// Whether this is a Light ACK.
    pub is_light: bool,
}

/// NAK information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NakPacket {
    /// Numerically ordered runs of lost sequence numbers.
    pub loss_ranges: Vec<LossRange>,
}

/// Inclusive circular range of lost 31-bit packet sequence numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossRange {
    /// First lost sequence number.
    pub first_seq: u32,
    /// Last lost sequence number, which may be numerically smaller after wrap.
    pub last_seq: u32,
}

impl LossRange {
    /// Number of sequence positions in this inclusive circular range.
    pub fn sequence_count(self) -> u32 {
        (self.last_seq.wrapping_sub(self.first_seq) & SEQUENCE_MASK) + 1
    }

    /// Iterate the sequence positions in circular order.
    pub fn iter(self) -> impl Iterator<Item = u32> {
        let mut seq = self.first_seq;
        let sequence_count = self.sequence_count();
        std::iter::from_fn(move || {
            let current = seq;
            seq = seq.wrapping_add(1) & SEQUENCE_MASK;
            Some(current)
        })
        .take(sequence_count as usize)
    }
}

/// Compact result of applying an inclusive DROPREQ sequence range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropRangeSummary {
    /// Number of sequence positions covered by the request.
    pub sequence_count: u32,
    /// Number of buffered packets actually removed.
    pub packets_removed: u32,
    /// Number of recorded losses actually removed.
    pub losses_removed: u32,
}

/// Receive buffer.
#[derive(Debug)]
pub struct ReceiverBuffer {
    /// Received packets (sequence_number -> ReceivedPacket). Ordered storage
    /// preserves efficient successor queries on loss/reorder paths.
    packets: BTreeMap<u32, ReceivedPacket>,

    delivery_seq_hint: Option<u32>,

    /// The next expected sequence number.
    expected_seq: u32,

    /// Highest sequence position whose receive/loss/drop state has already
    /// been classified. Positions through this frontier form one contiguous
    /// interval in 31-bit circular sequence order. A packet beyond it can
    /// therefore expose only the interval immediately after the frontier;
    /// packets at or behind it can only recover a known loss or duplicate
    /// already-accounted state.
    loss_detection_frontier: u32,

    /// Detected missing packets in one lazily allocated circular bitmap.
    loss_list: LossBitmap,

    /// Last ACK send time
    last_ack_time: Timestamp,

    /// The sequence number last ACKed.
    last_ack_seq: u32,

    /// Packets received since the last ACK was sent (for Light ACK).
    packets_since_ack: u32,

    /// ACK sequence number (the ACK packet's own number).
    ack_number: u32,

    /// The sequence position the peer last confirmed via ACKACK. Periodic
    /// ACK generation is suppressed while this is unchanged (spec §4.8.1),
    /// except when buffer space has freed since the last full ACK.
    last_ackacked_seq: Option<u32>,

    /// The full-ACK number the peer last confirmed. An ACKACK for an older
    /// full ACK cannot confirm a newer advertised receive window, even if
    /// both ACKs carry the same sequence position.
    last_ackacked_number: Option<u32>,

    /// The available-buffer value advertised in the last ACK, so a
    /// position-stale periodic ACK is still sent when buffer space has
    /// freed (libsrt's `bNeedFullAck` exception).
    last_advertised_buffer: u32,

    /// TSBPD delay (microseconds).
    tsbpd_delay_us: u64,

    /// Whether TSBPD is enabled.
    tsbpd_enabled: bool,

    /// TSBPD time base (TsbpdTimeBase = T_NOW - HSREQ_TIMESTAMP, microseconds).
    tsbpd_time_base: u64,

    /// First RTT sample, used to compensate one-way-delay changes while
    /// measuring TSBPD clock drift.
    first_rtt_sample: Option<u32>,

    /// Current TSBPD clock-drift estimate.
    drift_tracer: TsbpdDriftTracer,

    /// Whether the TSBPD wraparound period is active.
    wrapping_period_active: bool,

    /// RTT (microseconds).
    rtt: u32,

    /// RTT variance (microseconds).
    rtt_var: u32,

    /// Maximum buffer size.
    max_buffer_size: u32,

    /// Packets delivered to, but not yet consumed from, the application's
    /// bounded delivery queue. They remain part of advertised receive-window
    /// occupancy.
    application_backlog_packets: u32,

    /// Total packets received (for statistics).
    total_received: u64,

    /// All decrypted DATA packets presented to the receive buffer.
    total_data_packets_received: u64,

    /// Total packets lost (for statistics).
    total_lost: u64,

    /// Total duplicate packets (for statistics).
    total_duplicates: u64,

    /// Valid packets received with the retransmission bit set.
    total_retransmitted: u64,

    /// Missing packets abandoned by TLPKTDROP.
    total_dropped: u64,

    /// Encrypted packets the connection could not decrypt.
    total_undecryptable: u64,

    /// ACK control packets emitted by the owning connection.
    total_acks_sent: u64,

    /// NAK control packets emitted by the owning connection.
    total_naks_sent: u64,

    /// Total bytes received (for statistics).
    total_bytes_received: u64,

    /// SRT datagram bytes for all decrypted DATA packets, including duplicates.
    total_srt_bytes_received: u64,

    /// Jitter (microseconds), calculated per RFC 3550.
    jitter: u32,

    /// Previous packet arrival interval (for jitter calculation).
    last_transit: Option<i64>,

    /// Tracks ACK send times (for RTT calculation).
    ack_timestamps: AckTimestampTracker,

    /// Receiving rate estimator.
    rate_estimator: ReceivingRateEstimator,

    /// Link capacity estimator.
    link_capacity_estimator: LinkCapacityEstimator,

    #[cfg(test)]
    delivery_scan_calls: Cell<usize>,

    #[cfg(test)]
    receive_expected_sequence_scans: Cell<usize>,

    /// Number of newly exposed missing positions inspected by loss detection.
    /// This makes the persistent-old-hole complexity invariant testable
    /// without putting instrumentation in production builds.
    #[cfg(test)]
    loss_detection_steps: Cell<usize>,
}

impl ReceiverBuffer {
    /// Create a new receive buffer.
    pub fn new(
        initial_seq: u32,
        tsbpd_delay_ms: u16,
        start_time: Timestamp,
        tsbpd_time_base: u64,
    ) -> Self {
        Self::with_buffer_size(
            initial_seq,
            tsbpd_delay_ms,
            start_time,
            tsbpd_time_base,
            DEFAULT_FLOW_WINDOW,
        )
    }

    pub(crate) fn with_buffer_size(
        initial_seq: u32,
        tsbpd_delay_ms: u16,
        start_time: Timestamp,
        tsbpd_time_base: u64,
        max_buffer_size: u32,
    ) -> Self {
        let max_buffer_size = max_buffer_size.min(MAX_FLOW_WINDOW);
        Self {
            packets: BTreeMap::new(),
            delivery_seq_hint: None,
            expected_seq: initial_seq,
            loss_detection_frontier: initial_seq.wrapping_sub(1) & 0x7FFF_FFFF,
            last_advertised_buffer: 0,
            loss_list: LossBitmap::new(initial_seq, max_buffer_size),
            last_ack_time: start_time,
            last_ack_seq: initial_seq,
            last_ackacked_seq: None,
            last_ackacked_number: None,
            packets_since_ack: 0,
            // The first Full ACK increments this to one, as required by the
            // wire specification.
            ack_number: 0,
            tsbpd_delay_us: tsbpd_delay_ms as u64 * 1000,
            tsbpd_enabled: true,
            tsbpd_time_base,
            first_rtt_sample: None,
            drift_tracer: TsbpdDriftTracer::default(),
            wrapping_period_active: false,
            rtt: 100_000, // Initial RTT: 100ms
            rtt_var: 50_000,
            max_buffer_size,
            application_backlog_packets: 0,
            total_received: 0,
            total_data_packets_received: 0,
            total_lost: 0,
            total_duplicates: 0,
            total_retransmitted: 0,
            total_dropped: 0,
            total_undecryptable: 0,
            total_acks_sent: 0,
            total_naks_sent: 0,
            total_bytes_received: 0,
            total_srt_bytes_received: 0,
            jitter: 0,
            last_transit: None,
            ack_timestamps: AckTimestampTracker::new(),
            rate_estimator: ReceivingRateEstimator::new(start_time),
            link_capacity_estimator: LinkCapacityEstimator::new(),
            #[cfg(test)]
            delivery_scan_calls: Cell::new(0),
            #[cfg(test)]
            receive_expected_sequence_scans: Cell::new(0),
            #[cfg(test)]
            loss_detection_steps: Cell::new(0),
        }
    }

    /// Enable/disable TSBPD.
    pub fn set_tsbpd_enabled(&mut self, enabled: bool) {
        self.tsbpd_enabled = enabled;
    }

    #[cfg(test)]
    pub(crate) fn tsbpd_enabled(&self) -> bool {
        self.tsbpd_enabled
    }

    /// Get the next expected sequence number.
    pub fn expected_sequence(&self) -> u32 {
        self.expected_seq
    }

    /// Forcibly advance the next expected sequence number to at least
    /// `sequence_number`, discarding buffered packets and loss-list entries
    /// that fall below it. A no-op if `sequence_number` is not ahead of the
    /// current expected sequence.
    pub fn advance_expected_sequence(&mut self, sequence_number: u32) {
        if !sequence_greater_than(sequence_number, self.expected_seq) {
            return;
        }

        // A forced advance intentionally accounts for every skipped position
        // without declaring it lost. Keep the classification interval
        // contiguous so a later packet cannot rediscover the skipped range.
        let skipped_through = sequence_number.wrapping_sub(1) & 0x7FFF_FFFF;
        if sequence_greater_than(skipped_through, self.loss_detection_frontier) {
            self.loss_detection_frontier = skipped_through;
        }

        self.packets
            .retain(|&seq, _| !sequence_less_than(seq, sequence_number));
        self.refresh_delivery_seq_hint();
        let stale_losses: Vec<u32> = self
            .loss_list
            .iter()
            .filter(|&seq| sequence_less_than(seq, sequence_number))
            .collect();
        for seq in stale_losses {
            self.loss_list.remove(seq);
        }
        self.expected_seq = sequence_number;
        while self.packets.contains_key(&self.expected_seq) {
            self.expected_seq = self.expected_seq.wrapping_add(1) & 0x7FFF_FFFF;
        }
        self.loss_list.set_base(self.expected_seq);
    }

    /// Receive a packet.
    ///
    /// Returns the newly exposed loss range, if any.
    pub fn receive(&mut self, packet: DataPacket, now: Timestamp) -> Option<LossRange> {
        let seq = packet.sequence_number;
        let was_expected = seq == self.expected_seq;
        let packet_size = packet.payload.len() + SRT_HEADER_SIZE;
        self.total_data_packets_received = self.total_data_packets_received.saturating_add(1);
        self.total_srt_bytes_received = self
            .total_srt_bytes_received
            .saturating_add(packet_size as u64);
        if packet.retransmitted {
            self.total_retransmitted = self.total_retransmitted.saturating_add(1);
        }

        if self.packets.contains_key(&seq) {
            self.total_duplicates += 1;
            return None;
        }

        if sequence_less_than(seq, self.expected_seq) {
            self.total_duplicates = self.total_duplicates.saturating_add(1);
            return None;
        }

        // Reject sequence numbers further than the flow window ahead of
        // expected_seq — a conforming sender never exceeds this gap, so a
        // larger one indicates a corrupted or malicious packet.
        if seq.wrapping_sub(self.expected_seq) & 0x7FFF_FFFF > self.max_buffer_size {
            return None;
        }

        self.total_received += 1;
        self.packets_since_ack += 1;

        self.record_arrival(now, packet_size);
        self.update_jitter(now, packet.timestamp);
        self.check_tsbpd_wrap(packet.timestamp);

        if self
            .delivery_seq_hint
            .is_none_or(|hint| sequence_less_than(seq, hint))
        {
            self.delivery_seq_hint = Some(seq);
        }

        let new_loss_range = self.detect_losses(seq);

        self.packets.insert(
            seq,
            ReceivedPacket {
                position: packet.position,
                order_flag: packet.order_flag,
                message_number: packet.message_number,
                timestamp: packet.timestamp,
                payload: packet.payload,
                recv_time: now,
            },
        );

        let recovered_loss = self.loss_list.remove(seq);
        self.advance_expected_seq(was_expected, recovered_loss);

        new_loss_range
    }

    fn record_arrival(&mut self, now: Timestamp, packet_size: usize) {
        self.total_bytes_received += packet_size as u64;
        self.rate_estimator.on_packet_received(now, packet_size);
        self.link_capacity_estimator.on_packet_received(now);
    }

    fn update_jitter(&mut self, now: Timestamp, packet_timestamp: u32) {
        let transit = now.as_micros() as i64 - packet_timestamp as i64;
        if let Some(last) = self.last_transit {
            let d = (transit - last).unsigned_abs() as u32;
            self.jitter = self
                .jitter
                .saturating_add((d.saturating_sub(self.jitter)) / 16);
        }
        self.last_transit = Some(transit);
    }

    fn check_tsbpd_wrap(&mut self, packet_timestamp: u32) {
        if self.tsbpd_enabled {
            let ts = packet_timestamp as u64;
            if ts >= WRAPPING_PERIOD_START && !self.wrapping_period_active {
                self.wrapping_period_active = true;
            }
        }
    }

    /// Classify the newly exposed interval ending at received packet `seq`.
    ///
    /// The frontier makes the cost proportional to sequence positions exposed
    /// for the first time. An old unresolved hole is never revisited merely
    /// because later in-order packets continue to arrive.
    fn detect_losses(&mut self, seq: u32) -> Option<LossRange> {
        if !sequence_greater_than(seq, self.loss_detection_frontier) {
            return None;
        }

        let first = self.loss_detection_frontier.wrapping_add(1) & SEQUENCE_MASK;
        let count = seq.wrapping_sub(first) & SEQUENCE_MASK;
        let inserted = self.loss_list.insert_range(first, count);
        debug_assert_eq!(
            inserted, count,
            "newly classified losses must fit in the receiver loss bitmap"
        );
        #[cfg(test)]
        self.loss_detection_steps.set(
            self.loss_detection_steps
                .get()
                .saturating_add(count as usize),
        );
        self.total_lost += u64::from(count);
        self.loss_detection_frontier = seq;
        (count != 0).then(|| LossRange {
            first_seq: first,
            last_seq: seq.wrapping_sub(1) & SEQUENCE_MASK,
        })
    }

    fn advance_expected_seq(&mut self, was_expected: bool, recovered_loss: bool) {
        if was_expected && !recovered_loss {
            self.expected_seq = self.expected_seq.wrapping_add(1) & 0x7FFF_FFFF;
        } else if was_expected {
            #[cfg(test)]
            self.receive_expected_sequence_scans
                .set(self.receive_expected_sequence_scans.get().saturating_add(1));
            while self.packets.contains_key(&self.expected_seq) {
                self.expected_seq = self.expected_seq.wrapping_add(1) & 0x7FFF_FFFF;
            }
        }
        self.loss_list.set_base(self.expected_seq);
    }

    fn packet_base_time(&self, timestamp: u32) -> u64 {
        self.tsbpd_time_base
            .saturating_add(timestamp as u64)
            .saturating_add(
                if self.wrapping_period_active && (timestamp as u64) < WRAPPING_PERIOD_START {
                    MAX_TIMESTAMP + 1
                } else {
                    0
                },
            )
    }

    fn delivery_time(&self, entry: &ReceivedPacket) -> Timestamp {
        if !self.tsbpd_enabled {
            return entry.recv_time;
        }

        let base_and_delay = self
            .packet_base_time(entry.timestamp)
            .saturating_add(self.tsbpd_delay_us);
        Timestamp::from_micros(base_and_delay.saturating_add_signed(self.drift_tracer.drift_us()))
    }

    /// Get a deliverable packet (TSBPD).
    pub fn pop_ready(&mut self, now: Timestamp) -> Option<DataPacket> {
        // Find a deliverable sequence number.
        let delivery_seq = self.find_deliverable_seq(now)?;

        let entry = self.packets.remove(&delivery_seq)?;
        if self.delivery_seq_hint == Some(delivery_seq) {
            self.delivery_seq_hint = self.next_sequence_after(delivery_seq);
        }

        // Detect the end of the TSBPD wraparound period.
        // Per spec (draft-sharabayko-srt.md, #tsbpd-time-base section):
        // "ends once the packet with timestamp within (30, 60) seconds interval is delivered".
        // libsrt treats the upper endpoint as inclusive, which we mirror for
        // trace-level compatibility.
        if self.tsbpd_enabled && self.wrapping_period_active {
            let ts = entry.timestamp as u64;
            if (WRAPPING_PERIOD_END_MIN..=WRAPPING_PERIOD_END_MAX).contains(&ts) {
                self.tsbpd_time_base += MAX_TIMESTAMP + 1;
                self.wrapping_period_active = false;
            }
        }

        Some(DataPacket {
            sequence_number: delivery_seq,
            position: entry.position,
            order_flag: entry.order_flag,
            encryption_flag: 0,
            retransmitted: false,
            message_number: entry.message_number,
            timestamp: entry.timestamp,
            dest_socket_id: 0,
            payload: entry.payload,
        })
    }

    /// Find the deliverable sequence number.
    ///
    /// BTreeMap iterates in numeric order, but 31-bit sequence numbers use
    /// circular order with wrap at 0x7FFF_FFFF. SRT spec says TSBPD delivers
    /// "in order, but based on timestamps" -- delivery must follow circular
    /// order, not numeric. Returning the first numeric candidate would
    /// invert order across the wrap, so pick the circular minimum.
    ///
    /// If the circular minimum packet is deliverable, return it directly.
    /// If the minimum packet's delivery time hasn't arrived, fall back to
    /// a full candidate scan to preserve out-of-order timestamp handling.
    ///
    /// `has_gap` uses the loss bitmap's bounded summary lookup -- "is there a
    /// loss before seq" is equivalent to "is the circular minimum before
    /// seq". This avoids scanning every loss for every packet candidate.
    fn find_deliverable_seq(&self, now: Timestamp) -> Option<u32> {
        let loss_list_min = self.loss_list.first();
        // Fast path 1: hint is deliverable right now (no gap before it).
        if let Some(seq) = self.delivery_seq_hint
            && let Some(entry) = self.packets.get(&seq)
            && (!self.tsbpd_enabled || self.delivery_time(entry) <= now)
            && !loss_list_min.is_some_and(|min| sequence_less_than(min, seq))
        {
            return Some(seq);
        }

        // Ordered storage gives the loss-recovery steady state an O(log n)
        // oldest-packet lookup. Across sequence wrap, fall back to the full
        // circular comparison below.
        if let (Some(min), Some(&oldest)) = (loss_list_min, self.packets.keys().next())
            && !sequence_less_than(min, oldest)
            && oldest >= self.expected_seq
        {
            let entry = &self.packets[&oldest];
            if !self.tsbpd_enabled || self.delivery_time(entry) <= now {
                return Some(oldest);
            }
            return None;
        }

        #[cfg(test)]
        self.delivery_scan_calls
            .set(self.delivery_scan_calls.get().saturating_add(1));

        let mut best: Option<u32> = None;
        for (&seq, entry) in &self.packets {
            let time_ok = !self.tsbpd_enabled || self.delivery_time(entry) <= now;
            let has_gap = loss_list_min.is_some_and(|min| sequence_less_than(min, seq));
            if time_ok && !has_gap {
                // Keep the circularly earlier of best and seq.
                best = match best {
                    Some(b) if sequence_less_than(b, seq) => Some(b),
                    _ => Some(seq),
                };
            }
        }
        best
    }

    /// Return the nearest buffered sequence strictly after `sequence_number`
    /// in the 31-bit circular sequence space.
    fn next_sequence_after(&self, sequence_number: u32) -> Option<u32> {
        let next = sequence_number.wrapping_add(1) & 0x7FFF_FFFF;
        self.packets
            .range(next..)
            .next()
            .map(|(&seq, _)| seq)
            .or_else(|| self.packets.keys().next().copied())
    }

    fn refresh_delivery_seq_hint(&mut self) {
        self.delivery_seq_hint = self
            .packets
            .keys()
            .copied()
            .reduce(|a, b| if sequence_less_than(a, b) { a } else { b });
    }

    #[cfg(test)]
    fn delivery_scan_calls(&self) -> usize {
        self.delivery_scan_calls.get()
    }

    #[cfg(test)]
    fn receive_expected_sequence_scans(&self) -> usize {
        self.receive_expected_sequence_scans.get()
    }

    #[cfg(test)]
    fn loss_detection_steps(&self) -> usize {
        self.loss_detection_steps.get()
    }

    /// Whether the current ACK position was already confirmed by an ACKACK.
    ///
    /// Spec §4.8.1: "The ACKACK tells the receiver to stop sending the ACK
    /// position because the sender already knows it. Otherwise, ACKs (with
    /// outdated information) would continue to be sent regularly." Mirrors
    /// libsrt's `m_iRcvLastAckAck == ack` suppression check
    /// (`sendCtrl(UMSG_ACK)`, `core.cpp:8364`).
    fn position_already_ackacked(&self) -> bool {
        self.last_ackacked_number == Some(self.ack_number)
            && self.last_ackacked_seq == Some(self.expected_seq)
    }

    /// Check whether an ACK should be generated.
    pub fn should_send_ack(&self, now: Timestamp) -> bool {
        // Light ACK: every 64 packets received. At high packet rates the
        // acknowledged position advances between ACKACKs, so a light ACK is
        // never stale.
        if self.packets_since_ack >= LIGHT_ACK_INTERVAL {
            return true;
        }

        // Periodic ACK: every 10ms.
        let elapsed = now
            .as_micros()
            .saturating_sub(self.last_ack_time.as_micros());
        if elapsed < ACK_INTERVAL_US {
            return false;
        }

        // Suppress the periodic ACK while the acknowledged position is
        // unchanged and the advertised buffer space has not changed either:
        // available_buffer_packets only differs from the last full ACK when
        // packets were delivered or dropped since, which is exactly the
        // buffer-freed full-ACK exception libsrt keeps (`bNeedFullAck`,
        // `core.cpp:8357`) so the sender's flow window reopens.
        !(self.position_already_ackacked()
            && self.available_buffer_packets() == self.last_advertised_buffer)
    }

    /// Generate an ACK.
    pub fn generate_ack(&mut self, now: Timestamp) -> AckPacket {
        let is_light = self.packets_since_ack >= LIGHT_ACK_INTERVAL
            && now
                .as_micros()
                .saturating_sub(self.last_ack_time.as_micros())
                < ACK_INTERVAL_US;

        self.last_ack_time = now;
        self.last_ack_seq = self.expected_seq;
        self.packets_since_ack = 0;

        if !is_light {
            self.ack_number = self.ack_number.wrapping_add(1);
            self.ack_timestamps
                .record(self.ack_number, now, self.expected_seq);
        }
        self.last_advertised_buffer = self.available_buffer_packets();

        // Calculate the receiving rate and link capacity.
        let (receiving_rate, recv_rate) = self.rate_estimator.calculate_rates(now);
        let link_capacity = self.link_capacity_estimator.calculate_capacity();

        AckPacket {
            ack_seq: self.expected_seq,
            rtt: self.rtt,
            rtt_var: self.rtt_var,
            available_buffer: self.available_buffer_packets(),
            receiving_rate,
            link_capacity,
            recv_rate,
            is_light,
        }
    }

    /// Update application-owned receive occupancy maintained by the owning
    /// connection as it queues and polls `DataReceived` events.
    pub(crate) fn set_application_backlog_packets(&mut self, packets: u32) {
        self.application_backlog_packets = packets.min(self.max_buffer_size);
    }

    fn available_buffer_packets(&self) -> u32 {
        self.max_buffer_size
            .saturating_sub(self.packets.len() as u32)
            .saturating_sub(self.application_backlog_packets)
    }

    /// Generate a periodic NAK.
    pub fn generate_periodic_nak(&self) -> Option<NakPacket> {
        if self.loss_list.is_empty() {
            return None;
        }

        let mut loss_ranges = Vec::new();
        self.loss_list.for_each_numeric_run(|start, end| {
            loss_ranges.push(LossRange {
                first_seq: start,
                last_seq: end,
            });
        });

        Some(NakPacket { loss_ranges })
    }

    pub(crate) fn for_each_periodic_nak_range(&self, mut emit: impl FnMut(LossRange)) {
        self.loss_list.for_each_numeric_run(|first_seq, last_seq| {
            emit(LossRange {
                first_seq,
                last_seq,
            });
        });
    }

    /// Calculate the NAK send interval: (RTT + 4*RTTVar) / 2.
    pub fn nak_interval(&self) -> u64 {
        let interval = (self.rtt as u64 + 4 * self.rtt_var as u64) / 2;
        interval.max(20_000) // Minimum 20ms.
    }

    /// Process an ACKACK and update RTT.
    pub fn handle_ackack(&mut self, ack_number: u32, packet_timestamp: u32, now: Timestamp) {
        // Look up the ACK's send time.
        let rtt_sample = self
            .ack_timestamps
            .get_send_time(ack_number)
            .and_then(|send_time| {
                let rtt = (now.as_micros().saturating_sub(send_time.as_micros())) as u32;
                (rtt != 0 && rtt <= 30_000_000).then_some(rtt)
            });

        // The peer confirmed this ACK position; remember it so
        // should_send_ack can suppress redundant periodic ACKs (§4.8.1).
        if let Some(acked_seq) = self.ack_timestamps.get_acked_seq(ack_number) {
            self.last_ackacked_number = Some(ack_number);
            self.last_ackacked_seq = Some(acked_seq);
        }

        if let Some(rtt) = rtt_sample {
            // Smooth with EWMA: RTT = 7/8 * RTT + 1/8 * rtt
            self.rtt = (self.rtt * 7 / 8) + (rtt / 8);

            // RTTVar = 3/4 * RTTVar + 1/4 * |RTT - rtt|
            let diff = self.rtt.abs_diff(rtt);
            self.rtt_var = (self.rtt_var * 3 / 4) + (diff / 4);
        }

        if !self.tsbpd_enabled {
            return;
        }

        if self.first_rtt_sample.is_none() {
            self.first_rtt_sample = rtt_sample;
        }
        let rtt_delta = rtt_sample
            .zip(self.first_rtt_sample)
            .map_or(0, |(sample, first)| i64::from(sample) - i64::from(first))
            / 2;
        let drift_sample =
            now.as_micros() as i64 - self.packet_base_time(packet_timestamp) as i64 - rtt_delta;
        if self.drift_tracer.update(drift_sample) {
            self.tsbpd_time_base = self
                .tsbpd_time_base
                .saturating_add_signed(self.drift_tracer.overdrift_us());
        }
    }

    /// Remove expired packets (TLPKTDROP).
    pub fn drop_too_late(&mut self, now: Timestamp) -> Vec<u32> {
        if !self.tsbpd_enabled {
            return Vec::new();
        }

        let tlpktdrop_threshold = ((self.tsbpd_delay_us as u128 * 125 / 100) as u64).max(1_000_000); // Minimum 1 second.

        let mut dropped = Vec::new();

        let expired: Vec<u32> = self
            .loss_list
            .iter()
            .filter(|&seq| {
                let estimated_delivery = self
                    .packets
                    .get(&seq)
                    .map(|packet| self.delivery_time(packet).as_micros())
                    .unwrap_or_else(|| {
                        let next_packet = self
                            .packets
                            .range(seq.wrapping_add(1)..)
                            .next()
                            .or_else(|| self.packets.iter().next());
                        next_packet.map_or_else(
                            || {
                                let base = self.tsbpd_time_base + self.tsbpd_delay_us;
                                if self.wrapping_period_active {
                                    base + MAX_TIMESTAMP + 1
                                } else {
                                    base
                                }
                            },
                            |(_, entry)| self.delivery_time(entry).as_micros(),
                        )
                    });
                now.as_micros() > estimated_delivery + tlpktdrop_threshold
            })
            .collect();

        for seq in expired {
            self.loss_list.remove(seq);
            dropped.push(seq);
        }

        self.total_dropped = self.total_dropped.saturating_add(dropped.len() as u64);

        if !dropped.is_empty() {
            let dropped_set: FxHashSet<u32> = dropped.iter().copied().collect();
            while self.packets.contains_key(&self.expected_seq)
                || dropped_set.contains(&self.expected_seq)
            {
                self.expected_seq = self.expected_seq.wrapping_add(1) & 0x7FFF_FFFF;
            }
            self.loss_list.set_base(self.expected_seq);
        }

        dropped
    }

    /// Validate a 31-bit inclusive DROPREQ range against this receiver's
    /// negotiated window without allocating or iterating over the range.
    pub(crate) fn validate_drop_range(&self, first_seq: u32, last_seq: u32) -> Result<u32, Error> {
        if first_seq & !SEQUENCE_MASK != 0 || last_seq & !SEQUENCE_MASK != 0 {
            return Err(Error::invalid_data("DROPREQ sequence has high bit set"));
        }

        let distance = last_seq.wrapping_sub(first_seq) & SEQUENCE_MASK;
        if distance >= self.max_buffer_size {
            return Err(Error::invalid_data(
                "DROPREQ range exceeds receive buffer window",
            ));
        }

        if sequence_greater_than(first_seq, self.expected_seq)
            && first_seq.wrapping_sub(self.expected_seq) & SEQUENCE_MASK > self.max_buffer_size
        {
            return Err(Error::invalid_data(
                "DROPREQ begins beyond the expected receive window",
            ));
        }

        // A request beginning beyond the classified receive window is not a
        // credible sender transition. Reject it before loss classification so
        // an attacker cannot turn a short, valid-length DROPREQ into a walk of
        // an arbitrarily large 31-bit sequence gap.
        if sequence_greater_than(first_seq, self.loss_detection_frontier) {
            let frontier_distance =
                first_seq.wrapping_sub(self.loss_detection_frontier) & SEQUENCE_MASK;
            if frontier_distance > self.max_buffer_size.saturating_add(1) {
                return Err(Error::invalid_data(
                    "DROPREQ begins beyond receive buffer window",
                ));
            }
        }

        Ok(distance)
    }

    /// Drop all packets in the 31-bit sequence range `[first_seq, last_seq]`
    /// from both the packet buffer and the loss list (DROPREQ path).
    ///
    /// The inclusive range must fit within the negotiated receive window so
    /// this method cannot be used to force unbounded iteration or allocation.
    pub fn drop_range(&mut self, first_seq: u32, last_seq: u32) -> Result<DropRangeSummary, Error> {
        let distance = self.validate_drop_range(first_seq, last_seq)?;
        let sequence_count = distance + 1;
        let hint_was_dropped = self
            .delivery_seq_hint
            .is_some_and(|seq| sequence_in_range(first_seq, distance, seq));

        // A DROPREQ can be the first evidence of sequence progress beyond the
        // classification frontier. Any intervening positions are genuine
        // newly exposed losses; the requested interval itself is accounted as
        // dropped and must never be rediscovered by a later packet.
        self.advance_drop_frontier(first_seq, last_seq);

        // Remove only packet keys that lie in the requested numeric interval.
        // A circular range has at most two such intervals. Repeating a range
        // successor lookup after each removal is O(k log n), where k is the
        // number of requested sequence positions (bounded by the negotiated
        // receive window), independent of unrelated retained TSBPD packets.
        let packets_removed = self.remove_drop_packets(first_seq, last_seq);
        let losses_removed = self.remove_drop_losses(first_seq, sequence_count);

        if hint_was_dropped {
            self.delivery_seq_hint = self.next_sequence_after(last_seq);
        }

        self.total_dropped = self.total_dropped.saturating_add(u64::from(sequence_count));
        self.advance_expected_after_drop(first_seq, distance);
        Ok(DropRangeSummary {
            sequence_count,
            packets_removed,
            losses_removed,
        })
    }

    fn advance_drop_frontier(&mut self, first_seq: u32, last_seq: u32) {
        if sequence_greater_than(last_seq, self.loss_detection_frontier) {
            if sequence_greater_than(first_seq, self.loss_detection_frontier) {
                let _ = self.detect_losses(first_seq);
            }
            self.loss_detection_frontier = last_seq;
        }
    }

    fn remove_drop_packets(&mut self, first_seq: u32, last_seq: u32) -> u32 {
        let mut packets_removed = 0;
        if first_seq <= last_seq {
            while let Some(seq) = self
                .packets
                .range(first_seq..=last_seq)
                .next()
                .map(|(&seq, _)| seq)
            {
                self.packets.remove(&seq);
                packets_removed += 1;
            }
        } else {
            while let Some(seq) = self.packets.range(first_seq..).next().map(|(&seq, _)| seq) {
                self.packets.remove(&seq);
                packets_removed += 1;
            }
            while let Some(seq) = self.packets.range(..=last_seq).next().map(|(&seq, _)| seq) {
                self.packets.remove(&seq);
                packets_removed += 1;
            }
        }
        packets_removed
    }

    fn remove_drop_losses(&mut self, first_seq: u32, sequence_count: u32) -> u32 {
        self.loss_list.remove_range(first_seq, sequence_count)
    }

    fn advance_expected_after_drop(&mut self, first_seq: u32, distance: u32) {
        while self.packets.contains_key(&self.expected_seq)
            || sequence_in_range(first_seq, distance, self.expected_seq)
        {
            self.expected_seq = self.expected_seq.wrapping_add(1) & SEQUENCE_MASK;
        }
        self.loss_list.set_base(self.expected_seq);
    }

    /// Get the current ACK sequence number.
    pub fn ack_number(&self) -> u32 {
        self.ack_number
    }

    /// Get RTT.
    pub fn rtt(&self) -> u32 {
        self.rtt
    }

    /// Get RTT variance.
    pub fn rtt_var(&self) -> u32 {
        self.rtt_var
    }

    pub(crate) fn record_ack_sent(&mut self) {
        self.total_acks_sent = self.total_acks_sent.saturating_add(1);
    }

    pub(crate) fn record_nak_sent(&mut self) {
        self.total_naks_sent = self.total_naks_sent.saturating_add(1);
    }

    pub(crate) fn record_undecryptable(&mut self) {
        self.total_undecryptable = self.total_undecryptable.saturating_add(1);
    }

    /// Get statistics.
    pub fn stats(&self) -> ReceiverStats {
        // Calculate the packet loss rate (percent * 100).
        // total_received also includes recovered packets, so
        // loss rate = total_lost / (total_received + total_lost) * 100 * 100
        let total = self.total_received + self.total_lost;
        let loss_rate_percent_x100 =
            (self.total_lost * 10000).checked_div(total).unwrap_or(0) as u32;

        // One pass for all three. The buffer runs to `max_buffer_size`
        // (8192 packets by default) and this is sampled periodically per
        // connection, so walking it three times costs two extra full
        // traversals of the packet map per sample.
        //
        // The span cannot use `next()`/`next_back()` the way the sender's
        // does: this map is keyed by sequence number, and `delivery_time`
        // is not monotonic in that order once packets are reordered or
        // retransmitted.
        let mut payload_bytes_in_buffer = 0u64;
        let mut oldest_delivery: Option<u64> = None;
        let mut newest_delivery: Option<u64> = None;
        for entry in self.packets.values() {
            payload_bytes_in_buffer += entry.payload.len() as u64;
            let delivery = self.delivery_time(entry).as_micros();
            oldest_delivery = Some(oldest_delivery.map_or(delivery, |old: u64| old.min(delivery)));
            newest_delivery = Some(newest_delivery.map_or(delivery, |new: u64| new.max(delivery)));
        }
        let buffer_span_micros = oldest_delivery
            .zip(newest_delivery)
            .map_or(0, |(oldest, newest)| newest.saturating_sub(oldest));

        ReceiverStats {
            packets_in_buffer: self.packets.len() as u32,
            payload_bytes_in_buffer,
            packets_in_loss_list: self.loss_list.len() as u32,
            available_buffer_packets: self.available_buffer_packets(),
            available_buffer_bytes: None,
            max_buffer_packets: self.max_buffer_size,
            buffer_span_micros,
            total_received: self.total_received,
            total_data_packets_received: self.total_data_packets_received,
            total_lost: self.total_lost,
            total_duplicates: self.total_duplicates,
            total_retransmitted: self.total_retransmitted,
            total_dropped: self.total_dropped,
            total_undecryptable: self.total_undecryptable,
            total_acks_sent: self.total_acks_sent,
            total_naks_sent: self.total_naks_sent,
            rtt: self.rtt,
            rtt_var: self.rtt_var,
            total_bytes_received: self.total_bytes_received,
            total_srt_bytes_received: self.total_srt_bytes_received,
            loss_rate_percent_x100,
            jitter: self.jitter,
            receiving_rate_packets_per_second: self.rate_estimator.estimated_packet_rate,
            receiving_rate_bytes_per_second: self.rate_estimator.estimated_byte_rate,
            link_capacity_packets_per_second: self.link_capacity_estimator.estimated_capacity,
            link_capacity_bytes_per_second: {
                let packet_rate = u64::from(self.rate_estimator.estimated_packet_rate);
                (packet_rate > 0).then(|| {
                    u64::from(self.link_capacity_estimator.estimated_capacity)
                        .saturating_mul(u64::from(self.rate_estimator.estimated_byte_rate))
                        / packet_rate
                })
            },
            tsbpd_delay_micros: self.tsbpd_delay_us,
        }
    }
}

/// Receiver statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiverStats {
    /// Number of packets in the buffer.
    pub packets_in_buffer: u32,
    /// Exact payload-byte occupancy of the local receive buffer.
    pub payload_bytes_in_buffer: u64,
    /// Number of packets in the loss list.
    pub packets_in_loss_list: u32,
    /// Remaining receive-buffer capacity, in packets.
    pub available_buffer_packets: u32,
    /// Byte capacity is unavailable because the receive-buffer limit is packets.
    pub available_buffer_bytes: Option<u64>,
    /// Configured receive-buffer capacity, in packets.
    pub max_buffer_packets: u32,
    /// Timestamp span represented by packets currently buffered.
    pub buffer_span_micros: u64,
    /// Unique DATA packets accepted for delivery.
    pub total_received: u64,
    /// All decrypted DATA packets received, including retransmissions and duplicates.
    pub total_data_packets_received: u64,
    /// Total packets lost.
    pub total_lost: u64,
    /// Total duplicate packets.
    pub total_duplicates: u64,
    /// Accepted packets carrying the retransmission bit.
    pub total_retransmitted: u64,
    /// Missing packets abandoned by TLPKTDROP.
    pub total_dropped: u64,
    /// Encrypted packets rejected because they could not be decrypted.
    pub total_undecryptable: u64,
    /// ACK control packets sent.
    pub total_acks_sent: u64,
    /// NAK control packets sent.
    pub total_naks_sent: u64,
    /// RTT (microseconds).
    pub rtt: u32,
    /// RTT variance (microseconds).
    pub rtt_var: u32,
    /// SRT datagram bytes in unique DATA packets accepted for delivery.
    pub total_bytes_received: u64,
    /// SRT datagram bytes received, including retransmissions and duplicates.
    ///
    /// This excludes caller-owned IP and UDP headers.
    pub total_srt_bytes_received: u64,
    /// Packet loss rate (percent * 100, e.g. 123 = 1.23%).
    pub loss_rate_percent_x100: u32,
    /// Jitter (microseconds).
    pub jitter: u32,
    /// Smoothed local receive rate in packets per second.
    pub receiving_rate_packets_per_second: u32,
    /// Smoothed local wire receive rate in bytes per second.
    pub receiving_rate_bytes_per_second: u32,
    /// Packet-pair link-capacity estimate in packets per second.
    pub link_capacity_packets_per_second: u32,
    /// Link-capacity estimate converted using measured wire bytes per packet.
    pub link_capacity_bytes_per_second: Option<u64>,
    /// Configured receiver TSBPD delay.
    pub tsbpd_delay_micros: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loss_set(buf: &ReceiverBuffer) -> FxHashSet<u32> {
        buf.loss_list.iter().collect()
    }

    fn loss_range(first_seq: u32, last_seq: u32) -> LossRange {
        LossRange {
            first_seq,
            last_seq,
        }
    }

    #[test]
    fn loss_range_iterates_in_circular_order() {
        let range = loss_range(0x7FFF_FFFE, 1);
        assert_eq!(range.sequence_count(), 4);
        assert_eq!(
            range.iter().collect::<Vec<_>>(),
            vec![0x7FFF_FFFE, 0x7FFF_FFFF, 0, 1]
        );
    }

    fn make_packet(seq: u32, timestamp: u32) -> DataPacket {
        DataPacket {
            sequence_number: seq,
            position: crate::srt_packet::PacketPosition::Single,
            order_flag: false,
            encryption_flag: 0,
            retransmitted: false,
            message_number: 1,
            timestamp,
            dest_socket_id: 1,
            payload: vec![1, 2, 3].into(),
        }
    }

    #[test]
    fn loss_bitmap_allocates_lazily_and_tracks_first_loss() {
        let mut losses = LossBitmap::new(100, 128);
        assert!(losses.storage.is_empty());
        assert_eq!(losses.first(), None);

        assert!(losses.insert(102));
        assert!(losses.insert(100));
        assert!(losses.insert(165));
        assert!(!losses.insert(102));
        assert_eq!(losses.len(), 3);
        assert_eq!(losses.first(), Some(100));

        assert!(losses.remove(100));
        assert_eq!(losses.first(), Some(102));
        assert_eq!(
            losses.iter().collect::<FxHashSet<_>>(),
            FxHashSet::from_iter([102, 165])
        );
    }

    #[test]
    fn default_loss_bitmap_heap_footprint_stays_bounded() {
        let mut losses = LossBitmap::new(0, DEFAULT_FLOW_WINDOW);
        assert_eq!(losses.storage.capacity(), 0);
        assert!(losses.insert(0));
        let bytes = losses.storage.capacity() * std::mem::size_of::<u64>();
        eprintln!("default LossBitmap heap footprint: {bytes} bytes");
        assert!(
            bytes <= 1_100,
            "default loss bitmap exceeded its heap budget: {bytes} bytes"
        );
    }

    #[test]
    fn maximum_loss_bitmap_heap_footprint_stays_bounded() {
        let mut losses = LossBitmap::new(0, MAX_FLOW_WINDOW);
        assert!(losses.insert(0));
        let logical_bytes = losses.storage.len() * std::mem::size_of::<u64>();
        eprintln!("maximum LossBitmap logical heap footprint: {logical_bytes} bytes");
        assert_eq!(logical_bytes, 8_320);
    }

    #[test]
    fn loss_bitmap_range_ops_and_runs_cross_words_and_sequence_wrap() {
        let base = SEQUENCE_MASK - 100;
        let mut losses = LossBitmap::new(base, 200);
        let first = SEQUENCE_MASK - 90;

        assert_eq!(losses.insert_range(first, 130), 130);
        assert_eq!(losses.insert_range(first, 130), 0);
        let mut runs = Vec::new();
        losses.for_each_numeric_run(|start, end| runs.push((start, end)));
        assert_eq!(runs, vec![(0, 38), (first, SEQUENCE_MASK)]);

        assert_eq!(losses.remove_range(SEQUENCE_MASK - 20, 41), 41);
        let mut runs = Vec::new();
        losses.for_each_numeric_run(|start, end| runs.push((start, end)));
        assert_eq!(
            runs,
            vec![(20, 38), (first, SEQUENCE_MASK - 21)],
            "numeric NAK runs stay sorted while the logical window wraps"
        );
        assert_eq!(losses.len(), 89);
    }

    #[test]
    fn loss_bitmap_range_removal_intersects_a_range_starting_before_base() {
        let mut losses = LossBitmap::new(100, 100);
        assert_eq!(losses.insert_range(100, 100), 100);
        assert_eq!(losses.remove_range(95, 20), 15);
        assert_eq!(losses.first(), Some(115));
        assert_eq!(losses.len(), 85);
    }

    #[test]
    fn loss_bitmap_matches_set_for_non_power_of_two_windows() {
        for window_size in [65, 100, 127, 129, 1_000, 8_191, 8_193] {
            for base_seq in [61, SEQUENCE_MASK - 3] {
                let mut losses = LossBitmap::new(base_seq, window_size);
                let mut expected = FxHashSet::default();

                for offset in (0..window_size).step_by(3) {
                    let seq = base_seq.wrapping_add(offset) & SEQUENCE_MASK;
                    assert_eq!(losses.insert(seq), expected.insert(seq));
                }
                for offset in (0..window_size).step_by(9) {
                    let seq = base_seq.wrapping_add(offset) & SEQUENCE_MASK;
                    assert_eq!(losses.remove(seq), expected.remove(&seq));
                }

                let advanced_base = base_seq.wrapping_add(window_size / 4) & SEQUENCE_MASK;
                let stale: Vec<u32> = expected
                    .iter()
                    .copied()
                    .filter(|&seq| seq.wrapping_sub(advanced_base) & SEQUENCE_MASK >= window_size)
                    .collect();
                for seq in stale {
                    assert!(losses.remove(seq));
                    expected.remove(&seq);
                }
                losses.set_base(advanced_base);
                for offset in (0..window_size).rev().step_by(5) {
                    let seq = advanced_base.wrapping_add(offset) & SEQUENCE_MASK;
                    assert_eq!(losses.insert(seq), expected.insert(seq));
                }

                assert_eq!(losses.iter().collect::<FxHashSet<_>>(), expected);
                let first = expected
                    .iter()
                    .copied()
                    .min_by_key(|&seq| seq.wrapping_sub(advanced_base) & SEQUENCE_MASK);
                assert_eq!(losses.first(), first);
            }
        }
    }

    #[test]
    fn loss_bitmap_wraps_without_aliasing_old_sequences() {
        let mut losses = LossBitmap::new(0x7FFF_FFFE, 64);
        for seq in [0x7FFF_FFFE, 0x7FFF_FFFF, 0, 1] {
            assert!(losses.insert(seq));
        }
        assert_eq!(losses.first(), Some(0x7FFF_FFFE));

        assert!(losses.remove(0x7FFF_FFFE));
        losses.set_base(0x7FFF_FFFF);
        assert_eq!(losses.first(), Some(0x7FFF_FFFF));
        assert!(!losses.remove(63));
        assert!(losses.contains(&0x7FFF_FFFF));
    }

    #[test]
    fn test_receiver_buffer_new() {
        let start = Timestamp::from_micros(0);
        let buf = ReceiverBuffer::new(1000, 120, start, 0);
        assert_eq!(buf.expected_sequence(), 1000);
    }

    #[test]
    fn test_receiver_buffer_receive_in_order() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 順序通りに受信
        let losses = buf.receive(make_packet(1000, 100), now);
        assert!(losses.is_none());
        assert_eq!(buf.expected_sequence(), 1001);

        let losses = buf.receive(make_packet(1001, 200), now);
        assert!(losses.is_none());
        assert_eq!(buf.expected_sequence(), 1002);
    }

    #[test]
    fn pop_ready_moves_the_received_bytes_allocation() {
        let start = Timestamp::from_micros(0);
        let now = Timestamp::from_micros(1_000);
        let mut receiver = ReceiverBuffer::new(1000, 120, start, 0);
        receiver.set_tsbpd_enabled(false);
        let payload = Bytes::from_static(b"shared receiver payload");
        let expected_ptr = payload.as_ptr();
        receiver.receive(DataPacket::new(1000, 1, 100, 1, payload), now);

        let delivered = receiver.pop_ready(now).expect("packet is ready");
        assert_eq!(delivered.payload.as_ptr(), expected_ptr);
        assert_eq!(delivered.payload.as_ref(), b"shared receiver payload");
    }

    #[test]
    fn test_receiver_buffer_loss_detection() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 1000 を受信
        buf.receive(make_packet(1000, 100), now);
        // 1001 をスキップして 1002 を受信
        let losses = buf.receive(make_packet(1002, 300), now);

        assert!(losses.is_some());
        let lost = losses.expect("欠落パケットは Some になる想定");
        assert_eq!(lost, loss_range(1001, 1001));
    }

    /// A single packet whose sequence number is far beyond the flow
    /// window must be rejected outright, not treated as evidence of a
    /// huge loss run -- otherwise one crafted packet forces the
    /// loss-detection scan to register (and allocate for) one entry per
    /// sequence number in the gap, up to ~2^30 entries. This is a DoS
    /// regression test, not a throughput one: it only needs to finish
    /// quickly and leave no bogus loss entries behind.
    #[test]
    fn test_receiver_buffer_rejects_packet_beyond_flow_window() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::with_buffer_size(1000, 120, start, 0, 16);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1000);

        // Just inside the window: accepted, registers bounded losses.
        let losses = buf.receive(make_packet(1010, 100), now);
        assert_eq!(losses, Some(loss_range(1000, 1009)));

        // Far beyond any plausible flow window: must be dropped, not
        // turned into ~2^30 loss-list entries.
        let losses = buf.receive(make_packet(1000u32.wrapping_add(1 << 20), 100), now);
        assert!(losses.is_none());
        assert_eq!(
            buf.stats().total_lost,
            10,
            "the rejected far-future packet must not add loss entries"
        );
        assert_eq!(buf.expected_sequence(), 1000);
    }

    /// Regression for the `find_deliverable_seq` "fast path 2" argument
    /// order: the loss-list-recovered check compared `(oldest, min)`
    /// instead of `(min, oldest)`, so a buffered packet right after an
    /// *unresolved* loss (the loss list's circular minimum still before
    /// it) was delivered immediately instead of waiting for the gap to be
    /// recovered or TLPKTDROP'd. 1000 never arrives here; 1001 must not
    /// be handed to the application while it's still missing.
    #[test]
    fn test_receiver_buffer_unresolved_loss_blocks_fast_path() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 1002 arrives first: registers 1000 and 1001 as lost.
        buf.receive(make_packet(1002, 300), now);
        // 1001 arrives, recovering it from the loss list -- but 1000 is
        // still missing and still the loss list's circular minimum.
        buf.receive(make_packet(1001, 200), now);

        assert_eq!(
            buf.pop_ready(now),
            None,
            "1001 must not be delivered while 1000 is still an unresolved loss"
        );
    }

    #[test]
    fn test_receiver_buffer_duplicate() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        buf.receive(make_packet(1000, 100), now);
        // 同じパケットを再度受信
        let losses = buf.receive(make_packet(1000, 100), now);
        assert!(losses.is_none());

        let stats = buf.stats();
        assert_eq!(stats.total_duplicates, 1);
    }

    #[test]
    fn test_receiver_buffer_pop_ready() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        buf.receive(make_packet(1000, 100), now);
        buf.receive(make_packet(1001, 200), now);

        let pkt = buf.pop_ready(now);
        assert!(pkt.is_some());
        assert_eq!(
            pkt.expect("配信可能パケットは Some になる想定")
                .sequence_number,
            1000
        );

        let pkt = buf.pop_ready(now);
        assert!(pkt.is_some());
        assert_eq!(
            pkt.expect("配信可能パケットは Some になる想定")
                .sequence_number,
            1001
        );
    }

    #[test]
    fn test_receiver_buffer_ack_generation() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);

        let now = Timestamp::from_micros(1000);

        buf.receive(make_packet(1000, 100), now);
        buf.receive(make_packet(1001, 200), now);

        let ack = buf.generate_ack(now);
        assert_eq!(ack.ack_seq, 1002);
    }

    /// Spec §4.8.1: after an ACKACK confirms the current position, periodic
    /// ACK generation is suppressed until the position or the advertised
    /// buffer space changes. Mirrors libsrt's `m_iRcvLastAckAck == ack`
    /// check with its `bNeedFullAck` exception.
    #[test]
    fn test_periodic_ack_suppressed_until_position_or_buffer_changes() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);

        let t0 = Timestamp::from_micros(10_000); // one full ACK period
        buf.receive(make_packet(1000, 100), t0);
        assert!(buf.should_send_ack(t0));
        let first = buf.generate_ack(t0);
        assert_eq!(first.ack_seq, 1001);

        // Peer confirms via ACKACK for the full ACK number.
        let ackack_time = Timestamp::from_micros(11_000);
        buf.handle_ackack(buf.ack_number(), 0, ackack_time);

        // One ACK period later, nothing changed: suppressed.
        let t1 = Timestamp::from_micros(20_000);
        assert!(!buf.should_send_ack(t1));

        // Buffer space changed since the last ACK (packet delivered past its
        // TSBPD time): the buffer-freed exception applies.
        let t_deliver = Timestamp::from_micros(131_000); // ts 100us + 120ms delay + slack
        assert!(buf.pop_ready(t_deliver).is_some());
        let ack = buf.generate_ack(t_deliver);
        assert_ne!(
            ack.available_buffer, first.available_buffer,
            "buffer-freed exception must change the advertised space"
        );

        // New position acknowledged again -> suppression resumes.
        buf.handle_ackack(buf.ack_number(), 0, Timestamp::from_micros(132_000));
        let t2 = Timestamp::from_micros(141_000);
        assert!(!buf.should_send_ack(t2));

        // A new data packet advances the position: ACK allowed again.
        buf.receive(make_packet(1001, 200), t2);
        assert!(buf.should_send_ack(t2));
    }

    #[test]
    fn stale_ackack_does_not_confirm_a_newer_full_ack() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);

        buf.receive(make_packet(1000, 100), Timestamp::from_micros(10_000));
        let first = buf.generate_ack(Timestamp::from_micros(10_000));
        let first_number = buf.ack_number();

        // Delivery frees space without advancing expected_seq, requiring a
        // newer Full ACK that carries the same position but a new window.
        assert!(buf.pop_ready(Timestamp::from_micros(131_000)).is_some());
        let second = buf.generate_ack(Timestamp::from_micros(131_000));
        let second_number = buf.ack_number();
        assert_eq!(first.ack_seq, second.ack_seq);
        assert_ne!(first_number, second_number);

        // UDP can reorder ACKACK control packets. Confirmation of the first
        // ACK must not suppress the newer window update.
        buf.handle_ackack(first_number, 0, Timestamp::from_micros(132_000));
        assert!(buf.should_send_ack(Timestamp::from_micros(141_000)));

        buf.handle_ackack(second_number, 0, Timestamp::from_micros(142_000));
        assert!(!buf.should_send_ack(Timestamp::from_micros(151_000)));
    }

    #[test]
    fn test_receiver_buffer_nak_generation() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        buf.receive(make_packet(1000, 100), now);
        buf.receive(make_packet(1002, 300), now); // 1001 欠落

        let nak = buf.generate_periodic_nak();
        assert!(nak.is_some());
        assert_eq!(
            nak.expect("欠落パケットは NAK が生成される想定")
                .loss_ranges,
            vec![loss_range(1001, 1001)]
        );
    }

    #[test]
    fn test_ack_timestamp_tracker() {
        let mut tracker = AckTimestampTracker::new();

        // ACK 送信時刻を記録
        let t1 = Timestamp::from_micros(1000);
        let t2 = Timestamp::from_micros(2000);
        let t3 = Timestamp::from_micros(3000);

        tracker.record(1, t1, 100);
        tracker.record(2, t2, 200);
        tracker.record(3, t3, 300);

        // 記録した時刻と ACK 位置を取得できる
        assert_eq!(tracker.get_send_time(1), Some(t1));
        assert_eq!(tracker.get_send_time(2), Some(t2));
        assert_eq!(tracker.get_send_time(3), Some(t3));
        assert_eq!(tracker.get_acked_seq(1), Some(100));
        assert_eq!(tracker.get_acked_seq(2), Some(200));
        assert_eq!(tracker.get_acked_seq(3), Some(300));

        // 存在しない ACK 番号は None
        assert_eq!(tracker.get_send_time(99), None);
        assert_eq!(tracker.get_acked_seq(99), None);

        // Re-recording the same ACK replaces its metadata in place.
        tracker.record(2, t3, 222);
        assert_eq!(tracker.get_send_time(2), Some(t3));
        assert_eq!(tracker.get_acked_seq(2), Some(222));
    }

    #[test]
    fn test_ack_timestamp_tracker_max_entries() {
        let mut tracker = AckTimestampTracker::new();

        // MAX_ENTRIES (16) を超えるエントリを追加
        for i in 0..20u32 {
            tracker.record(i, Timestamp::from_micros(i as u64 * 1000), i * 10);
        }

        // 古いエントリは削除される (0-3 が削除される)
        assert_eq!(tracker.get_send_time(0), None);
        assert_eq!(tracker.get_send_time(3), None);
        assert_eq!(tracker.get_acked_seq(0), None);
        assert_eq!(tracker.get_acked_seq(3), None);

        // 新しいエントリは残る
        assert!(tracker.get_send_time(4).is_some());
        assert!(tracker.get_send_time(19).is_some());
        assert!(tracker.get_acked_seq(19).is_some());
    }

    #[test]
    fn ack_timestamp_tracker_uses_one_fixed_lazy_backing() {
        let mut tracker = AckTimestampTracker::new();
        assert!(tracker.entries.is_none());

        tracker.record(1, Timestamp::from_micros(1), 100);
        let bytes = std::mem::size_of_val(
            tracker
                .entries
                .as_deref()
                .expect("the first ACK allocates the fixed backing"),
        );
        assert_eq!(bytes, 256);
    }

    #[test]
    fn ack_timestamp_tracker_evicts_by_age_across_number_wrap() {
        let mut tracker = AckTimestampTracker::new();
        let first = u32::MAX - 7;

        for offset in 0..20u32 {
            let ack_number = first.wrapping_add(offset);
            tracker.record(
                ack_number,
                Timestamp::from_micros(u64::from(offset)),
                offset,
            );
        }

        for offset in 0..4u32 {
            assert_eq!(tracker.get_send_time(first.wrapping_add(offset)), None);
        }
        for offset in 4..20u32 {
            let ack_number = first.wrapping_add(offset);
            assert_eq!(
                tracker.get_send_time(ack_number),
                Some(Timestamp::from_micros(u64::from(offset)))
            );
            assert_eq!(tracker.get_acked_seq(ack_number), Some(offset));
        }
    }

    #[test]
    fn tsbpd_drift_tracer_moves_excess_into_time_base() {
        let mut tracer = TsbpdDriftTracer::default();
        for _ in 1..TSBPD_DRIFT_MAX_SAMPLES {
            assert!(!tracer.update(7_000));
        }
        assert!(tracer.update(7_000));

        assert_eq!(tracer.overdrift_us(), 5_000);
        assert_eq!(tracer.drift_us(), 2_000);
    }

    #[test]
    fn test_receiving_rate_estimator() {
        let start = Timestamp::from_micros(0);
        let mut estimator = ReceivingRateEstimator::new(start);

        // 1ms 間隔でパケットを受信 (1000 packets/sec 相当)
        for i in 0..100 {
            let now = Timestamp::from_micros(i * 1000); // 1ms 間隔
            estimator.on_packet_received(now, 1500); // 1500 bytes
        }

        let now = Timestamp::from_micros(100_000); // 100ms 経過
        let (packet_rate, byte_rate) = estimator.calculate_rates(now);

        // 約 1000 packets/sec を期待
        // EWMA により初回は 1/8 の重みなので、完全な値にはならない
        assert!(packet_rate > 0, "パケットレートが 0 より大きいこと");

        // バイトレートも計算される
        assert!(byte_rate > 0, "バイトレートが 0 より大きいこと");
    }

    #[test]
    fn test_receiving_rate_estimator_no_packets() {
        let start = Timestamp::from_micros(0);
        let mut estimator = ReceivingRateEstimator::new(start);

        // パケットを受信しない状態でレート計算
        let now = Timestamp::from_micros(100_000);
        let (packet_rate, byte_rate) = estimator.calculate_rates(now);

        // サンプルがないので 0 のまま
        assert_eq!(packet_rate, 0);
        assert_eq!(byte_rate, 0);
    }

    #[test]
    fn test_link_capacity_estimator() {
        let mut estimator = LinkCapacityEstimator::new();

        // 100μs 間隔でパケットを受信 (10000 packets/sec 相当)
        for i in 0..20 {
            let now = Timestamp::from_micros(i * 100);
            estimator.on_packet_received(now);
        }

        let capacity = estimator.calculate_capacity();

        // 約 10000 packets/sec を期待
        // Packet Pair Technique で下位 25% を使うため、値は変動する
        assert!(capacity > 0, "容量が 0 より大きいこと");
    }

    #[test]
    fn test_link_capacity_estimator_no_samples() {
        let mut estimator = LinkCapacityEstimator::new();

        // パケット受信がない場合
        let capacity = estimator.calculate_capacity();

        // サンプルなしで 0 を返す
        assert_eq!(capacity, 0);
    }

    #[test]
    fn test_link_capacity_estimator_single_interval() {
        let mut estimator = LinkCapacityEstimator::new();

        // 2 つのパケットで 1 つの間隔を記録
        estimator.on_packet_received(Timestamp::from_micros(0));
        estimator.on_packet_received(Timestamp::from_micros(100)); // 100μs 間隔

        let capacity = estimator.calculate_capacity();

        // 1 つのサンプルでも計算される (1,000,000 / 100 = 10000)
        assert_eq!(capacity, 10000);
    }

    #[test]
    fn link_capacity_estimator_uses_one_fixed_lazy_backing() {
        let mut estimator = LinkCapacityEstimator::new();
        assert!(estimator.intervals.is_none());

        estimator.on_packet_received(Timestamp::from_micros(0));
        estimator.on_packet_received(Timestamp::from_micros(0));
        assert!(estimator.intervals.is_none());
        estimator.on_packet_received(Timestamp::from_micros(100));

        let bytes = std::mem::size_of_val(
            estimator
                .intervals
                .as_deref()
                .expect("the first valid interval allocates the fixed backing"),
        );
        assert_eq!(bytes, 128);
        assert_eq!(estimator.interval_count, 1);
    }

    #[test]
    fn link_capacity_estimator_retains_latest_sixteen_intervals() {
        let mut estimator = LinkCapacityEstimator::new();
        let mut arrival = 0;
        estimator.on_packet_received(Timestamp::from_micros(arrival));
        for interval in 1..=20 {
            arrival += interval;
            estimator.on_packet_received(Timestamp::from_micros(arrival));
        }

        assert_eq!(estimator.interval_count, 16);
        // The retained intervals are 5..=20. Index 16 / 4 selects 9us.
        assert_eq!(estimator.calculate_capacity(), 1_000_000 / 9);
    }

    #[test]
    fn test_rtt_calculation_with_ack_timestamps() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        // パケットを受信
        let now = Timestamp::from_micros(1000);
        buf.receive(make_packet(1000, 100), now);

        // ACK を生成 (これにより ACK 送信時刻が記録される)
        let ack_time = Timestamp::from_micros(2000);
        let ack = buf.generate_ack(ack_time);
        let ack_number = ack.ack_seq;

        // ACKACK を受信 (RTT = 50ms)
        let ackack_time = Timestamp::from_micros(52000); // 50ms 後
        buf.handle_ackack(ack_number, 0, ackack_time);

        // RTT が計算される (EWMA: 1/8 の重み)
        let stats = buf.stats();
        // 初期 RTT は 100ms (100000μs) なので、
        // RTT = 7/8 * 100000 + 1/8 * 50000 = 87500 + 6250 = 93750
        assert!(stats.rtt > 0, "RTT が計算されていること");
    }

    #[test]
    fn test_ack_includes_recv_rate() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        // パケットを複数回受信
        for i in 0..10 {
            let now = Timestamp::from_micros(i * 1000);
            buf.receive(make_packet(1000 + i as u32, 100 + i as u32 * 100), now);
        }

        // ACK 生成
        let now = Timestamp::from_micros(10000);
        let ack = buf.generate_ack(now);

        // AckPacket のフィールドが設定される
        // 初回なので値は小さいが、フィールドが存在することを確認
        let _receiving_rate = ack.receiving_rate;
        let _link_capacity = ack.link_capacity;
        let _recv_rate = ack.recv_rate;

        // Full ACK として生成される (Light ACK ではない)
        assert!(!ack.is_light);
    }

    #[test]
    fn test_total_bytes_received() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 3 バイトのペイロード + 16 バイトのヘッダ = 19 バイト
        buf.receive(make_packet(1000, 100), now);
        let stats = buf.stats();
        assert_eq!(stats.total_bytes_received, 19);

        // さらに 1 パケット受信
        buf.receive(make_packet(1001, 200), now);
        let stats = buf.stats();
        assert_eq!(stats.total_bytes_received, 38);
    }

    #[test]
    fn test_loss_rate_calculation() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 10 パケット受信、2 パケット損失 (1001, 1004)
        buf.receive(make_packet(1000, 100), now);
        buf.receive(make_packet(1002, 200), now); // 1001 損失
        buf.receive(make_packet(1003, 300), now);
        buf.receive(make_packet(1005, 400), now); // 1004 損失
        buf.receive(make_packet(1006, 500), now);
        buf.receive(make_packet(1007, 600), now);
        buf.receive(make_packet(1008, 700), now);
        buf.receive(make_packet(1009, 800), now);

        let stats = buf.stats();
        // total_received = 8, total_lost = 2
        // loss_rate = 2 / (8 + 2) * 100 * 100 = 2000 (= 20.00%)
        assert_eq!(stats.total_received, 8);
        assert_eq!(stats.total_lost, 2);
        assert_eq!(stats.loss_rate_percent_x100, 2000);
    }

    #[test]
    fn test_loss_rate_zero() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 損失なしで受信
        buf.receive(make_packet(1000, 100), now);
        buf.receive(make_packet(1001, 200), now);
        buf.receive(make_packet(1002, 300), now);

        let stats = buf.stats();
        assert_eq!(stats.total_received, 3);
        assert_eq!(stats.total_lost, 0);
        assert_eq!(stats.loss_rate_percent_x100, 0);
    }

    #[test]
    fn test_jitter_calculation() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        // タイムスタンプと到着時刻の差が一定の場合、ジッターは小さい
        buf.receive(make_packet(1000, 1000), Timestamp::from_micros(2000)); // transit = 1000
        buf.receive(make_packet(1001, 2000), Timestamp::from_micros(3000)); // transit = 1000, d = 0

        let stats = buf.stats();
        // d = 0 なので jitter は増えない
        assert_eq!(stats.jitter, 0);

        // タイムスタンプと到着時刻の差が変動する場合、ジッターが増加
        buf.receive(make_packet(1002, 3000), Timestamp::from_micros(4500)); // transit = 1500, d = 500
        let stats = buf.stats();
        // jitter = 0 + (500 - 0) / 16 = 31
        assert_eq!(stats.jitter, 31);

        // さらに変動
        buf.receive(make_packet(1003, 4000), Timestamp::from_micros(5000)); // transit = 1000, d = 500
        let stats = buf.stats();
        // jitter = 31 + (500 - 31) / 16 = 31 + 29 = 60
        assert_eq!(stats.jitter, 60);
    }

    #[test]
    fn test_jitter_no_packets() {
        let start = Timestamp::from_micros(0);
        let buf = ReceiverBuffer::new(1000, 120, start, 0);

        let stats = buf.stats();
        // パケットを受信していない場合、jitter は 0
        assert_eq!(stats.jitter, 0);
    }

    #[test]
    fn test_tsbpd_delivery_time_uses_tsbpd_time_base() {
        let start = Timestamp::from_micros(1_000_000); // T=1 秒
        // TsbpdTimeBase = 500_000μs (RTT_0/2 = 250ms 相当)
        let tsbpd_time_base = 500_000;
        let mut buf = ReceiverBuffer::new(1000, 120, start, tsbpd_time_base);

        let now = Timestamp::from_micros(1_000_000);
        let pkt = make_packet(1000, 200_000); // PKT_TIMESTAMP = 200ms
        buf.receive(pkt, now);

        let delivered = buf.pop_ready(Timestamp::from_micros(1_500_000));
        // delivery_time = tsbpd_time_base + PKT_TIMESTAMP + tsbpd_delay
        //                = 500_000 + 200_000 + 120_000 = 820_000μs
        // now=1_500_000 > 820_000 なので配送される
        assert!(delivered.is_some());
        assert_eq!(
            delivered
                .expect("配信可能パケットは Some になる想定")
                .sequence_number,
            1000
        );
    }

    #[test]
    fn tsbpd_drift_correction_updates_already_buffered_delivery_time() {
        let mut buf = ReceiverBuffer::new(1000, 0, Timestamp::from_micros(0), 100_000);
        buf.receive(make_packet(1000, 10), Timestamp::from_micros(0));

        // libsrt averages 1,000 ACKACK samples. A 7ms average drift carries
        // 5ms into the base and leaves a 2ms delivery offset.
        for _ in 0..TSBPD_DRIFT_MAX_SAMPLES {
            buf.handle_ackack(0, 0, Timestamp::from_micros(107_000));
        }

        assert_eq!(buf.tsbpd_time_base, 105_000);
        assert_eq!(buf.drift_tracer.drift_us(), 2_000);
        assert!(buf.pop_ready(Timestamp::from_micros(100_010)).is_none());
        assert!(buf.pop_ready(Timestamp::from_micros(107_010)).is_some());
    }

    #[test]
    fn test_tsbpd_delivery_not_ready_before_delay() {
        let start = Timestamp::from_micros(1_000_000);
        let tsbpd_time_base = 500_000;
        let mut buf = ReceiverBuffer::new(1000, 120, start, tsbpd_time_base);

        let now = Timestamp::from_micros(1_000_000);
        let pkt = make_packet(1000, 200_000);
        buf.receive(pkt, now);

        // PKT_TIMESTAMP=200_000 + tsbpd_time_base=500_000 = 700_000
        // tsbpd_delay=120_000, delivery_time = 820_000
        // now=700_000 < 820_000 なので配送されない
        let delivered = buf.pop_ready(Timestamp::from_micros(700_000));
        assert!(delivered.is_none());
    }

    #[test]
    fn test_tsbpd_ready_search_is_not_repeated_for_the_buffered_window() {
        let mut buf = ReceiverBuffer::new(0, 250, Timestamp::from_micros(0), 0);

        for seq in 0..512u32 {
            let now_us = (u64::from(seq) + 1) * 1_316;
            let now = Timestamp::from_micros(now_us);
            buf.receive(make_packet(seq, now_us as u32), now);
            let _ = buf.pop_ready(now);
        }

        assert!(
            buf.delivery_scan_calls() < 256,
            "buffered TSBPD search scanned {} times",
            buf.delivery_scan_calls()
        );
    }

    #[test]
    fn test_in_order_receive_does_not_search_for_a_future_sequence() {
        let mut buf = ReceiverBuffer::new(0, 250, Timestamp::from_micros(0), 0);

        for seq in 0..512u32 {
            let now_us = (u64::from(seq) + 1) * 1_316;
            let now = Timestamp::from_micros(now_us);
            buf.receive(make_packet(seq, now_us as u32), now);
        }

        assert_eq!(buf.receive_expected_sequence_scans(), 0);
    }

    #[test]
    fn loss_detection_reports_only_new_gaps_behind_persistent_loss() {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        // Keep sequence zero missing and receive alternating packets. Every
        // later packet adds another missing run while the first hole remains.
        for (index, seq) in (1u32..128).step_by(2).enumerate() {
            let losses = buf.receive(make_packet(seq, seq), now);
            let loss = if index == 0 { 0 } else { seq - 1 };
            assert_eq!(losses, Some(loss_range(loss, loss)));
        }
        assert!(buf.loss_list.contains(&0));
    }

    #[test]
    fn loss_detection_handles_sequence_wrap() {
        let mut buf = ReceiverBuffer::new(0x7FFF_FFFD, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        for (seq, expected_loss) in [(0x7FFF_FFFE, 0x7FFF_FFFD), (0, 0x7FFF_FFFF), (2, 1)] {
            assert_eq!(
                buf.receive(make_packet(seq, seq), now),
                Some(loss_range(expected_loss, expected_loss))
            );
        }

        assert_eq!(
            loss_set(&buf),
            FxHashSet::from_iter([0x7FFF_FFFD, 0x7FFF_FFFF, 1])
        );
    }

    #[test]
    fn receiver_packet_storage_is_ordered() {
        let buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        let _: &BTreeMap<u32, ReceivedPacket> = &buf.packets;
    }

    #[test]
    fn in_order_receive_and_pop_use_delivery_hint_without_map_scan() {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        for seq in 0..512 {
            buf.receive(make_packet(seq, seq), now);
        }
        for seq in 0..512 {
            assert_eq!(
                buf.pop_ready(now).map(|packet| packet.sequence_number),
                Some(seq)
            );
        }

        assert_eq!(buf.delivery_scan_calls(), 0);
    }

    #[test]
    fn next_buffered_sequence_uses_circular_order_across_wrap() {
        let mut buf = ReceiverBuffer::new(0x7FFF_FFFE, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        buf.receive(make_packet(0x7FFF_FFFE, 1), now);
        buf.receive(make_packet(0x7FFF_FFFF, 2), now);
        buf.receive(make_packet(0, 3), now);

        assert_eq!(buf.next_sequence_after(0x7FFF_FFFF), Some(0));
    }

    #[test]
    fn test_tsbpd_ready_search_falls_back_for_out_of_order_timestamps() {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        let received_at = Timestamp::from_micros(0);

        buf.receive(make_packet(0, 1_000_000), received_at);
        buf.receive(make_packet(1, 0), received_at);

        assert_eq!(
            buf.pop_ready(Timestamp::from_micros(200_000))
                .map(|packet| packet.sequence_number),
            Some(1)
        );
        assert_eq!(
            buf.pop_ready(Timestamp::from_micros(1_200_000))
                .map(|packet| packet.sequence_number),
            Some(0)
        );
    }

    #[test]
    fn test_drop_too_late_uses_tsbpd_time_base() {
        let start = Timestamp::from_micros(1_000_000);
        let tsbpd_time_base = 500_000;
        let mut buf = ReceiverBuffer::new(1000, 120, start, tsbpd_time_base);

        let now = Timestamp::from_micros(1_000_000);
        // 1001 を受信して 1000 が損失として登録される
        buf.receive(make_packet(1001, 200_000), now);

        assert_eq!(loss_set(&buf), FxHashSet::from_iter([1000]));

        // TLPKTDROP = max(1.25 * 120_000, 1_000_000) = 1_000_000μs
        // 次側パケット seq 1001 の delivery_time = 500_000 + 200_000 + 120_000 = 820_000
        // now = 2_000_000 > 820_000 + 1_000_000 = 1_820_000 なので削除される
        let dropped = buf.drop_too_late(Timestamp::from_micros(2_000_000));
        assert_eq!(dropped, vec![1000]);
    }

    #[test]
    fn tlpktdrop_handles_multiple_losses() {
        let start = Timestamp::from_micros(1_000_000);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 500_000);
        let received_at = Timestamp::from_micros(1_000_000);

        // These buffered packets leave four independent losses. Each missing
        // sequence is past its TLPKTDROP deadline at the timer instant.
        for seq in [1002, 1004, 1006] {
            buf.receive(make_packet(seq, 200_000), received_at);
        }
        assert_eq!(
            loss_set(&buf),
            FxHashSet::from_iter([1000, 1001, 1003, 1005])
        );

        let dropped = buf.drop_too_late(Timestamp::from_micros(2_000_000));

        assert_eq!(
            FxHashSet::from_iter(dropped),
            FxHashSet::from_iter([1000, 1001, 1003, 1005])
        );
        assert!(buf.loss_list.is_empty());
        assert_eq!(buf.expected_sequence(), 1007);
    }

    #[test]
    fn tlpktdrop_without_losses_is_empty() {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(true);

        assert!(
            buf.drop_too_late(Timestamp::from_micros(2_000_000))
                .is_empty()
        );
    }

    /// TLPKTDROP で諦めたシーケンス (1000) が expected_seq に永久に張り付き、
    /// 以後届くパケットのたびに receive() のギャップ検出ループが同じ穴を
    /// 「新規損失」として際限なく再カウントし続けるバグの回帰テスト。
    /// 差分テストで、10% loss + 100ms
    /// delay + 高ビットレートのセルにおいて pkt_rcv_loss_total が受信
    /// パケット数の 1000 倍以上に達する形で発見された。
    #[test]
    fn test_drop_too_late_advances_expected_seq_and_stops_recounting() {
        let start = Timestamp::from_micros(1_000_000);
        let tsbpd_time_base = 500_000;
        let mut buf = ReceiverBuffer::new(1000, 120, start, tsbpd_time_base);

        let now = Timestamp::from_micros(1_000_000);
        // 1001 を受信して 1000 が損失として登録される (expected_seq は
        // 1000 のまま -- 1000 自体は一度も届いていないため)。
        buf.receive(make_packet(1001, 200_000), now);
        assert_eq!(buf.expected_sequence(), 1000);

        // TLPKTDROP で 1000 を諦める。
        let dropped = buf.drop_too_late(Timestamp::from_micros(2_000_000));
        assert_eq!(dropped, vec![1000]);

        // 修正前は expected_seq が 1000 に張り付いたままだった。
        // 1000 (諦めた) と 1001 (受信済み) の両方を追い越して 1002 まで
        // 進んでいるはずで、1001 は既に受信済みなのでループはそこも越える。
        assert_eq!(buf.expected_sequence(), 1002);
        assert_eq!(buf.total_lost, 1);

        // 以後、間隔をおいて新しいパケットが多数届いても、既に諦めた 1000
        // が「新規損失」として再カウントされてはならない -- total_lost は
        // 1 のまま (1000 のみ) であるべきで、修正前は毎回のパケット到着で
        // ここが際限なく増加していた。
        for (i, seq) in (1002u32..1050).enumerate() {
            let t = Timestamp::from_micros(2_000_000 + i as u64 * 10_000);
            buf.receive(make_packet(seq, 300_000 + i as u32 * 1_000), t);
        }
        assert_eq!(buf.total_lost, 1);
        assert_eq!(buf.expected_sequence(), 1050);
    }

    #[test]
    fn test_drop_too_late_individual_delivery() {
        let start = Timestamp::from_micros(1_000_000);
        let tsbpd_time_base = 500_000;
        let mut buf = ReceiverBuffer::new(1000, 500, start, tsbpd_time_base);
        // tsbpd_delay = 500ms, tsbpd_delay_us = 500_000

        let now = Timestamp::from_micros(1_000_000);
        // 1000 を受信 (delivery_time = 500_000 + 100_000 + 500_000 = 1_100_000)
        buf.receive(make_packet(1000, 100_000), now);
        // 1002 を受信して 1001 が損失として登録される
        // 1001 の推定配信時刻は次側パケット seq 1002 の delivery_time
        // = 500_000 + 300_000 + 500_000 = 1_300_000
        buf.receive(make_packet(1002, 300_000), now);

        // TLPKTDROP = max(1.25 * 500_000, 1_000_000) = 1_000_000
        // 1000: delivery = 1_100_000, 1_100_000 + 1_000_000 = 2_100_000
        // 1001: estimated = 1_300_000, 1_300_000 + 1_000_000 = 2_300_000
        // now = 2_200_000: 1000 は超過、1001 は未到達 → 1000 のみ削除 (1000 は loss_list にないので削除されない)
        // now = 2_400_000: 両方超過 → 1001 が削除される
        let dropped = buf.drop_too_late(Timestamp::from_micros(2_400_000));
        assert_eq!(dropped, vec![1001]);
        assert!(buf.loss_list.is_empty());
    }

    #[test]
    fn test_light_ack_does_not_increment_ack_number() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        // 64 パケット受信して Light ACK 条件を満たす
        let now = Timestamp::from_micros(0);
        for i in 0..64 {
            buf.receive(make_packet(1000 + i as u32, i as u32 * 100), now);
        }

        let ack_number_before = buf.ack_number();
        let ack = buf.generate_ack(now);
        assert!(ack.is_light);

        // Light ACK では ack_number がインクリメントされない
        assert_eq!(buf.ack_number(), ack_number_before);
    }

    #[test]
    fn test_full_ack_increments_ack_number() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        // 数パケット受信 (Light ACK 条件を満たさない)
        let now = Timestamp::from_micros(0);
        for i in 0..10 {
            buf.receive(make_packet(1000 + i as u32, i as u32 * 100), now);
        }

        let ack_number_before = buf.ack_number();
        // 定期 ACK 間隔 (10ms) 経過させる
        let ack = buf.generate_ack(Timestamp::from_micros(10_000));
        assert!(!ack.is_light);

        // Full ACK では ack_number がインクリメントされる
        assert_eq!(buf.ack_number(), ack_number_before + 1);
        assert_eq!(buf.ack_number(), 1);
    }

    #[test]
    fn test_pop_ready_blocks_on_loss_across_wrap_boundary() {
        // ラップ境界をまたぐ区間で先頭の 0x7FFF_FFFE が欠損しているとき、loss_list による
        // HoL ブロッキングが後続 (循環順で 0x7FFF_FFFE より後ろ) の配信を止め続けることを検証する。
        // 欠損なしの配送順序は PBT が網羅するため、ここでは PBT で作りにくい損失ありの境界ケースを置く。
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(0x7FFF_FFFE, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 0x7FFF_FFFE を欠損させ、循環順で後続の 0x7FFF_FFFF, 0, 1 を受信する。
        // 0x7FFF_FFFE が loss_list に残る。
        buf.receive(make_packet(0x7FFF_FFFF, 100), now);
        buf.receive(make_packet(0, 100), now);
        buf.receive(make_packet(1, 100), now);

        // 0x7FFF_FFFE が損失として残る間は、循環順で後ろの候補は配信されない。
        assert!(buf.pop_ready(now).is_none());
    }

    #[test]
    fn test_pop_ready_skips_hole_after_drop_across_wrap_boundary() {
        // ラップ境界をまたぐ区間で 0x7FFF_FFFE が欠損したまま drop_too_late で穴が loss_list から
        // 除去されたら、後続 0x7FFF_FFFF, 0, 1 が循環順で配信されること (穴スキップ維持) を検証する。
        // drop_too_late は tsbpd 有効が前提のため、ここでは tsbpd を無効化しない。
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(0x7FFF_FFFE, 120, start, 0);

        let recv_now = Timestamp::from_micros(1000);
        buf.receive(make_packet(0x7FFF_FFFF, 100), recv_now);
        buf.receive(make_packet(0, 100), recv_now);
        buf.receive(make_packet(1, 100), recv_now);

        // 穴 (0x7FFF_FFFE) が残る間は HoL ブロッキングで配信されない。
        // tlpktdrop 閾値 (最低 1 秒) を確実に超える時刻で評価する。
        let late_now = Timestamp::from_micros(10_000_000);
        assert!(buf.pop_ready(late_now).is_none());

        // drop_too_late で期限切れの穴 (0x7FFF_FFFE) を loss_list から除去する。
        let dropped = buf.drop_too_late(late_now);
        assert_eq!(dropped, vec![0x7FFF_FFFE]);

        // 穴が消えた後、後続が循環順で配信される。
        let mut popped = Vec::new();
        while let Some(pkt) = buf.pop_ready(late_now) {
            popped.push(pkt.sequence_number);
        }
        assert_eq!(popped, vec![0x7FFF_FFFF, 0, 1]);
    }

    #[test]
    fn test_loss_bitmap_summary_tracks_first_across_wrap_boundary() {
        // The bitmap summary must advance to the next circular loss when the
        // oldest loss is recovered, including across sequence wrap.
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(0x7FFF_FFFD, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(1000);

        // 0x7FFF_FFFD, 0x7FFF_FFFE, 0x7FFF_FFFF, 0 を欠損させ、循環順で
        // 最も新しい 1 のみ受信する。循環順最古の
        // 0x7FFF_FFFD になるはず。
        buf.receive(make_packet(1, 100), now);
        assert!(buf.loss_list.contains(&0x7FFF_FFFD));
        assert!(buf.loss_list.contains(&0x7FFF_FFFE));
        assert!(buf.loss_list.contains(&0x7FFF_FFFF));
        assert!(buf.loss_list.contains(&0));

        // 循環順最古の欠損 (0x7FFF_FFFD) が回復する。新しい最小値は
        // 残りの中で循環順最古の 0x7FFF_FFFE になるはず。
        buf.receive(make_packet(0x7FFF_FFFD, 100), now);

        // 0x7FFF_FFFD 自体は (循環順で手前に欠損がないので) 即座に配信可能になる。
        assert_eq!(
            buf.pop_ready(now).map(|p| p.sequence_number),
            Some(0x7FFF_FFFD)
        );

        // summary が正しく 0x7FFF_FFFE を指していれば、seq=1 (循環順で
        // 0x7FFF_FFFE より後ろ) はまだ穴によってブロックされ、配信されない。
        // summary が壊れていて最小値が誤って None だと、ここで
        // 1 が (誤って) 配信されてしまうはず。
        assert!(buf.pop_ready(now).is_none());

        // 残りの欠損も回復させれば、循環順どおりに配信される。
        buf.receive(make_packet(0x7FFF_FFFE, 100), now);
        buf.receive(make_packet(0x7FFF_FFFF, 100), now);
        buf.receive(make_packet(0, 100), now);

        // 0x7FFF_FFFD は既に上で配信済みなので、残りは循環順どおり
        // 0x7FFF_FFFE, 0x7FFF_FFFF, 0, 1 の順で配信される。
        let mut popped = Vec::new();
        while let Some(pkt) = buf.pop_ready(now) {
            popped.push(pkt.sequence_number);
        }
        assert_eq!(popped, vec![0x7FFF_FFFE, 0x7FFF_FFFF, 0, 1]);
    }

    #[test]
    fn test_wrapping_period_delivery_time_compensation() {
        // ラップ後パケットの配信時刻に MAX_TIMESTAMP + 1 が加算されることを検証する。
        let start = Timestamp::from_micros(0);
        let tsbpd_time_base = 500_000;
        let mut buf = ReceiverBuffer::new(1000, 120, start, tsbpd_time_base);

        // ラップ前窗口のパケットを受信して wrapping_period_active を有効化する。
        // WRAPPING_PERIOD_START = MAX_TIMESTAMP - 30_000_000
        let wrap_start_ts = WRAPPING_PERIOD_START as u32;
        let now = Timestamp::from_micros(1_000_000);
        buf.receive(make_packet(1000, wrap_start_ts), now);
        assert!(buf.wrapping_period_active);

        // ラップ後パケット (ts = 10_000_000 < WRAPPING_PERIOD_START) の配信時刻は
        // tsbpd_time_base + ts + MAX_TIMESTAMP + 1 + tsbpd_delay_us になる。
        let post_wrap_ts: u32 = 10_000_000;
        buf.receive(make_packet(1001, post_wrap_ts), now);

        // 配信時刻が正しく補正されていることを確認する。
        // 補正あり: delivery_time = 500_000 + 10_000_000 + (MAX_TIMESTAMP + 1) + 120_000
        //          = 500_000 + 10_000_000 + 4_294_967_296 + 120_000
        //          = 4_305_587_296 μs
        // 補正なし: delivery_time = 500_000 + 10_000_000 + 120_000 = 10_620_000 μs
        // 補正なしの時刻では即時配信されるが、補正ありの時刻では配信されないことを確認する。
        let early = Timestamp::from_micros(10_620_000);
        assert!(
            buf.pop_ready(early).is_none(),
            "補正後の配信時刻は未来のはず"
        );

        // 補正後の配信時刻を超えると配信される。
        // 1000 (ラップ前) と 1001 (ラップ後、補正あり) の両方が配信される。
        let late = Timestamp::from_micros(4_305_588_000);
        let pkt0 = buf.pop_ready(late);
        assert!(pkt0.is_some(), "ラップ前パケットが配信されるはず");
        assert_eq!(pkt0.expect("配信パケット").sequence_number, 1000);

        let pkt1 = buf.pop_ready(late);
        assert!(pkt1.is_some(), "ラップ後パケットが配信されるはず");
        assert_eq!(pkt1.expect("配信パケット").sequence_number, 1001);
    }

    #[test]
    fn test_wrapping_period_drop_too_late_fallback() {
        // wrapping_period_active が有効な場合、drop_too_late のフォールバック式に
        // MAX_TIMESTAMP + 1 が加算されることを検証する。
        let start = Timestamp::from_micros(0);
        let tsbpd_time_base = 500_000;
        let mut buf = ReceiverBuffer::new(1000, 120, start, tsbpd_time_base);

        // ラップ前窗口のパケットを受信して wrapping_period_active を有効化する。
        let wrap_start_ts = WRAPPING_PERIOD_START as u32;
        let now = Timestamp::from_micros(1_000_000);
        buf.receive(make_packet(1000, wrap_start_ts), now);

        // 1002 を受信して 1001 を損失として登録する。
        buf.receive(make_packet(1002, 200_000), now);
        assert!(buf.loss_list.contains(&1001));

        // wrapping_period_active が有効な場合、次側パケット seq 1002 の delivery_time が
        // 推定配信時刻として使用される。seq 1002 の delivery_time はラップ補正付きで
        // = 500_000 + 200_000 + MAX_TIMESTAMP + 1 + 120_000 = 4_295_787_296 μs
        // TLPKTDROP = max(1.25 * 120_000, 1_000_000) = 1_000_000
        // now = 4_295_787_296 + 1_000_000 = 4_296_787_296 で削除される。
        // それより前の時刻では削除されない。
        let before = Timestamp::from_micros(4_295_787_000);
        let dropped = buf.drop_too_late(before);
        assert!(dropped.is_empty(), "閾値未満では削除されないはず");

        let after = Timestamp::from_micros(4_296_788_000);
        let dropped = buf.drop_too_late(after);
        assert_eq!(dropped, vec![1001], "閾値超過で削除されるはず");
    }

    #[test]
    fn test_wrapping_period_end_in_pop_ready() {
        // pop_ready() 内で終了窗口パケット (ts が 30〜60 秒の範囲) が配信されたときに
        // wrapping_period_active が false になり tsbpd_time_base が更新されることを検証する。
        let start = Timestamp::from_micros(0);
        let tsbpd_time_base = 0;
        let mut buf = ReceiverBuffer::new(1000, 120, start, tsbpd_time_base);

        // ラップ前窗口のパケットを受信して wrapping_period_active を有効化する。
        let wrap_start_ts = WRAPPING_PERIOD_START as u32;
        let now = Timestamp::from_micros(1_000_000);
        buf.receive(make_packet(1000, wrap_start_ts), now);
        assert!(buf.wrapping_period_active);

        // 終了窗口パケット (ts = 40_000_000, 40 秒) を受信する。
        // これは (WRAPPING_PERIOD_END_MIN..WRAPPING_PERIOD_END_MAX) の範囲内。
        // ラップ後パケットのため配信時刻に MAX_TIMESTAMP + 1 が加算される。
        let end_ts: u32 = 40_000_000;
        buf.receive(make_packet(1001, end_ts), now);

        // 両パケットの配信時刻:
        // 1000: delivery_time = 0 + WRAPPING_PERIOD_START + 120_000 = 4_265_087_295
        // 1001: delivery_time = 0 + 40_000_000 + MAX_TIMESTAMP + 1 + 120_000 = 4_335_087_296
        // 両パケットの配信時刻を超える時刻で配信する。
        // 1000 が配信された後、1001 が配信されると pop_ready() 内で終了判定が発火する。
        let late = Timestamp::from_micros(4_335_088_000);
        let pkt0 = buf.pop_ready(late);
        assert!(pkt0.is_some(), "1000 が配信されるはず");
        assert_eq!(pkt0.expect("配信パケット").sequence_number, 1000);

        // 1001 を配信する。終了判定が発火し wrapping_period_active が false になる。
        // tsbpd_time_base は private フィールドのため直接検証できないが、
        // 終了判定のコード (self.tsbpd_time_base += MAX_TIMESTAMP + 1) と
        // wrapping_period_active の変化で間接的に検証する。
        let pkt1 = buf.pop_ready(late);
        assert!(pkt1.is_some(), "1001 が配信されるはず");
        assert_eq!(pkt1.expect("配信パケット").sequence_number, 1001);
        assert!(
            !buf.wrapping_period_active,
            "終了判定が発火し wrapping_period_active が false になるはず"
        );
    }

    #[test]
    fn wrapping_period_ends_at_libsrt_inclusive_upper_boundary() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        let now = Timestamp::from_micros(1_000_000);
        buf.receive(make_packet(1000, WRAPPING_PERIOD_START as u32), now);
        buf.receive(make_packet(1001, WRAPPING_PERIOD_END_MAX as u32), now);

        // The wrapped 60-second packet is deliverable after its adjusted
        // timestamp plus the configured TSBPD delay.
        let late = Timestamp::from_micros(MAX_TIMESTAMP + 1 + WRAPPING_PERIOD_END_MAX + 120_000);
        assert_eq!(
            buf.pop_ready(late).map(|packet| packet.sequence_number),
            Some(1000)
        );
        assert_eq!(
            buf.pop_ready(late).map(|packet| packet.sequence_number),
            Some(1001)
        );
        assert!(
            !buf.wrapping_period_active,
            "the 60-second endpoint closes the wrapping period"
        );
    }

    #[test]
    fn test_wrapping_period_no_end_in_pop_ready_when_tsbpd_disabled() {
        // TSBPD 無効時は pop_ready() 内の終了判定が発火しないことを検証する。
        // TSBPD 無効時は delivery_time = now なので、終了窗口パケット (ts が 30〜60 秒) も
        // 即時配信可能になる。その配信時に終了判定が発火しないことを確認する。
        let start = Timestamp::from_micros(0);
        let tsbpd_time_base = 500_000;
        let mut buf = ReceiverBuffer::new(1000, 120, start, tsbpd_time_base);

        // ラップ前窗口のパケットを受信して wrapping_period_active を有効化する。
        let wrap_start_ts = WRAPPING_PERIOD_START as u32;
        let now = Timestamp::from_micros(1_000_000);
        buf.receive(make_packet(1000, wrap_start_ts), now);
        assert!(buf.wrapping_period_active);

        // 終了窗口パケット (ts = 40_000_000) を受信する。
        let end_ts: u32 = 40_000_000;
        buf.receive(make_packet(1001, end_ts), now);

        // TSBPD を無効化する。これにより delivery_time = now となり即時配信可能になる。
        buf.set_tsbpd_enabled(false);

        // 1000 を配信する。終了判定は発火しない。
        let pkt0 = buf.pop_ready(now);
        assert!(pkt0.is_some(), "1000 が配信されるはず");
        assert!(
            buf.wrapping_period_active,
            "TSBPD 無効時は終了判定が発火しないはず"
        );

        // 1001 (終了窗口パケット) を配信する。TSBPD 無効時は終了判定が発火しない。
        let pkt1 = buf.pop_ready(now);
        assert!(pkt1.is_some(), "1001 が配信されるはず");
        assert!(
            buf.wrapping_period_active,
            "TSBPD 無効時は終了窗口パケットでも終了判定が発火しないはず"
        );
    }

    #[test]
    fn detect_losses_handles_large_gap_without_circular_walk() {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        let losses = buf
            .receive(make_packet(4_096, 1), now)
            .expect("the gap is reported as losses");
        assert_eq!(losses.sequence_count(), 4_096);
        assert_eq!(losses, loss_range(0, 4_095));
    }

    #[test]
    fn detect_losses_finds_contiguous_gaps() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(100, 120, start, 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        buf.receive(make_packet(100, 100), now);
        // 101-104 missing, 105 arrives
        let losses = buf.receive(make_packet(105, 600), now);
        assert_eq!(losses, Some(loss_range(101, 104)));
    }

    #[test]
    fn detect_losses_with_partially_buffered_gap() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(100, 120, start, 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        buf.receive(make_packet(100, 100), now);
        // 102 arrives first (101 lost)
        buf.receive(make_packet(102, 300), now);
        // 104 arrives: gap is 103, but 102 is already buffered
        let losses = buf.receive(make_packet(104, 500), now);
        assert_eq!(losses, Some(loss_range(103, 103)));
    }

    #[test]
    fn loss_frontier_does_not_revisit_a_persistent_old_hole() {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        assert_eq!(buf.receive(make_packet(1, 1), now), Some(loss_range(0, 0)));
        for seq in 2..DEFAULT_FLOW_WINDOW {
            assert_eq!(buf.receive(make_packet(seq, seq), now), None);
        }

        assert_eq!(buf.loss_detection_frontier, DEFAULT_FLOW_WINDOW - 1);
        assert_eq!(buf.loss_detection_steps(), 1);
        assert_eq!(buf.stats().total_lost, 1);
        assert_eq!(
            buf.generate_periodic_nak().unwrap().loss_ranges,
            vec![loss_range(0, 0)]
        );
    }

    #[test]
    fn loss_frontier_only_exposes_new_gap_after_late_recovery() {
        let mut buf = ReceiverBuffer::new(100, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        assert_eq!(
            buf.receive(make_packet(102, 1), now),
            Some(loss_range(100, 101))
        );
        assert_eq!(buf.receive(make_packet(101, 2), now), None);
        assert_eq!(buf.loss_detection_steps(), 2);
        assert_eq!(
            buf.receive(make_packet(104, 3), now),
            Some(loss_range(103, 103))
        );
        assert_eq!(buf.loss_detection_steps(), 3);
        assert_eq!(buf.loss_detection_frontier, 104);
        assert_eq!(
            buf.generate_periodic_nak().unwrap().loss_ranges,
            vec![loss_range(100, 100), loss_range(103, 103)]
        );
    }

    #[test]
    fn loss_frontier_crosses_31_bit_wrap_once() {
        let initial = 0x7FFF_FFFE;
        let mut buf = ReceiverBuffer::new(initial, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        assert_eq!(
            buf.receive(make_packet(0, 1), now),
            Some(loss_range(0x7FFF_FFFE, 0x7FFF_FFFF))
        );
        assert_eq!(buf.receive(make_packet(1, 2), now), None);
        assert_eq!(buf.receive(make_packet(0x7FFF_FFFF, 3), now), None);
        assert_eq!(buf.loss_detection_frontier, 1);
        assert_eq!(buf.loss_detection_steps(), 2);
        assert_eq!(
            buf.generate_periodic_nak().unwrap().loss_ranges,
            vec![loss_range(0x7FFF_FFFE, 0x7FFF_FFFE)]
        );
    }

    #[test]
    fn drop_range_extends_frontier_without_resurrecting_dropped_positions() {
        let mut buf = ReceiverBuffer::new(100, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        assert_eq!(buf.receive(make_packet(100, 1), now), None);
        let summary = buf.drop_range(103, 104).expect("valid forward drop");
        assert_eq!(summary.sequence_count, 2);
        assert_eq!(buf.loss_detection_frontier, 104);
        assert_eq!(buf.receive(make_packet(105, 2), now), None);
        assert_eq!(
            buf.generate_periodic_nak().unwrap().loss_ranges,
            vec![loss_range(101, 102)]
        );
        assert_eq!(buf.stats().total_lost, 2);
    }

    #[test]
    fn forced_advance_accounts_for_skipped_positions_at_frontier() {
        let mut buf = ReceiverBuffer::new(100, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        buf.advance_expected_sequence(105);
        assert_eq!(buf.loss_detection_frontier, 104);
        assert_eq!(
            buf.receive(make_packet(106, 1), now),
            Some(loss_range(105, 105))
        );
        assert_eq!(buf.loss_detection_steps(), 1);
        assert_eq!(
            buf.generate_periodic_nak().unwrap().loss_ranges,
            vec![loss_range(105, 105)]
        );
    }

    #[test]
    fn jitter_accumulates_over_successive_packets() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(100, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        // First packet establishes the baseline transit time.
        buf.receive(make_packet(100, 1_000), Timestamp::from_micros(2_000));
        assert_eq!(buf.jitter, 0);

        // Second packet with identical transit: d=0, jitter stays 0.
        buf.receive(make_packet(101, 2_000), Timestamp::from_micros(3_000));
        assert_eq!(buf.jitter, 0);

        // Third packet with 160 µs transit change: jitter += (160 - 0)/16 = 10.
        buf.receive(make_packet(102, 3_000), Timestamp::from_micros(4_160));
        assert_eq!(buf.jitter, 10);
    }

    #[test]
    fn advance_expected_seq_skips_buffered_after_recovery() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(100, 120, start, 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);

        // 102 arrives first (100, 101 lost)
        buf.receive(make_packet(102, 300), now);
        assert_eq!(buf.expected_sequence(), 100);

        // 101 arrives (still out of order, 100 missing)
        buf.receive(make_packet(101, 200), now);
        assert_eq!(buf.expected_sequence(), 100);

        // 100 arrives: expected_seq should advance past buffered 101, 102 → 103
        buf.receive(make_packet(100, 100), now);
        assert_eq!(buf.expected_sequence(), 103);
    }

    #[test]
    fn telemetry_counts_retransmit_control_and_undecrypt_transitions() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(100, 120, start, 0);
        let mut packet = make_packet(100, 1_000);
        packet.retransmitted = true;
        buf.receive(packet, Timestamp::from_micros(1_000));
        buf.record_ack_sent();
        buf.record_nak_sent();
        buf.record_undecryptable();

        let stats = buf.stats();
        assert_eq!(stats.total_retransmitted, 1);
        assert_eq!(stats.total_acks_sent, 1);
        assert_eq!(stats.total_naks_sent, 1);
        assert_eq!(stats.total_undecryptable, 1);
        assert_eq!(stats.payload_bytes_in_buffer, 3);
        assert_eq!(stats.max_buffer_packets, DEFAULT_FLOW_WINDOW);
        assert_eq!(
            stats.available_buffer_packets,
            DEFAULT_FLOW_WINDOW.saturating_sub(1)
        );
    }

    #[test]
    fn drop_range_removes_packets_and_losses() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(100, 120, start, 0);

        buf.receive(make_packet(100, 1_000), Timestamp::from_micros(1_000));
        // Skip 101 so it enters the loss list.
        buf.receive(make_packet(102, 3_000), Timestamp::from_micros(3_000));

        let dropped = buf.drop_range(100, 102).expect("bounded range");
        assert_eq!(dropped.sequence_count, 3);
        assert_eq!(dropped.packets_removed, 2);
        assert_eq!(dropped.losses_removed, 1);

        // Packets gone — nothing ready even well past TSBPD.
        assert!(buf.pop_ready(Timestamp::from_micros(10_000_000)).is_none());

        // expected_seq advanced past dropped range.
        assert!(buf.expected_sequence() > 102);
    }

    #[test]
    fn drop_range_rejects_out_of_window_range_before_mutating_state() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::with_buffer_size(100, 120, start, 0, 4);

        let error = buf
            .drop_range(100, 104)
            .expect_err("five packets exceed the four-packet receive window");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(buf.expected_sequence(), 100);
        assert_eq!(buf.stats().total_dropped, 0);
    }

    #[test]
    fn drop_range_rejects_far_future_start_before_classifying_gap() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::with_buffer_size(100, 120, start, 0, 4);

        let error = buf
            .drop_range(105, 105)
            .expect_err("the start lies beyond the four-packet receive window");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(buf.expected_sequence(), 100);
        assert_eq!(buf.loss_detection_frontier, 99);
        assert_eq!(buf.loss_detection_steps(), 0);
        assert_eq!(buf.stats().total_lost, 0);
        assert_eq!(buf.stats().total_dropped, 0);
    }

    #[test]
    fn drop_range_rejects_progress_beyond_expected_bitmap_window() {
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, 32);
        buf.set_tsbpd_enabled(false);
        assert_eq!(
            buf.receive(make_packet(32, 1), now),
            Some(loss_range(0, 31))
        );

        let frontier = buf.loss_detection_frontier;
        let error = buf
            .drop_range(40, 40)
            .expect_err("DROPREQ starts beyond the expected receive window");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(buf.loss_detection_frontier, frontier);
        assert_eq!(
            buf.generate_periodic_nak().unwrap().loss_ranges,
            vec![loss_range(0, 31)]
        );
    }

    #[test]
    fn receiver_buffer_inline_footprint_stays_bounded() {
        let bytes = std::mem::size_of::<ReceiverBuffer>();
        let ack_bytes = std::mem::size_of::<AckTimestampTracker>();
        let link_capacity_bytes = std::mem::size_of::<LinkCapacityEstimator>();
        eprintln!("ReceiverBuffer inline footprint: {bytes} bytes");
        eprintln!("ACK timestamp ring inline footprint: {ack_bytes} bytes");
        eprintln!("link-capacity ring inline footprint: {link_capacity_bytes} bytes");
        assert!(
            bytes <= 512,
            "inline receiver state grew beyond its resource budget: {bytes} bytes"
        );
        assert!(ack_bytes <= 16);
        assert!(link_capacity_bytes <= 32);
    }

    #[test]
    fn drop_range_preserves_bounded_wrapped_ranges() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::with_buffer_size(0x7FFF_FFFE, 120, start, 0, 4);

        let dropped = buf
            .drop_range(0x7FFF_FFFE, 0)
            .expect("three wrapped packets fit the receive window");
        assert_eq!(dropped.sequence_count, 3);
        assert_eq!(buf.expected_sequence(), 1);
    }

    #[test]
    fn drop_range_repairs_deleted_delivery_hint() {
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(100, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        for seq in 100..103 {
            buf.receive(make_packet(seq, seq), now);
        }
        assert_eq!(buf.delivery_seq_hint, Some(100));

        buf.drop_range(100, 100).expect("single-packet range");
        assert_eq!(buf.delivery_seq_hint, Some(101));
        let scans_before = buf.delivery_scan_calls();
        assert_eq!(
            buf.pop_ready(now).map(|packet| packet.sequence_number),
            Some(101)
        );
        assert_eq!(
            buf.pop_ready(now).map(|packet| packet.sequence_number),
            Some(102)
        );
        assert_eq!(buf.delivery_scan_calls(), scans_before);
    }

    #[test]
    fn wrapped_drop_range_repairs_hint_to_successor_after_range() {
        const MAX_SEQUENCE: u32 = 0x7FFF_FFFF;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(MAX_SEQUENCE - 2, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        for seq in [MAX_SEQUENCE - 2, MAX_SEQUENCE - 1, MAX_SEQUENCE, 0, 1, 2] {
            buf.receive(make_packet(seq, seq), now);
        }
        assert_eq!(buf.delivery_seq_hint, Some(MAX_SEQUENCE - 2));

        let summary = buf
            .drop_range(MAX_SEQUENCE - 2, 0)
            .expect("bounded wrapped range");
        assert_eq!(summary.sequence_count, 4);
        assert_eq!(summary.packets_removed, 4);
        assert_eq!(buf.delivery_seq_hint, Some(1));
        let scans_before = buf.delivery_scan_calls();
        assert_eq!(
            buf.pop_ready(now).map(|packet| packet.sequence_number),
            Some(1)
        );
        assert_eq!(
            buf.pop_ready(now).map(|packet| packet.sequence_number),
            Some(2)
        );
        assert_eq!(buf.delivery_scan_calls(), scans_before);
    }

    #[test]
    fn tiny_drop_range_is_local_with_many_future_tsbpd_packets() {
        const RETAINED_PACKETS: u32 = 32_768;
        const DROPPED_SEQUENCE: u32 = RETAINED_PACKETS / 2;
        let received_at = Timestamp::from_micros(1);
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);

        // In-order receive advances expected_seq even though future TSBPD
        // timestamps keep every packet retained. This deliberately exceeds
        // the negotiated flow window and exercises the state shape that made
        // a whole-map DROPREQ scan unsafe.
        for seq in 0..RETAINED_PACKETS {
            buf.receive(make_packet(seq, 1_000_000_000 + seq), received_at);
        }
        assert_eq!(buf.packets.len(), RETAINED_PACKETS as usize);
        assert!(buf.packets.len() > buf.max_buffer_size as usize);
        assert_eq!(buf.delivery_seq_hint, Some(0));

        let summary = buf
            .drop_range(DROPPED_SEQUENCE, DROPPED_SEQUENCE)
            .expect("single-sequence range");
        assert_eq!(summary.sequence_count, 1);
        assert_eq!(summary.packets_removed, 1);
        assert_eq!(summary.losses_removed, 0);
        assert_eq!(buf.packets.len(), RETAINED_PACKETS as usize - 1);
        assert!(!buf.packets.contains_key(&DROPPED_SEQUENCE));
        assert_eq!(buf.delivery_seq_hint, Some(0));
    }

    #[test]
    fn drop_range_keeps_or_advances_first_loss_as_needed() {
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(100, 120, Timestamp::default(), 0);
        buf.set_tsbpd_enabled(false);
        buf.receive(make_packet(103, 1), now);
        assert_eq!(buf.loss_list.first(), Some(100));

        let non_min = buf.drop_range(101, 101).expect("non-minimum loss");
        assert_eq!(non_min.losses_removed, 1);
        assert_eq!(buf.loss_list.first(), Some(100));

        let minimum = buf.drop_range(100, 100).expect("minimum loss");
        assert_eq!(minimum.losses_removed, 1);
        assert_eq!(buf.loss_list.first(), Some(102));
        assert_eq!(
            buf.generate_periodic_nak().unwrap().loss_ranges,
            vec![loss_range(102, 102)]
        );
    }

    #[test]
    fn drop_range_bulk_clears_dense_maximum_window() {
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        buf.receive(make_packet(DEFAULT_FLOW_WINDOW - 1, 1), now);
        assert_eq!(buf.loss_list.len(), (DEFAULT_FLOW_WINDOW - 1) as usize);

        let summary = buf
            .drop_range(0, DEFAULT_FLOW_WINDOW - 1)
            .expect("maximum legal range");
        assert_eq!(summary.sequence_count, DEFAULT_FLOW_WINDOW);
        assert!(buf.loss_list.is_empty());
        assert!(buf.packets.is_empty());
        assert_eq!(buf.loss_list.first(), None);
        assert_eq!(buf.delivery_seq_hint, None);
        assert_eq!(buf.expected_sequence(), DEFAULT_FLOW_WINDOW);
    }

    #[test]
    fn drop_range_bulk_clears_mixed_packet_and_loss_state() {
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::with_buffer_size(100, 120, Timestamp::from_micros(0), 0, 8);
        buf.set_tsbpd_enabled(false);
        for seq in [100, 102, 104] {
            buf.receive(make_packet(seq, seq), now);
        }

        let summary = buf.drop_range(101, 103).expect("bounded mixed range");
        assert_eq!(summary.sequence_count, 3);
        assert!(!buf.packets.contains_key(&102));
        assert!(buf.packets.contains_key(&104));
        assert!(!buf.loss_list.contains(&101));
        assert!(!buf.loss_list.contains(&103));
        assert_eq!(buf.expected_sequence(), 105);
    }
}
