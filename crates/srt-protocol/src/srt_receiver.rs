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
//!
//! ## ACK cadence
//!
//! Defaults are Haivision-identical and RFC-aligned:
//!
//! - Full ACK every **10 ms** = Haivision `COMM_SYN_INTERVAL_US` (`core.h`) /
//!   RFC [draft-sharabayko-srt](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt)
//!   §3.2.4 / [`ACK_INTERVAL_MICROS`].
//! - Light ACK every **64** packets = Haivision `SELF_CLOCK_INTERVAL` /
//!   RFC recommendation / [`LIGHT_ACK_INTERVAL_PACKETS`].
//!
//! There is no public `SRTO_*` for ACK interval. LiveCC/FileCC leave
//! `ACKTimeout_us` / `ACKMaxPackets` at 0, so libsrt stays on the hardcoded
//! SYN path. This crate ships the same SYN defaults; optional coalesce is a
//! product knob, not a new CC default and not `ACKMaxPackets` as a live
//! default.
//!
//! Both intervals are per-connection ([`ConnectionOptions`](crate::ConnectionOptions)
//! / [`ReceiverBuffer::set_ack_coalesce`]), not process-global. Optional
//! coalesce may only raise the interval (never make ACK faster than SYN):
//!
//! | Knob | Min (= default) | Default | Max | Label |
//! |---|---:|---:|---:|---|
//! | Full ACK | 10 ms | 10 ms | 40 ms | Values `> 10 ms` are **non-default / non-RFC-recommended**. Contabo 4× (40 ms, issue #30 comment 5560077515) is the evidence ceiling, **not** the default. |
//! | Light ACK | 64 pkts | 64 pkts | 256 pkts | Values `> 64` are **non-default / non-RFC-recommended**. Contabo 4× (256) is the evidence ceiling, **not** the default. |
//!
//! **Light ACK cadence divergence (documented, not changed):** Haivision
//! `checkACKTimer` escalates `64 × LightACKCount` (64, 128, 192, …) until
//! a full ACK resets the count. This crate resets `packets_since_ack` on
//! every ACK, including Light ACK, so the next Light ACK is again N packets.
//! Stricter Haivision parity is out of scope unless that is the explicit
//! goal.
//!
//! Correctness bounds encoded here:
//!
//! - **TSBPD / TLPKTDROP**: the ACK *timer tick* stays at `COMM_SYN` (10 ms)
//!   so coalescing ACKs does not coarsen idle delivery or too-late drop.
//!   Packet receive still calls `enqueue_ready_data` on every DATA packet.
//! - **SYN semantics stay separate**: NAK (immediate on gap + RTT-based
//!   periodic NAK) and EXP are **not** retargeted by the ACK knob.
//! - **ACKACK / RTT**: ACKACK is generated only for Full ACK (Light ACK
//!   never increments the ACK number). Same-seq ACK suppress after ACKACK
//!   is already mirrored and **kept**. The 40 ms ceiling slows ACKACK→RTT
//!   samples 4× — a known NAK/loss-timing risk, not a reason to raise the
//!   default.
//! - **Small flight / receive window**: a window smaller than 64 packets
//!   does not Light-ACK; full ACK on the COMM_SYN timer is the progress
//!   path. A 40 ms full ACK can stall FC / small flight windows because
//!   ackpoint advance is 4× coarser.
//! - **Configured latency**: hostile if TSBPD latency ≲ 2–3× the ACK
//!   interval (e.g. 120 ms latency with a 40 ms ACK sits on that edge).
//!   The knobs do not hard-reject that pairing.
//!
//! High-fan-in listeners can set the Contabo-measured 4× cell:
//! [`HIGH_FANIN_ACK_INTERVAL_MICROS`] / [`HIGH_FANIN_LIGHT_ACK_INTERVAL_PACKETS`].
//! Do not change the global defaults to those values.

use crate::adaptive_receiver_packet_window::{
    AdaptiveReceiverPacketWindow, MAX_RETIRED_RELEASED_PER_VISIT,
};
use crate::range_bitset::RangeBitset;
use bytes::Bytes;

use std::ops::ControlFlow;

use crate::error::Error;
use crate::srt_handshake::{DEFAULT_FLOW_WINDOW, MAX_FLOW_WINDOW};
use crate::srt_packet::{
    DataPacket, PacketPosition, SRT_HEADER_SIZE, sequence_greater_than, sequence_less_than,
};
use crate::time::Timestamp;

/// Light ACK send interval (packets).
///
/// Haivision `SELF_CLOCK_INTERVAL` / RFC recommendation. Named default
/// **and floor** for [`ConnectionOptions::light_ack_interval_packets`](crate::ConnectionOptions).
pub const LIGHT_ACK_INTERVAL_PACKETS: u32 = 64;

/// Fewest packets between Light ACKs. Equal to the Haivision/RFC default;
/// optional coalesce may only raise this, never lower it.
pub const MIN_LIGHT_ACK_INTERVAL_PACKETS: u32 = LIGHT_ACK_INTERVAL_PACKETS;

/// Most packets between Light ACKs. Contabo 4× evidence ceiling (issue #30
/// comment 5560077515), not a new RFC recommendation.
pub const MAX_LIGHT_ACK_INTERVAL_PACKETS: u32 = 256;

/// Contabo-measured 4× Light ACK coalesce for high-fan-in listeners
/// (issue #30). Optional evidence target; **not** the protocol default.
pub const HIGH_FANIN_LIGHT_ACK_INTERVAL_PACKETS: u32 = MAX_LIGHT_ACK_INTERVAL_PACKETS;

/// Most gaps one receive-side service visit gives up. Each
/// [`ReceiverBuffer::drop_too_late`] call gives up at most the head gap, at
/// a constant cost, and the caller pops what that made ready before asking
/// again, so a backlog of due gaps is retired over several visits instead of
/// in one window-sized pass.
pub const MAX_EXPIRED_GAPS_PER_VISIT: usize = 64;

/// Sequence numbers are carried in the low 31 bits of each wire word.
const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;

/// Full ACK numbers are 31-bit, like libsrt's `CAckNo` (`m_iMaxAckSeqNo`).
const ACK_NUMBER_MASK: u32 = 0x7FFF_FFFF;

/// How far behind the current ACK number an ACKACK may still name a sent
/// ACK: half the 31-bit domain.
const ACK_NUMBER_HALF_DOMAIN: u64 = 1 << 30;

/// Periodic ACK interval (microseconds).
///
/// Haivision/UDT `COMM_SYN_INTERVAL_US` (10 ms). Named default **and floor**
/// for [`ConnectionOptions::ack_interval_micros`](crate::ConnectionOptions).
pub const ACK_INTERVAL_MICROS: u64 = 10_000; // 10ms

/// Fastest full-ACK cadence. Equal to `COMM_SYN`; optional coalesce may
/// only raise this, never make ACK faster than Haivision SYN.
pub const MIN_ACK_INTERVAL_MICROS: u64 = ACK_INTERVAL_MICROS;

/// Slowest full-ACK cadence. Contabo 4× evidence ceiling (40 ms), not a
/// new SYN. Full ACKs are the only ACKACK/RTT samples; 40 ms slows them 4×.
pub const MAX_ACK_INTERVAL_MICROS: u64 = 40_000;

/// Contabo-measured 4× full-ACK coalesce for high-fan-in listeners
/// (issue #30). Optional evidence target; **not** the protocol default.
pub const HIGH_FANIN_ACK_INTERVAL_MICROS: u64 = MAX_ACK_INTERVAL_MICROS;

const _: () = assert!(MIN_ACK_INTERVAL_MICROS == ACK_INTERVAL_MICROS);
const _: () = assert!(MAX_ACK_INTERVAL_MICROS == HIGH_FANIN_ACK_INTERVAL_MICROS);
const _: () = assert!(MIN_LIGHT_ACK_INTERVAL_PACKETS == LIGHT_ACK_INTERVAL_PACKETS);
const _: () = assert!(MAX_LIGHT_ACK_INTERVAL_PACKETS == HIGH_FANIN_LIGHT_ACK_INTERVAL_PACKETS);

/// Clamp a requested full-ACK interval to the supported range.
#[must_use]
pub const fn clamp_ack_interval_micros(interval_micros: u64) -> u64 {
    if interval_micros < MIN_ACK_INTERVAL_MICROS {
        MIN_ACK_INTERVAL_MICROS
    } else if interval_micros > MAX_ACK_INTERVAL_MICROS {
        MAX_ACK_INTERVAL_MICROS
    } else {
        interval_micros
    }
}

/// Clamp a requested Light ACK packet interval to the supported range.
#[must_use]
pub const fn clamp_light_ack_interval_packets(interval_packets: u32) -> u32 {
    if interval_packets < MIN_LIGHT_ACK_INTERVAL_PACKETS {
        MIN_LIGHT_ACK_INTERVAL_PACKETS
    } else if interval_packets > MAX_LIGHT_ACK_INTERVAL_PACKETS {
        MAX_LIGHT_ACK_INTERVAL_PACKETS
    } else {
        interval_packets
    }
}

/// Number of Full ACKs whose send time and position are kept for ACKACK
/// matching (RTT sampling and ACK suppression).
///
/// Contract: an ACKACK samples RTT if it names one of the last 256 Full
/// ACKs this receiver sent. The connection sends at most two Full ACKs per
/// 10 ms ACK interval (the periodic one, plus one forced window-reopen ACK
/// that only a Full ACK advertising zero can arm), so the history covers at
/// least 1.28 s of RTT at the default cadence and proportionally more when
/// ACKs are coalesced. An ACKACK for a sent ACK older than that is still
/// valid input, but yields no RTT sample and no suppression update.
///
/// Cost: one lazily allocated 4 KiB backing per receiver, allocated by the
/// first Full ACK; every connected leg sends periodic Full ACKs.
pub(crate) const MAX_ACK_TIMESTAMPS: usize = 256;
const _: () = assert!(MAX_ACK_TIMESTAMPS.is_power_of_two() && MAX_ACK_TIMESTAMPS >= 2);

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
/// Positions map onto a [`RangeBitset`] of the window rounded up to a power
/// of two (at least 64), allocated on the first loss. A range of losses is
/// one range assignment, so classifying or clearing a gap costs the same at
/// every window size.
#[derive(Debug)]
struct LossBitmap {
    bits: RangeBitset,
    window_size: u32,
    base_seq: u32,
}

impl LossBitmap {
    fn new(base_seq: u32, window_size: u32) -> Self {
        let capacity = window_size
            .max(64)
            .checked_next_power_of_two()
            .expect("receive window must fit the 31-bit sequence comparison domain")
            as usize;
        Self {
            bits: RangeBitset::new(capacity),
            window_size,
            base_seq,
        }
    }

    fn capacity(&self) -> usize {
        self.bits.capacity()
    }

    fn offset(&self, seq: u32) -> Option<u32> {
        let offset = seq.wrapping_sub(self.base_seq) & SEQUENCE_MASK;
        (offset < self.window_size).then_some(offset)
    }

    fn bit_index(&self, seq: u32) -> usize {
        seq as usize & (self.capacity() - 1)
    }

    /// The at most two linear bit ranges holding `count <= capacity`
    /// positions from `first_seq`.
    fn index_ranges(&self, first_seq: u32, count: u32) -> [(usize, usize); 2] {
        let start = self.bit_index(first_seq);
        let end = start + count as usize;
        let capacity = self.capacity();
        if end <= capacity {
            [(start, end), (0, 0)]
        } else {
            [(start, capacity), (0, end - capacity)]
        }
    }

    fn assign_range(&mut self, first_seq: u32, count: u32, value: bool) -> u32 {
        self.index_ranges(first_seq, count)
            .into_iter()
            .map(|(start, end)| self.bits.assign(start, end, value))
            .sum()
    }

    fn remove(&mut self, seq: u32) -> bool {
        if self.is_empty() || self.offset(seq).is_none() {
            return false;
        }
        let index = self.bit_index(seq);
        self.bits.set(index, false)
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
        self.assign_range(first_seq, count, true)
    }

    #[cfg(test)]
    fn insert(&mut self, seq: u32) -> bool {
        self.insert_range(seq, 1) == 1
    }

    fn remove_range(&mut self, first_seq: u32, count: u32) -> u32 {
        if count == 0 || self.is_empty() {
            return 0;
        }
        let offset = first_seq.wrapping_sub(self.base_seq) & SEQUENCE_MASK;
        if offset < self.window_size {
            return self.assign_range(first_seq, count.min(self.window_size - offset), false);
        }

        let until_base = SEQUENCE_MASK - offset + 1;
        if count <= until_base {
            return 0;
        }
        self.assign_range(
            self.base_seq,
            (count - until_base).min(self.window_size),
            false,
        )
    }

    fn contains(&self, seq: u32) -> bool {
        !self.is_empty() && self.offset(seq).is_some() && self.bits.get(self.bit_index(seq))
    }

    fn is_empty(&self) -> bool {
        self.bits.len() == 0
    }

    fn len(&self) -> u32 {
        self.bits.len()
    }

    fn set_base(&mut self, base_seq: u32) {
        self.base_seq = base_seq;
    }

    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        let base_seq = self.base_seq;
        let window_size = self.window_size;
        let mask = self.capacity() - 1;
        let base_index = base_seq as usize & mask;
        (0..self.capacity() / 64).flat_map(move |word_index| {
            let word = self.bits.word(word_index);
            std::iter::successors((word != 0).then_some(word), |word| {
                let next = *word & (*word - 1);
                (next != 0).then_some(next)
            })
            .filter_map(move |word| {
                count_work!(LossEntriesVisited);
                let index = word_index * 64 + word.trailing_zeros() as usize;
                let offset = index.wrapping_sub(base_index) & mask;
                (offset < window_size as usize)
                    .then_some(base_seq.wrapping_add(offset as u32) & SEQUENCE_MASK)
            })
        })
    }

    /// Loss runs in numeric order: the part of the window past the 2^31
    /// wrap first.
    fn for_each_numeric_run(&self, mut emit: impl FnMut(u32, u32)) {
        if self.is_empty() {
            return;
        }
        let mut emit = |start, end| {
            emit(start, end);
            ControlFlow::Continue(())
        };
        const SEQUENCE_MODULUS: u64 = 1 << 31;
        let numeric_end = u64::from(self.base_seq) + u64::from(self.window_size);
        if numeric_end > SEQUENCE_MODULUS {
            let _ =
                self.for_each_run_segment(0, (numeric_end - SEQUENCE_MODULUS) as u32, &mut emit);
            let _ = self.for_each_run_segment(
                self.base_seq,
                (SEQUENCE_MODULUS - u64::from(self.base_seq)) as u32,
                &mut emit,
            );
        } else {
            let _ = self.for_each_run_segment(self.base_seq, self.window_size, &mut emit);
        }
    }

    /// Loss runs in sequence order -- oldest first, so the losses nearest
    /// their drop deadline are named first -- starting at sequence `from`
    /// (or at the window base when `from` is `None` or no longer inside the
    /// window), until `emit` breaks. A run straddling `from` is reported
    /// from `from`; runs split at the 2^31 wrap. A periodic NAK resumes its
    /// report here, so one fire walks only the part of the list it reports.
    fn try_for_each_run_in_sequence_from(
        &self,
        from: Option<u32>,
        mut emit: impl FnMut(u32, u32) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if self.is_empty() {
            return ControlFlow::Continue(());
        }
        let base = self.base_seq;
        let offset_of = |seq: u32| seq.wrapping_sub(base) & SEQUENCE_MASK;
        let start = from
            .map(offset_of)
            .filter(|&offset| offset < self.window_size)
            .unwrap_or(0);
        let first = base.wrapping_add(start) & SEQUENCE_MASK;
        let count = self.window_size - start;
        let before_wrap = (1u64 << 31) - u64::from(first);
        if u64::from(count) <= before_wrap {
            self.for_each_run_segment(first, count, &mut emit)
        } else {
            self.for_each_run_segment(first, before_wrap as u32, &mut emit)?;
            self.for_each_run_segment(0, count - before_wrap as u32, &mut emit)
        }
    }

    /// Runs of `count` positions from `seq`, a span that does not cross the
    /// 2^31 wrap. Each run costs one next-set and one next-clear search, so
    /// a walk reads words in proportion to the runs it reports, however far
    /// apart they are.
    fn for_each_run_segment(
        &self,
        seq: u32,
        count: u32,
        emit: &mut impl FnMut(u32, u32) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        let mut pending: Option<(u32, u32)> = None;
        let mut piece_seq = seq;
        for (start, end) in self.index_ranges(seq, count) {
            let mut merge = |run_start: usize, run_end: usize| {
                let first = piece_seq + (run_start - start) as u32;
                let last = piece_seq + (run_end - start) as u32 - 1;
                pending = match pending {
                    Some((pending_first, pending_last)) if pending_last + 1 == first => {
                        Some((pending_first, last))
                    }
                    Some((pending_first, pending_last)) => {
                        emit(pending_first, pending_last)?;
                        Some((first, last))
                    }
                    None => Some((first, last)),
                };
                ControlFlow::Continue(())
            };
            let mut index = start;
            while let Some(found) = self.bits.next_one(index, end) {
                index = self.word_runs(found, end, &mut merge)?;
            }
            piece_seq += (end - start) as u32;
        }
        match pending {
            Some((first, last)) => emit(first, last),
            None => ControlFlow::Continue(()),
        }
    }

    /// Visit the runs of losses in the data word holding `found` (the first
    /// loss at or after the walk's position), reading that word once; a
    /// run reaching the word's end is followed through the summary levels.
    /// Returns where the walk resumes.
    fn word_runs(
        &self,
        found: usize,
        end: usize,
        visit: &mut impl FnMut(usize, usize) -> ControlFlow<()>,
    ) -> ControlFlow<(), usize> {
        let base = found & !63;
        let limit = (base + 64).min(end);
        let mut word = self.bits.word(base / 64) & (!0u64 << (found - base));
        if limit < base + 64 {
            word &= (1u64 << (limit - base)) - 1;
        }
        while word != 0 {
            let run_start = base + word.trailing_zeros() as usize;
            let run_end = run_start + (word >> (run_start - base)).trailing_ones() as usize;
            if run_end == base + 64 && run_end < end {
                let run_end = self.bits.next_zero(run_end, end).unwrap_or(end);
                visit(run_start, run_end)?;
                return ControlFlow::Continue(run_end);
            }
            visit(run_start, run_end)?;
            word &= (!0u64).checked_shl((run_end - base) as u32).unwrap_or(0);
        }
        ControlFlow::Continue(limit)
    }

    /// The oldest loss in sequence order from the window base.
    fn first(&self) -> Option<u32> {
        if self.is_empty() {
            return None;
        }
        let mask = self.capacity() - 1;
        let start = self.base_seq as usize & mask;
        let index = self
            .bits
            .next_one(start, self.capacity())
            .or_else(|| self.bits.next_one(0, start))?;
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

/// TSBPD wraparound period: a post-wrap timestamp at or above this ends it.
/// libsrt's `CTsbpdTime::updateBaseTime` ends it only within [30 s, 60 s];
/// this receiver accepts any post-wrap timestamp up to
/// `WRAPPING_CARRYOVER_BELOW`, where the carry it folds into the base is
/// the one `packet_base_time` was already adding, so a run of [30 s, 60 s]
/// packets that was dropped, skipped or never sent cannot leave the period
/// open past the carryover boundary.
const WRAPPING_PERIOD_END_MIN: u64 = 30_000_000;

/// During the wraparound period a timestamp below this is post-wrap and gets
/// the `MAX_TIMESTAMP + 1` carryover; one at or above it is pre-wrap. Half
/// the range separates the two with margin: the period starts at
/// `WRAPPING_PERIOD_START`, so pre-wrap packets still buffered then are within
/// one latency of it, and it ends at the first delivered post-wrap packet or
/// peer KEEPALIVE stamped at least `WRAPPING_PERIOD_END_MIN`, so post-wrap
/// timestamps stay within one latency of that.
const WRAPPING_CARRYOVER_BELOW: u64 = MAX_TIMESTAMP.div_ceil(2);

/// Tracks ACK send times and acknowledged positions (for RTT calculation
/// and ACK suppression).
///
/// Slot `n & (MAX_ACK_TIMESTAMPS - 1)` holds ACK `n` until ACK
/// `n + MAX_ACK_TIMESTAMPS` replaces it. A lookup matches the full 32-bit
/// ACK number, so two generations of one slot never alias. An unused slot
/// holds a number that does not map to it, so no lookup can match it and no
/// separate validity bitmap is needed.
#[derive(Debug)]
struct AckTimestampTracker {
    entries: Option<Box<[AckTimestamp; MAX_ACK_TIMESTAMPS]>>,
}

#[derive(Debug, Clone, Copy)]
struct AckTimestamp {
    ack_number: u32,
    acked_seq: u32,
    send_time: Timestamp,
}

impl AckTimestampTracker {
    fn new() -> Self {
        Self { entries: None }
    }

    fn slot(ack_number: u32) -> usize {
        ack_number as usize & (MAX_ACK_TIMESTAMPS - 1)
    }

    /// Record an ACK send time and the sequence position it acknowledged.
    fn record(&mut self, ack_number: u32, send_time: Timestamp, acked_seq: u32) {
        let entries = self.entries.get_or_insert_with(|| {
            // `!slot` maps to slot `MAX - 1 - slot`, never to `slot` itself
            // (MAX - 1 is odd), so an unused slot never matches a lookup.
            Box::new(std::array::from_fn(|slot| AckTimestamp {
                ack_number: !(slot as u32),
                acked_seq: 0,
                send_time: Timestamp::default(),
            }))
        });
        entries[Self::slot(ack_number)] = AckTimestamp {
            ack_number,
            acked_seq,
            send_time,
        };
    }

    fn get(&self, ack_number: u32) -> Option<&AckTimestamp> {
        let entry = &self.entries.as_ref()?[Self::slot(ack_number)];
        (entry.ack_number == ack_number).then_some(entry)
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

/// The shared receive-clock state inherited by a newly connected group leg.
/// Delay and RTT estimation remain properties of the individual connection.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GroupReceiveTime {
    time_base: i64,
    wrap_generation: u64,
    wrapping: bool,
    drift_us: i64,
}

impl GroupReceiveTime {
    pub(crate) fn phase(self) -> (u64, bool) {
        (self.wrap_generation, self.wrapping)
    }
}

/// Receive buffer.
#[derive(Debug)]
pub struct ReceiverBuffer {
    /// Received packets in an adaptive sparse/dense packet window.
    packets: AdaptiveReceiverPacketWindow<ReceivedPacket, 8>,

    /// Circularly oldest packet still retained locally. Unlike
    /// `expected_seq`, this does not advance until TSBPD delivery or an
    /// explicit drop retires the packet, so it anchors alias-free live span.
    oldest_retained_seq: Option<u32>,

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

    /// Full ACK period for this connection (clamped microseconds).
    /// Stored as `u32` so the two knobs pack into 8 bytes (`MAX` is 40_000).
    ack_interval_micros: u32,

    /// Light ACK packet cadence for this connection (clamped).
    light_ack_interval_packets: u32,

    /// Full ACKs generated so far. The current ACK number is its low 31
    /// bits: libsrt's `CAckNo::incack` rolls 0x7fff_ffff -> 0, and the first
    /// Full ACK is 1 (`common.h:728-735`, `core.cpp:8566-8571`).
    full_acks_sent: u64,

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

    /// Whether the last Full ACK was a periodic one that advertised a full
    /// window; see [`Self::receive_window_reopened`].
    window_reopen_armed: bool,

    /// TSBPD delay (microseconds).
    tsbpd_delay_us: u64,

    /// Whether TSBPD is enabled.
    tsbpd_enabled: bool,

    /// TSBPD time base (TsbpdTimeBase = T_NOW - HSREQ_TIMESTAMP, microseconds).
    /// Signed: a peer whose clock is older than this receiver's epoch (a
    /// bonded member carrying its group's start time, say) puts the base
    /// before zero, and libsrt's steady-clock base never clamps there.
    tsbpd_time_base: i64,

    /// First RTT sample, used to compensate one-way-delay changes while
    /// measuring TSBPD clock drift.
    first_rtt_sample: Option<u32>,

    /// Current TSBPD clock-drift estimate.
    drift_tracer: TsbpdDriftTracer,

    /// Whether the TSBPD wraparound period is active.
    wrapping_period_active: bool,
    /// Counts completed timestamp carries independently of signed clock drift.
    wrap_generation: u64,

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
}

impl ReceiverBuffer {
    /// Only used after the owning connection has relinquished protocol authority.
    pub(crate) fn reclaim_terminal(&mut self, max_packets: usize) -> (usize, bool) {
        let released = self.packets.clear_bounded(max_packets);
        (released, self.packets.is_released())
    }

    /// Create a new receive buffer.
    pub fn new(
        initial_seq: u32,
        tsbpd_delay_ms: u16,
        start_time: Timestamp,
        tsbpd_time_base: i64,
    ) -> Self {
        Self::with_buffer_size(
            initial_seq,
            tsbpd_delay_ms,
            start_time,
            tsbpd_time_base,
            DEFAULT_FLOW_WINDOW,
        )
    }

    /// Create a receive buffer with an explicit permanent packet-window limit.
    pub fn with_buffer_size(
        initial_seq: u32,
        tsbpd_delay_ms: u16,
        start_time: Timestamp,
        tsbpd_time_base: i64,
        max_buffer_size: u32,
    ) -> Self {
        let max_buffer_size = max_buffer_size.clamp(1, MAX_FLOW_WINDOW);
        Self {
            packets: AdaptiveReceiverPacketWindow::new(max_buffer_size, 4),
            oldest_retained_seq: None,
            expected_seq: initial_seq,
            loss_detection_frontier: initial_seq.wrapping_sub(1) & 0x7FFF_FFFF,
            last_advertised_buffer: 0,
            window_reopen_armed: false,
            loss_list: LossBitmap::new(initial_seq, max_buffer_size),
            last_ack_time: start_time,
            last_ack_seq: initial_seq,
            last_ackacked_seq: None,
            last_ackacked_number: None,
            packets_since_ack: 0,
            ack_interval_micros: ACK_INTERVAL_MICROS as u32,
            light_ack_interval_packets: LIGHT_ACK_INTERVAL_PACKETS,
            // The first Full ACK increments this to one, as required by the
            // wire specification.
            full_acks_sent: 0,
            tsbpd_delay_us: tsbpd_delay_ms as u64 * 1000,
            tsbpd_enabled: true,
            tsbpd_time_base,
            first_rtt_sample: None,
            drift_tracer: TsbpdDriftTracer::default(),
            wrapping_period_active: false,
            wrap_generation: 0,
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
        }
    }

    pub(crate) fn group_time(&self) -> GroupReceiveTime {
        GroupReceiveTime {
            time_base: self.tsbpd_time_base,
            wrap_generation: self.wrap_generation,
            wrapping: self.wrapping_period_active,
            drift_us: self.drift_tracer.drift_us(),
        }
    }

    /// Changing a wrap epoch would reinterpret raw packets or losses that
    /// can still be repaired in the old clock. Complete queued events are safe.
    pub(crate) fn group_clock_drained(&self) -> bool {
        self.packets.is_empty() && self.loss_list.is_empty()
    }

    pub(crate) fn inherit_group_time(&mut self, time: GroupReceiveTime) {
        if time.phase() < self.group_time().phase() {
            return;
        }
        self.tsbpd_time_base = time.time_base;
        self.wrap_generation = time.wrap_generation;
        self.wrapping_period_active = time.wrapping;
        self.drift_tracer.drift_us = time.drift_us;
    }

    /// Enable/disable TSBPD.
    pub fn set_tsbpd_enabled(&mut self, enabled: bool) {
        self.tsbpd_enabled = enabled;
    }

    /// Set per-connection ACK coalesce knobs. Values are clamped to
    /// [`MIN_ACK_INTERVAL_MICROS`]..=[`MAX_ACK_INTERVAL_MICROS`] and
    /// [`MIN_LIGHT_ACK_INTERVAL_PACKETS`]..=[`MAX_LIGHT_ACK_INTERVAL_PACKETS`].
    pub fn set_ack_coalesce(&mut self, ack_interval_micros: u64, light_ack_interval_packets: u32) {
        self.ack_interval_micros = clamp_ack_interval_micros(ack_interval_micros) as u32;
        self.light_ack_interval_packets =
            clamp_light_ack_interval_packets(light_ack_interval_packets);
    }

    /// Configured full-ACK interval for this buffer, after clamping.
    #[must_use]
    pub fn ack_interval_micros(&self) -> u64 {
        u64::from(self.ack_interval_micros)
    }

    /// Configured Light ACK interval for this buffer, after clamping.
    ///
    /// Never below [`LIGHT_ACK_INTERVAL_PACKETS`]. A receive window smaller
    /// than that cadence does not Light-ACK; full ACK is the progress path.
    #[must_use]
    pub fn light_ack_interval_packets(&self) -> u32 {
        self.effective_light_ack_interval_packets()
    }

    /// ACK timer period. Always [`ACK_INTERVAL_MICROS`] (`COMM_SYN`) so
    /// TSBPD/TLPKTDROP stay on the SYN tick when ACK is coalesced. Product
    /// knobs cannot make ACK faster than SYN.
    #[must_use]
    pub fn ack_timer_tick_micros(&self) -> u64 {
        u64::from(self.ack_interval_micros).min(ACK_INTERVAL_MICROS)
    }

    /// Whether the ACK timer should emit a (full) ACK this tick.
    ///
    /// The default (10 ms = `COMM_SYN`) emits on every tick unless a Full
    /// ACK already went out less than one interval ago (a DATA-driven
    /// periodic ACK that ran just before a timer due at the same instant,
    /// or a late timer). A coalesced interval (`> COMM_SYN`) emits only
    /// after the configured period has elapsed; intermediate ticks still run
    /// TSBPD/TLPKTDROP.
    ///
    /// Together with the DATA path (which needs a whole interval since the
    /// last ACK of any kind) this keeps non-forced Full ACKs one interval
    /// apart, and each may arm at most one forced reopen Full ACK
    /// ([`Self::receive_window_reopened`]): at most two Full ACKs in any
    /// interval, which is what the ACKACK history (256 Full ACKs) is sized for.
    #[must_use]
    pub fn should_emit_timer_ack(&self, now: Timestamp) -> bool {
        if u64::from(self.ack_interval_micros) <= ACK_INTERVAL_MICROS {
            self.ack_timestamps
                .get_send_time(self.ack_number())
                .is_none_or(|last_full| {
                    now.as_micros().saturating_sub(last_full.as_micros())
                        >= u64::from(self.ack_interval_micros)
                })
        } else {
            self.ack_interval_elapsed(now)
        }
    }

    fn ack_interval_elapsed(&self, now: Timestamp) -> bool {
        now.as_micros()
            .saturating_sub(self.last_ack_time.as_micros())
            >= u64::from(self.ack_interval_micros)
    }

    fn effective_light_ack_interval_packets(&self) -> u32 {
        // Never emit Light ACK more often than Haivision SELF_CLOCK (64).
        // A receive window smaller than that cadence simply never Light-ACKs;
        // full ACK on the COMM_SYN timer is the progress path. Do not lower
        // the interval to a quarter of a small window.
        self.light_ack_interval_packets
            .max(MIN_LIGHT_ACK_INTERVAL_PACKETS)
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

        if let Some(oldest) = self.oldest_retained_seq
            && sequence_less_than(oldest, sequence_number)
        {
            let distance = sequence_number.wrapping_sub(oldest) & SEQUENCE_MASK;
            if distance > self.max_buffer_size {
                self.packets.clear();
            } else {
                let last_discard = sequence_number.wrapping_sub(1) & SEQUENCE_MASK;
                self.packets.remove_range(oldest, last_discard);
            }
        }
        self.refresh_retained_hints();
        // Every loss lies at or after the expected sequence: the skipped
        // ones go in one range clear, and the expected sequence becomes the
        // first loss left or the position after the frontier, at least
        // `sequence_number` either way.
        let skipped = sequence_number.wrapping_sub(self.expected_seq) & SEQUENCE_MASK;
        self.loss_list.remove_range(self.expected_seq, skipped);
        self.expected_seq = self.first_unresolved_seq();
        self.loss_list.set_base(self.expected_seq);
        self.release_retired_packets();
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

        if self.packets.contains_key(seq) {
            self.total_duplicates += 1;
            return None;
        }

        if sequence_less_than(seq, self.expected_seq) {
            self.total_duplicates = self.total_duplicates.saturating_add(1);
            return None;
        }

        // libsrt's circular receiver accepts offsets strictly below its
        // capacity. Anchor that span at the oldest retained TSBPD packet when
        // it precedes expected_seq, so progress cannot alias live storage in a
        // future direct-indexed packet window.
        if !self.sequence_fits_live_span(seq) || !self.has_capacity_for_packet(seq) {
            return None;
        }

        self.total_received += 1;
        self.packets_since_ack += 1;

        self.record_arrival(now, packet_size);
        self.update_jitter(now, packet.timestamp);
        self.check_tsbpd_wrap(packet.timestamp);

        let new_loss_range = self.detect_losses(seq);

        self.insert_retained_packet(
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
        self.release_retired_packets();

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

    /// Feed a peer KEEPALIVE's timestamp to the TSBPD wrap tracking, as
    /// libsrt feeds it to `CTsbpdTime::updateBaseTime` (core.cpp:12673): a
    /// sender idle across the 32-bit wrap stamps no DATA near it, and
    /// without this the first DATA after the pause plays ~71.6 minutes
    /// early, or the period opened before the pause never closes.
    ///
    /// Unlike libsrt, a KEEPALIVE does not close the period while a
    /// pre-wrap packet is still held or a loss is still unresolved (either
    /// could be pre-wrap): closing folds the carry into the base, which
    /// would push such a packet ~71.6 minutes late. Delivery or a later
    /// KEEPALIVE closes it once they are gone.
    pub fn handle_keepalive(&mut self, timestamp: u32) {
        if !self.tsbpd_enabled {
            return;
        }
        if !self.wrapping_period_active {
            self.check_tsbpd_wrap(timestamp);
            return;
        }
        let pre_wrap_held = self
            .oldest_retained_seq
            .and_then(|seq| self.packets.get(seq))
            .is_some_and(|entry| u64::from(entry.timestamp) >= WRAPPING_CARRYOVER_BELOW);
        if !pre_wrap_held && self.loss_list.is_empty() {
            self.end_wrapping_period_at(timestamp);
        }
    }

    /// Close an open wrap period when post-wrap `timestamp` is past
    /// `WRAPPING_PERIOD_END_MIN`, folding the carry into the base.
    fn end_wrapping_period_at(&mut self, timestamp: u32) {
        if (WRAPPING_PERIOD_END_MIN..WRAPPING_CARRYOVER_BELOW).contains(&u64::from(timestamp)) {
            self.tsbpd_time_base += MAX_TIMESTAMP as i64 + 1;
            self.wrap_generation += 1;
            self.wrapping_period_active = false;
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
        self.total_lost += u64::from(count);
        self.loss_detection_frontier = seq;
        (count != 0).then(|| LossRange {
            first_seq: first,
            last_seq: seq.wrapping_sub(1) & SEQUENCE_MASK,
        })
    }

    fn newly_exposed_loss_count(&self, seq: u32) -> u32 {
        if sequence_greater_than(seq, self.loss_detection_frontier) {
            let first = self.loss_detection_frontier.wrapping_add(1) & SEQUENCE_MASK;
            seq.wrapping_sub(first) & SEQUENCE_MASK
        } else {
            0
        }
    }

    fn protocol_occupancy(&self) -> u32 {
        (self.packets.len() as u32).saturating_add(self.loss_list.len())
    }

    fn receive_occupancy(&self) -> u32 {
        self.protocol_occupancy()
            .saturating_add(self.application_backlog_packets)
    }

    fn has_capacity_for_packet(&self, seq: u32) -> bool {
        let recovery_credit = u32::from(self.loss_list.contains(seq));
        let delta = 1u32
            .saturating_add(self.newly_exposed_loss_count(seq))
            .saturating_sub(recovery_credit);
        self.receive_occupancy()
            .checked_add(delta)
            .is_some_and(|occupancy| occupancy <= self.max_buffer_size)
    }

    fn packet_window_base(&self) -> u32 {
        self.oldest_retained_seq
            .filter(|&seq| sequence_less_than(seq, self.expected_seq))
            .unwrap_or(self.expected_seq)
    }

    fn sequence_fits_live_span(&self, seq: u32) -> bool {
        seq.wrapping_sub(self.packet_window_base()) & SEQUENCE_MASK < self.max_buffer_size
    }

    fn insert_retained_packet(&mut self, seq: u32, packet: ReceivedPacket) {
        let replaced = self
            .packets
            .insert(seq, packet)
            .expect("alias-free live span checked by preflight");
        debug_assert!(
            replaced.is_none(),
            "duplicate packet passed receive preflight"
        );
        if self
            .oldest_retained_seq
            .is_none_or(|oldest| sequence_less_than(seq, oldest))
        {
            self.oldest_retained_seq = Some(seq);
        }
    }

    fn remove_retained_packet(&mut self, seq: u32) -> Option<ReceivedPacket> {
        let packet = self.packets.remove(seq)?;
        if self.oldest_retained_seq == Some(seq) {
            let next = self.next_sequence_after(seq);
            self.oldest_retained_seq = next;
        }
        Some(packet)
    }

    fn advance_expected_seq(&mut self, was_expected: bool, recovered_loss: bool) {
        if was_expected && !recovered_loss {
            self.expected_seq = self.expected_seq.wrapping_add(1) & 0x7FFF_FFFF;
        } else if was_expected {
            self.expected_seq = self.first_unresolved_seq();
        }
        self.loss_list.set_base(self.expected_seq);
    }

    /// The oldest position still unresolved: the oldest loss, or the
    /// position after the classification frontier when nothing is missing.
    /// Every position before it was received, dropped or given up, so this
    /// is the next expected sequence -- libsrt's first-loss-or-next ACK
    /// position (`CUDT::getFirstNoncontSequence`) -- found without probing
    /// the received packets it passes.
    fn first_unresolved_seq(&self) -> u32 {
        self.loss_list
            .first()
            .unwrap_or(self.loss_detection_frontier.wrapping_add(1) & SEQUENCE_MASK)
    }

    /// The receiver-clock moment, possibly before this clock's epoch, at
    /// which the sender stamped `timestamp`, before drift correction.
    fn packet_base_time(&self, timestamp: u32) -> i64 {
        let carry =
            if self.wrapping_period_active && u64::from(timestamp) < WRAPPING_CARRYOVER_BELOW {
                MAX_TIMESTAMP as i64 + 1
            } else {
                0
            };
        self.tsbpd_time_base
            .saturating_add(i64::from(timestamp))
            .saturating_add(carry)
    }

    /// A receiver-clock moment as a `Timestamp`; one before the epoch has
    /// already passed, so it is the epoch itself.
    fn local_time(micros: i64) -> Timestamp {
        Timestamp::from_micros(u64::try_from(micros).unwrap_or(0))
    }

    fn delivery_time(&self, entry: &ReceivedPacket) -> Timestamp {
        count_work!(DeadlineProbes);
        if !self.tsbpd_enabled {
            return entry.recv_time;
        }

        Self::local_time(
            self.packet_base_time(entry.timestamp)
                .saturating_add_unsigned(self.tsbpd_delay_us)
                .saturating_add(self.drift_tracer.drift_us()),
        )
    }

    /// The connection-clock-domain moment the sender originally queued this
    /// packet (F01): `packet_base_time` plus the same sender/receiver
    /// clock-drift correction `delivery_time` applies, but WITHOUT TSBPD's
    /// deliberate release delay (`tsbpd_delay_us`) -- that delay is a
    /// buffering policy, not part of the clock-domain conversion this is
    /// for. This keeps the identity `delivery_time == source_time +
    /// tsbpd_delay_us` exactly, and keeps `age()` accurate to within the
    /// receiver's own RTT-sample jitter rather than a further constant
    /// bias of up to `TSBPD_DRIFT_MAX_US`. When TSBPD is disabled there is
    /// no established time base to convert against, so this falls back to
    /// `recv_time`, mirroring `delivery_time`'s own fallback.
    fn source_time(&self, entry: &ReceivedPacket) -> Timestamp {
        if !self.tsbpd_enabled {
            return entry.recv_time;
        }
        Self::local_time(
            self.packet_base_time(entry.timestamp)
                .saturating_add(self.drift_tracer.drift_us()),
        )
    }

    /// Get a deliverable packet (TSBPD).
    pub fn pop_ready(&mut self, now: Timestamp) -> Option<DataPacket> {
        self.pop_ready_with_source_time(now)
            .map(|(packet, _)| packet)
    }

    /// Like [`Self::pop_ready`], additionally returning the packet's source
    /// time (F01) -- when the sender originally queued it (clock-drift
    /// corrected, same as `delivery_time`), not when it arrived
    /// (`recv_time`) or when TSBPD released it (`delivery_time`, which
    /// adds only the deliberate buffering delay on top of this same base:
    /// `delivery_time == source_time + tsbpd_delay_us`). A separate method
    /// (not a new struct field stashing the last value) so
    /// `ReceiverBuffer`'s inline footprint, checked by
    /// `receiver_buffer_inline_footprint_stays_bounded`, does not grow for
    /// callers that don't need this.
    pub fn pop_ready_with_source_time(
        &mut self,
        now: Timestamp,
    ) -> Option<(DataPacket, Timestamp)> {
        // Find a deliverable sequence number.
        let delivery_seq = self.find_deliverable_seq(now)?;

        let entry = self.remove_retained_packet(delivery_seq)?;

        // Computed before the wraparound-period mutation below purely as
        // documentation of intent (this entry's source time logically
        // belongs to "before" the mutation the entry itself triggers), not
        // because the two orderings actually differ: the mutation folds
        // exactly the `MAX_TIMESTAMP + 1` the pre-mutation branch of
        // `packet_base_time` would otherwise add on the fly into the base
        // itself, so for the one packet that triggers it (and every other
        // packet, which the mutation never touches) `source_time` is
        // provably identical whichever side of the mutation it's read on.
        let source_time = self.source_time(&entry);

        // Detect the end of the TSBPD wraparound period. The spec
        // (draft-sharabayko-srt.md, #tsbpd-time-base) and libsrt end it on a
        // packet stamped within [30 s, 60 s]; any later post-wrap packet
        // below `WRAPPING_CARRYOVER_BELOW` ends it here too (see
        // `WRAPPING_PERIOD_END_MIN`), since that run may have been dropped
        // or never sent.
        if self.tsbpd_enabled && self.wrapping_period_active {
            self.end_wrapping_period_at(entry.timestamp);
        }

        Some((
            DataPacket {
                sequence_number: delivery_seq,
                position: entry.position,
                order_flag: entry.order_flag,
                encryption_flag: 0,
                retransmitted: false,
                message_number: entry.message_number,
                timestamp: entry.timestamp,
                dest_socket_id: 0,
                payload: entry.payload,
            },
            source_time,
        ))
    }

    /// Find the deliverable sequence number.
    ///
    /// Live TSBPD preserves circular sequence order even when timestamps
    /// decrease (SRT draft §7.1; libsrt v1.5.7 `CRcvBuffer::isRcvDataReady`).
    /// A future head blocks later packets; searching for another due packet
    /// both reorders the stream and lets one DATA force a window-sized scan.
    fn find_deliverable_seq(&self, now: Timestamp) -> Option<u32> {
        let sequence = self.oldest_retained_seq?;
        if self
            .loss_list
            .first()
            .is_some_and(|loss| sequence_less_than(loss, sequence))
        {
            return None;
        }
        let entry = self.packets.get(sequence)?;
        (!self.tsbpd_enabled || self.delivery_time(entry) <= now).then_some(sequence)
    }

    /// Whether the unread sequence head can be delivered without advancing it.
    pub(crate) fn has_ready_data(&self, now: Timestamp) -> bool {
        self.find_deliverable_seq(now).is_some()
    }

    /// The sequence [`Self::pop_ready`] would deliver at `now`, without
    /// delivering it, for black-box differential tests against libsrt's
    /// `CRcvBuffer::isRcvDataReady` (`crates/srt-libsrt-diff`). Observing
    /// readiness by popping would change the buffer's occupancy.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn deliverable_sequence(&self, now: Timestamp) -> Option<u32> {
        self.find_deliverable_seq(now)
    }

    /// Return the nearest buffered sequence strictly after `sequence_number`
    /// in the 31-bit circular sequence space.
    fn next_sequence_after(&self, sequence_number: u32) -> Option<u32> {
        self.packets.successor_after(sequence_number)
    }

    fn refresh_retained_hints(&mut self) {
        let oldest = self.packets.first_from(self.expected_seq);
        self.oldest_retained_seq = oldest;
    }

    /// Number of sparse pages currently allocated in the adaptive packet window.
    pub fn sparse_pages(&self) -> usize {
        self.packets.sparse_pages()
    }

    /// Number of dense pages currently allocated in the adaptive packet window.
    pub fn dense_pages(&self) -> usize {
        self.packets.dense_pages()
    }

    /// Total page promotions from sparse to dense since buffer creation.
    pub fn promotions(&self) -> usize {
        self.packets.promotions()
    }

    /// Total page demotions from dense to sparse since buffer creation.
    pub fn demotions(&self) -> usize {
        self.packets.demotions()
    }

    /// Total heap bytes owned by the adaptive packet window.
    pub fn packet_window_heap_bytes(&self) -> usize {
        self.packets.heap_bytes()
    }
    /// Whether the current ACK position was already confirmed by an ACKACK.
    ///
    /// Spec §4.8.1: "The ACKACK tells the receiver to stop sending the ACK
    /// position because the sender already knows it. Otherwise, ACKs (with
    /// outdated information) would continue to be sent regularly." Mirrors
    /// libsrt's `m_iRcvLastAckAck == ack` suppression check
    /// (`sendCtrl(UMSG_ACK)`, `core.cpp:8364`).
    fn position_already_ackacked(&self) -> bool {
        self.last_ackacked_number == Some(self.ack_number())
            && self.last_ackacked_seq == Some(self.expected_seq)
    }

    /// Check whether an ACK should be generated.
    pub fn should_send_ack(&self, now: Timestamp) -> bool {
        // Light ACK: every N packets received (default 64 = SELF_CLOCK).
        // At high packet rates the acknowledged position advances between
        // ACKACKs, so a light ACK is never stale.
        //
        // Divergence from Haivision `checkACKTimer`: libsrt escalates
        // `64 × LightACKCount` (64, 128, 192, …) until a full ACK. We
        // reset `packets_since_ack` on every ACK (including Light ACK),
        // so the next Light ACK is again N packets. Documented; not
        // changed here.
        if self.packets_since_ack >= self.effective_light_ack_interval_packets() {
            return true;
        }

        // Periodic ACK: every configured interval (default 10ms).
        if !self.ack_interval_elapsed(now) {
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
        self.generate_ack_inner(now, false)
    }

    /// Whether `ack_number` could have come from an ACK this buffer sent.
    ///
    /// ACK numbers live in libsrt's 31-bit domain, which includes zero once
    /// the counter has wrapped (`CAckNo::incack`); a Light ACK is told apart
    /// by its 4-byte length, not by number zero, and is never ACKACKed. A
    /// number is sent when it lies no further behind the current one than
    /// the number of Full ACKs generated (and within half the domain), so a
    /// number above the highest assigned names an ACK that was never sent.
    /// An *old* number stays valid on purpose: libsrt re-ACKACKs the same
    /// ACK number when it sees a duplicate Full ACK (`srtcore/core.cpp`
    /// `processCtrlAck`), which is exactly what a lost ACKACK produces, so
    /// age alone must not make the input malformed.
    #[must_use]
    pub fn ack_number_was_sent(&self, ack_number: u32) -> bool {
        let behind = self.ack_number().wrapping_sub(ack_number) & ACK_NUMBER_MASK;
        ack_number <= ACK_NUMBER_MASK
            && u64::from(behind) < self.full_acks_sent.min(ACK_NUMBER_HALF_DOMAIN)
    }

    /// Generate a Full ACK regardless of the Light ACK cadence.
    ///
    /// Used when the application has reopened a receive window this buffer
    /// had advertised as zero: only a Small/Full ACK carries the
    /// available-buffer field, so the peer keeps throttling until one is
    /// sent. The cumulative ACK position is untouched -- application
    /// capacity moving must not fabricate delivery progress.
    pub fn generate_full_ack(&mut self, now: Timestamp) -> AckPacket {
        self.generate_ack_inner(now, true)
    }

    /// Whether this buffer holds no data that could still be delivered.
    ///
    /// Positions that were never received are not deliverable and do not
    /// count: a peer that has closed its send half will never fill them, and
    /// waiting for them would hold the connection open on data that cannot
    /// exist. TLPKTDROP retires them the ordinary way.
    #[must_use]
    pub fn is_delivery_drained(&self) -> bool {
        self.packets.is_empty()
    }

    /// The next pending delivery deadline in circular sequence order, if any.
    /// A later packet's earlier timestamp cannot bypass this head.
    ///
    /// This buffer stores individually retained packets and message
    /// fragments, not necessarily complete messages -- a returned deadline
    /// can belong to a packet still waiting on a sibling fragment, not only
    /// to one legitimately waiting on its own playout time. A generic
    /// connection-level timeout (the inactivity timer bounding a
    /// peer-shutdown drain, in particular) must not treat a *future*
    /// deadline here as stalled and truncate it: `tsbpd_delay` is
    /// configurable per session and can exceed any fixed timeout. A
    /// deadline that is not in the future, by contrast, is not by itself
    /// evidence of a legitimate wait -- the caller still has to rule out an
    /// incomplete tail that can never be delivered.
    #[must_use]
    pub fn earliest_pending_deadline(&self) -> Option<Timestamp> {
        self.oldest_retained_seq
            .and_then(|sequence| self.packets.get(sequence))
            .map(|entry| self.delivery_time(entry))
    }

    /// Whether the last periodic Full ACK advertised a full receive window
    /// and this buffer now has free capacity again.
    ///
    /// The zero->positive transition is the one receive-window change that
    /// cannot wait for the next ACK tick: the peer is stopped, and its
    /// progress (if any) may take an unbounded time to arrive. Nonzero ->
    /// larger changes keep the ordinary cadence.
    ///
    /// Only a periodic (non-forced) Full ACK arms this. A Light ACK carries
    /// no window, and a forced reopen ACK that still advertised zero
    /// (DATA arrived first) leaves the next periodic Full ACK to re-advertise
    /// it. Otherwise the Full ACK rate followed packets / 64 for a Light
    /// ACK, or the application's consume rate for a peer that refills each
    /// freed slot at once, and outran the ACKACK history.
    pub fn receive_window_reopened(&self) -> bool {
        self.window_reopen_armed && self.available_buffer_packets() > 0
    }

    fn generate_ack_inner(&mut self, now: Timestamp, force_full: bool) -> AckPacket {
        let is_light = !force_full
            && self.packets_since_ack >= self.effective_light_ack_interval_packets()
            && !self.ack_interval_elapsed(now);

        self.last_ack_time = now;
        self.last_ack_seq = self.expected_seq;
        // Reset every ACK. Haivision instead increments LightACKCount and
        // stretches the next Light ACK to 64× that count until a full ACK.
        self.packets_since_ack = 0;

        if !is_light {
            self.full_acks_sent += 1;
            self.ack_timestamps
                .record(self.ack_number(), now, self.expected_seq);
            self.window_reopen_armed = !force_full && self.available_buffer_packets() == 0;
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
        debug_assert!(
            self.protocol_occupancy().saturating_add(packets) <= self.max_buffer_size,
            "application backlog must transfer occupied packet positions from the receiver"
        );
        self.application_backlog_packets = packets.min(self.max_buffer_size);
    }

    fn available_buffer_packets(&self) -> u32 {
        self.max_buffer_size
            .saturating_sub(self.packets.len() as u32)
            .saturating_sub(self.loss_list.len())
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

    /// Loss ranges oldest first from sequence `from`, until `emit` breaks;
    /// see `LossBitmap::try_for_each_run_in_sequence_from`.
    pub(crate) fn try_for_each_periodic_nak_range_from(
        &self,
        from: Option<u32>,
        mut emit: impl FnMut(LossRange) -> ControlFlow<()>,
    ) {
        let _ = self
            .loss_list
            .try_for_each_run_in_sequence_from(from, |first_seq, last_seq| {
                emit(LossRange {
                    first_seq,
                    last_seq,
                })
            });
    }

    /// Calculate the NAK send interval: (RTT + 4*RTTVar) / 2.
    pub fn nak_interval(&self) -> u64 {
        let interval = (self.rtt as u64 + 4 * self.rtt_var as u64) / 2;
        interval.max(crate::PERIODIC_NAK_INTERVAL_MICROS) // Minimum 20ms.
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
        let drift_sample = (now.as_micros() as i64)
            .saturating_sub(self.packet_base_time(packet_timestamp))
            .saturating_sub(rtt_delta);
        if self.drift_tracer.update(drift_sample) {
            self.tsbpd_time_base = self
                .tsbpd_time_base
                .saturating_add(self.drift_tracer.overdrift_us());
        }
    }

    /// How long past its TSBPD deadline a missing packet with nothing received
    /// after it is still awaited before TLPKTDROP gives up on it.
    fn tlpktdrop_threshold_us(&self) -> u64 {
        ((self.tsbpd_delay_us as u128 * 125 / 100) as u64).max(1_000_000) // Minimum 1 second.
    }

    /// When a group stops waiting for the gap ahead of a packet this member
    /// released, the sender having queued it at `source_time` (in this
    /// receiver's clock): that packet's play time. Like libsrt's group
    /// reader (`CUDTGroup::recv` delivers the lowest readable packet across
    /// members and counts what it passed over as dropped), and like this
    /// receiver's own gaps (see `drop_too_late`). `None` without TSBPD.
    pub(crate) fn gives_up_at(&self, source_time: Timestamp) -> Option<Timestamp> {
        self.tsbpd_enabled.then(|| {
            Timestamp::from_micros(source_time.as_micros().saturating_add(self.tsbpd_delay_us))
        })
    }

    /// Give up, TLPKTDROP style, on the head gap once the packet after it is
    /// due, and return the gap given up.
    ///
    /// Like libsrt, only a gap at the head of the buffer goes: `CUDT::tsbpd`
    /// drops up to the first valid packet when it is due and preceded by a gap
    /// (core.cpp:5693-5703), and `CRcvBuffer::getFirstValidPacketInfo` flags
    /// that gap only when nothing retained comes before it
    /// (buffer_rcv.cpp:677-692). A retained packet the application has not
    /// read yet -- one not yet due behind a later packet with an earlier
    /// timestamp, or one a full delivery queue holds back -- therefore keeps
    /// the loss behind it open, still recoverable by a retransmission. The
    /// next gap becomes the head only after the packets before it are popped,
    /// so one call gives up at most one gap: the caller alternates delivery
    /// and expiry, as libsrt's TSBPD thread does with its reader. One call
    /// costs one successor lookup, one deadline and one range clear however
    /// many losses wait behind the head. The returned range runs from the
    /// oldest loss to the position before the packet that made it due (or to
    /// the classification frontier when no later packet is retained).
    pub fn drop_too_late(&mut self, now: Timestamp) -> Option<LossRange> {
        if !self.tsbpd_enabled {
            return None;
        }
        let gap = self.due_head_gap(now)?;
        let removed = self
            .loss_list
            .remove_range(gap.first_seq, gap.sequence_count());
        self.total_dropped = self.total_dropped.saturating_add(u64::from(removed));
        self.expected_seq = self.first_unresolved_seq();
        self.loss_list.set_base(self.expected_seq);
        Some(gap)
    }

    /// The head gap -- from the oldest loss to the packet retained after it
    /// -- if nothing retained precedes it and that packet is due. Every loss
    /// in the gap shares that packet, so one deadline decides them all. With
    /// nothing retained, the losses wait for the estimated play time plus the
    /// TLPKTDROP threshold.
    fn due_head_gap(&self, now: Timestamp) -> Option<LossRange> {
        let first_seq = self.loss_list.first()?;
        if self
            .oldest_retained_seq
            .is_some_and(|oldest| sequence_less_than(oldest, first_seq))
        {
            return None;
        }
        count_work!(SuccessorProbes);
        let successor = self
            .packets
            .successor_after(first_seq)
            .and_then(|next| Some((next, self.packets.get(next)?)));
        let now = now.as_micros();
        let (last_seq, due) = match successor {
            // Like libsrt (`CUDT::tsbpd` drops up to the first received
            // packet once it is due): the gap goes when the packet after it
            // is due. The 1 s floor of the threshold is the sender's drop
            // rule, not the receiver's.
            Some((next, packet)) => (
                next.wrapping_sub(1) & SEQUENCE_MASK,
                now >= self.delivery_time(packet).as_micros(),
            ),
            None => (
                self.loss_detection_frontier,
                now > self.estimated_tail_drop_time(),
            ),
        };
        due.then_some(LossRange {
            first_seq,
            last_seq,
        })
    }

    /// When a loss with no later packet retained is given up: the play time
    /// estimated from the time base, plus the TLPKTDROP threshold.
    fn estimated_tail_drop_time(&self) -> u64 {
        let carry = if self.wrapping_period_active {
            MAX_TIMESTAMP as i64 + 1
        } else {
            0
        };
        let estimated_delivery = self
            .tsbpd_time_base
            .saturating_add_unsigned(self.tsbpd_delay_us)
            .saturating_add(carry);
        Self::local_time(estimated_delivery)
            .as_micros()
            .saturating_add(self.tlpktdrop_threshold_us())
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
            && first_seq.wrapping_sub(self.expected_seq) & SEQUENCE_MASK >= self.max_buffer_size
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

        if sequence_greater_than(last_seq, self.packet_window_base())
            && !self.sequence_fits_live_span(last_seq)
        {
            return Err(Error::invalid_data(
                "DROPREQ ends beyond the live receive window",
            ));
        }

        let new_losses = self.newly_exposed_loss_count(first_seq);
        if self
            .receive_occupancy()
            .checked_add(new_losses)
            .is_none_or(|occupancy| occupancy > self.max_buffer_size)
        {
            return Err(Error::invalid_data(
                "DROPREQ would exceed receive buffer occupancy",
            ));
        }

        Ok(distance)
    }

    /// Drop all packets in the 31-bit sequence range `[first_seq, last_seq]`
    /// from both the packet buffer and the loss list (DROPREQ path).
    ///
    /// The inclusive range must fit within the negotiated receive window so
    /// this method cannot be used to force unbounded iteration or allocation.
    /// The receive state moves by the range's endpoints: packets and losses
    /// leave in one range clear each and the expected sequence is re-derived,
    /// so the call costs the same at every range width. The dropped packets'
    /// storage is released at most one visit's budget at a time; see
    /// [`Self::release_retired_packets`].
    pub fn drop_range(&mut self, first_seq: u32, last_seq: u32) -> Result<DropRangeSummary, Error> {
        let distance = self.validate_drop_range(first_seq, last_seq)?;
        let sequence_count = distance + 1;
        // A DROPREQ can be the first evidence of sequence progress beyond the
        // classification frontier. Any intervening positions are genuine
        // newly exposed losses; the requested interval itself is accounted as
        // dropped and must never be rediscovered by a later packet.
        self.advance_drop_frontier(first_seq, last_seq);

        // Remove only packets in the requested circular interval. Those
        // become unreachable at once; their storage is released in bounded
        // visits, independent of the interval width.
        let packets_removed = self.remove_drop_packets(first_seq, last_seq);
        let losses_removed = self.remove_drop_losses(first_seq, sequence_count);

        self.total_dropped = self.total_dropped.saturating_add(u64::from(sequence_count));
        self.advance_expected_after_drop();
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
        let distance = last_seq.wrapping_sub(first_seq) & SEQUENCE_MASK;
        let oldest_was_dropped = self
            .oldest_retained_seq
            .is_some_and(|oldest| sequence_in_range(first_seq, distance, oldest));
        let packets_removed = self
            .clip_to_live_span(first_seq, last_seq)
            .and_then(|(first, last)| self.packets.remove_range(first, last))
            .unwrap_or(0) as u32;
        if oldest_was_dropped {
            let next = self.next_sequence_after(last_seq);
            self.oldest_retained_seq = next;
        }
        packets_removed
    }

    /// The part of `first_seq..=last_seq` inside the live packet span. Every
    /// retained packet lies in that span, and the span maps one-to-one onto
    /// the packet window's slots, so a range clear there cannot reach a
    /// retained packet whose slot merely aliases a position outside it.
    fn clip_to_live_span(&self, first_seq: u32, last_seq: u32) -> Option<(u32, u32)> {
        let base = self.packet_window_base();
        let distance = last_seq.wrapping_sub(first_seq) & SEQUENCE_MASK;
        let first_offset = first_seq.wrapping_sub(base) & SEQUENCE_MASK;
        let (start, end) = if first_offset < self.max_buffer_size {
            (first_offset, first_offset + distance)
        } else {
            let lead = base.wrapping_sub(first_seq) & SEQUENCE_MASK;
            if lead > distance {
                return None;
            }
            (0, distance - lead)
        };
        let end = end.min(self.max_buffer_size - 1);
        Some((
            base.wrapping_add(start) & SEQUENCE_MASK,
            base.wrapping_add(end) & SEQUENCE_MASK,
        ))
    }

    fn remove_drop_losses(&mut self, first_seq: u32, sequence_count: u32) -> u32 {
        self.loss_list.remove_range(first_seq, sequence_count)
    }

    fn advance_expected_after_drop(&mut self) {
        self.expected_seq = self.first_unresolved_seq();
        self.loss_list.set_base(self.expected_seq);
    }

    /// Release packets a DROPREQ or a forced advance removed, at most one
    /// visit's budget (`MAX_RETIRED_RELEASED_PER_VISIT` work units). Every
    /// receive, drop and advance runs one, and the owning connection runs one
    /// per ACK tick, so a window-sized removal is released over bounded
    /// visits rather than in the call that made it. Returns whether retired
    /// packets remain.
    pub fn release_retired_packets(&mut self) -> bool {
        if self.packets.has_retired() {
            self.packets.release_retired(MAX_RETIRED_RELEASED_PER_VISIT);
        }
        self.packets.has_retired()
    }

    /// Get the current ACK sequence number (libsrt's 31-bit domain).
    pub fn ack_number(&self) -> u32 {
        (self.full_acks_sent & u64::from(ACK_NUMBER_MASK)) as u32
    }

    /// Seed the Full ACK counter, so a test can reach the ACK number wrap.
    #[cfg(test)]
    pub(crate) fn seed_full_acks_sent_for_test(&mut self, full_acks_sent: u64) {
        self.full_acks_sent = full_acks_sent;
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
        self.record_naks_sent(1);
    }

    pub(crate) fn record_naks_sent(&mut self, count: u32) {
        self.total_naks_sent = self.total_naks_sent.saturating_add(u64::from(count));
    }

    pub(crate) fn record_undecryptable(&mut self) {
        self.total_undecryptable = self.total_undecryptable.saturating_add(1);
    }

    /// The cumulative loss and duplicate counts, read from the counters the
    /// receiver maintains. O(1): unlike [`Self::stats`], it does not walk
    /// the receive buffer, so a transport can fold a retiring connection
    /// into its ledger without work that grows with the window.
    #[must_use]
    pub fn loss_counters(&self) -> ReceiverLossCounters {
        ReceiverLossCounters {
            total_lost: self.total_lost,
            total_duplicates: self.total_duplicates,
        }
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
            packets_in_loss_list: self.loss_list.len(),
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

/// A receiver's cumulative loss and duplicate counts: the scalar part of
/// [`ReceiverStats`], available without a buffer walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiverLossCounters {
    /// Total packets lost; equals [`ReceiverStats::total_lost`].
    pub total_lost: u64,
    /// Total duplicate packets; equals [`ReceiverStats::total_duplicates`].
    pub total_duplicates: u64,
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
    /// Negotiated receiver TSBPD delay (this side's playout latency).
    pub tsbpd_delay_micros: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::WorkCounters;
    use rustc_hash::FxHashSet;

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
        assert!(!losses.bits.is_allocated());
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
        assert_eq!(losses.bits.allocated_bytes(), 0);
        assert!(losses.insert(0));
        let bytes = losses.bits.allocated_bytes();
        eprintln!("default LossBitmap heap footprint: {bytes} bytes");
        assert!(
            bytes <= 1_100,
            "default loss bitmap exceeded its heap budget: {bytes} bytes"
        );
    }

    /// 1,024 data words, three 16-word block levels and two top-level masks.
    #[test]
    fn maximum_loss_bitmap_heap_footprint_stays_bounded() {
        let mut losses = LossBitmap::new(0, MAX_FLOW_WINDOW);
        assert!(losses.insert(0));
        let bytes = losses.bits.allocated_bytes();
        eprintln!("maximum LossBitmap heap footprint: {bytes} bytes");
        assert_eq!(bytes, 8_592);
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

    /// Bitmap words one DATA arrival may read or write, whatever gap it
    /// classifies and whatever the window: a constant, not words per 64
    /// positions.
    const RECEIVE_BITMAP_WORD_LIMIT: u64 = 32;

    /// The windows every work-bound test compares.
    const WORK_BOUND_WINDOWS: [u32; 3] = [32, DEFAULT_FLOW_WINDOW, MAX_FLOW_WINDOW];

    /// F11: classifying the gap a far-ahead DATA exposes is one range
    /// assignment, so its cost does not grow with the gap. The production
    /// ISN is random, so both an aligned and an unaligned start are covered.
    #[test]
    fn wide_gap_classification_work_is_window_independent() {
        let now = Timestamp::from_micros(1_000);
        let mut words = Vec::new();
        for window in WORK_BOUND_WINDOWS {
            for isn in [0, 40] {
                let mut buf = ReceiverBuffer::with_buffer_size(
                    isn,
                    120,
                    Timestamp::from_micros(0),
                    0,
                    window,
                );
                buf.set_tsbpd_enabled(false);
                let far = isn + window - 1;
                let (losses, work) =
                    WorkCounters::measure(|| buf.receive(make_packet(far, 1), now));
                assert_eq!(losses, Some(loss_range(isn, far - 1)));
                assert_eq!(buf.total_lost, u64::from(window - 1));
                words.push((window, isn, work.bitmap_words()));
            }
        }
        eprintln!("(window, isn, bitmap words): {words:?}");
        assert!(
            words
                .iter()
                .all(|&(_, _, words)| words <= RECEIVE_BITMAP_WORD_LIMIT),
            "a gap's classification must not walk the window"
        );

        let mut buf =
            ReceiverBuffer::with_buffer_size(0, 120, Timestamp::from_micros(0), 0, MAX_FLOW_WINDOW);
        buf.set_tsbpd_enabled(false);
        for seq in 0..DEFAULT_FLOW_WINDOW {
            let (losses, work) = WorkCounters::measure(|| buf.receive(make_packet(seq, seq), now));
            assert_eq!(losses, None);
            assert_eq!(
                work.bitmap_words(),
                0,
                "an in-order packet exposes no new position"
            );
        }
    }

    /// Bitmap words one reported loss run may cost a periodic NAK: finding
    /// where the run starts and where it ends, each a constant number of
    /// word and mask reads.
    const NAK_BITMAP_WORDS_PER_RUN: u64 = 24;

    /// F09: a periodic NAK reads bitmap words in proportion to the runs it
    /// reports, not to the window -- with one far loss, nine sparse losses
    /// spread over the window, one window-wide run, and an alternating list
    /// the encoder cuts after 16 runs.
    #[test]
    fn periodic_nak_bitmap_reads_scale_with_runs_not_window() {
        let mut results = Vec::new();
        for window in WORK_BOUND_WINDOWS {
            let base = SEQUENCE_MASK - window / 2;
            let at = |offset: u32| base.wrapping_add(offset) & SEQUENCE_MASK;
            let mut far = LossBitmap::new(base, window);
            far.insert(at(window - 2));
            let mut sparse = LossBitmap::new(base, window);
            for index in 1..=9 {
                sparse.insert(at(window / 10 * index));
            }
            let mut dense = LossBitmap::new(base, window);
            dense.insert_range(base, window);
            let mut alternating = LossBitmap::new(base, window);
            for offset in (0..window).step_by(2) {
                alternating.insert(at(offset));
            }
            for (name, losses, limit_runs) in [
                ("far", &far, None),
                ("sparse", &sparse, None),
                ("dense", &dense, None),
                ("alternating", &alternating, Some(16)),
            ] {
                let mut runs = 0u64;
                let ((), work) = WorkCounters::measure(|| {
                    let _ = losses.try_for_each_run_in_sequence_from(None, |_, _| {
                        runs += 1;
                        if Some(runs) == limit_runs {
                            ControlFlow::Break(())
                        } else {
                            ControlFlow::Continue(())
                        }
                    });
                });
                results.push((window, name, runs, work.bitmap_words()));
            }
        }
        eprintln!("(window, list, runs, bitmap words): {results:?}");
        for &(window, name, runs, words) in &results {
            assert!(
                words <= NAK_BITMAP_WORDS_PER_RUN * (runs + 1),
                "window {window}, {name}: {words} words for {runs} runs"
            );
        }
    }

    /// Packet-window probes one DATA arrival may make, whatever it fills.
    const RECEIVE_SLOT_PROBE_LIMIT: u64 = 8;

    /// F12: filling the hole in front of a retained window-wide suffix
    /// takes the new expected sequence from the loss list and the
    /// classification frontier instead of probing every retained packet.
    #[test]
    fn filling_the_head_hole_does_not_scan_the_retained_suffix() {
        let now = Timestamp::from_micros(1);
        let mut results = Vec::new();
        for window in WORK_BOUND_WINDOWS {
            let mut buf =
                ReceiverBuffer::with_buffer_size(0, 120, Timestamp::from_micros(0), 0, window);
            for seq in 1..window {
                buf.receive(make_packet(seq, 100_000_000), now);
            }
            let (_, work) = WorkCounters::measure(|| buf.receive(make_packet(0, 100_000_000), now));
            assert_eq!(buf.expected_sequence(), window);
            assert!(buf.loss_list.is_empty());
            results.push((window, work.frontier_steps, work.packet_slot_probes));
        }
        eprintln!("(window, frontier steps, slot probes): {results:?}");
        for &(window, steps, probes) in &results {
            assert!(
                steps == 0 && probes <= RECEIVE_SLOT_PROBE_LIMIT,
                "window {window}: {steps} frontier steps, {probes} slot probes"
            );
        }
    }

    /// Positions a DROPREQ gave up between two losses do not pin the
    /// expected sequence once the losses are repaired: like libsrt's
    /// first-loss-or-next ACK position, it moves past everything resolved.
    #[test]
    fn dropped_positions_between_repaired_losses_do_not_pin_the_ack() {
        let mut buf = ReceiverBuffer::new(100, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        let now = Timestamp::from_micros(1_000);
        buf.receive(make_packet(101, 1), now);
        buf.drop_range(103, 104).expect("forward drop");
        buf.receive(make_packet(105, 2), now);
        assert_eq!(loss_set(&buf), FxHashSet::from_iter([100, 102]));

        buf.receive(make_packet(100, 3), now);
        assert_eq!(buf.expected_sequence(), 102);
        buf.receive(make_packet(102, 4), now);
        assert_eq!(buf.expected_sequence(), 106);
        assert_eq!(buf.generate_ack(now).ack_seq, 106);
    }

    /// F01: an ACK tick that expires nothing inspects only the head gap --
    /// one successor lookup and one deadline -- however many losses wait
    /// behind it. A due backlog of gaps is retired in bounded visits.
    #[test]
    fn tlpktdrop_tick_work_is_window_independent() {
        let start = Timestamp::from_micros(0);
        let mut results = Vec::new();
        for window in WORK_BOUND_WINDOWS {
            // One DATA a window ahead, due in 100 s: W - 1 losses behind it.
            let mut buf = ReceiverBuffer::with_buffer_size(0, 120, start, 0, window);
            buf.receive(make_packet(window - 1, 100_000_000), start);
            let mut idle = WorkCounters::default();
            for tick in 1..=8u64 {
                let (dropped, work) = WorkCounters::measure(|| {
                    buf.drop_too_late(Timestamp::from_micros(tick * 10_000))
                });
                assert!(dropped.is_none());
                idle = WorkCounters {
                    loss_entries_visited: idle.loss_entries_visited.max(work.loss_entries_visited),
                    successor_probes: idle.successor_probes.max(work.successor_probes),
                    deadline_probes: idle.deadline_probes.max(work.deadline_probes),
                    bitmap_data_words: idle.bitmap_data_words.max(work.bitmap_words()),
                    ..idle
                };
            }
            assert_eq!(buf.loss_list.len(), window - 1);
            results.push((window, idle));
        }
        eprintln!("(window, worst idle tick): {results:?}");
        for (window, idle) in results {
            assert!(
                idle.loss_entries_visited == 0
                    && idle.successor_probes <= 1
                    && idle.deadline_probes <= 1
                    && idle.bitmap_data_words <= EXPIRY_TICK_BITMAP_WORD_LIMIT,
                "window {window}: {idle:?}"
            );
        }
    }

    /// Bitmap words one given-up gap may cost: finding it and clearing it.
    const EXPIRED_GAP_BITMAP_WORDS: u64 = 24;

    /// F01: a backlog of due gaps goes one head gap per call, each a
    /// constant amount of work, alternating with delivery of the packet the
    /// gap held back, until none is left.
    #[test]
    fn tlpktdrop_due_backlog_retires_one_head_gap_per_call() {
        let start = Timestamp::from_micros(0);
        let late = Timestamp::from_micros(1_000_000);
        for window in WORK_BOUND_WINDOWS {
            let mut buf = ReceiverBuffer::with_buffer_size(0, 120, start, 0, window);
            for seq in (1..window).step_by(2) {
                buf.receive(make_packet(seq, 0), start);
            }
            let gaps = (window / 2) as usize;
            let mut given_up = Vec::new();
            let mut delivered = 0;
            while let (Some(gap), work) = WorkCounters::measure(|| buf.drop_too_late(late)) {
                assert!(
                    work.loss_entries_visited == 0
                        && work.successor_probes <= 1
                        && work.deadline_probes <= 1
                        && work.bitmap_words() <= EXPIRED_GAP_BITMAP_WORDS,
                    "window {window}: {work:?}"
                );
                given_up.push(gap);
                assert!(
                    buf.drop_too_late(late).is_none(),
                    "the packet the gap held back now heads the buffer"
                );
                while buf.pop_ready(late).is_some() {
                    delivered += 1;
                }
            }
            let expected: Vec<_> = (0..window)
                .step_by(2)
                .map(|seq| loss_range(seq, seq))
                .collect();
            assert_eq!(given_up.len(), gaps);
            assert_eq!(given_up, expected);
            assert_eq!(delivered, gaps);
            assert_eq!(buf.expected_sequence(), window);
            assert!(buf.loss_list.is_empty());
            assert_eq!(buf.stats().total_dropped, gaps as u64);
        }
    }

    /// Bitmap words a tick may read to find and inspect the head gap.
    const EXPIRY_TICK_BITMAP_WORD_LIMIT: u64 = 16;

    /// Packet-window probes plus released payloads one DROPREQ may cost:
    /// the retirement budget of one visit plus a constant.
    const DROP_VISIT_SLOT_LIMIT: u64 = 2 * 256 + 16;

    /// Bitmap words one DROPREQ may read or write: two range clears and the
    /// frontier lookup.
    const DROP_BITMAP_WORD_LIMIT: u64 = 96;

    /// A DROPREQ reaching back before the retained span drops only what is
    /// in its range, even where a range position shares a packet-window slot
    /// with a retained packet further on.
    #[test]
    fn a_dropreq_behind_the_span_spares_packets_sharing_its_slots() {
        let now = Timestamp::from_micros(1);
        let window = DEFAULT_FLOW_WINDOW;
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, window);
        for seq in (0..=50).chain([window - 42]) {
            buf.receive(make_packet(seq, 100_000_000), now);
        }
        let behind = 0u32.wrapping_sub(100) & SEQUENCE_MASK;
        let summary = buf.drop_range(behind, 50).expect("valid drop");
        assert_eq!(summary.packets_removed, 51);
        assert!(
            buf.packets.contains_key(window - 42),
            "slot alias was dropped"
        );
        assert_eq!(buf.packets.len(), 1);
    }

    /// Arriving DATA also releases a visit's worth of dropped packets, so a
    /// busy receiver does not wait for ACK ticks to free them.
    #[test]
    fn arriving_data_releases_dropped_packets() {
        let now = Timestamp::from_micros(1);
        let window = DEFAULT_FLOW_WINDOW;
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, window);
        for seq in 0..window {
            buf.receive(make_packet(seq, 100_000_000), now);
        }
        buf.drop_range(0, window - 1).expect("valid drop");
        let mut arrivals = 0;
        while buf.packets.has_retired() {
            assert!(arrivals < 40, "arrivals stopped releasing");
            buf.receive(make_packet(window + arrivals, 100_000_000), now);
            arrivals += 1;
        }
        assert_eq!(buf.packets.len(), arrivals as usize);
    }

    /// Bitmap words one forced advance may read or write.
    const FORCED_ADVANCE_BITMAP_WORD_LIMIT: u64 = 32;

    /// F04: a group member lagging behind a wide gap is advanced one
    /// delivered packet at a time; each advance clears the losses it passes
    /// as a range and re-derives the expected sequence, so it costs the same
    /// at every window.
    #[test]
    fn forced_advance_work_is_window_independent() {
        let now = Timestamp::from_micros(1);
        let mut results = Vec::new();
        for window in WORK_BOUND_WINDOWS {
            let mut laggard =
                ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, window);
            laggard.receive(make_packet(window - 1, 100_000_000), now);
            let mut worst = WorkCounters::default();
            for target in 1..=8 {
                let ((), work) =
                    WorkCounters::measure(|| laggard.advance_expected_sequence(target));
                assert_eq!(laggard.expected_sequence(), target);
                if work.loss_entries_visited + work.bitmap_words() + work.frontier_steps
                    > worst.loss_entries_visited + worst.bitmap_words() + worst.frontier_steps
                {
                    worst = work;
                }
            }
            assert_eq!(laggard.stats().packets_in_loss_list, window - 1 - 8);
            results.push((window, worst));
        }
        for (window, work) in &results {
            eprintln!(
                "window {window}: loss entries {} bitmap words {} frontier steps {} slots {}",
                work.loss_entries_visited,
                work.bitmap_words(),
                work.frontier_steps,
                work.packet_slot_probes
            );
        }
        for (window, work) in results {
            assert!(
                work.loss_entries_visited == 0
                    && work.frontier_steps == 0
                    && work.bitmap_words() <= FORCED_ADVANCE_BITMAP_WORD_LIMIT,
                "window {window}: {work:?}"
            );
        }
    }

    /// F10: a window-wide DROPREQ advances the receive state by the range's
    /// endpoints and retires the packets it covers within a fixed per-visit
    /// budget -- over a retained full window, and over an empty interval
    /// starting at the expected sequence.
    #[test]
    fn wide_dropreq_work_per_visit_is_window_independent() {
        let now = Timestamp::from_micros(1);
        let mut results = Vec::new();
        for window in WORK_BOUND_WINDOWS {
            let mut full =
                ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, window);
            for seq in 0..window {
                full.receive(make_packet(seq, 100_000_000), now);
            }
            let (summary, work) = WorkCounters::measure(|| full.drop_range(0, window - 1));
            assert_eq!(summary.expect("valid drop").packets_removed, window);
            assert_eq!(full.expected_sequence(), window);
            assert!(
                full.is_delivery_drained(),
                "dropped packets are gone at once"
            );
            results.push((window, "retained", work));
            // Their storage goes in bounded visits until none is left.
            let mut visits = 0;
            loop {
                let (more, work) = WorkCounters::measure(|| full.release_retired_packets());
                visits += 1;
                results.push((window, "release visit", work));
                if !more {
                    break;
                }
            }
            assert!(full.packets.is_released());
            assert_eq!(full.sparse_pages() + full.dense_pages(), 0);
            assert!(visits <= window as usize / 192 + 1, "{visits} visits");

            let mut empty =
                ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, window);
            let (summary, work) = WorkCounters::measure(|| empty.drop_range(0, window - 1));
            assert_eq!(summary.expect("valid drop").sequence_count, window);
            assert_eq!(empty.expected_sequence(), window);
            results.push((window, "empty", work));
        }
        for (window, case, work) in results
            .iter()
            .filter(|(_, case, _)| *case != "release visit")
        {
            eprintln!(
                "window {window} {case}: slots {} released {} bitmap words {} frontier steps {}",
                work.packet_slot_probes,
                work.released_chunks,
                work.bitmap_words(),
                work.frontier_steps
            );
        }
        for (window, case, work) in results {
            assert!(
                work.packet_slot_probes + work.released_chunks <= DROP_VISIT_SLOT_LIMIT
                    && work.bitmap_words() <= DROP_BITMAP_WORD_LIMIT
                    && work.frontier_steps == 0,
                "window {window} {case}: {work:?}"
            );
        }
    }

    /// A periodic NAK walks a wrapped window oldest first, resumes inside
    /// either side of the wrap, reports a straddled run from the resume
    /// point, and stops when told to.
    #[test]
    fn sequence_runs_resume_from_a_position_and_stop_on_break() {
        let base = SEQUENCE_MASK - 100;
        let mut losses = LossBitmap::new(base, 200);
        let first = SEQUENCE_MASK - 90;
        losses.insert_range(first, 130);
        losses.remove_range(SEQUENCE_MASK - 20, 41);
        // Oldest first: (first, MASK - 21) before the wrap, then (20, 38).
        let runs_from = |losses: &LossBitmap, from: Option<u32>, limit: usize| {
            let mut runs = Vec::new();
            let _ = losses.try_for_each_run_in_sequence_from(from, |start, end| {
                runs.push((start, end));
                if runs.len() == limit {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            });
            runs
        };
        let older = (first, SEQUENCE_MASK - 21);
        assert_eq!(runs_from(&losses, None, 9), [older, (20, 38)]);
        assert_eq!(
            runs_from(&losses, None, 1),
            [older],
            "a break stops the walk"
        );
        assert_eq!(
            runs_from(&losses, Some(first + 5), 9),
            [(first + 5, SEQUENCE_MASK - 21), (20, 38)]
        );
        assert_eq!(runs_from(&losses, Some(SEQUENCE_MASK - 20), 9), [(20, 38)]);
        assert_eq!(runs_from(&losses, Some(30), 9), [(30, 38)]);
        assert_eq!(runs_from(&losses, Some(39), 9), []);
        assert_eq!(
            runs_from(&losses, Some(base - 1), 9),
            [older, (20, 38)],
            "a resume point outside the window restarts at the base"
        );

        // The small-list path (at most eight losses) orders the same way.
        let mut few = LossBitmap::new(SEQUENCE_MASK - 3, 32);
        for loss in [SEQUENCE_MASK - 1, SEQUENCE_MASK, 0, 2] {
            few.insert(loss);
        }
        assert_eq!(
            runs_from(&few, None, 9),
            [(SEQUENCE_MASK - 1, SEQUENCE_MASK), (0, 0), (2, 2)]
        );
        assert_eq!(runs_from(&few, Some(0), 9), [(0, 0), (2, 2)]);
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
        assert!(losses.contains(0x7FFF_FFFF));
    }

    #[test]
    fn test_receiver_buffer_new() {
        let start = Timestamp::from_micros(0);
        let buf = ReceiverBuffer::new(1000, 120, start, 0);
        assert_eq!(buf.expected_sequence(), 1000);
    }

    #[test]
    fn zero_receive_window_is_clamped_to_one_slot() {
        let buf = ReceiverBuffer::with_buffer_size(1000, 120, Timestamp::default(), 0, 0);
        assert_eq!(buf.max_buffer_size, 1);
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

    #[test]
    fn receiver_enforces_strict_flow_window_boundary_and_retained_capacity() {
        const WINDOW: u32 = 32;
        let now = Timestamp::from_micros(1);
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, WINDOW);

        // Future TSBPD timestamps retain every in-order packet even while the
        // ACK position advances beyond them.
        for seq in 0..WINDOW {
            assert_eq!(
                buf.receive(make_packet(seq, 1_000_000_000 + seq), now),
                None
            );
        }
        assert_eq!(buf.expected_sequence(), WINDOW);
        assert_eq!(buf.packets.len(), WINDOW as usize);
        assert_eq!(buf.oldest_retained_seq, Some(0));
        assert_eq!(buf.receive_occupancy(), WINDOW);
        assert_eq!(buf.available_buffer_packets(), 0);

        // libsrt's ring boundary is offset < capacity: position 32 cannot
        // coexist with retained position 0 in a 32-slot window.
        assert_eq!(
            buf.receive(make_packet(WINDOW, 1_000_000_000 + WINDOW), now),
            None
        );
        assert_eq!(buf.stats().total_received, u64::from(WINDOW));
        assert_eq!(buf.packets.len(), WINDOW as usize);
        assert_eq!(buf.loss_detection_frontier, WINDOW - 1);
    }

    #[test]
    fn loss_reservations_allow_recovery_at_zero_free_capacity() {
        const WINDOW: u32 = 32;
        let now = Timestamp::from_micros(1);
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, WINDOW);

        assert_eq!(
            buf.receive(make_packet(WINDOW - 1, 1_000_000_000), now),
            Some(loss_range(0, WINDOW - 2))
        );
        assert_eq!(buf.packets.len(), 1);
        assert_eq!(buf.loss_list.len(), WINDOW - 1);
        assert_eq!(buf.receive_occupancy(), WINDOW);
        assert_eq!(buf.available_buffer_packets(), 0);

        // Replacing one reserved loss with its packet has zero occupancy
        // delta and must remain admissible even at an advertised zero window.
        assert_eq!(buf.receive(make_packet(0, 1_000_000_000), now), None);
        assert!(buf.packets.contains_key(0));
        assert!(!buf.loss_list.contains(0));
        assert_eq!(buf.packets.len(), 2);
        assert_eq!(buf.loss_list.len(), WINDOW - 2);
        assert_eq!(buf.receive_occupancy(), WINDOW);
        assert_eq!(buf.available_buffer_packets(), 0);
    }

    #[test]
    fn retained_packet_anchors_drop_progress_across_sequence_wrap() {
        const WINDOW: u32 = 32;
        let now = Timestamp::from_micros(1);

        for initial in [0, SEQUENCE_MASK - 15] {
            let mut buf =
                ReceiverBuffer::with_buffer_size(initial, 120, Timestamp::default(), 0, WINDOW);
            assert_eq!(buf.receive(make_packet(initial, 1_000_000_000), now), None);

            for offset in 1..WINDOW {
                let seq = initial.wrapping_add(offset) & SEQUENCE_MASK;
                buf.drop_range(seq, seq)
                    .expect("drop remains inside retained packet span");
            }
            let outside = initial.wrapping_add(WINDOW) & SEQUENCE_MASK;
            let error = buf
                .drop_range(outside, outside)
                .expect_err("retained packet prevents a second ring revolution");
            assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
            assert_eq!(buf.oldest_retained_seq, Some(initial));
            assert_eq!(buf.packets.len(), 1);
        }
    }

    #[test]
    fn application_backlog_consumes_and_restores_receive_capacity() {
        const WINDOW: u32 = 32;
        let now = Timestamp::from_micros(1);
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, WINDOW);
        buf.set_tsbpd_enabled(false);

        buf.set_application_backlog_packets(WINDOW);
        assert_eq!(buf.available_buffer_packets(), 0);
        assert_eq!(buf.receive(make_packet(0, 1), now), None);
        assert_eq!(buf.stats().total_received, 0);

        buf.set_application_backlog_packets(WINDOW - 1);
        assert_eq!(buf.receive(make_packet(0, 1), now), None);
        assert_eq!(buf.stats().total_received, 1);
        assert_eq!(buf.receive_occupancy(), WINDOW);

        buf.set_application_backlog_packets(0);
        assert_eq!(buf.available_buffer_packets(), WINDOW - 1);
    }

    #[test]
    fn application_backlog_bounds_forward_drop_loss_reservations() {
        const WINDOW: u32 = 32;
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, WINDOW);
        buf.set_application_backlog_packets(WINDOW - 1);

        let error = buf
            .drop_range(2, 2)
            .expect_err("two new losses do not fit beside 31 queued packets");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(buf.loss_detection_frontier, SEQUENCE_MASK);
        assert!(buf.loss_list.is_empty());

        buf.set_application_backlog_packets(WINDOW - 2);
        buf.drop_range(2, 2)
            .expect("two reservations exactly fill the receive capacity");
        assert_eq!(buf.loss_list.len(), 2);
        assert_eq!(buf.receive_occupancy(), WINDOW);
        assert_eq!(buf.available_buffer_packets(), 0);
    }

    #[test]
    fn forced_advance_retires_old_packets_before_rebasing_live_span() {
        const WINDOW: u32 = 32;
        let now = Timestamp::from_micros(1);
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, WINDOW);
        assert_eq!(buf.receive(make_packet(0, 1_000_000_000), now), None);
        assert_eq!(buf.oldest_retained_seq, Some(0));

        buf.advance_expected_sequence(WINDOW);
        assert!(buf.packets.is_empty());
        assert_eq!(buf.oldest_retained_seq, None);
        assert_eq!(buf.expected_sequence(), WINDOW);

        assert_eq!(buf.receive(make_packet(WINDOW, 1_000_000_000), now), None);
        assert_eq!(buf.oldest_retained_seq, Some(WINDOW));
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

    /// Full ACK numbers follow libsrt's 31-bit `CAckNo` domain: 0x7fff_ffff
    /// rolls to 0, which is a real, ACKACK-able number (`common.h:728-735`).
    #[test]
    fn ack_numbers_follow_libsrts_31_bit_domain_through_zero() {
        let mut receiver = ReceiverBuffer::new(1000, 120, Timestamp::from_micros(0), 0);
        receiver.set_tsbpd_enabled(false);
        assert!(!receiver.ack_number_was_sent(0), "nothing sent yet");
        receiver.full_acks_sent = 0x7FFF_FFFD;
        assert!(
            !receiver.ack_number_was_sent(0),
            "zero is not sent before the wrap"
        );

        for (index, expected) in [0x7FFF_FFFE, 0x7FFF_FFFF, 0, 1].into_iter().enumerate() {
            let now = Timestamp::from_micros(10_000 + index as u64 * 10_000);
            let ack = receiver.generate_ack_inner(now, true);
            assert!(!ack.is_light);
            assert_eq!(receiver.ack_number(), expected);
            assert_eq!(ack.ack_seq, 1000);
            assert!(receiver.ack_number_was_sent(expected));
            assert!(!receiver.ack_number_was_sent(expected | 0x8000_0000));
            assert!(!receiver.ack_number_was_sent((expected + 1) & 0x7FFF_FFFF));
            receiver.handle_ackack(expected, 0, now.add_micros(2_000));
            assert_eq!(receiver.last_ackacked_number, Some(expected));
        }
    }

    /// The documented ACKACK history: the last 256 Full ACKs, which is at
    /// least one second at two Full ACKs per 10 ms interval.
    const ACKACK_HISTORY_ACKS: u32 = 256;

    /// RTT after one ACKACK sample, per the §4.10 EWMA in `handle_ackack`.
    fn smoothed_rtt(rtt: u32, sample: u32) -> u32 {
        rtt * 7 / 8 + sample / 8
    }

    /// A receiver with no TSBPD, so an ACKACK only updates RTT and
    /// ACK suppression.
    fn ackack_receiver() -> ReceiverBuffer {
        let mut receiver = ReceiverBuffer::new(1000, 120, Timestamp::from_micros(0), 0);
        receiver.set_tsbpd_enabled(false);
        receiver
    }

    /// Send `count` Full ACKs `spacing_us` apart, the first at `first_us`.
    /// Returns the time of the last one.
    fn send_full_acks(
        receiver: &mut ReceiverBuffer,
        first_us: u64,
        spacing_us: u64,
        count: u64,
    ) -> Timestamp {
        let mut now = Timestamp::from_micros(first_us);
        for index in 0..count {
            now = Timestamp::from_micros(first_us + index * spacing_us);
            assert!(!receiver.generate_full_ack(now).is_light);
        }
        now
    }

    /// Deliver an ACKACK and assert it takes an RTT sample of exactly
    /// `sample_us` and confirms `ack_number` for ACK suppression.
    fn assert_ackack_samples(
        receiver: &mut ReceiverBuffer,
        ack_number: u32,
        now: Timestamp,
        sample_us: u32,
    ) {
        let before = receiver.rtt();
        assert!(receiver.ack_number_was_sent(ack_number));
        receiver.handle_ackack(ack_number, 0, now);
        assert_eq!(
            receiver.rtt(),
            smoothed_rtt(before, sample_us),
            "ACKACK #{ack_number} must take an RTT sample of {sample_us} us"
        );
        assert_eq!(receiver.last_ackacked_number, Some(ack_number));
    }

    /// Deliver an ACKACK for a sent ACK that has left the history: it is
    /// still valid input, but yields no RTT sample and no suppression update.
    fn assert_ackack_evicted(receiver: &mut ReceiverBuffer, ack_number: u32, now: Timestamp) {
        let (rtt, rtt_var) = (receiver.rtt(), receiver.rtt_var());
        let suppression = (receiver.last_ackacked_number, receiver.last_ackacked_seq);
        assert!(receiver.ack_number_was_sent(ack_number));
        receiver.handle_ackack(ack_number, 0, now);
        assert_eq!((receiver.rtt(), receiver.rtt_var()), (rtt, rtt_var));
        assert_eq!(
            (receiver.last_ackacked_number, receiver.last_ackacked_seq),
            suppression
        );
    }

    /// More than 16 later Full ACKs must not cost the RTT sample of an
    /// ACKACK that arrives a 250 ms round trip later (§4.10).
    #[test]
    fn ackack_after_many_later_full_acks_still_samples_rtt() {
        let mut receiver = ackack_receiver();
        send_full_acks(&mut receiver, 10_000, 10_000, 1);
        assert_eq!(receiver.ack_number(), 1);
        send_full_acks(&mut receiver, 20_000, 10_000, 24);
        assert_eq!(receiver.ack_number(), 25);

        assert_ackack_samples(&mut receiver, 1, Timestamp::from_micros(260_000), 250_000);
    }

    /// The history horizon is a count of Full ACKs, not wall time: the
    /// oldest retained ACK samples RTT and the one before it does not, at
    /// the default 10 ms cadence and at a coalesced 40 ms cadence alike.
    #[test]
    fn ackack_history_horizon_is_counted_in_full_acks() {
        for spacing in [10_000u64, 40_000] {
            let mut receiver = ackack_receiver();
            let horizon = u64::from(ACKACK_HISTORY_ACKS);

            // ACK #1 is the oldest of exactly `horizon` Full ACKs.
            let last = send_full_acks(&mut receiver, spacing, spacing, horizon);
            let now = last.add_micros(1_000);
            let sample = (now.as_micros() - spacing) as u32;
            assert_ackack_samples(&mut receiver, 1, now, sample);

            // Two more Full ACKs: #3 is now the oldest retained, #2 is just
            // outside the horizon.
            let last = send_full_acks(&mut receiver, last.as_micros() + spacing, spacing, 2);
            let now = last.add_micros(1_000);
            assert_ackack_evicted(&mut receiver, 2, now);
            let sample = (now.as_micros() - 3 * spacing) as u32;
            assert_ackack_samples(&mut receiver, 3, now, sample);
        }
    }

    /// ACK identity is the 31-bit number across `0x7fff_ffff -> 0`: two ACKs
    /// that share a slot in different generations never alias.
    #[test]
    fn ackack_history_keeps_exact_identity_across_the_ack_number_wrap() {
        const MASK: u32 = 0x7FFF_FFFF;
        let mut receiver = ackack_receiver();
        let first = MASK - 2;
        receiver.full_acks_sent = u64::from(first - 1);
        let horizon = ACKACK_HISTORY_ACKS;
        let spacing = 10_000u64;
        let send_time =
            |ack_number: u32| spacing * (1 + u64::from(ack_number.wrapping_sub(first) & MASK));

        // A full history whose oldest entry is `first`, straddling the wrap.
        let last = send_full_acks(&mut receiver, send_time(first), spacing, u64::from(horizon));
        assert_eq!(receiver.ack_number(), (first + horizon - 1) & MASK);
        let now = last.add_micros(1_000);
        for ack_number in [MASK, 0, 1] {
            let sample = (now.as_micros() - send_time(ack_number)) as u32;
            assert_ackack_samples(&mut receiver, ack_number, now, sample);
        }

        // The next ACK takes `first`'s slot in the next generation.
        let reuse = (first + horizon) & MASK;
        assert_eq!(reuse & (horizon - 1), first & (horizon - 1));
        let last = send_full_acks(&mut receiver, send_time(reuse), spacing, 1);
        assert_eq!(receiver.ack_number(), reuse);
        let now = last.add_micros(1_000);
        assert_ackack_evicted(&mut receiver, first, now);
        assert_ackack_samples(&mut receiver, reuse, now, 1_000);
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

    /// The 4 KiB backing is allocated by the first Full ACK, and an unused
    /// slot matches no ACK number: neither zero (which a wrapped counter
    /// assigns) nor the value the slot was initialised with.
    #[test]
    fn ack_timestamp_tracker_allocates_lazily_and_unused_slots_never_match() {
        let mut tracker = AckTimestampTracker::new();
        assert!(tracker.entries.is_none());
        assert_eq!(tracker.get_send_time(0), None);

        let sent = Timestamp::from_micros(1);
        tracker.record(1, sent, 100);
        let bytes = std::mem::size_of_val(
            tracker
                .entries
                .as_deref()
                .expect("the first ACK allocates the fixed backing"),
        );
        assert_eq!(bytes, 4096);

        let slots = 0..MAX_ACK_TIMESTAMPS as u32;
        for ack_number in slots.clone().chain(slots.map(|slot| !slot)) {
            if ack_number != 1 {
                assert_eq!(tracker.get_send_time(ack_number), None, "ACK #{ack_number}");
                assert_eq!(tracker.get_acked_seq(ack_number), None, "ACK #{ack_number}");
            }
        }
        assert_eq!(tracker.get_send_time(1), Some(sent));
        assert_eq!(tracker.get_acked_seq(1), Some(100));
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
    fn test_in_order_receive_does_not_search_for_a_future_sequence() {
        let mut buf = ReceiverBuffer::new(0, 250, Timestamp::from_micros(0), 0);

        let before = WorkCounters::snapshot();
        for seq in 0..512u32 {
            let now_us = (u64::from(seq) + 1) * 1_316;
            let now = Timestamp::from_micros(now_us);
            buf.receive(make_packet(seq, now_us as u32), now);
        }

        assert_eq!(WorkCounters::since(before).frontier_steps, 0);
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
        assert!(buf.loss_list.contains(0));
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
        let _: &AdaptiveReceiverPacketWindow<ReceivedPacket, 8> = &buf.packets;
    }

    #[test]
    fn in_order_receive_and_pop_preserve_sequence_order() {
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
    fn tsbpd_head_blocks_later_packets_with_earlier_timestamps() {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        buf.receive(make_packet(0, 1_000_000), Timestamp::from_micros(0));
        buf.receive(make_packet(1, 0), Timestamp::from_micros(0));
        assert!(buf.pop_ready(Timestamp::from_micros(200_000)).is_none());
        assert_eq!(
            buf.earliest_pending_deadline(),
            Some(Timestamp::from_micros(1_120_000))
        );
        for sequence in [0, 1] {
            assert_eq!(
                buf.pop_ready(Timestamp::from_micros(1_120_000))
                    .map(|packet| packet.sequence_number),
                Some(sequence)
            );
        }
    }

    /// TLPKTDROP gives up only a gap at the head of the buffer, as libsrt
    /// (`CUDT::tsbpd`, core.cpp:5693-5703; `getFirstValidPacketInfo`,
    /// buffer_rcv.cpp:677-692). A future head (a later timestamp) keeps the
    /// loss behind it open even when the packet after the loss is due, so a
    /// retransmission still fills it and all three are delivered in order.
    /// Found by the libsrt receive-buffer differential
    /// (`crates/srt-libsrt-diff`).
    #[test]
    fn tlpktdrop_spares_a_loss_behind_a_future_head() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(0, 120, start, 0);
        buf.receive(make_packet(0, 50_000), start);
        buf.receive(make_packet(2, 10_000), start);
        // 2 is due at 130 ms, the head 0 only at 170 ms.
        let between = Timestamp::from_micros(150_000);
        assert!(buf.drop_too_late(between).is_none());
        assert_eq!(
            buf.expected_sequence(),
            1,
            "the loss is still acknowledged as open"
        );

        buf.receive(make_packet(1, 30_000), between);
        let due = Timestamp::from_micros(170_000);
        let delivered: Vec<_> = std::iter::from_fn(|| buf.pop_ready(due))
            .map(|packet| packet.sequence_number)
            .collect();
        assert_eq!(delivered, [0, 1, 2]);
        assert_eq!(buf.stats().total_dropped, 0);
    }

    #[test]
    fn tsbpd_future_head_readiness_work_does_not_scale_with_window() {
        for window in [32, MAX_FLOW_WINDOW] {
            let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, window);
            for sequence in 0..window {
                buf.receive(
                    make_packet(sequence, 100_000_000 - sequence),
                    Timestamp::from_micros(1),
                );
            }
            assert_eq!(buf.stats().packets_in_buffer, window);
            let before = WorkCounters::snapshot();
            for _ in 0..64 {
                assert!(buf.pop_ready(Timestamp::from_micros(2)).is_none());
            }
            assert!(
                WorkCounters::since(before).deadline_probes <= 64,
                "each unsuccessful readiness check may inspect only the head"
            );
        }
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
        assert_eq!(dropped, Some(loss_range(1000, 1000)));
    }

    /// Like libsrt's receiver (`CUDT::tsbpd`, which drops up to the first
    /// received packet once its play time comes), a loss that is never
    /// resent holds back the packet after it only until that packet is due,
    /// not a further `max(1.25 x latency, 1 s)`: that floor is the sender's
    /// drop rule (`SRT_TLPKTDROP_MINTHRESHOLD_MS`).
    #[test]
    fn a_lost_packet_is_given_up_when_the_next_one_is_due() {
        let start = Timestamp::from_micros(1_000_000);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 500_000);
        // 1000 never arrives; 1001 plays at 500_000 + 200_000 + 120_000.
        buf.receive(make_packet(1001, 200_000), start);
        let due = Timestamp::from_micros(820_000);

        let before = Timestamp::from_micros(819_999);
        assert!(buf.drop_too_late(before).is_none());
        assert!(buf.pop_ready(before).is_none());

        assert_eq!(buf.drop_too_late(due), Some(loss_range(1000, 1000)));
        assert_eq!(
            buf.pop_ready(due).map(|packet| packet.sequence_number),
            Some(1001)
        );
    }

    /// Separate losses go one head gap at a time, each once the packet that
    /// held it back has been delivered.
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

        let late = Timestamp::from_micros(2_000_000);
        let mut dropped = Vec::new();
        let mut delivered = Vec::new();
        while let Some(gap) = buf.drop_too_late(late) {
            dropped.push(gap);
            assert!(
                buf.drop_too_late(late).is_none(),
                "{gap:?} unblocked a packet"
            );
            delivered.extend(buf.pop_ready(late).map(|packet| packet.sequence_number));
        }

        assert_eq!(
            dropped,
            vec![
                loss_range(1000, 1001),
                loss_range(1003, 1003),
                loss_range(1005, 1005)
            ]
        );
        assert_eq!(delivered, [1002, 1004, 1006]);
        assert!(buf.loss_list.is_empty());
        assert_eq!(buf.expected_sequence(), 1007);
    }

    #[test]
    fn tlpktdrop_without_losses_is_empty() {
        let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(true);

        assert!(
            buf.drop_too_late(Timestamp::from_micros(2_000_000))
                .is_none()
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
        assert_eq!(dropped, Some(loss_range(1000, 1000)));

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

    /// A loss behind a retained packet the application has not read goes
    /// only once that packet is delivered and the loss heads the buffer.
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
        // (1002 の delivery_time = 500_000 + 300_000 + 500_000 = 1_300_000)
        buf.receive(make_packet(1002, 300_000), now);

        let late = Timestamp::from_micros(2_400_000);
        assert!(
            buf.drop_too_late(late).is_none(),
            "unread 1000 heads the buffer"
        );
        assert_eq!(
            buf.pop_ready(late).map(|packet| packet.sequence_number),
            Some(1000)
        );
        assert_eq!(buf.drop_too_late(late), Some(loss_range(1001, 1001)));
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
    fn ack_interval_clamps_to_correctness_bounds() {
        assert_eq!(clamp_ack_interval_micros(0), MIN_ACK_INTERVAL_MICROS);
        assert_eq!(
            clamp_ack_interval_micros(1_000_000),
            MAX_ACK_INTERVAL_MICROS
        );
        assert_eq!(
            clamp_ack_interval_micros(ACK_INTERVAL_MICROS),
            ACK_INTERVAL_MICROS
        );
        assert_eq!(
            clamp_ack_interval_micros(HIGH_FANIN_ACK_INTERVAL_MICROS),
            HIGH_FANIN_ACK_INTERVAL_MICROS
        );
        assert_eq!(
            clamp_light_ack_interval_packets(1),
            MIN_LIGHT_ACK_INTERVAL_PACKETS
        );
        assert_eq!(
            clamp_light_ack_interval_packets(65_536),
            MAX_LIGHT_ACK_INTERVAL_PACKETS
        );
        assert_eq!(
            clamp_light_ack_interval_packets(LIGHT_ACK_INTERVAL_PACKETS),
            LIGHT_ACK_INTERVAL_PACKETS
        );
        assert_eq!(
            clamp_light_ack_interval_packets(HIGH_FANIN_LIGHT_ACK_INTERVAL_PACKETS),
            HIGH_FANIN_LIGHT_ACK_INTERVAL_PACKETS
        );
    }

    #[test]
    fn configured_light_ack_interval_is_honored() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);
        buf.set_ack_coalesce(HIGH_FANIN_ACK_INTERVAL_MICROS, 256);

        let now = Timestamp::from_micros(0);
        for i in 0..255 {
            buf.receive(make_packet(1000 + i, i * 100), now);
        }
        assert!(
            !buf.should_send_ack(now),
            "255 packets is below a 256-packet Light ACK interval"
        );

        buf.receive(make_packet(1255, 25_500), now);
        assert!(buf.should_send_ack(now));
        let ack = buf.generate_ack(now);
        assert!(ack.is_light);
        assert_eq!(buf.ack_number(), 0);
    }

    #[test]
    fn configured_ack_interval_defers_full_ack() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);
        buf.set_ack_coalesce(HIGH_FANIN_ACK_INTERVAL_MICROS, 256);

        buf.receive(make_packet(1000, 100), Timestamp::from_micros(0));
        assert!(!buf.should_send_ack(Timestamp::from_micros(10_000)));
        assert!(!buf.should_send_ack(Timestamp::from_micros(39_999)));
        assert!(buf.should_send_ack(Timestamp::from_micros(40_000)));

        let ack = buf.generate_ack(Timestamp::from_micros(40_000));
        assert!(!ack.is_light);
        assert_eq!(buf.ack_number(), 1);
    }

    #[test]
    fn coalesced_ack_keeps_comm_syn_timer_tick() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_ack_coalesce(HIGH_FANIN_ACK_INTERVAL_MICROS, 256);
        assert_eq!(buf.ack_timer_tick_micros(), ACK_INTERVAL_MICROS);
        assert!(!buf.should_emit_timer_ack(Timestamp::from_micros(10_000)));
        assert!(buf.should_emit_timer_ack(Timestamp::from_micros(40_000)));

        let mut defaulted = ReceiverBuffer::new(1000, 120, start, 0);
        defaulted.set_ack_coalesce(MIN_ACK_INTERVAL_MICROS, LIGHT_ACK_INTERVAL_PACKETS);
        assert_eq!(defaulted.ack_timer_tick_micros(), ACK_INTERVAL_MICROS);
        assert!(defaulted.should_emit_timer_ack(Timestamp::from_micros(0)));
    }

    #[test]
    fn small_receive_window_does_not_lower_light_ack_below_haivision_interval() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::with_buffer_size(1000, 120, start, 0, 32);
        buf.set_tsbpd_enabled(false);
        buf.set_ack_coalesce(ACK_INTERVAL_MICROS, MAX_LIGHT_ACK_INTERVAL_PACKETS);
        assert_eq!(
            buf.light_ack_interval_packets(),
            MAX_LIGHT_ACK_INTERVAL_PACKETS
        );

        let now = Timestamp::from_micros(0);
        for i in 0..32 {
            buf.receive(make_packet(1000 + i, i * 100), now);
        }
        assert!(
            !buf.should_send_ack(now),
            "a 32-packet window cannot satisfy Light ACK ≥ 64; full ACK is the path"
        );
        assert!(buf.should_send_ack(Timestamp::from_micros(ACK_INTERVAL_MICROS)));
    }

    #[test]
    fn light_ack_resets_every_interval_unlike_haivision_escalation() {
        // Haivision checkACKTimer escalates 64×LightACKCount (64, 128, 192…)
        // until a full ACK. This crate resets packets_since_ack on every ACK,
        // including Light ACK, so the next Light ACK is again N packets.
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        buf.set_tsbpd_enabled(false);

        let now = Timestamp::from_micros(0);
        for i in 0..64 {
            buf.receive(make_packet(1000 + i, i * 100), now);
        }
        let first = buf.generate_ack(now);
        assert!(first.is_light);
        assert_eq!(buf.ack_number(), 0);

        for i in 0..64 {
            buf.receive(make_packet(1064 + i, (64 + i) * 100), now);
        }
        let second = buf.generate_ack(now);
        assert!(
            second.is_light,
            "second Light ACK fires at 64 packets, not Haivision's escalated 128"
        );
        assert_eq!(buf.ack_number(), 0);
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
        assert_eq!(dropped, Some(loss_range(0x7FFF_FFFE, 0x7FFF_FFFE)));

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
        assert!(buf.loss_list.contains(0x7FFF_FFFD));
        assert!(buf.loss_list.contains(0x7FFF_FFFE));
        assert!(buf.loss_list.contains(0x7FFF_FFFF));
        assert!(buf.loss_list.contains(0));

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
        assert!(buf.loss_list.contains(1001));

        // wrapping_period_active が有効な場合、次側パケット seq 1002 の delivery_time が
        // 推定配信時刻として使用される。seq 1002 の delivery_time はラップ補正付きで
        // = 500_000 + 200_000 + MAX_TIMESTAMP + 1 + 120_000 = 4_295_787_296 μs
        // TLPKTDROP = max(1.25 * 120_000, 1_000_000) = 1_000_000
        // now = 4_295_787_296 + 1_000_000 = 4_296_787_296 で削除される。
        // それより前の時刻では削除されない。
        let before = Timestamp::from_micros(4_295_787_000);
        let dropped = buf.drop_too_late(before);
        assert!(dropped.is_none(), "the unread head keeps the loss open");

        let after = Timestamp::from_micros(4_296_788_000);
        assert_eq!(
            buf.pop_ready(after).map(|packet| packet.sequence_number),
            Some(1000)
        );
        let dropped = buf.drop_too_late(after);
        assert_eq!(
            dropped,
            Some(loss_range(1001, 1001)),
            "閾値超過で削除されるはず"
        );
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

    /// F01: `source_time` must apply the wrap correction for a packet
    /// popped from within the wraparound window, and for the specific
    /// packet that closes that window out (mutating
    /// `tsbpd_time_base`/`wrapping_period_active` as a side effect of
    /// `pop_ready`) -- proving the formula doesn't silently drop the
    /// correction for either. It does NOT distinguish reading `source_time`
    /// before vs. after that mutation: the two are provably identical (see
    /// `pop_ready_with_source_time`'s own comment), so no test could
    /// meaningfully assert an ordering dependency here. Also checks source
    /// time never appears to regress across the boundary.
    #[test]
    fn source_time_across_the_wrap_boundary_is_monotonic_not_reset() {
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);

        let wrap_start_ts = WRAPPING_PERIOD_START as u32;
        let now = Timestamp::from_micros(1_000_000);
        buf.receive(make_packet(1000, wrap_start_ts), now);
        assert!(buf.wrapping_period_active);

        let end_ts: u32 = 40_000_000;
        buf.receive(make_packet(1001, end_ts), now);

        let late = Timestamp::from_micros(4_335_088_000);
        let (pkt0, source_time_0) = buf
            .pop_ready_with_source_time(late)
            .expect("1000 is deliverable");
        assert_eq!(pkt0.sequence_number, 1000);
        assert_eq!(source_time_0, Timestamp::from_micros(WRAPPING_PERIOD_START));

        let (pkt1, source_time_1) = buf
            .pop_ready_with_source_time(late)
            .expect("1001 is deliverable, closing out the wrap window");
        assert_eq!(pkt1.sequence_number, 1001);
        assert_eq!(
            source_time_1,
            Timestamp::from_micros(MAX_TIMESTAMP + 1 + u64::from(end_ts)),
            "the boundary packet's own source time must include the wrap \
             correction, not read as if it were still pre-wrap"
        );
        assert!(
            source_time_1 > source_time_0,
            "source time must keep advancing across the wrap boundary, \
             never appear to jump backward: {source_time_0:?} -> {source_time_1:?}"
        );
    }

    /// Packets still buffered when the wrap period starts are pre-wrap
    /// packets: the carryover must not push them ~71 minutes into the future,
    /// so a live stream crossing `WRAPPING_PERIOD_START` is delivered in
    /// order and in full.
    #[test]
    fn packets_buffered_when_the_wrap_period_starts_stay_in_order() {
        let mut buf = ReceiverBuffer::new(0, 250, Timestamp::from_micros(0), 0);
        let first_ts = WRAPPING_PERIOD_START - 500_000;
        let mut delivered = Vec::new();
        for seq in 0..100u32 {
            let ts = first_ts + u64::from(seq) * 10_000;
            let now = Timestamp::from_micros(ts);
            buf.receive(make_packet(seq, ts as u32), now);
            while let Some(packet) = buf.pop_ready(now) {
                delivered.push(packet.sequence_number);
            }
        }
        let drained = Timestamp::from_micros(first_ts + 100 * 10_000 + 250_000);
        while let Some(packet) = buf.pop_ready(drained) {
            delivered.push(packet.sequence_number);
        }
        assert_eq!(delivered, (0..100).collect::<Vec<_>>());
    }

    #[test]
    fn wrapping_period_ends_at_libsrt_inclusive_upper_boundary() {
        const LIBSRT_END_MAX: u64 = 60_000_000;
        let start = Timestamp::from_micros(0);
        let mut buf = ReceiverBuffer::new(1000, 120, start, 0);
        let now = Timestamp::from_micros(1_000_000);
        buf.receive(make_packet(1000, WRAPPING_PERIOD_START as u32), now);
        buf.receive(make_packet(1001, LIBSRT_END_MAX as u32), now);

        // The wrapped 60-second packet is deliverable after its adjusted
        // timestamp plus the configured TSBPD delay.
        let late = Timestamp::from_micros(MAX_TIMESTAMP + 1 + LIBSRT_END_MAX + 120_000);
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

    /// The wrap period must end even when no delivered packet is stamped
    /// in [30 s, 60 s]: here that run was dropped by DROPREQ, as it could
    /// be by a forced advance or simply never sent during a DATA pause.
    /// Otherwise the carry stops at `WRAPPING_CARRYOVER_BELOW` and every
    /// later packet plays ~71.6 minutes early, without its jitter buffer.
    #[test]
    fn wrap_period_ends_on_a_later_post_wrap_delivery() {
        let at = Timestamp::from_micros;
        let wrap = MAX_TIMESTAMP + 1;
        let mut buf = ReceiverBuffer::new(1000, 120, at(0), 0);
        let pre = MAX_TIMESTAMP - 10_000_000;
        buf.receive(make_packet(1000, pre as u32), at(pre));
        assert!(buf.pop_ready(at(pre + 120_000)).is_some());
        assert!(buf.wrapping_period_active);

        buf.receive(make_packet(1001, 40_000_000), at(wrap + 40_000_000));
        buf.drop_range(1001, 1001)
            .expect("DROPREQ inside the window");
        buf.receive(make_packet(1002, 61_000_000), at(wrap + 61_000_000));
        assert_eq!(
            buf.pop_ready(at(wrap + 61_120_000))
                .map(|packet| packet.sequence_number),
            Some(1002)
        );

        let late = WRAPPING_CARRYOVER_BELOW + 1;
        buf.receive(make_packet(1003, late as u32), at(wrap + late));
        assert!(
            buf.pop_ready(at(wrap + late + 119_999)).is_none(),
            "keeps its latency"
        );
        assert!(buf.pop_ready(at(wrap + late + 120_000)).is_some());
    }

    /// A sender idle across the wrap stamps only KEEPALIVEs near it: one
    /// past `WRAPPING_PERIOD_START` opens the period and one at 35 s closes
    /// it, so DATA resuming even past `WRAPPING_CARRYOVER_BELOW` (a pause
    /// of over 35 minutes) keeps its latency.
    #[test]
    fn keepalives_open_and_close_the_wrap_period_during_a_data_pause() {
        let at = Timestamp::from_micros;
        let wrap = MAX_TIMESTAMP + 1;
        let mut buf = ReceiverBuffer::new(1000, 120, at(0), 0);
        let pre = MAX_TIMESTAMP - 40_000_000;
        buf.receive(make_packet(1000, pre as u32), at(pre));
        assert!(buf.pop_ready(at(pre + 120_000)).is_some());
        assert!(!buf.wrapping_period_active);

        buf.handle_keepalive((MAX_TIMESTAMP - 20_000_000) as u32);
        assert!(buf.wrapping_period_active, "a pre-wrap KEEPALIVE opens it");
        buf.handle_keepalive(35_000_000);
        assert!(
            !buf.wrapping_period_active,
            "a post-wrap KEEPALIVE closes it"
        );

        let resume = WRAPPING_CARRYOVER_BELOW + 1;
        buf.receive(make_packet(1001, resume as u32), at(wrap + resume));
        assert!(
            buf.pop_ready(at(wrap + resume + 119_999)).is_none(),
            "keeps its latency"
        );
        assert!(buf.pop_ready(at(wrap + resume + 120_000)).is_some());
    }

    /// libsrt closes the period on any [30 s, 60 s] KEEPALIVE. With a 60 s
    /// latency a pre-wrap packet can still be buffered then, and folding
    /// the carry into the base would hold it ~71.6 minutes: the KEEPALIVE
    /// must wait until it is delivered.
    #[test]
    fn keepalive_keeps_the_wrap_period_open_while_a_pre_wrap_packet_is_held() {
        let at = Timestamp::from_micros;
        let latency = 60_000_000;
        let mut buf = ReceiverBuffer::new(1000, 60_000, at(0), 0);
        let pre = MAX_TIMESTAMP - 5_000_000;
        buf.receive(make_packet(1000, pre as u32), at(pre));
        assert!(buf.wrapping_period_active);

        buf.handle_keepalive(35_000_000);
        assert!(buf.pop_ready(at(pre + latency - 1)).is_none());
        assert!(
            buf.pop_ready(at(pre + latency)).is_some(),
            "the held pre-wrap packet plays at its own deadline"
        );
        buf.handle_keepalive(56_000_000);
        assert!(
            !buf.wrapping_period_active,
            "and then a KEEPALIVE closes it"
        );
    }

    /// An unresolved loss may be a pre-wrap packet still to be
    /// retransmitted: a KEEPALIVE must not close the period under it even
    /// when the buffered head is already post-wrap.
    #[test]
    fn keepalive_keeps_the_wrap_period_open_while_a_loss_is_unresolved() {
        let at = Timestamp::from_micros;
        let wrap = MAX_TIMESTAMP + 1;
        let latency = 60_000_000;
        let mut buf = ReceiverBuffer::new(1000, 60_000, at(0), 0);
        let pre = MAX_TIMESTAMP - 5_000_000;
        buf.receive(make_packet(1000, pre as u32), at(pre));
        assert!(
            buf.receive(make_packet(1002, 1_000_000), at(wrap + 1_000_000))
                .is_some(),
            "1001 is lost"
        );
        assert_eq!(
            buf.pop_ready(at(pre + latency))
                .map(|packet| packet.sequence_number),
            Some(1000)
        );

        buf.handle_keepalive(56_000_000);
        let retransmitted = pre + 1_000_000;
        buf.receive(
            make_packet(1001, retransmitted as u32),
            at(wrap + 57_000_000),
        );
        assert_eq!(
            buf.pop_ready(at(retransmitted + latency))
                .map(|packet| packet.sequence_number),
            Some(1001),
            "the retransmitted pre-wrap packet plays at its own deadline"
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
        assert_eq!(buf.total_lost, 1);
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
        assert_eq!(buf.total_lost, 2);
        assert_eq!(
            buf.receive(make_packet(104, 3), now),
            Some(loss_range(103, 103))
        );
        assert_eq!(buf.total_lost, 3);
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
        assert_eq!(buf.total_lost, 2);
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
        assert_eq!(buf.total_lost, 1);
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
        assert_eq!(buf.total_lost, 0);
        assert_eq!(buf.stats().total_lost, 0);
        assert_eq!(buf.stats().total_dropped, 0);
    }

    #[test]
    fn drop_range_rejects_progress_beyond_expected_bitmap_window() {
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::with_buffer_size(0, 120, Timestamp::default(), 0, 32);
        buf.set_tsbpd_enabled(false);
        assert_eq!(
            buf.receive(make_packet(31, 1), now),
            Some(loss_range(0, 30))
        );

        let frontier = buf.loss_detection_frontier;
        let error = buf
            .drop_range(40, 40)
            .expect_err("DROPREQ starts beyond the expected receive window");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(buf.loss_detection_frontier, frontier);
        assert_eq!(
            buf.generate_periodic_nak().unwrap().loss_ranges,
            vec![loss_range(0, 30)]
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
    fn drop_range_at_head_preserves_successor_delivery() {
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(100, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        for seq in 100..103 {
            buf.receive(make_packet(seq, seq), now);
        }

        buf.drop_range(100, 100).expect("single-packet range");
        assert_eq!(
            buf.pop_ready(now).map(|packet| packet.sequence_number),
            Some(101)
        );
        assert_eq!(
            buf.pop_ready(now).map(|packet| packet.sequence_number),
            Some(102)
        );
    }

    #[test]
    fn wrapped_drop_range_preserves_successor_delivery() {
        const MAX_SEQUENCE: u32 = 0x7FFF_FFFF;
        let now = Timestamp::from_micros(1_000);
        let mut buf = ReceiverBuffer::new(MAX_SEQUENCE - 2, 120, Timestamp::from_micros(0), 0);
        buf.set_tsbpd_enabled(false);
        for seq in [MAX_SEQUENCE - 2, MAX_SEQUENCE - 1, MAX_SEQUENCE, 0, 1, 2] {
            buf.receive(make_packet(seq, seq), now);
        }

        let summary = buf
            .drop_range(MAX_SEQUENCE - 2, 0)
            .expect("bounded wrapped range");
        assert_eq!(summary.sequence_count, 4);
        assert_eq!(summary.packets_removed, 4);
        assert_eq!(
            buf.pop_ready(now).map(|packet| packet.sequence_number),
            Some(1)
        );
        assert_eq!(
            buf.pop_ready(now).map(|packet| packet.sequence_number),
            Some(2)
        );
    }

    #[test]
    fn tiny_drop_range_is_local_with_many_future_tsbpd_packets() {
        const RETAINED_PACKETS: u32 = if cfg!(miri) { 256 } else { 32_768 };
        const DROPPED_SEQUENCE: u32 = RETAINED_PACKETS / 2;
        let received_at = Timestamp::from_micros(1);
        let mut buf =
            ReceiverBuffer::with_buffer_size(0, 120, Timestamp::from_micros(0), 0, MAX_FLOW_WINDOW);

        // In-order receive advances expected_seq even though future TSBPD
        // timestamps keep every packet retained. A maximum configured window
        // preserves the large-map DROPREQ complexity case without violating
        // the receiver's hard local occupancy bound.
        for seq in 0..RETAINED_PACKETS {
            buf.receive(make_packet(seq, 1_000_000_000 + seq), received_at);
        }
        assert_eq!(buf.packets.len(), RETAINED_PACKETS as usize);
        assert!(buf.packets.len() < buf.max_buffer_size as usize);

        let summary = buf
            .drop_range(DROPPED_SEQUENCE, DROPPED_SEQUENCE)
            .expect("single-sequence range");
        assert_eq!(summary.sequence_count, 1);
        assert_eq!(summary.packets_removed, 1);
        assert_eq!(summary.losses_removed, 0);
        assert_eq!(buf.packets.len(), RETAINED_PACKETS as usize - 1);
        assert!(!buf.packets.contains_key(DROPPED_SEQUENCE));
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
        assert_eq!(buf.loss_list.len(), DEFAULT_FLOW_WINDOW - 1);

        let summary = buf
            .drop_range(0, DEFAULT_FLOW_WINDOW - 1)
            .expect("maximum legal range");
        assert_eq!(summary.sequence_count, DEFAULT_FLOW_WINDOW);
        assert!(buf.loss_list.is_empty());
        assert!(buf.packets.is_empty());
        assert_eq!(buf.loss_list.first(), None);
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
        assert!(!buf.packets.contains_key(102));
        assert!(buf.packets.contains_key(104));
        assert!(!buf.loss_list.contains(101));
        assert!(!buf.loss_list.contains(103));
        assert_eq!(buf.expected_sequence(), 105);
    }

    #[test]
    fn tsbpd_recovered_head_blocks_an_earlier_deadline() {
        let mut buf = ReceiverBuffer::new(0, 100, Timestamp::default(), 0);
        let at = |ms: u64| Timestamp::from_micros(ms * 1_000);
        buf.receive(make_packet(0, 0), at(0));
        buf.receive(make_packet(2, 20_000), at(1));
        assert_eq!(buf.pop_ready(at(100)).map(|p| p.sequence_number), Some(0));
        assert!(buf.pop_ready(at(125)).is_none(), "the missing head blocks");
        buf.receive(make_packet(1, 30_000), at(125));
        assert!(
            buf.pop_ready(at(125)).is_none(),
            "the recovered head is not due"
        );
        for sequence in [1, 2] {
            assert_eq!(
                buf.pop_ready(at(130)).map(|packet| packet.sequence_number),
                Some(sequence)
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn tsbpd_delivery_matches_a_sequence_ordered_queue(
            initial in 0..=SEQUENCE_MASK,
            timestamps in proptest::collection::vec(0..2_000_000u32, 1..64),
        ) {
            let mut buf = ReceiverBuffer::new(initial, 120, Timestamp::default(), 0);
            // Reverse arrival fills gaps, including across sequence wrap.
            for offset in (0..timestamps.len()).rev() {
                let sequence = initial.wrapping_add(offset as u32) & SEQUENCE_MASK;
                buf.receive(make_packet(sequence, timestamps[offset]), Timestamp::default());
            }
            let mut times: Vec<u64> = timestamps.iter().map(|&ts| u64::from(ts) + 120_000).collect();
            times.sort_unstable();
            let mut head = 0;
            for now in times {
                loop {
                    let expected = timestamps.get(head)
                        .filter(|&&ts| u64::from(ts) + 120_000 <= now)
                        .map(|_| initial.wrapping_add(head as u32) & SEQUENCE_MASK);
                    let actual = buf.pop_ready(Timestamp::from_micros(now))
                        .map(|packet| packet.sequence_number);
                    proptest::prop_assert_eq!(actual, expected);
                    if expected.is_none() {
                        break;
                    }
                    head += 1;
                }
            }
            proptest::prop_assert_eq!(head, timestamps.len());
        }
    }

    /// One receive-side entry point the bounded-work proptest drives, with
    /// window-relative arguments (fractions of the window, in 1/65,536ths).
    #[derive(Debug, Clone)]
    enum WorkAction {
        Receive { ahead: u16, timestamp: u32 },
        Duplicate,
        Drop { behind: u16, width: u16 },
        Tick { elapsed: u32 },
        Advance { ahead: u16 },
        Release,
        Pop,
    }

    fn work_action() -> impl proptest::strategy::Strategy<Value = WorkAction> {
        use proptest::prelude::*;
        prop_oneof![
            4 => (any::<u16>(), 0..400_000u32)
                .prop_map(|(ahead, timestamp)| WorkAction::Receive { ahead, timestamp }),
            1 => Just(WorkAction::Duplicate),
            1 => (any::<u16>(), any::<u16>())
                .prop_map(|(behind, width)| WorkAction::Drop { behind, width }),
            2 => (0..300_000u32).prop_map(|elapsed| WorkAction::Tick { elapsed }),
            1 => any::<u16>().prop_map(|ahead| WorkAction::Advance { ahead }),
            1 => Just(WorkAction::Release),
            1 => Just(WorkAction::Pop),
        ]
    }

    /// `fraction` (in 1/65,536ths) of `window`.
    fn window_share(window: u32, fraction: u16) -> u32 {
        ((u64::from(window) * u64::from(fraction)) >> 16) as u32
    }

    /// Per-call work limits every receive-side entry point stays within at
    /// every window: one release visit (256 units) plus a constant of slot
    /// probes, one head gap's successor and deadline (a TLPKTDROP call gives
    /// up at most one), a constant of bitmap words, and never a loss
    /// enumeration or pending-key scan.
    const ENTRY_SLOT_LIMIT: u64 = 2 * 256 + 2 * 64 + 32;
    const ENTRY_GAP_LIMIT: u64 = 3;
    const ENTRY_BITMAP_WORD_LIMIT: u64 = 3 * EXPIRED_GAP_BITMAP_WORDS + DROP_BITMAP_WORD_LIMIT;
    const ENTRY_FRONTIER_STEP_LIMIT: u64 = 2;

    /// Apply one action to `buf` and return the work it did.
    fn apply_work_action(
        buf: &mut ReceiverBuffer,
        action: &WorkAction,
        window: u32,
        clock: &mut u64,
        last: &mut Option<DataPacket>,
    ) -> WorkCounters {
        let expected = buf.expected_sequence();
        let now = Timestamp::from_micros(*clock);
        let ((), work) = WorkCounters::measure(|| match *action {
            WorkAction::Receive { ahead, timestamp } => {
                let sequence = expected.wrapping_add(window_share(window, ahead)) & SEQUENCE_MASK;
                let packet = make_packet(sequence, timestamp);
                *last = Some(packet.clone());
                let _ = buf.receive(packet, now);
            }
            WorkAction::Duplicate => {
                if let Some(packet) = last.clone() {
                    let _ = buf.receive(packet, now);
                }
            }
            WorkAction::Drop { behind, width } => {
                let first = expected.wrapping_sub(window_share(window, behind) / 2) & SEQUENCE_MASK;
                let width = window_share(window, width).min(window - 1);
                let _ = buf.drop_range(first, first.wrapping_add(width) & SEQUENCE_MASK);
            }
            WorkAction::Tick { elapsed } => {
                *clock += u64::from(elapsed);
                let _ = buf.drop_too_late(Timestamp::from_micros(*clock));
            }
            WorkAction::Advance { ahead } => {
                let target = expected.wrapping_add(window_share(window, ahead)) & SEQUENCE_MASK;
                buf.advance_expected_sequence(target);
            }
            WorkAction::Release => {
                buf.release_retired_packets();
            }
            WorkAction::Pop => {
                let _ = buf.pop_ready(now);
            }
        });
        work
    }

    fn within_entry_limits(work: &WorkCounters) -> bool {
        work.packet_slot_probes + work.released_chunks <= ENTRY_SLOT_LIMIT
            && work.successor_probes <= ENTRY_GAP_LIMIT
            && work.deadline_probes <= ENTRY_GAP_LIMIT
            && work.bitmap_words() <= ENTRY_BITMAP_WORD_LIMIT
            && work.frontier_steps <= ENTRY_FRONTIER_STEP_LIMIT
            && work.loss_entries_visited == 0
            && work.pending_keys_visited == 0
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

        /// Random receive-side streams -- sequence wrap, non-monotone
        /// timestamps, duplicates, wide gaps, DROPREQs reaching behind the
        /// span, TLPKTDROP ticks, a lagging group member's forced advances,
        /// release visits and deliveries -- keep every call's work within
        /// the same window-independent limits at W = 32 / 8,192 / 65,536.
        #[test]
        fn receive_entry_points_do_window_independent_work(
            initial in (SEQUENCE_MASK - 64)..=SEQUENCE_MASK,
            actions in proptest::collection::vec(work_action(), 1..96),
        ) {
            for window in WORK_BOUND_WINDOWS {
                let mut buf =
                    ReceiverBuffer::with_buffer_size(initial, 120, Timestamp::default(), 0, window);
                let mut clock = 1;
                let mut last = None;
                for action in &actions {
                    let work = apply_work_action(&mut buf, action, window, &mut clock, &mut last);
                    proptest::prop_assert!(
                        within_entry_limits(&work),
                        "window {}: {:?} did {:?}", window, action, work
                    );
                }
            }
        }
    }
}
