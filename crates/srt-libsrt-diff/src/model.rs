//! What both receivers are fed and what is compared between them.
//!
//! Every observation is normalized to a form both implementations can
//! produce without consulting the other. The normalizations, each an
//! intentional and documented difference rather than a tolerance:
//!
//! - **Admission.** libsrt distinguishes a duplicate (`CRcvBuffer::insert`
//!   returns -1) from a packet behind the buffer start (`bufidx < 0`,
//!   core.cpp:10763); srt-rs counts both as duplicates
//!   (`ReceiverBuffer::receive`, srt_receiver.rs). Both become
//!   [`Admission::Old`]. A packet beyond the window is refused by both; on an
//!   empty live buffer with TLPKTDROP enabled, libsrt also closes the connection
//!   (core.cpp:10781-10805), which ends the scenario ([`Receiver::closed`]).
//! - **Loss ranges.** libsrt keeps one node per range in a linked list
//!   (list.h:158-275); srt-rs reports numeric runs from a bitmap, split where
//!   the 31-bit sequence wraps (`generate_periodic_nak`). Both are expanded to
//!   sequence positions and merged into maximal runs in circular order from the
//!   scenario's initial sequence ([`canonical_ranges`]).
//! - **Drops.** libsrt drops one head gap per TSBPD pass and reports
//!   missing/discarded counts (`CRcvBuffer::dropUpTo`, buffer_rcv.cpp:209-256);
//!   srt-rs returns the dropped loss ranges (`drop_too_late`). Both are
//!   compared as the canonical set of positions given up in that step.
//! - **ACK position.** The next-unacknowledged DATA sequence: libsrt's
//!   `getFirstNoncontSequence` live branch (core.cpp:8318-8336) and srt-rs's
//!   `expected_sequence`. srt-rs's independent `ack_number` is not compared.
//! - **Play time.** libsrt reports `SRT_MSGCTRL::srctime`, the absolute TSBPD
//!   play time including the latency (buffer_rcv.cpp:450-453); srt-rs reports
//!   the source time without it (`pop_ready_with_source_time`). The srt-rs
//!   value is shifted by the configured latency.
//!
//! Not compared: advertised buffer space (libsrt subtracts
//! acknowledged-but-unread packets, `CRcvBuffer::getAvailSize`, buffer_rcv.h;
//! srt-rs counts packets, holes and backlog), statistics, and the DATA order
//! flag, which TSBPD ignores on both sides (buffer_rcv.cpp:195-202).

use std::fmt;

/// Mask of the 31-bit DATA sequence space.
pub const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;

/// Configuration shared by both receivers in one scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Usable packet capacity of the receive window.
    pub capacity: u32,
    /// Peer initial sequence number.
    pub initial_seq: u32,
    /// Negotiated receive latency.
    pub latency_ms: u16,
    /// TSBPD time base, microseconds since the synthetic epoch.
    pub time_base_us: u64,
    /// Largest payload a packet may carry.
    pub payload_limit: u32,
    /// Whether the receiver gives up on late losses (TLPKTDROP).
    pub tlpktdrop: bool,
}

impl Profile {
    /// SOLO-message live TSBPD with TLPKTDROP: 120 ms latency and a time base
    /// ten seconds after the synthetic epoch, so no deadline sits near zero
    /// (libsrt treats a zero time point as "none", core.cpp:5675).
    #[must_use]
    pub fn live(initial_seq: u32, capacity: u32) -> Self {
        Self {
            capacity,
            initial_seq,
            latency_ms: 120,
            time_base_us: 10_000_000,
            payload_limit: 1316,
            tlpktdrop: true,
        }
    }

    /// Latency in microseconds.
    #[must_use]
    pub fn latency_us(&self) -> u64 {
        u64::from(self.latency_ms) * 1000
    }

    /// The moment packet `timestamp` becomes due, with no clock drift.
    #[must_use]
    pub fn deadline(&self, timestamp: u32) -> u64 {
        self.time_base_us + u64::from(timestamp) + self.latency_us()
    }
}

/// One SOLO DATA packet as both receivers see it.
#[derive(Clone, PartialEq, Eq)]
pub struct Packet {
    /// 31-bit sequence number.
    pub seq: u32,
    /// 26-bit message number.
    pub msgno: u32,
    /// Sender timestamp, microseconds.
    pub timestamp: u32,
    /// DATA order flag (ignored by TSBPD on both sides).
    pub order_flag: bool,
    /// Retransmission flag.
    pub retransmitted: bool,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl Packet {
    /// A first-transmission SOLO packet whose payload names its sequence.
    #[must_use]
    pub fn solo(seq: u32, timestamp: u32) -> Self {
        let seq = seq & SEQUENCE_MASK;
        Self {
            seq,
            msgno: (seq % 0x03FF_FFFF) + 1,
            timestamp,
            order_flag: false,
            retransmitted: false,
            payload: seq.to_be_bytes().to_vec(),
        }
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Packet(seq={}, msgno={}, ts={}, O={}, R={}, payload={:02x?})",
            self.seq,
            self.msgno,
            self.timestamp,
            u8::from(self.order_flag),
            u8::from(self.retransmitted),
            self.payload
        )
    }
}

/// Normalized admission outcome of one packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Stored in the buffer.
    Accepted,
    /// Already held, or behind the receive position.
    Old,
    /// Beyond the receive window.
    NoRoom,
}

/// One delivered SOLO message.
#[derive(Clone, PartialEq, Eq)]
pub struct Delivered {
    /// Sequence number of the packet.
    pub seq: u32,
    /// Message number.
    pub msgno: u32,
    /// Absolute TSBPD play time, microseconds since the synthetic epoch.
    pub play_time_us: u64,
    /// Payload bytes.
    pub payload: Vec<u8>,
}

impl fmt::Debug for Delivered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Delivered(seq={}, msgno={}, play={}, payload={:02x?})",
            self.seq, self.msgno, self.play_time_us, self.payload
        )
    }
}

/// Inclusive circular range of 31-bit sequence numbers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SeqRange {
    /// First sequence.
    pub first: u32,
    /// Last sequence, numerically smaller after a wrap.
    pub last: u32,
}

impl SeqRange {
    /// Number of positions in the range.
    #[must_use]
    pub fn len(self) -> u32 {
        (self.last.wrapping_sub(self.first) & SEQUENCE_MASK) + 1
    }

    /// Never true: a range holds at least one position.
    #[must_use]
    pub fn is_empty(self) -> bool {
        false
    }

    fn positions(self) -> impl Iterator<Item = u32> {
        (0..self.len()).map(move |offset| self.first.wrapping_add(offset) & SEQUENCE_MASK)
    }
}

impl fmt::Debug for SeqRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}..={}", self.first, self.last)
        }
    }
}

/// State visible after every step.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Snapshot {
    /// Whether a read at the current time would deliver.
    pub ready: bool,
    /// Next unacknowledged DATA sequence.
    pub ack_seq: u32,
    /// Canonical loss ranges.
    pub losses: Vec<SeqRange>,
}

/// A receive buffer under test, driven with explicit time.
pub trait Receiver {
    /// Offer one packet arriving at `now_us`.
    fn insert(&mut self, packet: &Packet, now_us: u64) -> Admission;
    /// Read one message if one is ready at `now_us`.
    fn read(&mut self, now_us: u64) -> Option<Delivered>;
    /// One TLPKTDROP service pass at `now_us`; returns the positions given up.
    fn service(&mut self, now_us: u64) -> Vec<SeqRange>;
    /// Observable state at `now_us`.
    fn snapshot(&self, now_us: u64) -> Snapshot;
    /// Whether the receiver would have closed its connection.
    fn closed(&self) -> bool {
        false
    }
}

/// Merge `ranges` into maximal runs in circular order from `origin`.
///
/// Positions are compared by their distance from `origin`, which every
/// scenario keeps far below half the sequence space.
#[must_use]
pub fn canonical_ranges(origin: u32, ranges: impl IntoIterator<Item = SeqRange>) -> Vec<SeqRange> {
    let mut offsets: Vec<u32> = ranges
        .into_iter()
        .flat_map(SeqRange::positions)
        .map(|seq| seq.wrapping_sub(origin) & SEQUENCE_MASK)
        .collect();
    offsets.sort_unstable();
    offsets.dedup();
    let mut merged: Vec<(u32, u32)> = Vec::new();
    for offset in offsets {
        match merged.last_mut() {
            Some((_, last)) if *last + 1 == offset => *last = offset,
            _ => merged.push((offset, offset)),
        }
    }
    merged
        .into_iter()
        .map(|(first, last)| SeqRange {
            first: origin.wrapping_add(first) & SEQUENCE_MASK,
            last: origin.wrapping_add(last) & SEQUENCE_MASK,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ranges_merge_across_the_sequence_wrap() {
        let split = [
            SeqRange { first: 0, last: 2 },
            SeqRange {
                first: SEQUENCE_MASK - 1,
                last: SEQUENCE_MASK,
            },
        ];
        assert_eq!(
            canonical_ranges(SEQUENCE_MASK - 5, split),
            vec![SeqRange {
                first: SEQUENCE_MASK - 1,
                last: 2
            }]
        );
    }
}
