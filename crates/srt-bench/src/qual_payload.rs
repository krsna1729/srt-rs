//! Diagnostic payload identity for the conservation experiment.
//!
//! The end-of-run deficit cannot be attributed while the receiver counts every
//! DATA payload the same way: a missing payload, a fence payload, and a
//! retransmitted copy are indistinguishable from counts alone. This module gives
//! the harness payloads a small header so the receiver can tell measured DATA
//! from the diagnostic fence, and can track *which* source ticks arrived rather
//! than only how many.
//!
//! Layout, in the first [`HEADER_LEN`] bytes of a normal SRT payload:
//!
//! ```text
//! byte  0..4   magic   MEASURED_MAGIC or FENCE_MAGIC
//! byte  4..8   id      tick id (measured) or final tick id (fence)
//! byte  8..    filler  zeroes, so the payload length is unchanged
//! ```
//!
//! The payload stays exactly as long as the measured workload's, so framing,
//! pacing and MTU behaviour are untouched; only the first eight bytes differ.
//! Bytes with no recognised magic are [`PayloadKind::Foreign`] and are ignored by
//! the diagnostic accounting, so a stream carrying anything else cannot silently
//! inflate a missing-tick count.
//!
//! Connection identity already identifies the peer, so the payload carries no
//! `peer_id`: duplicating it in every payload would be bytes the wire does not
//! need to answer the question.

use bytes::Bytes;

/// Magic for a measured workload payload.
pub const MEASURED_MAGIC: u32 = 0x514D_3031; // "QM01"
/// Magic for a diagnostic fence payload.
pub const FENCE_MAGIC: u32 = 0x5146_3031; // "QF01"
/// Header size in bytes.
pub const HEADER_LEN: usize = 8;

/// What a payload is, as far as the diagnostic accounting is concerned.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PayloadKind {
    /// Measured workload payload carrying its source tick id.
    Measured { tick: u32 },
    /// Diagnostic fence carrying the last measured tick id for that peer.
    Fence { final_tick: u32 },
    /// No recognised magic: not part of the diagnostic experiment.
    Foreign,
}

/// One measured payload of `len` bytes, tagged with its source tick.
///
/// One allocation per tick; the same `Bytes` is then shared across every
/// destination, which is what the sender has always done -- the change is that
/// the shared payload now identifies its tick.
pub fn measured_payload(len: usize, tick: u32) -> Bytes {
    let mut buffer = vec![0u8; len.max(HEADER_LEN)];
    buffer[..4].copy_from_slice(&MEASURED_MAGIC.to_be_bytes());
    buffer[4..8].copy_from_slice(&tick.to_be_bytes());
    Bytes::from(buffer)
}

/// One fence payload of `len` bytes, tagged with the last measured tick.
pub fn fence_payload(len: usize, final_tick: u32) -> Bytes {
    let mut buffer = vec![0u8; len.max(HEADER_LEN)];
    buffer[..4].copy_from_slice(&FENCE_MAGIC.to_be_bytes());
    buffer[4..8].copy_from_slice(&final_tick.to_be_bytes());
    Bytes::from(buffer)
}

/// Classify a received payload.
pub fn classify(payload: &[u8]) -> PayloadKind {
    if payload.len() < HEADER_LEN {
        return PayloadKind::Foreign;
    }
    let magic = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    match magic {
        MEASURED_MAGIC => PayloadKind::Measured { tick: id },
        FENCE_MAGIC => PayloadKind::Fence { final_tick: id },
        _ => PayloadKind::Foreign,
    }
}

/// Which measured ticks arrived, over a window with a known tick count.
///
/// Fixed capacity, allocated once per connection from the run's expected tick
/// count: the diagnostic must not itself become an unbounded structure, and it
/// must not allocate per received payload.
#[derive(Debug, Clone)]
pub struct TickSet {
    bits: Vec<u64>,
    expected: u32,
    received: u32,
    duplicates: u32,
}

impl TickSet {
    /// Capacity for ticks `0..expected`.
    pub fn new(expected: u32) -> Self {
        let words = (expected as usize / 64) + 1;
        Self {
            bits: vec![0u64; words],
            expected,
            received: 0,
            duplicates: 0,
        }
    }

    /// Record a received tick. Returns false for a tick outside the window or a
    /// duplicate, which are counted rather than trusted.
    pub fn insert(&mut self, tick: u32) -> bool {
        if tick >= self.expected {
            return false;
        }
        let (word, bit) = (tick as usize / 64, tick as usize % 64);
        let mask = 1u64 << bit;
        if self.bits[word] & mask != 0 {
            self.duplicates += 1;
            return false;
        }
        self.bits[word] |= mask;
        self.received += 1;
        true
    }

    /// Ticks that have not arrived, as compact inclusive ranges.
    pub fn missing_ranges(&self) -> Vec<(u32, u32)> {
        let mut ranges = Vec::new();
        let mut start: Option<u32> = None;
        for tick in 0..self.expected {
            let present = self.bits[tick as usize / 64] & (1u64 << (tick % 64)) != 0;
            match (present, start) {
                (false, None) => start = Some(tick),
                (true, Some(from)) => {
                    ranges.push((from, tick - 1));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(from) = start {
            ranges.push((from, self.expected - 1));
        }
        ranges
    }

    pub fn received(&self) -> u32 {
        self.received
    }

    pub fn duplicates(&self) -> u32 {
        self.duplicates
    }

    pub fn expected(&self) -> u32 {
        self.expected
    }

    pub fn missing(&self) -> u32 {
        self.expected - self.received
    }

    /// Whether the missing ticks form one contiguous suffix ending at the last
    /// tick of the window -- the shape a truncated tail produces, as opposed to
    /// scatter, which a mid-stream hole produces. Counts cannot distinguish them,
    /// which is the whole reason this exists.
    pub fn missing_is_suffix(&self) -> bool {
        match self.missing_ranges().last() {
            Some((from, to)) => *to == self.expected - 1 && *from == self.received_of_suffix(),
            None => true,
        }
    }

    fn received_of_suffix(&self) -> u32 {
        // First missing tick of the trailing range equals the count of received
        // ticks when the missing set is exactly that suffix.
        self.received
    }

    /// Total size of the compact missing representation, for reporting.
    pub fn missing_range_count(&self) -> usize {
        self.missing_ranges().len()
    }

    /// Render ranges as `a-b,c-d` for a single-line artifact field.
    pub fn missing_ranges_text(&self) -> String {
        if self.missing_ranges().is_empty() {
            return "none".to_string();
        }
        self.missing_ranges()
            .iter()
            .map(|(from, to)| {
                if from == to {
                    from.to_string()
                } else {
                    format!("{from}-{to}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_payload_roundtrips_and_keeps_its_length() {
        let payload = measured_payload(1316, 42);
        assert_eq!(payload.len(), 1316, "length must not change");
        assert_eq!(classify(&payload), PayloadKind::Measured { tick: 42 });
    }

    #[test]
    fn fence_payload_roundtrips_and_keeps_its_length() {
        let payload = fence_payload(1316, 45_591);
        assert_eq!(payload.len(), 1316);
        assert_eq!(
            classify(&payload),
            PayloadKind::Fence { final_tick: 45_591 }
        );
    }

    #[test]
    fn measured_and_fence_are_distinguishable_at_the_maximum_tick() {
        assert_ne!(
            classify(&measured_payload(16, u32::MAX)),
            classify(&fence_payload(16, u32::MAX))
        );
    }

    #[test]
    fn payloads_without_the_magic_are_foreign() {
        assert_eq!(classify(&[0u8; 64]), PayloadKind::Foreign);
        assert_eq!(classify(b"not a diagnostic payload"), PayloadKind::Foreign);
    }

    #[test]
    fn payloads_shorter_than_the_header_are_foreign() {
        assert_eq!(classify(&[]), PayloadKind::Foreign);
        assert_eq!(classify(&[0x51, 0x4D]), PayloadKind::Foreign);
    }

    #[test]
    fn a_tick_arriving_twice_is_counted_once() {
        let mut set = TickSet::new(100);
        assert!(set.insert(7));
        assert!(!set.insert(7), "a duplicate is not a new tick");
        assert_eq!(set.received(), 1);
        assert_eq!(set.duplicates(), 1);
    }

    #[test]
    fn ticks_outside_the_window_are_rejected_not_counted() {
        let mut set = TickSet::new(10);
        assert!(!set.insert(10));
        assert_eq!(set.received(), 0);
        assert_eq!(set.duplicates(), 0);
    }

    #[test]
    fn missing_ranges_are_compact_and_exact() {
        let mut set = TickSet::new(20);
        for tick in 0..20 {
            if !(5..=9).contains(&tick) {
                set.insert(tick);
            }
        }
        assert_eq!(set.missing_ranges(), vec![(5, 9)]);
        assert_eq!(set.missing_ranges_text(), "5-9");
        assert_eq!(set.missing(), 5);
        assert!(!set.missing_is_suffix(), "a middle hole is not a suffix");
    }

    #[test]
    fn a_truncated_tail_is_recognised_as_a_suffix() {
        let mut set = TickSet::new(20);
        for tick in 0..15 {
            set.insert(tick);
        }
        assert_eq!(set.missing_ranges(), vec![(15, 19)]);
        assert!(set.missing_is_suffix(), "15-19 is the trailing suffix");
    }

    #[test]
    fn scatter_is_not_mistaken_for_a_suffix() {
        let mut set = TickSet::new(20);
        for tick in 0..20 {
            if !matches!(tick, 3 | 11 | 19) {
                set.insert(tick);
            }
        }
        assert_eq!(set.missing_ranges(), vec![(3, 3), (11, 11), (19, 19)]);
        assert!(
            !set.missing_is_suffix(),
            "scattered gaps must not read as a truncated tail"
        );
    }

    #[test]
    fn a_complete_window_has_no_missing_ranges() {
        let mut set = TickSet::new(8);
        for tick in 0..8 {
            set.insert(tick);
        }
        assert_eq!(set.missing(), 0);
        assert_eq!(set.missing_ranges_text(), "none");
        assert!(set.missing_is_suffix());
    }

    #[test]
    fn single_tick_gaps_render_as_one_number() {
        let mut set = TickSet::new(6);
        for tick in [0u32, 1, 3, 4] {
            set.insert(tick);
        }
        assert_eq!(set.missing_ranges_text(), "2,5");
    }
}
