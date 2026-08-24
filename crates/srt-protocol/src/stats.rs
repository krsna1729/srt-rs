//! Connection-level SRT telemetry.
//!
//! [`ConnectionStats`] follows the same broad contract as libsrt's
//! `SRT_TRACEBSTATS` without copying its C ABI: cumulative counters live in
//! the sender/receiver snapshots, instantaneous values are named with their
//! units, and interval values are derived from two snapshots plus an elapsed
//! duration supplied by the caller. Taking a snapshot never clears counters.

use std::time::Duration;

use crate::{ReceiverStats, SenderStats};

/// A non-clearing snapshot of all statistics available for one connection.
///
/// A direction is `None` until its protocol buffer has been initialized. This
/// is preferable to reporting zero for measurements the connection cannot yet
/// make.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionStats {
    /// Local sending statistics, if the sender direction is initialized.
    pub sender: Option<SenderStats>,
    /// Local receiving statistics, if the receiver direction is initialized.
    pub receiver: Option<ReceiverStats>,
}

impl ConnectionStats {
    /// Derive interval counts and rates from an earlier snapshot.
    ///
    /// The sans-I/O core does not read a wall clock. Callers choose the sample
    /// cadence and pass the actual elapsed duration here. A counter that moved
    /// backwards (for example, because snapshots came from different
    /// connections) produces a [`CounterDelta`] whose fields are `None` rather
    /// than a misleading wrapping or saturating result. A zero duration still
    /// produces counts, but rates are `None`.
    pub fn interval_since(&self, previous: &Self, elapsed: Duration) -> ConnectionStatsInterval {
        ConnectionStatsInterval {
            elapsed,
            sender: self.sender.zip(previous.sender).map(|(current, previous)| {
                SenderStatsInterval::between(current, previous, elapsed)
            }),
            receiver: self
                .receiver
                .zip(previous.receiver)
                .map(|(current, previous)| {
                    ReceiverStatsInterval::between(current, previous, elapsed)
                }),
        }
    }
}

/// Count and rate for one cumulative counter over an interval.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CounterDelta {
    /// Counter increase over the interval, or `None` if the counter regressed.
    pub count: Option<u64>,
    /// Counter increase per second. `None` on regression or zero elapsed time.
    pub per_second: Option<f64>,
}

impl CounterDelta {
    fn between(current: u64, previous: u64, elapsed: Duration) -> Self {
        let count = current.checked_sub(previous);
        let seconds = elapsed.as_secs_f64();
        Self {
            count,
            per_second: count
                .filter(|_| seconds > 0.0)
                .map(|count| count as f64 / seconds),
        }
    }
}

/// Counter changes between two connection snapshots.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ConnectionStatsInterval {
    /// Caller-supplied time between the snapshots.
    pub elapsed: Duration,
    /// Sending interval, when both snapshots contain a sender direction.
    pub sender: Option<SenderStatsInterval>,
    /// Receiving interval, when both snapshots contain a receiver direction.
    pub receiver: Option<ReceiverStatsInterval>,
}

/// Sending counter changes between two snapshots.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SenderStatsInterval {
    /// All DATA packet transmissions, including retransmissions.
    pub packets_sent: CounterDelta,
    /// Original DATA packet transmissions, excluding retransmissions.
    pub unique_packets_sent: CounterDelta,
    /// Payload bytes in original DATA packets.
    pub payload_bytes_sent: CounterDelta,
    /// SRT datagram bytes emitted, including SRT headers and retransmissions.
    pub srt_bytes_sent: CounterDelta,
    /// Retransmitted SRT datagram bytes, including SRT headers.
    pub retransmitted_srt_bytes: CounterDelta,
    /// Packet loss occurrences reported by the peer.
    pub packets_lost: CounterDelta,
    /// Retransmitted DATA packets emitted.
    pub packets_retransmitted: CounterDelta,
    /// DATA packets abandoned by sender TLPKTDROP.
    pub packets_dropped: CounterDelta,
    /// Payload bytes abandoned by sender TLPKTDROP.
    pub payload_bytes_dropped: CounterDelta,
    /// ACK control packets received.
    pub acks_received: CounterDelta,
    /// NAK control packets received.
    pub naks_received: CounterDelta,
}

impl SenderStatsInterval {
    fn between(current: SenderStats, previous: SenderStats, elapsed: Duration) -> Self {
        Self {
            packets_sent: CounterDelta::between(
                current.total_data_packets_sent,
                previous.total_data_packets_sent,
                elapsed,
            ),
            unique_packets_sent: CounterDelta::between(
                current.total_sent,
                previous.total_sent,
                elapsed,
            ),
            payload_bytes_sent: CounterDelta::between(
                current.total_bytes_sent,
                previous.total_bytes_sent,
                elapsed,
            ),
            srt_bytes_sent: CounterDelta::between(
                current.total_srt_bytes_sent,
                previous.total_srt_bytes_sent,
                elapsed,
            ),
            retransmitted_srt_bytes: CounterDelta::between(
                current.total_retransmitted_srt_bytes,
                previous.total_retransmitted_srt_bytes,
                elapsed,
            ),
            packets_lost: CounterDelta::between(current.total_lost, previous.total_lost, elapsed),
            packets_retransmitted: CounterDelta::between(
                current.total_retransmits,
                previous.total_retransmits,
                elapsed,
            ),
            packets_dropped: CounterDelta::between(
                current.total_dropped,
                previous.total_dropped,
                elapsed,
            ),
            payload_bytes_dropped: CounterDelta::between(
                current.total_bytes_dropped,
                previous.total_bytes_dropped,
                elapsed,
            ),
            acks_received: CounterDelta::between(
                current.total_acks_received,
                previous.total_acks_received,
                elapsed,
            ),
            naks_received: CounterDelta::between(
                current.total_naks_received,
                previous.total_naks_received,
                elapsed,
            ),
        }
    }
}

/// Receiving counter changes between two snapshots.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ReceiverStatsInterval {
    /// All decrypted DATA packets received, including duplicates.
    pub packets_received: CounterDelta,
    /// First-arriving DATA packets accepted for delivery.
    pub unique_packets_received: CounterDelta,
    /// SRT datagram bytes received, including duplicates.
    pub srt_bytes_received: CounterDelta,
    /// SRT datagram bytes in packets accepted for delivery.
    pub unique_srt_bytes_received: CounterDelta,
    /// Newly detected missing original DATA packets.
    pub packets_lost: CounterDelta,
    /// DATA packets received with the retransmission flag.
    pub packets_retransmitted: CounterDelta,
    /// Missing DATA packets abandoned by receiver TLPKTDROP.
    pub packets_dropped: CounterDelta,
    /// Duplicate or already-delivered DATA packets.
    pub packets_duplicate: CounterDelta,
    /// DATA packets rejected at the decryption boundary.
    pub packets_undecryptable: CounterDelta,
    /// ACK control packets sent.
    pub acks_sent: CounterDelta,
    /// NAK control packets sent.
    pub naks_sent: CounterDelta,
}

impl ReceiverStatsInterval {
    fn between(current: ReceiverStats, previous: ReceiverStats, elapsed: Duration) -> Self {
        Self {
            packets_received: CounterDelta::between(
                current.total_data_packets_received,
                previous.total_data_packets_received,
                elapsed,
            ),
            unique_packets_received: CounterDelta::between(
                current.total_received,
                previous.total_received,
                elapsed,
            ),
            srt_bytes_received: CounterDelta::between(
                current.total_srt_bytes_received,
                previous.total_srt_bytes_received,
                elapsed,
            ),
            unique_srt_bytes_received: CounterDelta::between(
                current.total_bytes_received,
                previous.total_bytes_received,
                elapsed,
            ),
            packets_lost: CounterDelta::between(current.total_lost, previous.total_lost, elapsed),
            packets_retransmitted: CounterDelta::between(
                current.total_retransmitted,
                previous.total_retransmitted,
                elapsed,
            ),
            packets_dropped: CounterDelta::between(
                current.total_dropped,
                previous.total_dropped,
                elapsed,
            ),
            packets_duplicate: CounterDelta::between(
                current.total_duplicates,
                previous.total_duplicates,
                elapsed,
            ),
            packets_undecryptable: CounterDelta::between(
                current.total_undecryptable,
                previous.total_undecryptable,
                elapsed,
            ),
            acks_sent: CounterDelta::between(
                current.total_acks_sent,
                previous.total_acks_sent,
                elapsed,
            ),
            naks_sent: CounterDelta::between(
                current.total_naks_sent,
                previous.total_naks_sent,
                elapsed,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_reports_counts_rates_and_counter_resets() {
        let previous = ConnectionStats {
            sender: Some(SenderStats {
                total_sent: 100,
                total_data_packets_sent: 100,
                total_bytes_sent: 1_000,
                total_lost: 8,
                ..SenderStats::default()
            }),
            receiver: Some(ReceiverStats {
                total_received: 80,
                total_data_packets_received: 80,
                total_undecryptable: 2,
                ..ReceiverStats::default()
            }),
        };
        let current = ConnectionStats {
            sender: Some(SenderStats {
                total_sent: 120,
                total_data_packets_sent: 120,
                total_bytes_sent: 1_400,
                total_lost: 3,
                ..SenderStats::default()
            }),
            receiver: Some(ReceiverStats {
                total_received: 90,
                total_data_packets_received: 90,
                total_undecryptable: 4,
                ..ReceiverStats::default()
            }),
        };

        let interval = current.interval_since(&previous, Duration::from_millis(500));
        let sender = interval.sender.expect("sender interval");
        assert_eq!(sender.packets_sent.count, Some(20));
        assert_eq!(sender.packets_sent.per_second, Some(40.0));
        assert_eq!(sender.payload_bytes_sent.per_second, Some(800.0));
        assert_eq!(sender.packets_lost.count, None);
        assert_eq!(sender.packets_lost.per_second, None);

        let receiver = interval.receiver.expect("receiver interval");
        assert_eq!(receiver.packets_received.per_second, Some(20.0));
        assert_eq!(receiver.packets_undecryptable.per_second, Some(4.0));
    }

    #[test]
    fn zero_elapsed_preserves_counts_but_has_no_rates() {
        let previous = ConnectionStats {
            sender: Some(SenderStats::default()),
            receiver: None,
        };
        let current = ConnectionStats {
            sender: Some(SenderStats {
                total_sent: 1,
                total_data_packets_sent: 1,
                ..SenderStats::default()
            }),
            receiver: None,
        };

        let interval = current.interval_since(&previous, Duration::ZERO);
        let sent = interval.sender.expect("sender interval").packets_sent;
        assert_eq!(sent.count, Some(1));
        assert_eq!(sent.per_second, None);
        assert!(interval.receiver.is_none());
    }
}
