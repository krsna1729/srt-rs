use shiguredo_srt::{ConnectionOutput, SrtConnection, TimerId, Timestamp};
use std::collections::HashMap;

/// Manual timer store — the fallback for runtimes without a built-in timer
/// engine (mio) or for code that wants explicit control over timer lifecycle.
///
/// Simple `HashMap<TimerId, Timestamp>` with O(n) scan on fire.
/// Runtimes with native timer engines should use their own primitives.
pub struct ManualTimerStore {
    timers: HashMap<TimerId, Timestamp>,
}

impl ManualTimerStore {
    pub fn new() -> Self {
        Self {
            timers: HashMap::new(),
        }
    }

    /// Fire all timers whose deadline has passed.
    pub fn fire_expired(&mut self, now: Timestamp, conn: &mut SrtConnection) {
        let due = self.due_timers(now);
        for id in due {
            let _ = conn.handle_timer(id, now);
        }
    }

    /// Find and remove all expired timer IDs.
    pub fn due_timers(&mut self, now: Timestamp) -> Vec<TimerId> {
        let due: Vec<TimerId> = self
            .timers
            .iter()
            .filter(|(_, d)| now.as_micros() >= d.as_micros())
            .map(|(id, _)| *id)
            .collect();
        for id in &due {
            self.timers.remove(id);
        }
        due
    }

    /// Apply a `SetTimer` or `ClearTimer` output from `poll_output()`.
    pub fn apply_output(&mut self, output: &ConnectionOutput, now: Timestamp) {
        match output {
            ConnectionOutput::SetTimer {
                id,
                duration_micros,
            } => {
                self.timers.insert(*id, now.add_micros(*duration_micros));
            }
            ConnectionOutput::ClearTimer { id } => {
                self.timers.remove(id);
            }
            _ => {}
        }
    }

    /// Microseconds until the next timer fires.
    pub fn time_until_earliest(&self, now: Timestamp, default_us: u64) -> u64 {
        self.timers
            .values()
            .map(|d| d.as_micros().saturating_sub(now.as_micros()))
            .min()
            .unwrap_or(default_us)
    }

    /// Absolute deadline of this connection's next armed timer.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Timestamp> {
        self.timers.values().copied().min()
    }
}

impl Default for ManualTimerStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(micros: u64) -> Timestamp {
        Timestamp::from_micros(micros)
    }

    #[test]
    fn apply_set_then_due() {
        let mut store = ManualTimerStore::new();
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Keepalive,
                duration_micros: 100,
            },
            ts(0),
        );
        assert!(store.due_timers(ts(50)).is_empty());
        let due = store.due_timers(ts(100));
        assert_eq!(due, vec![TimerId::Keepalive]);
    }

    #[test]
    fn apply_clear_removes_timer() {
        let mut store = ManualTimerStore::new();
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Ack,
                duration_micros: 100,
            },
            ts(0),
        );
        store.apply_output(&ConnectionOutput::ClearTimer { id: TimerId::Ack }, ts(50));
        assert!(store.due_timers(ts(200)).is_empty());
    }

    #[test]
    fn overwrite_timer_uses_latest_deadline() {
        let mut store = ManualTimerStore::new();
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Nak,
                duration_micros: 100,
            },
            ts(0),
        );
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Nak,
                duration_micros: 200,
            },
            ts(50),
        );
        assert!(store.due_timers(ts(100)).is_empty());
        assert_eq!(store.due_timers(ts(250)), vec![TimerId::Nak]);
    }

    #[test]
    fn time_until_earliest_returns_default_when_empty() {
        let store = ManualTimerStore::new();
        assert_eq!(store.time_until_earliest(ts(0), 999), 999);
    }

    #[test]
    fn time_until_earliest_saturates_at_zero() {
        let mut store = ManualTimerStore::new();
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Keepalive,
                duration_micros: 100,
            },
            ts(0),
        );
        assert_eq!(store.time_until_earliest(ts(200), 999), 0);
    }

    #[test]
    fn next_deadline_tracks_minimum() {
        let mut store = ManualTimerStore::new();
        assert_eq!(store.next_deadline(), None);
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Keepalive,
                duration_micros: 300,
            },
            ts(0),
        );
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Ack,
                duration_micros: 100,
            },
            ts(0),
        );
        assert_eq!(store.next_deadline(), Some(ts(100)));
    }

    #[test]
    fn multiple_timers_fire_independently() {
        let mut store = ManualTimerStore::new();
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Keepalive,
                duration_micros: 100,
            },
            ts(0),
        );
        store.apply_output(
            &ConnectionOutput::SetTimer {
                id: TimerId::Ack,
                duration_micros: 200,
            },
            ts(0),
        );
        let due = store.due_timers(ts(150));
        assert_eq!(due, vec![TimerId::Keepalive]);
        let due = store.due_timers(ts(250));
        assert_eq!(due, vec![TimerId::Ack]);
    }

    #[test]
    fn send_packet_output_is_ignored() {
        let mut store = ManualTimerStore::new();
        store.apply_output(&ConnectionOutput::SendPacket(vec![1, 2, 3]), ts(0));
        assert!(store.next_deadline().is_none());
    }
}
