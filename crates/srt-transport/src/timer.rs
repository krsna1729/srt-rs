use shiguredo_srt::{ConnectionOutput, SrtConnection, TimerId, Timestamp};

/// Manual timer store — the fallback for runtimes without a built-in timer
/// engine (mio) or for code that wants explicit control over timer lifecycle.
///
/// Fixed `[Option<Timestamp>; 7]` array indexed by `TimerId`. No hashing,
/// no allocation, fits in a single cache line.
pub struct ManualTimerStore {
    deadlines: [Option<Timestamp>; TimerId::COUNT],
}

impl ManualTimerStore {
    pub fn new() -> Self {
        Self {
            deadlines: [None; TimerId::COUNT],
        }
    }

    /// Fire all timers whose deadline has passed.
    pub fn fire_expired(&mut self, now: Timestamp, conn: &mut SrtConnection) {
        for &id in &TimerId::ALL {
            if let Some(deadline) = self.deadlines[id.index()]
                && now.as_micros() >= deadline.as_micros()
            {
                self.deadlines[id.index()] = None;
                let _ = conn.handle_timer(id, now);
            }
        }
    }

    /// Find and remove all expired timer IDs.
    pub fn due_timers(&mut self, now: Timestamp) -> DueTimers {
        let mut ids = [None; TimerId::COUNT];
        let mut count = 0;
        for &id in &TimerId::ALL {
            if let Some(deadline) = self.deadlines[id.index()]
                && now.as_micros() >= deadline.as_micros()
            {
                self.deadlines[id.index()] = None;
                ids[count] = Some(id);
                count += 1;
            }
        }
        DueTimers { ids, count }
    }

    /// Apply a `SetTimer` or `ClearTimer` output from `poll_output()`.
    pub fn apply_output(&mut self, output: &ConnectionOutput, now: Timestamp) {
        match output {
            ConnectionOutput::SetTimer {
                id,
                duration_micros,
            } => {
                self.deadlines[id.index()] = Some(now.add_micros(*duration_micros));
            }
            ConnectionOutput::ClearTimer { id } => {
                self.deadlines[id.index()] = None;
            }
            _ => {}
        }
    }

    /// Microseconds until the next timer fires.
    pub fn time_until_earliest(&self, now: Timestamp, default_us: u64) -> u64 {
        self.deadlines
            .iter()
            .filter_map(|d| d.map(|d| d.as_micros().saturating_sub(now.as_micros())))
            .min()
            .unwrap_or(default_us)
    }

    /// Absolute deadline of this connection's next armed timer.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Timestamp> {
        self.deadlines.iter().filter_map(|d| *d).min()
    }
}

/// Iterator-like container for due timer IDs. Avoids allocating a Vec.
pub struct DueTimers {
    ids: [Option<TimerId>; TimerId::COUNT],
    count: usize,
}

impl DueTimers {
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl IntoIterator for DueTimers {
    type Item = TimerId;
    type IntoIter = DueTimersIter;

    fn into_iter(self) -> Self::IntoIter {
        DueTimersIter {
            ids: self.ids,
            pos: 0,
            count: self.count,
        }
    }
}

pub struct DueTimersIter {
    ids: [Option<TimerId>; TimerId::COUNT],
    pos: usize,
    count: usize,
}

impl Iterator for DueTimersIter {
    type Item = TimerId;

    fn next(&mut self) -> Option<TimerId> {
        if self.pos < self.count {
            let id = self.ids[self.pos].take();
            self.pos += 1;
            id
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count - self.pos;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for DueTimersIter {}

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
        let due: Vec<_> = store.due_timers(ts(100)).into_iter().collect();
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
        let due: Vec<_> = store.due_timers(ts(250)).into_iter().collect();
        assert_eq!(due, vec![TimerId::Nak]);
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
        let due: Vec<_> = store.due_timers(ts(150)).into_iter().collect();
        assert_eq!(due, vec![TimerId::Keepalive]);
        let due: Vec<_> = store.due_timers(ts(250)).into_iter().collect();
        assert_eq!(due, vec![TimerId::Ack]);
    }

    #[test]
    fn send_packet_output_is_ignored() {
        let mut store = ManualTimerStore::new();
        store.apply_output(&ConnectionOutput::SendPacket(vec![1, 2, 3]), ts(0));
        assert!(store.next_deadline().is_none());
    }
}
