//! Min-heap of absolute worker-schedule deadlines.
//!
//! [`crate::DueIndex`] indexes protocol [`shiguredo_srt::Timestamp`] values
//! (microseconds). This heap stores [`crate::MonotonicDeadline`] nanoseconds
//! so a worker can arm `epoll_pwait2` / absolute `timerfd` without rounding
//! the next wake to a whole microsecond or scanning every connection.
//!
//! Replaced entries stay in the heap until they surface; an amortized rebuild
//! keeps `heap_len <= max(64, 4 * live)`.

use std::cmp::Ordering as CmpOrdering;
use std::collections::hash_map::Entry as HashEntry;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;

use crate::MonotonicDeadline;

const REBUILD_FLOOR: usize = 64;
const REBUILD_RATIO: usize = 4;

#[derive(Debug)]
struct HeapEntry<K> {
    deadline_nanos: u64,
    key: K,
}

impl<K> PartialEq for HeapEntry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_nanos == other.deadline_nanos
    }
}

impl<K> Eq for HeapEntry<K> {}

impl<K> PartialOrd for HeapEntry<K> {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for HeapEntry<K> {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.deadline_nanos.cmp(&other.deadline_nanos)
    }
}

/// Next-deadline index for one transport worker.
///
/// `pop_due` returns **every** key whose deadline is `<= now`, which is the
/// A2 wake-all-due rule: one wait, then service the whole due set.
#[derive(Debug)]
pub struct DeadlineHeap<K> {
    current: HashMap<K, u64>,
    heap: BinaryHeap<std::cmp::Reverse<HeapEntry<K>>>,
    rebuild_floor: usize,
    rebuild_ratio: usize,
}

impl<K> Default for DeadlineHeap<K> {
    fn default() -> Self {
        Self {
            current: HashMap::new(),
            heap: BinaryHeap::new(),
            rebuild_floor: REBUILD_FLOOR,
            rebuild_ratio: REBUILD_RATIO,
        }
    }
}

impl<K> DeadlineHeap<K>
where
    K: Clone + Eq + Hash,
{
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: K, deadline: MonotonicDeadline) {
        let deadline_nanos = deadline.as_nanos();
        self.current.insert(key.clone(), deadline_nanos);
        self.heap.push(std::cmp::Reverse(HeapEntry {
            deadline_nanos,
            key,
        }));
        self.maybe_rebuild();
    }

    pub fn remove(&mut self, key: &K) {
        if self.current.remove(key).is_some() {
            self.maybe_rebuild();
        }
    }

    /// Drain every live key whose deadline is at or before `now`.
    pub fn pop_due(&mut self, now: MonotonicDeadline, out: &mut Vec<K>) {
        out.clear();
        let now_nanos = now.as_nanos();
        while let Some(std::cmp::Reverse(top)) = self.heap.peek()
            && top.deadline_nanos <= now_nanos
        {
            let std::cmp::Reverse(entry) = self.heap.pop().expect("peeked entry exists");
            match self.current.entry(entry.key.clone()) {
                HashEntry::Occupied(slot) if *slot.get() == entry.deadline_nanos => {
                    slot.remove();
                    out.push(entry.key);
                }
                _ => {}
            }
        }
        self.maybe_rebuild();
    }

    /// Earliest live deadline, discarding stale heap heads.
    pub fn peek_min(&mut self) -> Option<MonotonicDeadline> {
        loop {
            let std::cmp::Reverse(entry) = self.heap.pop()?;
            match self.current.get(&entry.key) {
                Some(&deadline) if deadline == entry.deadline_nanos => {
                    let result = MonotonicDeadline::from_nanos(deadline);
                    self.heap.push(std::cmp::Reverse(entry));
                    return Some(result);
                }
                _ => continue,
            }
        }
    }

    fn maybe_rebuild(&mut self) {
        if self.current.is_empty() {
            self.heap.clear();
            return;
        }
        let bound = self
            .rebuild_floor
            .max(self.current.len().saturating_mul(self.rebuild_ratio));
        if self.rebuild_ratio > 0 && self.heap.len() > bound {
            self.heap = self
                .current
                .iter()
                .map(|(key, &deadline_nanos)| {
                    std::cmp::Reverse(HeapEntry {
                        deadline_nanos,
                        key: key.clone(),
                    })
                })
                .collect();
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.current.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }
}

/// Combine a connection's pacing wait and next protocol-timer wait into one
/// relative delay. The worker turns that into an absolute
/// [`MonotonicDeadline`] immediately before arming the waiter.
#[must_use]
pub fn schedule_wait_micros(pacing_us: u64, timer_us: u64) -> u64 {
    pacing_us.min(timer_us)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(n: u64) -> MonotonicDeadline {
        MonotonicDeadline::from_nanos(n)
    }

    #[test]
    fn peek_min_selects_earliest_live_deadline() {
        let mut heap = DeadlineHeap::<u32>::new();
        heap.set(3, ns(300));
        heap.set(1, ns(100));
        heap.set(2, ns(200));
        assert_eq!(heap.peek_min(), Some(ns(100)));
        heap.set(1, ns(400));
        assert_eq!(heap.peek_min(), Some(ns(200)));
    }

    #[test]
    fn pop_due_returns_every_connection_at_or_before_now() {
        let mut heap = DeadlineHeap::<u32>::new();
        heap.set(1, ns(100));
        heap.set(2, ns(100));
        heap.set(3, ns(250));
        let mut due = Vec::new();
        heap.pop_due(ns(100), &mut due);
        due.sort_unstable();
        assert_eq!(due, vec![1, 2]);
        assert_eq!(heap.peek_min(), Some(ns(250)));
        assert_eq!(heap.len(), 1);
    }

    #[test]
    fn overwrite_and_remove_ignore_stale_heap_entries() {
        let mut heap = DeadlineHeap::<u32>::new();
        heap.set(1, ns(50));
        heap.set(1, ns(500));
        heap.remove(&1);
        heap.set(2, ns(80));
        let mut due = Vec::new();
        heap.pop_due(ns(100), &mut due);
        assert_eq!(due, vec![2]);
        heap.pop_due(ns(500), &mut due);
        assert!(due.is_empty());
        assert!(heap.is_empty());
    }

    #[test]
    fn schedule_wait_uses_the_binding_clock() {
        assert_eq!(schedule_wait_micros(800, 1_200), 800);
        assert_eq!(schedule_wait_micros(2_000, 400), 400);
    }
}
