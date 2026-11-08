//! A FIFO of distinct keys that can also remove any key exactly.
//!
//! The failure, fault and resolution indexes are drained oldest first, and a
//! retiring session must take its own entries out of them. With a plain
//! `VecDeque` that removal is a `retain` over the whole queue, so retiring
//! one session costs every other session's entries. Here pushing, popping
//! and removing a known key are each one hash probe and one O(log n) ordered
//! map operation in the queue's own length.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

#[derive(Debug)]
pub(crate) struct KeyedQueue<K> {
    /// Arrival number to key, oldest first.
    order: BTreeMap<u64, K>,
    /// Key to its arrival number. Keys can carry peer-chosen parts (a
    /// group's ID), so this keeps std's keyed hasher.
    arrival: HashMap<K, u64>,
    next: u64,
}

impl<K> Default for KeyedQueue<K> {
    fn default() -> Self {
        Self {
            order: BTreeMap::new(),
            arrival: HashMap::new(),
            next: 0,
        }
    }
}

impl<K: Clone + Eq + Hash> KeyedQueue<K> {
    /// Append `key`. Every caller queues a key at most once while it is
    /// queued (one record per quarantined leg, one resolution per attempt).
    pub(crate) fn push_back(&mut self, key: K) {
        let Entry::Vacant(entry) = self.arrival.entry(key) else {
            debug_assert!(false, "a key is queued at most once");
            return;
        };
        self.order.insert(self.next, entry.key().clone());
        entry.insert(self.next);
        self.next += 1;
    }

    /// Remove and return the oldest key.
    pub(crate) fn pop_front(&mut self) -> Option<K> {
        let (_, key) = self.order.pop_first()?;
        self.arrival.remove(&key);
        Some(key)
    }

    /// Remove `key` wherever it is queued.
    pub(crate) fn remove(&mut self, key: &K) {
        count_work!(RetirementProbes);
        if let Some(arrival) = self.arrival.remove(key) {
            self.order.remove(&arrival);
        }
    }

    /// Keys queued.
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;

    proptest! {
        /// Against a `VecDeque` with `retain`: the same keys come out in the
        /// same order whatever is pushed, popped or removed.
        #[test]
        fn matches_a_retained_deque(ops in proptest::collection::vec((0..3u8, 0..16u32), 1..200)) {
            let mut queue = KeyedQueue::default();
            let mut model: VecDeque<u32> = VecDeque::new();
            for (op, key) in ops {
                match op {
                    0 if !model.contains(&key) => {
                        queue.push_back(key);
                        model.push_back(key);
                    }
                    1 => prop_assert_eq!(queue.pop_front(), model.pop_front()),
                    _ => {
                        queue.remove(&key);
                        model.retain(|queued| *queued != key);
                    }
                }
                prop_assert_eq!(queue.len(), model.len());
            }
            while let Some(key) = model.pop_front() {
                prop_assert_eq!(queue.pop_front(), Some(key));
            }
            prop_assert_eq!(queue.pop_front(), None);
        }
    }
}
