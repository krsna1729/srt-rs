use srt_proto::Timestamp;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::hash::Hash;

use crate::indexed_heap::IndexedHeap;

/// Indexes the next deadline of many timer owners without scanning every
/// owner on each shared-loop iteration.
///
/// An exact indexed heap: each key has one node, so setting, moving,
/// removing or popping a deadline costs one hash lookup and O(log n) node
/// moves, and the earliest deadline is read in O(1). No call cleans up stale
/// history or rebuilds the heap, so no single call's work grows with the
/// number of keys beyond that logarithm.
#[derive(Debug)]
pub struct DueIndex<K> {
    handles: HashMap<K, u32>,
    keys: Vec<Option<K>>,
    free: Vec<u32>,
    heap: IndexedHeap,
}

impl<K> Default for DueIndex<K> {
    fn default() -> Self {
        Self {
            handles: HashMap::new(),
            keys: Vec::new(),
            free: Vec::new(),
            heap: IndexedHeap::default(),
        }
    }
}

impl<K> DueIndex<K>
where
    K: Clone + Eq + Hash,
{
    /// Index `key` at exactly `deadline`.
    pub fn set(&mut self, key: K, deadline: Timestamp) {
        let handle = self.handle(key);
        self.heap.set(handle, deadline.as_micros());
    }

    /// Index `key` due no later than `deadline`: insert it, or move it
    /// earlier. An entry already due earlier is kept, so a deadline that only
    /// moves later (a last-activity stamp) costs one lookup and no heap work;
    /// the owner re-checks the real deadline when the entry is popped, and
    /// [`Self::earliest`] may then report a conservative (earlier) time.
    pub fn set_no_later(&mut self, key: K, deadline: Timestamp) {
        let handle = self.handle(key);
        self.heap.set_no_later(handle, deadline.as_micros());
    }

    /// The deadline indexed for `key`.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<Timestamp> {
        let &handle = self.handles.get(key)?;
        self.heap.get(handle).map(Timestamp::from_micros)
    }

    pub fn remove(&mut self, key: &K) {
        if let Some(handle) = self.handles.remove(key) {
            self.heap.remove(handle);
            self.release(handle);
        }
    }

    /// Drain every currently due entry.
    #[allow(dead_code)]
    pub fn pop_due(&mut self, now: Timestamp, out: &mut Vec<K>) {
        let _ = self.pop_due_bounded(now, usize::MAX, out);
    }

    /// Drain at most `max_work` due entries, earliest first. Returns
    /// `(entries_visited, due_entries_remaining)`.
    pub fn pop_due_bounded(
        &mut self,
        now: Timestamp,
        max_work: usize,
        out: &mut Vec<K>,
    ) -> (usize, bool) {
        out.clear();
        let mut visited = 0;
        while visited < max_work && self.has_due(now) {
            let (_, handle) = self.heap.pop().expect("a due entry exists");
            visited += 1;
            let key = self.keys[handle as usize]
                .take()
                .expect("a heap node names a live key");
            self.handles.remove(&key);
            self.free.push(handle);
            out.push(key);
        }
        (visited, self.has_due(now))
    }

    /// Whether the earliest entry is due at `now`. O(1).
    #[must_use]
    #[inline]
    pub fn has_due(&self, now: Timestamp) -> bool {
        self.heap
            .peek()
            .is_some_and(|(deadline, _)| deadline <= now.as_micros())
    }

    /// The earliest indexed deadline. O(1); exact unless entries were placed
    /// with [`Self::set_no_later`], which may make it earlier than the real
    /// deadline, never later.
    #[must_use]
    pub fn earliest(&self) -> Option<Timestamp> {
        self.heap
            .peek()
            .map(|(deadline, _)| Timestamp::from_micros(deadline))
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// The heap handle of `key`, allocating one for a new key. One hash
    /// either way.
    fn handle(&mut self, key: K) -> u32 {
        match self.handles.entry(key) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let handle = self.free.pop().unwrap_or_else(|| {
                    self.keys.push(None);
                    u32::try_from(self.keys.len() - 1).expect("fewer than 2^32 keys")
                });
                self.keys[handle as usize] = Some(entry.key().clone());
                entry.insert(handle);
                handle
            }
        }
    }

    fn release(&mut self, handle: u32) {
        self.keys[handle as usize] = None;
        self.free.push(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work::WorkCounters;
    use proptest::prelude::*;

    fn ts(micros: u64) -> Timestamp {
        Timestamp::from_micros(micros)
    }

    #[test]
    fn set_remove_leaves_empty() {
        let mut idx = DueIndex::<u32>::default();
        idx.set(1, ts(100));
        idx.remove(&1);
        assert!(idx.is_empty());
        let mut out = Vec::new();
        idx.pop_due(ts(200), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn overwrite_deadline_uses_latest() {
        let mut idx = DueIndex::<u32>::default();
        idx.set(1, ts(100));
        idx.set(1, ts(300));
        assert_eq!(idx.len(), 1);
        let mut out = Vec::new();
        idx.pop_due(ts(200), &mut out);
        assert!(out.is_empty(), "the replaced deadline must not fire");
        idx.pop_due(ts(300), &mut out);
        assert_eq!(out, vec![1]);
    }

    #[test]
    fn pop_due_returns_earliest_first() {
        let mut idx = DueIndex::<u32>::default();
        idx.set(3, ts(300));
        idx.set(1, ts(100));
        idx.set(2, ts(200));
        let mut out = Vec::new();
        idx.pop_due(ts(300), &mut out);
        assert_eq!(out, vec![1, 2, 3]);
    }

    #[test]
    fn earliest_is_the_live_minimum() {
        let mut idx = DueIndex::<u32>::default();
        assert_eq!(idx.earliest(), None);
        idx.set(1, ts(100));
        idx.set(1, ts(300));
        assert_eq!(idx.earliest(), Some(ts(300)));
        assert_eq!(idx.get(&1), Some(ts(300)));
    }

    #[test]
    fn set_no_later_keeps_an_earlier_entry_and_moves_a_later_one() {
        let mut idx = DueIndex::<u32>::default();
        idx.set_no_later(1, ts(100));
        idx.set_no_later(1, ts(300));
        assert_eq!(idx.get(&1), Some(ts(100)), "kept conservative");
        idx.set_no_later(1, ts(50));
        assert_eq!(idx.get(&1), Some(ts(50)), "moved earlier");
    }

    /// F05: one key rescheduled a million times, and 4,096 keys rescheduled
    /// in random directions, never cost one call more than a logarithmic
    /// number of node moves -- there is no stale history to rebuild or skip.
    #[test]
    fn every_call_does_logarithmic_work() {
        let mut idx = DueIndex::<u32>::default();
        let mut state = 0x9e37_79b9_u32;
        let mut worst = 0;
        for step in 0..100_000_u64 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let ((), work) =
                WorkCounters::measure(|| idx.set(state % 4_096, ts(step ^ u64::from(state))));
            worst = worst.max(work.heap_entries_visited + work.heap_entries_cloned);
        }
        assert_eq!(idx.len(), 4_096);
        assert!(worst <= 13, "worst set: {worst} node moves");
        let (_, peek) = WorkCounters::measure(|| idx.earliest());
        assert_eq!(peek.heap_entries_visited, 0);
    }

    #[derive(Clone, Debug)]
    enum Op {
        Set(u8, u64),
        SetNoLater(u8, u64),
        Remove(u8),
        PopDue(u64),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => (0..8u8, 0..1000u64).prop_map(|(k, d)| Op::Set(k, d)),
            1 => (0..8u8, 0..1000u64).prop_map(|(k, d)| Op::SetNoLater(k, d)),
            1 => (0..8u8).prop_map(Op::Remove),
            2 => (0..1000u64).prop_map(Op::PopDue),
        ]
    }

    proptest! {
        #[test]
        fn pop_due_matches_a_model(ops in proptest::collection::vec(op_strategy(), 0..80)) {
            let mut idx = DueIndex::<u8>::default();
            let mut model = std::collections::HashMap::<u8, u64>::new();
            for op in ops {
                match op {
                    Op::Set(k, d) => {
                        idx.set(k, ts(d));
                        model.insert(k, d);
                    }
                    Op::SetNoLater(k, d) => {
                        idx.set_no_later(k, ts(d));
                        let entry = model.entry(k).or_insert(d);
                        *entry = (*entry).min(d);
                    }
                    Op::Remove(k) => {
                        idx.remove(&k);
                        model.remove(&k);
                    }
                    Op::PopDue(now) => {
                        let mut out = Vec::new();
                        idx.pop_due(ts(now), &mut out);
                        let mut expected: Vec<u8> = model
                            .iter()
                            .filter_map(|(&key, &deadline)| (deadline <= now).then_some(key))
                            .collect();
                        expected.sort_unstable();
                        out.sort_unstable();
                        prop_assert_eq!(&out, &expected);
                        for key in expected {
                            model.remove(&key);
                        }
                    }
                }
                prop_assert_eq!(idx.len(), model.len());
                prop_assert_eq!(
                    idx.earliest().map(|deadline| deadline.as_micros()),
                    model.values().copied().min()
                );
            }
        }
    }
}
