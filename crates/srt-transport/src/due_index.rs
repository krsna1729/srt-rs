use shiguredo_srt::Timestamp;
use std::cmp::Ordering as CmpOrdering;
use std::collections::hash_map::Entry as HashEntry;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;

#[derive(Debug)]
struct DueEntry<K> {
    deadline_micros: u64,
    key: K,
}

impl<K> PartialEq for DueEntry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline_micros == other.deadline_micros
    }
}

impl<K> Eq for DueEntry<K> {}

impl<K> PartialOrd for DueEntry<K> {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for DueEntry<K> {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.deadline_micros.cmp(&other.deadline_micros)
    }
}

/// Indexes the next deadline of many timer owners without scanning every
/// owner on each shared-loop iteration. Replaced/removed heap entries are
/// discarded lazily.
#[derive(Debug)]
pub struct DueIndex<K> {
    current: HashMap<K, u64>,
    heap: BinaryHeap<std::cmp::Reverse<DueEntry<K>>>,
}

impl<K> Default for DueIndex<K> {
    fn default() -> Self {
        Self {
            current: HashMap::new(),
            heap: BinaryHeap::new(),
        }
    }
}

impl<K> DueIndex<K>
where
    K: Clone + Eq + Hash,
{
    pub fn set(&mut self, key: K, deadline: Timestamp) {
        let deadline_micros = deadline.as_micros();
        self.current.insert(key.clone(), deadline_micros);
        self.heap.push(std::cmp::Reverse(DueEntry {
            deadline_micros,
            key,
        }));
    }

    pub fn remove(&mut self, key: &K) {
        self.current.remove(key);
    }

    pub fn pop_due(&mut self, now: Timestamp, out: &mut Vec<K>) {
        out.clear();
        while let Some(std::cmp::Reverse(top)) = self.heap.peek()
            && top.deadline_micros <= now.as_micros()
        {
            let std::cmp::Reverse(entry) = self.heap.pop().expect("peeked entry exists");
            match self.current.entry(entry.key.clone()) {
                HashEntry::Occupied(slot) if *slot.get() == entry.deadline_micros => {
                    slot.remove();
                    out.push(entry.key);
                }
                _ => {}
            }
        }
    }

    /// Earliest live deadline, cleaning stale heap entries as necessary.
    pub fn peek_min_deadline(&mut self) -> Option<Timestamp> {
        loop {
            let std::cmp::Reverse(entry) = self.heap.pop()?;
            match self.current.get(&entry.key) {
                Some(&deadline) if deadline == entry.deadline_micros => {
                    let result = Timestamp::from_micros(deadline);
                    self.heap.push(std::cmp::Reverse(entry));
                    return Some(result);
                }
                _ => continue,
            }
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

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(out.is_empty(), "old stale deadline must not fire");
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
    fn peek_min_deadline_skips_stale() {
        let mut idx = DueIndex::<u32>::default();
        idx.set(1, ts(100));
        idx.set(1, ts(300));
        assert_eq!(idx.peek_min_deadline(), Some(ts(300)));
    }

    #[test]
    fn peek_min_deadline_empty_returns_none() {
        let mut idx = DueIndex::<u32>::default();
        assert_eq!(idx.peek_min_deadline(), None);
    }

    #[derive(Clone, Debug)]
    enum Op {
        Set(u8, u64),
        Remove(u8),
        PopDue(u64),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            3 => (0..8u8, 0..1000u64).prop_map(|(k, d)| Op::Set(k, d)),
            1 => (0..8u8).prop_map(Op::Remove),
            2 => (0..1000u64).prop_map(Op::PopDue),
        ]
    }

    proptest! {
        #[test]
        fn len_matches_logical_entries(ops in proptest::collection::vec(op_strategy(), 0..80)) {
            let mut idx = DueIndex::<u8>::default();
            let mut model = std::collections::HashMap::<u8, u64>::new();
            for op in ops {
                match op {
                    Op::Set(k, d) => {
                        idx.set(k, ts(d));
                        model.insert(k, d);
                    }
                    Op::Remove(k) => {
                        idx.remove(&k);
                        model.remove(&k);
                    }
                    Op::PopDue(now) => {
                        let mut out = Vec::new();
                        idx.pop_due(ts(now), &mut out);
                        for k in &out {
                            model.remove(k);
                        }
                    }
                }
                prop_assert_eq!(idx.len(), model.len());
            }
        }

        #[test]
        fn pop_due_never_fires_future_deadlines(ops in proptest::collection::vec(op_strategy(), 0..80)) {
            let mut idx = DueIndex::<u8>::default();
            let mut model = std::collections::HashMap::<u8, u64>::new();
            for op in ops {
                match op {
                    Op::Set(k, d) => {
                        idx.set(k, ts(d));
                        model.insert(k, d);
                    }
                    Op::Remove(k) => {
                        idx.remove(&k);
                        model.remove(&k);
                    }
                    Op::PopDue(now) => {
                        let mut out = Vec::new();
                        idx.pop_due(ts(now), &mut out);
                        for k in &out {
                            let deadline = model.remove(k).expect("popped key was in model");
                            prop_assert!(deadline <= now, "fired deadline {deadline} > now {now}");
                        }
                    }
                }
            }
        }
    }
}
