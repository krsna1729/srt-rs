use shiguredo_srt::Timestamp;
use std::cmp::Ordering as CmpOrdering;
use std::collections::hash_map::Entry as HashEntry;
use std::collections::{BinaryHeap, HashMap};
use std::hash::Hash;

const REBUILD_FLOOR: usize = 64;
const REBUILD_RATIO: usize = 4;

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
/// discarded lazily, with an exact rebuild maintaining
/// `heap_len <= max(64, 4 * live_len)` after every mutation. Because a rebuild
/// requires proportionally many stale-producing mutations, its O(live) cost
/// is amortized O(1) per mutation.
#[derive(Debug)]
pub struct DueIndex<K> {
    current: HashMap<K, u64>,
    heap: BinaryHeap<std::cmp::Reverse<DueEntry<K>>>,
    rebuild_floor: usize,
    rebuild_ratio: usize,
    #[cfg(any(test, feature = "bench-internals"))]
    stale_popped: usize,
    #[cfg(any(test, feature = "bench-internals"))]
    rebuild_count: usize,
}

impl<K> Default for DueIndex<K> {
    fn default() -> Self {
        Self {
            current: HashMap::new(),
            heap: BinaryHeap::new(),
            rebuild_floor: REBUILD_FLOOR,
            rebuild_ratio: REBUILD_RATIO,
            #[cfg(any(test, feature = "bench-internals"))]
            stale_popped: 0,
            #[cfg(any(test, feature = "bench-internals"))]
            rebuild_count: 0,
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
        self.maybe_rebuild();
    }

    pub fn remove(&mut self, key: &K) {
        if self.current.remove(key).is_some() {
            self.maybe_rebuild();
        }
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
                _ => {
                    #[cfg(any(test, feature = "bench-internals"))]
                    {
                        self.stale_popped += 1;
                    }
                }
            }
        }
        self.maybe_rebuild();
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
                _ => {
                    #[cfg(any(test, feature = "bench-internals"))]
                    {
                        self.stale_popped += 1;
                    }
                    continue;
                }
            }
        }
    }

    /// Rebuild once stale history exceeds a proportional threshold.
    ///
    /// A rebuild is O(live), but it runs only after at least O(live) stale
    /// entries accumulated, so repeated maintenance is amortized O(1) per
    /// mutation while keeping historical work strictly bounded.
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
                .map(|(key, &deadline_micros)| {
                    std::cmp::Reverse(DueEntry {
                        deadline_micros,
                        key: key.clone(),
                    })
                })
                .collect();
            #[cfg(any(test, feature = "bench-internals"))]
            {
                self.rebuild_count += 1;
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

    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn with_rebuild_policy(rebuild_floor: usize, rebuild_ratio: usize) -> Self {
        Self {
            rebuild_floor,
            rebuild_ratio,
            ..Self::default()
        }
    }

    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn live_len(&self) -> usize {
        self.current.len()
    }

    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn heap_len(&self) -> usize {
        self.heap.len()
    }

    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn stale_popped(&self) -> usize {
        self.stale_popped
    }

    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn rebuild_count(&self) -> usize {
        self.rebuild_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ts(micros: u64) -> Timestamp {
        Timestamp::from_micros(micros)
    }

    fn assert_bounded(idx: &DueIndex<u32>) {
        assert!(
            idx.heap_len() <= REBUILD_FLOOR.max(REBUILD_RATIO * idx.live_len()),
            "heap={} live={}",
            idx.heap_len(),
            idx.live_len()
        );
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

    #[test]
    fn one_key_one_million_reschedules_stays_bounded() {
        let mut idx = DueIndex::<u32>::default();
        for deadline in 0..1_000_000 {
            idx.set(1, ts(deadline));
        }
        assert_eq!(idx.live_len(), 1);
        assert_bounded(&idx);
        assert!(idx.rebuild_count() > 0);
        assert_eq!(idx.peek_min_deadline(), Some(ts(999_999)));
    }

    #[test]
    fn randomized_thousand_key_rescheduling_stays_bounded() {
        let mut idx = DueIndex::<u32>::default();
        let mut state = 0x9e37_79b9_u32;
        for step in 0..100_000_u64 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            idx.set(state % 1_000, ts(step ^ u64::from(state)));
            assert_bounded(&idx);
        }
        assert_eq!(idx.live_len(), 1_000);
    }

    #[test]
    fn set_remove_churn_and_deadline_direction_changes_stay_bounded() {
        let mut idx = DueIndex::<u32>::default();
        for round in 0..10_000_u64 {
            let key = (round % 128) as u32;
            idx.set(key, ts(1_000_000 + round));
            idx.set(key, ts(1_000_000 - round.min(1_000_000)));
            if round % 3 == 0 {
                idx.remove(&key);
            }
            assert_bounded(&idx);
        }
    }

    #[test]
    fn stale_pop_and_rebuild_counters_are_observable() {
        let mut stale = DueIndex::<u32>::with_rebuild_policy(usize::MAX, 0);
        stale.set(1, ts(1));
        stale.set(1, ts(2));
        assert_eq!(stale.peek_min_deadline(), Some(ts(2)));
        assert_eq!(stale.stale_popped(), 1);

        let mut rebuilt = DueIndex::<u32>::with_rebuild_policy(1, 1);
        rebuilt.set(1, ts(1));
        rebuilt.set(1, ts(2));
        assert_eq!(rebuilt.rebuild_count(), 1);
        assert_eq!(rebuilt.heap_len(), rebuilt.live_len());
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
                prop_assert!(
                    idx.heap_len() <= REBUILD_FLOOR.max(REBUILD_RATIO * idx.live_len())
                );
            }
        }

        #[test]
        fn pop_due_matches_last_write_wins_model(ops in proptest::collection::vec(op_strategy(), 0..80)) {
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
                prop_assert!(
                    idx.heap_len() <= REBUILD_FLOOR.max(REBUILD_RATIO * idx.live_len())
                );
            }
        }
    }
}
