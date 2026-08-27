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
