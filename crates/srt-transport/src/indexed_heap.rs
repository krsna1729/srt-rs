//! Exact indexed binary min-heap of deadlines.
//!
//! Every live handle has exactly one node and the heap knows each node's
//! position, so setting, moving or removing a deadline is one sift of
//! O(log n) node moves, and the earliest deadline is the root. There are no
//! stale entries to discard lazily and no rebuild: no single call does work
//! that grows with the population beyond that logarithm. Handles are small
//! dense integers (an arena slot, or a slab index a keyed wrapper assigns),
//! so positions live in a plain vector and a sift never hashes.

/// Position marker for a handle with no node.
const ABSENT: u32 = u32::MAX;

/// Entry `i` of the one backing vector carries two unrelated things: heap
/// node `i` (meaningful for `i < len`) and the node position of handle `i`.
/// Every node names a distinct handle, so there are never more nodes than
/// entries, and one allocation serves both: a heap costs a table one
/// allocation, not two.
#[derive(Clone, Copy, Debug)]
struct Entry {
    /// Node `i`'s deadline, in microseconds.
    deadline: u64,
    /// Node `i`'s handle.
    handle: u32,
    /// Node index of handle `i`, [`ABSENT`] if it has none.
    position: u32,
}

const VACANT: Entry = Entry {
    deadline: 0,
    handle: 0,
    position: ABSENT,
};

#[derive(Debug, Default)]
pub(crate) struct IndexedHeap {
    /// Nodes `0..len` form a binary min-heap on the deadline.
    entries: Vec<Entry>,
    len: usize,
}

impl IndexedHeap {
    /// Live nodes.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    fn position(&self, handle: u32) -> Option<usize> {
        let position = self.entries.get(handle as usize)?.position;
        (position != ABSENT).then_some(position as usize)
    }

    /// The deadline indexed for `handle`.
    #[inline]
    pub(crate) fn get(&self, handle: u32) -> Option<u64> {
        self.position(handle).map(|at| self.entries[at].deadline)
    }

    /// The earliest node.
    #[inline]
    pub(crate) fn peek(&self) -> Option<(u64, u32)> {
        (self.len > 0).then(|| (self.entries[0].deadline, self.entries[0].handle))
    }

    /// Index `handle` at exactly `deadline`.
    pub(crate) fn set(&mut self, handle: u32, deadline: u64) {
        let Some(at) = self.position(handle) else {
            self.push(handle, deadline);
            return;
        };
        let old = self.entries[at].deadline;
        self.entries[at].deadline = deadline;
        if deadline < old {
            self.sift_up(at);
        } else if deadline > old {
            self.sift_down(at);
        }
    }

    /// Index `handle` no later than `deadline`: insert it, or move an
    /// existing node earlier; a node already earlier stays where it is, a
    /// conservative entry its owner re-indexes when it surfaces.
    pub(crate) fn set_no_later(&mut self, handle: u32, deadline: u64) {
        match self.get(handle) {
            Some(old) if old <= deadline => {}
            _ => self.set(handle, deadline),
        }
    }

    /// Remove `handle`'s node, returning its deadline.
    pub(crate) fn remove(&mut self, handle: u32) -> Option<u64> {
        let at = self.position(handle)?;
        let deadline = self.entries[at].deadline;
        self.take_at(at);
        Some(deadline)
    }

    /// Remove and return the earliest node.
    pub(crate) fn pop(&mut self) -> Option<(u64, u32)> {
        let root = self.peek()?;
        self.take_at(0);
        Some(root)
    }

    fn push(&mut self, handle: u32, deadline: u64) {
        let index = handle as usize;
        if index >= self.entries.len() {
            self.entries.resize(index + 1, VACANT);
        }
        let at = self.len;
        // A new node names a handle with none yet, so the nodes stay fewer
        // than the handles the vector already covers.
        debug_assert!(at < self.entries.len());
        self.len += 1;
        self.entries[at].deadline = deadline;
        self.entries[at].handle = handle;
        self.entries[index].position = at as u32;
        self.sift_up(at);
    }

    /// Remove the node at `at`, filling the hole with the last node.
    fn take_at(&mut self, at: usize) {
        count_work!(HeapEntriesVisited);
        let handle = self.entries[at].handle;
        self.entries[handle as usize].position = ABSENT;
        self.len -= 1;
        let last = self.len;
        if at < last {
            let (deadline, moved) = (self.entries[last].deadline, self.entries[last].handle);
            self.entries[at].deadline = deadline;
            self.entries[at].handle = moved;
            self.entries[moved as usize].position = at as u32;
            self.sift_up(at);
            self.sift_down(at);
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        count_work!(HeapEntriesVisited);
        let (deadline_a, handle_a) = (self.entries[a].deadline, self.entries[a].handle);
        let (deadline_b, handle_b) = (self.entries[b].deadline, self.entries[b].handle);
        self.entries[a].deadline = deadline_b;
        self.entries[a].handle = handle_b;
        self.entries[b].deadline = deadline_a;
        self.entries[b].handle = handle_a;
        self.entries[handle_b as usize].position = a as u32;
        self.entries[handle_a as usize].position = b as u32;
    }

    fn sift_up(&mut self, mut at: usize) {
        while at > 0 {
            let parent = (at - 1) / 2;
            if self.entries[at].deadline >= self.entries[parent].deadline {
                break;
            }
            self.swap(at, parent);
            at = parent;
        }
    }

    fn sift_down(&mut self, mut at: usize) {
        let len = self.len;
        loop {
            let left = 2 * at + 1;
            if left >= len {
                break;
            }
            let right = left + 1;
            let child = if right < len && self.entries[right].deadline < self.entries[left].deadline
            {
                right
            } else {
                left
            };
            if self.entries[child].deadline >= self.entries[at].deadline {
                break;
            }
            self.swap(at, child);
            at = child;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    proptest! {
        /// Against a model map: every operation leaves exactly the live
        /// deadlines indexed, and the root is their minimum.
        #[test]
        fn matches_a_model(ops in proptest::collection::vec((0..4u8, 0..32u32, 0..64u64), 1..200)) {
            let mut heap = IndexedHeap::default();
            let mut model: BTreeMap<u32, u64> = BTreeMap::new();
            for (op, handle, deadline) in ops {
                match op {
                    0 => {
                        heap.set(handle, deadline);
                        model.insert(handle, deadline);
                    }
                    1 => {
                        heap.set_no_later(handle, deadline);
                        let entry = model.entry(handle).or_insert(deadline);
                        *entry = (*entry).min(deadline);
                    }
                    2 => prop_assert_eq!(heap.remove(handle), model.remove(&handle)),
                    _ => {
                        let popped = heap.pop();
                        let min = model.iter().map(|(&h, &d)| (d, h)).min();
                        prop_assert_eq!(popped.map(|(d, _)| d), min.map(|(d, _)| d));
                        if let Some((_, h)) = popped {
                            model.remove(&h);
                        }
                    }
                }
                prop_assert_eq!(heap.len(), model.len());
                for (&h, &d) in &model {
                    prop_assert_eq!(heap.get(h), Some(d));
                }
                prop_assert_eq!(
                    heap.peek().map(|(d, _)| d),
                    model.values().copied().min()
                );
            }
        }
    }
}
