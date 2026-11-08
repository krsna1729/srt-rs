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

#[derive(Debug, Default)]
pub(crate) struct IndexedHeap {
    /// `(deadline_micros, handle)`, a binary min-heap on the deadline.
    nodes: Vec<(u64, u32)>,
    /// Node index of each handle, [`ABSENT`] if it has none.
    positions: Vec<u32>,
}

impl IndexedHeap {
    /// Live nodes.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The deadline indexed for `handle`.
    #[inline]
    pub(crate) fn get(&self, handle: u32) -> Option<u64> {
        let position = *self.positions.get(handle as usize)?;
        (position != ABSENT).then(|| self.nodes[position as usize].0)
    }

    /// The earliest node.
    #[inline]
    pub(crate) fn peek(&self) -> Option<(u64, u32)> {
        self.nodes.first().copied()
    }

    /// Index `handle` at exactly `deadline`.
    pub(crate) fn set(&mut self, handle: u32, deadline: u64) {
        match self.get(handle) {
            None => self.push(handle, deadline),
            Some(old) if deadline < old => {
                let at = self.positions[handle as usize] as usize;
                self.nodes[at].0 = deadline;
                self.sift_up(at);
            }
            Some(old) if deadline > old => {
                let at = self.positions[handle as usize] as usize;
                self.nodes[at].0 = deadline;
                self.sift_down(at);
            }
            Some(_) => {}
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
        let deadline = self.get(handle)?;
        let at = self.positions[handle as usize] as usize;
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
        if index >= self.positions.len() {
            self.positions.resize(index + 1, ABSENT);
        }
        let at = self.nodes.len();
        self.nodes.push((deadline, handle));
        self.positions[index] = at as u32;
        self.sift_up(at);
    }

    /// Remove the node at `at`, filling the hole with the last node.
    fn take_at(&mut self, at: usize) {
        count_work!(HeapEntriesVisited);
        let (_, handle) = self.nodes.swap_remove(at);
        self.positions[handle as usize] = ABSENT;
        if at < self.nodes.len() {
            self.positions[self.nodes[at].1 as usize] = at as u32;
            self.sift_up(at);
            self.sift_down(at);
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        count_work!(HeapEntriesVisited);
        self.nodes.swap(a, b);
        self.positions[self.nodes[a].1 as usize] = a as u32;
        self.positions[self.nodes[b].1 as usize] = b as u32;
    }

    fn sift_up(&mut self, mut at: usize) {
        while at > 0 {
            let parent = (at - 1) / 2;
            if self.nodes[at].0 >= self.nodes[parent].0 {
                break;
            }
            self.swap(at, parent);
            at = parent;
        }
    }

    fn sift_down(&mut self, mut at: usize) {
        let len = self.nodes.len();
        loop {
            let left = 2 * at + 1;
            if left >= len {
                break;
            }
            let right = left + 1;
            let child = if right < len && self.nodes[right].0 < self.nodes[left].0 {
                right
            } else {
                left
            };
            if self.nodes[child].0 >= self.nodes[at].0 {
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
