//! Dense deadline index for established physical peers.
//!
//! An exact indexed min-heap keyed by `DenseSlotArena` slot index: each slot
//! has at most one node, so updates and cancellations are one sift and the
//! earliest deadline is the root. There is no stale history, no lazy cleanup
//! and no rebuild, so no single call's work grows with the peer population
//! beyond O(log n). Positions live in a vector indexed by slot, so a sift
//! never hashes.
//!
//! A node also records the slot generation it was set for. Every slot
//! removal cancels its deadline first, so a popped node always names its
//! current occupant; the generation is a defensive check, not a cleanup
//! mechanism.

use srt_proto::Timestamp;

use crate::dense_slot_arena::{DenseSlotArena, PeerSlotId};
use crate::indexed_heap::IndexedHeap;

/// Deadline index specialized for established peers in `DenseSlotArena`.
#[derive(Debug, Default)]
pub struct DenseDueIndex {
    heap: IndexedHeap,
    /// Slot generation each live node was set for.
    generations: Vec<u32>,
}

#[allow(dead_code)]
impl DenseDueIndex {
    /// Set or update the deadline of an occupied slot; an empty slot is
    /// ignored.
    #[inline]
    pub fn set<T>(&mut self, slot_idx: usize, deadline: Timestamp, slots: &DenseSlotArena<T>) {
        if slots.get_by_slot(slot_idx).is_none() {
            return;
        }
        if slot_idx >= self.generations.len() {
            self.generations.resize(slot_idx + 1, 0);
        }
        self.generations[slot_idx] = slots.slot_generation(slot_idx);
        self.heap.set(slot_idx as u32, deadline.as_micros());
    }

    /// Cancel a slot's deadline.
    #[inline]
    pub fn remove(&mut self, slot_idx: usize) {
        self.heap.remove(slot_idx as u32);
    }

    /// Drain every currently due deadline.
    pub fn pop_due<T>(
        &mut self,
        now: Timestamp,
        slots: &DenseSlotArena<T>,
        out: &mut Vec<PeerSlotId>,
    ) {
        let _ = self.pop_due_bounded(now, slots, usize::MAX, out);
    }

    /// Drain at most `max_work` due deadlines, earliest first. Returns
    /// `(entries_visited, due_entries_remaining)`.
    pub fn pop_due_bounded<T>(
        &mut self,
        now: Timestamp,
        slots: &DenseSlotArena<T>,
        max_work: usize,
        out: &mut Vec<PeerSlotId>,
    ) -> (usize, bool) {
        out.clear();
        let mut visited = 0;
        while visited < max_work && self.has_due(now) {
            let (_, slot_idx) = self.heap.pop().expect("a due node exists");
            visited += 1;
            let generation = self.generations[slot_idx as usize];
            debug_assert_eq!(
                generation,
                slots.slot_generation(slot_idx as usize),
                "slot removal cancels its deadline"
            );
            if generation == slots.slot_generation(slot_idx as usize) {
                out.push(PeerSlotId {
                    slot_idx,
                    generation,
                });
            }
        }
        (visited, self.has_due(now))
    }

    /// Whether the earliest deadline is due at `now`. O(1).
    #[must_use]
    #[inline]
    pub fn has_due(&self, now: Timestamp) -> bool {
        self.heap
            .peek()
            .is_some_and(|(deadline, _)| deadline <= now.as_micros())
    }

    /// The earliest live deadline. O(1).
    #[must_use]
    #[inline]
    pub fn earliest(&self) -> Option<Timestamp> {
        self.heap
            .peek()
            .map(|(deadline, _)| Timestamp::from_micros(deadline))
    }

    /// The deadline indexed for `slot_idx`.
    #[must_use]
    #[inline]
    pub fn get(&self, slot_idx: usize) -> Option<Timestamp> {
        self.heap.get(slot_idx as u32).map(Timestamp::from_micros)
    }

    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work::WorkCounters;
    use std::net::SocketAddr;

    fn ts(micros: u64) -> Timestamp {
        Timestamp::from_micros(micros)
    }

    fn new_test_arena(size: usize) -> DenseSlotArena<&'static str> {
        DenseSlotArena::new(size)
    }

    fn insert_slot(arena: &mut DenseSlotArena<&'static str>, val: &'static str) -> usize {
        let (slot_idx, id) = arena.allocate_socket_id(0).unwrap();
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        arena.insert_at_slot(slot_idx, id, addr, val);
        slot_idx
    }

    #[test]
    fn set_then_due() {
        let mut arena = new_test_arena(4);
        let s0 = insert_slot(&mut arena, "p0");
        let mut idx = DenseDueIndex::default();

        idx.set(s0, ts(100), &arena);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.earliest(), Some(ts(100)));

        let mut due = Vec::new();
        idx.pop_due(ts(99), &arena, &mut due);
        assert!(due.is_empty());
        assert_eq!(idx.len(), 1);

        idx.pop_due(ts(100), &arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
        assert!(idx.is_empty());
    }

    #[test]
    fn set_then_remove() {
        let mut arena = new_test_arena(4);
        let s0 = insert_slot(&mut arena, "p0");
        let mut idx = DenseDueIndex::default();

        idx.set(s0, ts(100), &arena);
        idx.remove(s0);
        assert_eq!(idx.len(), 0);
        assert_eq!(idx.earliest(), None);

        let mut due = Vec::new();
        idx.pop_due(ts(200), &arena, &mut due);
        assert!(due.is_empty());
    }

    #[test]
    fn an_empty_slot_takes_no_deadline() {
        let arena = new_test_arena(4);
        let mut idx = DenseDueIndex::default();
        idx.set(0, ts(100), &arena);
        assert!(idx.is_empty());
    }

    #[test]
    fn overwrite_later_and_earlier() {
        let mut arena = new_test_arena(4);
        let s0 = insert_slot(&mut arena, "p0");
        let mut idx = DenseDueIndex::default();

        idx.set(s0, ts(100), &arena);
        idx.set(s0, ts(200), &arena);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.earliest(), Some(ts(200)));

        let mut due = Vec::new();
        idx.pop_due(ts(150), &arena, &mut due);
        assert!(due.is_empty());

        idx.set(s0, ts(50), &arena);
        assert_eq!(idx.earliest(), Some(ts(50)));
        idx.pop_due(ts(50), &arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
        assert!(idx.is_empty());
    }

    #[test]
    fn multiple_peers_fire_by_deadline_order() {
        let mut arena = new_test_arena(8);
        let s0 = insert_slot(&mut arena, "p0");
        let s1 = insert_slot(&mut arena, "p1");
        let s2 = insert_slot(&mut arena, "p2");
        let mut idx = DenseDueIndex::default();

        idx.set(s0, ts(300), &arena);
        idx.set(s1, ts(100), &arena);
        idx.set(s2, ts(200), &arena);
        assert_eq!(idx.earliest(), Some(ts(100)));

        let mut due = Vec::new();
        idx.pop_due(ts(250), &arena, &mut due);
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].slot_idx, s1 as u32);
        assert_eq!(due[1].slot_idx, s2 as u32);
        assert_eq!(idx.earliest(), Some(ts(300)));

        idx.pop_due(ts(300), &arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
    }

    #[test]
    fn a_reused_slot_fires_with_its_new_generation() {
        let mut arena = new_test_arena(64);
        let s0 = insert_slot(&mut arena, "peerA");
        let mut idx = DenseDueIndex::default();

        idx.set(s0, ts(100), &arena);
        idx.remove(s0);
        arena.remove_by_slot(s0).unwrap();

        let (s_reused, id_b) = loop {
            let (s, id) = arena.allocate_socket_id(0).unwrap();
            if s == s0 {
                break (s, id);
            }
            let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
            arena.insert_at_slot(s, id, addr, "dummy");
        };
        let addr: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        arena.insert_at_slot(s_reused, id_b, addr, "peerB");
        idx.set(s_reused, ts(200), &arena);

        let mut due = Vec::new();
        idx.pop_due(ts(150), &arena, &mut due);
        assert!(due.is_empty(), "peer A's cancelled deadline never fires");
        idx.pop_due(ts(200), &arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s_reused as u32);
        assert_eq!(due[0].generation, arena.slot_generation(s_reused));
    }

    #[test]
    fn timestamp_boundary_values_31bit_and_64bit() {
        let mut arena = new_test_arena(4);
        let s0 = insert_slot(&mut arena, "p0");
        let s1 = insert_slot(&mut arena, "p1");
        let mut idx = DenseDueIndex::default();

        let u31_max = 0x7fff_ffffu64;
        let u64_large = u64::MAX - 1000;

        idx.set(s0, ts(u31_max), &arena);
        idx.set(s1, ts(u64_large), &arena);
        assert_eq!(idx.earliest(), Some(ts(u31_max)));

        let mut due = Vec::new();
        idx.pop_due(ts(u31_max), &arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
        assert_eq!(idx.earliest(), Some(ts(u64_large)));

        idx.pop_due(ts(u64_large), &arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s1 as u32);
        assert!(idx.is_empty());
    }

    /// F05: rescheduling every slot of a full 4,096-slot arena in both
    /// directions never costs one call more than a logarithmic number of
    /// node moves, and the earliest deadline is read without any.
    #[test]
    fn every_call_does_logarithmic_work() {
        let mut arena = new_test_arena(4_096);
        let slots: Vec<usize> = (0..4_096).map(|_| insert_slot(&mut arena, "p")).collect();
        let mut idx = DenseDueIndex::default();
        let mut worst = 0;
        for round in 0..8u64 {
            for (i, &slot) in slots.iter().enumerate() {
                let deadline = if round % 2 == 0 {
                    1_000_000 + round * 10_000 + i as u64
                } else {
                    1_000_000 - round * 10_000 - i as u64
                };
                let ((), work) = WorkCounters::measure(|| idx.set(slot, ts(deadline), &arena));
                worst = worst.max(work.heap_entries_visited);
            }
        }
        assert!(worst <= 12, "worst set: {worst} node moves");
        let (_, peek) = WorkCounters::measure(|| idx.earliest());
        assert_eq!(peek.heap_entries_visited, 0);
    }

    proptest::proptest! {
        #[test]
        fn reference_model_parity(
            ops in proptest::collection::vec(
                (0..4usize, 0..4u8, 0..10_000u64),
                1..64
            )
        ) {
            let mut arena = new_test_arena(64);
            let mut slots = Vec::new();
            for i in 0..4 {
                let (slot_idx, id) = arena.allocate_socket_id(0).unwrap();
                let addr: SocketAddr = format!("127.0.0.1:{}", 7000 + i).parse().unwrap();
                arena.insert_at_slot(slot_idx, id, addr, "test");
                slots.push(slot_idx);
            }

            let mut idx = DenseDueIndex::default();
            let mut ref_map = std::collections::HashMap::<usize, u64>::new();

            for (slot_choice, op_type, value) in ops {
                let slot_idx = slots[slot_choice];
                match op_type {
                    0 => {
                        idx.set(slot_idx, ts(value), &arena);
                        ref_map.insert(slot_idx, value);
                    }
                    1 => {
                        idx.remove(slot_idx);
                        ref_map.remove(&slot_idx);
                    }
                    2 => {
                        let expected = ref_map.values().min().copied().map(ts);
                        assert_eq!(idx.earliest(), expected);
                    }
                    _ => {
                        let mut due = Vec::new();
                        idx.pop_due(ts(value), &arena, &mut due);
                        let mut ref_due = Vec::new();
                        ref_map.retain(|&slot, &mut deadline| {
                            if deadline <= value {
                                ref_due.push(slot);
                                false
                            } else {
                                true
                            }
                        });
                        assert_eq!(due.len(), ref_due.len());
                    }
                }
                assert_eq!(idx.len(), ref_map.len());
            }
        }
    }
}
