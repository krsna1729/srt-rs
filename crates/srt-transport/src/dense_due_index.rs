//! Dense generational deadline index for established physical peers.
//!
//! Replaces the generic `HashMap<PhysicalPeerKey, u64>` + `BinaryHeap` with
//! a generational binary heap indexing dense route slots in `DenseSlotArena`.
//!
//! Updates and cancellations operate directly on slot metadata without hashing.
//! Lazy heap stale amplification is bounded by an amortized rebuild threshold.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use shiguredo_srt::Timestamp;

use crate::dense_slot_arena::{DenseSlotArena, PeerSlotId};

/// Minimum heap size before stale amplification triggers an amortized rebuild pass.
pub const DEFAULT_REBUILD_FLOOR: usize = 64;

/// Maximum allowable ratio of `heap_len / live_deadlines` before rebuilding.
pub const DEFAULT_REBUILD_RATIO: usize = 4;

/// Generational deadline entry in the dense heap.
#[derive(Debug, Clone, Copy)]
pub struct DenseDueEntry {
    pub deadline_micros: u64,
    pub slot_idx: u32,
    pub generation: u32,
    pub version: u32,
}

impl PartialEq for DenseDueEntry {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.deadline_micros == other.deadline_micros
    }
}

impl Eq for DenseDueEntry {}

impl PartialOrd for DenseDueEntry {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DenseDueEntry {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline_micros.cmp(&other.deadline_micros)
    }
}

/// Deadline index specialized for established peers in `DenseSlotArena`.
#[derive(Debug)]
pub struct DenseDueIndex {
    heap: BinaryHeap<Reverse<DenseDueEntry>>,
    live: usize,
    stale_popped: usize,
    rebuild_count: usize,
    rebuild_floor: usize,
    rebuild_threshold_ratio: usize,
}

impl Default for DenseDueIndex {
    fn default() -> Self {
        Self::new(DEFAULT_REBUILD_FLOOR, DEFAULT_REBUILD_RATIO)
    }
}
#[allow(dead_code)]
impl DenseDueIndex {
    #[must_use]
    pub fn new(rebuild_floor: usize, rebuild_threshold_ratio: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            live: 0,
            stale_popped: 0,
            rebuild_count: 0,
            rebuild_floor,
            rebuild_threshold_ratio,
        }
    }

    /// Set or update the established deadline for an occupied slot.
    #[inline]
    pub fn set<T>(&mut self, slot_idx: usize, deadline: Timestamp, slots: &mut DenseSlotArena<T>) {
        let deadline_micros = deadline.as_micros();
        let was_active = slots
            .get_by_slot(slot_idx)
            .is_some_and(|s| s.deadline_micros.is_some());
        let Some((generation, version)) = slots.set_slot_deadline(slot_idx, deadline_micros) else {
            return;
        };
        if !was_active {
            self.live += 1;
        }
        self.heap.push(Reverse(DenseDueEntry {
            deadline_micros,
            slot_idx: slot_idx as u32,
            generation,
            version,
        }));
        self.maybe_rebuild(slots);
    }

    /// Clear the deadline for a slot without scanning the heap.
    #[inline]
    pub fn remove<T>(&mut self, slot_idx: usize, slots: &mut DenseSlotArena<T>) {
        if slots.clear_slot_deadline(slot_idx) {
            self.live = self.live.saturating_sub(1);
            self.maybe_rebuild(slots);
        }
    }

    /// Drain all deadlines due at or before `now`.
    pub fn pop_due<T>(
        &mut self,
        now: Timestamp,
        slots: &mut DenseSlotArena<T>,
        out: &mut Vec<PeerSlotId>,
    ) {
        out.clear();
        let now_micros = now.as_micros();
        let mut live_popped = false;
        while let Some(Reverse(top)) = self.heap.peek()
            && top.deadline_micros <= now_micros
        {
            let Reverse(entry) = self.heap.pop().expect("peeked entry exists");
            let idx = entry.slot_idx as usize;
            if let Some(slot_id) = slots.consume_due_deadline(
                idx,
                entry.generation,
                entry.version,
                entry.deadline_micros,
            ) {
                self.live = self.live.saturating_sub(1);
                out.push(slot_id);
                live_popped = true;
            } else {
                self.stale_popped += 1;
            }
        }
        if live_popped {
            self.maybe_rebuild(slots);
        }
    }

    /// Earliest live deadline, discarding stale heap heads lazily.
    pub fn peek_min_deadline<T>(&mut self, slots: &DenseSlotArena<T>) -> Option<Timestamp> {
        while let Some(Reverse(entry)) = self.heap.peek() {
            let idx = entry.slot_idx as usize;
            if slots.is_live_deadline(idx, entry.generation, entry.version, entry.deadline_micros) {
                return Some(Timestamp::from_micros(entry.deadline_micros));
            }
            let Reverse(_) = self.heap.pop().expect("peeked entry exists");
            self.stale_popped += 1;
        }
        None
    }

    /// Rebuild the heap in a single $O(H)$ pass, purging all entries that no longer match slot state.
    pub fn rebuild<T>(&mut self, slots: &DenseSlotArena<T>) {
        self.rebuild_count += 1;
        let mut raw = std::mem::take(&mut self.heap).into_vec();
        raw.retain(|Reverse(entry)| {
            let idx = entry.slot_idx as usize;
            slots.is_live_deadline(idx, entry.generation, entry.version, entry.deadline_micros)
        });
        self.heap = BinaryHeap::from(raw);
    }

    #[inline]
    fn maybe_rebuild<T>(&mut self, slots: &DenseSlotArena<T>) {
        if self.live == 0 {
            if !self.heap.is_empty() {
                self.heap.clear();
            }
            return;
        }
        if self.rebuild_threshold_ratio > 0
            && self.heap.len() > self.rebuild_floor
            && self.heap.len() > self.live * self.rebuild_threshold_ratio
        {
            self.rebuild(slots);
        }
    }
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.live
    }

    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    #[must_use]
    #[inline]
    pub fn live_count(&self) -> usize {
        self.live
    }

    #[must_use]
    #[inline]
    pub fn heap_len(&self) -> usize {
        self.heap.len()
    }

    #[must_use]
    #[inline]
    pub fn stale_popped_count(&self) -> usize {
        self.stale_popped
    }

    #[must_use]
    #[inline]
    pub fn rebuild_count(&self) -> usize {
        self.rebuild_count
    }

    #[must_use]
    #[inline]
    pub fn amplification_ratio(&self) -> f64 {
        if self.live == 0 {
            self.heap.len() as f64
        } else {
            self.heap.len() as f64 / self.live as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        idx.set(s0, ts(100), &mut arena);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(100)));

        let mut due = Vec::new();
        idx.pop_due(ts(99), &mut arena, &mut due);
        assert!(due.is_empty());
        assert_eq!(idx.len(), 1);

        idx.pop_due(ts(100), &mut arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
    }

    #[test]
    fn set_then_remove() {
        let mut arena = new_test_arena(4);
        let s0 = insert_slot(&mut arena, "p0");
        let mut idx = DenseDueIndex::default();

        idx.set(s0, ts(100), &mut arena);
        assert_eq!(idx.len(), 1);

        idx.remove(s0, &mut arena);
        assert_eq!(idx.len(), 0);
        assert_eq!(idx.peek_min_deadline(&arena), None);

        let mut due = Vec::new();
        idx.pop_due(ts(200), &mut arena, &mut due);
        assert!(due.is_empty());
    }

    #[test]
    fn overwrite_later_and_earlier() {
        let mut arena = new_test_arena(4);
        let s0 = insert_slot(&mut arena, "p0");
        let mut idx = DenseDueIndex::default();

        // 1. Overwrite later: 100 -> 200
        idx.set(s0, ts(100), &mut arena);
        idx.set(s0, ts(200), &mut arena);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(200)));

        let mut due = Vec::new();
        idx.pop_due(ts(150), &mut arena, &mut due);
        assert!(due.is_empty());

        // 2. Overwrite earlier: 200 -> 50
        idx.set(s0, ts(50), &mut arena);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(50)));

        idx.pop_due(ts(50), &mut arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn repeated_overwrite_in_same_slot_invalidates_all_predecessors() {
        let mut arena = new_test_arena(4);
        let s0 = insert_slot(&mut arena, "p0");
        let mut idx = DenseDueIndex::default();

        idx.set(s0, ts(10), &mut arena);
        idx.set(s0, ts(20), &mut arena);
        idx.set(s0, ts(30), &mut arena);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(30)));

        let mut due = Vec::new();
        idx.pop_due(ts(25), &mut arena, &mut due);
        assert!(due.is_empty());

        idx.pop_due(ts(30), &mut arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn multiple_peers_fire_by_deadline_order() {
        let mut arena = new_test_arena(8);
        let s0 = insert_slot(&mut arena, "p0");
        let s1 = insert_slot(&mut arena, "p1");
        let s2 = insert_slot(&mut arena, "p2");
        let mut idx = DenseDueIndex::default();

        idx.set(s0, ts(300), &mut arena);
        idx.set(s1, ts(100), &mut arena);
        idx.set(s2, ts(200), &mut arena);
        assert_eq!(idx.len(), 3);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(100)));

        let mut due = Vec::new();
        idx.pop_due(ts(250), &mut arena, &mut due);
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].slot_idx, s1 as u32);
        assert_eq!(due[1].slot_idx, s2 as u32);
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(300)));

        idx.pop_due(ts(300), &mut arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn slot_removal_and_reuse_safety() {
        let mut arena = new_test_arena(64);
        let s0 = insert_slot(&mut arena, "peerA");
        let mut idx = DenseDueIndex::default();

        // 1. Peer A occupies slot S, sets deadline A1 at 100
        idx.set(s0, ts(100), &mut arena);
        assert_eq!(idx.len(), 1);

        // 2. Remove peer A
        // Index removes A, then arena removes slot
        idx.remove(s0, &mut arena);
        arena.remove_by_slot(s0).unwrap();
        assert_eq!(idx.len(), 0);

        // 3. Reuse slot S for peer B
        let (s_reused, id_b) = loop {
            let (s, id) = arena.allocate_socket_id(0).unwrap();
            if s == s0 {
                break (s, id);
            }
            let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
            arena.insert_at_slot(s, id, addr, "dummy");
        };
        assert_eq!(s_reused, s0);
        let addr: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        arena.insert_at_slot(s_reused, id_b, addr, "peerB");

        // 4. Set deadline B1 at 200
        idx.set(s_reused, ts(200), &mut arena);
        assert_eq!(idx.len(), 1);

        // 5. Advance time past A1 (100) but before B1 (200)
        let mut due = Vec::new();
        idx.pop_due(ts(150), &mut arena, &mut due);
        // A1 must be discarded without modifying/firing B
        assert!(due.is_empty());
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(200)));

        // 6. Time reaches B1 (200)
        idx.pop_due(ts(200), &mut arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s_reused as u32);
        assert_eq!(due[0].generation, arena.slot_generation(s_reused));
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn rebuild_removes_stale_amplification_and_preserves_live_deadlines() {
        let mut arena = new_test_arena(64);
        let mut idx = DenseDueIndex::new(8, 2); // Floor 8, 2x ratio

        let s0 = insert_slot(&mut arena, "p0");
        let s1 = insert_slot(&mut arena, "p1");

        // Set live deadlines
        idx.set(s0, ts(100), &mut arena);
        idx.set(s1, ts(200), &mut arena);
        assert_eq!(idx.live_count(), 2);
        assert_eq!(idx.heap_len(), 2);

        // Create churn on s0: 10 reschedules
        for i in 1..=10 {
            idx.set(s0, ts(100 + i), &mut arena);
        }

        // Rebuild should have triggered when heap_len > 8 && heap_len > 2 * 2
        assert!(idx.rebuild_count() > 0);
        // Explicit rebuild purges all remaining lazy stale entries
        idx.rebuild(&arena);
        assert_eq!(idx.live_count(), 2);
        assert_eq!(idx.heap_len(), 2);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(110)));

        let mut due = Vec::new();
        idx.pop_due(ts(200), &mut arena, &mut due);
        assert_eq!(due.len(), 2);
        assert_eq!(idx.live_count(), 0);
    }

    #[test]
    fn cancel_all_deadlines_purges_stale_heap_entries() {
        let mut arena = new_test_arena(128);
        let mut idx = DenseDueIndex::new(32, 2); // Floor 32, 2x ratio
        let mut slots = Vec::new();
        for i in 0..50 {
            let s = insert_slot(&mut arena, "peer");
            slots.push(s);
            idx.set(s, ts(100 + i as u64), &mut arena);
        }
        assert_eq!(idx.live_count(), 50);
        assert_eq!(idx.heap_len(), 50);

        // Reschedule each slot twice to generate stale heap entries
        for &s in &slots {
            idx.set(s, ts(500), &mut arena);
            idx.set(s, ts(1000), &mut arena);
        }
        assert_eq!(idx.live_count(), 50);
        assert!(idx.heap_len() >= 50);

        // Cancel all 50 deadlines
        for &s in &slots {
            idx.remove(s, &mut arena);
        }
        assert_eq!(idx.live_count(), 0);
        // With live == 0 and heap_len > floor (32), rebuild triggered on remove
        // and purged all stale entries down to 0!
        assert_eq!(idx.heap_len(), 0);
        assert_eq!(idx.peek_min_deadline(&arena), None);
    }

    #[test]
    fn partial_cancellation_maintains_heap_live_ratio_bound() {
        let mut arena = new_test_arena(256);
        let mut idx = DenseDueIndex::new(32, 2); // Floor 32, 2x ratio
        let mut slots = Vec::new();
        for i in 0..100 {
            let s = insert_slot(&mut arena, "peer");
            slots.push(s);
            idx.set(s, ts(100 + i as u64), &mut arena);
        }
        assert_eq!(idx.live_count(), 100);

        // Churn: reschedule each slot twice
        for &s in &slots {
            idx.set(s, ts(500), &mut arena);
            idx.set(s, ts(1000), &mut arena);
        }

        // Cancel 90 deadlines, leaving 10 live
        for &s in &slots[..90] {
            idx.remove(s, &mut arena);
        }
        assert_eq!(idx.live_count(), 10);
        // Heap must be strictly bounded to live * ratio or <= floor
        assert!(
            idx.heap_len() <= 32 || idx.heap_len() <= idx.live_count() * 2,
            "heap_len {} must be bounded by floor or live*ratio",
            idx.heap_len()
        );
    }

    #[test]
    fn timestamp_boundary_values_31bit_and_64bit() {
        let mut arena = new_test_arena(4);
        let s0 = insert_slot(&mut arena, "p0");
        let s1 = insert_slot(&mut arena, "p1");
        let mut idx = DenseDueIndex::default();

        let u31_max = 0x7fff_ffffu64;
        let u64_large = u64::MAX - 1000;

        idx.set(s0, ts(u31_max), &mut arena);
        idx.set(s1, ts(u64_large), &mut arena);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(u31_max)));

        let mut due = Vec::new();
        idx.pop_due(ts(u31_max), &mut arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s0 as u32);
        assert_eq!(idx.peek_min_deadline(&arena), Some(ts(u64_large)));

        idx.pop_due(ts(u64_large), &mut arena, &mut due);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].slot_idx, s1 as u32);
        assert!(idx.is_empty());
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

            let mut idx = DenseDueIndex::new(8, 2);
            let mut ref_map = std::collections::HashMap::<usize, u64>::new();

            for (slot_choice, op_type, value) in ops {
                let slot_idx = slots[slot_choice];
                match op_type {
                    0 => {
                        // Set
                        idx.set(slot_idx, ts(value), &mut arena);
                        ref_map.insert(slot_idx, value);
                    }
                    1 => {
                        // Remove
                        idx.remove(slot_idx, &mut arena);
                        ref_map.remove(&slot_idx);
                    }
                    2 => {
                        // Peek
                        let expected = ref_map.values().min().copied().map(ts);
                        assert_eq!(idx.peek_min_deadline(&arena), expected);
                    }
                    _ => {
                        // Pop due
                        let mut due = Vec::new();
                        idx.pop_due(ts(value), &mut arena, &mut due);
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
                assert_eq!(idx.live_count(), ref_map.len());
            }
        }
    }
}
