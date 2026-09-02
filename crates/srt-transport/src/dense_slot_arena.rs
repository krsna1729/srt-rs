//! Generational dense slot arena for established SRT socket routing.
//!
//! Encodes the dense slot index in the low bits of locally allocated SRT Socket IDs
//! and a generation tag in the high bits. Datagrams with nonzero Destination
//! Socket IDs route directly to their slot in O(1) via `AND -> indexed load -> CMP`,
//! validating the full 32-bit Socket ID and UDP source address without hash-table lookup.
//!
//! Compact [`RouteSlot`] metadata (~40 bytes) keeps the empty routing table cache-friendly
//! (~160 KiB at 4096 peer capacity vs ~6.8 MiB for inline storage), while connection objects
//! are allocated only on active admission.

use std::collections::VecDeque;
use std::net::SocketAddr;
/// One peer slot returned when removing an active peer from the arena.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PeerSlot<T> {
    pub generation: u32,
    pub socket_id: u32,
    pub address: SocketAddr,
    pub value: T,
}

/// Compact routing slot in the generational slot arena.
///
/// Keeps routing metadata compact and cache-resident (~40 bytes) so that
/// empty or low-occupancy tables avoid multi-megabyte footprints while
/// forged, stale, or port-scanning packets reject directly in L1 cache
/// without chasing pointers to the heap-allocated connection object.
#[derive(Debug)]
pub struct RouteSlot<T> {
    pub socket_id: u32,
    pub address: SocketAddr,
    pub value: Option<Box<T>>,
}

/// Read-only view into an occupied slot.
pub struct SlotRef<'a, T> {
    pub socket_id: u32,
    pub address: SocketAddr,
    pub value: &'a T,
}

/// Mutable view into an occupied slot.
#[allow(dead_code)]
pub struct SlotMut<'a, T> {
    pub socket_id: u32,
    pub address: SocketAddr,
    pub value: &'a mut T,
}
/// Generational dense slot arena for established SRT peer dispatch.
#[derive(Debug)]
pub struct DenseSlotArena<T> {
    slots: Vec<RouteSlot<T>>,
    free_slots: VecDeque<u32>,
    slot_generations: Vec<u32>,
    slot_used: Vec<bool>,
    slot_bits: u32,
    slot_mask: usize,
    max_slots: usize,
    len: usize,
}
#[allow(dead_code)]
impl<T> DenseSlotArena<T> {
    /// Create a new slot arena bounded by `max_slots`.
    pub fn new(max_slots: usize) -> Self {
        let max_slots = max_slots.max(1);
        let capacity = max_slots.max(64).next_power_of_two();
        let slot_bits = capacity.trailing_zeros();
        let slot_mask = capacity - 1;

        let free_slots: VecDeque<u32> = (0..capacity as u32).collect();
        let slot_generations = vec![1u32; capacity];
        let slot_used = vec![false; capacity];
        let mut slots = Vec::with_capacity(capacity);
        slots.resize_with(capacity, || RouteSlot {
            socket_id: 0,
            address: SocketAddr::from(([0, 0, 0, 0], 0)),
            value: None,
        });

        Self {
            slots,
            free_slots,
            slot_generations,
            slot_used,
            slot_bits,
            slot_mask,
            max_slots,
            len: 0,
        }
    }

    /// Number of occupied slots.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no slots are occupied.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum active slots allowed.
    #[inline]
    pub fn max_slots(&self) -> usize {
        self.max_slots
    }

    /// Bitmask used to extract slot index from socket ID.
    #[inline]
    pub fn slot_mask(&self) -> usize {
        self.slot_mask
    }

    /// Number of low bits used for slot index.
    #[inline]
    pub fn slot_bits(&self) -> u32 {
        self.slot_bits
    }

    /// Map a socket ID to its candidate slot index.
    #[inline]
    pub fn slot_index_for_socket_id(&self, socket_id: u32) -> usize {
        (socket_id as usize) & self.slot_mask
    }

    /// Estimated heap and inline memory footprint of the arena in bytes.
    pub fn memory_footprint_bytes(&self) -> usize {
        let base = std::mem::size_of::<Self>();
        let slots = self.slots.capacity() * std::mem::size_of::<RouteSlot<T>>();
        let generations = self.slot_generations.capacity() * std::mem::size_of::<u32>();
        let used = self.slot_used.capacity() * std::mem::size_of::<bool>();
        let free = self.free_slots.capacity() * std::mem::size_of::<u32>();
        let occupied_boxes = self.len * std::mem::size_of::<T>();
        base + slots + generations + used + free + occupied_boxes
    }

    /// Reserve a slot and construct a unique local Socket ID.
    ///
    /// If `preferred != 0` and its candidate slot has never been used, the preferred
    /// ID is honored and the slot generation is adopted. If the candidate slot was
    /// previously used and released, a fresh generation tag is synthesized so that
    /// delayed UDP datagrams matching the old preferred ID cannot alias the new connection.
    pub fn allocate_socket_id(&mut self, preferred: u32) -> Option<(usize, u32)> {
        if self.len >= self.max_slots {
            return None;
        }

        if preferred != 0 {
            let target_slot = (preferred as usize) & self.slot_mask;
            if target_slot < self.slots.len()
                && !self.slot_used[target_slot]
                && self.slots[target_slot].value.is_none()
                && let Some(pos) = self
                    .free_slots
                    .iter()
                    .position(|&s| s as usize == target_slot)
            {
                self.free_slots.remove(pos);
                self.slot_used[target_slot] = true;
                self.slot_generations[target_slot] = (preferred >> self.slot_bits).max(1);
                return Some((target_slot, preferred));
            }
        }
        let slot_idx = self.free_slots.pop_front()? as usize;
        self.slot_used[slot_idx] = true;
        let mut current_gen = self.slot_generations[slot_idx];
        let mut socket_id = (current_gen << self.slot_bits) | (slot_idx as u32);
        if socket_id == 0 {
            current_gen = current_gen.wrapping_add(1).max(1);
            self.slot_generations[slot_idx] = current_gen;
            socket_id = (current_gen << self.slot_bits) | (slot_idx as u32);
        }
        Some((slot_idx, socket_id))
    }

    /// Place an established or half-open peer into an allocated slot.
    pub fn insert_at_slot(
        &mut self,
        slot_idx: usize,
        socket_id: u32,
        address: SocketAddr,
        value: T,
    ) {
        assert!(slot_idx < self.slots.len(), "slot_idx out of bounds");
        assert!(
            self.slots[slot_idx].value.is_none(),
            "slot already occupied"
        );
        self.slots[slot_idx] = RouteSlot {
            socket_id,
            address,
            value: Some(Box::new(value)),
        };
        self.len += 1;
    }

    /// Direct O(1) indexed lookup for established datagrams.
    ///
    /// Validates full 32-bit socket ID and UDP source address without hashing.
    #[inline]
    pub fn get(&self, destination_socket_id: u32, source_addr: SocketAddr) -> Option<&T> {
        let slot_idx = self.slot_index_for_socket_id(destination_socket_id);
        let slot = self.slots.get(slot_idx)?;
        if slot.socket_id == destination_socket_id && slot.address == source_addr {
            slot.value.as_deref()
        } else {
            None
        }
    }

    /// Direct O(1) indexed mutable lookup for established datagrams.
    ///
    /// Validates full 32-bit socket ID and UDP source address without hashing.
    #[inline]
    pub fn get_mut(
        &mut self,
        destination_socket_id: u32,
        source_addr: SocketAddr,
    ) -> Option<&mut T> {
        let slot_idx = (destination_socket_id as usize) & self.slot_mask;
        let slot = self.slots.get_mut(slot_idx)?;
        if slot.socket_id == destination_socket_id && slot.address == source_addr {
            slot.value.as_deref_mut()
        } else {
            None
        }
    }

    /// Inspect a slot by its known slot index.
    #[inline]
    pub fn get_by_slot(&self, slot_idx: usize) -> Option<SlotRef<'_, T>> {
        let slot = self.slots.get(slot_idx)?;
        let value = slot.value.as_deref()?;
        Some(SlotRef {
            socket_id: slot.socket_id,
            address: slot.address,
            value,
        })
    }

    /// Mutably inspect a slot by its known slot index.
    #[inline]
    pub fn get_by_slot_mut(&mut self, slot_idx: usize) -> Option<SlotMut<'_, T>> {
        let slot = self.slots.get_mut(slot_idx)?;
        let value = slot.value.as_deref_mut()?;
        Some(SlotMut {
            socket_id: slot.socket_id,
            address: slot.address,
            value,
        })
    }

    /// Check if a given socket ID and source address currently occupy their slot.
    #[inline]
    pub fn contains(&self, socket_id: u32, source_addr: SocketAddr) -> bool {
        self.get(socket_id, source_addr).is_some()
    }

    /// Remove a peer by its slot index, advancing generation to invalidate stale packets.
    pub fn remove_by_slot(&mut self, slot_idx: usize) -> Option<PeerSlot<T>> {
        if slot_idx >= self.slots.len() {
            return None;
        }
        let slot = &mut self.slots[slot_idx];
        let val = slot.value.take()?;
        let prev_id = slot.socket_id;
        let prev_addr = slot.address;
        slot.socket_id = 0;

        let current_gen = self.slot_generations[slot_idx];
        self.slot_generations[slot_idx] = current_gen.wrapping_add(1).max(1);
        self.free_slots.push_back(slot_idx as u32);
        self.len -= 1;
        Some(PeerSlot {
            generation: current_gen,
            socket_id: prev_id,
            address: prev_addr,
            value: *val,
        })
    }

    /// Iterator over all occupied peer slots.
    pub fn iter(&self) -> impl Iterator<Item = SlotRef<'_, T>> {
        self.slots.iter().filter_map(|slot| {
            let value = slot.value.as_deref()?;
            Some(SlotRef {
                socket_id: slot.socket_id,
                address: slot.address,
                value,
            })
        })
    }

    /// Mutable iterator over all occupied peer slots.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = SlotMut<'_, T>> {
        self.slots.iter_mut().filter_map(|slot| {
            let socket_id = slot.socket_id;
            let address = slot.address;
            let value = slot.value.as_deref_mut()?;
            Some(SlotMut {
                socket_id,
                address,
                value,
            })
        })
    }

    /// Mutable iterator over occupied slots yielding borrowed address reference.
    pub fn iter_direct_mut(&mut self) -> impl Iterator<Item = (&SocketAddr, &mut T)> {
        self.slots.iter_mut().filter_map(|slot| {
            let addr = &slot.address;
            let value = slot.value.as_deref_mut()?;
            Some((addr, value))
        })
    }

    /// Consuming iterator over all occupied peer slots.
    pub fn into_occupied(self) -> impl Iterator<Item = PeerSlot<T>> {
        let slot_bits = self.slot_bits;
        self.slots.into_iter().filter_map(move |slot| {
            let val = slot.value?;
            let current_gen = (slot.socket_id >> slot_bits).max(1);
            Some(PeerSlot {
                generation: current_gen,
                socket_id: slot.socket_id,
                address: slot.address,
                value: *val,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_allocates_up_to_capacity_and_generates_masked_ids() {
        let mut arena: DenseSlotArena<&'static str> = DenseSlotArena::new(4);
        assert_eq!(arena.max_slots(), 4);
        assert_eq!(arena.len(), 0);

        let addr1: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let (s0, id0) = arena.allocate_socket_id(0).unwrap();
        assert_eq!(arena.slot_index_for_socket_id(id0), s0);
        arena.insert_at_slot(s0, id0, addr1, "peer0");

        let addr2: SocketAddr = "127.0.0.1:5002".parse().unwrap();
        let (s1, id1) = arena.allocate_socket_id(0).unwrap();
        assert_eq!(arena.slot_index_for_socket_id(id1), s1);
        arena.insert_at_slot(s1, id1, addr2, "peer1");

        assert_eq!(arena.len(), 2);
        assert_eq!(arena.get(id0, addr1), Some(&"peer0"));
        assert_eq!(arena.get(id1, addr2), Some(&"peer1"));

        // Wrong source address rejected
        assert_eq!(arena.get(id0, addr2), None);
        // Stale / forged socket ID rejected
        assert_eq!(arena.get(id0 ^ 0x1000, addr1), None);
    }

    #[test]
    fn slot_reuse_advances_generation_and_rejects_stale_ids() {
        let mut arena: DenseSlotArena<usize> = DenseSlotArena::new(64);
        let addr: SocketAddr = "10.0.0.1:8000".parse().unwrap();

        let (slot0, old_id) = arena.allocate_socket_id(0).unwrap();
        arena.insert_at_slot(slot0, old_id, addr, 42);
        assert_eq!(arena.get(old_id, addr), Some(&42));

        // Remove slot 0 -> goes to back of FIFO queue
        let removed = arena.remove_by_slot(slot0).unwrap();
        assert_eq!(removed.socket_id, old_id);
        assert_eq!(arena.get(old_id, addr), None);

        // Cycle through FIFO until slot 0 rotates back
        let (new_slot, new_id) = loop {
            let (s, id) = arena.allocate_socket_id(0).unwrap();
            if s == slot0 {
                break (s, id);
            }
            arena.insert_at_slot(s, id, addr, 0);
        };
        assert_eq!(new_slot, slot0);
        assert_ne!(new_id, old_id);
        assert_eq!(arena.slot_index_for_socket_id(new_id), slot0);
        arena.insert_at_slot(new_slot, new_id, addr, 99);
        // New ID resolves
        assert_eq!(arena.get(new_id, addr), Some(&99));
        // Old stale ID is strictly rejected!
        assert_eq!(arena.get(old_id, addr), None);
    }

    #[test]
    fn preferred_socket_id_first_use_and_subsequent_reuse_generates_new_id() {
        let mut arena: DenseSlotArena<usize> = DenseSlotArena::new(64);
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let preferred = 0x2000_0001;
        // 1. Allocate preferred X on first use
        let (slot1, id1) = arena.allocate_socket_id(preferred).unwrap();
        assert_eq!(id1, preferred);
        assert_eq!(arena.slot_index_for_socket_id(preferred), slot1);
        arena.insert_at_slot(slot1, id1, addr, 10);
        assert_eq!(arena.get(preferred, addr), Some(&10));

        // 2. Remove
        let removed = arena.remove_by_slot(slot1).unwrap();
        assert_eq!(removed.socket_id, preferred);
        assert_eq!(arena.get(preferred, addr), None);

        // 3. Allocate preferred X again -> must participate in FIFO rotation, not reuse slot 1 immediately
        let (slot2, id2) = arena.allocate_socket_id(preferred).unwrap();
        assert_ne!(
            slot2, slot1,
            "repeated preferred ID must not immediately reuse the freed slot"
        );
        assert_eq!(slot2, 0, "must pop front of FIFO queue (slot 0)");
        assert_ne!(id2, preferred);
        // 4. Insert with new id, verify old (preferred, same_addr) cannot resolve
        arena.insert_at_slot(slot2, id2, addr, 20);
        assert_eq!(arena.get(id2, addr), Some(&20));
        assert_eq!(arena.get(preferred, addr), None);
    }

    #[test]
    fn preferred_socket_id_boundary_values_0x8000_0000_0x8000_0001_u32_max() {
        let mut arena: DenseSlotArena<u32> = DenseSlotArena::new(64);
        let addr: SocketAddr = "10.1.2.3:4567".parse().unwrap();

        // 0x8000_0000 has high bit set and slot 0
        let (slot0, id0) = arena.allocate_socket_id(0x8000_0000).unwrap();
        assert_eq!(slot0, 0);
        assert_eq!(id0, 0x8000_0000);
        assert_ne!(id0, 0, "socket ID 0 must never be returned");
        arena.insert_at_slot(slot0, id0, addr, 1);
        assert_eq!(arena.get(0x8000_0000, addr), Some(&1));

        // 0x8000_0001 has high bit set and slot 1
        let (slot1, id1) = arena.allocate_socket_id(0x8000_0001).unwrap();
        assert_eq!(slot1, 1);
        assert_eq!(id1, 0x8000_0001);
        arena.insert_at_slot(slot1, id1, addr, 2);
        assert_eq!(arena.get(0x8000_0001, addr), Some(&2));

        // u32::MAX has all 32 bits set
        let (slot_max, id_max) = arena.allocate_socket_id(u32::MAX).unwrap();
        assert_eq!(slot_max, arena.slot_mask());
        assert_eq!(id_max, u32::MAX);
        arena.insert_at_slot(slot_max, id_max, addr, 3);
        assert_eq!(arena.get(u32::MAX, addr), Some(&3));
    }

    #[test]
    fn preferred_id_followed_by_ordinary_generated_reuse() {
        let mut arena: DenseSlotArena<u32> = DenseSlotArena::new(64);

        let addr: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let preferred = 0x0010_0003;

        let (slot, id) = arena.allocate_socket_id(preferred).unwrap();
        assert_eq!(id, preferred);
        arena.insert_at_slot(slot, id, addr, 111);

        assert!(arena.remove_by_slot(slot).is_some());

        // Allocate with 0 (ordinary generation): slot is reused with advanced generation
        // Under FIFO rotation, freed slot rotates to the back of the queue.
        // Allocate until slot rotates back to front:
        let (new_slot, new_id) = loop {
            let (s, id) = arena.allocate_socket_id(0).unwrap();
            if s == slot {
                break (s, id);
            }
            arena.insert_at_slot(s, id, addr, 0);
        };
        assert_eq!(new_slot, slot);
        assert_ne!(new_id, preferred);

        arena.insert_at_slot(new_slot, new_id, addr, 222);
        assert_eq!(arena.get(new_id, addr), Some(&222));
        assert_eq!(arena.get(preferred, addr), None);
    }

    #[test]
    fn preferred_socket_id_non_power_of_two_capacity_preserves_and_isolates() {
        let cases = [(30, 63), (30, 31), (1000, 1023), (1, 63)];
        for (max_peers, preferred) in cases {
            let mut arena: DenseSlotArena<u32> = DenseSlotArena::new(max_peers);
            let addr: SocketAddr = "10.0.0.1:8888".parse().unwrap();

            // 1. Preferred ID must be honored on first use even when max_peers is not a power of two
            let (slot1, id1) = arena
                .allocate_socket_id(preferred)
                .expect("allocate preferred on non-power-of-two capacity");
            assert_eq!(id1, preferred);
            assert_eq!(arena.slot_index_for_socket_id(preferred), slot1);

            arena.insert_at_slot(slot1, id1, addr, 1234);
            assert_eq!(arena.get(preferred, addr), Some(&1234));

            // 2. Remove
            let removed = arena.remove_by_slot(slot1).expect("remove slot");
            assert_eq!(removed.socket_id, preferred);
            assert_eq!(arena.get(preferred, addr), None);

            // 3. Subsequent reuse with same preferred ID must participate in FIFO rotation
            let (slot2, id2) = arena
                .allocate_socket_id(preferred)
                .expect("reallocate on freed slot");
            assert_ne!(
                slot2, slot1,
                "repeated preferred ID must not immediately reuse original slot"
            );
            assert_ne!(id2, preferred);

            arena.insert_at_slot(slot2, id2, addr, 5678);
            assert_eq!(arena.get(id2, addr), Some(&5678));
            assert_eq!(arena.get(preferred, addr), None);
        }
    }

    #[test]
    fn free_slots_rotate_fifo_spreading_reuse() {
        let mut arena: DenseSlotArena<u32> = DenseSlotArena::new(64);
        let addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();

        // Allocate slots 0, 1, 2
        let (s0, id0) = arena.allocate_socket_id(0).unwrap();
        let (s1, id1) = arena.allocate_socket_id(0).unwrap();
        let (s2, id2) = arena.allocate_socket_id(0).unwrap();
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        arena.insert_at_slot(s0, id0, addr, 0);
        arena.insert_at_slot(s1, id1, addr, 1);
        arena.insert_at_slot(s2, id2, addr, 2);

        // Remove slot 0, then remove slot 1
        arena.remove_by_slot(s0).unwrap();
        arena.remove_by_slot(s1).unwrap();

        // FIFO rotation: next allocations must use unallocated slots 3, 4, ... before reusing slot 0 then 1
        let (s3, id3) = arena.allocate_socket_id(0).unwrap();
        assert_eq!(s3, 3, "FIFO order must allocate unused slot 3 first");
        arena.insert_at_slot(s3, id3, addr, 3);

        // Allocate remaining slots up to capacity (capacity for max_peers 8 is 64)
        let mut allocated = Vec::new();
        for expected in 4..64 {
            let (s, id) = arena.allocate_socket_id(0).unwrap();
            assert_eq!(s, expected);
            arena.insert_at_slot(s, id, addr, s as u32);
            allocated.push(s);
        }

        // Now that all fresh slots 0..64 were used, next allocations must wrap to freed slot 0, then slot 1!
        let (reused_s0, _) = arena.allocate_socket_id(0).unwrap();
        assert_eq!(reused_s0, s0, "must rotate to slot 0 in FIFO order");
        let (reused_s1, _) = arena.allocate_socket_id(0).unwrap();
        assert_eq!(reused_s1, s1, "must rotate to slot 1 in FIFO order");
    }
    #[test]
    fn arena_scaling_footprint_and_reclamation_1_30_200_1000_4096() {
        let mut arena: DenseSlotArena<[u8; 1536]> = DenseSlotArena::new(4096);
        let empty_floor = arena.memory_footprint_bytes();
        assert!(empty_floor < 250_000);

        for &peer_count in &[1, 30, 200, 1000, 4096] {
            let mut allocated = Vec::with_capacity(peer_count);
            for i in 0..peer_count {
                let (slot, id) = arena.allocate_socket_id(0).expect("allocate slot");
                let addr = SocketAddr::from(([10, 0, (i / 256) as u8, (i % 256) as u8], 5000));
                arena.insert_at_slot(slot, id, addr, [0u8; 1536]);
                allocated.push((slot, id, addr));
            }

            assert_eq!(arena.len(), peer_count);
            let occupied_bytes = arena.memory_footprint_bytes();
            assert_eq!(occupied_bytes, empty_floor + peer_count * 1536);

            for &(slot, id, addr) in &allocated {
                assert!(arena.get(id, addr).is_some());
                assert_eq!(arena.slot_index_for_socket_id(id), slot);
            }

            for (slot, id, addr) in allocated {
                let removed = arena.remove_by_slot(slot).expect("remove slot");
                assert_eq!(removed.socket_id, id);
                assert_eq!(removed.address, addr);
            }
            assert_eq!(arena.len(), 0);
            assert_eq!(arena.memory_footprint_bytes(), empty_floor);
        }
    }

    #[test]
    fn empty_arena_footprint_is_compact_at_4096_capacity() {
        let arena: DenseSlotArena<[u8; 1536]> = DenseSlotArena::new(4096);
        let bytes = arena.memory_footprint_bytes();
        // Previous inline storage: 4096 * ~1.6 KiB = ~6.8 MiB.
        // Compact RouteSlot storage: 4096 * 40B + overhead = ~200 KiB.
        assert!(
            bytes < 250_000,
            "empty 4096 arena footprint should be < 250 KiB, was {bytes} bytes"
        );
    }

    #[test]
    fn address_mismatch_and_nonexistent_ids_fail_lookup() {
        let mut arena: DenseSlotArena<u32> = DenseSlotArena::new(8);
        let addr1: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:10002".parse().unwrap();

        let (slot, id) = arena.allocate_socket_id(0).unwrap();
        arena.insert_at_slot(slot, id, addr1, 100);

        assert_eq!(arena.get(id, addr1), Some(&100));
        assert_eq!(arena.get(id, addr2), None);
        assert_eq!(arena.get(id.wrapping_add(8), addr1), None);
        assert_eq!(arena.get_mut(id, addr2), None);
        assert!(!arena.contains(id, addr2));
        assert!(arena.contains(id, addr1));
    }

    #[test]
    fn get_mut_modifies_value_in_place() {
        let mut arena: DenseSlotArena<String> = DenseSlotArena::new(4);
        let addr: SocketAddr = "192.168.1.1:6000".parse().unwrap();
        let (slot, id) = arena.allocate_socket_id(0).unwrap();
        arena.insert_at_slot(slot, id, addr, "hello".to_string());

        if let Some(val) = arena.get_mut(id, addr) {
            val.push_str(" world");
        }
        assert_eq!(arena.get(id, addr).map(|s| s.as_str()), Some("hello world"));
    }

    #[test]
    fn capacity_limits_and_full_drain() {
        let mut arena: DenseSlotArena<usize> = DenseSlotArena::new(4);
        let mut allocated = Vec::new();

        for i in 0..4 {
            let addr: SocketAddr = format!("10.0.0.1:{}", 7000 + i).parse().unwrap();
            let (slot, id) = arena.allocate_socket_id(0).unwrap();
            arena.insert_at_slot(slot, id, addr, i);
            allocated.push((slot, id, addr));
        }

        assert_eq!(arena.len(), 4);
        assert!(arena.allocate_socket_id(0).is_none());

        let count = arena.iter().count();
        assert_eq!(count, 4);

        let (s0, id0, a0) = allocated[0];
        let (s2, id2, a2) = allocated[2];
        assert!(arena.remove_by_slot(s0).is_some());
        assert!(arena.remove_by_slot(s2).is_some());
        assert_eq!(arena.len(), 2);
        assert_eq!(arena.get(id0, a0), None);
        assert_eq!(arena.get(id2, a2), None);

        let addr: SocketAddr = "10.0.0.1:7099".parse().unwrap();
        let (s4, id4) = arena.allocate_socket_id(0).unwrap();
        arena.insert_at_slot(s4, id4, addr, 4);
        let (s5, id5) = arena.allocate_socket_id(0).unwrap();
        arena.insert_at_slot(s5, id5, addr, 5);
        assert_eq!(arena.len(), 4);
        assert!(arena.allocate_socket_id(0).is_none());
    }

    #[test]
    fn into_occupied_and_iter_mut() {
        let mut arena: DenseSlotArena<i32> = DenseSlotArena::new(8);
        for i in 0..3i32 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 8000 + i).parse().unwrap();
            let (slot, id) = arena.allocate_socket_id(0).unwrap();
            arena.insert_at_slot(slot, id, addr, i);
        }

        for slot in arena.iter_mut() {
            *slot.value *= 10;
        }

        let mut values: Vec<i32> = arena.into_occupied().map(|s| s.value).collect();
        values.sort();
        assert_eq!(values, vec![0, 10, 20]);
    }

    #[test]
    fn remove_out_of_bounds_and_double_remove() {
        let mut arena: DenseSlotArena<u32> = DenseSlotArena::new(4);
        assert!(arena.remove_by_slot(999).is_none());
        assert!(arena.remove_by_slot(0).is_none());

        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let (slot, id) = arena.allocate_socket_id(0).unwrap();
        arena.insert_at_slot(slot, id, addr, 1);

        assert!(arena.remove_by_slot(slot).is_some());
        assert!(arena.remove_by_slot(slot).is_none());
    }

    use proptest::prelude::*;
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    enum ModelOp {
        Allocate {
            preferred: u32,
        },
        Insert {
            val: u32,
            port: u16,
        },
        Get {
            probe_id: u32,
            port: u16,
        },
        GetMut {
            probe_id: u32,
            port: u16,
            new_val: u32,
        },
        Remove {
            slot_choice: usize,
        },
    }

    fn op_strategy() -> impl Strategy<Value = ModelOp> {
        prop_oneof![
            any::<u32>().prop_map(|preferred| ModelOp::Allocate { preferred }),
            (any::<u32>(), 1000..2000u16).prop_map(|(val, port)| ModelOp::Insert { val, port }),
            (any::<u32>(), 1000..2000u16)
                .prop_map(|(probe_id, port)| ModelOp::Get { probe_id, port }),
            (any::<u32>(), 1000..2000u16, any::<u32>()).prop_map(|(probe_id, port, new_val)| {
                ModelOp::GetMut {
                    probe_id,
                    port,
                    new_val,
                }
            }),
            (0..64usize).prop_map(|slot_choice| ModelOp::Remove { slot_choice }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn differential_dense_slot_arena_matches_hashmap(
            ops in proptest::collection::vec(op_strategy(), 1..100)
        ) {
            let mut arena = DenseSlotArena::<u32>::new(16);
            let mut model: HashMap<u32, (SocketAddr, u32)> = HashMap::new();
            let mut pending_allocations: Vec<(usize, u32)> = Vec::new();
            let mut active_slots: Vec<usize> = Vec::new();

            for op in ops {
                match op {
                    ModelOp::Allocate { preferred } => {
                        let res = arena.allocate_socket_id(preferred);
                        if let Some((slot, id)) = res {
                            assert_ne!(id, 0, "socket ID 0 must never be generated");
                            assert_eq!(arena.slot_index_for_socket_id(id), slot);
                            pending_allocations.push((slot, id));
                        }
                    }
                    ModelOp::Insert { val, port } => {
                        if let Some((slot, id)) = pending_allocations.pop() {
                            let addr = SocketAddr::from(([127, 0, 0, 1], port));
                            arena.insert_at_slot(slot, id, addr, val);
                            model.insert(id, (addr, val));
                            if !active_slots.contains(&slot) {
                                active_slots.push(slot);
                            }
                        }
                    }
                    ModelOp::Get { probe_id, port } => {
                        let addr = SocketAddr::from(([127, 0, 0, 1], port));
                        let actual = arena.get(probe_id, addr);
                        let expected = model.get(&probe_id).and_then(|(stored_addr, val)| {
                            if *stored_addr == addr {
                                Some(val)
                            } else {
                                None
                            }
                        });
                        assert_eq!(actual, expected);
                    }
                    ModelOp::GetMut { probe_id, port, new_val } => {
                        let addr = SocketAddr::from(([127, 0, 0, 1], port));
                        let actual = arena.get_mut(probe_id, addr);
                        if let Some(val) = actual {
                            *val = new_val;
                            if let Some(entry) = model.get_mut(&probe_id) {
                                entry.1 = new_val;
                            }
                        }
                    }
                    ModelOp::Remove { slot_choice } => {
                        if !active_slots.is_empty() {
                            let idx = slot_choice % active_slots.len();
                            let slot = active_slots.swap_remove(idx);
                            if let Some(removed) = arena.remove_by_slot(slot) {
                                model.remove(&removed.socket_id);
                                assert_eq!(arena.get(removed.socket_id, removed.address), None);
                            }
                        }
                    }
                }

                assert_eq!(arena.len(), model.len());
                assert_eq!(arena.iter().count(), model.len());
                for slot in arena.iter() {
                    let expected = model.get(&slot.socket_id);
                    assert!(expected.is_some());
                    let (expected_addr, expected_val) = expected.unwrap();
                    assert_eq!(&slot.address, expected_addr);
                    assert_eq!(slot.value, expected_val);
                }
            }
        }
    }
}
