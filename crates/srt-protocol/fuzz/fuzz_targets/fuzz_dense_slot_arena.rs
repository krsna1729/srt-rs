#![no_main]

use libfuzzer_sys::fuzz_target;
use srt_transport::DenseSlotArena;
use std::collections::HashMap;
use std::net::SocketAddr;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Bound arena capacity to 4..=64 to force collisions and slot reuse
    let cap_selector = data[0];
    let capacity = match cap_selector % 4 {
        0 => 4,
        1 => 8,
        2 => 16,
        _ => 32,
    };

    let mut arena = DenseSlotArena::<u64>::new(capacity);
    let mut model: HashMap<u32, (SocketAddr, u64)> = HashMap::new();
    let mut pending_allocations: Vec<(usize, u32)> = Vec::new();
    let mut active_slots: Vec<usize> = Vec::new();

    for chunk in data[1..].chunks(8) {
        if chunk.len() < 4 {
            break;
        }
        let op = chunk[0] % 5;
        let u16_val = u16::from_le_bytes([chunk[1], chunk[2]]);
        let u32_val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        match op {
            0 => {
                // Allocate
                let preferred = if chunk.len() >= 8 {
                    u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]])
                } else {
                    u32_val
                };
                if let Some((slot, id)) = arena.allocate_socket_id(preferred) {
                    assert_eq!(arena.slot_index_for_socket_id(id), slot);
                    pending_allocations.push((slot, id));
                }
            }
            1 => {
                // Insert
                if let Some((slot, id)) = pending_allocations.pop() {
                    let port = 1000 + (u16_val % 100);
                    let addr = SocketAddr::from(([127, 0, 0, 1], port));
                    let val = u32_val as u64;
                    arena.insert_at_slot(slot, id, addr, val);
                    model.insert(id, (addr, val));
                    if !active_slots.contains(&slot) {
                        active_slots.push(slot);
                    }
                }
            }
            2 => {
                // Lookup
                let port = 1000 + (u16_val % 100);
                let addr = SocketAddr::from(([127, 0, 0, 1], port));
                let probe_id = u32_val;
                let actual = arena.get(probe_id, addr);
                let expected = model.get(&probe_id).and_then(|(stored_addr, val)| {
                    if *stored_addr == addr {
                        Some(val)
                    } else {
                        None
                    }
                });
                assert_eq!(actual, expected);
                assert_eq!(arena.contains(probe_id, addr), expected.is_some());
            }
            3 => {
                // Mutate
                let port = 1000 + (u16_val % 100);
                let addr = SocketAddr::from(([127, 0, 0, 1], port));
                let probe_id = u32_val;
                let new_val = u32_val.rotate_left(3) as u64;
                if let Some(val) = arena.get_mut(probe_id, addr) {
                    *val = new_val;
                    if let Some(entry) = model.get_mut(&probe_id) {
                        entry.1 = new_val;
                    }
                }
            }
            4 => {
                // Remove
                if !active_slots.is_empty() {
                    let idx = (u16_val as usize) % active_slots.len();
                    let slot = active_slots.swap_remove(idx);
                    if let Some(removed) = arena.remove_by_slot(slot) {
                        model.remove(&removed.socket_id);
                        assert_eq!(arena.get(removed.socket_id, removed.address), None);
                    }
                }
            }
            _ => unreachable!(),
        }

        assert_eq!(arena.len(), model.len());
        assert_eq!(arena.iter().count(), model.len());
    }
});
