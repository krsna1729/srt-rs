#![no_main]

#[path = "../../challengers/receiver_packet_window.rs"]
mod receiver_packet_window;

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use receiver_packet_window::ReceiverPacketWindow;

const MASK: u32 = 0x7fff_ffff;
const WINDOW: u32 = 256;

fn successor(map: &BTreeMap<u32, u8>, sequence: u32) -> Option<u32> {
    let next = sequence.wrapping_add(1) & MASK;
    map.keys()
        .min_by_key(|&&candidate| candidate.wrapping_sub(next) & MASK)
        .copied()
}

fuzz_target!(|data: &[u8]| {
    let Some(initial) = data.get(..4) else {
        return;
    };
    let base = u32::from_le_bytes(initial.try_into().unwrap()) & MASK;
    let mut paged = ReceiverPacketWindow::new(WINDOW);
    let mut model = BTreeMap::new();

    for action in data[4..].chunks_exact(4) {
        let offset = u32::from(u16::from_le_bytes([action[1], action[2]])) % WINDOW;
        let sequence = base.wrapping_add(offset) & MASK;
        match action[0] % 5 {
            0 => assert_eq!(paged.insert(sequence, action[3]), Ok(model.insert(sequence, action[3]))),
            1 => assert_eq!(paged.remove(sequence), model.remove(&sequence)),
            2 => assert_eq!(paged.get(sequence), model.get(&sequence)),
            3 => assert_eq!(paged.successor_after(sequence), successor(&model, sequence)),
            _ => {
                let count = u32::from(action[3]) % WINDOW + 1;
                let last = sequence.wrapping_add(count - 1) & MASK;
                let before = model.len();
                model.retain(|&candidate, _| {
                    candidate.wrapping_sub(sequence) & MASK >= count
                });
                assert_eq!(paged.remove_range(sequence, last), Some(before - model.len()));
            }
        }
        assert_eq!(paged.len(), model.len());
    }
});
