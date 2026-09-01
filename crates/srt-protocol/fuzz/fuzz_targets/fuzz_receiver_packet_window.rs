#![no_main]

#[path = "../../challengers/adaptive_receiver_packet_window.rs"]
mod adaptive_receiver_packet_window;
#[path = "../../challengers/receiver_packet_window.rs"]
mod receiver_packet_window;

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use adaptive_receiver_packet_window::AdaptiveReceiverPacketWindow;
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
    let mut adaptive = AdaptiveReceiverPacketWindow::<u8, 8>::new(WINDOW, 4);
    let mut model = BTreeMap::new();

    for action in data[4..].chunks_exact(4) {
        let offset = u32::from(u16::from_le_bytes([action[1], action[2]])) % WINDOW;
        let sequence = base.wrapping_add(offset) & MASK;
        match action[0] % 5 {
            0 => {
                let expected = model.insert(sequence, action[3]);
                assert_eq!(paged.insert(sequence, action[3]), Ok(expected));
                assert_eq!(adaptive.insert(sequence, action[3]), Ok(expected));
            }
            1 => {
                let expected = model.remove(&sequence);
                assert_eq!(paged.remove(sequence), expected);
                assert_eq!(adaptive.remove(sequence), expected);
            }
            2 => {
                assert_eq!(paged.get(sequence), model.get(&sequence));
                assert_eq!(adaptive.get(sequence), model.get(&sequence));
            }
            3 => {
                let expected = successor(&model, sequence);
                assert_eq!(paged.successor_after(sequence), expected);
                assert_eq!(adaptive.successor_after(sequence), expected);
            }
            _ => {
                let count = u32::from(action[3]) % WINDOW + 1;
                let last = sequence.wrapping_add(count - 1) & MASK;
                let before = model.len();
                model.retain(|&candidate, _| {
                    candidate.wrapping_sub(sequence) & MASK >= count
                });
                let expected = Some(before - model.len());
                assert_eq!(paged.remove_range(sequence, last), expected);
                assert_eq!(adaptive.remove_range(sequence, last), expected);
            }
        }
        assert_eq!(paged.len(), model.len());
        assert_eq!(adaptive.len(), model.len());
    }
});
