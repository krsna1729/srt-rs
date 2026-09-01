#[path = "../../challengers/receiver_packet_window.rs"]
mod receiver_packet_window;

use std::collections::BTreeMap;

use proptest::prelude::*;
use receiver_packet_window::ReceiverPacketWindow;

const MASK: u32 = 0x7fff_ffff;

fn model_successor(map: &BTreeMap<u32, u32>, sequence: u32) -> Option<u32> {
    let next = sequence.wrapping_add(1) & MASK;
    map.keys()
        .min_by_key(|&&candidate| candidate.wrapping_sub(next) & MASK)
        .copied()
}

fn in_range(first: u32, count: u32, sequence: u32) -> bool {
    sequence.wrapping_sub(first) & MASK < count
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn paged_window_matches_ordered_map_across_wrap_and_reclamation(
        base in any::<u32>().prop_map(|value| value & MASK),
        window_size in prop::sample::select(vec![65u32, 100, 127, 129, 1_000, 8_191, 8_193]),
        actions in prop::collection::vec((any::<u8>(), any::<u16>(), any::<u16>()), 1..400),
    ) {
        let mut paged = ReceiverPacketWindow::new(window_size);
        let mut model = BTreeMap::new();

        for (opcode, raw_offset, raw_count) in actions {
            let offset = u32::from(raw_offset) % window_size;
            let sequence = base.wrapping_add(offset) & MASK;
            match opcode % 5 {
                0 => {
                    let expected = model.insert(sequence, offset);
                    prop_assert_eq!(paged.insert(sequence, offset), Ok(expected));
                }
                1 => {
                    prop_assert_eq!(paged.remove(sequence), model.remove(&sequence));
                }
                2 => {
                    prop_assert_eq!(paged.get(sequence).copied(), model.get(&sequence).copied());
                }
                3 => {
                    prop_assert_eq!(paged.successor_after(sequence), model_successor(&model, sequence));
                }
                _ => {
                    let count = u32::from(raw_count) % window_size + 1;
                    let last = sequence.wrapping_add(count - 1) & MASK;
                    let before = model.len();
                    model.retain(|&candidate, _| !in_range(sequence, count, candidate));
                    prop_assert_eq!(paged.remove_range(sequence, last), Some(before - model.len()));
                }
            }
            prop_assert_eq!(paged.len(), model.len());
            prop_assert_eq!(paged.is_empty(), model.is_empty());
        }
    }
}
