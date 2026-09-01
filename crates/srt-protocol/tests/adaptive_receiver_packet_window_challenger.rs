#[path = "../challengers/adaptive_receiver_packet_window.rs"]
mod adaptive_receiver_packet_window;

use adaptive_receiver_packet_window::AdaptiveReceiverPacketWindow;

const MASK: u32 = 0x7fff_ffff;

#[test]
fn sparse_page_promotes_and_optional_demotion_restores_sparse_storage() {
    let mut promotion_only = AdaptiveReceiverPacketWindow::<_, 4>::new(128, false);
    let mut demoting = AdaptiveReceiverPacketWindow::<_, 4>::new(128, true);
    for sequence in 0..5 {
        promotion_only.insert(sequence, sequence).unwrap();
        demoting.insert(sequence, sequence).unwrap();
    }
    assert_eq!(
        (promotion_only.sparse_pages(), promotion_only.dense_pages()),
        (0, 1)
    );
    assert_eq!((demoting.sparse_pages(), demoting.dense_pages()), (0, 1));

    promotion_only.remove(4);
    demoting.remove(4);
    assert_eq!(
        (promotion_only.sparse_pages(), promotion_only.dense_pages()),
        (0, 1)
    );
    assert_eq!((demoting.sparse_pages(), demoting.dense_pages()), (1, 0));
    assert_eq!(demoting.get(0), Some(&0));
}

#[test]
fn replacement_alias_rejection_successor_and_range_wrap_match_fixed_semantics() {
    let start = MASK - 70;
    let mut window = AdaptiveReceiverPacketWindow::<_, 4>::new(256, true);
    for sequence in [start, MASK - 1, MASK, 0, 1, 63, 64] {
        assert_eq!(window.insert(sequence, sequence), Ok(None));
    }
    assert_eq!(window.insert(MASK, 7), Ok(Some(MASK)));
    assert_eq!(window.insert(255, 255), Err(255));
    assert_eq!(window.successor_after(MASK - 1), Some(MASK));
    assert_eq!(window.successor_after(MASK), Some(0));
    assert_eq!(window.first_from(MASK), Some(MASK));
    assert_eq!(window.remove_range(MASK - 1, 1), Some(4));
    assert_eq!(window.len(), 3);
    assert_eq!(window.successor_after(start), Some(63));
}

#[test]
fn capacity_four_and_eight_bound_sparse_heap_then_reclaim_to_directory_floor() {
    let mut four = AdaptiveReceiverPacketWindow::<[u64; 7], 4>::new(8_192, true);
    let mut eight = AdaptiveReceiverPacketWindow::<[u64; 7], 8>::new(8_192, true);
    let four_empty = four.heap_bytes();
    let eight_empty = eight.heap_bytes();
    for sequence in (0..8_192).step_by(64) {
        four.insert(sequence, [0x42; 7]).unwrap();
        eight.insert(sequence, [0x42; 7]).unwrap();
    }
    eprintln!(
        "adaptive sparse heap: N=4 {} bytes, N=8 {} bytes; empty floors: {four_empty}/{eight_empty}",
        four.heap_bytes(),
        eight.heap_bytes()
    );
    assert_eq!((four.sparse_pages(), four.dense_pages()), (128, 0));
    assert_eq!((eight.sparse_pages(), eight.dense_pages()), (128, 0));
    assert!(four.heap_bytes() < eight.heap_bytes());
    assert_eq!(four.remove_range(0, 8_191), Some(128));
    assert_eq!(eight.remove_range(0, 8_191), Some(128));
    assert_eq!(four.heap_bytes(), four_empty);
    assert_eq!(eight.heap_bytes(), eight_empty);
}

#[test]
fn invalid_range_is_rejected_without_mutation() {
    let mut window = AdaptiveReceiverPacketWindow::<_, 4>::new(65, false);
    window.insert(10, 10).unwrap();
    assert_eq!(window.remove_range(10, 75), None);
    assert_eq!(window.get(10), Some(&10));
}
