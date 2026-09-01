#[path = "../challengers/receiver_packet_window.rs"]
mod receiver_packet_window;

use receiver_packet_window::ReceiverPacketWindow;

const MASK: u32 = 0x7fff_ffff;

#[cfg(target_os = "linux")]
fn rss_bytes() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_ascii_whitespace()
        .next()?
        .parse::<usize>()
        .ok()?;
    Some(kib * 1_024)
}

#[cfg(not(target_os = "linux"))]
fn rss_bytes() -> Option<usize> {
    None
}

#[test]
fn lookup_replacement_removal_and_alias_rejection_use_full_tags() {
    let mut window = ReceiverPacketWindow::new(32);
    assert_eq!(window.insert(7, 70), Ok(None));
    assert_eq!(window.insert(7, 71), Ok(Some(70)));
    assert_eq!(window.get(7), Some(&71));
    assert_eq!(window.insert(71, 710), Err(710));
    assert_eq!(window.remove(71), None);
    assert_eq!(window.remove(7), Some(71));
    assert!(window.is_empty());
    assert_eq!(window.allocated_pages(), 0);
}

#[test]
fn successor_and_range_removal_cross_sequence_and_page_wrap() {
    let start = MASK - 70;
    let sequences = [start, MASK - 1, MASK, 0, 1, 63, 64];
    let mut window = ReceiverPacketWindow::new(256);
    for sequence in sequences {
        assert_eq!(window.insert(sequence, sequence), Ok(None));
    }

    assert_eq!(window.successor_after(MASK - 1), Some(MASK));
    assert_eq!(window.successor_after(MASK), Some(0));
    assert_eq!(window.successor_after(64), Some(start));
    assert_eq!(window.first_from(MASK), Some(MASK));
    assert_eq!(window.remove_range(MASK - 1, 1), Some(4));
    assert_eq!(window.len(), 3);
    assert_eq!(window.successor_after(start), Some(63));
}

#[test]
fn sparse_pages_are_allocated_and_reclaimed_independently() {
    let mut window = ReceiverPacketWindow::new(8_192);
    let empty_bytes = window.heap_bytes();
    for sequence in [0, 63, 64, 4_096, 8_191] {
        window.insert(sequence, [0u8; 64]).unwrap();
    }
    assert_eq!(window.allocated_pages(), 4);
    assert!(window.heap_bytes() > empty_bytes);
    assert_eq!(window.remove_range(0, 8_191), Some(5));
    assert_eq!(window.allocated_pages(), 0);
    assert_eq!(window.heap_bytes(), empty_bytes);
}

#[test]
fn oversized_range_is_rejected_without_mutation() {
    let mut window = ReceiverPacketWindow::new(65);
    window.insert(10, 10).unwrap();
    assert_eq!(window.remove_range(10, 74), Some(1));
    window.insert(10, 10).unwrap();
    assert_eq!(window.remove_range(10, 75), None);
    assert_eq!(window.get(10), Some(&10));
}

#[test]
#[cfg_attr(miri, ignore = "resource-scale evidence is covered outside Miri")]
fn thousand_connection_post_burst_owned_heap_returns_to_fixed_floor() {
    const CONNECTIONS: usize = 1_000;
    let mut windows: Vec<ReceiverPacketWindow<[u8; 64]>> = (0..CONNECTIONS)
        .map(|_| ReceiverPacketWindow::new(8_192))
        .collect();
    let baseline: usize = windows.iter().map(ReceiverPacketWindow::heap_bytes).sum();
    let baseline_rss = rss_bytes();
    for window in &mut windows {
        for sequence in 0..256 {
            window.insert(sequence, [0x42; 64]).unwrap();
        }
    }
    let burst: usize = windows.iter().map(ReceiverPacketWindow::heap_bytes).sum();
    let burst_rss = rss_bytes();
    for window in &mut windows {
        assert_eq!(window.remove_range(0, 255), Some(256));
    }
    let after: usize = windows.iter().map(ReceiverPacketWindow::heap_bytes).sum();
    let after_rss = rss_bytes();
    eprintln!(
        "1,000 windows owned heap: baseline={baseline}, burst={burst}, post-burst={after} bytes; \
         process RSS: baseline={baseline_rss:?}, burst={burst_rss:?}, post-burst={after_rss:?} bytes"
    );
    assert_eq!(after, baseline);
    assert!(burst > baseline);
    assert!(baseline <= 1_100_000);
}
