#[path = "../challengers/adaptive_receiver_packet_window.rs"]
mod adaptive_receiver_packet_window;
#[path = "../challengers/receiver_packet_window.rs"]
mod receiver_packet_window;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;

use adaptive_receiver_packet_window::AdaptiveReceiverPacketWindow;
use receiver_packet_window::ReceiverPacketWindow;

const WINDOW: u32 = 8_192;
const PAGE_SLOTS: u32 = 64;
const PAGE_COUNT: u32 = WINDOW / PAGE_SLOTS;
const OCCUPANCIES: [u32; 7] = [1, 2, 4, 8, 16, 32, 64];
const VALUE: [u64; 7] = [0x42; 7];

struct CountingAllocator;

thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every operation is delegated unchanged to the system allocator.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ENABLED.with(|enabled| {
            if enabled.get() {
                ALLOCATIONS.set(ALLOCATIONS.get() + 1);
                BYTES.set(BYTES.get() + layout.size());
            }
        });
        // SAFETY: the caller supplied `layout`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller supplied this allocation and layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn measure<T>(run: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCATIONS.set(0);
    BYTES.set(0);
    ENABLED.set(true);
    let value = run();
    ENABLED.set(false);
    (value, ALLOCATIONS.get(), BYTES.get())
}

fn sequences(occupancy: u32) -> impl Iterator<Item = u32> {
    (0..PAGE_COUNT).flat_map(move |page| (0..occupancy).map(move |slot| page * PAGE_SLOTS + slot))
}

fn adaptive<const N: usize>(
    occupancy: u32,
    demote_at: usize,
) -> AdaptiveReceiverPacketWindow<[u64; 7], N> {
    let mut window = AdaptiveReceiverPacketWindow::new(WINDOW, demote_at);
    for sequence in sequences(occupancy) {
        window.insert(sequence, VALUE).unwrap();
    }
    window
}

fn promoted_then_settled<const N: usize>(
    demote_at: usize,
    occupancy: u32,
) -> (AdaptiveReceiverPacketWindow<[u64; 7], N>, usize, usize) {
    let mut window = adaptive::<N>(N as u32 + 1, demote_at);
    let (_, allocations, bytes) = measure(|| {
        for page in 0..PAGE_COUNT {
            for slot in occupancy..=N as u32 {
                window.remove(page * PAGE_SLOTS + slot);
            }
        }
    });
    (window, allocations, bytes)
}

fn record_history<const N: usize>(demote_at: usize, occupancy: u32) -> (usize, usize) {
    let (window, allocations, bytes) = promoted_then_settled::<N>(demote_at, occupancy);
    eprintln!(
        "N={N} demote@{demote_at} settle={occupancy}: heap={} sparse={} dense={} \
         transition={allocations}/{bytes} allocations/bytes",
        window.heap_bytes(),
        window.sparse_pages(),
        window.dense_pages(),
    );
    let demoted = occupancy as usize <= demote_at;
    assert_eq!(
        window.sparse_pages(),
        usize::from(demoted) * PAGE_COUNT as usize
    );
    assert_eq!(
        window.dense_pages(),
        usize::from(!demoted) * PAGE_COUNT as usize
    );
    assert_eq!(allocations, usize::from(demoted) * PAGE_COUNT as usize);
    (window.heap_bytes(), bytes)
}

#[test]
fn allocation_matrix_exposes_sparse_and_transition_thresholds() {
    for occupancy in OCCUPANCIES {
        let (btree, btree_allocs, btree_bytes) = measure(|| {
            sequences(occupancy)
                .map(|sequence| (sequence, VALUE))
                .collect::<BTreeMap<_, _>>()
        });
        let (fixed, fixed_allocs, fixed_bytes) = measure(|| {
            let mut window = ReceiverPacketWindow::new(WINDOW);
            for sequence in sequences(occupancy) {
                window.insert(sequence, VALUE).unwrap();
            }
            window
        });
        let (four, four_allocs, four_bytes) = measure(|| adaptive::<4>(occupancy, 1));
        let (eight, eight_allocs, eight_bytes) = measure(|| adaptive::<8>(occupancy, 4));
        eprintln!(
            "occupancy {occupancy:>2}/page: btree={btree_allocs}/{btree_bytes}, \
             fixed={fixed_allocs}/{fixed_bytes}, adaptive4={four_allocs}/{four_bytes}, \
             adaptive8-demote4={eight_allocs}/{eight_bytes} allocations/bytes"
        );
        let expected = (occupancy * PAGE_COUNT) as usize;
        assert_eq!(btree.len(), expected);
        assert_eq!(fixed.len(), expected);
        assert_eq!(four.len(), expected);
        assert_eq!(eight.len(), expected);
        if occupancy == 1 {
            assert!(four_bytes < fixed_bytes / 10);
            assert!(four_bytes <= btree_bytes * 2);
        }
        if occupancy == 64 {
            assert!(four_bytes < btree_bytes);
            assert!(eight_bytes < btree_bytes);
        }
    }
}

#[test]
fn post_promotion_history_matrix_exposes_retained_dense_pages() {
    for occupancy in 1..=4 {
        for demote_at in 1..=4 {
            record_history::<4>(demote_at, occupancy);
        }
        record_history::<8>(1, occupancy);
        record_history::<8>(4, occupancy);
    }

    let (n4_d1_settle4, _) = record_history::<4>(1, 4);
    let (n8_d4_settle4, _) = record_history::<8>(4, 4);
    let fresh_n4_settle4 = adaptive::<4>(4, 1).heap_bytes();
    assert!(n4_d1_settle4 > fresh_n4_settle4 * 10);
    assert!(n8_d4_settle4 < n4_d1_settle4 / 4);
}

#[test]
fn maximum_window_directory_floor_is_explicit() {
    let default = AdaptiveReceiverPacketWindow::<[u64; 7], 8>::new(WINDOW, 4).heap_bytes();
    let maximum = AdaptiveReceiverPacketWindow::<[u64; 7], 8>::new(65_536, 4).heap_bytes();
    eprintln!(
        "empty directory floor: default={default} bytes/connection, \
         maximum={maximum} bytes/connection; 1,000 maximum windows={} bytes",
        maximum * 1_000
    );
    assert_eq!(maximum, default * 8);
    assert!(maximum <= 17 * 1_024);
}

fn churn<const N: usize>(
    demote_at: usize,
    low: usize,
) -> AdaptiveReceiverPacketWindow<[u64; 7], N> {
    let mut window = AdaptiveReceiverPacketWindow::new(WINDOW, demote_at);
    for sequence in 0..low as u32 {
        window.insert(sequence, VALUE).unwrap();
    }
    for _ in 0..1_000 {
        for sequence in low as u32..=N as u32 {
            window.insert(sequence, VALUE).unwrap();
        }
        for sequence in (low as u32..=N as u32).rev() {
            window.remove(sequence);
        }
    }
    window
}

#[test]
fn hysteresis_cycle_matrix_exposes_remote_churn_cost() {
    for low in 1..=4 {
        let (_, allocations, bytes) = measure(|| churn::<4>(low, low));
        eprintln!("N4 {low}<->5 demote@{low}: {allocations}/{bytes} allocations/bytes");
        assert!(allocations >= 1_900);
    }

    let (_, at_four_allocs, at_four_bytes) = measure(|| churn::<8>(4, 4));
    let (_, at_five_allocs, at_five_bytes) = measure(|| churn::<8>(4, 5));
    let (_, at_eight_allocs, at_eight_bytes) = measure(|| churn::<8>(4, 8));
    eprintln!(
        "N8 demote@4 cycles: 4<->9={at_four_allocs}/{at_four_bytes}, \
         5<->9={at_five_allocs}/{at_five_bytes}, \
         8<->9={at_eight_allocs}/{at_eight_bytes} allocations/bytes"
    );
    assert!(at_four_allocs >= 1_900);
    assert!(at_five_allocs < 10);
    assert!(at_eight_allocs < 10);
}

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
#[cfg_attr(miri, ignore = "resource-scale evidence is covered outside Miri")]
fn same_process_btree_and_adaptive_lifecycle_records_rss_high_water() {
    const CONNECTIONS: usize = 1_000;
    let mut maps: Vec<BTreeMap<u32, [u64; 7]>> =
        (0..CONNECTIONS).map(|_| BTreeMap::new()).collect();
    let mut windows: Vec<AdaptiveReceiverPacketWindow<[u64; 7], 8>> = (0..CONNECTIONS)
        .map(|_| AdaptiveReceiverPacketWindow::new(WINDOW, 4))
        .collect();
    let idle_rss = rss_bytes();

    for (map, window) in maps.iter_mut().zip(&mut windows) {
        for sequence in (0..256).step_by(64) {
            map.insert(sequence, VALUE);
            window.insert(sequence, VALUE).unwrap();
        }
    }
    let sparse_heap: usize = windows
        .iter()
        .map(AdaptiveReceiverPacketWindow::heap_bytes)
        .sum();
    let sparse_rss = rss_bytes();

    for (map, window) in maps.iter_mut().zip(&mut windows) {
        for sequence in 0..256 {
            map.insert(sequence, VALUE);
            window.insert(sequence, VALUE).unwrap();
        }
    }
    let dense_heap: usize = windows
        .iter()
        .map(AdaptiveReceiverPacketWindow::heap_bytes)
        .sum();
    let dense_rss = rss_bytes();

    for (map, window) in maps.iter_mut().zip(&mut windows) {
        map.retain(|sequence, _| sequence % 64 == 0);
        for sequence in 0..256 {
            if sequence % 64 != 0 {
                window.remove(sequence);
            }
        }
    }
    let sparse_again_heap: usize = windows
        .iter()
        .map(AdaptiveReceiverPacketWindow::heap_bytes)
        .sum();
    let sparse_again_rss = rss_bytes();

    for (map, window) in maps.iter_mut().zip(&mut windows) {
        map.clear();
        assert_eq!(window.remove_range(0, 255), Some(4));
    }
    let empty_heap: usize = windows
        .iter()
        .map(AdaptiveReceiverPacketWindow::heap_bytes)
        .sum();
    let empty_rss = rss_bytes();
    eprintln!(
        "1,000 same-process BTreeMap+adaptive lifecycle: RSS idle={idle_rss:?}, \
         sparse={sparse_rss:?}, dense={dense_rss:?}, sparse-again={sparse_again_rss:?}, \
         empty={empty_rss:?}; adaptive owned heap sparse={sparse_heap}, dense={dense_heap}, \
         sparse-again={sparse_again_heap}, empty={empty_heap} bytes"
    );
    assert_eq!(sparse_again_heap, sparse_heap);
    assert!(dense_heap > sparse_heap);
    assert!(empty_heap < sparse_heap);
}
