#[path = "../challengers/receiver_packet_window.rs"]
mod receiver_packet_window;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;

use receiver_packet_window::ReceiverPacketWindow;

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

#[test]
fn dense_and_sparse_allocation_tradeoff_is_explicit() {
    const WINDOW: u32 = 8_192;
    const VALUE: [u64; 7] = [0x42; 7];

    let (btree_dense, btree_dense_allocs, btree_dense_bytes) = measure(|| {
        (0..WINDOW)
            .map(|sequence| (sequence, VALUE))
            .collect::<BTreeMap<_, _>>()
    });
    let (paged_dense, paged_dense_allocs, paged_dense_bytes) = measure(|| {
        let mut window = ReceiverPacketWindow::new(WINDOW);
        for sequence in 0..WINDOW {
            window.insert(sequence, VALUE).unwrap();
        }
        window
    });
    let (btree_sparse, btree_sparse_allocs, btree_sparse_bytes) = measure(|| {
        (0..WINDOW)
            .step_by(64)
            .map(|sequence| (sequence, VALUE))
            .collect::<BTreeMap<_, _>>()
    });
    let (paged_sparse, paged_sparse_allocs, paged_sparse_bytes) = measure(|| {
        let mut window = ReceiverPacketWindow::new(WINDOW);
        for sequence in (0..WINDOW).step_by(64) {
            window.insert(sequence, VALUE).unwrap();
        }
        window
    });

    eprintln!(
        "dense BTreeMap: {btree_dense_allocs} allocations, {btree_dense_bytes} bytes; \
         paged: {paged_dense_allocs} allocations, {paged_dense_bytes} bytes"
    );
    eprintln!(
        "sparse BTreeMap: {btree_sparse_allocs} allocations, {btree_sparse_bytes} bytes; \
         paged: {paged_sparse_allocs} allocations, {paged_sparse_bytes} bytes"
    );

    assert_eq!(btree_dense.len(), paged_dense.len());
    assert_eq!(btree_sparse.len(), paged_sparse.len());
    assert!(paged_dense_allocs < btree_dense_allocs);
    assert!(paged_dense_bytes < btree_dense_bytes);
    assert!(paged_sparse_bytes > btree_sparse_bytes);
    assert_eq!(paged_sparse.allocated_pages(), 128);
}
