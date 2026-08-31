//! Allocation regression coverage for the receiver loss-scan benchmarks.

use shiguredo_srt::{DataPacket, PacketPosition, ReceiverBuffer, Timestamp};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());

// SAFETY: allocation and deallocation are delegated unchanged to `System`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `layout` is supplied by the allocator caller.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` are supplied by the allocator caller.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

const TOTAL_PACKETS: u32 = 5_000;
const LOSS_STRIDE: u32 = 7;
const PAYLOAD_SIZE: usize = 1_316;

fn timestamp(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn packet(seq: u32, packet_timestamp: u32) -> DataPacket {
    DataPacket {
        sequence_number: seq,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0,
        retransmitted: false,
        message_number: seq & 0x03FF_FFFF,
        timestamp: packet_timestamp,
        dest_socket_id: 1,
        payload: vec![0x42; PAYLOAD_SIZE].into(),
    }
}

fn scattered_loss(recovery_batch: usize) {
    let mut receiver = ReceiverBuffer::new(0, 120, timestamp(0), 0);
    receiver.set_tsbpd_enabled(false);
    let mut held_back = Vec::with_capacity(recovery_batch);
    let mut now_us = 0;

    for seq in 0..TOTAL_PACKETS {
        now_us += 1_000;
        if seq % LOSS_STRIDE == 0 {
            held_back.push(seq);
        } else {
            let _ = receiver.receive(packet(seq, now_us as u32), timestamp(now_us));
        }
        if held_back.len() >= recovery_batch || seq == TOTAL_PACKETS - 1 {
            for &held_seq in &held_back {
                let _ = receiver.receive(packet(held_seq, now_us as u32), timestamp(now_us));
            }
            held_back.clear();
        }
        while receiver.pop_ready(timestamp(now_us)).is_some() {}
    }
}

fn burst_loss(burst_len: u32, post_burst: u32) {
    let mut receiver = ReceiverBuffer::new(0, 120, timestamp(0), 0);
    receiver.set_tsbpd_enabled(false);
    let mut now_us = 0;
    let total = burst_len + post_burst;

    for seq in burst_len..total {
        now_us += 1_000;
        let _ = receiver.receive(packet(seq, now_us as u32), timestamp(now_us));
        while receiver.pop_ready(timestamp(now_us)).is_some() {}
    }
    for seq in 0..burst_len {
        now_us += 1_000;
        let _ = receiver.receive(packet(seq, now_us as u32), timestamp(now_us));
        while receiver.pop_ready(timestamp(now_us)).is_some() {}
    }
}

fn persistent_old_hole(packet_count: u32) {
    let mut receiver = ReceiverBuffer::new(0, 120, timestamp(0), 0);
    receiver.set_tsbpd_enabled(false);
    for seq in 1..packet_count {
        let now = timestamp(u64::from(seq) + 1);
        let _ = receiver.receive(packet(seq, seq), now);
        while receiver.pop_ready(now).is_some() {}
    }
}

fn count_allocations(run: impl FnOnce()) -> u64 {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    run();
    ALLOCATIONS.load(Ordering::Relaxed)
}

#[test]
fn loss_scenarios_do_not_allocate_a_packet_order_view_per_receive() {
    let _guard = ALLOCATION_TEST_LOCK.lock().expect("allocation test lock");
    let scattered_50 = count_allocations(|| scattered_loss(50));
    let scattered_500 = count_allocations(|| scattered_loss(500));
    let burst_100_500 = count_allocations(|| burst_loss(100, 500));
    let burst_1000_2000 = count_allocations(|| burst_loss(1_000, 2_000));

    eprintln!("scattered recovery 50 allocations: {scattered_50}");
    eprintln!("scattered recovery 500 allocations: {scattered_500}");
    eprintln!("burst 100 + 500 allocations: {burst_100_500}");
    eprintln!("burst 1000 + 2000 allocations: {burst_1000_2000}");

    assert!(
        scattered_50 < 12_000,
        "unexpected allocations: {scattered_50}"
    );
    assert!(
        scattered_500 < 12_000,
        "unexpected allocations: {scattered_500}"
    );
    assert!(
        burst_100_500 < 1_500,
        "persistent loss rebuilt packet order: {burst_100_500} allocations"
    );
    assert!(
        burst_1000_2000 < 7_000,
        "persistent loss rebuilt packet order: {burst_1000_2000} allocations"
    );
}

#[test]
fn persistent_old_hole_has_no_frontier_bookkeeping_allocations() {
    let _guard = ALLOCATION_TEST_LOCK.lock().expect("allocation test lock");
    let allocations = count_allocations(|| persistent_old_hole(8_192));
    eprintln!("persistent old hole allocations: {allocations}");

    // One payload and approximately one ordered-map node allocation per
    // retained packet dominate this scenario. The frontier itself must remain
    // inline state and add no per-arrival heap allocation.
    assert!(
        allocations < 17_000,
        "frontier bookkeeping allocated per arrival: {allocations}"
    );
}

#[test]
fn full_ack_tracker_allocates_once_then_stays_allocation_free() {
    let _guard = ALLOCATION_TEST_LOCK.lock().expect("allocation test lock");
    let mut receiver = ReceiverBuffer::new(0, 120, timestamp(0), 0);
    receiver.set_tsbpd_enabled(false);
    let warmup_allocations = count_allocations(|| {
        std::hint::black_box(receiver.generate_ack(timestamp(1)));
    });

    let allocations = count_allocations(|| {
        for tick in 1..=1_000 {
            std::hint::black_box(receiver.generate_ack(timestamp(10_000 + tick)));
        }
    });
    eprintln!("first full ACK allocations: {warmup_allocations}");
    eprintln!("1,000 full ACK telemetry allocations: {allocations}");
    assert_eq!(warmup_allocations, 1);
    assert_eq!(allocations, 0);
}
