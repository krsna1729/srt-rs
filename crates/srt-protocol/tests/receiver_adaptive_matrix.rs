//! Production receiver adaptive packet window end-to-end matrix.
//!
//! Evaluates the integrated `AdaptiveReceiverPacketWindow<ReceivedPacket, 8>`
//! inside production `ReceiverBuffer` under real receiver workloads across
//! 1, 30, 200, and 1,000 connections:
//!
//! - healthy in-order delivery
//! - reordering and jitter
//! - persistent old hole
//! - scattered loss recovery
//! - dense burst recovery, promotion, demotion, and empty-page reclamation
//! - future TSBPD retention
//! - DROPREQ range removal
//! - TLPKTDROP loss expiry and frontier advancement
//! - fragmentation and application backlog accounting
//! - bonded group reservation ownership
//! - 31-bit sequence wrap

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, DataPacket, GroupEvent, GroupMode,
    PacketPosition, ReceiverBuffer, SrtConnection, SrtGroup, Timestamp,
};

struct CountingAllocator;
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static DEALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AllocReport {
    allocs: u64,
    alloc_bytes: u64,
    frees: u64,
    free_bytes: u64,
}

impl std::fmt::Display for AllocReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "+{}/+{} B, -{}/-{} B",
            self.allocs, self.alloc_bytes, self.frees, self.free_bytes
        )
    }
}

thread_local! {
    static COUNT_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
}

// SAFETY: allocation and deallocation are delegated unchanged to `System`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNT_ALLOCATIONS.with(|enabled| {
            if enabled.get() {
                ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
                ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            }
        });
        // SAFETY: `layout` is supplied by the allocator caller.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        COUNT_ALLOCATIONS.with(|enabled| {
            if enabled.get() {
                DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
                DEALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            }
        });
        // SAFETY: `ptr` and `layout` are supplied by the allocator caller.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn measure_allocations<T>(f: impl FnOnce() -> T) -> (T, AllocReport) {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    DEALLOCATIONS.store(0, Ordering::Relaxed);
    DEALLOCATED_BYTES.store(0, Ordering::Relaxed);
    COUNT_ALLOCATIONS.with(|e| e.set(true));
    let result = f();
    COUNT_ALLOCATIONS.with(|e| e.set(false));
    let report = AllocReport {
        allocs: ALLOCATIONS.load(Ordering::Relaxed),
        alloc_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
        frees: DEALLOCATIONS.load(Ordering::Relaxed),
        free_bytes: DEALLOCATED_BYTES.load(Ordering::Relaxed),
    };
    (result, report)
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

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn make_packet(seq: u32, timestamp_us: u32) -> DataPacket {
    DataPacket {
        sequence_number: seq,
        position: PacketPosition::Single,
        order_flag: false,
        encryption_flag: 0,
        retransmitted: false,
        message_number: seq & 0x03ff_ffff,
        timestamp: timestamp_us,
        dest_socket_id: 1,
        payload: Bytes::from_static(b"srt-test-payload"),
    }
}

fn transfer(caller: &mut SrtConnection, listener: &mut SrtConnection, now: Timestamp) {
    while let Some(output) = caller.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            listener
                .feed_recv_buf(&packet, now)
                .expect("packet should decode");
        }
    }
}

fn establish_pair() -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    });
    caller.connect(ts(0)).expect("caller should connect");
    for round in 0..10 {
        transfer(&mut caller, &mut listener, ts(round * 10_000));
        while let Some(output) = listener.poll_output() {
            if let ConnectionOutput::SendPacket(packet) = output {
                caller
                    .feed_recv_buf(&packet, ts(round * 10_000))
                    .expect("response should decode");
            }
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, listener);
        }
    }
    panic!("pair did not connect");
}

fn packets_from(connection: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while let Some(output) = connection.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            packets.push(packet);
        }
    }
    packets
}

#[test]
fn healthy_in_order_traffic_retains_minimal_sparse_pages() {
    let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
    buf.set_tsbpd_enabled(false);
    let now = Timestamp::from_micros(1_000);

    for seq in 0..1_000 {
        let loss = buf.receive(make_packet(seq, seq), now);
        assert_eq!(loss, None);
        let popped = buf.pop_ready(now);
        assert_eq!(popped.map(|p| p.sequence_number), Some(seq));
    }

    assert_eq!(buf.stats().available_buffer_packets, 8_192);
    assert_eq!(buf.dense_pages(), 0);
    assert_eq!(buf.promotions(), 0);
    assert_eq!(buf.demotions(), 0);
}

#[test]
fn reordering_and_jitter_are_buffered_and_delivered_in_circular_order() {
    let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
    buf.set_tsbpd_enabled(false);
    let now = Timestamp::from_micros(1_000);

    for batch in (0..64).step_by(4) {
        for offset in (0..4).rev() {
            let seq = batch + offset;
            let _ = buf.receive(make_packet(seq, seq), now);
        }
        for expected in batch..batch + 4 {
            let popped = buf.pop_ready(now);
            assert_eq!(popped.map(|p| p.sequence_number), Some(expected));
        }
    }

    assert_eq!(buf.expected_sequence(), 64);
    assert_eq!(buf.stats().available_buffer_packets, 8_192);
}

#[test]
fn persistent_old_hole_bounds_growth_and_recovers_cleanly() {
    let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
    buf.set_tsbpd_enabled(false);
    let now = Timestamp::from_micros(1_000);

    for seq in 1..=100 {
        let _ = buf.receive(make_packet(seq, seq), now);
    }
    assert_eq!(buf.pop_ready(now), None);
    assert_eq!(buf.expected_sequence(), 0);
    assert!(buf.stats().packets_in_buffer > 0);

    let _ = buf.receive(make_packet(0, 0), now);
    assert_eq!(buf.expected_sequence(), 101);

    for expected in 0..=100 {
        let popped = buf.pop_ready(now);
        assert_eq!(popped.map(|p| p.sequence_number), Some(expected));
    }
    assert_eq!(buf.pop_ready(now), None);
}

#[test]
fn scattered_loss_and_recovery_restores_sparse_pages() {
    let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
    buf.set_tsbpd_enabled(false);
    let now = Timestamp::from_micros(1_000);

    let mut missing = Vec::new();
    for seq in 0..256 {
        if seq % 7 == 0 {
            missing.push(seq);
        } else {
            let _ = buf.receive(make_packet(seq, seq), now);
        }
    }

    for &seq in &missing {
        let _ = buf.receive(make_packet(seq, seq), now);
    }

    for expected in 0..256 {
        let popped = buf.pop_ready(now);
        assert_eq!(popped.map(|p| p.sequence_number), Some(expected));
    }
    assert_eq!(buf.stats().available_buffer_packets, 8_192);
}

#[test]
fn dense_recovery_promotes_dense_then_demotes_to_sparse_and_reclaims() {
    let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
    buf.set_tsbpd_enabled(false);
    let now = Timestamp::from_micros(1_000);

    // Sequence 0 missing, sequences 1..128 arrive.
    // 128 packets across 2 pages -> promotes to Dense!
    for seq in 1..=128 {
        let _ = buf.receive(make_packet(seq, seq), now);
    }
    assert!(buf.dense_pages() >= 2);
    assert!(buf.promotions() >= 2);

    let _ = buf.receive(make_packet(0, 0), now);
    for _ in 0..121 {
        assert!(buf.pop_ready(now).is_some());
    }

    // Demotion to SparsePage triggers when occupancy falls to <= 4 per page.
    assert!(buf.demotions() >= 1);

    while buf.pop_ready(now).is_some() {}
    assert_eq!(buf.stats().available_buffer_packets, 8_192);
    assert_eq!(buf.dense_pages(), 0);
    assert_eq!(buf.sparse_pages(), 0);
}

#[test]
fn future_tsbpd_retention_holds_and_delivers_on_schedule() {
    let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
    let t_arrive = Timestamp::from_micros(1_000);
    let t_deliver = Timestamp::from_micros(125_000);

    for seq in 0..32 {
        let _ = buf.receive(make_packet(seq, 1_000), t_arrive);
    }

    assert_eq!(buf.pop_ready(t_arrive), None);
    assert_eq!(buf.stats().packets_in_buffer, 32);

    for seq in 0..32 {
        let popped = buf.pop_ready(t_deliver);
        assert_eq!(popped.map(|p| p.sequence_number), Some(seq));
    }
    assert_eq!(buf.stats().packets_in_buffer, 0);
}

#[test]
fn dropreq_range_retirement_reclaims_pages() {
    let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
    buf.set_tsbpd_enabled(false);
    let now = Timestamp::from_micros(1_000);

    for seq in 0..128 {
        let _ = buf.receive(make_packet(seq, seq), now);
    }
    assert!(buf.stats().packets_in_buffer == 128);

    let summary = buf.drop_range(10, 80).expect("valid drop range");
    assert_eq!(summary.packets_removed, 71);
    assert_eq!(buf.stats().packets_in_buffer, 128 - 71);

    for seq in 0..10 {
        assert_eq!(buf.pop_ready(now).map(|p| p.sequence_number), Some(seq));
    }
    for seq in 81..128 {
        assert_eq!(buf.pop_ready(now).map(|p| p.sequence_number), Some(seq));
    }
    assert_eq!(buf.stats().packets_in_buffer, 0);
}

#[test]
fn tlpktdrop_expiry_advances_frontier_and_expected_seq() {
    let mut buf = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
    let t0 = Timestamp::from_micros(1_000);

    for seq in 1..=5 {
        let _ = buf.receive(make_packet(seq, 1_000), t0);
    }
    assert_eq!(buf.expected_sequence(), 0);
    // Time advances past TLPKTDROP threshold (minimum 1 second + delivery time).
    let t_late = Timestamp::from_micros(2_000_000);
    let dropped = buf.drop_too_late(t_late);
    assert_eq!(dropped, vec![0]);
    assert_eq!(buf.expected_sequence(), 6);

    // Buffered packets 1..5 can now be popped.
    for seq in 1..=5 {
        assert_eq!(buf.pop_ready(t_late).map(|p| p.sequence_number), Some(seq));
    }
}

#[test]
fn sequence_wrap_31bit_operates_transparently() {
    const MASK: u32 = 0x7FFF_FFFF;
    let start = MASK - 10;
    let mut buf = ReceiverBuffer::new(start, 120, Timestamp::from_micros(0), 0);
    buf.set_tsbpd_enabled(false);
    let now = Timestamp::from_micros(1_000);

    for step in 0..22 {
        let seq = start.wrapping_add(step) & MASK;
        let _ = buf.receive(make_packet(seq, seq), now);
        let popped = buf.pop_ready(now);
        assert_eq!(popped.map(|p| p.sequence_number), Some(seq));
    }

    assert_eq!(buf.expected_sequence(), (start.wrapping_add(22)) & MASK);
    assert_eq!(buf.stats().available_buffer_packets, 8_192);
}

#[test]
fn fragmented_message_and_application_backlog_accounting() {
    let (mut caller, mut listener) = establish_pair();
    let large_payload = vec![0x42; 5_000];
    caller.send_message(&large_payload, ts(10_000)).unwrap();
    transfer(&mut caller, &mut listener, ts(10_000));

    let mut received_bytes = 0;
    while let Some(event) = listener.poll_event() {
        if let shiguredo_srt::ConnectionEvent::DataReceived { payload, .. } = event {
            received_bytes += payload.len();
        }
    }
    assert_eq!(received_bytes, 5_000);
}

#[test]
fn bonded_group_transfer_preserves_reservation() {
    let (mut caller, listener) = establish_pair();
    let mut group = SrtGroup::new(0x4000_0001, GroupMode::Broadcast).unwrap();
    group.add_member(1, 100, listener).unwrap();

    caller.send_message(b"group-payload", ts(10_000)).unwrap();
    for packet in packets_from(&mut caller) {
        group
            .member_mut(1)
            .expect("group member")
            .connection_mut()
            .feed_recv_buf(&packet, ts(10_000))
            .expect("packet should decode");
    }

    let mut delivered = false;
    while let Some(event) = group.poll_event(ts(10_000)) {
        if let GroupEvent::DataReceived(msg) = event {
            assert_eq!(&msg.payload[..], b"group-payload");
            delivered = true;
        }
    }
    assert!(delivered);
}

fn exercise_compact_phase(
    receivers: &mut [ReceiverBuffer],
    now: Timestamp,
    idle_heap: usize,
) -> (AllocReport, AllocReport) {
    let ((), report_fill) = measure_allocations(|| {
        for r in receivers.iter_mut() {
            for seq in 0..4 {
                let _ = r.receive(make_packet(seq, seq), now);
            }
        }
    });
    let ((), report_drain) = measure_allocations(|| {
        for r in receivers.iter_mut() {
            while r.pop_ready(now).is_some() {}
        }
    });
    let compact_heap: usize = receivers.iter().map(|r| r.packet_window_heap_bytes()).sum();
    assert_eq!(compact_heap, idle_heap);
    (report_fill, report_drain)
}

fn exercise_adversarial_sparse_phase(
    receivers: &mut [ReceiverBuffer],
    now: Timestamp,
    connections: usize,
) -> (AllocReport, usize, Option<usize>) {
    let ((), report) = measure_allocations(|| {
        for r in receivers.iter_mut() {
            for page in 0..128 {
                let seq = page * 64;
                let _ = r.receive(make_packet(seq, seq), now);
            }
        }
    });
    for r in receivers.iter() {
        assert_eq!(r.sparse_pages(), 128);
        assert_eq!(r.dense_pages(), 0);
        assert_eq!(r.promotions(), 0);
    }
    let heap: usize = receivers.iter().map(|r| r.packet_window_heap_bytes()).sum();
    assert_eq!(heap, connections * 68_624);
    (report, heap, rss_bytes())
}

fn exercise_moderately_sparse_phase(
    receivers: &mut [ReceiverBuffer],
    now: Timestamp,
) -> (AllocReport, usize) {
    let ((), report) = measure_allocations(|| {
        for r in receivers.iter_mut() {
            for page in 0..32 {
                let seq1 = page * 64 + 1;
                let seq2 = page * 64 + 2;
                let _ = r.receive(make_packet(seq1, seq1), now);
                let _ = r.receive(make_packet(seq2, seq2), now);
            }
        }
    });
    for r in receivers.iter() {
        assert_eq!(r.sparse_pages(), 128);
        assert_eq!(r.dense_pages(), 0);
        assert_eq!(r.promotions(), 0);
    }
    let heap: usize = receivers.iter().map(|r| r.packet_window_heap_bytes()).sum();
    (report, heap)
}

fn exercise_dense_burst_phase(
    receivers: &mut [ReceiverBuffer],
    now: Timestamp,
    sparse_heap: usize,
) -> (AllocReport, usize, Option<usize>) {
    let ((), report) = measure_allocations(|| {
        for r in receivers.iter_mut() {
            for page in 0..16 {
                let base = page * 64;
                for slot in 3..64 {
                    let seq = base + slot;
                    let _ = r.receive(make_packet(seq, seq), now);
                }
            }
        }
    });
    for r in receivers.iter() {
        assert_eq!(r.dense_pages(), 16);
        assert_eq!(r.sparse_pages(), 112);
        assert!(r.promotions() >= 16);
    }
    let heap: usize = receivers.iter().map(|r| r.packet_window_heap_bytes()).sum();
    assert!(heap > sparse_heap);
    (report, heap, rss_bytes())
}

fn exercise_post_burst_settle_phase(
    receivers: &mut [ReceiverBuffer],
    expected_sparse_heap: usize,
) -> (AllocReport, usize, Option<usize>) {
    let ((), report) = measure_allocations(|| {
        for r in receivers.iter_mut() {
            for page in 0..16 {
                let base = page * 64;
                let _ = r.drop_range(base + 4, base + 63);
            }
        }
    });
    for r in receivers.iter() {
        assert_eq!(r.dense_pages(), 0);
        assert_eq!(r.sparse_pages(), 128);
        assert!(r.demotions() >= 16);
    }
    let heap: usize = receivers.iter().map(|r| r.packet_window_heap_bytes()).sum();
    assert_eq!(heap, expected_sparse_heap);
    (report, heap, rss_bytes())
}

fn exercise_full_drain_phase(
    receivers: &mut [ReceiverBuffer],
    expected_empty_heap: usize,
) -> (AllocReport, usize, Option<usize>) {
    let ((), report) = measure_allocations(|| {
        for r in receivers.iter_mut() {
            let _ = r.drop_range(0, 8191);
        }
    });
    for r in receivers.iter() {
        assert_eq!(r.sparse_pages(), 0);
        assert_eq!(r.dense_pages(), 0);
    }
    let heap: usize = receivers.iter().map(|r| r.packet_window_heap_bytes()).sum();
    assert_eq!(heap, expected_empty_heap);
    (report, heap, rss_bytes())
}

fn scale_connection_lifecycle(connections: usize) {
    let (mut compact_receivers, _) = measure_allocations(|| {
        (0..connections)
            .map(|_| {
                let mut r = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
                r.set_tsbpd_enabled(false);
                r
            })
            .collect::<Vec<_>>()
    });
    let idle_heap: usize = compact_receivers
        .iter()
        .map(|r| r.packet_window_heap_bytes())
        .sum();
    let idle_rss = rss_bytes();
    let now = ts(1_000);

    // Phase A: Healthy / compact (4 packets in page 0).
    let (report_compact, report_compact_drain) =
        exercise_compact_phase(&mut compact_receivers, now, idle_heap);
    drop(compact_receivers);

    // Multi-page lifecycle across all 128 directory pages.
    let (mut receivers, report_construction) = measure_allocations(|| {
        (0..connections)
            .map(|_| {
                let mut r = ReceiverBuffer::new(0, 120, Timestamp::from_micros(0), 0);
                r.set_tsbpd_enabled(false);
                r
            })
            .collect::<Vec<_>>()
    });

    // Phase B: Adversarial sparse (1 packet/page across all 128 pages).
    let (report_sparse, sparse_heap, sparse_rss) =
        exercise_adversarial_sparse_phase(&mut receivers, now, connections);

    // Phase C: Moderately sparse (several packets/page across pages 0..32).
    let (report_mod_sparse, mod_sparse_heap) =
        exercise_moderately_sparse_phase(&mut receivers, now);

    // Phase D: Dense burst (promote pages 0..16 to dense).
    let (report_dense, dense_heap, dense_rss) =
        exercise_dense_burst_phase(&mut receivers, now, sparse_heap);

    // Phase E: Post-burst settle (pages 0..16 settle to 4 entries/page -> demote to sparse).
    let (report_settle, post_demote_heap, post_demote_rss) =
        exercise_post_burst_settle_phase(&mut receivers, sparse_heap);

    // Phase F: Full drain (reclaim all 128 pages to empty directory floor).
    let (report_drain, empty_heap, empty_rss) =
        exercise_full_drain_phase(&mut receivers, idle_heap);

    eprintln!(
        "[{connections:>4} conns] HEAP: idle={idle_heap} B, 128-sparse={sparse_heap} B, \
         mod-sparse={mod_sparse_heap} B, dense-16={dense_heap} B, post-demote={post_demote_heap} B, \
         empty={empty_heap} B | RSS: idle={idle_rss:?}, sparse={sparse_rss:?}, dense={dense_rss:?}, \
         post-demote={post_demote_rss:?}, empty={empty_rss:?} | ALLOCS: ctor=({report_construction}), \
         compact=({report_compact}), compact-drain=({report_compact_drain}), \
         empty->sparse128=({report_sparse}), sparse->mod=({report_mod_sparse}), \
         mod->dense16=({report_dense}), dense->sparse-settle=({report_settle}), \
         sparse->empty-drain=({report_drain})"
    );
}

#[test]
#[cfg_attr(miri, ignore = "resource-scale evidence is covered outside Miri")]
fn multi_connection_scaling_1_30_200_1000_lifecycle_footprint() {
    for &connections in &[1, 30, 200, 1_000] {
        scale_connection_lifecycle(connections);
    }
}
