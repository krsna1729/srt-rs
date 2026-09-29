//! Readiness-runtime receive path A/B: copying vs zero-copy decode.
//!
//! Three arms over the same real loopback datagrams:
//!
//! | Arm | Receive scratch | Decode | Payload |
//! |---|---|---|---|
//! | `copy` | `RecvBatch` (scratch slots) | `SrtPacket::decode` | fresh `Bytes` (malloc + memcpy) |
//! | `bytes` | `BytesRecvBatch` (chunk slots) | `SrtPacket::decode_bytes` | refcounted slice of the chunk |
//! | `bytes_copy` | `BytesRecvBatch` | `SrtPacket::decode` | fresh `Bytes` |
//!
//! `bytes_copy` is the control that separates the two effects the switch
//! bundles: the chunk-backed scratch, and the zero-copy decode.
//!
//! Every decoded payload is retained until its round's datagrams have all
//! been consumed -- what a receiver buffer does with them -- and released
//! inside the timed region, so the comparison includes the release side of
//! each strategy. Protocol work after decode is identical for all arms and
//! is deliberately not measured.
//!
//! `harness = false`: prints one report line per arm.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;
use srt_proto::wire::{DataPacket, SrtPacket};
use srt_transport::advanced::driver::RecvBudget;
use srt_transport::advanced::native_io::{
    BytesRecvBatch, RecvBatch, drain_recv_fd, drain_recv_fd_bytes,
};

struct CountingAllocator;
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every allocation and deallocation straight to `System`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: delegating to the system allocator with the caller's layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: delegating to the system allocator with the caller's pointers/layout.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: delegating to the system allocator with the caller's pointers/layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// One 8 Mbit/s SRT packet: the rate the product sends per output.
const PAYLOAD: usize = 1316;
/// Wire-ceiling slot, as the production adapters size their scratch.
const SLOT: usize = 2048;
const BATCH: usize = 32;
const PACKETS_PER_ROUND: usize = 128;
const ROUNDS: usize = 32;
const REPEATS: usize = 11;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arm {
    Copy,
    Bytes,
    BytesCopy,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Bytes => "bytes",
            Self::BytesCopy => "bytes_copy",
        }
    }
}

fn datagram(sequence: u32) -> Vec<u8> {
    let payload = Bytes::from(vec![0xABu8; PAYLOAD]);
    let packet = SrtPacket::Data(DataPacket::new(
        sequence,
        sequence,
        sequence.wrapping_mul(PAYLOAD as u32),
        0x1234_5678,
        payload,
    ));
    let mut buf = Vec::with_capacity(PAYLOAD + 64);
    packet.encode(&mut buf).expect("datagram encodes");
    buf
}

fn payload_of(packet: SrtPacket) -> Bytes {
    match packet {
        SrtPacket::Data(data) => data.payload,
        SrtPacket::Control(_) => unreachable!("the bench sends DATA datagrams"),
    }
}

/// Drain one round of `PACKETS_PER_ROUND` datagrams, retaining every payload
/// and releasing the round's retention inside the timed region.
fn run_round(
    arm: Arm,
    fd: RawFd,
    batch: &mut RecvBatch,
    bytes_batch: &mut BytesRecvBatch,
    retained: &mut Vec<Bytes>,
) -> io::Result<usize> {
    let budget = RecvBudget::from_rounds(1);
    let mut got = 0usize;
    while got < PACKETS_PER_ROUND {
        match arm {
            Arm::Copy => {
                let report = drain_recv_fd(fd, batch, budget, |_, data| {
                    retained.push(payload_of(SrtPacket::decode(data).expect("decode")));
                    got += 1;
                })?;
                if report.datagrams == 0 && report.would_block {
                    break;
                }
            }
            Arm::Bytes => {
                let report = drain_recv_fd_bytes(fd, bytes_batch, budget, |_, datagram| {
                    retained.push(payload_of(
                        SrtPacket::decode_bytes(&datagram).expect("decode"),
                    ));
                    got += 1;
                })?;
                if report.datagrams == 0 && report.would_block {
                    break;
                }
            }
            Arm::BytesCopy => {
                let report = drain_recv_fd_bytes(fd, bytes_batch, budget, |_, datagram| {
                    retained.push(payload_of(SrtPacket::decode(&datagram).expect("decode")));
                    got += 1;
                })?;
                if report.datagrams == 0 && report.would_block {
                    break;
                }
            }
        }
    }
    retained.clear();
    Ok(got)
}

struct Rig {
    receiver: UdpSocket,
    sender: UdpSocket,
    dest: std::net::SocketAddr,
    batch: RecvBatch,
    bytes_batch: BytesRecvBatch,
    retained: Vec<Bytes>,
}

fn rig() -> Rig {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_nonblocking(true).expect("nonblocking");
    let dest = receiver.local_addr().expect("receiver addr");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    // One round (128 x 1332 B) must fit without drops; the kernel caps this
    // at net.core.rmem_max/wmem_max and the assert below proves it held.
    srt_transport::advanced::platform::set_sock_bufs(receiver.as_raw_fd(), 4 * 1024 * 1024)
        .expect("receiver buffers");
    srt_transport::advanced::platform::set_sock_bufs(sender.as_raw_fd(), 4 * 1024 * 1024)
        .expect("sender buffers");
    Rig {
        receiver,
        sender,
        dest,
        batch: RecvBatch::with_capacity(BATCH, SLOT),
        bytes_batch: BytesRecvBatch::with_capacity(BATCH, SLOT),
        retained: Vec::with_capacity(PACKETS_PER_ROUND),
    }
}

/// Arms interleave round by round so host drift cannot favour one of them.
fn main() {
    let mut entries: Vec<(Arm, Rig, Vec<u128>, usize, usize)> =
        [Arm::Copy, Arm::Bytes, Arm::BytesCopy]
            .into_iter()
            .map(|arm| {
                (
                    arm,
                    rig(),
                    Vec::with_capacity(REPEATS * ROUNDS),
                    0usize,
                    0usize,
                )
            })
            .collect();

    println!(
        "# readiness receive path: payload={PAYLOAD} slot={SLOT} batch={BATCH} \
         packets_per_round={PACKETS_PER_ROUND} rounds={} (median per round, arms interleaved)",
        REPEATS * ROUNDS
    );

    for round in 0..(REPEATS * ROUNDS) {
        for (arm, rig, samples, allocations, packets) in entries.iter_mut() {
            for index in 0..PACKETS_PER_ROUND {
                let sequence = (round * PACKETS_PER_ROUND + index) as u32;
                rig.sender
                    .send_to(&datagram(sequence), rig.dest)
                    .expect("send datagram");
            }
            let before = ALLOC_COUNT.load(Ordering::Relaxed);
            let started = Instant::now();
            let got = run_round(
                *arm,
                rig.receiver.as_raw_fd(),
                &mut rig.batch,
                &mut rig.bytes_batch,
                &mut rig.retained,
            )
            .expect("drain round");
            let elapsed = started.elapsed();
            *allocations += ALLOC_COUNT.load(Ordering::Relaxed) - before;
            assert_eq!(
                got, PACKETS_PER_ROUND,
                "round {round} drained {got} of {PACKETS_PER_ROUND} datagrams: the receive \
                 buffer dropped, so this measurement is not a per-datagram cost"
            );
            *packets += got;
            samples.push(elapsed.as_nanos());
        }
    }

    for (arm, _rig, samples, allocations, packets) in entries.iter_mut() {
        samples.sort_unstable();
        let median = samples[samples.len() / 2] as f64;
        println!(
            "READINESS_RECV_PATH arm={} payload={} ns_per_packet={:.1} allocs_per_packet={:.4}",
            arm.name(),
            PAYLOAD,
            median / PACKETS_PER_ROUND as f64,
            *allocations as f64 / *packets as f64
        );
    }
}
