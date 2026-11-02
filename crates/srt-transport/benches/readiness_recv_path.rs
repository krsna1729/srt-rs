//! Readiness-runtime receive path A/B: copying vs zero-copy decode, and the
//! cost of arrival stamps and GRO.
//!
//! Five arms over the same real loopback datagrams:
//!
//! | Arm | Receive scratch | Decode | Payload |
//! |---|---|---|---|
//! | `copy` | `RecvBatch` (scratch slots) | `SrtPacket::decode` | fresh `Bytes` (malloc + memcpy) |
//! | `bytes` | `BytesRecvBatch` (chunk slots) | `SrtPacket::decode_bytes` | refcounted slice of the chunk |
//! | `bytes_copy` | `BytesRecvBatch` | `SrtPacket::decode` | fresh `Bytes` |
//! | `stamped` | `bytes` + `SO_TIMESTAMPNS` | `SrtPacket::decode_bytes` | refcounted slice |
//! | `gro` | `stamped` + `UDP_GRO`, `BytesRecvBatch::with_gro` | `SrtPacket::decode_bytes` | slice of the message, copied once into the chunk |
//!
//! `bytes_copy` is the control that separates the two effects the switch
//! bundles: the chunk-backed scratch, and the zero-copy decode. `stamped`
//! against `bytes` is the cost of arrival stamps; `gro` against `stamped` is
//! the per-datagram effect of GRO. Loopback coalesces only what was sent as
//! one GSO packet, so the `gro` arm's sender sends `GSO_SEGMENTS` datagrams
//! per `UDP_SEGMENT` send; the other arms send one datagram per syscall.
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
use srt_proto::Timestamp;
use srt_proto::wire::{DataPacket, SrtPacket};
use srt_transport::advanced::driver::RecvBudget;
use srt_transport::advanced::native_io::{
    BytesRecvBatch, RecvBatch, drain_recv_fd, drain_recv_fd_bytes, enable_receive_timestamps,
    enable_udp_gro,
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
/// Datagrams per GSO send: 48 x 1332 B stays under one UDP payload.
const GSO_SEGMENTS: usize = 48;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arm {
    Copy,
    Bytes,
    BytesCopy,
    Stamped,
    Gro,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Bytes => "bytes",
            Self::BytesCopy => "bytes_copy",
            Self::Stamped => "stamped",
            Self::Gro => "gro",
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
    let now = Timestamp::from_micros(0);
    let mut got = 0usize;
    while got < PACKETS_PER_ROUND {
        let report = match arm {
            Arm::Copy => drain_recv_fd(fd, batch, budget, now, |_, data, _| {
                retained.push(payload_of(SrtPacket::decode(data).expect("decode")));
                got += 1;
            })?,
            Arm::Bytes | Arm::Stamped | Arm::Gro => {
                drain_recv_fd_bytes(fd, bytes_batch, budget, now, |_, datagram, _| {
                    retained.push(payload_of(
                        SrtPacket::decode_bytes(&datagram).expect("decode"),
                    ));
                    got += 1;
                })?
            }
            Arm::BytesCopy => {
                drain_recv_fd_bytes(fd, bytes_batch, budget, now, |_, datagram, _| {
                    retained.push(payload_of(SrtPacket::decode(&datagram).expect("decode")));
                    got += 1;
                })?
            }
        };
        if report.datagrams == 0 && report.would_block {
            break;
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

fn rig(arm: Arm) -> Rig {
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
    if matches!(arm, Arm::Stamped | Arm::Gro) {
        enable_receive_timestamps(receiver.as_raw_fd()).expect("SO_TIMESTAMPNS");
    }
    let bytes_batch = if arm == Arm::Gro {
        enable_udp_gro(receiver.as_raw_fd()).expect("UDP_GRO");
        set_gso_segment(&sender, datagram(0).len());
        BytesRecvBatch::with_gro(BATCH)
    } else {
        BytesRecvBatch::with_capacity(BATCH, SLOT).with_arrival_stamps(arm == Arm::Stamped)
    };
    Rig {
        receiver,
        sender,
        dest,
        batch: RecvBatch::with_capacity(BATCH, SLOT),
        bytes_batch,
        retained: Vec::with_capacity(PACKETS_PER_ROUND),
    }
}

/// Every send on `sender` larger than `segment` leaves as one GSO packet.
fn set_gso_segment(sender: &UdpSocket, segment: usize) {
    let segment = libc::c_int::try_from(segment).expect("segment fits a c_int");
    // SAFETY: `segment` is a live c_int whose size is passed with it.
    let set = unsafe {
        libc::setsockopt(
            sender.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            (&segment as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(set, 0, "UDP_SEGMENT: {}", io::Error::last_os_error());
}

/// Send one round's datagrams: one per syscall, or `GSO_SEGMENTS` per GSO
/// send for the `gro` arm.
fn send_round(arm: Arm, rig: &Rig, round: usize) {
    let datagrams =
        (0..PACKETS_PER_ROUND).map(|index| datagram((round * PACKETS_PER_ROUND + index) as u32));
    if arm != Arm::Gro {
        for datagram in datagrams {
            rig.sender
                .send_to(&datagram, rig.dest)
                .expect("send datagram");
        }
        return;
    }
    let datagrams: Vec<Vec<u8>> = datagrams.collect();
    for group in datagrams.chunks(GSO_SEGMENTS) {
        rig.sender
            .send_to(&group.concat(), rig.dest)
            .expect("send GSO packet");
    }
}

/// Arms interleave round by round so host drift cannot favour one of them.
fn main() {
    let mut entries: Vec<(Arm, Rig, Vec<u128>, usize, usize)> = [
        Arm::Copy,
        Arm::Bytes,
        Arm::BytesCopy,
        Arm::Stamped,
        Arm::Gro,
    ]
    .into_iter()
    .map(|arm| {
        (
            arm,
            rig(arm),
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
            send_round(*arm, rig, round);
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
