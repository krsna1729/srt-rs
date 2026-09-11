//! Allocation-guard regression test for `GroupConn::drive` (D02, Opus
//! review).
//!
//! An earlier version of this fix was checked only by comparing
//! `report.legs.as_ptr()` across two `drive()` calls. That is not airtight:
//! the system allocator can (and, on this host with glibc, does) hand a
//! freed block straight back at the identical address, so an
//! allocate-fresh-every-call implementation can pass that check by pure
//! coincidence. This test instead counts real allocator calls, the same
//! technique `crates/srt-protocol/tests/allocation_guard.rs` already uses,
//! so a regression back to "allocate a fresh `Vec` every call" shows up as
//! a real, nonzero, per-call allocation count instead of a lucky pointer
//! match.

use shiguredo_srt::{ConnectionOutput, GroupType, SrtConnection, Timestamp};
use srt_transport::{
    CallerConfig, GroupCallerLeg, GroupConfig, GroupConn, GroupDriveReport, OutputDrainBudget,
    RuntimeFlavor,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

struct CountingAllocator;

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

// SAFETY: delegates to `System` for all allocation; only adds an atomic counter.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: layout is caller-guaranteed valid; forwarded to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: ptr/layout are caller-guaranteed valid; forwarded to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// A minimal SRT listener peer for one bonded leg -- binds, decodes
/// whatever the group leg sends, and answers its own protocol output back
/// to whichever address last reached it. Mirrors
/// `group_conn::group_conn_tests::Peer` (private to that module), rebuilt
/// here from only public API since this is an external integration test.
struct Peer {
    socket: std::net::UdpSocket,
    connection: SrtConnection,
    caller: Option<std::net::SocketAddr>,
}

impl Peer {
    fn new() -> Self {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
        socket.set_nonblocking(true).expect("peer is nonblocking");
        Self {
            socket,
            connection: SrtConnection::new_listener(shiguredo_srt::ConnectionOptions {
                tsbpd_delay: 0,
                ..Default::default()
            }),
            caller: None,
        }
    }

    fn drive(&mut self, now: Timestamp) {
        let mut buffer = [0_u8; 4096];
        loop {
            match self.socket.recv_from(&mut buffer) {
                Ok((size, caller)) => {
                    self.caller = Some(caller);
                    self.connection
                        .feed_recv_buf(&buffer[..size], now)
                        .expect("group packet decodes");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("peer receive failed: {error}"),
            }
        }
        let Some(caller) = self.caller else {
            return;
        };
        while let Some(output) = self.connection.poll_output() {
            if let ConnectionOutput::SendPacket(packet) = output {
                self.socket
                    .send_to(&packet, caller)
                    .expect("peer sends protocol response");
            }
        }
    }
}

fn connect_two_leg_group() -> (GroupConn, Peer, Peer) {
    let mut first_peer = Peer::new();
    let mut second_peer = Peer::new();
    let group = GroupConfig::new(45, GroupType::Broadcast);
    let mut conn = GroupConn::caller(
        group,
        [
            GroupCallerLeg::new(
                1,
                10,
                CallerConfig::builder(first_peer.socket.local_addr().expect("first address"))
                    .build()
                    .expect("first caller config"),
            ),
            GroupCallerLeg::new(
                2,
                20,
                CallerConfig::builder(second_peer.socket.local_addr().expect("second address"))
                    .build()
                    .expect("second caller config"),
            ),
        ],
        RuntimeFlavor::Mio,
        Timestamp::from_micros(0),
    )
    .expect("bonded caller builds");

    let mut report = GroupDriveReport::default();
    for round in 0..20 {
        let now = Timestamp::from_micros(round * 10_000);
        conn.drive(now, OutputDrainBudget::default(), &mut report)
            .expect("group sends protocol output");
        first_peer.drive(now);
        second_peer.drive(now);
        conn.drive(now, OutputDrainBudget::default(), &mut report)
            .expect("group receives protocol output");
        if conn
            .group()
            .members()
            .iter()
            .all(|member| member.connection().state() == shiguredo_srt::ConnectionState::Connected)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(
        conn.group()
            .members()
            .iter()
            .all(|member| member.connection().state() == shiguredo_srt::ConnectionState::Connected),
        "group did not connect"
    );
    (conn, first_peer, second_peer)
}

/// Once connected and idle (no new data, no due timers), repeated
/// `drive()` calls on the same reused `GroupDriveReport` must not keep
/// allocating -- the only per-call allocation the old, pre-fix code had
/// was the now-eliminated fresh `Vec::with_capacity(self.legs.len())` for
/// `report.legs`. `report.legs.clear()` never allocates on an
/// already-sized `Vec`, so the true regression signal is a per-call
/// allocation count that stays at (or returns to) zero, not a lucky
/// pointer match.
#[test]
fn idle_drive_calls_do_not_keep_allocating() {
    let (mut conn, _first_peer, _second_peer) = connect_two_leg_group();
    let mut report = GroupDriveReport::default();

    // Warm up: let the connect handshake's own bookkeeping (which does
    // allocate) settle, and let `report.legs` grow to its steady two-leg
    // capacity once, outside the measured window.
    for round in 0..5 {
        let now = Timestamp::from_micros(1_000_000 + round * 10_000);
        conn.drive(now, OutputDrainBudget::default(), &mut report)
            .expect("warmup drive");
    }

    // A fixed `now` for every idle call from here on, deliberately not
    // advancing time, so no periodic timer (ACK, keepalive) can cross its
    // own deadline and fire mid-measurement -- isolating exactly "no new
    // data, no timer due" instead of also measuring real (and expected)
    // periodic-timer allocation this fix never touched.
    let idle_now = Timestamp::from_micros(1_050_000);

    // A first idle call still pays a real, one-time lazy-init cost
    // (measured: nonzero here even after the connect-phase warmup above,
    // flat regardless of how many further calls follow) -- pay it once,
    // outside the measured window, so the actual measurement below is
    // pure per-call cost.
    conn.drive(idle_now, OutputDrainBudget::default(), &mut report)
        .expect("settle drive");

    let before = ALLOC_COUNT.load(Ordering::Relaxed);
    const IDLE_CALLS: u64 = 50;
    for _ in 0..IDLE_CALLS {
        conn.drive(idle_now, OutputDrainBudget::default(), &mut report)
            .expect("idle drive");
    }
    let after = ALLOC_COUNT.load(Ordering::Relaxed);
    let total = after - before;

    assert_eq!(
        total, 0,
        "{IDLE_CALLS} idle drive() calls allocated {total} times combined -- \
         a regression back to a fresh Vec::with_capacity per call would show \
         up here as at least {IDLE_CALLS} (one per call)"
    );
}
