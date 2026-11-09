//! The libsrt 1.5.7 side, through the C ABI of `cpp/receiver_shim.h`.

use std::ptr::{self, NonNull};

use crate::model::{Admission, Delivered, Packet, Profile, Receiver, SeqRange, Snapshot};

const OK: i32 = 0;
const E_CAPACITY: i32 = -3;
const INSERT_ACCEPTED: i32 = 0;
const INSERT_DUPLICATE: i32 = 1;
const INSERT_BELATED: i32 = 2;
const INSERT_NO_ROOM: i32 = 3;
const INSERT_DISCREPANCY: i32 = 4;
/// PB bits of a SOLO packet (`PB_SOLO`, packet.h).
const BOUNDARY_SOLO: u8 = 3;

#[repr(C)]
struct RawRx {
    _opaque: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawRange {
    first: u32,
    last: u32,
}

#[repr(C)]
struct RawPacket {
    seq: u32,
    msgno: u32,
    timestamp: u32,
    boundary: u8,
    inorder: u8,
    retransmitted: u8,
    reserved: u8,
}

#[repr(C)]
struct RawConfig {
    capacity: u32,
    initial_seq: u32,
    payload_limit: u32,
    latency_ms: u16,
    tlpktdrop: u8,
    reserved: u8,
    time_base_us: i64,
}

#[repr(C)]
#[derive(Default)]
struct RawDrop {
    missing: u32,
    discarded: u32,
    changed: u8,
    reserved: [u8; 3],
    range: RawRange,
}

#[repr(C)]
#[derive(Default)]
struct RawDelivered {
    seq: u32,
    msgno: u32,
    play_time_us: i64,
    len: usize,
}

unsafe extern "C" {
    fn srt_diff_create(config: *const RawConfig, out: *mut *mut RawRx) -> i32;
    fn srt_diff_destroy(rx: *mut RawRx);
    fn srt_diff_insert(
        rx: *mut RawRx,
        packet: *const RawPacket,
        payload: *const u8,
        len: usize,
        outcome: *mut i32,
    ) -> i32;
    fn srt_diff_ready(rx: *mut RawRx, now_us: i64, ready: *mut u8) -> i32;
    fn srt_diff_read(
        rx: *mut RawRx,
        now_us: i64,
        buffer: *mut u8,
        capacity: usize,
        delivered: *mut RawDelivered,
        present: *mut u8,
    ) -> i32;
    fn srt_diff_service(rx: *mut RawRx, now_us: i64, drop: *mut RawDrop) -> i32;
    fn srt_diff_ack_seq(rx: *mut RawRx, ack_seq: *mut u32) -> i32;
    fn srt_diff_losses(
        rx: *mut RawRx,
        ranges: *mut RawRange,
        capacity: usize,
        needed: *mut usize,
    ) -> i32;
}

fn check(status: i32, call: &str) {
    assert_eq!(status, OK, "libsrt oracle: {call} failed with {status}");
}

fn micros(us: u64) -> i64 {
    i64::try_from(us).expect("synthetic time fits i64 microseconds")
}

/// libsrt's `CRcvBuffer`, `CRcvLossList` and the mirrored `CUDT` glue.
///
/// Owns a C++ object that is neither `Send` nor `Sync` (`NonNull` keeps this
/// type the same).
pub struct LibsrtReceiver {
    rx: NonNull<RawRx>,
    payload: Vec<u8>,
    closed: bool,
}

impl LibsrtReceiver {
    /// A libsrt receiver configured from `profile`.
    ///
    /// # Panics
    /// If the shim rejects the configuration.
    #[must_use]
    pub fn new(profile: Profile) -> Self {
        let config = RawConfig {
            capacity: profile.capacity,
            initial_seq: profile.initial_seq,
            payload_limit: profile.payload_limit,
            latency_ms: profile.latency_ms,
            tlpktdrop: u8::from(profile.tlpktdrop),
            reserved: 0,
            time_base_us: micros(profile.time_base_us),
        };
        let mut rx = ptr::null_mut();
        // SAFETY: `config` and `rx` are valid for the duration of the call;
        // the shim writes `rx` only on success.
        check(unsafe { srt_diff_create(&config, &mut rx) }, "create");
        Self {
            rx: NonNull::new(rx).expect("srt_diff_create returned a handle"),
            payload: vec![0; profile.payload_limit as usize],
            closed: false,
        }
    }

    fn losses(&self) -> Vec<SeqRange> {
        let mut ranges = vec![RawRange::default(); 16];
        loop {
            let mut needed = 0;
            // SAFETY: `ranges` has `ranges.len()` writable elements and the
            // handle is live; the shim never writes past `capacity`.
            let status = unsafe {
                srt_diff_losses(
                    self.rx.as_ptr(),
                    ranges.as_mut_ptr(),
                    ranges.len(),
                    &mut needed,
                )
            };
            if status == E_CAPACITY {
                ranges.resize(needed, RawRange::default());
                continue;
            }
            check(status, "losses");
            ranges.truncate(needed);
            return ranges
                .iter()
                .map(|range| SeqRange {
                    first: range.first,
                    last: range.last,
                })
                .collect();
        }
    }
}

impl Drop for LibsrtReceiver {
    fn drop(&mut self) {
        // SAFETY: the handle came from srt_diff_create and is destroyed once.
        unsafe { srt_diff_destroy(self.rx.as_ptr()) }
    }
}

impl Receiver for LibsrtReceiver {
    fn insert(&mut self, packet: &Packet, _now_us: u64) -> Admission {
        let raw = RawPacket {
            seq: packet.seq,
            msgno: packet.msgno,
            timestamp: packet.timestamp,
            boundary: BOUNDARY_SOLO,
            inorder: u8::from(packet.order_flag),
            retransmitted: u8::from(packet.retransmitted),
            reserved: 0,
        };
        let mut outcome = -1;
        // SAFETY: `raw` and the payload slice are valid for the call and
        // the payload length is the slice length.
        let status = unsafe {
            srt_diff_insert(
                self.rx.as_ptr(),
                &raw,
                packet.payload.as_ptr(),
                packet.payload.len(),
                &mut outcome,
            )
        };
        check(status, "insert");
        match outcome {
            INSERT_ACCEPTED => Admission::Accepted,
            INSERT_DUPLICATE | INSERT_BELATED => Admission::Old,
            INSERT_NO_ROOM => Admission::NoRoom,
            INSERT_DISCREPANCY => {
                self.closed = true;
                Admission::NoRoom
            }
            other => panic!("libsrt oracle: unknown insert outcome {other}"),
        }
    }

    fn read(&mut self, now_us: u64) -> Option<Delivered> {
        let mut delivered = RawDelivered::default();
        let mut present = 0;
        // SAFETY: `payload` has `payload.len()` writable bytes, at least
        // the configured payload limit; the out-parameters are valid.
        let status = unsafe {
            srt_diff_read(
                self.rx.as_ptr(),
                micros(now_us),
                self.payload.as_mut_ptr(),
                self.payload.len(),
                &mut delivered,
                &mut present,
            )
        };
        check(status, "read");
        (present != 0).then(|| Delivered {
            seq: delivered.seq,
            msgno: delivered.msgno,
            play_time_us: u64::try_from(delivered.play_time_us).expect("play time after epoch"),
            payload: self.payload[..delivered.len].to_vec(),
        })
    }

    fn service(&mut self, now_us: u64) -> Vec<SeqRange> {
        let mut drop = RawDrop::default();
        // SAFETY: `drop` is a valid out-parameter and the handle is live.
        check(
            unsafe { srt_diff_service(self.rx.as_ptr(), micros(now_us), &mut drop) },
            "service",
        );
        // Positions holding packets are never inside a head gap in this
        // profile: TSBPD reads only at the head, so nothing is read out of
        // order (buffer_rcv.cpp:195-202, 393-473).
        assert_eq!(drop.discarded, 0, "libsrt discarded buffered packets");
        if drop.changed == 0 {
            return Vec::new();
        }
        vec![SeqRange {
            first: drop.range.first,
            last: drop.range.last,
        }]
    }

    fn snapshot(&self, now_us: u64) -> Snapshot {
        let mut ready = 0;
        let mut ack_seq = 0;
        // SAFETY: valid out-parameters, live handle.
        check(
            unsafe { srt_diff_ready(self.rx.as_ptr(), micros(now_us), &mut ready) },
            "ready",
        );
        // SAFETY: valid out-parameter, live handle.
        check(
            unsafe { srt_diff_ack_seq(self.rx.as_ptr(), &mut ack_seq) },
            "ack",
        );
        Snapshot {
            ready: ready != 0,
            ack_seq,
            losses: self.losses(),
        }
    }

    fn closed(&self) -> bool {
        self.closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RawConfig {
        RawConfig {
            capacity: 64,
            initial_seq: 0,
            payload_limit: 1316,
            latency_ms: 120,
            tlpktdrop: 1,
            reserved: 0,
            time_base_us: 10_000_000,
        }
    }

    #[test]
    fn native_construction_rejects_overflowing_pool_sizes_and_clock_values() {
        for payload_limit in [1457, 33_554_432, u32::MAX] {
            let mut raw = config();
            raw.payload_limit = payload_limit;
            let mut handle = ptr::null_mut();
            // SAFETY: valid configuration and out-pointer, rejected before allocation.
            assert_eq!(unsafe { srt_diff_create(&raw, &mut handle) }, -1);
            assert!(handle.is_null());
        }
        for time_base_us in [10_000_000_000_000_000, i64::MAX] {
            let mut raw = config();
            raw.time_base_us = time_base_us;
            let mut handle = ptr::null_mut();
            // SAFETY: valid configuration and out-pointer, rejected before clock conversion.
            assert_eq!(unsafe { srt_diff_create(&raw, &mut handle) }, -1);
            assert!(handle.is_null());
        }
    }

    #[test]
    fn native_observation_rejects_overflowing_clock_values() {
        let receiver = LibsrtReceiver::new(Profile::live(0, 64));
        let mut ready = 0;
        let mut drop = RawDrop::default();
        // SAFETY: live handle and valid out-parameters; invalid time is rejected.
        unsafe {
            assert_eq!(
                srt_diff_ready(receiver.rx.as_ptr(), i64::MAX, &mut ready),
                -1
            );
            assert_eq!(
                srt_diff_service(receiver.rx.as_ptr(), i64::MAX, &mut drop),
                -1
            );
        }
    }
}
