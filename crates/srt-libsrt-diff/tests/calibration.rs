//! Hand-written scenarios with known libsrt behavior. Each pins both the
//! agreement and the expected outcome, so a harness that silently compared
//! two wrong answers would still fail here.

use srt_libsrt_diff::model::SEQUENCE_MASK;
use srt_libsrt_diff::{
    Action, Admission, Packet, Profile, SeqRange, SrtRsReceiver, Trace, libsrt_receiver,
    oracle_available, run, run_fresh,
};

const WINDOW: u32 = 64;

fn agree(test: &str, profile: Profile, actions: &[Action]) -> Option<Trace> {
    if !oracle_available(test) {
        return None;
    }
    match run_fresh(profile, actions).expect("oracle available") {
        Ok(trace) => Some(trace),
        Err(divergence) => panic!("{test}: {divergence}"),
    }
}

fn delivered_seqs(trace: &Trace) -> Vec<u32> {
    trace.delivered.iter().map(|message| message.seq).collect()
}

fn at(profile: Profile, from: u64, deadline: u64) -> Action {
    let _ = profile;
    Action::Advance(deadline - from)
}

/// libsrt and srt-rs agree that a due later packet with an earlier
/// timestamp waits behind the future sequence head (buffer_rcv.cpp:708-725).
#[test]
fn decreasing_timestamp_head_blocks_later_packets() {
    let profile = Profile::live(1000, WINDOW);
    let head = profile.deadline(50_000);
    let later = profile.deadline(10_000);
    let actions = [
        Action::Insert(Packet::solo(1000, 50_000)),
        Action::Insert(Packet::solo(1001, 10_000)),
        at(profile, profile.time_base_us, later),
        Action::Read,
        Action::Service,
        Action::Read,
        Action::Advance(head - later - 1),
        Action::Read,
        Action::Advance(1),
        Action::Read,
        Action::Read,
    ];
    let Some(trace) = agree(
        "decreasing_timestamp_head_blocks_later_packets",
        profile,
        &actions,
    ) else {
        return;
    };
    assert_eq!(delivered_seqs(&trace), [1000, 1001]);
    assert!(!trace.snapshots[2].ready, "the head is not due yet");
    assert!(trace.snapshots[8].ready, "the head is due at its deadline");
}

/// A due packet beyond a loss cannot make that loss expire while an unread
/// packet still heads the buffer (core.cpp:5693-5703, buffer_rcv.cpp:677-692).
/// This is the first defect found by the randomized differential harness.
#[test]
fn unread_head_keeps_a_later_loss_recoverable() {
    let profile = Profile::live(1000, WINDOW);
    let actions = [
        Action::Insert(Packet::solo(1000, 50_000)),
        Action::Insert(Packet::solo(1002, 10_000)),
        Action::Advance(150_000),
        Action::Service,
        Action::Insert(Packet::solo(1001, 30_000)),
        Action::Advance(20_000),
        Action::Read,
        Action::Read,
        Action::Read,
    ];
    let Some(trace) = agree(
        "unread_head_keeps_a_later_loss_recoverable",
        profile,
        &actions,
    ) else {
        return;
    };
    assert_eq!(trace.snapshots[3].ack_seq, 1001);
    assert!(trace.drops.is_empty());
    assert_eq!(delivered_seqs(&trace), [1000, 1001, 1002]);
}

/// A missing head is given up once the first received packet after it is
/// due (core.cpp:5693-5703), and only then.
#[test]
fn missing_head_is_dropped_when_the_next_packet_is_due() {
    let profile = Profile::live(500, WINDOW);
    let due = profile.deadline(20_000);
    let actions = [
        Action::Insert(Packet::solo(502, 20_000)),
        Action::Insert(Packet::solo(503, 21_000)),
        at(profile, profile.time_base_us, due - 1),
        Action::Service,
        Action::Read,
        Action::Advance(1),
        Action::Read,
        Action::Service,
        Action::Read,
        Action::Advance(1000),
        Action::Read,
    ];
    let Some(trace) = agree(
        "missing_head_is_dropped_when_the_next_packet_is_due",
        profile,
        &actions,
    ) else {
        return;
    };
    assert_eq!(
        trace.drops,
        [vec![SeqRange {
            first: 500,
            last: 501
        }]]
    );
    assert_eq!(delivered_seqs(&trace), [502, 503]);
    let before = &trace.snapshots[3];
    assert_eq!(before.ack_seq, 500);
    assert_eq!(
        before.losses,
        [SeqRange {
            first: 500,
            last: 501
        }]
    );
    let after = &trace.snapshots[7];
    assert!(after.losses.is_empty());
    assert_eq!(after.ack_seq, 504);
}

/// A retransmission that fills the head before its successor is due is
/// delivered; one arriving after the drop is refused as old.
#[test]
fn recovered_and_belated_head() {
    let profile = Profile::live(7, WINDOW);
    let mut retransmitted = Packet::solo(7, 5_000);
    retransmitted.retransmitted = true;
    let actions = [
        Action::Insert(Packet::solo(8, 6_000)),
        Action::Insert(Packet::solo(10, 8_000)),
        Action::Insert(retransmitted.clone()),
        at(profile, profile.time_base_us, profile.deadline(8_000)),
        Action::Read,
        Action::Read,
        Action::Read,
        Action::Service,
        Action::Read,
        Action::Insert(Packet {
            seq: 9,
            ..retransmitted
        }),
        Action::Read,
    ];
    let Some(trace) = agree("recovered_and_belated_head", profile, &actions) else {
        return;
    };
    assert_eq!(delivered_seqs(&trace), [7, 8, 10]);
    assert_eq!(trace.drops, [vec![SeqRange { first: 9, last: 9 }]]);
    assert_eq!(
        trace.admissions,
        [
            Admission::Accepted,
            Admission::Accepted,
            Admission::Accepted,
            Admission::Old
        ]
    );
}

/// Duplicates, including one with a different payload, never replace the
/// first accepted packet (buffer_rcv.cpp:179-193), before or after delivery.
#[test]
fn duplicates_keep_the_first_packet() {
    let profile = Profile::live(42, WINDOW);
    let original = Packet::solo(43, 1_000);
    let mut conflicting = original.clone();
    conflicting.payload = vec![0xEE; 7];
    conflicting.retransmitted = true;
    let actions = [
        Action::Insert(original.clone()),
        Action::Insert(original.clone()),
        Action::Insert(conflicting.clone()),
        Action::Insert(Packet::solo(42, 900)),
        Action::Insert(Packet::solo(42, 900)),
        at(profile, profile.time_base_us, profile.deadline(1_000)),
        Action::Read,
        Action::Read,
        Action::Insert(conflicting),
        Action::Insert(original),
        Action::Read,
    ];
    let Some(trace) = agree("duplicates_keep_the_first_packet", profile, &actions) else {
        return;
    };
    assert_eq!(delivered_seqs(&trace), [42, 43]);
    assert_eq!(trace.delivered[1].payload, 43u32.to_be_bytes());
    assert_eq!(
        trace.admissions,
        [
            Admission::Accepted,
            Admission::Old,
            Admission::Old,
            Admission::Accepted,
            Admission::Old,
            Admission::Old,
            Admission::Old
        ]
    );
}

/// Loss detection, recovery, TLPKTDROP and delivery across the 31-bit
/// sequence wrap.
#[test]
fn sequence_wrap() {
    let first = SEQUENCE_MASK - 2;
    let profile = Profile::live(first, WINDOW);
    let actions = [
        Action::Insert(Packet::solo(first, 1_000)),
        Action::Insert(Packet::solo(SEQUENCE_MASK, 2_000)),
        Action::Insert(Packet::solo(1, 3_000)),
        Action::Insert(Packet::solo(3, 4_000)),
        Action::Insert(Packet::solo(first + 1, 1_500)),
        at(profile, profile.time_base_us, profile.deadline(4_000)),
        Action::Read,
        Action::Read,
        Action::Read,
        Action::Read,
        Action::Service,
        Action::Read,
        Action::Read,
        Action::Service,
        Action::Read,
    ];
    let Some(trace) = agree("sequence_wrap", profile, &actions) else {
        return;
    };
    assert_eq!(
        delivered_seqs(&trace),
        [first, first + 1, SEQUENCE_MASK, 1, 3]
    );
    assert_eq!(
        trace.drops,
        [
            vec![SeqRange { first: 0, last: 0 }],
            vec![SeqRange { first: 2, last: 2 }]
        ]
    );
    assert_eq!(trace.snapshots.last().map(|s| s.ack_seq), Some(4));
}

/// A packet beyond the window is refused by both; on an empty live buffer
/// libsrt would also close the connection (core.cpp:10781-10805).
#[test]
fn window_edge() {
    let profile = Profile::live(0, 8);
    let actions = [
        Action::Insert(Packet::solo(7, 1_000)),
        Action::Insert(Packet::solo(8, 1_000)),
        Action::Insert(Packet::solo(0, 1_000)),
    ];
    let Some(trace) = agree("window_edge", profile, &actions) else {
        return;
    };
    assert_eq!(
        trace.admissions,
        [Admission::Accepted, Admission::NoRoom, Admission::Accepted]
    );
}

/// Harness self-test: without the mirrored `CUDT::tsbpd` TLPKTDROP step
/// (core.cpp:5693-5703) libsrt's buffer alone never gives up a missing head,
/// so the oracle stalls and disagrees with srt-rs. This proves the
/// orchestration is load-bearing rather than decorative.
#[test]
fn omitting_the_tlpktdrop_orchestration_breaks_agreement() {
    let test = "omitting_the_tlpktdrop_orchestration_breaks_agreement";
    if !oracle_available(test) {
        return;
    }
    let profile = Profile::live(500, WINDOW);
    let actions = [
        Action::Insert(Packet::solo(501, 20_000)),
        at(profile, profile.time_base_us, profile.deadline(20_000)),
        Action::Service,
        Action::Read,
    ];
    let mut srt_rs = SrtRsReceiver::new(profile);
    let mut without_drop = libsrt_receiver(Profile {
        tlpktdrop: false,
        ..profile
    })
    .expect("oracle available");
    let divergence = run(profile, &actions, without_drop.as_mut(), &mut srt_rs)
        .expect_err("libsrt without its TLPKTDROP step must disagree");
    assert_eq!(divergence.step, 2, "{divergence}");
    assert_eq!(divergence.observable, "step outcome", "{divergence}");

    let mut srt_rs = SrtRsReceiver::new(profile);
    let mut with_drop = libsrt_receiver(profile).expect("oracle available");
    let trace = run(profile, &actions, with_drop.as_mut(), &mut srt_rs)
        .unwrap_or_else(|divergence| panic!("{test}: {divergence}"));
    assert_eq!(delivered_seqs(&trace), [501]);
}

/// Timestamp wrap is independent of the 31-bit DATA sequence wrap. libsrt
/// arms wrap correction when reading the pre-wrap head, then commits the
/// next epoch when reading a timestamp in [30 s, 60 s] (tsbpd_time.cpp:248-274).
#[test]
fn timestamps_cross_the_32_bit_wrap_without_early_delivery() {
    let profile = Profile::live(SEQUENCE_MASK - 1, WINDOW);
    let high = u32::MAX - 10_000_000;
    let first_due = profile.deadline(high);
    let actions = [
        Action::Insert(Packet::solo(SEQUENCE_MASK - 1, high)),
        Action::Insert(Packet::solo(SEQUENCE_MASK, 1_000_000)),
        Action::Insert(Packet::solo(0, 40_000_000)),
        Action::Advance(first_due - profile.time_base_us - 1),
        Action::Read,
        Action::Advance(1),
        Action::Read,
        Action::Read,
        Action::Advance(11_000_001),
        Action::Read,
        Action::Advance(39_000_000),
        Action::Read,
    ];
    let Some(trace) = agree(
        "timestamps_cross_the_32_bit_wrap_without_early_delivery",
        profile,
        &actions,
    ) else {
        return;
    };
    assert_eq!(
        delivered_seqs(&trace),
        [SEQUENCE_MASK - 1, SEQUENCE_MASK, 0]
    );
    assert_eq!(trace.delivered[1].play_time_us, first_due + 11_000_001);
    assert_eq!(trace.delivered[2].play_time_us, first_due + 50_000_001);
}

#[test]
fn an_empty_window_rejection_without_tlpktdrop_keeps_the_receiver_open() {
    let profile = Profile {
        tlpktdrop: false,
        ..Profile::live(100, WINDOW)
    };
    let actions = [
        Action::Insert(Packet::solo(100 + WINDOW, 1_000)),
        Action::Insert(Packet::solo(100, 1_000)),
        at(profile, profile.time_base_us, profile.deadline(1_000)),
        Action::Read,
    ];
    let Some(trace) = agree(
        "an_empty_window_rejection_without_tlpktdrop_keeps_the_receiver_open",
        profile,
        &actions,
    ) else {
        return;
    };
    assert_eq!(trace.admissions, [Admission::NoRoom, Admission::Accepted]);
    assert_eq!(delivered_seqs(&trace), [100]);
}
