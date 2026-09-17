//! End-to-end recovery of a lost flight tail, through the transport's own
//! timer store.
//!
//! # Why this test is not a duplicate of the protocol's unit test
//!
//! The unit tests in `srt-protocol` drive the protocol's `SetTimer`/`ClearTimer`
//! outputs through a minimal store of their own. That proves the protocol's
//! *decisions*, but the property that actually matters for production is
//! narrower and lives one layer out:
//!
//! ```text
//! DATA is submitted  ->  SetTimer(SenderRto) is queued  ->  the transport
//! applies it to a real store  ->  the deadline elapses  ->  the store fires
//! the timer  ->  the tail probe goes out
//! ```
//!
//! An earlier version of this fix queued the right recovery *action* but had no
//! reachable *trigger*: its timer was only ever armed by the code that drained
//! an already-filled retransmission queue, so a lost tail -- which fills no
//! queue -- never reached it. Every step above has to be exercised for the
//! property to hold, so these tests use `ManualTimerStore` (the same type every
//! native runtime's connection uses) and never call
//! `SrtConnection::handle_timer` directly.
//!
//! A lost *suffix* of a flight is also a loss the receiver cannot name: no later
//! sequence number arrives to expose the gap, so no NAK is generated and the
//! receiver's own accounting stays at zero loss while the payload is simply
//! absent. The sender's timeout is the only party left that can notice, which is
//! why the assertions below check both endpoints.

use srt_proto::wire::{DataPacket, SrtPacket};
use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, OutputMeta, SrtConnection, TimerId,
    Timestamp,
};
use srt_transport::advanced::driver::ManualTimerStore;

const FLIGHT: usize = 4;
const TICK_MICROS: u64 = 10_000;

/// One endpoint: a connection plus the timer store driving its timers.
struct Endpoint {
    conn: SrtConnection,
    timers: ManualTimerStore,
    /// DATA datagrams this endpoint has submitted, in order.
    first_transmissions: usize,
}

impl Endpoint {
    fn new(conn: SrtConnection) -> Self {
        Self {
            conn,
            timers: ManualTimerStore::new(),
            first_transmissions: 0,
        }
    }

    fn state(&self) -> ConnectionState {
        self.conn.state()
    }
}

/// Move everything `from` produced: timer actions into its own store, DATA
/// datagrams onto the wire (withholding every first transmission from
/// `drop_data_from` onward, if set), and everything else to the peer.
///
/// Retransmissions are never withheld: these tests model a loss that occurred
/// once, not a link that stays down.
fn move_outputs(
    from: &mut Endpoint,
    to: &mut SrtConnection,
    now: Timestamp,
    drop_data_from: Option<usize>,
) {
    while let Some(output) = from
        .conn
        .poll_output()
        .expect("exact-size output materializes")
    {
        from.timers.apply_output(&output, now);
        let ConnectionOutput::SendPacket(bytes) = output else {
            continue;
        };
        if let Some(packet) = data_packet(&bytes)
            && !packet.retransmitted
        {
            let index = from.first_transmissions;
            from.first_transmissions += 1;
            if drop_data_from.is_some_and(|from| index >= from) {
                continue; // lost on the wire, never delivered
            }
        }
        to.feed_recv_buf(&bytes, now)
            .expect("peer accepts the packet");
    }
}

/// Drain whatever the handshake's final leg left queued (typically
/// `ClearTimer { id: Handshake }`, queued as a side effect of processing the
/// peer's last handshake packet during `connected_pair`'s own draining loop,
/// one tick after the endpoint it belongs to was last drained). Tests below
/// that inspect the *first* output after `connected_pair()` need a clean
/// queue, not a leftover handshake artifact unrelated to the property under
/// test.
fn drain_residual(conn: &mut SrtConnection) {
    while conn
        .poll_output()
        .expect("exact-size output materializes")
        .is_some()
    {}
}

fn data_packet(bytes: &[u8]) -> Option<DataPacket> {
    match SrtPacket::decode(bytes) {
        Ok(SrtPacket::Data(packet)) => Some(packet),
        _ => None,
    }
}

fn connected_pair() -> (Endpoint, Endpoint) {
    let mut caller = Endpoint::new(SrtConnection::new_caller(ConnectionOptions {
        socket_id: 1001,
        tsbpd_delay: 0,
        ..ConnectionOptions::default()
    }));
    let mut listener = Endpoint::new(SrtConnection::new_listener(ConnectionOptions {
        socket_id: 2001,
        tsbpd_delay: 0,
        ..ConnectionOptions::default()
    }));
    caller
        .conn
        .connect(Timestamp::from_micros(0))
        .expect("caller starts");

    let mut now = Timestamp::from_micros(0);
    for _ in 0..40 {
        now = Timestamp::from_micros(now.as_micros() + TICK_MICROS);
        // Timers first: whatever the previous tick armed and time has now
        // expired fires here, exactly as a runtime's event loop would.
        caller.timers.fire_expired(now, &mut caller.conn);
        listener.timers.fire_expired(now, &mut listener.conn);
        move_outputs(&mut caller, &mut listener.conn, now, None);
        move_outputs(&mut listener, &mut caller.conn, now, None);
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            break;
        }
    }
    assert_eq!(
        caller.state(),
        ConnectionState::Connected,
        "handshake must connect"
    );
    assert_eq!(
        listener.state(),
        ConnectionState::Connected,
        "handshake must connect"
    );
    (caller, listener)
}

/// Outcome of one scripted flight.
struct Outcome {
    delivered: u64,
    receiver_reported_loss: u64,
    retransmits: u64,
}

/// Send `FLIGHT` payloads, withholding every first transmission from
/// `drop_data_from` onward (if set), and run the pair for `ticks` real timer
/// ticks.
fn run_flight(drop_data_from: Option<usize>, ticks: usize) -> Outcome {
    let (mut caller, mut listener) = connected_pair();
    let mut now = Timestamp::from_micros(1_000_000);
    for i in 0..FLIGHT {
        caller
            .conn
            .send(format!("payload {i}").as_bytes(), now)
            .expect("send admits the payload");
    }

    for _ in 0..ticks {
        now = Timestamp::from_micros(now.as_micros() + TICK_MICROS);
        caller.timers.fire_expired(now, &mut caller.conn);
        listener.timers.fire_expired(now, &mut listener.conn);
        move_outputs(&mut caller, &mut listener.conn, now, drop_data_from);
        move_outputs(&mut listener, &mut caller.conn, now, None);
        // Events coalesce; delivery is read from the receiver's own accounting
        // below, never from event count.
        while listener.conn.poll_event().is_some() {}
        while caller.conn.poll_event().is_some() {}
    }

    Outcome {
        delivered: listener
            .conn
            .receiver_stats()
            .expect("connected receiver")
            .total_received,
        receiver_reported_loss: listener
            .conn
            .receiver_stats()
            .expect("connected receiver")
            .total_lost,
        retransmits: caller
            .conn
            .sender_stats()
            .expect("connected sender")
            .total_retransmits,
    }
}

/// Control: with nothing dropped, every payload arrives and nothing is
/// retransmitted. Without this, the tail test could pass (or fail) for a harness
/// reason instead of the property under test.
#[test]
fn an_intact_flight_needs_no_recovery() {
    let outcome = run_flight(None, 400);
    assert_eq!(outcome.delivered, FLIGHT as u64);
    assert_eq!(outcome.retransmits, 0);
    assert_eq!(outcome.receiver_reported_loss, 0);
}

/// The property: a lost final DATA datagram is recovered by the sender's own
/// timeout, armed and fired by the real timer store.
#[test]
fn a_lost_flight_tail_is_recovered_by_the_transport_timer_store() {
    let outcome = run_flight(Some(FLIGHT - 1), 400);
    assert_eq!(
        outcome.delivered, FLIGHT as u64,
        "a lost final DATA datagram must be recovered by the sender: the receiver \
         cannot name a gap that no later sequence number exposes, so nothing else \
         will ask for it"
    );
    assert!(
        outcome.retransmits >= 1,
        "recovery must come from the sender's timeout, not from the receiver"
    );
    assert_eq!(
        outcome.receiver_reported_loss, 0,
        "the receiver never had evidence of this loss: that is exactly why the \
         sender's own timeout has to cover it"
    );
}

/// The case in which only the submission trigger can help: the whole flight is
/// lost, so the receiver acknowledges nothing and the ACK-progress restart --
/// the other event that arms the timeout -- never fires.
#[test]
fn a_flight_lost_in_full_is_recovered_by_the_submission_trigger() {
    let outcome = run_flight(Some(0), 400);
    assert_eq!(
        outcome.delivered, FLIGHT as u64,
        "with no feedback at all, the timeout armed at submission is the only \
         trigger left"
    );
    assert!(outcome.retransmits >= FLIGHT as u64);
}

/// A lost flight tail of three packets is recovered by one probe plus the NAK
/// recovery that the probe's arrival enables -- not by replaying the
/// unacknowledged flight.
#[test]
fn a_lost_three_packet_tail_is_recovered_by_one_probe() {
    let outcome = run_flight(Some(FLIGHT - 3), 400);
    assert_eq!(outcome.delivered, FLIGHT as u64);
    assert!(
        outcome.retransmits >= 3,
        "the probe repairs one packet and exposes the other two to NAK recovery \
         (saw {} retransmissions)",
        outcome.retransmits
    );
}

/// Regression: queuing the arm action is not the same as making it reachable.
///
/// `note_data_submitted` runs when `poll_output()` materializes a DATA
/// datagram, and used to append `SetTimer(SenderRto)` to the back of the same
/// FIFO the rest of the unsent flight already sat in. A transport that drains
/// output one item per visit and stops when it cannot make progress on the
/// next one (bounded TX capacity being the ordinary reason) would then never
/// reach the arm at all this visit: DATA2..DATAn block it, so the timer store
/// never sees `SetTimer` and DATA1's timeout never actually starts running,
/// even though the connection believes an epoch is armed.
///
/// This test never drains DATA2..DATA4 -- it proves the arm is visible with
/// them still sitting, unpolled, behind it.
#[test]
fn the_rto_arm_is_not_stranded_behind_the_rest_of_the_flight() {
    let (mut caller, _listener) = connected_pair();
    drain_residual(&mut caller.conn);
    let now = Timestamp::from_micros(1_000_000);
    for i in 0..FLIGHT {
        caller
            .conn
            .send(format!("payload {i}").as_bytes(), now)
            .expect("send admits the payload");
    }

    // Exactly one submission leaves the protocol -- everything still queued
    // behind it models a visit that ran out of TX capacity for the rest.
    let first = caller
        .conn
        .poll_output()
        .expect("exact-size output materializes")
        .expect("the first flight member is queued");
    assert!(
        matches!(first, ConnectionOutput::SendPacket(_)),
        "expected the first DATA datagram, got {first:?}"
    );

    match caller.conn.peek_output() {
        Some(OutputMeta::SetTimer {
            id: TimerId::SenderRto,
            ..
        }) => {}
        other => panic!(
            "the sender's RTO arm must be visible immediately after DATA1 leaves \
             the protocol, not stuck behind DATA2..DATA4: got {other:?}"
        ),
    }

    let arm = caller
        .conn
        .poll_output()
        .expect("exact-size output materializes")
        .expect("the arm action is queued");
    caller.timers.apply_output(&arm, now);
    assert!(
        caller.timers.next_deadline().is_some(),
        "the RTO deadline must already be running in the timer store with \
         DATA2..DATA4 still unpolled"
    );

    // The rest of the flight is exactly what was blocked -- confirm it is
    // still there, in order, behind the arm that just left.
    for i in 1..FLIGHT {
        let next = caller
            .conn
            .poll_output()
            .expect("exact-size output materializes")
            .expect("the remaining flight member is queued");
        assert!(
            matches!(next, ConnectionOutput::SendPacket(_)),
            "expected DATA{}, got {next:?}",
            i + 1
        );
    }
}

/// Regression, the other half: an ACK-progress reset must not be strandable
/// behind DATA that has not even been submitted yet.
///
/// A cumulative ACK that retires every submitted packet clears the sender's
/// timeout (nothing outstanding is left to time), but if more of the flight
/// is still queued waiting for TX capacity, the old FIFO ordering would leave
/// `ClearTimer` stuck behind it -- so an external timer store would keep the
/// previous epoch's deadline running past the point the connection itself
/// considers it retired.
#[test]
fn ack_progress_updates_the_timer_even_with_data_still_queued() {
    let (mut caller, mut listener) = connected_pair();
    drain_residual(&mut caller.conn);
    drain_residual(&mut listener.conn);
    let now = Timestamp::from_micros(1_000_000);
    for i in 0..3 {
        caller
            .conn
            .send(format!("payload {i}").as_bytes(), now)
            .expect("send admits the payload");
    }

    // Submit and deliver only the first two of three payloads; the third
    // stays queued, unpolled, at the caller for the rest of this test. The
    // submission arm's `SetTimer` interleaves with the datagrams themselves
    // (that interleaving is exactly what the previous test pins), so this
    // drains by datagram count delivered, not by call count.
    let mut delivered = 0;
    while delivered < 2 {
        let output = caller
            .conn
            .poll_output()
            .expect("exact-size output materializes")
            .expect("a flight member or timer action is queued");
        caller.timers.apply_output(&output, now);
        if let ConnectionOutput::SendPacket(bytes) = output {
            listener
                .conn
                .feed_recv_buf(&bytes, now)
                .expect("peer accepts the packet");
            delivered += 1;
        }
    }
    assert!(
        caller.timers.next_deadline().is_some(),
        "submitting the first packet must have armed the sender timeout"
    );

    // Force the listener to acknowledge what it has, then hand that ACK
    // straight to the caller -- bypassing the ack timer's own cadence is
    // fine here, since the property under test is what the caller's output
    // queue does with the reset, not how the listener schedules ACKs.
    listener
        .conn
        .handle_timer(TimerId::Ack, now)
        .expect("ack timer handling succeeds");
    let ack = listener
        .conn
        .poll_output()
        .expect("exact-size output materializes")
        .expect("the listener has an ACK to send");
    let ConnectionOutput::SendPacket(ack_bytes) = ack else {
        panic!("expected the listener's ACK, got {ack:?}");
    };
    caller
        .conn
        .feed_recv_buf(&ack_bytes, now)
        .expect("the caller accepts the ACK");

    // The third payload is still sitting in the caller's output queue,
    // unpolled, at this point -- exactly the condition that used to strand
    // the reset behind it.
    match caller.conn.peek_output() {
        Some(OutputMeta::ClearTimer {
            id: TimerId::SenderRto,
        })
        | Some(OutputMeta::SetTimer {
            id: TimerId::SenderRto,
            ..
        }) => {}
        other => panic!(
            "the ACK-progress reset must be visible immediately, not stuck behind \
             the still-queued third payload: got {other:?}"
        ),
    }

    let reset = caller
        .conn
        .poll_output()
        .expect("exact-size output materializes")
        .expect("the reset action is queued");
    caller.timers.apply_output(&reset, now);

    // And the third payload is still exactly where it was left: queued,
    // never submitted, now right behind the reset.
    let third = caller
        .conn
        .poll_output()
        .expect("exact-size output materializes")
        .expect("the third payload is still queued");
    assert!(
        matches!(third, ConnectionOutput::SendPacket(_)),
        "expected the still-queued third payload, got {third:?}"
    );
}

/// Drain only timer actions, applying each to `timers`, stopping the moment
/// the next queued output is a datagram -- modeling a transport that has run
/// out of TX capacity for datagrams. Timer actions cost no such capacity, so
/// a real bounded transport keeps draining those regardless.
fn drain_timers_only(conn: &mut SrtConnection, timers: &mut ManualTimerStore, now: Timestamp) {
    while let Some(OutputMeta::SetTimer { .. }) | Some(OutputMeta::ClearTimer { .. }) =
        conn.peek_output()
    {
        let output = conn
            .poll_output()
            .expect("exact-size output materializes")
            .expect("peeked output is still there");
        timers.apply_output(&output, now);
    }
}

/// Every retransmitted DATA sequence among a batch of drained outputs,
/// ignoring control traffic (ACK/keepalive/etc, which is not the property
/// under test here).
fn retransmitted_sequences(outputs: &[ConnectionOutput]) -> Vec<u32> {
    outputs
        .iter()
        .filter_map(|output| match output {
            ConnectionOutput::SendPacket(bytes) => match SrtPacket::decode(bytes) {
                Ok(SrtPacket::Data(packet)) if packet.retransmitted => Some(packet.sequence_number),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Regression: a blind RTO probe must not be queued a second time while an
/// earlier one from the same epoch is still sitting un-submitted behind
/// blocked TX capacity.
///
/// Before the fix, `has_retransmit()` cleared the moment `process_retransmit`
/// dequeued the probe into connection output, regardless of whether the
/// transport had actually materialized (submitted) it. A transport that keeps
/// draining timer actions (free of TX capacity) while a datagram stays
/// blocked would then see a fresh probe queued on every subsequent expiry,
/// growing output state unboundedly instead of staying bounded at exactly
/// one -- the "one probe" property `docs/differential-audit-robotweax.md`
/// documents this timer as guaranteeing.
#[test]
fn a_blocked_probe_is_never_queued_twice() {
    let (mut caller, _listener) = connected_pair();
    drain_residual(&mut caller.conn);
    let mut now = Timestamp::from_micros(1_000_000);
    for i in 0..FLIGHT {
        caller
            .conn
            .send(format!("payload {i}").as_bytes(), now)
            .expect("send admits the payload");
    }

    // Submit the whole flight -- capacity is available for this part; the
    // starvation modeled below starts only once the flight is on the wire
    // and nothing has acknowledged it yet.
    let mut armed_with = None;
    while let Some(output) = caller.conn.poll_output().unwrap() {
        caller.timers.apply_output(&output, now);
        if let ConnectionOutput::SetTimer {
            id: TimerId::SenderRto,
            duration_micros,
        } = output
        {
            armed_with = Some(duration_micros);
        }
    }
    let armed_with = armed_with.expect("submitting the flight arms the sender timeout");

    // Three consecutive (backed-off) expiries, never draining the retransmit
    // datagram itself -- only timer actions, exactly as a real transport
    // would while genuinely out of TX capacity.
    let mut deadline = now.as_micros() + armed_with;
    for _ in 0..3 {
        now = Timestamp::from_micros(deadline + 1);
        caller.timers.fire_expired(now, &mut caller.conn);
        drain_timers_only(&mut caller.conn, &mut caller.timers, now);
        deadline = caller
            .timers
            .next_deadline()
            .expect("an expiry with outstanding data must rearm")
            .as_micros();
    }

    // Capacity returns: drain everything now queued. Exactly one probe of
    // one sequence must have accumulated, no matter how many blocked
    // expiries passed in between.
    let mut outputs = Vec::new();
    while let Some(output) = caller.conn.poll_output().unwrap() {
        caller.timers.apply_output(&output, now);
        outputs.push(output);
    }
    let probed = retransmitted_sequences(&outputs);
    assert_eq!(
        probed.len(),
        1,
        "exactly one probe datagram must exist after repeated blocked expiries, got {probed:?}"
    );

    // The probe has now actually left the protocol. A further expiry must be
    // able to queue a fresh probe of its own -- the pending marker must
    // clear on real submission, not stay stuck forever.
    let next_deadline = caller
        .timers
        .next_deadline()
        .expect("still armed after the probe was submitted");
    now = Timestamp::from_micros(next_deadline.as_micros() + 1);
    caller.timers.fire_expired(now, &mut caller.conn);
    let mut outputs = Vec::new();
    while let Some(output) = caller.conn.poll_output().unwrap() {
        caller.timers.apply_output(&output, now);
        outputs.push(output);
    }
    let reprobed = retransmitted_sequences(&outputs);
    assert_eq!(
        reprobed.len(),
        1,
        "a fresh expiry after the earlier probe was actually submitted must queue \
         exactly one new probe, got {reprobed:?}"
    );
}
