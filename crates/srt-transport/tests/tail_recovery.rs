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
use srt_proto::{ConnectionOptions, ConnectionOutput, ConnectionState, SrtConnection, Timestamp};
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
