//! CONCLUSION-admission challengers.
//!
//! The handshake commits exactly once per generation. A replayed CONCLUSION -
//! byte-identical, arriving after the connection is established - must not
//! re-admit it: no second `Connected` event, no second buffer initialisation,
//! and no rewrite of the sequence spaces and receiver state the first
//! admission established. The tests therefore carry live traffic before the
//! replay and assert both sides of it: the send cursor and the receiver's
//! totals. Each side is driven by explicit packet exchange and timers, never
//! by sleeping.

use srt_proto::handshake::{HandshakePacket, HandshakeType};
use srt_proto::wire::{ControlPacket, SrtPacket};
use srt_proto::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionState, ErrorKind,
    SrtConnection, Timestamp,
};

fn test_options() -> ConnectionOptions {
    ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    }
}

/// Socket identities the pair is pinned to, so a replay can be addressed
/// deliberately instead of relying on the random ones.
const CALLER_SOCKET_ID: u32 = 0x1111;
const LISTENER_SOCKET_ID: u32 = 0x2222;

/// The 31-bit DATA sequence space, which wraps rather than overflowing.
const SEQUENCE_MASK: u32 = 0x7fff_ffff;

/// Payloads each side sends before a replay, so the admitted sequence space and
/// the receiver totals are not simply the initial values.
const BEFORE_REPLAY: usize = 3;

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn packets_from(connection: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while let Some(output) = connection.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(packet) = output {
            packets.push(packet);
        }
    }
    packets
}

/// Whether the packet is a CONCLUSION handshake, in either direction: the
/// request from the caller, the response from the listener, or a retransmit of
/// either.
fn is_conclusion(packet: &[u8]) -> bool {
    let Ok(SrtPacket::Control(control)) = SrtPacket::decode(packet) else {
        return false;
    };
    matches!(
        HandshakePacket::decode(&control),
        Ok(handshake) if handshake.handshake_type == HandshakeType::Conclusion
    )
}

/// A copy of `packet` addressed to `dest_socket_id`, so a replay can reach a
/// socket that has already admitted the connection.
fn retarget(packet: &[u8], dest_socket_id: u32) -> Vec<u8> {
    let SrtPacket::Control(mut control) = SrtPacket::decode(packet).expect("control packet") else {
        panic!("expected a control packet");
    };
    control.dest_socket_id = dest_socket_id;
    encode(control)
}

/// A copy of `packet` whose handshake initial sequence is altered, which is
/// what an on-path mutation of an otherwise valid conclusion looks like. The
/// identity guard compares the CIF fields, so the patch lands inside it: the
/// version, encryption field and extension field take the first eight bytes,
/// the initial sequence the next four.
fn retampered(packet: &[u8]) -> Vec<u8> {
    let SrtPacket::Control(mut control) = SrtPacket::decode(packet).expect("control packet") else {
        panic!("expected a control packet");
    };
    control.control_info[8] ^= 0x01;
    encode(control)
}

fn encode(control: ControlPacket) -> Vec<u8> {
    let mut bytes = Vec::new();
    control
        .encode(&mut bytes)
        .expect("packet fits the configured datagram bound");
    bytes
}

/// `Connected` events observed since the last look. Draining is what makes the
/// count meaningful: a second admission would queue a second event.
fn connected_events(connection: &mut SrtConnection) -> usize {
    let mut count = 0;
    while let Some(event) = connection.poll_event() {
        if matches!(event, ConnectionEvent::Connected) {
            count += 1;
        }
    }
    count
}

fn drain_events(connection: &mut SrtConnection) {
    while connection.poll_event().is_some() {}
}

fn receiver_total(connection: &SrtConnection) -> u64 {
    connection
        .receiver_stats()
        .expect("a connected receiver reports stats")
        .total_received
}

/// Hand every packet `from` produced to `to`, as the wire would.
fn deliver(from: &mut SrtConnection, to: &mut SrtConnection, now: Timestamp) {
    for packet in packets_from(from) {
        to.feed_recv_buf(&packet, now)
            .expect("a delivered packet decodes");
    }
}

fn next_cursor(connection: &SrtConnection) -> u32 {
    connection
        .next_sequence_number()
        .expect("a connected sender holds a sequence cursor")
}

/// An established pair plus the last handshake packet each side sent: the
/// caller's CONCLUSION request and the listener's CONCLUSION response.
struct Established {
    caller: SrtConnection,
    listener: SrtConnection,
    conclusion_request: Vec<u8>,
    conclusion_response: Vec<u8>,
}

fn establish() -> Established {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: CALLER_SOCKET_ID,
        ..test_options()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: LISTENER_SOCKET_ID,
        ..test_options()
    });
    caller.connect(ts(0)).expect("caller connects");
    let mut conclusion_request = None;
    let mut conclusion_response = None;
    for round in 0..10 {
        let now = ts(round * 10_000);
        for packet in packets_from(&mut caller) {
            if is_conclusion(&packet) {
                conclusion_request = Some(packet.clone());
            }
            listener
                .feed_recv_buf(&packet, now)
                .expect("request decodes");
        }
        for packet in packets_from(&mut listener) {
            if is_conclusion(&packet) {
                conclusion_response = Some(packet.clone());
            }
            caller
                .feed_recv_buf(&packet, now)
                .expect("response decodes");
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return Established {
                caller,
                listener,
                conclusion_request: conclusion_request.expect("a conclusion request"),
                conclusion_response: conclusion_response.expect("a conclusion response"),
            };
        }
    }
    panic!("pair did not connect");
}

#[test]
fn a_replayed_conclusion_response_does_not_re_admit_the_caller() {
    let mut established = establish();
    assert_eq!(
        connected_events(&mut established.caller),
        1,
        "the first admission reports one Connected event"
    );

    // Live traffic first, both ways: the caller's cursor and the caller's
    // receiver both stop being the pristine initial state.
    let baseline = next_cursor(&established.caller);
    for index in 0..BEFORE_REPLAY {
        established
            .caller
            .send(b"caller before the replay", ts(100_000 + index as u64))
            .expect("the caller sends");
        established
            .listener
            .send(b"listener before the replay", ts(100_000 + index as u64))
            .expect("the listener sends");
    }
    deliver(
        &mut established.caller,
        &mut established.listener,
        ts(101_000),
    );
    deliver(
        &mut established.listener,
        &mut established.caller,
        ts(101_000),
    );
    drain_events(&mut established.caller);
    let admitted_cursor = (baseline + BEFORE_REPLAY as u32) & SEQUENCE_MASK;
    assert_eq!(
        next_cursor(&established.caller),
        admitted_cursor,
        "the admitted send cursor is the initial sequence plus the sent payloads"
    );
    assert_eq!(
        receiver_total(&established.caller),
        BEFORE_REPLAY as u64,
        "the receiver holds what it received before the replay"
    );

    // The peer's response arrives a second time, after admission.
    established
        .caller
        .feed_recv_buf(&established.conclusion_response, ts(200_000))
        .expect("the replayed response decodes");

    assert_eq!(established.caller.state(), ConnectionState::Connected);
    assert_eq!(
        connected_events(&mut established.caller),
        0,
        "a replayed conclusion must not admit the connection again"
    );
    assert_eq!(
        next_cursor(&established.caller),
        admitted_cursor,
        "the sequence space of the first admission is final"
    );
    assert_eq!(
        receiver_total(&established.caller),
        BEFORE_REPLAY as u64,
        "re-admission must not re-initialise the receiver"
    );

    // And the connection still carries in order: the next payload is delivered,
    // not seen as a gap.
    established
        .listener
        .send(b"after the replay", ts(201_000))
        .expect("the listener sends");
    deliver(
        &mut established.listener,
        &mut established.caller,
        ts(201_001),
    );
    assert_eq!(
        receiver_total(&established.caller),
        BEFORE_REPLAY as u64 + 1,
        "delivery continues after the replay"
    );

    // The replay is answered, not admitted: the caller retransmits its own
    // saved conclusion.
    let answered = packets_from(&mut established.caller);
    let conclusion = answered
        .iter()
        .find(|packet| is_conclusion(packet))
        .expect("the caller answers a replay with its conclusion");
    assert_eq!(
        conclusion, &established.conclusion_request,
        "the answer is the saved conclusion, byte for byte"
    );
}

#[test]
fn a_replayed_conclusion_request_is_answered_without_re_admitting_the_listener() {
    let mut established = establish();
    assert_eq!(
        connected_events(&mut established.listener),
        1,
        "the first admission reports one Connected event"
    );

    // Live traffic first, both ways: the listener's cursor and the listener's
    // receiver both stop being the pristine initial state.
    let baseline = next_cursor(&established.listener);
    for index in 0..BEFORE_REPLAY {
        established
            .caller
            .send(b"caller before the replay", ts(100_000 + index as u64))
            .expect("the caller sends");
        established
            .listener
            .send(b"listener before the replay", ts(100_000 + index as u64))
            .expect("the listener sends");
    }
    deliver(
        &mut established.caller,
        &mut established.listener,
        ts(101_000),
    );
    deliver(
        &mut established.listener,
        &mut established.caller,
        ts(101_000),
    );
    drain_events(&mut established.listener);
    let admitted_cursor = (baseline + BEFORE_REPLAY as u32) & SEQUENCE_MASK;
    assert_eq!(
        next_cursor(&established.listener),
        admitted_cursor,
        "the admitted send cursor is the initial sequence plus the sent payloads"
    );
    assert_eq!(
        receiver_total(&established.listener),
        BEFORE_REPLAY as u64,
        "the receiver holds what it received before the replay"
    );

    // The raw request cannot belong to this socket once the connection is
    // admitted: the destination check refuses it.
    let refused = established
        .listener
        .feed_recv_buf(&established.conclusion_request, ts(200_000))
        .expect_err("a zero-destination conclusion is refused after admission");
    assert_eq!(refused.kind, ErrorKind::InvalidData);
    assert!(
        refused
            .to_string()
            .contains("destination socket ID mismatch"),
        "the destination check refused it, not the handshake state: {refused}"
    );

    // Addressed to this socket, the replay reaches the handshake state, which
    // must answer it without admitting the connection again.
    let addressed = retarget(&established.conclusion_request, LISTENER_SOCKET_ID);
    established
        .listener
        .feed_recv_buf(&addressed, ts(200_001))
        .expect("an addressed conclusion is delivered to the handshake state");

    assert_eq!(established.listener.state(), ConnectionState::Connected);
    assert_eq!(
        connected_events(&mut established.listener),
        0,
        "a replayed conclusion must not admit the connection again"
    );
    assert_eq!(
        next_cursor(&established.listener),
        admitted_cursor,
        "the sequence space of the first admission is final"
    );
    assert_eq!(
        receiver_total(&established.listener),
        BEFORE_REPLAY as u64,
        "re-admission must not re-initialise the receiver"
    );

    // The connection still carries in order after the replay.
    established
        .caller
        .send(b"after the replay", ts(201_000))
        .expect("the caller sends");
    deliver(
        &mut established.caller,
        &mut established.listener,
        ts(201_001),
    );
    assert_eq!(
        receiver_total(&established.listener),
        BEFORE_REPLAY as u64 + 1,
        "delivery continues after the replay"
    );

    // The replay is answered by retransmitting the saved response, which is
    // what a lost response needs, and is not a new admission.
    let answered = packets_from(&mut established.listener);
    let conclusion = answered
        .iter()
        .find(|packet| is_conclusion(packet))
        .expect("the listener answers the replay with its conclusion response");
    assert_eq!(
        conclusion, &established.conclusion_response,
        "the answer is the saved conclusion, byte for byte"
    );
    assert_eq!(
        connected_events(&mut established.listener),
        0,
        "answering a replay queues no admission event"
    );
}

#[test]
fn a_tampered_conclusion_is_refused_after_admission() {
    let mut established = establish();
    assert_eq!(connected_events(&mut established.caller), 1);
    drain_events(&mut established.caller);

    // Drain whatever the connection queued on completion, so the refusal's own
    // silence is what the last assertion reads.
    let _ = packets_from(&mut established.caller);
    let tampered = retampered(&established.conclusion_response);
    let refused = established
        .caller
        .feed_recv_buf(&tampered, ts(200_000))
        .expect_err("a conclusion that does not match the admitted handshake is refused");
    assert_eq!(refused.kind, ErrorKind::InvalidData);
    assert!(
        refused
            .to_string()
            .contains("late handshake does not match the established session"),
        "the identity guard refused it, not the destination check: {refused}"
    );
    assert_eq!(established.caller.state(), ConnectionState::Connected);
    assert_eq!(
        connected_events(&mut established.caller),
        0,
        "a refused conclusion is not an admission"
    );
    assert!(
        packets_from(&mut established.caller).is_empty(),
        "a refused conclusion is not answered"
    );
}
