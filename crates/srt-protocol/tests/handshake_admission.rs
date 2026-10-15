//! CONCLUSION-admission challengers.
//!
//! The handshake commits exactly once per generation. A replayed CONCLUSION -
//! byte-identical, arriving after the connection is already established - must
//! not re-admit it: no second `Connected` event, no second buffer
//! initialisation, and no rewrite of the sequence spaces the first admission
//! established. Each side is driven by explicit packet exchange and timers,
//! never by sleeping.

use srt_proto::handshake::{HandshakePacket, HandshakeType};
use srt_proto::wire::{ControlPacket, ControlType, SrtPacket};
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

fn is_handshake(packet: &[u8]) -> bool {
    matches!(
        SrtPacket::decode(packet),
        Ok(SrtPacket::Control(ControlPacket {
            control_type: ControlType::Handshake,
            ..
        }))
    )
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
    let cursor = established.caller.next_sequence_number();

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
        established.caller.next_sequence_number(),
        cursor,
        "the sequence space of the first admission is final"
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
    let cursor = established.listener.next_sequence_number();

    // The raw request cannot belong to this socket once the connection is
    // admitted: the input boundary refuses it before any state is consulted.
    let refused = established
        .listener
        .feed_recv_buf(&established.conclusion_request, ts(200_000))
        .expect_err("a zero-destination conclusion is refused after admission");
    assert_eq!(refused.kind, ErrorKind::InvalidData);

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
        established.listener.next_sequence_number(),
        cursor,
        "the sequence space of the first admission is final"
    );

    // The replay is answered by retransmitting the response, which is what a
    // lost response needs, and is not a new admission.
    let answered = packets_from(&mut established.listener);
    assert!(
        answered.iter().any(|packet| is_handshake(packet)),
        "the listener answers the replay with its conclusion response"
    );
    assert_eq!(
        connected_events(&mut established.listener),
        0,
        "answering a replay queues no admission event"
    );
}
