//! Wire ACK authority: what a peer's cumulative ACK may retire.
//!
//! A peer can only acknowledge what it could have learned about, so the
//! sender bounds an incoming ACK by its *peer-justified frontier*: the DATA's
//! first transmission or the DROPREQ reporting it must have crossed the
//! submission boundary. A sequence the application merely accepted - queued
//! behind the sender's own TX capacity - is not justifiable, and an ACK naming
//! it is refused outright rather than ignored, because it would otherwise
//! compute an advertised window end past that frontier. The comparison is the
//! protocol's own 31-bit one, so the wrap behaves like every other position.

use srt_proto::wire::{ControlPacket, ControlType};
use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, ErrorKind, SrtConnection, TimerId,
    Timestamp,
};

/// The 31-bit sequence space.
const SEQUENCE_MASK: u32 = 0x7fff_ffff;

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

fn establish_pair(options: ConnectionOptions) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: CALLER_SOCKET_ID,
        ..options.clone()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: LISTENER_SOCKET_ID,
        ..options
    });
    caller.connect(ts(0)).expect("caller connects");
    for round in 0..10 {
        for packet in packets_from(&mut caller) {
            listener
                .feed_recv_buf(&packet, ts(round * 10_000))
                .expect("request decodes");
        }
        for packet in packets_from(&mut listener) {
            caller
                .feed_recv_buf(&packet, ts(round * 10_000))
                .expect("response decodes");
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, listener);
        }
    }
    panic!("pair did not connect");
}

/// A cumulative ACK for `ack_seq`, addressed to `dest_socket_id`.
fn ack_for(dest_socket_id: u32, ack_seq: u32, now: Timestamp) -> Vec<u8> {
    let mut control = ControlPacket::new(ControlType::Ack, now.as_micros() as u32, dest_socket_id);
    control.control_info = ack_seq.to_le_bytes().to_vec();
    let mut bytes = Vec::new();
    control
        .encode(&mut bytes)
        .expect("packet fits the configured datagram bound");
    bytes
}

fn buffered(connection: &SrtConnection) -> u32 {
    connection
        .sender_stats()
        .expect("a connected sender reports stats")
        .packets_in_buffer
}

#[test]
fn an_ack_beyond_the_submitted_frontier_is_refused() {
    let (mut caller, mut listener) = establish_pair(ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    });
    caller
        .send(b"queued but not submitted", ts(100_000))
        .expect("the application's payload is accepted");
    let cursor = caller
        .next_sequence_number()
        .expect("a connected sender holds a cursor");
    // An ACK names the next sequence the peer expects, so this claims the peer
    // received the payload the sender has only accepted so far.
    let ack = ack_for(CALLER_SOCKET_ID, cursor, ts(101_000));

    // Nothing has been polled out, so the DATA has not crossed the submission
    // boundary and the peer could not have learned about the sequence.
    let refused = caller
        .feed_recv_buf(&ack, ts(101_000))
        .expect_err("an ACK past the peer-justified frontier is refused");
    assert_eq!(refused.kind, ErrorKind::InvalidData);
    assert!(
        refused.to_string().contains("peer-justified frontier"),
        "the frontier is what refused it: {refused}"
    );
    assert_eq!(buffered(&caller), 1, "the refused ACK retired nothing");

    // Once the DATA has crossed the boundary the peer can acknowledge it for
    // real, and that ACK retires the flight.
    let submitted = packets_from(&mut caller);
    assert!(!submitted.is_empty(), "the DATA is submitted on poll");
    for packet in submitted {
        listener
            .feed_recv_buf(&packet, ts(102_000))
            .expect("the DATA decodes");
    }
    listener
        .handle_timer(TimerId::Ack, ts(112_000))
        .expect("ack timer");
    let acks = packets_from(&mut listener);
    assert!(!acks.is_empty(), "the receiving peer acknowledges");
    for packet in acks {
        caller
            .feed_recv_buf(&packet, ts(112_001))
            .expect("a peer's ACK for submitted DATA is legitimate");
    }
    assert_eq!(buffered(&caller), 0, "the acknowledged flight is retired");
}

#[test]
fn the_frontier_wraps_with_the_sequence_space() {
    let (mut caller, _listener) = establish_pair(ConnectionOptions {
        initial_seq: Some(SEQUENCE_MASK - 1),
        tsbpd_delay: 0,
        ..Default::default()
    });
    caller.send(b"last", ts(100_000)).expect("send");
    caller.send(b"wrapped", ts(101_000)).expect("send");
    let submitted = packets_from(&mut caller);
    assert_eq!(submitted.len(), 2, "both payloads are submitted");

    // The peer could have learned about everything up to the wrap, so an ACK
    // for the position just past it is legitimate...
    let across_the_wrap = ack_for(CALLER_SOCKET_ID, 0, ts(102_000));
    assert!(
        caller.feed_recv_buf(&across_the_wrap, ts(102_000)).is_ok(),
        "an ACK for the position past the wrap is justified"
    );

    // ...and one position further is not.
    let beyond = ack_for(CALLER_SOCKET_ID, 1, ts(103_000));
    let refused = caller
        .feed_recv_buf(&beyond, ts(103_000))
        .expect_err("the wrap does not widen the frontier");
    assert_eq!(refused.kind, ErrorKind::InvalidData);
    assert!(
        refused.to_string().contains("peer-justified frontier"),
        "the frontier is what refused it: {refused}"
    );
}
