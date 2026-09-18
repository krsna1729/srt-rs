#![no_main]

//! Focused fuzzing for control-packet admission.
//!
//! Every datagram is a *control* packet with a fuzzer-chosen type, subtype,
//! type-specific word and information field, so the shapes the connection now
//! validates (word alignment, no-argument payloads, DROPREQ's two sequence
//! words, ACKACK's ACK number, key-management bodies) are explored directly
//! rather than by chance.
//!
//! What is asserted here is what the hardening pass claims:
//!
//! * a rejected control cannot change connection state, and
//! * neither side can be driven into a panic or an oversized datagram.
//!
//! Liveness itself is not asserted here: `last_recv_time` is private, and the
//! property that matters -- a rejected packet must not bank peer activity --
//! is pinned deterministically by
//! `malformed_controls_cannot_refresh_liveness_or_state`.

use libfuzzer_sys::fuzz_target;
use srt_proto::handshake::DEFAULT_MTU;
use srt_proto::wire::{ControlPacket, ControlType, SRT_HEADER_SIZE, SrtPacket};
use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, ErrorKind, SrtConnection, Timestamp,
};

fn control_type(selector: u8) -> ControlType {
    use ControlType::*;
    match selector % 9 {
        0 => Handshake,
        1 => Keepalive,
        2 => Ack,
        3 => Nak,
        4 => Shutdown,
        5 => AckAck,
        6 => UserDefined,
        7 => DropReq,
        _ => CongestionWarning,
    }
}

fn transfer(from: &mut SrtConnection, to: &mut SrtConnection, now: Timestamp) {
    while let Some(output) = from.poll_output().expect("output materializes") {
        if let ConnectionOutput::SendPacket(packet) = output {
            assert!(packet.len() <= DEFAULT_MTU as usize);
            let _ = to.feed_recv_buf(&packet, now);
        }
    }
}

fn connected_pair() -> Option<(SrtConnection, SrtConnection)> {
    let mut caller = SrtConnection::new_caller(ConnectionOptions::default());
    let mut listener = SrtConnection::new_listener(ConnectionOptions::default());
    caller.connect(Timestamp::default()).ok()?;
    for round in 0..8 {
        let now = Timestamp::from_micros(round * 1_000);
        transfer(&mut caller, &mut listener, now);
        transfer(&mut listener, &mut caller, now);
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return Some((caller, listener));
        }
    }
    None
}

fuzz_target!(|data: &[u8]| {
    let Some((mut caller, mut listener)) = connected_pair() else {
        return;
    };

    let mut now_us = 10_000u64;
    let mut rest = data;
    // Layout per datagram: [type][subtype u16][type-specific u32][len u16]
    // followed by that many information-field bytes.
    while rest.len() >= 9 {
        let selector = rest[0];
        let subtype = u16::from_le_bytes([rest[1], rest[2]]);
        let type_specific_info = u32::from_le_bytes([rest[3], rest[4], rest[5], rest[6]]);
        let declared = usize::from(u16::from_le_bytes([rest[7], rest[8]]));
        rest = &rest[9..];
        // Leave room for the fixed SRT header: the MTU bound below applies
        // to the whole encoded datagram, not to the information field alone.
        let take = declared
            .min(rest.len())
            .min((DEFAULT_MTU as usize).saturating_sub(SRT_HEADER_SIZE));
        let control_info = rest[..take].to_vec();
        rest = &rest[take..];

        let to_caller = selector & 1 == 0;
        let dest_socket_id = if to_caller {
            caller.socket_id()
        } else {
            listener.socket_id()
        };
        let packet = ControlPacket {
            control_type: control_type(selector),
            subtype,
            type_specific_info,
            timestamp: 0,
            dest_socket_id,
            control_info,
        };
        let mut encoded = Vec::new();
        if packet.encode(&mut encoded).is_err() {
            continue;
        }
        assert!(encoded.len() <= DEFAULT_MTU as usize);

        // The decoder must not silently rewrite what was encoded.
        if let Ok(SrtPacket::Control(decoded)) = SrtPacket::decode(&encoded) {
            assert_eq!(decoded.control_type, packet.control_type);
            assert_eq!(decoded.control_info, packet.control_info);
        }

        now_us = now_us.saturating_add(1_000);
        let now = Timestamp::from_micros(now_us);

        let target = if to_caller {
            &mut caller
        } else {
            &mut listener
        };
        let before = target.state();
        if let Err(error) = target.feed_recv_buf(&encoded, now) {
            // A control *rejected for its own content* is not a protocol
            // transition: it must leave a connected session exactly where it
            // was. The other error kinds are deliberate terminal transitions
            // -- a handshake rejection ends the attempt, and a fail-closed
            // output/event overflow disconnects on purpose -- so they are not
            // subject to this assertion.
            if error.kind == ErrorKind::InvalidData {
                assert_eq!(
                    target.state(),
                    before,
                    "a malformed control changed connection state"
                );
            }
        }

        transfer(&mut caller, &mut listener, now);
        transfer(&mut listener, &mut caller, now);
        while caller.poll_event().is_some() {}
        while listener.poll_event().is_some() {}
        while caller.poll_output().expect("output materializes").is_some() {}
        while listener
            .poll_output()
            .expect("output materializes")
            .is_some()
        {}
    }
});
