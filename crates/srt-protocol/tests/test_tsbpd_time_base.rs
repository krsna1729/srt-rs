//! Regression tests for the caller-side TSBPD time base (spec §4.5.1.1).

use srt_proto::wire::{ControlType, SrtPacket};
use srt_proto::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, SrtConnection, TimerId, Timestamp,
};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

const ONE_WAY_US: u64 = 5_000;

fn drain(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(output) = conn.poll_output().unwrap() {
        if let ConnectionOutput::SendPacket(bytes) = output {
            out.push(bytes);
        }
    }
    out
}

fn transfer(sender: &mut SrtConnection, receiver: &mut SrtConnection, arrival: Timestamp) {
    for bytes in drain(sender) {
        receiver
            .feed_recv_buf(&bytes, ts(arrival.as_micros() + ONE_WAY_US))
            .expect("scripted handshake packet is accepted");
    }
}

#[test]
fn listener_conclusion_response_carries_session_timestamp() {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x1000_0001,
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2000_0002,
        ..Default::default()
    });

    caller.connect(ts(0)).expect("caller connects");
    transfer(&mut caller, &mut listener, ts(0));
    transfer(&mut listener, &mut caller, ts(ONE_WAY_US));
    transfer(&mut caller, &mut listener, ts(2 * ONE_WAY_US));

    // The listener processed the CONCLUSION at wall 3*ONE_WAY; its session
    // clock was stamped at 1*ONE_WAY, so the response must carry the
    // listener's session-relative elapsed time, 2*ONE_WAY. Pre-fix this was
    // 0 (start_time unset until after the response was sent).
    let responses = drain(&mut listener);
    assert_eq!(responses.len(), 1, "exactly the CONCLUSION response queued");
    match SrtPacket::decode(&responses[0]).expect("valid packet") {
        SrtPacket::Control(control) => {
            assert_eq!(
                control.control_type,
                srt_proto::wire::ControlType::Handshake
            );
            assert_eq!(
                control.timestamp,
                2 * ONE_WAY_US as u32,
                "CONCLUSION response must carry the listener's session                  timestamp, not a zero stamp"
            );
        }
        other => panic!("expected control packet, got {other:?}"),
    }
}

// Note: a delivery-timing test cannot discriminate this fix — the same
// zero-stamp that inflates the caller's time base also deflates the
// listener's DATA timestamps by the identical offset (its clock starts
// later), cancelling out in PktTsbpdTime. The wire-level assertion above is
// the honest discriminator.

/// Elapsed handshake time before the listener sees the caller's INDUCTION:
/// long enough that an epoch reset at completion is unmistakable.
const HANDSHAKE_DELAY_US: u64 = 2_000_000;

fn timestamp_of(bytes: &[u8]) -> u32 {
    match SrtPacket::decode(bytes).expect("valid packet") {
        SrtPacket::Data(data) => data.timestamp,
        SrtPacket::Control(control) => control.timestamp,
    }
}

fn data_received(conn: &mut SrtConnection) -> usize {
    std::iter::from_fn(|| conn.poll_event())
        .filter(|event| matches!(event, ConnectionEvent::DataReceived { .. }))
        .count()
}

/// The caller keeps the epoch its INDUCTION and CONCLUSION used: libsrt
/// stamps `tsStartTime` once when the socket opens (core.cpp `clearData`)
/// and stamps every later DATA and control packet against it
/// (core.cpp `setPacketTS`/`setDataPacketTS`). The listener derives its TSBPD
/// base from the CONCLUSION timestamp, so a caller that restarted its clock
/// at completion would send DATA that looks `HANDSHAKE_DELAY_US` old.
#[test]
fn caller_data_and_keepalive_continue_the_handshake_epoch() {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x1000_0001,
        ..Default::default()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2000_0002,
        ..Default::default()
    });

    caller.connect(ts(0)).expect("caller connects");
    transfer(&mut caller, &mut listener, ts(HANDSHAKE_DELAY_US));
    transfer(
        &mut listener,
        &mut caller,
        ts(HANDSHAKE_DELAY_US + ONE_WAY_US),
    );
    let conclusion = drain(&mut caller);
    assert_eq!(conclusion.len(), 1, "exactly the CONCLUSION request queued");
    let conclusion_ts = timestamp_of(&conclusion[0]);
    assert_eq!(conclusion_ts as u64, HANDSHAKE_DELAY_US + 2 * ONE_WAY_US);
    for bytes in conclusion {
        listener
            .feed_recv_buf(&bytes, ts(HANDSHAKE_DELAY_US + 3 * ONE_WAY_US))
            .expect("CONCLUSION is accepted");
    }
    let done = HANDSHAKE_DELAY_US + 4 * ONE_WAY_US;
    transfer(&mut listener, &mut caller, ts(done - ONE_WAY_US));
    assert!(caller.state() == srt_proto::ConnectionState::Connected);

    caller.send(b"epoch", ts(done)).expect("DATA is queued");
    let data = drain(&mut caller);
    assert_eq!(data.len(), 1, "exactly one DATA packet");
    assert_eq!(
        timestamp_of(&data[0]) as u64,
        done,
        "DATA continues the epoch of the CONCLUSION stamped {conclusion_ts}"
    );

    let keepalive_at = done + 1_000_000;
    caller
        .handle_timer(TimerId::Keepalive, ts(keepalive_at))
        .expect("keepalive timer");
    let keepalive = drain(&mut caller)
        .into_iter()
        .find(|bytes| {
            matches!(SrtPacket::decode(bytes),
                Ok(SrtPacket::Control(c)) if c.control_type == ControlType::Keepalive)
        })
        .expect("a KEEPALIVE is sent");
    assert_eq!(timestamp_of(&keepalive) as u64, keepalive_at);

    // The listener's TSBPD base came from the CONCLUSION timestamp, so the
    // DATA must be held for the 120 ms latency, not judged two seconds late.
    let arrival = done + ONE_WAY_US;
    listener
        .feed_recv_buf(&data[0], ts(arrival))
        .expect("DATA is accepted");
    assert_eq!(data_received(&mut listener), 0, "held for its latency");
    listener
        .handle_timer(TimerId::DeliveryContinue, ts(arrival + 120_000))
        .expect("delivery");
    assert_eq!(
        data_received(&mut listener),
        1,
        "delivered at its play time"
    );
}
