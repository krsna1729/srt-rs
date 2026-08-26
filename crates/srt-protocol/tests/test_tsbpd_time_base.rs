//! Regression tests for the caller-side TSBPD time base (spec §4.5.1.1).

use shiguredo_srt::{ConnectionOptions, ConnectionOutput, SrtConnection, SrtPacket, Timestamp};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

const ONE_WAY_US: u64 = 5_000;

fn drain(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(output) = conn.poll_output() {
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
            assert_eq!(control.control_type, shiguredo_srt::ControlType::Handshake);
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
