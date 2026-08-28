#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{ConnectionOptions, ConnectionOutput, SrtConnection, TimerId, Timestamp};

fn transfer(from: &mut SrtConnection, to: &mut SrtConnection, now: Timestamp) {
    while let Some(output) = from.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
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
        if caller.state() == shiguredo_srt::ConnectionState::Connected
            && listener.state() == shiguredo_srt::ConnectionState::Connected
        {
            return Some((caller, listener));
        }
    }
    None
}

fn timer(selector: u8) -> TimerId {
    match selector % 7 {
        0 => TimerId::Handshake,
        1 => TimerId::Keepalive,
        2 => TimerId::Ack,
        3 => TimerId::Nak,
        4 => TimerId::Retransmit,
        5 => TimerId::Inactivity,
        _ => TimerId::Shutdown,
    }
}

// Start from a valid connected state, then interpret the input as a sequence
// of structured actions. This reaches loss, ACK/NAK, timer, destination-ID,
// delivery, and disconnect paths that a fresh listener fed only random bytes
// almost never reaches.
fuzz_target!(|data: &[u8]| {
    let Some((mut caller, mut listener)) = connected_pair() else {
        return;
    };
    let mut now_us = 10_000u64;
    let mut rest = data;
    while rest.len() >= 3 {
        let action = rest[0];
        let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
        rest = &rest[3..];
        let take = len.min(rest.len());
        let (payload, remainder) = rest.split_at(take);
        rest = remainder;
        now_us = now_us.saturating_add(u64::from(action).saturating_mul(100).max(1));
        let now = Timestamp::from_micros(now_us);

        match action % 10 {
            0 => {
                let _ = caller.feed_recv_buf(payload, now);
            }
            1 => {
                let _ = listener.feed_recv_buf(payload, now);
            }
            2 => {
                if caller.send(payload, now).is_ok() {
                    transfer(&mut caller, &mut listener, now);
                }
            }
            3 => {
                if listener.send(payload, now).is_ok() {
                    transfer(&mut listener, &mut caller, now);
                }
            }
            4 => {
                let _ = caller.handle_timer(timer(action), now);
            }
            5 => {
                let _ = listener.handle_timer(timer(action), now);
            }
            6 => {
                transfer(&mut caller, &mut listener, now);
            }
            7 => {
                transfer(&mut listener, &mut caller, now);
            }
            8 => {
                if caller.send_message(payload, now).is_ok() {
                    transfer(&mut caller, &mut listener, now);
                }
            }
            _ => {
                if listener.send_message(payload, now).is_ok() {
                    transfer(&mut listener, &mut caller, now);
                }
            }
        }
        while caller.poll_event().is_some() {}
        while listener.poll_event().is_some() {}
    }
});
