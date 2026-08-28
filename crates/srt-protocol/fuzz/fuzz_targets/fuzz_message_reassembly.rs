#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{ConnectionOutput, SrtConnection, ConnectionOptions, ConnectionState, TimerId, Timestamp};

fn transfer(from: &mut SrtConnection, to: &mut SrtConnection, now: Timestamp) {
    while let Some(output) = from.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            let _ = to.feed_recv_buf(&packet, now);
        }
    }
}

fn connected_pair() -> Option<(SrtConnection, SrtConnection)> {
    let opts = ConnectionOptions {
        tsbpd_delay: 0,
        ..Default::default()
    };
    let mut caller = SrtConnection::new_caller(opts.clone());
    let mut listener = SrtConnection::new_listener(opts);
    caller.connect(Timestamp::default()).ok()?;
    for round in 0..8 {
        let now = Timestamp::from_micros(round * 1_000);
        transfer(&mut caller, &mut listener, now);
        transfer(&mut listener, &mut caller, now);
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            while caller.poll_event().is_some() {}
            while listener.poll_event().is_some() {}
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
    let mut msg_count = 0u32;
    while rest.len() >= 3 {
        let action = rest[0];
        let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
        rest = &rest[3..];
        let take = len.min(rest.len());
        let (payload, remainder) = rest.split_at(take);
        rest = remainder;
        now_us = now_us.saturating_add(u64::from(action).saturating_mul(100).max(1));
        let now = Timestamp::from_micros(now_us);

        match action % 6 {
            0 => {
                // Send a multi-packet message.
                if caller.send_message(payload, now).is_ok() {
                    transfer(&mut caller, &mut listener, now);
                    msg_count += 1;
                }
            }
            1 => {
                // Send single packet.
                if caller.send(payload, now).is_ok() {
                    transfer(&mut caller, &mut listener, now);
                }
            }
            2 => {
                // Feed raw bytes as if from wire.
                let _ = listener.feed_recv_buf(payload, now);
            }
            3 => {
                // ACK timer — drives TLPKTDROP + DROPREQ.
                let _ = listener.handle_timer(TimerId::Ack, now);
                transfer(&mut listener, &mut caller, now);
            }
            4 => {
                let _ = caller.handle_timer(TimerId::Ack, now);
                transfer(&mut caller, &mut listener, now);
            }
            _ => {
                transfer(&mut caller, &mut listener, now);
                transfer(&mut listener, &mut caller, now);
            }
        }
        while caller.poll_event().is_some() {}
        while listener.poll_event().is_some() {}

        if msg_count > 50 {
            break;
        }
    }
});
