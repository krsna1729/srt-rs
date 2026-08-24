#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMode, SrtConnection, SrtGroup,
    TimerId, Timestamp,
};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn transfer(source: &mut SrtConnection, target: &mut SrtConnection, now: Timestamp) {
    while let Some(output) = source.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            let _ = target.feed_recv_buf(&packet, now);
        }
    }
}

fn establish_pair(options: ConnectionOptions) -> Option<(SrtConnection, SrtConnection)> {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        ..options.clone()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        tsbpd_delay: 0,
        ..options
    });
    caller.connect(ts(0)).ok()?;
    for round in 0..10 {
        transfer(&mut caller, &mut listener, ts(round * 10_000));
        transfer(&mut listener, &mut caller, ts(round * 10_000));
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return Some((caller, listener));
        }
    }
    None
}

fn drain(connection: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while let Some(output) = connection.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            packets.push(packet);
        }
    }
    packets
}

fn acknowledge(
    packets: &mut Vec<Vec<u8>>,
    listener: &mut SrtConnection,
    caller: &mut SrtConnection,
    now: Timestamp,
) {
    for packet in packets.drain(..) {
        let _ = listener.feed_recv_buf(&packet, now);
        while listener.poll_event().is_some() {}
    }
    let _ = listener.handle_timer(TimerId::Ack, now);
    transfer(listener, caller, now);
}

// Start with a real two-leg Broadcast group, then vary sends and ACK timing.
// This keeps temporary flow control, sequence alignment, and requalification
// reachable instead of only fuzzing impossible disconnected states.
fuzz_target!(|data: &[u8]| {
    let options = ConnectionOptions {
        flow_window_packets: 3,
        ..ConnectionOptions::default()
    };
    let Some((caller_a, mut listener_a)) = establish_pair(options.clone()) else {
        return;
    };
    let Some((caller_b, mut listener_b)) = establish_pair(options) else {
        return;
    };
    let Ok(mut group) = SrtGroup::new(0x4000_0021, GroupMode::Broadcast) else {
        return;
    };
    if group.add_member(1, 1, caller_a).is_err() || group.add_member(2, 1, caller_b).is_err() {
        return;
    }

    let mut a_packets = Vec::new();
    let mut b_packets = Vec::new();
    for (index, byte) in data.iter().take(64).enumerate() {
        let now = ts(100_000 + index as u64 * 1_000);
        let _ = group.send(&[*byte], now);
        a_packets.extend(drain(group.member_mut(1).expect("first member").connection_mut()));
        b_packets.extend(drain(group.member_mut(2).expect("second member").connection_mut()));

        if byte & 1 != 0 {
            acknowledge(
                &mut a_packets,
                &mut listener_a,
                group.member_mut(1).expect("first member").connection_mut(),
                now,
            );
        }
        if byte & 2 != 0 {
            acknowledge(
                &mut b_packets,
                &mut listener_b,
                group.member_mut(2).expect("second member").connection_mut(),
                now,
            );
        }
        let _ = group.can_send();
    }
});
