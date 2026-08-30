#![no_main]

use libfuzzer_sys::fuzz_target;
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMode, SrtConnection, SrtGroup,
    Timestamp,
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

// Models the real interop bug where a listener-side Backup group silently
// dropped every payload a caller-side Backup group actually sent: the two
// ends can independently decide a different physical leg is "Active" (e.g.
// because handshake completion order over the shared socket differs on
// each side). The sending and receiving groups here are built with member
// add order controlled by the fuzz input, independent of each other --
// whatever payload the sender group actually transmits on either leg must
// still reach the receiver group, regardless of that order.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let reverse_receiver_order = data[0] & 1 != 0;
    let weight_a = (data[1] as u16) + 1;
    let weight_b = (data[2] as u16) + 1;
    let payload_bytes = &data[3..];
    if payload_bytes.is_empty() {
        return;
    }

    let Some((caller_a, listener_a)) = establish_pair(ConnectionOptions::default()) else {
        return;
    };
    let Some((caller_b, listener_b)) = establish_pair(ConnectionOptions::default()) else {
        return;
    };

    let Ok(mut sender) = SrtGroup::new(0x4000_0040, GroupMode::Backup) else {
        return;
    };
    if sender.add_member(1, weight_a, caller_a).is_err()
        || sender.add_member(2, weight_b, caller_b).is_err()
    {
        return;
    }

    let Ok(mut receiver) = SrtGroup::new(0x4000_0041, GroupMode::Backup) else {
        return;
    };
    // clippy sees two calls to the same function and flags this as
    // if_same_then_else, but the whole point of the branch is the *order*
    // add_member is called in -- that's the race axis being fuzzed.
    #[allow(clippy::if_same_then_else)]
    let added = if reverse_receiver_order {
        receiver.add_member(2, weight_b, listener_b).is_ok()
            && receiver.add_member(1, weight_a, listener_a).is_ok()
    } else {
        receiver.add_member(1, weight_a, listener_a).is_ok()
            && receiver.add_member(2, weight_b, listener_b).is_ok()
    };
    if !added {
        return;
    }

    for (index, chunk) in payload_bytes.chunks(16).take(16).enumerate() {
        let now = ts(100_000 + index as u64 * 1_000);
        if sender.send(chunk, now).is_err() {
            continue;
        }
        for member_id in [1u32, 2u32] {
            let packets = drain(
                sender
                    .member_mut(member_id)
                    .expect("sender member")
                    .connection_mut(),
            );
            for packet in packets {
                let _ = receiver
                    .member_mut(member_id)
                    .expect("receiver member")
                    .connection_mut()
                    .feed_recv_buf(&packet, now);
            }
        }
        let delivered = receiver.poll_data(now);
        assert_eq!(
            delivered.as_ref().map(|packet| packet.payload.as_ref()),
            Some(chunk),
            "payload the sender group transmitted must reach the receiver group"
        );
    }
});
