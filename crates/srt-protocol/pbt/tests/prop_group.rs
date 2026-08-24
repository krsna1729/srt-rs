use proptest::prelude::*;
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMemberState, GroupMode,
    SrtConnection, SrtGroup, TimerId, Timestamp,
};

fn ts(micros: u64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn transfer(source: &mut SrtConnection, target: &mut SrtConnection, now: Timestamp) {
    while let Some(output) = source.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            target.feed_recv_buf(&packet, now).expect("packet decodes");
        }
    }
}

fn establish_pair(options: ConnectionOptions) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        tsbpd_delay: 0,
        ..options.clone()
    });
    let mut listener = SrtConnection::new_listener(ConnectionOptions {
        tsbpd_delay: 0,
        ..options
    });
    caller.connect(ts(0)).expect("caller connects");
    for round in 0..10 {
        transfer(&mut caller, &mut listener, ts(round * 10_000));
        transfer(&mut listener, &mut caller, ts(round * 10_000));
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, listener);
        }
    }
    panic!("pair did not connect");
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn broadcast_requalifies_after_arbitrary_flow_window(
        flow_window in 3u32..16,
        payload in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let (caller_a, mut listener_a) = establish_pair(ConnectionOptions {
            flow_window_packets: flow_window,
            ..ConnectionOptions::default()
        });
        let (caller_b, _) = establish_pair(ConnectionOptions::default());
        let mut group = SrtGroup::new(0x4000_0020, GroupMode::Broadcast).expect("group");
        group.add_member(1, 1, caller_a).expect("first member");
        group.add_member(2, 1, caller_b).expect("second member");

        let mut stalled_packets = Vec::new();
        while group.member(1).expect("first member").connection().can_send() {
            prop_assert_eq!(group.send(&payload, ts(100_000)).expect("group sends"), 2);
            stalled_packets.extend(drain(
                group.member_mut(1).expect("first member").connection_mut(),
            ));
            let _ = drain(group.member_mut(2).expect("second member").connection_mut());
        }

        prop_assert_eq!(group.send(&payload, ts(101_000)).expect("healthy leg sends"), 1);
        prop_assert_eq!(
            group.member(1).expect("first member").state(),
            GroupMemberState::Unstable,
        );
        for packet in stalled_packets {
            listener_a.feed_recv_buf(&packet, ts(102_000)).expect("data decodes");
            while listener_a.poll_event().is_some() {}
        }
        listener_a.handle_timer(TimerId::Ack, ts(103_000)).expect("ack timer");
        transfer(
            &mut listener_a,
            group.member_mut(1).expect("first member").connection_mut(),
            ts(103_000),
        );

        prop_assert!(group.can_send());
        prop_assert_eq!(
            group.member(1).expect("first member").state(),
            GroupMemberState::Active,
        );
        prop_assert_eq!(group.send(&payload, ts(104_000)).expect("both legs rejoin"), 2);
    }
}
