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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn fragmented_delivery_preserves_group_reservations_across_sequence_wrap(
        initial_seq in 0u32..=0x7fff_ffff,
        payload in prop::collection::vec(any::<u8>(), 1..5_000),
    ) {
        const WINDOW: u32 = 32;
        let (mut source, listener) = establish_pair(ConnectionOptions {
            initial_seq: Some(initial_seq),
            tsbpd_delay: 0,
            flow_window_packets: WINDOW,
            receive_buffer_packets: WINDOW,
            delivery_queue_packets: WINDOW,
            ..ConnectionOptions::default()
        });
        let mut receiver = SrtGroup::new(0x4000_0032, GroupMode::Backup).expect("receiver group");
        receiver.add_member(1, 1, listener).expect("receiver member");

        source.send_message(&payload, ts(100_000)).expect("fragmented send");
        source.send(b"following", ts(100_001)).expect("following send");
        let packets = drain(&mut source);
        let packet_count = packets.len() as u32 - 1;
        for packet in packets {
            receiver
                .member_mut(1)
                .expect("receiver member")
                .connection_mut()
                .feed_recv_buf(&packet, ts(110_000))
                .expect("packet decodes");
        }

        let first = receiver.poll_data(ts(120_000)).expect("fragmented delivery");
        prop_assert_eq!(first.sequence_number, initial_seq);
        prop_assert_eq!(first.packet_count, packet_count);
        prop_assert_eq!(first.payload.as_ref(), payload.as_slice());
        prop_assert_eq!(
            receiver
                .member(1)
                .expect("receiver member")
                .connection()
                .receiver_stats()
                .expect("receiver stats")
                .available_buffer_packets,
            WINDOW - 1,
        );

        let following = receiver.poll_data(ts(120_000)).expect("following delivery");
        prop_assert_eq!(
            following.sequence_number,
            initial_seq.wrapping_add(packet_count) & 0x7fff_ffff,
        );
        prop_assert_eq!(
            receiver
                .member(1)
                .expect("receiver member")
                .connection()
                .receiver_stats()
                .expect("receiver stats")
                .available_buffer_packets,
            WINDOW,
        );
    }

    /// Regression test for a real interop bug: the two ends of a 2-leg
    /// Backup group can independently (and non-deterministically -- e.g.
    /// depending on which leg's handshake happens to complete first over
    /// the network) decide a different leg is "Active". collect_events
    /// used to filter incoming DATA by the local Active/Standby label, so
    /// whichever side's local choice disagreed with which physical leg the
    /// sender actually used would silently drop every payload sent on it.
    /// Regardless of the order legs are added to the receiving group
    /// (simulating that race), every payload sent through the sending
    /// group must still be delivered.
    #[test]
    fn backup_group_delivers_regardless_of_receiver_add_order(
        reverse_receive_order in any::<bool>(),
        weight_a in 1u16..200,
        weight_b in 1u16..200,
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 1..6),
    ) {
        let (caller_a, listener_a) = establish_pair(ConnectionOptions::default());
        let (caller_b, listener_b) = establish_pair(ConnectionOptions::default());

        let mut sender = SrtGroup::new(0x4000_0030, GroupMode::Backup).expect("sender group");
        sender.add_member(1, weight_a, caller_a).expect("leg 1");
        sender.add_member(2, weight_b, caller_b).expect("leg 2");

        let mut receiver = SrtGroup::new(0x4000_0031, GroupMode::Backup).expect("receiver group");
        if reverse_receive_order {
            receiver.add_member(2, weight_b, listener_b).expect("leg 2");
            receiver.add_member(1, weight_a, listener_a).expect("leg 1");
        } else {
            receiver.add_member(1, weight_a, listener_a).expect("leg 1");
            receiver.add_member(2, weight_b, listener_b).expect("leg 2");
        }

        for payload in &payloads {
            sender.send(payload, ts(100_000)).expect("group sends");
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
                        .feed_recv_buf(&packet, ts(100_000));
                }
            }
            let delivered = receiver.poll_data(ts(100_000)).map(|packet| packet.payload);
            prop_assert_eq!(delivered.as_deref(), Some(payload.as_slice()));
        }
    }
}
