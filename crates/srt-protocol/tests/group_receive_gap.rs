//! A sequence every group member lost must not stall the receiving group.

use srt_proto::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMode, SrtConnection, SrtGroup,
    TimerId, Timestamp,
};

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

/// A connected pair that keeps `options`' TSBPD latency.
fn connect_pair(options: ConnectionOptions) -> (SrtConnection, SrtConnection) {
    let mut caller = SrtConnection::new_caller(options.clone());
    let mut listener = SrtConnection::new_listener(options);
    caller.connect(ts(0)).expect("caller connects");
    for round in 0..10 {
        let now = ts(round * 10_000);
        for packet in packets_from(&mut caller) {
            listener.feed_recv_buf(&packet, now).expect("decodes");
        }
        for packet in packets_from(&mut listener) {
            caller.feed_recv_buf(&packet, now).expect("decodes");
        }
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, listener);
        }
    }
    panic!("pair did not connect");
}

/// Both links lose the same sequence. Each member's TLPKTDROP gives up on it
/// and releases the next packet once that packet is due; the group must then
/// deliver it at once, in order, and count the one sequence it skipped, as
/// libsrt's group reader does -- not hold it a further second.
#[test]
fn group_receiver_skips_a_sequence_every_member_lost() {
    let options = ConnectionOptions {
        tsbpd_delay: 100,
        ..Default::default()
    };
    let mut group = SrtGroup::new(0x4000_0050, GroupMode::Broadcast).unwrap();
    let mut sources = Vec::new();
    for member_id in [1, 2] {
        let (source, listener) = connect_pair(options.clone());
        group.add_member(member_id, 1, listener).unwrap();
        sources.push((member_id, source));
    }

    let sent = ts(200_000);
    for (member_id, source) in &mut sources {
        let mut packets = Vec::new();
        for payload in [&b"zero"[..], b"one", b"two"] {
            source.send(payload, sent).unwrap();
            packets.extend(packets_from(source));
        }
        packets.remove(1); // "one" is lost on every link
        let member = group.member_mut(*member_id).unwrap().connection_mut();
        for packet in packets {
            member.feed_recv_buf(&packet, sent).unwrap();
        }
    }
    // Past the next packet's play time (sent + 100 ms latency), well inside
    // the `max(1.25 × latency, 1 s)` a group used to wait on top of it.
    let late = ts(400_000);
    for member_id in [1, 2] {
        let member = group.member_mut(member_id).unwrap().connection_mut();
        member.handle_timer(TimerId::Ack, late).unwrap();
        let _ = packets_from(member);
    }

    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| group.poll_data(late))
        .map(|packet| {
            packet
                .payload
                .chunks()
                .flat_map(|chunk| chunk.to_vec())
                .collect()
        })
        .collect();
    assert_eq!(delivered, [b"zero".to_vec(), b"two".to_vec()]);
    assert_eq!(group.skipped_receive_packets(), 1);
}

/// Only one link loses the sequence. The group may see that link release
/// the next packet first, but it must still deliver the other link's copy
/// rather than skip it.
#[test]
fn group_receiver_takes_a_sequence_another_member_still_holds() {
    recover_packet_from_sibling(0, 1);
}

#[test]
fn group_receiver_recovers_initial_prefix_from_sibling() {
    recover_packet_from_sibling(0, 0);
}

#[test]
fn group_receiver_recovers_initial_prefix_across_wrap() {
    recover_packet_from_sibling(0x7fff_ffff, 0);
}

fn recover_packet_from_sibling(initial_sequence: u32, lost_index: usize) {
    let options = ConnectionOptions {
        tsbpd_delay: 100,
        initial_seq: Some(initial_sequence),
        ..Default::default()
    };
    let mut group = SrtGroup::new(0x4000_0051, GroupMode::Broadcast).unwrap();
    let mut sources = Vec::new();
    for member_id in [1, 2] {
        let (source, listener) = connect_pair(options.clone());
        group.add_member(member_id, 1, listener).unwrap();
        sources.push((member_id, source));
    }
    // Drain lifecycle before DATA so member 1 is the first-collected leg.
    assert!(group.poll_data(ts(100_000)).is_none());

    let sent = ts(200_000);
    for (member_id, source) in &mut sources {
        let mut packets = Vec::new();
        for payload in [&b"zero"[..], b"one", b"two"] {
            source.send(payload, sent).unwrap();
            packets.extend(packets_from(source));
        }
        if *member_id == 1 {
            packets.remove(lost_index); // only the first-collected link loses it
        }
        let member = group.member_mut(*member_id).unwrap().connection_mut();
        for packet in packets {
            member.feed_recv_buf(&packet, sent).unwrap();
        }
    }
    let late = ts(400_000);
    for member_id in [1, 2] {
        let member = group.member_mut(member_id).unwrap().connection_mut();
        member.handle_timer(TimerId::Ack, late).unwrap();
        let _ = packets_from(member);
    }

    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| group.poll_data(late))
        .map(|packet| {
            packet
                .payload
                .chunks()
                .flat_map(|chunk| chunk.to_vec())
                .collect()
        })
        .collect();
    assert_eq!(
        delivered,
        [b"zero".to_vec(), b"one".to_vec(), b"two".to_vec()]
    );
    assert_eq!(group.skipped_receive_packets(), 0);
}

/// A terminal group's impossible gap must not strand accepted payloads, but
/// physical Closing and a bounded scan are not proof that a sibling's earlier
/// accepted packet does not remain queued.
#[test]
fn terminal_group_drains_accepted_tail_across_an_impossible_gap_boundedly() {
    terminal_tail(false);
}

#[test]
fn terminal_group_keeps_the_opposite_leg_queued_prefix() {
    terminal_tail(true);
}

fn terminal_tail(sibling_has_prefix: bool) {
    let options = ConnectionOptions {
        // File mode negotiates no TSBPD/TLPKTDROP: no future playback timer
        // can resolve a missing group prefix after every physical leg closes.
        congestion_control: "file".to_string(),
        flow_window_packets: 256,
        receive_buffer_packets: 256,
        delivery_queue_packets: 256,
        ..Default::default()
    };
    let mut group = SrtGroup::new(0x4000_0065, GroupMode::Broadcast).unwrap();
    let mut sources = Vec::new();
    for member_id in [1, 2] {
        let (source, member) = connect_pair(options.clone());
        group.add_member(member_id, 1, member).unwrap();
        sources.push((member_id, source));
    }
    assert!(group.poll_data(ts(90_000)).is_none());
    for (member_id, source) in &mut sources {
        queue_terminal_tail(&mut group, *member_id, source, sibling_has_prefix);
    }
    if !sibling_has_prefix {
        assert!(group.poll_data(ts(100_000)).is_none());
        assert!(group.has_pending_data(), "accepted tail waits behind zero");
    }
    for member_id in [1, 2] {
        group
            .member_mut(member_id)
            .unwrap()
            .connection_mut()
            .disconnect(ts(101_000));
        assert_eq!(
            group.member(member_id).unwrap().connection().state(),
            ConnectionState::Closing
        );
    }
    if !sibling_has_prefix {
        assert!(
            group.poll_data(ts(101_000)).is_none(),
            "Closing is not terminal"
        );
        assert_eq!(group.skipped_receive_packets(), 0);
    }
    // Real peer activity completes each local close while its previously
    // accepted DATA and lifecycle events still await the group consumer.
    let terminal = ts(1_100_001); // due for a keepalive, before close timeout
    complete_terminal_closes(&mut group, &mut sources, terminal);
    let (delivered, bounded_continuations, collection_exhaustions) =
        drain_terminal_tail(&mut group, terminal);
    assert_terminal_drain(
        &group,
        sibling_has_prefix,
        delivered,
        bounded_continuations,
        collection_exhaustions,
    );
}

fn assert_terminal_drain(
    group: &SrtGroup,
    sibling_has_prefix: bool,
    delivered: Vec<u32>,
    bounded_continuations: usize,
    collection_exhaustions: usize,
) {
    let first = if sibling_has_prefix { 0 } else { 1 };
    assert_eq!(delivered, (first..101).collect::<Vec<_>>());
    assert_eq!(
        group.skipped_receive_packets(),
        if sibling_has_prefix { 0 } else { 1 }
    );
    assert!(
        bounded_continuations > 0,
        "exercise queued lifecycle/data continuations"
    );
    if !sibling_has_prefix {
        assert!(
            collection_exhaustions > 0,
            "exercise the 64-event collection budget"
        );
    }
}

fn queue_terminal_tail(
    group: &mut SrtGroup,
    member_id: u32,
    source: &mut SrtConnection,
    sibling_has_prefix: bool,
) {
    let has_prefix = member_id == 2 && sibling_has_prefix;
    if !has_prefix {
        source.synchronize_send_sequence(1).unwrap();
        group
            .member_mut(member_id)
            .unwrap()
            .connection_mut()
            .advance_receive_sequence(1, ts(100_000));
    }
    let sequences = if has_prefix { 0..1u32 } else { 1..101u32 };
    for sequence in sequences {
        source.send(&sequence.to_be_bytes(), ts(100_000)).unwrap();
    }
    for packet in packets_from(source) {
        group
            .member_mut(member_id)
            .unwrap()
            .connection_mut()
            .feed_recv_buf(&packet, ts(100_000))
            .unwrap();
    }
}

fn complete_terminal_closes(
    group: &mut SrtGroup,
    sources: &mut [(u32, SrtConnection)],
    terminal: Timestamp,
) {
    for (member_id, source) in sources {
        source.handle_timer(TimerId::Keepalive, terminal).unwrap();
        for packet in packets_from(source) {
            group
                .member_mut(*member_id)
                .unwrap()
                .connection_mut()
                .feed_recv_buf(&packet, terminal)
                .unwrap();
        }
        assert_eq!(
            group.member(*member_id).unwrap().connection().state(),
            ConnectionState::Disconnected
        );
    }
}

fn drain_terminal_tail(group: &mut SrtGroup, terminal: Timestamp) -> (Vec<u32>, usize, usize) {
    let mut delivered = Vec::new();
    let mut bounded_continuations = 0;
    let mut collection_exhaustions = 0;
    let mut drained = false;
    for _ in 0..512 {
        let result = group.poll_data_bounded(terminal, 1);
        collection_exhaustions += usize::from(group.has_receive_continuation());
        if let Some(packet) = result.packet {
            let sequence = packet.sequence_number;
            assert!(packet.payload.eq(&sequence.to_be_bytes()[..]));
            delivered.push(sequence);
        } else if result.continuation {
            bounded_continuations += 1;
        } else {
            assert!(
                !group.has_pending_data(),
                "None cannot hide the accepted tail"
            );
            drained = true;
            break;
        }
    }
    assert!(
        drained,
        "bounded visits must eventually drain all accepted work"
    );
    (delivered, bounded_continuations, collection_exhaustions)
}
