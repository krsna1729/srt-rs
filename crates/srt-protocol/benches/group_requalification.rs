use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, GroupMode, SrtConnection, SrtGroup,
    TimerId, Timestamp,
};
use std::hint::black_box;

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

fn stalled_group() -> (SrtGroup, SrtConnection, Vec<Vec<u8>>) {
    let (caller_a, listener_a) = establish_pair(ConnectionOptions {
        flow_window_packets: 3,
        ..ConnectionOptions::default()
    });
    let (caller_b, _) = establish_pair(ConnectionOptions::default());
    let mut group = SrtGroup::new(0x4000_0022, GroupMode::Broadcast).expect("group");
    group.add_member(1, 1, caller_a).expect("first member");
    group.add_member(2, 1, caller_b).expect("second member");

    let mut packets = Vec::new();
    while group
        .member(1)
        .expect("first member")
        .connection()
        .can_send()
    {
        group.send(b"fill", ts(100_000)).expect("both legs send");
        packets.extend(drain(
            group.member_mut(1).expect("first member").connection_mut(),
        ));
        let _ = drain(group.member_mut(2).expect("second member").connection_mut());
    }
    group
        .send(b"continue", ts(101_000))
        .expect("healthy leg sends");
    (group, listener_a, packets)
}

fn benchmark_requalification(c: &mut Criterion) {
    c.bench_function("group/broadcast_requalification", |b| {
        b.iter_batched(
            stalled_group,
            |(mut group, mut listener, packets)| {
                for packet in packets {
                    listener
                        .feed_recv_buf(&packet, ts(102_000))
                        .expect("data decodes");
                    while listener.poll_event().is_some() {}
                }
                listener
                    .handle_timer(TimerId::Ack, ts(103_000))
                    .expect("ack timer");
                transfer(
                    &mut listener,
                    group.member_mut(1).expect("first member").connection_mut(),
                    ts(103_000),
                );
                black_box(group.can_send())
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, benchmark_requalification);
criterion_main!(benches);
