//! Periodic NAK encoding cost and wire-shape benchmark.
//!
//! The alternating cases are the worst wire shape: each outstanding loss is
//! a four-byte singleton record. Dense loss is the best shape: one eight-byte
//! range record independent of window size. Setup happens outside the timed
//! loop; each iteration measures range traversal, bounded chunk encoding, and
//! draining the generated sans-I/O output.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, ConnectionState, DEFAULT_MTU, MAX_FLOW_WINDOW,
    SrtConnection, SrtPacket, TimerId, Timestamp,
};
use std::hint::black_box;

const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;

#[derive(Clone, Copy)]
enum LossShape {
    One,
    EightScattered,
    Alternating,
    Dense,
}

fn drain_packets(connection: &mut SrtConnection) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while let Some(output) = connection.poll_output() {
        if let ConnectionOutput::SendPacket(packet) = output {
            packets.push(packet);
        }
    }
    packets
}

fn transfer(from: &mut SrtConnection, to: &mut SrtConnection, now: Timestamp) {
    for packet in drain_packets(from) {
        to.feed_recv_buf(&packet, now)
            .expect("valid handshake packet");
    }
}

fn connected_pair(window: u32) -> (SrtConnection, SrtConnection) {
    let options = ConnectionOptions {
        initial_seq: Some(0),
        tsbpd_delay: 0,
        flow_window_packets: window,
        receive_buffer_packets: window,
        ..ConnectionOptions::default()
    };
    let mut caller = SrtConnection::new_caller(options.clone());
    let mut listener = SrtConnection::new_listener(options);
    caller.connect(Timestamp::default()).expect("connect");
    for round in 0..8 {
        let now = Timestamp::from_micros(round * 1_000);
        transfer(&mut caller, &mut listener, now);
        transfer(&mut listener, &mut caller, now);
        if caller.state() == ConnectionState::Connected
            && listener.state() == ConnectionState::Connected
        {
            return (caller, listener);
        }
    }
    panic!("benchmark connection did not establish");
}

fn prepared_listener(window: u32, shape: LossShape) -> (SrtConnection, u64) {
    let (mut caller, mut listener) = connected_pair(window);
    let now = Timestamp::from_micros(10_000);
    caller.send(&[], now).expect("template send");
    let mut packet = match SrtPacket::decode(&drain_packets(&mut caller)[0]).expect("template") {
        SrtPacket::Data(packet) => packet,
        SrtPacket::Control(_) => unreachable!("send emits data"),
    };
    let high_offset = match shape {
        LossShape::One => 2,
        LossShape::EightScattered => 16,
        LossShape::Alternating | LossShape::Dense => window - 1,
    };
    packet.sequence_number = high_offset & SEQUENCE_MASK;
    let mut encoded = Vec::new();
    SrtPacket::Data(packet.clone()).encode(&mut encoded);
    listener
        .feed_recv_buf(&encoded, now)
        .expect("expose benchmark losses");

    let should_recover = |offset: u32| match shape {
        LossShape::One => offset == 1,
        LossShape::EightScattered | LossShape::Alternating => offset % 2 == 1,
        LossShape::Dense => false,
    };
    for offset in 0..high_offset {
        if !should_recover(offset) {
            continue;
        }
        packet.sequence_number = offset;
        encoded.clear();
        SrtPacket::Data(packet.clone()).encode(&mut encoded);
        listener
            .feed_recv_buf(&encoded, now)
            .expect("recover benchmark packet");
    }
    drain_packets(&mut listener);

    let loss_count = (0..high_offset)
        .filter(|offset| !should_recover(*offset))
        .count() as u64;
    (listener, loss_count)
}

fn emit_and_drain(listener: &mut SrtConnection) -> (usize, usize) {
    listener
        .handle_timer(TimerId::Nak, Timestamp::from_micros(20_000))
        .expect("NAK timer");
    let packets = drain_packets(listener);
    assert!(
        packets
            .iter()
            .all(|packet| packet.len() <= DEFAULT_MTU as usize)
    );
    let wire_bytes = packets.iter().map(Vec::len).sum();
    (packets.len(), wire_bytes)
}

fn bench_case(c: &mut Criterion, name: &str, window: u32, shape: LossShape) {
    let (mut listener, loss_count) = prepared_listener(window, shape);
    let wire_shape = emit_and_drain(&mut listener);
    eprintln!(
        "{name}: losses={loss_count}, wire_packets={}, wire_bytes={}",
        wire_shape.0, wire_shape.1
    );

    let mut group = c.benchmark_group("nak_chunking");
    group.throughput(Throughput::Elements(loss_count));
    group.bench_function(name, |b| {
        b.iter(|| black_box(emit_and_drain(&mut listener)));
    });
    group.finish();
}

fn benches(c: &mut Criterion) {
    bench_case(c, "one_loss", 32, LossShape::One);
    bench_case(c, "eight_scattered", 32, LossShape::EightScattered);
    bench_case(c, "alternating_8192", 8_192, LossShape::Alternating);
    bench_case(c, "dense_8191", 8_192, LossShape::Dense);
    bench_case(
        c,
        "alternating_65536",
        MAX_FLOW_WINDOW,
        LossShape::Alternating,
    );
    bench_case(c, "dense_65535", MAX_FLOW_WINDOW, LossShape::Dense);
}

criterion_group!(nak_chunking, benches);
criterion_main!(nak_chunking);
