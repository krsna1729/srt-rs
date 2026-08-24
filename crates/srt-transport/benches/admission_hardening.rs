use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use shiguredo_srt::{
    ConnectionOptions, ConnectionOutput, GroupExtensionData, GroupType, HandshakePacket,
    SRTGROUP_MASK, SrtConnection, Timestamp,
};
use srt_transport::{
    AdmissionOptions, AdmissionResolution, BondedInputPolicy, DueIndex, IngressTelemetry,
    ListenerPeerPolicy, PeerTable, PeerTableConfig, PolicyOverride,
};

fn induction(socket_id: u32) -> Vec<u8> {
    let packet = HandshakePacket::new_induction_request(socket_id).encode(0, 0);
    let mut bytes = Vec::new();
    packet.encode(&mut bytes);
    bytes
}

fn next_packet(connection: &mut SrtConnection) -> Vec<u8> {
    loop {
        if let Some(ConnectionOutput::SendPacket(packet)) = connection.poll_output() {
            return packet;
        }
    }
}

fn pending_conclusion(
    peer: SocketAddr,
    options: &AdmissionOptions,
    telemetry: &IngressTelemetry,
) -> (PeerTable, Vec<u8>) {
    let mut table = PeerTable::new();
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 11,
        stream_id: Some("#!::u=bench,r=live".to_owned()),
        ..ConnectionOptions::default()
    });
    caller.connect(Timestamp::default()).expect("start caller");
    let _ = table.admit(
        peer,
        &next_packet(&mut caller),
        Timestamp::default(),
        options,
        0,
        1,
        telemetry,
    );
    let mut outbound = Vec::new();
    table.poll_outbound(Timestamp::default(), &mut outbound);
    for (_, packet) in outbound {
        caller
            .feed_recv_buf(&packet, Timestamp::from_micros(1))
            .expect("induction response");
    }
    (table, next_packet(&mut caller))
}

fn bench_invalid_admission(c: &mut Criterion) {
    let options = AdmissionOptions::basic(7, 120, true);
    let telemetry = IngressTelemetry::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 10_000));
    let mut group = c.benchmark_group("admission_hardening");
    group.throughput(Throughput::Elements(1));
    group.bench_function("invalid_datagram_no_allocation", |b| {
        b.iter_batched(
            PeerTable::new,
            |mut table| {
                black_box(table.admit(
                    peer,
                    black_box(&[0u8; 64]),
                    Timestamp::default(),
                    &options,
                    0,
                    1,
                    &telemetry,
                ));
                assert!(table.is_empty());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_bounded_capacity(c: &mut Criterion) {
    let options = AdmissionOptions::basic(7, 120, true);
    let telemetry = IngressTelemetry::new();
    let packet = induction(1);
    c.bench_function("admission_capacity_rejection", |b| {
        b.iter_batched(
            || {
                let mut table = PeerTable::with_config(PeerTableConfig {
                    max_peers: 1,
                    half_open_timeout: Duration::from_secs(10),
                    ..PeerTableConfig::default()
                });
                let _ = table.admit(
                    SocketAddr::from(([127, 0, 0, 1], 10_000)),
                    &packet,
                    Timestamp::default(),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                table
            },
            |mut table| {
                black_box(table.admit(
                    SocketAddr::from(([127, 0, 0, 1], 10_001)),
                    &packet,
                    Timestamp::from_micros(1),
                    &options,
                    0,
                    1,
                    &telemetry,
                ));
                assert_eq!(table.len(), 1);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_due_index_churn(c: &mut Criterion) {
    c.bench_function("due_index_replace_and_expire_4096", |b| {
        b.iter(|| {
            let mut index = DueIndex::default();
            for key in 0..4096u32 {
                index.set(key, Timestamp::from_micros(u64::from(key)));
                index.set(key, Timestamp::from_micros(u64::from(key) + 4096));
            }
            let mut due = Vec::new();
            index.pop_due(Timestamp::from_micros(8192), &mut due);
            black_box(due);
        });
    });
}

fn bench_per_source_capacity(c: &mut Criterion) {
    let options = AdmissionOptions::basic(7, 120, true);
    let telemetry = IngressTelemetry::new();
    let packet = induction(1);
    let mut table = PeerTable::with_config(PeerTableConfig {
        max_peers: 4_097,
        max_half_open_peers: 4_097,
        max_established_peers: 4_097,
        max_peers_per_ip: 1,
        half_open_timeout: Duration::from_secs(10),
    });
    for index in 0..4_096_u16 {
        let third = (index / 250) as u8;
        let fourth = (index % 250 + 1) as u8;
        let _ = table.admit(
            SocketAddr::from(([10, 0, third, fourth], 10_000)),
            &packet,
            Timestamp::default(),
            &options,
            0,
            1,
            &telemetry,
        );
    }
    c.bench_function("admission_per_source_rejection_4096_peers", |b| {
        b.iter(|| {
            black_box(table.admit(
                SocketAddr::from(([10, 0, 0, 1], 10_001)),
                &packet,
                Timestamp::from_micros(1),
                &options,
                0,
                1,
                &telemetry,
            ));
            assert_eq!(table.len(), 4_096);
        });
    });
}

fn bench_cached_policy_resolution(c: &mut Criterion) {
    let options = AdmissionOptions::basic(7, 120, true);
    let telemetry = IngressTelemetry::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 10_000));
    let mut group = c.benchmark_group("admission_policy");
    group.throughput(Throughput::Elements(1));
    group.bench_function("cached_streamid_configuration", |b| {
        b.iter_batched(
            || pending_conclusion(peer, &options, &telemetry),
            |(mut table, conclusion)| {
                black_box(table.admit_with_resolver(
                    peer,
                    &conclusion,
                    Timestamp::from_micros(2),
                    &options,
                    0,
                    1,
                    &telemetry,
                    |request| {
                        black_box(&request.access_control);
                        AdmissionResolution::Configure(ListenerPeerPolicy {
                            latency: PolicyOverride::Set(Duration::from_millis(120)),
                            ..ListenerPeerPolicy::default()
                        })
                    },
                ));
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_bonded_second_leg_admission(c: &mut Criterion) {
    let first = SocketAddr::from(([127, 0, 0, 1], 10_000));
    let second = SocketAddr::from(([127, 0, 0, 1], 10_001));
    let caller_options = |socket_id| ConnectionOptions {
        socket_id,
        initial_seq: Some(1234),
        stream_id: Some("bench:bonded".to_owned()),
        group_extension: Some(GroupExtensionData {
            group_id: SRTGROUP_MASK | 1,
            group_type: GroupType::Broadcast,
            flags: 0,
            weight: 1,
        }),
        ..ConnectionOptions::default()
    };
    c.bench_function("bonded_second_leg_admission", |b| {
        b.iter_batched(
            || {
                let mut options = AdmissionOptions::basic(7, 120, true);
                options.bonded_inputs = BondedInputPolicy::Accept;
                let telemetry = IngressTelemetry::new();
                let mut table = PeerTable::new();
                let mut first_caller = SrtConnection::new_caller(caller_options(11));
                first_caller
                    .connect(Timestamp::default())
                    .expect("start first caller");
                let _ = table.admit(
                    first,
                    &next_packet(&mut first_caller),
                    Timestamp::default(),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                let mut outbound = Vec::new();
                table.poll_outbound(Timestamp::default(), &mut outbound);
                for (_, packet) in outbound {
                    first_caller
                        .feed_recv_buf(&packet, Timestamp::from_micros(1))
                        .expect("first induction response");
                }
                let first_conclusion = next_packet(&mut first_caller);
                let _ = table.admit(
                    first,
                    &first_conclusion,
                    Timestamp::from_micros(2),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                let mut outbound = Vec::new();
                table.poll_outbound(Timestamp::from_micros(2), &mut outbound);
                for (peer, packet) in outbound {
                    if peer == first {
                        first_caller
                            .feed_recv_buf(&packet, Timestamp::from_micros(3))
                            .expect("first conclusion response");
                    }
                }

                let mut second_caller = SrtConnection::new_caller(caller_options(12));
                second_caller
                    .connect(Timestamp::default())
                    .expect("start second caller");
                let _ = table.admit(
                    second,
                    &next_packet(&mut second_caller),
                    Timestamp::from_micros(3),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                let mut outbound = Vec::new();
                table.poll_outbound(Timestamp::from_micros(3), &mut outbound);
                for (peer, packet) in outbound {
                    if peer == second {
                        second_caller
                            .feed_recv_buf(&packet, Timestamp::from_micros(4))
                            .expect("second induction response");
                    }
                }
                (table, next_packet(&mut second_caller), options, telemetry)
            },
            |(mut table, conclusion, options, telemetry)| {
                black_box(table.admit(
                    second,
                    black_box(&conclusion),
                    Timestamp::from_micros(5),
                    &options,
                    0,
                    1,
                    &telemetry,
                ));
                assert_eq!(table.bonded_stats()[0].connection.legs.len(), 2);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_invalid_admission,
    bench_bounded_capacity,
    bench_due_index_churn,
    bench_per_source_capacity,
    bench_cached_policy_resolution,
    bench_bonded_second_leg_admission
);
criterion_main!(benches);
