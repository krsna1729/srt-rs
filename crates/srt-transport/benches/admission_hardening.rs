use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use srt_proto::handshake::{GroupExtensionData, GroupType, HandshakePacket, SRTGROUP_MASK};
use srt_proto::wire::SrtPacket;
use srt_proto::{ConnectionOptions, ConnectionOutput, SrtConnection, Timestamp};
use srt_transport::advanced::admission::{
    AdmissionDropReason, AdmissionOptions, AdmissionResolution, Admit, BondedInputPolicy,
    PeerTable, PeerTableConfig,
};
use srt_transport::advanced::telemetry::IngressTelemetry;
use srt_transport::test_support::{DenseDueIndex, DenseSlotArena, DueIndex, PhysicalPeerKey};
use srt_transport::{ListenerPeerPolicy, PolicyOverride};

fn induction(socket_id: u32) -> Vec<u8> {
    let packet = HandshakePacket::new_induction_request(socket_id).encode(0, 0);
    let mut bytes = Vec::new();
    packet
        .encode(&mut bytes)
        .expect("packet fits configured datagram bound");
    bytes
}

fn next_packet(connection: &mut SrtConnection) -> Vec<u8> {
    loop {
        if let Some(ConnectionOutput::SendPacket(packet)) = connection
            .poll_output()
            .expect("exact-size output materializes")
        {
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

/// The first CONCLUSION of a caller with `socket_id` at `peer`, after the
/// stateless INDUCTION exchange against `scratch`. SYN cookies are keyed once
/// per process, so it verifies on any table.
fn conclusion_for(
    scratch: &mut PeerTable,
    peer: SocketAddr,
    socket_id: u32,
    options: &AdmissionOptions,
    telemetry: &IngressTelemetry,
) -> Vec<u8> {
    let mut caller = SrtConnection::new_caller(ConnectionOptions {
        socket_id,
        ..ConnectionOptions::default()
    });
    caller.connect(Timestamp::default()).expect("start caller");
    let _ = scratch.admit(
        peer,
        &next_packet(&mut caller),
        Timestamp::default(),
        options,
        0,
        1,
        telemetry,
    );
    let mut outbound = Vec::new();
    scratch.poll_outbound(Timestamp::default(), &mut outbound);
    for (to, packet) in outbound {
        if to == peer {
            caller
                .feed_recv_buf(&packet, Timestamp::from_micros(1))
                .expect("induction response");
        }
    }
    next_packet(&mut caller)
}

/// A verified CONCLUSION refused because the table is full: capacity is
/// checked once the cookie verifies, before any state exists.
fn bench_bounded_capacity(c: &mut Criterion) {
    let options = AdmissionOptions::basic(7, 120, true);
    let telemetry = IngressTelemetry::new();
    let mut scratch = PeerTable::new();
    let held = SocketAddr::from(([127, 0, 0, 1], 10_000));
    let refused = SocketAddr::from(([127, 0, 0, 1], 10_001));
    let held_conclusion = conclusion_for(&mut scratch, held, 1, &options, &telemetry);
    let refused_conclusion = conclusion_for(&mut scratch, refused, 2, &options, &telemetry);
    c.bench_function("admission_conclusion_capacity_rejection", |b| {
        b.iter_batched(
            || {
                let mut table = PeerTable::with_config(PeerTableConfig {
                    max_peers: 1,
                    half_open_timeout: Duration::from_secs(10),
                    ..PeerTableConfig::default()
                });
                let _ = table.admit(
                    held,
                    &held_conclusion,
                    Timestamp::default(),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                table
            },
            |mut table| {
                let admit = table.admit(
                    refused,
                    &refused_conclusion,
                    Timestamp::from_micros(1),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                assert_eq!(admit, Admit::Dropped(AdmissionDropReason::Capacity));
                assert_eq!(table.len(), 1);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Answering an INDUCTION statelessly and draining the answer, and dropping
/// a CONCLUSION whose cookie fails verification: the per-datagram work any
/// source can make a listener do without state.
fn bench_stateless_handshakes(c: &mut Criterion) {
    let options = AdmissionOptions::basic(7, 120, true);
    let telemetry = IngressTelemetry::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 10_000));
    let mut group = c.benchmark_group("admission_stateless");
    group.throughput(Throughput::Elements(1));
    let request = induction(1);
    group.bench_function("induction_answer_and_drain", |b| {
        let mut table = PeerTable::new();
        let mut outbound = Vec::new();
        b.iter(|| {
            black_box(table.admit(
                peer,
                black_box(&request),
                Timestamp::default(),
                &options,
                0,
                1,
                &telemetry,
            ));
            table.poll_outbound(Timestamp::default(), &mut outbound);
            assert_eq!(outbound.len(), 1);
        });
    });
    let mut scratch = PeerTable::new();
    let genuine = conclusion_for(&mut scratch, peer, 2, &options, &telemetry);
    let SrtPacket::Control(control) = SrtPacket::decode(&genuine).expect("conclusion") else {
        panic!("a handshake control packet");
    };
    let mut handshake = HandshakePacket::decode(&control).expect("handshake body");
    handshake.syn_cookie ^= 0x5A5A_0000;
    let mut forged = Vec::new();
    handshake
        .encode(control.timestamp, control.dest_socket_id)
        .encode(&mut forged)
        .expect("handshake fits a datagram");
    group.bench_function("forged_conclusion_drop", |b| {
        let mut table = PeerTable::new();
        b.iter(|| {
            let admit = table.admit(
                peer,
                black_box(&forged),
                Timestamp::default(),
                &options,
                0,
                1,
                &telemetry,
            );
            assert_eq!(admit, Admit::Dropped(AdmissionDropReason::InvalidCookie));
        });
    });
    group.finish();
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

/// A verified CONCLUSION refused by the per-source limit with 4096 peers
/// held: routing and the source count are index lookups.
fn bench_per_source_capacity(c: &mut Criterion) {
    let options = AdmissionOptions::basic(7, 120, true);
    let telemetry = IngressTelemetry::new();
    let mut scratch = PeerTable::new();
    let mut table = PeerTable::with_config(PeerTableConfig {
        max_peers: 4_097,
        max_half_open_peers: 4_097,
        max_established_peers: 4_097,
        max_peers_per_ip: 1,
        half_open_timeout: Duration::from_secs(10),
        ..PeerTableConfig::default()
    });
    for index in 0..4_096_u16 {
        let third = (index / 250) as u8;
        let fourth = (index % 250 + 1) as u8;
        let peer = SocketAddr::from(([10, 0, third, fourth], 10_000));
        let conclusion = conclusion_for(
            &mut scratch,
            peer,
            u32::from(index) + 1,
            &options,
            &telemetry,
        );
        let _ = table.admit(
            peer,
            &conclusion,
            Timestamp::default(),
            &options,
            0,
            1,
            &telemetry,
        );
    }
    assert_eq!(table.len(), 4_096);
    let probe = SocketAddr::from(([10, 0, 0, 1], 10_001));
    let conclusion = conclusion_for(&mut scratch, probe, 0x9999, &options, &telemetry);
    c.bench_function(
        "admission_conclusion_per_source_rejection_4096_peers",
        |b| {
            b.iter(|| {
                let admit = table.admit(
                    probe,
                    black_box(&conclusion),
                    Timestamp::from_micros(1),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                assert_eq!(admit, Admit::Dropped(AdmissionDropReason::SourceCapacity));
                assert_eq!(table.len(), 4_096);
            });
        },
    );
}

fn bench_same_tuple_n_callers(c: &mut Criterion) {
    let options = AdmissionOptions::basic(7, 120, true);
    let telemetry = IngressTelemetry::new();
    let peer = SocketAddr::from(([127, 0, 0, 1], 10_000));
    const N: u64 = 64;
    c.bench_function("admission_same_tuple_64_callers", |b| {
        b.iter_batched(
            || {
                let mut packets = Vec::with_capacity(N as usize);
                for socket_id in 1..=N {
                    packets.push(induction(socket_id as u32));
                }
                packets
            },
            |packets| {
                let mut table = PeerTable::with_config(PeerTableConfig {
                    max_peers: N as usize,
                    max_half_open_peers: N as usize,
                    max_established_peers: N as usize,
                    max_peers_per_ip: N as usize,
                    half_open_timeout: Duration::from_secs(10),
                    ..PeerTableConfig::default()
                });
                for (index, packet) in packets.iter().enumerate() {
                    black_box(table.admit(
                        peer,
                        packet,
                        Timestamp::from_micros(index as u64),
                        &options,
                        0,
                        1,
                        &telemetry,
                    ));
                }
                black_box(table.half_open_count());
            },
            BatchSize::SmallInput,
        );
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
                // A bonded caller refuses a response without the listener's
                // own GROUP (libsrt `SRT_REJ_GROUP`), so the listener has one.
                options.connection_template = Some(ConnectionOptions {
                    group_extension: Some(GroupExtensionData {
                        group_id: SRTGROUP_MASK | 2,
                        group_type: GroupType::Broadcast,
                        flags: 0,
                        weight: 1,
                    }),
                    ..ConnectionOptions::default()
                });
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
fn bench_route_only_dispatch(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_only_dispatch");

    for size in [1, 30, 200, 1000, 4096] {
        let mut arena = DenseSlotArena::<usize>::new(size);
        let mut map: std::collections::HashMap<(SocketAddr, u32), usize> =
            std::collections::HashMap::new();
        let mut queries = Vec::with_capacity(size);

        for i in 0..size {
            let addr = SocketAddr::from((
                [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                5000,
            ));
            let (slot, id) = arena.allocate_socket_id(0).unwrap();
            arena.insert_at_slot(slot, id, addr, i);
            map.insert((addr, id), i);
            queries.push((id, addr));
        }

        group.throughput(Throughput::Elements(size as u64));

        group.bench_function(format!("dense_slot/{size}"), |b| {
            b.iter(|| {
                for &(id, addr) in &queries {
                    black_box(arena.get(black_box(id), black_box(addr)));
                }
            });
        });

        group.bench_function(format!("hash_map/{size}"), |b| {
            b.iter(|| {
                for &(id, addr) in &queries {
                    black_box(map.get(black_box(&(addr, id))));
                }
            });
        });
    }
    group.finish();
}

fn bench_established_data_progression(c: &mut Criterion) {
    let mut group = c.benchmark_group("established_data_progression");
    let options = AdmissionOptions::basic(100, 120, true);
    let telemetry = IngressTelemetry::new();

    for size in [1, 30, 200, 1000, 4096] {
        let mut table = PeerTable::with_config(PeerTableConfig {
            max_peers: size,
            max_half_open_peers: size,
            ..PeerTableConfig::default()
        });

        let mut streams = Vec::with_capacity(size);

        for i in 0..size {
            let peer = SocketAddr::from((
                [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                5000,
            ));
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                socket_id: (i as u32) + 10,
                stream_id: Some("#!::u=bench,r=live".to_owned()),
                ..ConnectionOptions::default()
            });
            caller.connect(Timestamp::default()).expect("start caller");
            let induction = next_packet(&mut caller);
            let _ = table.admit(
                peer,
                &induction,
                Timestamp::default(),
                &options,
                0,
                1,
                &telemetry,
            );
            let mut outbound = Vec::new();
            table.poll_outbound(Timestamp::default(), &mut outbound);
            for (_, packet) in outbound {
                let _ = caller.feed_recv_buf(&packet, Timestamp::from_micros(1));
            }
            let conclusion = next_packet(&mut caller);
            let _ = table.admit(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
            );
            let mut outbound2 = Vec::new();
            table.poll_outbound(Timestamp::from_micros(2), &mut outbound2);
            for (_, packet) in outbound2 {
                let _ = caller.feed_recv_buf(&packet, Timestamp::from_micros(2));
            }

            caller
                .send(b"progressive payload data", Timestamp::from_micros(3))
                .expect("send data");
            let base_pkt = next_packet(&mut caller);
            let initial_seq =
                u32::from_be_bytes([base_pkt[0] & 0x7f, base_pkt[1], base_pkt[2], base_pkt[3]]);

            // Pre-feed base_pkt beyond 120 ms TSBPD deadline to initialize expected_seq without gap
            let warm_now = Timestamp::from_micros(1_000_000);
            let _ = table.admit(peer, &base_pkt, warm_now, &options, 0, 1, &telemetry);

            streams.push((peer, base_pkt, initial_seq));
        }

        group.throughput(Throughput::Elements(size as u64));

        let mut events = Vec::new();
        table.poll_events(&mut events);
        let mut now_us = 1_000_010u64;

        group.bench_function(format!("dense_slots_progression/{size}"), |b| {
            b.iter(|| {
                now_us = now_us.wrapping_add(10);
                let now = Timestamp::from_micros(now_us);
                let wire_ts = (now_us.saturating_sub(120_000) as u32).to_be_bytes();
                for (peer, pkt, seq) in &mut streams {
                    *seq = (*seq + 1) & 0x7fff_ffff;
                    let be = seq.to_be_bytes();
                    pkt[0] = be[0] & 0x7f;
                    pkt[1] = be[1];
                    pkt[2] = be[2];
                    pkt[3] = be[3];
                    pkt[8..12].copy_from_slice(&wire_ts);
                    black_box(table.admit(
                        black_box(*peer),
                        black_box(pkt),
                        now,
                        &options,
                        0,
                        1,
                        &telemetry,
                    ));
                }
                table.poll_events(&mut events);
            });
        });
    }
    group.finish();
}

fn bench_ready_queue_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("ready_queue_scaling");
    let options = AdmissionOptions::basic(100, 120, true);
    let telemetry = IngressTelemetry::new();

    for size in [1, 30, 200, 1000, 4096] {
        let mut table = PeerTable::with_config(PeerTableConfig {
            max_peers: size,
            max_half_open_peers: size,
            ..PeerTableConfig::default()
        });
        let mut physical_peers = Vec::with_capacity(size);

        for i in 0..size {
            let peer = SocketAddr::from((
                [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                5000,
            ));
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                socket_id: (i as u32) + 10,
                stream_id: Some("#!::u=bench,r=live".to_owned()),
                ..ConnectionOptions::default()
            });
            caller.connect(Timestamp::default()).expect("start caller");
            let induction = next_packet(&mut caller);
            let _ = table.admit(
                peer,
                &induction,
                Timestamp::default(),
                &options,
                0,
                1,
                &telemetry,
            );
            let mut outbound = Vec::new();
            table.poll_outbound(Timestamp::default(), &mut outbound);
            for (_, packet) in outbound {
                let _ = caller.feed_recv_buf(&packet, Timestamp::from_micros(1));
            }
            let conclusion = next_packet(&mut caller);
            let _ = table.admit(
                peer,
                &conclusion,
                Timestamp::from_micros(2),
                &options,
                0,
                1,
                &telemetry,
            );
            let mut outbound2 = Vec::new();
            table.poll_outbound(Timestamp::from_micros(2), &mut outbound2);
            for (_, packet) in outbound2 {
                let _ = caller.feed_recv_buf(&packet, Timestamp::from_micros(2));
            }
            let physical = table.physical_for_address(peer).expect("peer established");
            physical_peers.push(physical);
        }

        let mut events = Vec::new();
        table.poll_events(&mut events);
        let mut out = Vec::new();
        table.poll_outbound(Timestamp::from_micros(10), &mut out);

        group.throughput(Throughput::Elements(size as u64));

        let mut drain_out = Vec::new();
        let mut drain_events = Vec::new();
        // 1. Unique readiness enqueue (transition from empty to queued)
        group.bench_function(format!("unique_readiness_enqueue/{size}"), |b| {
            b.iter_custom(|iters| {
                let mut elapsed = std::time::Duration::ZERO;
                for _ in 0..iters {
                    table.poll_outbound(Timestamp::default(), &mut drain_out);
                    table.poll_events(&mut drain_events);
                    let start = std::time::Instant::now();
                    for &peer in &physical_peers {
                        table.mark_ready_physical(black_box(peer));
                    }
                    elapsed += start.elapsed();
                }
                elapsed
            });
        });
        for &peer in &physical_peers {
            table.mark_ready_physical(peer);
        }
        group.bench_function(format!("duplicate_readiness_coalescing/{size}"), |b| {
            b.iter(|| {
                for &peer in &physical_peers {
                    table.mark_ready_physical(black_box(peer));
                }
            });
        });

        // 3. Drain + Rearm round-trip
        group.bench_function(format!("drain_and_rearm/{size}"), |b| {
            b.iter(|| {
                table.poll_outbound(Timestamp::default(), &mut drain_out);
                table.poll_events(&mut drain_events);
                for &peer in &physical_peers {
                    table.mark_ready_physical(black_box(peer));
                }
            });
        });
    }
    group.finish();
}
fn bench_dense_due_index_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("dense_due_index_scaling");

    for size in [1, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(size as u64));

        // 1. Unique set: one deadline per live peer slot
        group.bench_function(format!("unique_set/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut arena = DenseSlotArena::<usize>::new(size);
                    let mut slots = Vec::with_capacity(size);
                    for i in 0..size {
                        let addr = SocketAddr::from((
                            [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                            5000,
                        ));
                        let (s, id) = arena.allocate_socket_id(0).unwrap();
                        arena.insert_at_slot(s, id, addr, i);
                        slots.push(s);
                    }
                    let index = DenseDueIndex::default();
                    (arena, slots, index)
                },
                |state| {
                    let (arena, slots, index) = state;
                    for &slot in slots.iter() {
                        index.set(slot, Timestamp::from_micros(1000), arena);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // 2. Reschedule churn (modest 2x replacement)
        group.bench_function(format!("reschedule_modest/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut arena = DenseSlotArena::<usize>::new(size);
                    let mut slots = Vec::with_capacity(size);
                    let mut index = DenseDueIndex::default();
                    for i in 0..size {
                        let addr = SocketAddr::from((
                            [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                            5000,
                        ));
                        let (s, id) = arena.allocate_socket_id(0).unwrap();
                        arena.insert_at_slot(s, id, addr, i);
                        index.set(s, Timestamp::from_micros(1000), &arena);
                        slots.push(s);
                    }
                    (arena, slots, index)
                },
                |state| {
                    let (arena, slots, index) = state;
                    for &slot in slots.iter() {
                        index.set(slot, Timestamp::from_micros(2000), arena);
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // 3. Peek min deadline after every deadline was replaced
        group.bench_function(format!("peek_min_stale/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut arena = DenseSlotArena::<usize>::new(size);
                    let mut index = DenseDueIndex::default();
                    for i in 0..size {
                        let addr = SocketAddr::from((
                            [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                            5000,
                        ));
                        let (s, id) = arena.allocate_socket_id(0).unwrap();
                        arena.insert_at_slot(s, id, addr, i);
                        // Stale early deadline + live later deadline
                        index.set(s, Timestamp::from_micros(500), &arena);
                        index.set(s, Timestamp::from_micros(1000 + i as u64), &arena);
                    }
                    (arena, index)
                },
                |state| {
                    let (_arena, index) = state;
                    black_box(index.earliest());
                },
                BatchSize::SmallInput,
            );
        });

        // 4. Pop due after every deadline was replaced twice
        group.bench_function(format!("pop_due_stale/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut arena = DenseSlotArena::<usize>::new(size);
                    let mut index = DenseDueIndex::default();
                    for i in 0..size {
                        let addr = SocketAddr::from((
                            [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                            5000,
                        ));
                        let (s, id) = arena.allocate_socket_id(0).unwrap();
                        arena.insert_at_slot(s, id, addr, i);
                        // 2 reschedules before due timestamp
                        index.set(s, Timestamp::from_micros(100), &arena);
                        index.set(s, Timestamp::from_micros(200), &arena);
                        index.set(s, Timestamp::from_micros(300), &arena);
                    }
                    let due = Vec::with_capacity(size);
                    (arena, index, due)
                },
                |state| {
                    let (arena, index, due) = state;
                    index.pop_due(Timestamp::from_micros(300), arena, due);
                    black_box(&due);
                },
                BatchSize::SmallInput,
            );
        });

        // 5. Remove and slot reuse
        group.bench_function(format!("remove_and_reuse/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut arena = DenseSlotArena::<usize>::new(size);
                    let mut index = DenseDueIndex::default();
                    let mut slots = Vec::with_capacity(size);
                    for i in 0..size {
                        let addr = SocketAddr::from((
                            [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                            5000,
                        ));
                        let (s, id) = arena.allocate_socket_id(0).unwrap();
                        arena.insert_at_slot(s, id, addr, i);
                        index.set(s, Timestamp::from_micros(500), &arena);
                        slots.push((s, id, addr));
                    }
                    (arena, index, slots)
                },
                |state| {
                    let (arena, index, slots) = state;
                    for &(s, _, addr) in slots.iter() {
                        index.remove(s);
                        arena.remove_by_slot(s);
                        let (new_s, new_id) = arena.allocate_socket_id(0).unwrap();
                        arena.insert_at_slot(new_s, new_id, addr, 999);
                        index.set(new_s, Timestamp::from_micros(1000), arena);
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_generic_due_index_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("generic_due_index_scaling");

    for size in [1, 30, 200, 1000, 4096] {
        group.throughput(Throughput::Elements(size as u64));

        let peers: Vec<PhysicalPeerKey> = (0..size)
            .map(|i| PhysicalPeerKey {
                address: SocketAddr::from((
                    [10, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                    5000,
                )),
                local_socket_id: 100 + i as u32,
            })
            .collect();

        // 1. Unique set: one deadline per peer
        group.bench_function(format!("unique_set/{size}"), |b| {
            b.iter_batched_ref(
                || (DueIndex::<PhysicalPeerKey>::default(), peers.clone()),
                |(index, peers)| {
                    for &peer in peers.iter() {
                        index.set(peer, Timestamp::from_micros(1000));
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // 2. Reschedule churn (modest 2x replacement)
        group.bench_function(format!("reschedule_modest/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut index = DueIndex::<PhysicalPeerKey>::default();
                    for &peer in &peers {
                        index.set(peer, Timestamp::from_micros(1000));
                    }
                    (index, peers.clone())
                },
                |(index, peers)| {
                    for &peer in peers.iter() {
                        index.set(peer, Timestamp::from_micros(2000));
                    }
                },
                BatchSize::SmallInput,
            );
        });

        // 3. Peek min deadline after every deadline was replaced
        group.bench_function(format!("peek_min_stale/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut index = DueIndex::<PhysicalPeerKey>::default();
                    for (i, &peer) in peers.iter().enumerate() {
                        index.set(peer, Timestamp::from_micros(500));
                        index.set(peer, Timestamp::from_micros(1000 + i as u64));
                    }
                    index
                },
                |index| {
                    black_box(index.earliest());
                },
                BatchSize::SmallInput,
            );
        });

        // 4. Pop due after every deadline was replaced twice
        group.bench_function(format!("pop_due_stale/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut index = DueIndex::<PhysicalPeerKey>::default();
                    for &peer in &peers {
                        index.set(peer, Timestamp::from_micros(100));
                        index.set(peer, Timestamp::from_micros(200));
                        index.set(peer, Timestamp::from_micros(300));
                    }
                    let due = Vec::with_capacity(size);
                    (index, due)
                },
                |(index, due)| {
                    index.pop_due(Timestamp::from_micros(300), due);
                    black_box(&due);
                },
                BatchSize::SmallInput,
            );
        });

        // 5. Remove and reuse
        group.bench_function(format!("remove_and_reuse/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let mut index = DueIndex::<PhysicalPeerKey>::default();
                    for &peer in &peers {
                        index.set(peer, Timestamp::from_micros(500));
                    }
                    (index, peers.clone())
                },
                |(index, peers)| {
                    for &peer in peers.iter() {
                        index.remove(&peer);
                        let new_peer = PhysicalPeerKey {
                            address: peer.address,
                            local_socket_id: peer.local_socket_id + 100_000,
                        };
                        index.set(new_peer, Timestamp::from_micros(1000));
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_invalid_admission,
    bench_bounded_capacity,
    bench_stateless_handshakes,
    bench_due_index_churn,
    bench_per_source_capacity,
    bench_same_tuple_n_callers,
    bench_cached_policy_resolution,
    bench_bonded_second_leg_admission,
    bench_route_only_dispatch,
    bench_established_data_progression,
    bench_ready_queue_scaling,
    bench_dense_due_index_scaling,
    bench_generic_due_index_scaling
);
criterion_main!(benches);
