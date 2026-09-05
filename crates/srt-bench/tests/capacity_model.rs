use std::time::Duration;

use proptest::prelude::*;
use srt_bench::model::{
    Availability, BondMode, CapacityInput, CapacityReason, CellClass, ClassifierPolicy,
    EncryptionMode, HostEnvelope, NetworkEnvelope, ProtocolEnvelope, SrtBandwidthPolicy,
    WorkloadEnvelope, assess,
};

fn known_input() -> CapacityInput {
    CapacityInput {
        workload: WorkloadEnvelope {
            source_bps_per_stream: 8_000_000,
            source_streams: 1,
            physical_connections: 1,
            logical_streams: 1,
            payload_bytes: srt_bench::PAYLOAD_SIZE as u64,
            duration: Duration::from_secs(1),
        },
        protocol: ProtocolEnvelope {
            bandwidth: SrtBandwidthPolicy::ProtocolDefault,
            encryption: EncryptionMode::Plain,
            ..ProtocolEnvelope::default()
        },
        network: NetworkEnvelope {
            expected_rtt: Availability::Known(Duration::from_millis(10)),
            rtt_jitter: Availability::Known(Duration::ZERO),
            ..NetworkEnvelope::default()
        },
        sender: HostEnvelope {
            effective_receive_socket_buffer_bytes: Availability::Known(16 * 1024 * 1024),
            effective_send_socket_buffer_bytes: Availability::Known(16 * 1024 * 1024),
            host_pps_capacity: Availability::Known(1_000_000.0),
            nic_capacity_bps: Availability::NotApplicable,
            ..HostEnvelope::default()
        },
        receiver: HostEnvelope {
            effective_receive_socket_buffer_bytes: Availability::Known(16 * 1024 * 1024),
            effective_send_socket_buffer_bytes: Availability::Known(16 * 1024 * 1024),
            host_pps_capacity: Availability::Known(1_000_000.0),
            nic_capacity_bps: Availability::NotApplicable,
            ..HostEnvelope::default()
        },
        ..CapacityInput::default()
    }
}

fn assessment(input: CapacityInput) -> srt_bench::model::CapacityAssessment {
    assess(input, ClassifierPolicy::default()).expect("valid capacity input")
}

fn known_value(value: Availability<f64>) -> f64 {
    match value {
        Availability::Known(value) => value,
        Availability::Unknown | Availability::NotApplicable => panic!("expected known value"),
    }
}

#[test]
fn protocol_mtu_boundary_matches_what_the_core_actually_enforces() {
    // PROTOCOL TRUTH: `SrtConnection` sets
    // `max_payload_size = DEFAULT_MTU - SRT_HEADER_SIZE`, so the core budgets
    // 1500 for the SRT datagram and does NOT subtract IP/UDP. The hard reason
    // must match that, or the classifier would call a payload the
    // implementation happily emits a protocol violation.
    let mut input = known_input();
    let max_payload = (0..=shiguredo_srt::DEFAULT_MTU as u64)
        .rev()
        .find(|payload| {
            srt_bench::model::encoded_packet_size_bytes(
                *payload,
                input.protocol.encryption,
                input.protocol.cipher_mode,
                0,
            ) <= shiguredo_srt::DEFAULT_MTU as u64
        })
        .expect("an MTU-sized packet fits");
    assert_eq!(
        max_payload,
        shiguredo_srt::DEFAULT_MTU as u64 - shiguredo_srt::SRT_HEADER_SIZE as u64,
        "plaintext protocol budget must equal the core's max_payload_size"
    );
    input.workload.payload_bytes = max_payload;
    assert!(
        !assessment(input.clone())
            .reasons
            .contains(&CapacityReason::PayloadExceedsProtocolMtu)
    );

    input.workload.payload_bytes += 1;
    let above = assessment(input);
    assert_eq!(above.class, CellClass::ExceedsEnvelope);
    assert!(
        above
            .reasons
            .contains(&CapacityReason::PayloadExceedsProtocolMtu)
    );
}

#[test]
fn ipv4_envelope_is_reported_separately_from_protocol_truth() {
    // A payload the core will emit can still not fit a real 1500-byte IPv4
    // path once IP and UDP headers are added. That is a deployment property,
    // so it is its own reason and must not masquerade as protocol truth.
    let mut input = known_input();
    input.workload.payload_bytes =
        shiguredo_srt::DEFAULT_MTU as u64 - shiguredo_srt::SRT_HEADER_SIZE as u64;
    let a = assessment(input);
    assert!(
        !a.reasons
            .contains(&CapacityReason::PayloadExceedsProtocolMtu),
        "the core emits this payload, so it is not a protocol violation"
    );
    assert!(
        a.reasons
            .contains(&CapacityReason::PayloadExceedsIpv4MtuEnvelope),
        "but it cannot fit a 1500-byte IPv4 path once IP/UDP are added"
    );
}

#[test]
fn key_length_alone_does_not_add_an_authentication_tag() {
    // `--encryption 128|192|256` selects a KEY LENGTH. `Encryption::apply_to`
    // sets `key_length` and the passphrase and never touches the cipher mode,
    // and `ConnectionOptions` defaults to `CipherMode::Ctr`, which appends no
    // tag. An AES cell must therefore predict exactly the same packet size as
    // a plain one; charging GCM_TAG_LEN here invented 16 bytes per packet the
    // implementation never sends.
    let plain = known_input();
    let mut aes = plain.clone();
    aes.protocol.encryption = EncryptionMode::Aes256;
    assert_eq!(
        assessment(plain.clone()).derived.srt_data_packet_bytes,
        assessment(aes.clone()).derived.srt_data_packet_bytes,
        "AES-CTR carries no authentication tag"
    );

    // Only selecting GCM adds one.
    let mut gcm = aes;
    gcm.protocol.cipher_mode = shiguredo_srt::CipherMode::Gcm;
    assert_eq!(
        assessment(gcm).derived.srt_data_packet_bytes,
        assessment(plain).derived.srt_data_packet_bytes + shiguredo_srt::GCM_TAG_LEN as u64,
        "GCM adds exactly one tag"
    );
}

#[test]
fn the_gcm_tag_is_not_part_of_the_protocol_mtu_limit() {
    // `SrtConnection` sets `max_payload_size = DEFAULT_MTU - SRT_HEADER_SIZE`
    // regardless of cipher mode, and GCM appends its tag AFTER that limit is
    // applied. So the core accepts the same plaintext payload under GCM as in
    // plain, and charging the tag to the protocol limit claimed a maximum of
    // 1468 where the implementation allows 1484 -- a false hard reason.
    let max_plaintext = shiguredo_srt::DEFAULT_MTU as u64 - shiguredo_srt::SRT_HEADER_SIZE as u64;
    let mut gcm = known_input();
    gcm.protocol.encryption = EncryptionMode::Aes256;
    gcm.protocol.cipher_mode = shiguredo_srt::CipherMode::Gcm;
    gcm.workload.payload_bytes = max_plaintext;
    let a = assessment(gcm.clone());
    assert!(
        !a.reasons
            .contains(&CapacityReason::PayloadExceedsProtocolMtu),
        "the core accepts this plaintext payload under GCM"
    );

    gcm.workload.payload_bytes = max_plaintext + 1;
    assert!(
        assessment(gcm)
            .reasons
            .contains(&CapacityReason::PayloadExceedsProtocolMtu),
        "one byte over the core's own limit is a protocol violation"
    );
}

#[test]
fn the_gcm_tag_still_counts_at_the_wire_and_ip_layers() {
    let plain = known_input();
    let mut gcm = plain.clone();
    gcm.protocol.encryption = EncryptionMode::Aes256;
    gcm.protocol.cipher_mode = shiguredo_srt::CipherMode::Gcm;
    assert_eq!(
        assessment(gcm).derived.srt_data_packet_bytes,
        assessment(plain).derived.srt_data_packet_bytes + shiguredo_srt::GCM_TAG_LEN as u64,
        "the tag is real on the wire even though it is not in the MTU limit"
    );
}

#[test]
fn encryption_does_not_change_pacing_capacity() {
    // The sender paces on `avg_payload_size + SRT_HEADER_SIZE`, updated with
    // the PLAINTEXT payload length; the GCM tag is materialized later. So an
    // AES cell and a plain cell with the same payload must predict the same
    // pacing capacity, or AES cells acquire a pacing constraint the sender
    // does not impose.
    let plain = known_input();
    let mut aes = plain.clone();
    aes.protocol.encryption = EncryptionMode::Aes256;
    let (p, a) = (assessment(plain), assessment(aes));
    assert_eq!(
        known_value(p.derived.pacing_payload_capacity_bps),
        known_value(a.derived.pacing_payload_capacity_bps),
        "pacing capacity must not charge the GCM tag"
    );
    assert!(
        !a.reasons
            .contains(&CapacityReason::SourceExceedsPacingEnvelope)
    );
}

#[test]
fn pacing_modes_keep_source_and_transport_independent() {
    let mut fixed = known_input();
    fixed.protocol.bandwidth = SrtBandwidthPolicy::FixedBps(4_000_000);
    let fixed_assessment = assessment(fixed);
    assert_eq!(fixed_assessment.class, CellClass::DiagnosticControl);
    assert!(
        fixed_assessment
            .reasons
            .contains(&CapacityReason::SourceExceedsPacingEnvelope)
    );

    let mut relative = known_input();
    relative.protocol.bandwidth = SrtBandwidthPolicy::InputRelative {
        overhead_percent: 25,
    };
    let relative_assessment = assessment(relative);
    assert!(matches!(
        relative_assessment.derived.pacing_headroom_bps,
        Availability::Known(value) if value > 0.0
    ));
}

#[test]
fn loss_and_recovery_boundaries_are_explicit() {
    let mut input = known_input();
    input.network.expected_loss_probability = Availability::Known(0.01);
    let lossy = assessment(input.clone());
    let Availability::Known(factor) = lossy.derived.retransmission_factor else {
        panic!("loss factor should be known")
    };
    assert!((factor - 1.0101010101).abs() < 1e-9);

    input.network.expected_rtt = Availability::Known(Duration::from_millis(120));
    input.protocol.tsbpd_latency_ms = 20;
    let recovery = assessment(input);
    assert_eq!(recovery.class, CellClass::Conditional);
    assert_eq!(
        recovery.derived.one_repair_margin_ms,
        Availability::Known(-100.0)
    );
    assert!(
        recovery
            .reasons
            .contains(&CapacityReason::RecoveryMarginInsufficient)
    );
}

#[test]
fn window_host_socket_and_nic_boundaries_are_typed() {
    let mut input = known_input();
    // Long enough that the required window exceeds MIN_FLOW_WINDOW_PACKETS.
    // Below that the protocol clamps up to 32, so a "one packet under"
    // window is not a configuration the implementation can be given.
    input.network.expected_rtt = Availability::Known(Duration::from_millis(120));
    let baseline = assessment(input.clone());
    let Availability::Known(required) = baseline.derived.required_window_packets else {
        panic!("BDP should be known")
    };
    input.protocol.flow_window_packets = required as u32;
    input.protocol.receive_window_packets = required as u32;
    let at_window = assessment(input.clone());
    assert!(
        !at_window
            .reasons
            .contains(&CapacityReason::WindowBelowBdpRequirement)
    );
    input.protocol.flow_window_packets = required as u32 - 1;
    let below_window = assessment(input.clone());
    assert!(
        below_window
            .reasons
            .contains(&CapacityReason::WindowBelowBdpRequirement)
    );

    input = known_input();
    input.receiver.effective_receive_socket_buffer_bytes = Availability::Unknown;
    let unknown_socket = assessment(input.clone());
    assert_eq!(unknown_socket.class, CellClass::Conditional);
    assert!(
        unknown_socket
            .reasons
            .contains(&CapacityReason::EffectiveSocketBufferUnknown)
    );

    input = known_input();
    input.receiver.host_pps_capacity = Availability::Unknown;
    let unknown_host = assessment(input.clone());
    assert!(
        unknown_host
            .reasons
            .contains(&CapacityReason::HostPpsCapacityUnknown)
    );

    input = known_input();
    input.receiver.nic_capacity_bps = Availability::NotApplicable;
    let loopback = assessment(input.clone());
    assert!(
        !loopback
            .reasons
            .contains(&CapacityReason::NicCapacityUnknown)
    );

    let work = match loopback.derived.host_packet_work_pps {
        Availability::Known(value) => value,
        _ => panic!("host packet work should be known"),
    };
    input.receiver.host_pps_capacity = Availability::Known(work * 0.999);
    let overloaded_host = assessment(input);
    assert_eq!(overloaded_host.class, CellClass::ExceedsEnvelope);
    assert!(
        overloaded_host
            .reasons
            .contains(&CapacityReason::HostPpsCapacityExceeded)
    );
}

#[test]
fn per_leg_bdp_is_invariant_when_an_unbonded_population_grows() {
    let mut one = known_input();
    one.workload.source_bps_per_stream = 8_000_000;
    one.network.expected_rtt = Availability::Known(Duration::from_millis(120));
    let mut many = one.clone();
    many.workload.physical_connections = 200;
    many.workload.logical_streams = 200;
    many.workload.source_streams = 200;

    let one = assessment(one);
    let many = assessment(many);
    assert_eq!(
        one.derived.required_window_packets_per_leg,
        many.derived.required_window_packets_per_leg
    );
    assert_eq!(
        one.derived.bdp_packets_per_leg,
        many.derived.bdp_packets_per_leg
    );
}

#[test]
fn bonding_counts_sources_once_and_admission_uses_connect_cc() {
    let mut input = known_input();
    input.workload.physical_connections = 2;
    input.workload.logical_streams = 1;
    input.workload.source_streams = 1;
    input.protocol.bond = BondMode::Broadcast;
    input.admission.connect_cc = 50;
    let broadcast_assessment = assessment(input);
    assert_eq!(
        broadcast_assessment.derived.source_pps_total,
        broadcast_assessment.derived.source_pps_per_stream
    );
    assert_eq!(
        broadcast_assessment.derived.physical_data_pps,
        broadcast_assessment.derived.source_pps_total * 2.0
    );
    assert_eq!(broadcast_assessment.derived.admission_waves, 1);

    let mut input = known_input();
    input.workload.physical_connections = 600;
    input.admission.connect_cc = 50;
    assert_eq!(assessment(input).derived.admission_waves, 12);
}

proptest! {
    #[test]
    fn source_rate_increases_packet_work_and_host_utilization(
        low in 1_000_000u64..20_000_000,
        delta in 1u64..20_000_000,
    ) {
        let high = low.saturating_add(delta);
        let mut low_input = known_input();
        low_input.workload.source_bps_per_stream = low;
        let mut high_input = low_input.clone();
        high_input.workload.source_bps_per_stream = high;
        let low_assessment = assessment(low_input);
        let high_assessment = assessment(high_input);
        prop_assert!(high_assessment.derived.source_pps_total >= low_assessment.derived.source_pps_total);
        prop_assert!(known_value(high_assessment.derived.host_packet_work_pps) >= known_value(low_assessment.derived.host_packet_work_pps));
        prop_assert!(known_value(high_assessment.derived.host_pps_utilization) >= known_value(low_assessment.derived.host_pps_utilization));
    }

    #[test]
    fn rtt_increases_bdp(
        low_ms in 1u64..500,
        delta_ms in 1u64..500,
    ) {
        let mut low_input = known_input();
        low_input.network.expected_rtt = Availability::Known(Duration::from_millis(low_ms));
        let mut high_input = low_input.clone();
        high_input.network.expected_rtt = Availability::Known(Duration::from_millis(low_ms + delta_ms));
        let low_assessment = assessment(low_input);
        let high_assessment = assessment(high_input);
        prop_assert!(known_value(high_assessment.derived.bdp_packets) >= known_value(low_assessment.derived.bdp_packets));
        prop_assert!(known_value(high_assessment.derived.required_window_packets) >= known_value(low_assessment.derived.required_window_packets));
    }

    #[test]
    fn loss_increases_retransmission_factor(loss_low in 0.0f64..0.5, loss_delta in 0.000001f64..0.49) {
        let loss_high = (loss_low + loss_delta).min(0.99);
        let mut low_input = known_input();
        low_input.network.expected_loss_probability = Availability::Known(loss_low);
        let mut high_input = low_input.clone();
        high_input.network.expected_loss_probability = Availability::Known(loss_high);
        let low_assessment = assessment(low_input);
        let high_assessment = assessment(high_input);
        prop_assert!(known_value(high_assessment.derived.retransmission_factor) >= known_value(low_assessment.derived.retransmission_factor));
        prop_assert!(known_value(high_assessment.derived.expected_data_pps) >= known_value(low_assessment.derived.expected_data_pps));
    }

    #[test]
    fn socket_buffer_horizon_increases_with_buffer(bytes_low in 1u64..1_000_000, delta in 1u64..1_000_000) {
        let mut low_input = known_input();
        low_input.receiver.effective_receive_socket_buffer_bytes = Availability::Known(bytes_low);
        let mut high_input = low_input.clone();
        high_input.receiver.effective_receive_socket_buffer_bytes = Availability::Known(bytes_low + delta);
        let low_assessment = assessment(low_input);
        let high_assessment = assessment(high_input);
        prop_assert!(known_value(high_assessment.derived.effective_receive_socket_buffer_horizon_seconds) >= known_value(low_assessment.derived.effective_receive_socket_buffer_horizon_seconds));
    }
}

#[test]
fn socket_horizon_counts_datagram_bytes_not_payload_bytes() {
    // The UDP socket buffer drains datagrams, so its horizon must shrink once
    // headers and retransmissions are counted. Using payload bytes alone made
    // every horizon read longer than it really is.
    let mut input = known_input();
    input.receiver.effective_receive_socket_buffer_bytes = Availability::Known(16 * 1024 * 1024);
    let lossless = assessment(input.clone());

    input.network.expected_loss_probability = Availability::Known(0.10);
    let lossy = assessment(input);

    let a = known_value(
        lossless
            .derived
            .effective_receive_socket_buffer_horizon_seconds,
    );
    let b = known_value(
        lossy
            .derived
            .effective_receive_socket_buffer_horizon_seconds,
    );
    assert!(
        b < a,
        "retransmission amplification must shorten the buffer horizon: {b} vs {a}"
    );
}

#[test]
fn aes192_with_gcm_is_not_classifiable() {
    // `CryptoContext::new_sender`/`new_receiver` reject this pair, so it
    // cannot instantiate. "Impossible to run" is not a capacity class --
    // neither Conditional nor ExceedsEnvelope describes it -- so the model
    // must refuse rather than produce an assessment for a configuration that
    // can never exist.
    let mut input = known_input();
    input.protocol.encryption = EncryptionMode::Aes192;
    input.protocol.cipher_mode = shiguredo_srt::CipherMode::Gcm;
    let err = srt_bench::model::assess(input, srt_bench::model::ClassifierPolicy::default())
        .expect_err("AES-192 + GCM must not classify");
    assert!(err.0.contains("AES-192"), "{}", err.0);
}

#[test]
fn aes192_without_gcm_is_fine() {
    let mut input = known_input();
    input.protocol.encryption = EncryptionMode::Aes192;
    assert!(
        srt_bench::model::assess(input, srt_bench::model::ClassifierPolicy::default()).is_ok(),
        "AES-192 under the default CTR mode is a valid configuration"
    );
}

#[test]
fn backup_control_uncertainty_is_reflected_in_its_confidence() {
    // A zero-loss Backup cell has an Unknown control rate because leg
    // activity is not modelled. Deriving confidence from loss alone reported
    // CadenceBound alongside that Unknown -- contradictory public fields --
    // and since `control_rate_uncertain` is emitted from confidence, the
    // unknown could escape unflagged once host and NIC checks are
    // NotApplicable.
    let mut input = known_input();
    input.protocol.bond = srt_bench::model::BondMode::Backup;
    input.workload.physical_connections = 2;
    input.workload.logical_streams = 1;
    input.workload.source_streams = 1;
    input.network.expected_loss_probability = Availability::Known(0.0);

    let a = assessment(input);
    assert_eq!(
        a.derived.control_pps_est,
        Availability::Unknown,
        "Backup leg activity is not modelled"
    );
    assert_eq!(
        a.derived.control_pps_confidence,
        srt_bench::model::ControlPpsConfidence::Unknown,
        "confidence must follow the aggregate estimate, not the loss input"
    );
    assert!(
        a.reasons.contains(&CapacityReason::ControlRateUncertain),
        "an unknown control rate must always carry an uncertainty reason"
    );
}
