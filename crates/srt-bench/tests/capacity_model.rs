use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proptest::prelude::*;
use srt_bench::classifier::validate_results;
use srt_bench::harness::COLUMNS;
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
        host: HostEnvelope {
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
fn exact_mtu_boundary_is_allowed_and_one_byte_over_is_hard() {
    let mut input = known_input();
    input.workload.payload_bytes = srt_bench::model::CapacityInput::default()
        .workload
        .payload_bytes;
    input.workload.payload_bytes =
        shiguredo_srt::DEFAULT_MTU as u64 - shiguredo_srt::SRT_HEADER_SIZE as u64;
    let at_boundary = assessment(input.clone());
    assert!(
        !at_boundary
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
    input.host.effective_receive_socket_buffer_bytes = Availability::Unknown;
    let unknown_socket = assessment(input.clone());
    assert_eq!(unknown_socket.class, CellClass::Conditional);
    assert!(
        unknown_socket
            .reasons
            .contains(&CapacityReason::EffectiveSocketBufferUnknown)
    );

    input = known_input();
    input.host.host_pps_capacity = Availability::Unknown;
    let unknown_host = assessment(input.clone());
    assert!(
        unknown_host
            .reasons
            .contains(&CapacityReason::HostPpsCapacityUnknown)
    );

    input = known_input();
    input.host.nic_capacity_bps = Availability::NotApplicable;
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
    input.host.host_pps_capacity = Availability::Known(work * 0.999);
    let overloaded_host = assessment(input);
    assert_eq!(overloaded_host.class, CellClass::ExceedsEnvelope);
    assert!(
        overloaded_host
            .reasons
            .contains(&CapacityReason::HostPpsCapacityExceeded)
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
        low_input.host.effective_receive_socket_buffer_bytes = Availability::Known(bytes_low);
        let mut high_input = low_input.clone();
        high_input.host.effective_receive_socket_buffer_bytes = Availability::Known(bytes_low + delta);
        let low_assessment = assessment(low_input);
        let high_assessment = assessment(high_input);
        prop_assert!(known_value(high_assessment.derived.effective_receive_socket_buffer_horizon_seconds) >= known_value(low_assessment.derived.effective_receive_socket_buffer_horizon_seconds));
    }
}

fn result_row(role: &str, model_class: &str) -> String {
    let mut values = vec![String::new(); COLUMNS.len()];
    let set = |values: &mut [String], column: &str, value: &str| {
        let index = COLUMNS
            .iter()
            .position(|candidate| *candidate == column)
            .unwrap();
        values[index] = value.to_string();
    };
    set(&mut values, "role", role);
    set(&mut values, "conns", "1");
    set(&mut values, "logical_streams", "1");
    set(&mut values, "source_streams", "1");
    set(&mut values, "source_bps", "8000000");
    set(&mut values, "secs", "1");
    set(&mut values, "established", "1");
    set(&mut values, "torn_down", "0");
    set(&mut values, "core_total", "760");
    set(&mut values, "cpu_user_ms", "1");
    set(&mut values, "cpu_sys_ms", "1");
    set(&mut values, "peak_rss_kb", "1");
    set(&mut values, "udp_rcvbuf_err", "0");
    set(&mut values, "src_overflow", "0");
    set(&mut values, "datapath_q_dropped", "0");
    set(&mut values, "local_dropped", "0");
    set(
        &mut values,
        "model_policy_rev",
        "stage-a-v1-no-unvalidated-margin",
    );
    set(&mut values, "model_class_pre", model_class);
    set(&mut values, "model_reasons_pre", "");
    values.join("\t")
}

#[test]
fn prediction_validation_reports_agreement_and_mismatch() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let clean_path = std::env::temp_dir().join(format!("srt-model-validation-{suffix}.tsv"));
    let header = COLUMNS.join("\t");
    std::fs::write(
        &clean_path,
        format!(
            "{header}\n{}\n{}\n",
            result_row("caller", "production-candidate"),
            result_row("listener", "production-candidate")
        ),
    )
    .expect("write clean fixture");
    let clean_output = validate_results(&clean_path, "tsv").expect("validate clean fixture");
    assert!(clean_output.contains("agreement"));
    assert!(clean_output.contains("true"));
    std::fs::remove_file(&clean_path).expect("remove clean fixture");

    let mismatch_path = std::env::temp_dir().join(format!("srt-model-mismatch-{suffix}.tsv"));
    std::fs::write(
        &mismatch_path,
        format!(
            "{header}\n{}\n{}\n",
            result_row("caller", "exceeds-envelope"),
            result_row("listener", "exceeds-envelope")
        ),
    )
    .expect("write mismatch fixture");
    let mismatch_output =
        validate_results(&mismatch_path, "tsv").expect("validate mismatch fixture");
    assert!(mismatch_output.contains("mismatch"));
    std::fs::remove_file(mismatch_path).expect("remove mismatch fixture");
}
