//! Pure capacity and deployment-envelope classification.
//!
//! This module only evaluates typed inputs. It does not open sockets, read
//! host state, or consume benchmark observations. That separation is what
//! keeps a pre-run prediction from quietly becoming a post-run explanation.

use std::fmt;
use std::time::Duration;

use crate::source::BandwidthPolicy;

/// A value whose absence has a meaning distinct from zero.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Availability<T> {
    /// A configured or measured value is available.
    Known(T),
    /// The value would matter, but no defensible value was supplied.
    Unknown,
    /// The value does not apply to this topology.
    NotApplicable,
}

impl<T> Availability<T> {
    #[must_use]
    pub fn is_known(self) -> bool {
        matches!(self, Self::Known(_))
    }
}

/// Bonding mode relevant to the amount of physical data traffic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BondMode {
    /// One physical SRT leg per logical stream.
    #[default]
    None,
    /// Every physical leg carries the source workload.
    Broadcast,
    /// One physical leg carries the source workload at a time.
    Backup,
}

impl BondMode {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Broadcast => "broadcast",
            Self::Backup => "backup",
        }
    }
}

/// The SRT pacing policy, in the units users configure it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SrtBandwidthPolicy {
    /// The protocol's default maximum bandwidth.
    ProtocolDefault,
    /// `source_bps / 8` bytes/s, retained for existing bench invocations.
    #[default]
    LegacySourceFixed,
    /// An explicit maximum bandwidth in bits/s.
    FixedBps(u64),
    /// `INPUTBW = source_bps` with the specified `OHEADBW` percentage.
    InputRelative { overhead_percent: u8 },
}

impl SrtBandwidthPolicy {
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::ProtocolDefault => "protocol-default".to_string(),
            Self::LegacySourceFixed => "legacy-source-fixed".to_string(),
            Self::FixedBps(bps) => format!("fixed:{bps}"),
            Self::InputRelative { overhead_percent } => {
                format!("input-relative:{overhead_percent}")
            }
        }
    }
}

impl From<BandwidthPolicy> for SrtBandwidthPolicy {
    fn from(policy: BandwidthPolicy) -> Self {
        match policy {
            BandwidthPolicy::ProtocolDefault => Self::ProtocolDefault,
            BandwidthPolicy::LegacySourceFixed => Self::LegacySourceFixed,
            BandwidthPolicy::Fixed(bps) => Self::FixedBps(bps),
            BandwidthPolicy::InputRelative { overhead_percent } => {
                Self::InputRelative { overhead_percent }
            }
        }
    }
}

/// Encryption mode relevant to the encoded DATA packet size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EncryptionMode {
    #[default]
    Plain,
    Aes128,
    Aes192,
    Aes256,
}

impl EncryptionMode {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Aes128 => "128",
            Self::Aes192 => "192",
            Self::Aes256 => "256",
        }
    }

    #[must_use]
    const fn tag_bytes(self) -> u64 {
        match self {
            Self::Plain => 0,
            Self::Aes128 | Self::Aes192 | Self::Aes256 => shiguredo_srt::GCM_TAG_LEN as u64,
        }
    }
}

impl From<crate::Encryption> for EncryptionMode {
    fn from(encryption: crate::Encryption) -> Self {
        match encryption {
            crate::Encryption::Plain => Self::Plain,
            crate::Encryption::Aes128 => Self::Aes128,
            crate::Encryption::Aes192 => Self::Aes192,
            crate::Encryption::Aes256 => Self::Aes256,
        }
    }
}

/// Application workload inputs. Rates are aggregate only after applying the
/// explicit `source_streams` multiplier; physical and logical counts remain
/// separate for bonded cells.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkloadEnvelope {
    /// Source payload rate for one independent producer (bit/s).
    pub source_bps_per_stream: u64,
    /// Number of independent payload producers.
    pub source_streams: u64,
    /// Number of physical SRT legs/connections.
    pub physical_connections: u64,
    /// Number of application-visible logical streams.
    pub logical_streams: u64,
    /// Payload bytes in each source packet.
    pub payload_bytes: u64,
    /// Requested stream duration.
    pub duration: Duration,
}

/// Protocol configuration and implementation defaults used by the model.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolEnvelope {
    /// Resolved SRT pacing policy.
    pub bandwidth: SrtBandwidthPolicy,
    /// Whether DATA packets carry the protocol's GCM authentication tag.
    pub encryption: EncryptionMode,
    /// Sender flow-control window (packets).
    pub flow_window_packets: u32,
    /// Receiver window (packets).
    pub receive_window_packets: u32,
    /// TSBPD delivery latency (milliseconds).
    pub tsbpd_latency_ms: u64,
    /// ACK timer cadence (microseconds), from the protocol implementation.
    pub ack_interval: Duration,
    /// Light-ACK packet cadence, from the protocol implementation.
    pub light_ack_interval_packets: u32,
    /// Periodic NAK timer cadence (microseconds), from the protocol implementation.
    pub nak_interval: Duration,
    /// Keepalive timer cadence (microseconds), from the protocol implementation.
    pub keepalive_interval: Duration,
    /// Whether periodic NAK support is enabled by the negotiated connection.
    pub periodic_nak_enabled: bool,
    /// Bond topology affecting physical data duplication.
    pub bond: BondMode,
}

impl Default for ProtocolEnvelope {
    fn default() -> Self {
        Self {
            bandwidth: SrtBandwidthPolicy::default(),
            encryption: EncryptionMode::default(),
            flow_window_packets: shiguredo_srt::DEFAULT_FLOW_WINDOW,
            receive_window_packets: shiguredo_srt::DEFAULT_FLOW_WINDOW,
            tsbpd_latency_ms: 120,
            ack_interval: Duration::from_micros(shiguredo_srt::ACK_INTERVAL_MICROS),
            light_ack_interval_packets: shiguredo_srt::LIGHT_ACK_INTERVAL_PACKETS,
            nak_interval: Duration::from_micros(shiguredo_srt::PERIODIC_NAK_INTERVAL_MICROS),
            keepalive_interval: Duration::from_micros(shiguredo_srt::KEEPALIVE_INTERVAL_MICROS),
            periodic_nak_enabled: true,
            bond: BondMode::default(),
        }
    }
}

/// Expected network conditions. A zero is a real measured/configured zero;
/// use `Unknown` when the condition was not supplied.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkEnvelope {
    /// Expected round-trip time.
    pub expected_rtt: Availability<Duration>,
    /// Expected RTT variation/jitter.
    pub rtt_jitter: Availability<Duration>,
    /// Independent expected packet-loss probability in [0, 1).
    pub expected_loss_probability: Availability<f64>,
    /// Expected packet-reorder probability, when relevant.
    pub expected_reorder_probability: Availability<f64>,
    /// UDP + IP header bytes per datagram. IPv4's normal value is 28.
    pub udp_ip_header_bytes: u64,
    /// Link-layer bytes per datagram when a physical NIC applies.
    pub nic_link_overhead_bytes: Availability<u64>,
}

impl Default for NetworkEnvelope {
    fn default() -> Self {
        Self {
            expected_rtt: Availability::Unknown,
            rtt_jitter: Availability::Unknown,
            expected_loss_probability: Availability::Known(0.0),
            expected_reorder_probability: Availability::Known(0.0),
            udp_ip_header_bytes: 28,
            nic_link_overhead_bytes: Availability::Known(0),
        }
    }
}

/// Host/deployment envelope. Socket capacities are deliberately not inferred
/// from a request: the effective values are a separate input.
#[derive(Clone, Debug, PartialEq)]
pub struct HostEnvelope {
    /// Requested receive socket buffer (bytes).
    pub requested_receive_socket_buffer_bytes: u64,
    /// Requested send socket buffer (bytes).
    pub requested_send_socket_buffer_bytes: u64,
    /// Effective receive socket buffer (bytes).
    pub effective_receive_socket_buffer_bytes: Availability<u64>,
    /// Effective send socket buffer (bytes).
    pub effective_send_socket_buffer_bytes: Availability<u64>,
    /// Peers sharing one host UDP socket.
    pub socket_fan_in: u64,
    /// Host packet-processing capacity (packets/s), if defensibly known.
    pub host_pps_capacity: Availability<f64>,
    /// Physical NIC capacity (bits/s), or NotApplicable for loopback.
    pub nic_capacity_bps: Availability<u64>,
    /// Descriptive CPU allocation/set.
    pub cpu_allocation: String,
    /// Worker topology count.
    pub workers: u64,
}

impl Default for HostEnvelope {
    fn default() -> Self {
        Self {
            requested_receive_socket_buffer_bytes: 0,
            requested_send_socket_buffer_bytes: 0,
            effective_receive_socket_buffer_bytes: Availability::Unknown,
            effective_send_socket_buffer_bytes: Availability::Unknown,
            socket_fan_in: 1,
            host_pps_capacity: Availability::Unknown,
            nic_capacity_bps: Availability::Unknown,
            cpu_allocation: "unspecified".to_string(),
            workers: 1,
        }
    }
}

/// Admission inputs. The physical connection count is kept in the workload
/// envelope and is consumed here to derive waves without reimplementing the
/// runtime limiter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionEnvelope {
    /// Process-wide connect concurrency limit.
    pub connect_cc: u64,
}

impl Default for AdmissionEnvelope {
    fn default() -> Self {
        Self { connect_cc: 1 }
    }
}

/// Complete typed model input snapshot.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CapacityInput {
    pub workload: WorkloadEnvelope,
    pub protocol: ProtocolEnvelope,
    pub network: NetworkEnvelope,
    pub host: HostEnvelope,
    pub admission: AdmissionEnvelope,
}

impl Default for WorkloadEnvelope {
    fn default() -> Self {
        Self {
            source_bps_per_stream: crate::DEFAULT_SOURCE_BITRATE_BPS,
            source_streams: 1,
            physical_connections: 1,
            logical_streams: 1,
            payload_bytes: crate::PAYLOAD_SIZE as u64,
            duration: Duration::from_secs(1),
        }
    }
}

/// A deterministic policy layer. The default intentionally has no
/// evidence-free production margin: zero is the policy's explicit minimum,
/// while utilization above 100% remains a mathematical hard failure.
#[derive(Clone, Debug, PartialEq)]
pub struct ClassifierPolicy {
    /// Stable policy revision persisted with every assessment.
    pub revision: String,
    /// Minimum packets of window headroom for a candidate.
    pub minimum_window_headroom_packets: f64,
    /// Minimum one-repair margin in milliseconds for a candidate.
    pub minimum_recovery_margin_ms: f64,
    /// Minimum effective socket horizon in seconds for a candidate.
    pub minimum_socket_horizon_seconds: f64,
    /// Maximum host packet utilization before policy headroom is low.
    pub max_host_pps_utilization: f64,
    /// Maximum applicable NIC utilization before policy headroom is low.
    pub max_nic_utilization: f64,
    /// Optional explicit control-PPS policy ceiling.
    pub max_control_pps: Option<f64>,
    /// Optional explicit admission-wave policy ceiling.
    pub max_admission_waves: Option<u64>,
}

pub const CLASSIFIER_POLICY_REVISION: &str = "stage-a-v1-no-unvalidated-margin";

impl Default for ClassifierPolicy {
    fn default() -> Self {
        Self {
            revision: CLASSIFIER_POLICY_REVISION.to_string(),
            minimum_window_headroom_packets: 0.0,
            minimum_recovery_margin_ms: 0.0,
            minimum_socket_horizon_seconds: 0.0,
            max_host_pps_utilization: 1.0,
            max_nic_utilization: 1.0,
            max_control_pps: None,
            max_admission_waves: None,
        }
    }
}

/// Severity attached to a stable reason code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReasonSeverity {
    /// A known mathematical or implementation hard limit was exceeded.
    Hard,
    /// The requested cell is useful as a diagnostic experiment by design.
    Diagnostic,
    /// A policy margin or required input is not satisfied/known.
    Conditional,
}

impl ReasonSeverity {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hard => "hard",
            Self::Diagnostic => "diagnostic",
            Self::Conditional => "conditional",
        }
    }
}

/// Stable, machine-readable reason codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CapacityReason {
    PayloadExceedsProtocolMtu,
    SourceExceedsPacingEnvelope,
    ProtocolOverheadExceedsPacingHeadroom,
    WindowBelowBdpRequirement,
    WindowHeadroomLow,
    RecoveryMarginInsufficient,
    ExpectedRttUnknown,
    RttVarianceUnknown,
    ExpectedLossUnknown,
    ExpectedReorderUnknown,
    ControlRateUncertain,
    EffectiveSocketBufferUnknown,
    SocketBufferHorizonLow,
    HostPpsCapacityUnknown,
    PredictedPacketWorkUnknown,
    HostPpsHeadroomLow,
    HostPpsCapacityExceeded,
    NicCapacityUnknown,
    NicWireRateUnknown,
    NicHeadroomLow,
    NicCapacityExceeded,
    ExpectedControlRateHigh,
    AdmissionConcurrencyHigh,
}

const REASON_CODES: &[&str] = &[
    "payload_exceeds_protocol_mtu",
    "source_exceeds_pacing_envelope",
    "protocol_overhead_exceeds_pacing_headroom",
    "window_below_bdp_requirement",
    "window_headroom_low",
    "recovery_margin_insufficient",
    "expected_rtt_unknown",
    "rtt_variance_unknown",
    "expected_loss_unknown",
    "expected_reorder_unknown",
    "control_rate_uncertain",
    "effective_socket_buffer_unknown",
    "socket_buffer_horizon_low",
    "host_pps_capacity_unknown",
    "predicted_packet_work_unknown",
    "host_pps_headroom_low",
    "host_pps_capacity_exceeded",
    "nic_capacity_unknown",
    "nic_wire_rate_unknown",
    "nic_headroom_low",
    "nic_capacity_exceeded",
    "expected_control_rate_high",
    "admission_concurrency_high",
];

impl CapacityReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        REASON_CODES[self as usize]
    }

    #[must_use]
    pub const fn severity(self) -> ReasonSeverity {
        match self {
            Self::PayloadExceedsProtocolMtu
            | Self::WindowBelowBdpRequirement
            | Self::HostPpsCapacityExceeded
            | Self::NicCapacityExceeded => ReasonSeverity::Hard,
            Self::SourceExceedsPacingEnvelope
            | Self::ProtocolOverheadExceedsPacingHeadroom
            | Self::AdmissionConcurrencyHigh => ReasonSeverity::Diagnostic,
            _ => ReasonSeverity::Conditional,
        }
    }
}

impl fmt::Display for CapacityReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Confidence of the aggregate control-PPS estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPpsConfidence {
    /// Timer/light-ACK cadence and the keepalive upper bound are configured.
    CadenceBound,
    /// Loss expectation is known, but NAK range aggregation is not predictable.
    ExpectedLoss,
    /// A required loss input is unknown.
    Unknown,
}

impl ControlPpsConfidence {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CadenceBound => "cadence-bound",
            Self::ExpectedLoss => "expected-loss",
            Self::Unknown => "unknown",
        }
    }
}

/// Derived loads and margins. Bitrate fields are bit/s, packet fields are
/// packets/s or bytes as named, and margin/horizon fields are milliseconds or
/// seconds as named.
#[derive(Clone, Debug, PartialEq)]
pub struct DerivedLoad {
    pub source_pps_per_stream: f64,
    pub source_pps_total: f64,
    pub physical_data_pps: f64,
    pub expected_data_pps: Availability<f64>,
    pub payload_bps: f64,
    pub srt_data_packet_bytes: u64,
    pub pacing_packet_bytes: u64,
    pub pacing_payload_capacity_bps: Availability<f64>,
    pub pacing_headroom_bps: Availability<f64>,
    pub retransmission_factor: Availability<f64>,
    pub retransmission_excess: Availability<f64>,
    pub srt_data_bps: Availability<f64>,
    pub srt_control_bps: Availability<f64>,
    pub srt_total_bps: Availability<f64>,
    pub udp_ip_bps: Availability<f64>,
    pub nic_wire_bps: Availability<f64>,
    pub full_ack_pps_est: f64,
    pub light_ack_pps_est: f64,
    pub ack_pps_est: f64,
    pub ackack_pps_est: f64,
    pub nak_pps_est: Availability<f64>,
    pub keepalive_pps_est: f64,
    pub control_pps_est: Availability<f64>,
    pub control_pps_confidence: ControlPpsConfidence,
    pub bdp_bytes: Availability<f64>,
    pub bdp_packets: Availability<f64>,
    pub required_window_packets: Availability<f64>,
    pub configured_flow_window_packets: u32,
    pub configured_receive_window_packets: u32,
    pub flow_window_utilization: Availability<f64>,
    pub receive_window_utilization: Availability<f64>,
    pub flow_window_headroom_packets: Availability<f64>,
    pub receive_window_headroom_packets: Availability<f64>,
    pub guarded_rtt_ms: Availability<f64>,
    pub tsbpd_latency_ms: f64,
    pub one_repair_margin_ms: Availability<f64>,
    pub approximate_repair_rounds_available: Availability<f64>,
    pub requested_receive_socket_buffer_horizon_seconds: Availability<f64>,
    pub requested_send_socket_buffer_horizon_seconds: Availability<f64>,
    pub effective_receive_socket_buffer_horizon_seconds: Availability<f64>,
    pub effective_send_socket_buffer_horizon_seconds: Availability<f64>,
    pub host_packet_work_pps: Availability<f64>,
    pub host_pps_utilization: Availability<f64>,
    pub nic_utilization: Availability<f64>,
    pub estimated_max_resource_utilization: Availability<f64>,
    pub admission_waves: u64,
}

/// Complete pre-run assessment.
#[derive(Clone, Debug, PartialEq)]
pub struct CapacityAssessment {
    pub class: CellClass,
    pub reasons: Vec<CapacityReason>,
    pub derived: DerivedLoad,
    pub input: CapacityInput,
    pub policy_revision: String,
}

/// The four top-level classifier outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellClass {
    ProductionCandidate,
    Conditional,
    DiagnosticControl,
    ExceedsEnvelope,
}

impl CellClass {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProductionCandidate => "production-candidate",
            Self::Conditional => "conditional",
            Self::DiagnosticControl => "diagnostic-control",
            Self::ExceedsEnvelope => "exceeds-envelope",
        }
    }
}

/// Input validation failure. Invalid inputs are rejected before an
/// assessment is produced; they are not disguised as a zero load.
#[derive(Clone, Debug, PartialEq)]
pub struct ModelError(pub String);

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ModelError {}

fn known_sum(a: Availability<f64>, b: Availability<f64>) -> Availability<f64> {
    match (a, b) {
        (Availability::Known(a), Availability::Known(b)) => Availability::Known(a + b),
        (Availability::NotApplicable, Availability::NotApplicable) => Availability::NotApplicable,
        _ => Availability::Unknown,
    }
}

fn multiply_known(value: Availability<f64>, factor: f64) -> Availability<f64> {
    match value {
        Availability::Known(value) => Availability::Known(value * factor),
        Availability::Unknown => Availability::Unknown,
        Availability::NotApplicable => Availability::NotApplicable,
    }
}

fn horizon(bytes: Availability<u64>, bitrate_bps: f64) -> Availability<f64> {
    if bitrate_bps <= 0.0 {
        return Availability::Unknown;
    }
    match bytes {
        Availability::Known(bytes) => Availability::Known(8.0 * bytes as f64 / bitrate_bps),
        Availability::Unknown => Availability::Unknown,
        Availability::NotApplicable => Availability::NotApplicable,
    }
}

fn max_known(a: Availability<f64>, b: Availability<f64>) -> Availability<f64> {
    match (a, b) {
        (Availability::Known(a), Availability::Known(b)) => Availability::Known(a.max(b)),
        (Availability::Known(a), Availability::NotApplicable) => Availability::Known(a),
        (Availability::NotApplicable, Availability::Known(b)) => Availability::Known(b),
        (Availability::NotApplicable, Availability::NotApplicable) => Availability::NotApplicable,
        _ => Availability::Unknown,
    }
}

fn add_optional_bytes(
    srt_bps: Availability<f64>,
    packet_pps: Availability<f64>,
    bytes_per_packet: u64,
) -> Availability<f64> {
    match (srt_bps, packet_pps) {
        (Availability::Known(srt_bps), Availability::Known(packet_pps)) => {
            Availability::Known(srt_bps + packet_pps * bytes_per_packet as f64 * 8.0)
        }
        (Availability::NotApplicable, _) => Availability::NotApplicable,
        (_, Availability::NotApplicable) => Availability::NotApplicable,
        _ => Availability::Unknown,
    }
}

fn available_packet_rate(
    expected_data_pps: Availability<f64>,
    control_pps: Availability<f64>,
) -> Availability<f64> {
    known_sum(expected_data_pps, control_pps)
}

fn packet_rate_for_control(
    data_pps: Availability<f64>,
    control_pps: Availability<f64>,
) -> Availability<f64> {
    available_packet_rate(data_pps, control_pps)
}

#[derive(Clone, Copy)]
struct CoreRates {
    source_pps_per_stream: f64,
    source_pps_total: f64,
    physical_data_pps: f64,
    payload_bps: f64,
    srt_header_bytes: u64,
    pacing_packet_bytes: u64,
    srt_data_packet_bytes: u64,
    pacing_payload_capacity_bps: Availability<f64>,
    pacing_headroom_bps: Availability<f64>,
    retransmission_factor: Availability<f64>,
    retransmission_excess: Availability<f64>,
    expected_data_pps: Availability<f64>,
    srt_data_bps: Availability<f64>,
}

fn derive_core(input: &CapacityInput) -> CoreRates {
    let w = &input.workload;
    let p = &input.protocol;
    let source_pps_per_stream = w.source_bps_per_stream as f64 / (8.0 * w.payload_bytes as f64);
    let source_pps_total = source_pps_per_stream * w.source_streams as f64;
    let physical_multiplier = match p.bond {
        BondMode::Broadcast => w.physical_connections as f64 / w.logical_streams as f64,
        BondMode::None | BondMode::Backup => 1.0,
    };
    let physical_data_pps = source_pps_total * physical_multiplier;
    let payload_bps = w.source_bps_per_stream as f64 * w.source_streams as f64;
    let srt_header_bytes = shiguredo_srt::SRT_HEADER_SIZE as u64;
    let pacing_packet_bytes = srt_header_bytes + w.payload_bytes;
    let srt_data_packet_bytes = pacing_packet_bytes + p.encryption.tag_bytes();
    let pacing_bytes_per_second = pacing_bytes_per_second(p, w.source_bps_per_stream);
    let pacing_capacity_per_stream =
        pacing_bytes_per_second / pacing_packet_bytes as f64 * w.payload_bytes as f64 * 8.0;
    let pacing_payload_capacity_bps = Availability::Known(pacing_capacity_per_stream);
    let pacing_headroom_bps =
        Availability::Known(pacing_capacity_per_stream - w.source_bps_per_stream as f64);
    let (retransmission_factor, retransmission_excess) =
        retransmission_values(input.network.expected_loss_probability);
    let expected_data_pps = multiply_known(retransmission_factor, physical_data_pps);
    let srt_data_bps = multiply_known(expected_data_pps, srt_data_packet_bytes as f64 * 8.0);
    CoreRates {
        source_pps_per_stream,
        source_pps_total,
        physical_data_pps,
        payload_bps,
        srt_header_bytes,
        pacing_packet_bytes,
        srt_data_packet_bytes,
        pacing_payload_capacity_bps,
        pacing_headroom_bps,
        retransmission_factor,
        retransmission_excess,
        expected_data_pps,
        srt_data_bps,
    }
}

fn pacing_bytes_per_second(protocol: &ProtocolEnvelope, source_bps: u64) -> f64 {
    match protocol.bandwidth {
        SrtBandwidthPolicy::ProtocolDefault => {
            shiguredo_srt::DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC as f64
        }
        SrtBandwidthPolicy::LegacySourceFixed => (source_bps / 8).max(1) as f64,
        SrtBandwidthPolicy::FixedBps(bps) => (bps / 8).max(1) as f64,
        SrtBandwidthPolicy::InputRelative { overhead_percent } => {
            (source_bps / 8).max(1) as f64 * (100.0 + f64::from(overhead_percent)) / 100.0
        }
    }
}

fn retransmission_values(loss: Availability<f64>) -> (Availability<f64>, Availability<f64>) {
    match loss {
        Availability::Known(p) => {
            let factor = 1.0 / (1.0 - p);
            (
                Availability::Known(factor),
                Availability::Known(factor - 1.0),
            )
        }
        Availability::Unknown => (Availability::Unknown, Availability::Unknown),
        Availability::NotApplicable => (Availability::NotApplicable, Availability::NotApplicable),
    }
}

#[derive(Clone, Copy)]
struct ControlRates {
    full_ack_pps_est: f64,
    light_ack_pps_est: f64,
    ack_pps_est: f64,
    ackack_pps_est: f64,
    nak_pps_est: Availability<f64>,
    keepalive_pps_est: f64,
    control_pps_est: Availability<f64>,
    control_pps_confidence: ControlPpsConfidence,
    srt_control_bps: Availability<f64>,
}

fn derive_control(input: &CapacityInput, core: CoreRates) -> ControlRates {
    let p = &input.protocol;
    let w = &input.workload;
    let loss = input.network.expected_loss_probability;
    let physical_connections = w.physical_connections as f64;
    let data_pps_per_leg = core.physical_data_pps / physical_connections;
    let ack_interval_s = p.ack_interval.as_secs_f64();
    let full_ack_pps_est = physical_connections / ack_interval_s;
    let ack_pps_per_leg =
        (1.0 / ack_interval_s).max(data_pps_per_leg / f64::from(p.light_ack_interval_packets));
    let ack_pps_est = physical_connections * ack_pps_per_leg;
    let light_ack_pps_est = (ack_pps_est - full_ack_pps_est).max(0.0);
    let ackack_pps_est = full_ack_pps_est;
    let keepalive_pps_est = physical_connections / p.keepalive_interval.as_secs_f64();
    let nak_pps_est = match loss {
        Availability::Known(loss) if p.periodic_nak_enabled => {
            Availability::Known(core.physical_data_pps * loss)
        }
        Availability::Known(_) | Availability::NotApplicable => Availability::Known(0.0),
        Availability::Unknown => Availability::Unknown,
    };
    let control_pps_est = match nak_pps_est {
        Availability::Known(nak) => {
            Availability::Known(ack_pps_est + ackack_pps_est + keepalive_pps_est + nak)
        }
        Availability::Unknown => Availability::Unknown,
        Availability::NotApplicable => Availability::NotApplicable,
    };
    let control_pps_confidence = match loss {
        Availability::Known(loss) if loss > 0.0 => ControlPpsConfidence::ExpectedLoss,
        Availability::Known(_) | Availability::NotApplicable => ControlPpsConfidence::CadenceBound,
        Availability::Unknown => ControlPpsConfidence::Unknown,
    };
    let srt_control_bps = control_bitrate(
        core.srt_header_bytes,
        light_ack_pps_est,
        full_ack_pps_est,
        ackack_pps_est,
        nak_pps_est,
        keepalive_pps_est,
        control_pps_est,
    );
    ControlRates {
        full_ack_pps_est,
        light_ack_pps_est,
        ack_pps_est,
        ackack_pps_est,
        nak_pps_est,
        keepalive_pps_est,
        control_pps_est,
        control_pps_confidence,
        srt_control_bps,
    }
}

fn control_bitrate(
    header_bytes: u64,
    light_ack_pps: f64,
    full_ack_pps: f64,
    ackack_pps: f64,
    nak_pps: Availability<f64>,
    keepalive_pps: f64,
    control_pps: Availability<f64>,
) -> Availability<f64> {
    match (nak_pps, control_pps) {
        (Availability::Known(nak), Availability::Known(control)) => {
            let ack_bytes = light_ack_pps
                * (header_bytes + shiguredo_srt::LIGHT_ACK_CONTROL_INFO_BYTES as u64) as f64
                + full_ack_pps
                    * (header_bytes + shiguredo_srt::FULL_ACK_CONTROL_INFO_BYTES as u64) as f64;
            let ackack_bytes = ackack_pps
                * (header_bytes + shiguredo_srt::LIBSRT_COMPAT_PADDING_BYTES as u64) as f64;
            let nak_bytes = nak * (header_bytes + shiguredo_srt::NAK_RANGE_BYTES as u64) as f64;
            let keepalive_bytes = keepalive_pps
                * (header_bytes + shiguredo_srt::LIBSRT_COMPAT_PADDING_BYTES as u64) as f64;
            debug_assert!(control >= 0.0);
            Availability::Known((ack_bytes + ackack_bytes + nak_bytes + keepalive_bytes) * 8.0)
        }
        (Availability::Unknown, _) => Availability::Unknown,
        (_, Availability::NotApplicable) => Availability::NotApplicable,
        _ => Availability::Unknown,
    }
}

#[derive(Clone, Copy)]
struct NetworkRates {
    srt_total_bps: Availability<f64>,
    packet_pps: Availability<f64>,
    udp_ip_bps: Availability<f64>,
    nic_wire_bps: Availability<f64>,
}

fn derive_network(input: &CapacityInput, core: CoreRates, control: ControlRates) -> NetworkRates {
    let srt_total_bps = known_sum(core.srt_data_bps, control.srt_control_bps);
    let packet_pps = packet_rate_for_control(core.expected_data_pps, control.control_pps_est);
    let udp_ip_bps =
        add_optional_bytes(srt_total_bps, packet_pps, input.network.udp_ip_header_bytes);
    let nic_wire_bps = match input.host.nic_capacity_bps {
        Availability::NotApplicable => Availability::NotApplicable,
        Availability::Known(_) | Availability::Unknown => match input
            .network
            .nic_link_overhead_bytes
        {
            Availability::Known(overhead) => add_optional_bytes(udp_ip_bps, packet_pps, overhead),
            Availability::Unknown => Availability::Unknown,
            Availability::NotApplicable => Availability::NotApplicable,
        },
    };
    NetworkRates {
        srt_total_bps,
        packet_pps,
        udp_ip_bps,
        nic_wire_bps,
    }
}

#[derive(Clone, Copy)]
struct WindowRates {
    bdp_bytes: Availability<f64>,
    bdp_packets: Availability<f64>,
    required_window_packets: Availability<f64>,
    flow_window_utilization: Availability<f64>,
    receive_window_utilization: Availability<f64>,
    flow_window_headroom_packets: Availability<f64>,
    receive_window_headroom_packets: Availability<f64>,
}

fn derive_windows(input: &CapacityInput, core: CoreRates) -> WindowRates {
    let p = &input.protocol;
    let (bdp_bytes, bdp_packets, required_window_packets) = match input.network.expected_rtt {
        Availability::Known(rtt) => match core.srt_data_bps {
            Availability::Known(bps) => {
                let bytes = bps * rtt.as_secs_f64() / 8.0;
                let packets = bytes / core.srt_data_packet_bytes as f64;
                (
                    Availability::Known(bytes),
                    Availability::Known(packets),
                    Availability::Known(packets.ceil()),
                )
            }
            Availability::Unknown => (
                Availability::Unknown,
                Availability::Unknown,
                Availability::Unknown,
            ),
            Availability::NotApplicable => (
                Availability::NotApplicable,
                Availability::NotApplicable,
                Availability::NotApplicable,
            ),
        },
        Availability::Unknown => (
            Availability::Unknown,
            Availability::Unknown,
            Availability::Unknown,
        ),
        Availability::NotApplicable => (
            Availability::NotApplicable,
            Availability::NotApplicable,
            Availability::NotApplicable,
        ),
    };
    let flow_window_utilization =
        required_window_packets.map_known(|required| required / f64::from(p.flow_window_packets));
    let receive_window_utilization = required_window_packets
        .map_known(|required| required / f64::from(p.receive_window_packets));
    let flow_window_headroom_packets =
        required_window_packets.map_known(|required| f64::from(p.flow_window_packets) - required);
    let receive_window_headroom_packets = required_window_packets
        .map_known(|required| f64::from(p.receive_window_packets) - required);
    WindowRates {
        bdp_bytes,
        bdp_packets,
        required_window_packets,
        flow_window_utilization,
        receive_window_utilization,
        flow_window_headroom_packets,
        receive_window_headroom_packets,
    }
}

#[derive(Clone, Copy)]
struct RecoveryRates {
    guarded_rtt_ms: Availability<f64>,
    one_repair_margin_ms: Availability<f64>,
    approximate_repair_rounds_available: Availability<f64>,
    requested_receive_socket_buffer_horizon_seconds: Availability<f64>,
    requested_send_socket_buffer_horizon_seconds: Availability<f64>,
    effective_receive_socket_buffer_horizon_seconds: Availability<f64>,
    effective_send_socket_buffer_horizon_seconds: Availability<f64>,
}

fn derive_recovery_and_sockets(input: &CapacityInput, core: CoreRates) -> RecoveryRates {
    let p = &input.protocol;
    let n = &input.network;
    let h = &input.host;
    let guarded_rtt_ms = match (n.expected_rtt, n.rtt_jitter) {
        (Availability::Known(rtt), Availability::Known(jitter)) => {
            Availability::Known((rtt + jitter).as_secs_f64() * 1000.0)
        }
        (Availability::NotApplicable, Availability::NotApplicable) => Availability::NotApplicable,
        _ => Availability::Unknown,
    };
    let one_repair_margin_ms = guarded_rtt_ms.map_known(|rtt| p.tsbpd_latency_ms as f64 - rtt);
    let approximate_repair_rounds_available = match guarded_rtt_ms {
        Availability::Known(rtt) if rtt > 0.0 => {
            Availability::Known(p.tsbpd_latency_ms as f64 / rtt)
        }
        Availability::Known(_) => Availability::NotApplicable,
        Availability::Unknown => Availability::Unknown,
        Availability::NotApplicable => Availability::NotApplicable,
    };
    let socket_bitrate_bps = core.source_pps_per_stream
        * 8.0
        * input.workload.payload_bytes as f64
        * h.socket_fan_in.max(1) as f64;
    let requested_receive_socket_buffer_horizon = horizon(
        Availability::Known(h.requested_receive_socket_buffer_bytes),
        socket_bitrate_bps,
    );
    let requested_send_socket_buffer_horizon = horizon(
        Availability::Known(h.requested_send_socket_buffer_bytes),
        socket_bitrate_bps,
    );
    let effective_receive_socket_buffer_horizon =
        horizon(h.effective_receive_socket_buffer_bytes, socket_bitrate_bps);
    let effective_send_socket_buffer_horizon =
        horizon(h.effective_send_socket_buffer_bytes, socket_bitrate_bps);
    RecoveryRates {
        guarded_rtt_ms,
        one_repair_margin_ms,
        approximate_repair_rounds_available,
        requested_receive_socket_buffer_horizon_seconds: requested_receive_socket_buffer_horizon,
        requested_send_socket_buffer_horizon_seconds: requested_send_socket_buffer_horizon,
        effective_receive_socket_buffer_horizon_seconds: effective_receive_socket_buffer_horizon,
        effective_send_socket_buffer_horizon_seconds: effective_send_socket_buffer_horizon,
    }
}

#[derive(Clone, Copy)]
struct ResourceRates {
    host_packet_work_pps: Availability<f64>,
    host_pps_utilization: Availability<f64>,
    nic_utilization: Availability<f64>,
    estimated_max_resource_utilization: Availability<f64>,
    admission_waves: u64,
}

fn derive_resources(input: &CapacityInput, network: NetworkRates) -> ResourceRates {
    let h = &input.host;
    let host_packet_work_pps = network.packet_pps;
    let host_pps_utilization = match (host_packet_work_pps, h.host_pps_capacity) {
        (Availability::Known(work), Availability::Known(capacity)) => {
            Availability::Known(work / capacity)
        }
        (Availability::NotApplicable, _) | (_, Availability::NotApplicable) => {
            Availability::NotApplicable
        }
        _ => Availability::Unknown,
    };
    let nic_utilization = match (network.nic_wire_bps, h.nic_capacity_bps) {
        (Availability::Known(bps), Availability::Known(capacity)) => {
            Availability::Known(bps / capacity as f64)
        }
        (Availability::NotApplicable, _) | (_, Availability::NotApplicable) => {
            Availability::NotApplicable
        }
        _ => Availability::Unknown,
    };
    ResourceRates {
        host_packet_work_pps,
        host_pps_utilization,
        nic_utilization,
        estimated_max_resource_utilization: max_known(host_pps_utilization, nic_utilization),
        admission_waves: input
            .workload
            .physical_connections
            .div_ceil(input.admission.connect_cc),
    }
}

/// Derive all quantities and classify one input snapshot.
pub fn assess(
    input: CapacityInput,
    policy: ClassifierPolicy,
) -> Result<CapacityAssessment, ModelError> {
    validate(&input, &policy)?;

    let core = derive_core(&input);
    let control = derive_control(&input, core);
    let network = derive_network(&input, core, control);

    let windows = derive_windows(&input, core);
    let recovery = derive_recovery_and_sockets(&input, core);
    let resources = derive_resources(&input, network);

    let derived = DerivedLoad {
        source_pps_per_stream: core.source_pps_per_stream,
        source_pps_total: core.source_pps_total,
        physical_data_pps: core.physical_data_pps,
        expected_data_pps: core.expected_data_pps,
        payload_bps: core.payload_bps,
        srt_data_packet_bytes: core.srt_data_packet_bytes,
        pacing_packet_bytes: core.pacing_packet_bytes,
        pacing_payload_capacity_bps: core.pacing_payload_capacity_bps,
        pacing_headroom_bps: core.pacing_headroom_bps,
        retransmission_factor: core.retransmission_factor,
        retransmission_excess: core.retransmission_excess,
        srt_data_bps: core.srt_data_bps,
        srt_control_bps: control.srt_control_bps,
        srt_total_bps: network.srt_total_bps,
        udp_ip_bps: network.udp_ip_bps,
        nic_wire_bps: network.nic_wire_bps,
        full_ack_pps_est: control.full_ack_pps_est,
        light_ack_pps_est: control.light_ack_pps_est,
        ack_pps_est: control.ack_pps_est,
        ackack_pps_est: control.ackack_pps_est,
        nak_pps_est: control.nak_pps_est,
        keepalive_pps_est: control.keepalive_pps_est,
        control_pps_est: control.control_pps_est,
        control_pps_confidence: control.control_pps_confidence,
        bdp_bytes: windows.bdp_bytes,
        bdp_packets: windows.bdp_packets,
        required_window_packets: windows.required_window_packets,
        configured_flow_window_packets: input.protocol.flow_window_packets,
        configured_receive_window_packets: input.protocol.receive_window_packets,
        flow_window_utilization: windows.flow_window_utilization,
        receive_window_utilization: windows.receive_window_utilization,
        flow_window_headroom_packets: windows.flow_window_headroom_packets,
        receive_window_headroom_packets: windows.receive_window_headroom_packets,
        guarded_rtt_ms: recovery.guarded_rtt_ms,
        tsbpd_latency_ms: input.protocol.tsbpd_latency_ms as f64,
        one_repair_margin_ms: recovery.one_repair_margin_ms,
        approximate_repair_rounds_available: recovery.approximate_repair_rounds_available,
        requested_receive_socket_buffer_horizon_seconds: recovery
            .requested_receive_socket_buffer_horizon_seconds,
        requested_send_socket_buffer_horizon_seconds: recovery
            .requested_send_socket_buffer_horizon_seconds,
        effective_receive_socket_buffer_horizon_seconds: recovery
            .effective_receive_socket_buffer_horizon_seconds,
        effective_send_socket_buffer_horizon_seconds: recovery
            .effective_send_socket_buffer_horizon_seconds,
        host_packet_work_pps: resources.host_packet_work_pps,
        host_pps_utilization: resources.host_pps_utilization,
        nic_utilization: resources.nic_utilization,
        estimated_max_resource_utilization: resources.estimated_max_resource_utilization,
        admission_waves: resources.admission_waves,
    };

    let reasons = collect_reasons(&input, &policy, &derived);
    let class = classify_reasons(&reasons);

    Ok(CapacityAssessment {
        class,
        reasons,
        derived,
        input,
        policy_revision: policy.revision,
    })
}

fn collect_reasons(
    input: &CapacityInput,
    policy: &ClassifierPolicy,
    derived: &DerivedLoad,
) -> Vec<CapacityReason> {
    let mut reasons = Vec::new();
    add_pacing_reasons(input, derived, &mut reasons);
    add_window_reasons(input, policy, derived, &mut reasons);
    add_recovery_reasons(policy, derived, &mut reasons);
    add_network_reasons(input, derived, &mut reasons);
    add_socket_reasons(input, policy, derived, &mut reasons);
    add_host_reasons(input, policy, derived, &mut reasons);
    add_nic_reasons(input, policy, derived, &mut reasons);
    add_policy_reasons(policy, derived, &mut reasons);
    reasons
}

fn add_pacing_reasons(
    input: &CapacityInput,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    if input.workload.payload_bytes
        > shiguredo_srt::DEFAULT_MTU as u64 - shiguredo_srt::SRT_HEADER_SIZE as u64
    {
        reasons.push(CapacityReason::PayloadExceedsProtocolMtu);
    }
    if let Availability::Known(capacity) = derived.pacing_payload_capacity_bps
        && input.workload.source_bps_per_stream as f64 > capacity
    {
        reasons.push(CapacityReason::SourceExceedsPacingEnvelope);
    }
    if let (Availability::Known(expected), Availability::Known(capacity)) = (
        derived.expected_data_pps,
        derived.pacing_payload_capacity_bps,
    ) {
        let multiplier = derived.physical_data_pps / derived.source_pps_total;
        let required_pacing = expected * derived.pacing_packet_bytes as f64 * 8.0;
        let pacing_capacity = capacity * input.workload.source_streams as f64 * multiplier;
        if required_pacing > pacing_capacity {
            reasons.push(CapacityReason::ProtocolOverheadExceedsPacingHeadroom);
        }
    }
}

fn add_window_reasons(
    input: &CapacityInput,
    policy: &ClassifierPolicy,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    if let Availability::Known(required) = derived.required_window_packets
        && (required > f64::from(input.protocol.flow_window_packets)
            || required > f64::from(input.protocol.receive_window_packets))
    {
        reasons.push(CapacityReason::WindowBelowBdpRequirement);
    } else if let (Availability::Known(flow), Availability::Known(receive)) = (
        derived.flow_window_headroom_packets,
        derived.receive_window_headroom_packets,
    ) && (flow < policy.minimum_window_headroom_packets
        || receive < policy.minimum_window_headroom_packets)
    {
        reasons.push(CapacityReason::WindowHeadroomLow);
    }
}

fn add_recovery_reasons(
    policy: &ClassifierPolicy,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    if let Availability::Known(margin) = derived.one_repair_margin_ms
        && margin < policy.minimum_recovery_margin_ms
    {
        reasons.push(CapacityReason::RecoveryMarginInsufficient);
    }
}

fn add_network_reasons(
    input: &CapacityInput,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    if input.network.expected_rtt == Availability::Unknown {
        reasons.push(CapacityReason::ExpectedRttUnknown);
    }
    if input.network.rtt_jitter == Availability::Unknown {
        reasons.push(CapacityReason::RttVarianceUnknown);
    }
    if input.network.expected_loss_probability == Availability::Unknown {
        reasons.push(CapacityReason::ExpectedLossUnknown);
    }
    if input.network.expected_reorder_probability == Availability::Unknown {
        reasons.push(CapacityReason::ExpectedReorderUnknown);
    }
    if matches!(
        derived.control_pps_confidence,
        ControlPpsConfidence::ExpectedLoss | ControlPpsConfidence::Unknown
    ) {
        reasons.push(CapacityReason::ControlRateUncertain);
    }
}

fn add_socket_reasons(
    input: &CapacityInput,
    policy: &ClassifierPolicy,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    if input.host.effective_receive_socket_buffer_bytes == Availability::Unknown
        || input.host.effective_send_socket_buffer_bytes == Availability::Unknown
    {
        reasons.push(CapacityReason::EffectiveSocketBufferUnknown);
    }
    if let (Availability::Known(receive), Availability::Known(send)) = (
        derived.effective_receive_socket_buffer_horizon_seconds,
        derived.effective_send_socket_buffer_horizon_seconds,
    ) && (receive < policy.minimum_socket_horizon_seconds
        || send < policy.minimum_socket_horizon_seconds)
    {
        reasons.push(CapacityReason::SocketBufferHorizonLow);
    }
}

fn add_host_reasons(
    input: &CapacityInput,
    policy: &ClassifierPolicy,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    match (input.host.host_pps_capacity, derived.host_pps_utilization) {
        (Availability::Unknown, _) => reasons.push(CapacityReason::HostPpsCapacityUnknown),
        (Availability::Known(_), Availability::Unknown) => {
            reasons.push(CapacityReason::PredictedPacketWorkUnknown)
        }
        (Availability::Known(_), Availability::Known(utilization)) if utilization > 1.0 => {
            reasons.push(CapacityReason::HostPpsCapacityExceeded)
        }
        (Availability::Known(_), Availability::Known(utilization))
            if utilization >= policy.max_host_pps_utilization =>
        {
            reasons.push(CapacityReason::HostPpsHeadroomLow)
        }
        _ => {}
    }
}

fn add_nic_reasons(
    input: &CapacityInput,
    policy: &ClassifierPolicy,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    match (
        input.host.nic_capacity_bps,
        derived.nic_wire_bps,
        derived.nic_utilization,
    ) {
        (Availability::Unknown, _, _) => reasons.push(CapacityReason::NicCapacityUnknown),
        (Availability::Known(_), Availability::Unknown, _) => {
            reasons.push(CapacityReason::NicWireRateUnknown)
        }
        (Availability::Known(_), Availability::Known(_), Availability::Known(utilization))
            if utilization > 1.0 =>
        {
            reasons.push(CapacityReason::NicCapacityExceeded)
        }
        (Availability::Known(_), Availability::Known(_), Availability::Known(utilization))
            if utilization >= policy.max_nic_utilization =>
        {
            reasons.push(CapacityReason::NicHeadroomLow)
        }
        _ => {}
    }
}

fn add_policy_reasons(
    policy: &ClassifierPolicy,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    if let (Some(limit), Availability::Known(control)) =
        (policy.max_control_pps, derived.control_pps_est)
        && control > limit
    {
        reasons.push(CapacityReason::ExpectedControlRateHigh);
    }
    if let Some(limit) = policy.max_admission_waves
        && derived.admission_waves > limit
    {
        reasons.push(CapacityReason::AdmissionConcurrencyHigh);
    }
}

fn classify_reasons(reasons: &[CapacityReason]) -> CellClass {
    if reasons
        .iter()
        .any(|reason| reason.severity() == ReasonSeverity::Hard)
    {
        CellClass::ExceedsEnvelope
    } else if reasons
        .iter()
        .any(|reason| reason.severity() == ReasonSeverity::Diagnostic)
    {
        CellClass::DiagnosticControl
    } else if reasons.is_empty() {
        CellClass::ProductionCandidate
    } else {
        CellClass::Conditional
    }
}

fn validate(input: &CapacityInput, policy: &ClassifierPolicy) -> Result<(), ModelError> {
    validate_workload(input)?;
    validate_protocol(input)?;
    validate_network(input)?;
    validate_policy(policy)
}

fn validate_workload(input: &CapacityInput) -> Result<(), ModelError> {
    let w = &input.workload;
    if w.source_bps_per_stream == 0
        || w.source_streams == 0
        || w.physical_connections == 0
        || w.logical_streams == 0
        || w.payload_bytes == 0
        || w.duration.is_zero()
    {
        return Err(ModelError(
            "workload rates, counts, payload, and duration must be positive".to_string(),
        ));
    }
    if w.physical_connections < w.logical_streams {
        return Err(ModelError(
            "physical_connections must be at least logical_streams".to_string(),
        ));
    }
    Ok(())
}

fn validate_protocol(input: &CapacityInput) -> Result<(), ModelError> {
    if input.protocol.flow_window_packets == 0 || input.protocol.receive_window_packets == 0 {
        return Err(ModelError(
            "window sizes must be positive packet counts".to_string(),
        ));
    }
    if input.admission.connect_cc == 0 {
        return Err(ModelError("connect_cc must be positive".to_string()));
    }
    if input.host.socket_fan_in == 0 || input.host.workers == 0 {
        return Err(ModelError(
            "socket_fan_in and workers must be positive".to_string(),
        ));
    }
    match input.protocol.bandwidth {
        SrtBandwidthPolicy::FixedBps(0) => Err(ModelError(
            "fixed pacing bandwidth must be positive".to_string(),
        )),
        SrtBandwidthPolicy::InputRelative { overhead_percent }
            if !(5..=100).contains(&overhead_percent) =>
        {
            Err(ModelError(
                "input-relative overhead must be between 5 and 100 percent".to_string(),
            ))
        }
        _ => Ok(()),
    }
}

fn validate_network(input: &CapacityInput) -> Result<(), ModelError> {
    if let Availability::Known(loss) = input.network.expected_loss_probability
        && !(0.0..1.0).contains(&loss)
    {
        return Err(ModelError(
            "expected loss probability must satisfy 0 <= p < 1".to_string(),
        ));
    }
    if let Availability::Known(reorder) = input.network.expected_reorder_probability
        && !(0.0..=1.0).contains(&reorder)
    {
        return Err(ModelError(
            "expected reorder probability must satisfy 0 <= p <= 1".to_string(),
        ));
    }
    Ok(())
}

fn validate_policy(policy: &ClassifierPolicy) -> Result<(), ModelError> {
    if policy.minimum_window_headroom_packets < 0.0
        || policy.minimum_recovery_margin_ms < 0.0
        || policy.minimum_socket_horizon_seconds < 0.0
        || !(0.0..=1.0).contains(&policy.max_host_pps_utilization)
        || !(0.0..=1.0).contains(&policy.max_nic_utilization)
    {
        return Err(ModelError(
            "classifier policy thresholds are invalid".to_string(),
        ));
    }
    Ok(())
}

trait MapKnown<T> {
    fn map_known<U>(self, f: impl FnOnce(T) -> U) -> Availability<U>;
}

impl<T> MapKnown<T> for Availability<T> {
    fn map_known<U>(self, f: impl FnOnce(T) -> U) -> Availability<U> {
        match self {
            Self::Known(value) => Availability::Known(f(value)),
            Self::Unknown => Availability::Unknown,
            Self::NotApplicable => Availability::NotApplicable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known_input() -> CapacityInput {
        CapacityInput {
            protocol: ProtocolEnvelope {
                bandwidth: SrtBandwidthPolicy::ProtocolDefault,
                ..ProtocolEnvelope::default()
            },
            network: NetworkEnvelope {
                expected_rtt: Availability::Known(Duration::from_millis(1)),
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

    #[test]
    fn source_streams_not_physical_connections_drives_source_pps() {
        let mut input = known_input();
        input.workload.physical_connections = 2;
        input.workload.logical_streams = 1;
        input.workload.source_streams = 1;
        input.protocol.bond = BondMode::Broadcast;
        let assessment = assess(input, ClassifierPolicy::default()).expect("valid model");
        assert_eq!(
            assessment.derived.source_pps_total,
            assessment.derived.source_pps_per_stream
        );
        assert_eq!(
            assessment.derived.physical_data_pps,
            assessment.derived.source_pps_total * 2.0
        );
    }

    #[test]
    fn unknown_capacity_is_not_zero_or_infinite() {
        let input = CapacityInput::default();
        let assessment = assess(input, ClassifierPolicy::default()).expect("valid model");
        assert!(matches!(
            assessment.derived.host_pps_utilization,
            Availability::Unknown
        ));
        assert!(
            assessment
                .reasons
                .contains(&CapacityReason::HostPpsCapacityUnknown)
        );
    }

    #[test]
    fn loopback_nic_is_not_applicable() {
        let mut input = known_input();
        input.host.nic_capacity_bps = Availability::NotApplicable;
        let assessment = assess(input, ClassifierPolicy::default()).expect("valid model");
        assert_eq!(
            assessment.derived.nic_utilization,
            Availability::NotApplicable
        );
        assert!(
            !assessment
                .reasons
                .contains(&CapacityReason::NicCapacityUnknown)
        );
    }

    #[test]
    fn retransmission_factor_is_geometric_expectation() {
        let mut input = known_input();
        input.network.expected_loss_probability = Availability::Known(0.01);
        let assessment = assess(input, ClassifierPolicy::default()).expect("valid model");
        let Availability::Known(factor) = assessment.derived.retransmission_factor else {
            panic!("factor should be known")
        };
        assert!((factor - 1.0101010101).abs() < 1e-9);
    }

    #[test]
    fn latency_shorter_than_guarded_rtt_is_conditional() {
        let mut input = known_input();
        input.network.expected_rtt = Availability::Known(Duration::from_millis(120));
        input.protocol.tsbpd_latency_ms = 20;
        let assessment = assess(input, ClassifierPolicy::default()).expect("valid model");
        assert_eq!(assessment.class, CellClass::Conditional);
        assert!(
            assessment
                .reasons
                .contains(&CapacityReason::RecoveryMarginInsufficient)
        );
        assert_eq!(
            assessment.derived.one_repair_margin_ms,
            Availability::Known(-100.0)
        );
    }

    #[test]
    fn fixed_pacing_over_source_is_diagnostic_not_hard_failure() {
        let mut input = known_input();
        input.protocol.bandwidth = SrtBandwidthPolicy::FixedBps(4_000_000);
        let assessment = assess(input, ClassifierPolicy::default()).expect("valid model");
        assert_eq!(assessment.class, CellClass::DiagnosticControl);
        assert!(
            assessment
                .reasons
                .contains(&CapacityReason::SourceExceedsPacingEnvelope)
        );
    }

    #[test]
    fn window_above_bdp_is_exactly_usable_at_the_boundary() {
        let mut input = known_input();
        input.workload.source_bps_per_stream = 8_000_000;
        input.protocol.bandwidth = SrtBandwidthPolicy::ProtocolDefault;
        input.network.expected_rtt = Availability::Known(Duration::from_millis(10));
        let baseline = assess(input.clone(), ClassifierPolicy::default()).expect("valid model");
        let Availability::Known(required) = baseline.derived.required_window_packets else {
            panic!("BDP should be known")
        };
        input.protocol.flow_window_packets = required as u32;
        input.protocol.receive_window_packets = required as u32;
        let boundary = assess(input.clone(), ClassifierPolicy::default()).expect("valid model");
        assert!(
            !boundary
                .reasons
                .contains(&CapacityReason::WindowBelowBdpRequirement)
        );
        input.protocol.flow_window_packets = required as u32 - 1;
        let below = assess(input, ClassifierPolicy::default()).expect("valid model");
        assert!(
            below
                .reasons
                .contains(&CapacityReason::WindowBelowBdpRequirement)
        );
    }
}
