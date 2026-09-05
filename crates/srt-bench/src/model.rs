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

    /// Authentication-tag bytes a DATA packet carries.
    ///
    /// This is a property of the CIPHER MODE, not of the key length.
    /// `EncryptionMode` selects AES-128/192/256 -- `Encryption::apply_to`
    /// sets `key_length` and the passphrase and nothing else -- while the
    /// protocol's `ConnectionOptions` default is `CipherMode::Ctr`, which
    /// authenticates nothing and appends no tag. Charging `GCM_TAG_LEN` to
    /// every encrypted cell added 16 bytes per packet that the
    /// implementation never emits, inflating the MTU check, the SRT DATA
    /// wire rate and the UDP/IP rate.
    #[must_use]
    const fn tag_bytes(self, cipher: shiguredo_srt::CipherMode) -> u64 {
        match (self, cipher) {
            (Self::Plain, _) => 0,
            (_, shiguredo_srt::CipherMode::Ctr) => 0,
            (_, shiguredo_srt::CipherMode::Gcm) => shiguredo_srt::GCM_TAG_LEN as u64,
        }
    }
}

/// The windows `SrtConnection` will actually run with, given what was asked
/// for.
///
/// `normalize_options` clamps the flow window into
/// `[shiguredo_srt::MIN_FLOW_WINDOW_PACKETS, MAX_FLOW_WINDOW]` and then clamps the receive
/// window to at least the minimum and at most the flow window. Classifying
/// against the REQUESTED values reproduced the exact requested-versus-
/// effective confusion this model already fixes for socket buffers: asking
/// for a 1-packet flow window and being given 32, or asking for 100000 and
/// being given 65536, changed the BDP headroom answer.
#[must_use]
pub const fn effective_windows(flow_requested: u32, receive_requested: u32) -> (u32, u32) {
    let flow = if flow_requested < shiguredo_srt::MIN_FLOW_WINDOW_PACKETS {
        shiguredo_srt::MIN_FLOW_WINDOW_PACKETS
    } else if flow_requested > shiguredo_srt::MAX_FLOW_WINDOW {
        shiguredo_srt::MAX_FLOW_WINDOW
    } else {
        flow_requested
    };
    let receive = if receive_requested < shiguredo_srt::MIN_FLOW_WINDOW_PACKETS {
        shiguredo_srt::MIN_FLOW_WINDOW_PACKETS
    } else {
        receive_requested
    };
    (flow, if receive > flow { flow } else { receive })
}

/// The size SRT's own pacer measures: SRT header plus PLAINTEXT payload.
///
/// This deliberately excludes the GCM tag and the IP/UDP headers.
/// `SrtSender::recompute_packet_send_period` computes
/// `avg_payload_size + SRT_HEADER_SIZE`, and updates that average with the
/// plaintext `payload_len`; tag materialization happens later, at the
/// connection layer. Charging the tag against pacing would predict a pacing
/// constraint the sender does not impose, and could give an AES cell a
/// spurious `SourceExceedsPacingEnvelope`.
#[must_use]
pub const fn pacing_packet_size_bytes(payload_bytes: u64) -> u64 {
    shiguredo_srt::SRT_HEADER_SIZE as u64 + payload_bytes
}

/// Encoded IPv4/UDP/SRT DATA packet size, including an optional GCM tag.
/// `udp_ip_header_bytes` is part of the configured IP MTU budget.
///
/// Three sizes exist and must not be conflated:
/// - pacing:      SRT header + plaintext payload ([`pacing_packet_size_bytes`])
/// - SRT DATA:    SRT header + payload + GCM tag when encrypted
/// - IPv4 packet: IP + UDP + SRT DATA
#[must_use]
pub const fn encoded_packet_size_bytes(
    payload_bytes: u64,
    encryption: EncryptionMode,
    cipher: shiguredo_srt::CipherMode,
    udp_ip_header_bytes: u64,
) -> u64 {
    udp_ip_header_bytes
        + shiguredo_srt::SRT_HEADER_SIZE as u64
        + payload_bytes
        + encryption.tag_bytes(cipher)
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
    /// AES key length. Independent of the cipher mode: this selects
    /// 128/192/256-bit keys and says nothing about authentication.
    pub encryption: EncryptionMode,
    /// Cipher mode, which is what decides whether a DATA packet carries an
    /// authentication tag. The protocol default is `Ctr`, which carries
    /// none; srt-bench never selects `Gcm`.
    pub cipher_mode: shiguredo_srt::CipherMode,
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
            // Matches `ConnectionOptions`' own default; srt-bench never
            // negotiates GCM.
            cipher_mode: shiguredo_srt::CipherMode::Ctr,
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
            nic_link_overhead_bytes: Availability::Unknown,
        }
    }
}

/// Requested socket-buffer semantics. The OS default is not a zero-byte
/// buffer, so it must remain distinct from an explicit byte count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketBufferRequest {
    SystemDefault,
    Bytes(u64),
}

impl SocketBufferRequest {
    #[must_use]
    pub const fn from_bytes(bytes: u64) -> Self {
        if bytes == 0 {
            Self::SystemDefault
        } else {
            Self::Bytes(bytes)
        }
    }
}

/// One endpoint's host/deployment envelope. Socket capacities are deliberately
/// not inferred from a request: the effective values are a separate input.
#[derive(Clone, Debug, PartialEq)]
pub struct EndpointEnvelope {
    /// Requested receive socket buffer (bytes).
    pub requested_receive_socket_buffer_bytes: SocketBufferRequest,
    /// Requested send socket buffer (bytes).
    pub requested_send_socket_buffer_bytes: SocketBufferRequest,
    /// Effective receive socket buffer (bytes).
    pub effective_receive_socket_buffer_bytes: Availability<u64>,
    /// Effective send socket buffer (bytes).
    pub effective_send_socket_buffer_bytes: Availability<u64>,
    /// Peers sharing one receive-side host UDP socket.
    pub rx_socket_fan_in: u64,
    /// Peers sharing one send-side host UDP socket.
    pub tx_socket_fan_in: u64,
    /// Host packet-processing capacity (packets/s), if defensibly known.
    pub host_pps_capacity: Availability<f64>,
    /// Physical NIC capacity (bits/s), or NotApplicable for loopback.
    pub nic_capacity_bps: Availability<u64>,
    /// Descriptive CPU allocation/set.
    pub cpu_allocation: String,
    /// Worker topology count.
    pub workers: u64,
}

impl Default for EndpointEnvelope {
    fn default() -> Self {
        Self {
            requested_receive_socket_buffer_bytes: SocketBufferRequest::SystemDefault,
            requested_send_socket_buffer_bytes: SocketBufferRequest::SystemDefault,
            effective_receive_socket_buffer_bytes: Availability::Unknown,
            effective_send_socket_buffer_bytes: Availability::Unknown,
            rx_socket_fan_in: 1,
            tx_socket_fan_in: 1,
            host_pps_capacity: Availability::Unknown,
            nic_capacity_bps: Availability::Unknown,
            cpu_allocation: "unspecified".to_string(),
            workers: 1,
        }
    }
}

/// Compatibility name for callers that only need one endpoint fixture.
pub type HostEnvelope = EndpointEnvelope;

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
    pub sender: EndpointEnvelope,
    pub receiver: EndpointEnvelope,
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

impl ClassifierPolicy {
    /// Stable identity for the complete policy content, not only its label.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let optional_f64 = |value: Option<f64>| {
            value.map_or_else(|| "none".to_string(), |value| format!("{value:.17}"))
        };
        let optional_u64 = |value: Option<u64>| {
            value.map_or_else(|| "none".to_string(), |value| value.to_string())
        };
        format!(
            "revision={};window={:.17};recovery={:.17};socket={:.17};host={:.17};nic={:.17};control={};waves={}",
            self.revision,
            self.minimum_window_headroom_packets,
            self.minimum_recovery_margin_ms,
            self.minimum_socket_horizon_seconds,
            self.max_host_pps_utilization,
            self.max_nic_utilization,
            optional_f64(self.max_control_pps),
            optional_u64(self.max_admission_waves),
        )
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
    PayloadExceedsIpv4MtuEnvelope,
    SourceExceedsPacingEnvelope,
    ProtocolOverheadExceedsPacingHeadroom,
    WindowBelowBdpRequirement,
    WindowHeadroomLow,
    RecoveryMarginInsufficient,
    ExpectedRttUnknown,
    RttVarianceUnknown,
    ExpectedLossUnknown,
    ReorderImpactUnmodeled,
    BondLegDistributionUnknown,
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
    AdmissionWavesHigh,
}

const REASON_CODES: &[&str] = &[
    "payload_exceeds_protocol_mtu",
    "payload_exceeds_ipv4_mtu_envelope",
    "source_exceeds_pacing_envelope",
    "protocol_overhead_exceeds_pacing_headroom",
    "window_below_bdp_requirement",
    "window_headroom_low",
    "recovery_margin_insufficient",
    "expected_rtt_unknown",
    "rtt_variance_unknown",
    "expected_loss_unknown",
    "reorder_impact_unmodeled",
    "bond_leg_distribution_unknown",
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
    "admission_waves_high",
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
            | Self::PayloadExceedsIpv4MtuEnvelope
            | Self::WindowBelowBdpRequirement
            | Self::HostPpsCapacityExceeded
            | Self::NicCapacityExceeded => ReasonSeverity::Hard,
            Self::SourceExceedsPacingEnvelope | Self::ProtocolOverheadExceedsPacingHeadroom => {
                ReasonSeverity::Diagnostic
            }
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
    pub physical_data_pps_per_leg: Availability<f64>,
    pub expected_data_pps: Availability<f64>,
    pub expected_data_pps_per_leg: Availability<f64>,
    pub payload_bps: f64,
    pub srt_data_packet_bytes: u64,
    pub pacing_packet_bytes: u64,
    pub pacing_payload_capacity_bps: Availability<f64>,
    pub pacing_headroom_bps: Availability<f64>,
    pub retransmission_factor: Availability<f64>,
    pub retransmission_excess: Availability<f64>,
    pub srt_data_bps: Availability<f64>,
    pub srt_data_bps_per_leg: Availability<f64>,
    pub srt_control_bps: Availability<f64>,
    pub srt_total_bps: Availability<f64>,
    pub udp_ip_bps: Availability<f64>,
    pub nic_wire_bps: Availability<f64>,
    pub full_ack_pps_est: f64,
    pub light_ack_pps_est: Availability<f64>,
    pub ack_pps_est: Availability<f64>,
    pub ackack_pps_est: f64,
    pub nak_pps_est: Availability<f64>,
    pub keepalive_pps_est: f64,
    pub control_pps_est: Availability<f64>,
    pub control_pps_confidence: ControlPpsConfidence,
    pub bdp_bytes: Availability<f64>,
    pub bdp_packets: Availability<f64>,
    pub required_window_packets: Availability<f64>,
    pub bdp_bytes_per_leg: Availability<f64>,
    pub bdp_packets_per_leg: Availability<f64>,
    pub required_window_packets_per_leg: Availability<f64>,
    /// What the operator asked for.
    pub configured_flow_window_packets: u32,
    /// What `SrtConnection` will actually run with after clamping. Window
    /// classification uses these, not the requested values.
    pub effective_flow_window_packets: u32,
    pub effective_receive_window_packets: u32,
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
    pub sender_host_packet_work_pps: Availability<f64>,
    pub receiver_host_packet_work_pps: Availability<f64>,
    pub host_pps_utilization: Availability<f64>,
    pub sender_host_pps_utilization: Availability<f64>,
    pub receiver_host_pps_utilization: Availability<f64>,
    pub nic_utilization: Availability<f64>,
    pub sender_nic_utilization: Availability<f64>,
    pub receiver_nic_utilization: Availability<f64>,
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
    /// The operator-supplied policy label. Free-form, so two different
    /// threshold sets can claim the same revision.
    pub policy_revision: String,
    /// Canonical serialization of every policy threshold that produced this
    /// assessment. Unlike the revision label this identifies policy CONTENT,
    /// so a persisted prediction cannot be reinterpreted under a different
    /// threshold set wearing the same name.
    pub policy_fingerprint: String,
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

fn multiply_availability(a: Availability<f64>, b: Availability<f64>) -> Availability<f64> {
    match (a, b) {
        (Availability::Known(a), Availability::Known(b)) => Availability::Known(a * b),
        (Availability::NotApplicable, Availability::NotApplicable) => Availability::NotApplicable,
        _ => Availability::Unknown,
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

fn horizon_for(bytes: Availability<u64>, bitrate_bps: Availability<f64>) -> Availability<f64> {
    match bitrate_bps {
        Availability::Known(bitrate_bps) => horizon(bytes, bitrate_bps),
        Availability::Unknown => Availability::Unknown,
        Availability::NotApplicable => Availability::NotApplicable,
    }
}

fn requested_horizon(
    request: SocketBufferRequest,
    bitrate_bps: Availability<f64>,
) -> Availability<f64> {
    match request {
        SocketBufferRequest::SystemDefault => Availability::Unknown,
        SocketBufferRequest::Bytes(bytes) => horizon_for(Availability::Known(bytes), bitrate_bps),
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
    physical_data_pps_per_leg: Availability<f64>,
    payload_bps: f64,
    srt_header_bytes: u64,
    pacing_packet_bytes: u64,
    srt_data_packet_bytes: u64,
    pacing_payload_capacity_bps: Availability<f64>,
    pacing_headroom_bps: Availability<f64>,
    retransmission_factor: Availability<f64>,
    retransmission_excess: Availability<f64>,
    expected_data_pps: Availability<f64>,
    expected_data_pps_per_leg: Availability<f64>,
    srt_data_bps: Availability<f64>,
    srt_data_bps_per_leg: Availability<f64>,
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
    let physical_data_pps_per_leg = match p.bond {
        BondMode::None => Availability::Known(physical_data_pps / w.physical_connections as f64),
        // Broadcast sends every packet on every leg, so each leg really does
        // carry the full stream rate.
        BondMode::Broadcast
            if w.source_streams == w.logical_streams
                && w.physical_connections.is_multiple_of(w.logical_streams) =>
        {
            Availability::Known(source_pps_per_stream)
        }
        // Backup sends on ONE leg at a time. `source_pps_per_stream` is the
        // hot leg's peak, which is the right number for BDP and window
        // sizing, but it is not a distribution: multiplying it by every
        // physical connection would charge each standby leg the active leg's
        // data-dependent ACK work. The peak stays known for windows; control
        // PPS is left Unknown until leg activity is actually modelled.
        BondMode::Backup
            if w.source_streams == w.logical_streams
                && w.physical_connections.is_multiple_of(w.logical_streams) =>
        {
            Availability::Known(source_pps_per_stream)
        }
        BondMode::Broadcast | BondMode::Backup => Availability::Unknown,
    };
    let payload_bps = w.source_bps_per_stream as f64 * w.source_streams as f64;
    let srt_header_bytes = shiguredo_srt::SRT_HEADER_SIZE as u64;
    // Pacing and the SRT DATA wire size are different layers: the pacer never
    // sees the GCM tag.
    let pacing_packet_bytes = pacing_packet_size_bytes(w.payload_bytes);
    let srt_data_packet_bytes =
        encoded_packet_size_bytes(w.payload_bytes, p.encryption, p.cipher_mode, 0);
    let pacing_bytes_per_second = pacing_bytes_per_second(p, w.source_bps_per_stream);
    let pacing_capacity_per_stream =
        pacing_bytes_per_second / pacing_packet_bytes as f64 * w.payload_bytes as f64 * 8.0;
    let pacing_payload_capacity_bps = Availability::Known(pacing_capacity_per_stream);
    let pacing_headroom_bps =
        Availability::Known(pacing_capacity_per_stream - w.source_bps_per_stream as f64);
    let (retransmission_factor, retransmission_excess) =
        retransmission_values(input.network.expected_loss_probability);
    let expected_data_pps = multiply_known(retransmission_factor, physical_data_pps);
    let expected_data_pps_per_leg =
        multiply_availability(retransmission_factor, physical_data_pps_per_leg);
    let srt_data_bps = multiply_known(expected_data_pps, srt_data_packet_bytes as f64 * 8.0);
    let srt_data_bps_per_leg = multiply_known(
        expected_data_pps_per_leg,
        srt_data_packet_bytes as f64 * 8.0,
    );
    CoreRates {
        source_pps_per_stream,
        source_pps_total,
        physical_data_pps,
        physical_data_pps_per_leg,
        payload_bps,
        srt_header_bytes,
        pacing_packet_bytes,
        srt_data_packet_bytes,
        pacing_payload_capacity_bps,
        pacing_headroom_bps,
        retransmission_factor,
        retransmission_excess,
        expected_data_pps,
        expected_data_pps_per_leg,
        srt_data_bps,
        srt_data_bps_per_leg,
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
    light_ack_pps_est: Availability<f64>,
    ack_pps_est: Availability<f64>,
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
    // Consume the TYPED per-leg rate rather than re-deriving an average.
    // `max(timer_cadence, leg_rate / 64)` is not linear, so applying it to the
    // mean leg rate is not the same as summing it over legs -- for a Backup
    // bond with one hot and one idle leg the two differ materially. When leg
    // distribution is Unknown the ACK estimate must be Unknown too, not a
    // quietly averaged number that later presents as Known host/NIC
    // utilization.
    let ack_interval_s = p.ack_interval.as_secs_f64();
    let full_ack_pps_est = physical_connections / ack_interval_s;
    // Backup's per-leg rate is the HOT leg's peak, not a distribution across
    // legs, so multiplying it by every physical connection would charge each
    // standby leg the active leg's data-dependent ACK work. Until leg
    // activity is modelled, the data-dependent part of control is Unknown for
    // Backup; the peak remains usable for BDP and window sizing.
    let leg_rate_for_control = match p.bond {
        BondMode::Backup => Availability::Unknown,
        BondMode::None | BondMode::Broadcast => core.physical_data_pps_per_leg,
    };
    let ack_pps_est = match leg_rate_for_control {
        Availability::Known(data_pps_per_leg) => {
            let ack_pps_per_leg = (1.0 / ack_interval_s)
                .max(data_pps_per_leg / f64::from(p.light_ack_interval_packets));
            Availability::Known(physical_connections * ack_pps_per_leg)
        }
        Availability::Unknown => Availability::Unknown,
        Availability::NotApplicable => Availability::NotApplicable,
    };
    let light_ack_pps_est = ack_pps_est.map_known(|ack| (ack - full_ack_pps_est).max(0.0));
    let ackack_pps_est = full_ack_pps_est;
    let keepalive_pps_est = physical_connections / p.keepalive_interval.as_secs_f64();
    let nak_pps_est = match loss {
        Availability::Known(loss) if p.periodic_nak_enabled => {
            Availability::Known(core.physical_data_pps * loss)
        }
        Availability::Known(_) | Availability::NotApplicable => Availability::Known(0.0),
        Availability::Unknown => Availability::Unknown,
    };
    let control_pps_est = match (ack_pps_est, nak_pps_est) {
        (Availability::Known(ack), Availability::Known(nak)) => {
            Availability::Known(ack + ackack_pps_est + keepalive_pps_est + nak)
        }
        (Availability::NotApplicable, _) | (_, Availability::NotApplicable) => {
            Availability::NotApplicable
        }
        _ => Availability::Unknown,
    };
    // Confidence describes the AGGREGATE estimate, so it has to follow that
    // estimate rather than the loss input alone. A zero-loss Backup cell has
    // an Unknown control rate (leg activity is not modelled) yet would have
    // reported CadenceBound -- contradictory public fields, and worse,
    // `control_rate_uncertain` is emitted from confidence, so an unknown
    // control rate could escape without any uncertainty reason once the host
    // and NIC checks are NotApplicable.
    let control_pps_confidence = if control_pps_est == Availability::Unknown {
        ControlPpsConfidence::Unknown
    } else {
        match loss {
            Availability::Known(loss) if loss > 0.0 => ControlPpsConfidence::ExpectedLoss,
            Availability::Known(_) | Availability::NotApplicable => {
                ControlPpsConfidence::CadenceBound
            }
            Availability::Unknown => ControlPpsConfidence::Unknown,
        }
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
    light_ack_pps: Availability<f64>,
    full_ack_pps: f64,
    ackack_pps: f64,
    nak_pps: Availability<f64>,
    keepalive_pps: f64,
    control_pps: Availability<f64>,
) -> Availability<f64> {
    match (light_ack_pps, nak_pps, control_pps) {
        (
            Availability::Known(light_ack_pps),
            Availability::Known(nak),
            Availability::Known(control),
        ) => {
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
        (Availability::NotApplicable, _, _) | (_, _, Availability::NotApplicable) => {
            Availability::NotApplicable
        }
        _ => Availability::Unknown,
    }
}

#[derive(Clone, Copy)]
struct NetworkRates {
    srt_total_bps: Availability<f64>,
    packet_pps: Availability<f64>,
    udp_ip_bps: Availability<f64>,
    nic_wire_bps: Availability<f64>,
    /// Forward (sender -> receiver) DATA at the NIC layer.
    data_nic_wire_bps: Availability<f64>,
    /// Reverse (receiver -> sender) control at the NIC layer.
    control_nic_wire_bps: Availability<f64>,
}

fn derive_network(input: &CapacityInput, core: CoreRates, control: ControlRates) -> NetworkRates {
    let srt_total_bps = known_sum(core.srt_data_bps, control.srt_control_bps);
    let packet_pps = packet_rate_for_control(core.expected_data_pps, control.control_pps_est);
    let data_udp_ip_bps = multiply_known(
        core.expected_data_pps,
        encoded_packet_size_bytes(
            input.workload.payload_bytes,
            input.protocol.encryption,
            input.protocol.cipher_mode,
            input.network.udp_ip_header_bytes,
        ) as f64
            * 8.0,
    );
    let control_udp_ip_bps = add_optional_bytes(
        control.srt_control_bps,
        control.control_pps_est,
        input.network.udp_ip_header_bytes,
    );
    let udp_ip_bps = known_sum(data_udp_ip_bps, control_udp_ip_bps);
    let nic_applicable = !matches!(
        (
            input.sender.nic_capacity_bps,
            input.receiver.nic_capacity_bps,
        ),
        (Availability::NotApplicable, Availability::NotApplicable)
    );
    let at_nic = |bps: Availability<f64>, pps: Availability<f64>| -> Availability<f64> {
        if !nic_applicable {
            return Availability::NotApplicable;
        }
        match input.network.nic_link_overhead_bytes {
            Availability::Known(overhead) => add_optional_bytes(bps, pps, overhead),
            Availability::Unknown => Availability::Unknown,
            Availability::NotApplicable => Availability::NotApplicable,
        }
    };
    // Directional, because a conventional NIC is full duplex: a 10 GbE port
    // carries ~10 Gb/s of TX and ~10 Gb/s of RX at the same time, and is not
    // a single 10 Gb/s bidirectional budget. Summing DATA and reverse control
    // into one bucket let 9.5 Gb/s of TX plus 0.8 Gb/s of RX report 103% and
    // raise a HARD NicCapacityExceeded, which is a false ExceedsEnvelope.
    let data_nic_wire_bps = at_nic(data_udp_ip_bps, core.expected_data_pps);
    let control_nic_wire_bps = at_nic(control_udp_ip_bps, control.control_pps_est);
    let nic_wire_bps = at_nic(udp_ip_bps, packet_pps);
    NetworkRates {
        srt_total_bps,
        packet_pps,
        udp_ip_bps,
        nic_wire_bps,
        data_nic_wire_bps,
        control_nic_wire_bps,
    }
}

#[derive(Clone, Copy)]
struct WindowRates {
    effective_flow: u32,
    effective_receive: u32,
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
        Availability::Known(rtt) => match core.srt_data_bps_per_leg {
            Availability::Known(bps_per_leg) => {
                let bytes = bps_per_leg * rtt.as_secs_f64() / 8.0;
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
    let (effective_flow, effective_receive) =
        effective_windows(p.flow_window_packets, p.receive_window_packets);
    let flow_window_utilization =
        required_window_packets.map_known(|required| required / f64::from(effective_flow));
    let receive_window_utilization =
        required_window_packets.map_known(|required| required / f64::from(effective_receive));
    let flow_window_headroom_packets =
        required_window_packets.map_known(|required| f64::from(effective_flow) - required);
    let receive_window_headroom_packets =
        required_window_packets.map_known(|required| f64::from(effective_receive) - required);
    WindowRates {
        effective_flow,
        effective_receive,
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
    let sender = &input.sender;
    let receiver = &input.receiver;
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
    // The buffer being modelled is the UDP socket buffer, so its drain
    // horizon is governed by DATAGRAM bytes crossing that socket -- not by
    // application payload bytes. Charging only the payload excluded the SRT
    // header, the authentication tag where one exists, the IP/UDP headers,
    // and retransmission amplification, so every horizon read longer than it
    // is, and increasingly so under loss. `expected_data_pps_per_leg` already
    // carries the retransmission factor.
    let datagram_bytes = encoded_packet_size_bytes(
        input.workload.payload_bytes,
        p.encryption,
        p.cipher_mode,
        n.udp_ip_header_bytes,
    ) as f64;
    let socket_bitrate = |fan_in: u64| {
        core.expected_data_pps_per_leg
            .map_known(|pps| pps * 8.0 * datagram_bytes * fan_in.max(1) as f64)
    };
    let receive_socket_bitrate = socket_bitrate(receiver.rx_socket_fan_in);
    let send_socket_bitrate = socket_bitrate(sender.tx_socket_fan_in);
    let requested_receive_socket_buffer_horizon = requested_horizon(
        receiver.requested_receive_socket_buffer_bytes,
        receive_socket_bitrate,
    );
    let requested_send_socket_buffer_horizon = requested_horizon(
        sender.requested_send_socket_buffer_bytes,
        send_socket_bitrate,
    );
    let effective_receive_socket_buffer_horizon = horizon_for(
        receiver.effective_receive_socket_buffer_bytes,
        receive_socket_bitrate,
    );
    let effective_send_socket_buffer_horizon = horizon_for(
        sender.effective_send_socket_buffer_bytes,
        send_socket_bitrate,
    );
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
    sender_host_packet_work_pps: Availability<f64>,
    receiver_host_packet_work_pps: Availability<f64>,
    host_pps_utilization: Availability<f64>,
    sender_host_pps_utilization: Availability<f64>,
    receiver_host_pps_utilization: Availability<f64>,
    nic_utilization: Availability<f64>,
    sender_nic_utilization: Availability<f64>,
    receiver_nic_utilization: Availability<f64>,
    estimated_max_resource_utilization: Availability<f64>,
    admission_waves: u64,
}

fn endpoint_utilization(work: Availability<f64>, capacity: Availability<f64>) -> Availability<f64> {
    match (work, capacity) {
        (Availability::Known(work), Availability::Known(capacity)) => {
            Availability::Known(work / capacity)
        }
        (Availability::NotApplicable, _) | (_, Availability::NotApplicable) => {
            Availability::NotApplicable
        }
        _ => Availability::Unknown,
    }
}

fn endpoint_nic_utilization(
    wire_bps: Availability<f64>,
    capacity: Availability<u64>,
) -> Availability<f64> {
    match (wire_bps, capacity) {
        (Availability::Known(bps), Availability::Known(capacity)) => {
            Availability::Known(bps / capacity as f64)
        }
        (Availability::NotApplicable, _) | (_, Availability::NotApplicable) => {
            Availability::NotApplicable
        }
        _ => Availability::Unknown,
    }
}

fn derive_resources(input: &CapacityInput, network: NetworkRates) -> ResourceRates {
    let host_packet_work_pps = network.packet_pps;
    let sender_host_packet_work_pps = host_packet_work_pps;
    let receiver_host_packet_work_pps = host_packet_work_pps;
    let sender_host_pps_utilization =
        endpoint_utilization(sender_host_packet_work_pps, input.sender.host_pps_capacity);
    let receiver_host_pps_utilization = endpoint_utilization(
        receiver_host_packet_work_pps,
        input.receiver.host_pps_capacity,
    );
    // Each endpoint is charged the larger of its own two directions, not the
    // sum of both. The sender transmits DATA and receives control; the
    // receiver is the mirror image.
    let sender_nic_utilization = endpoint_nic_utilization(
        max_known(network.data_nic_wire_bps, network.control_nic_wire_bps),
        input.sender.nic_capacity_bps,
    );
    let receiver_nic_utilization = endpoint_nic_utilization(
        max_known(network.control_nic_wire_bps, network.data_nic_wire_bps),
        input.receiver.nic_capacity_bps,
    );
    let host_pps_utilization =
        max_known(sender_host_pps_utilization, receiver_host_pps_utilization);
    let nic_utilization = max_known(sender_nic_utilization, receiver_nic_utilization);
    ResourceRates {
        host_packet_work_pps,
        sender_host_packet_work_pps,
        receiver_host_packet_work_pps,
        host_pps_utilization,
        sender_host_pps_utilization,
        receiver_host_pps_utilization,
        nic_utilization,
        sender_nic_utilization,
        receiver_nic_utilization,
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
        physical_data_pps_per_leg: core.physical_data_pps_per_leg,
        expected_data_pps: core.expected_data_pps,
        expected_data_pps_per_leg: core.expected_data_pps_per_leg,
        payload_bps: core.payload_bps,
        srt_data_packet_bytes: core.srt_data_packet_bytes,
        pacing_packet_bytes: core.pacing_packet_bytes,
        pacing_payload_capacity_bps: core.pacing_payload_capacity_bps,
        pacing_headroom_bps: core.pacing_headroom_bps,
        retransmission_factor: core.retransmission_factor,
        retransmission_excess: core.retransmission_excess,
        srt_data_bps: core.srt_data_bps,
        srt_data_bps_per_leg: core.srt_data_bps_per_leg,
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
        bdp_bytes_per_leg: windows.bdp_bytes,
        bdp_packets_per_leg: windows.bdp_packets,
        required_window_packets_per_leg: windows.required_window_packets,
        configured_flow_window_packets: input.protocol.flow_window_packets,
        effective_flow_window_packets: windows.effective_flow,
        effective_receive_window_packets: windows.effective_receive,
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
        sender_host_packet_work_pps: resources.sender_host_packet_work_pps,
        receiver_host_packet_work_pps: resources.receiver_host_packet_work_pps,
        host_pps_utilization: resources.host_pps_utilization,
        sender_host_pps_utilization: resources.sender_host_pps_utilization,
        receiver_host_pps_utilization: resources.receiver_host_pps_utilization,
        nic_utilization: resources.nic_utilization,
        sender_nic_utilization: resources.sender_nic_utilization,
        receiver_nic_utilization: resources.receiver_nic_utilization,
        estimated_max_resource_utilization: resources.estimated_max_resource_utilization,
        admission_waves: resources.admission_waves,
    };

    let reasons = collect_reasons(&input, &policy, &derived);
    let class = classify_reasons(&reasons);

    let policy_fingerprint = policy.fingerprint();
    Ok(CapacityAssessment {
        class,
        reasons,
        derived,
        input,
        policy_revision: policy.revision,
        policy_fingerprint,
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
    // Two different limits, because the protocol core and a real IPv4 path do
    // not agree about what `DEFAULT_MTU` bounds.
    //
    // PROTOCOL TRUTH: `SrtConnection` sets
    // `max_payload_size = DEFAULT_MTU - SRT_HEADER_SIZE`, so the core treats
    // 1500 as the SRT datagram budget and will emit a 1484-byte payload. That
    // is what the implementation actually enforces, so it is the hard limit.
    //
    // DEPLOYMENT ENVELOPE: on a real 1500-byte IPv4 path the datagram also
    // carries IP and UDP headers, and an encrypted DATA packet carries the GCM
    // tag, so the same payload can exceed the path MTU and fragment. That is a
    // property of the deployment, not of this implementation, so it is
    // reported separately and must not be called protocol truth.
    // PROTOCOL TRUTH, and deliberately tag-free: `SrtConnection` sets
    // `max_payload_size = DEFAULT_MTU - SRT_HEADER_SIZE` regardless of cipher
    // mode, and GCM appends its tag AFTER that limit has been applied. So the
    // core accepts 1484 plaintext bytes even under GCM. Including the tag here
    // claimed the protocol maximum was 1468 and could raise a false hard
    // ExceedsEnvelope. The tag still belongs in the IPv4 envelope below and in
    // all wire-rate accounting.
    if pacing_packet_size_bytes(input.workload.payload_bytes) > shiguredo_srt::DEFAULT_MTU as u64 {
        reasons.push(CapacityReason::PayloadExceedsProtocolMtu);
    }
    if encoded_packet_size_bytes(
        input.workload.payload_bytes,
        input.protocol.encryption,
        input.protocol.cipher_mode,
        input.network.udp_ip_header_bytes,
    ) > shiguredo_srt::DEFAULT_MTU as u64
    {
        reasons.push(CapacityReason::PayloadExceedsIpv4MtuEnvelope);
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
        // Both sides must be PAYLOAD bitrate. `pacing_payload_capacity_bps`
        // is already the payload rate the pacing budget can carry, so pairing
        // it with a pacing-layer demand compared two different layers and
        // could fire just below the real budget -- e.g. a 10 Mbit/s budget
        // with 1316-byte payloads carries ~9.88 Mbit/s of payload, and a
        // 9.8 Mbit/s source presents ~9.92 Mbit/s at the pacing layer, which
        // is under budget yet compared as though it were over.
        let required_payload = expected * input.workload.payload_bytes as f64 * 8.0;
        let pacing_capacity = capacity * input.workload.source_streams as f64 * multiplier;
        if required_payload > pacing_capacity {
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
    if derived.physical_data_pps_per_leg == Availability::Unknown
        && matches!(input.protocol.bond, BondMode::Broadcast | BondMode::Backup)
    {
        reasons.push(CapacityReason::BondLegDistributionUnknown);
    }
    if let Availability::Known(required) = derived.required_window_packets
        && (required > f64::from(derived.effective_flow_window_packets)
            || required > f64::from(derived.effective_receive_window_packets))
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
    // Reorder is an accepted input but nothing downstream models its effect on
    // packet load, recovery margin or control rate. An unknown value and a
    // known nonzero value are therefore equally unmodelled, and both must stay
    // Conditional: supplying a reorder probability must never buy confidence
    // the model has not earned. Only a known zero is genuinely modelled, by
    // being the case where reorder changes nothing.
    let reorder_unmodelled = match input.network.expected_reorder_probability {
        Availability::Known(p) => p > 0.0,
        Availability::Unknown => true,
        Availability::NotApplicable => false,
    };
    if reorder_unmodelled {
        reasons.push(CapacityReason::ReorderImpactUnmodeled);
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
    if input.receiver.effective_receive_socket_buffer_bytes == Availability::Unknown
        || input.sender.effective_send_socket_buffer_bytes == Availability::Unknown
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
    let endpoint_capacities = [
        (
            input.sender.host_pps_capacity,
            derived.sender_host_pps_utilization,
        ),
        (
            input.receiver.host_pps_capacity,
            derived.receiver_host_pps_utilization,
        ),
    ];
    if endpoint_capacities
        .iter()
        .any(|(capacity, _)| *capacity == Availability::Unknown)
    {
        reasons.push(CapacityReason::HostPpsCapacityUnknown);
    } else if endpoint_capacities
        .iter()
        .any(|(capacity, utilization)| {
            matches!(capacity, Availability::Known(_))
                && matches!(utilization, Availability::Unknown)
        })
    {
        reasons.push(CapacityReason::PredictedPacketWorkUnknown);
    } else if endpoint_capacities.iter().any(|(_, utilization)| {
        matches!(utilization, Availability::Known(value) if *value > 1.0)
    }) {
        reasons.push(CapacityReason::HostPpsCapacityExceeded);
    } else if endpoint_capacities.iter().any(|(_, utilization)| {
        matches!(utilization, Availability::Known(value) if *value >= policy.max_host_pps_utilization)
    }) {
        reasons.push(CapacityReason::HostPpsHeadroomLow);
    }
}

fn add_nic_reasons(
    input: &CapacityInput,
    policy: &ClassifierPolicy,
    derived: &DerivedLoad,
    reasons: &mut Vec<CapacityReason>,
) {
    let endpoint_capacities = [
        (
            input.sender.nic_capacity_bps,
            derived.sender_nic_utilization,
        ),
        (
            input.receiver.nic_capacity_bps,
            derived.receiver_nic_utilization,
        ),
    ];
    if endpoint_capacities
        .iter()
        .any(|(capacity, _)| *capacity == Availability::Unknown)
    {
        reasons.push(CapacityReason::NicCapacityUnknown);
    } else if endpoint_capacities.iter().any(|(capacity, utilization)| {
        matches!(capacity, Availability::Known(_))
            && derived.nic_wire_bps == Availability::Unknown
            && *utilization == Availability::Unknown
    }) {
        reasons.push(CapacityReason::NicWireRateUnknown);
    } else if endpoint_capacities.iter().any(|(_, utilization)| {
        matches!(utilization, Availability::Known(value) if *value > 1.0)
    }) {
        reasons.push(CapacityReason::NicCapacityExceeded);
    } else if endpoint_capacities.iter().any(|(_, utilization)| {
        matches!(utilization, Availability::Known(value) if *value >= policy.max_nic_utilization)
    }) {
        reasons.push(CapacityReason::NicHeadroomLow);
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
        reasons.push(CapacityReason::AdmissionWavesHigh);
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
    validate_host(input)?;
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
    // Not a capacity question. `CryptoContext::new_sender` and
    // `new_receiver` both reject this pair outright, so the configuration
    // cannot instantiate and must not be classified as though it could run
    // -- neither Conditional nor ExceedsEnvelope describes "impossible".
    if input.protocol.encryption == EncryptionMode::Aes192
        && input.protocol.cipher_mode == shiguredo_srt::CipherMode::Gcm
    {
        return Err(ModelError(
            "AES-192 is not supported with GCM mode".to_string(),
        ));
    }
    // A zero window is NOT rejected. `normalize_options` clamps it up to
    // MIN_FLOW_WINDOW_PACKETS exactly as it clamps 1 or 31, so refusing zero
    // while accepting 1 reintroduced the requested-versus-effective
    // inconsistency this model exists to remove: the protocol runs all three
    // identically.
    if input.admission.connect_cc == 0 {
        return Err(ModelError("connect_cc must be positive".to_string()));
    }
    if input.sender.rx_socket_fan_in == 0
        || input.sender.tx_socket_fan_in == 0
        || input.receiver.rx_socket_fan_in == 0
        || input.receiver.tx_socket_fan_in == 0
        || input.sender.workers == 0
        || input.receiver.workers == 0
    {
        return Err(ModelError(
            "endpoint socket fan-in and workers must be positive".to_string(),
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

fn validate_host(input: &CapacityInput) -> Result<(), ModelError> {
    for capacity in [
        input.sender.host_pps_capacity,
        input.receiver.host_pps_capacity,
    ] {
        if let Availability::Known(capacity) = capacity
            && !(capacity.is_finite() && capacity > 0.0)
        {
            return Err(ModelError(
                "known host PPS capacity must be finite and positive".to_string(),
            ));
        }
    }
    for capacity in [
        input.sender.nic_capacity_bps,
        input.receiver.nic_capacity_bps,
    ] {
        if let Availability::Known(capacity) = capacity
            && capacity == 0
        {
            return Err(ModelError(
                "known NIC capacity must be positive".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_policy(policy: &ClassifierPolicy) -> Result<(), ModelError> {
    if policy.minimum_window_headroom_packets < 0.0
        || policy.minimum_recovery_margin_ms < 0.0
        || policy.minimum_socket_horizon_seconds < 0.0
        || !(0.0..=1.0).contains(&policy.max_host_pps_utilization)
        || !(0.0..=1.0).contains(&policy.max_nic_utilization)
        || policy
            .max_control_pps
            .is_some_and(|value| !(value.is_finite() && value >= 0.0))
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
        input.receiver.nic_capacity_bps = Availability::NotApplicable;
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
    fn windows_are_classified_against_what_the_protocol_will_actually_use() {
        // `SrtConnection::normalize_options` clamps flow into [32, 65536] and
        // then clamps receive to at most flow. Classifying the REQUESTED
        // numbers reproduced the requested-versus-effective confusion this
        // model already avoids for socket buffers.
        // Zero is a request like any other: the protocol clamps it up, so
        // the model must not reject what the implementation happily runs.
        assert_eq!(effective_windows(0, 0), (32, 32), "zero clamps up");
        assert_eq!(effective_windows(1, 1), (32, 32), "below minimum clamps up");
        assert_eq!(effective_windows(31, 31), (32, 32));
        assert_eq!(effective_windows(32, 32), (32, 32), "at minimum unchanged");
        assert_eq!(
            effective_windows(shiguredo_srt::MAX_FLOW_WINDOW, 64),
            (shiguredo_srt::MAX_FLOW_WINDOW, 64),
            "at maximum unchanged"
        );
        assert_eq!(
            effective_windows(shiguredo_srt::MAX_FLOW_WINDOW + 1, 64),
            (shiguredo_srt::MAX_FLOW_WINDOW, 64),
            "above maximum clamps down"
        );
        assert_eq!(
            effective_windows(1000, 5000),
            (1000, 1000),
            "receive cannot exceed flow"
        );

        let mut input = known_input();
        input.protocol.flow_window_packets = 1;
        input.protocol.receive_window_packets = 5000;
        let a = assess(input.clone(), ClassifierPolicy::default()).expect("valid model");
        assert_eq!(a.derived.configured_flow_window_packets, 1);
        assert_eq!(a.derived.effective_flow_window_packets, 32);
        assert_eq!(a.derived.effective_receive_window_packets, 32);

        // Zero must assess, not error: the protocol runs 0, 1 and 31 alike.
        input.protocol.flow_window_packets = 0;
        input.protocol.receive_window_packets = 0;
        let zero = assess(input, ClassifierPolicy::default())
            .expect("a zero window is clamped by the protocol, not rejected");
        assert_eq!(zero.derived.configured_flow_window_packets, 0);
        assert_eq!(
            zero.derived.effective_flow_window_packets,
            shiguredo_srt::MIN_FLOW_WINDOW_PACKETS
        );
        assert_eq!(
            zero.derived.effective_receive_window_packets,
            shiguredo_srt::MIN_FLOW_WINDOW_PACKETS
        );
    }

    #[test]
    fn window_above_bdp_is_exactly_usable_at_the_boundary() {
        let mut input = known_input();
        input.workload.source_bps_per_stream = 8_000_000;
        input.protocol.bandwidth = SrtBandwidthPolicy::ProtocolDefault;
        // Long enough that the required window is well above
        // shiguredo_srt::MIN_FLOW_WINDOW_PACKETS; below that the protocol clamps up to 32
        // and a "one packet under" window is not actually reachable.
        input.network.expected_rtt = Availability::Known(Duration::from_millis(120));
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
