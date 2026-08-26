//! Layered application configuration for a complete SRT stack.
//!
//! The protocol core deliberately remains sans-I/O. This module composes its
//! raw [`ConnectionOptions`] with transport, admission, and caller-pool policy
//! without hiding those lower layers: every builder exposes `config_mut`, and
//! [`SessionConfig`] exposes the underlying protocol options directly.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::os::fd::AsRawFd;
use std::time::Duration;

use shiguredo_srt::{
    ConnectionOptions, GroupExtensionData, GroupType, KeyLength, SRTGROUP_MASK, SrtConnection,
    Timestamp,
};
use zeroize::Zeroize;

use crate::{
    AdmissionOptions, BondedInputPolicy, OutputDrainBudget, PeerTable, PeerTableConfig,
    SOCK_BUF_BYTES, set_sock_bufs,
};

const DEFAULT_MESSAGE_PAYLOAD: usize = 1_316;
const DEFAULT_CONNECT_DEADLINE: Duration = Duration::from_secs(15);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_BATCH_SIZE: usize = 32;

/// A configuration error found before sockets or protocol state are created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    field: &'static str,
    reason: String,
}

impl ConfigError {
    fn new(field: &'static str, reason: impl Into<String>) -> Self {
        Self {
            field,
            reason: reason.into(),
        }
    }

    /// Stable field name suitable for configuration diagnostics.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Human-readable reason without the field prefix.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ConfigError {}

/// Failure to enqueue a session payload through the checked convenience API.
#[derive(Debug)]
pub enum SessionSendError {
    PayloadTooLarge { actual: usize, maximum: usize },
    Config(ConfigError),
    Protocol(shiguredo_srt::Error),
}

impl fmt::Display for SessionSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { actual, maximum } => {
                write!(
                    f,
                    "payload is {actual} bytes; configured maximum is {maximum}"
                )
            }
            Self::Config(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SessionSendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PayloadTooLarge { .. } => None,
            Self::Config(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}

impl From<shiguredo_srt::Error> for SessionSendError {
    fn from(value: shiguredo_srt::Error) -> Self {
        Self::Protocol(value)
    }
}

impl From<ConfigError> for SessionSendError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

/// Error while resolving configuration or constructing runtime-owned sockets.
#[derive(Debug)]
pub enum RuntimeBuildError {
    Config(ConfigError),
    Io(std::io::Error),
}

impl fmt::Display for RuntimeBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RuntimeBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

impl From<ConfigError> for RuntimeBuildError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<std::io::Error> for RuntimeBuildError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Typed pacing bandwidth. SRT always paces; `ProtocolDefault` selects the
/// libsrt-compatible 1 Gbit/s ceiling rather than disabling pacing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Bandwidth {
    #[default]
    ProtocolDefault,
    BytesPerSecond(NonZeroU64),
    BitsPerSecond(NonZeroU64),
    /// `SRTO_INPUTBW` with `SRTO_OHEADBW`: pace at the known source rate plus
    /// an allowance for retransmissions. `overhead_percent` must be 5..=100,
    /// matching libsrt's accepted range.
    InputBytesPerSecond {
        input: NonZeroU64,
        overhead_percent: u8,
    },
}

impl Bandwidth {
    fn as_connection_values(self) -> (Option<u64>, Option<u64>, u8) {
        match self {
            Self::ProtocolDefault => (None, None, 25),
            Self::BytesPerSecond(value) => (Some(value.get()), None, 25),
            Self::BitsPerSecond(value) => (Some(value.get().div_ceil(8)), None, 25),
            Self::InputBytesPerSecond {
                input,
                overhead_percent,
            } => (None, Some(input.get()), overhead_percent),
        }
    }

    fn from_connection_values(
        max_bandwidth_bytes_per_sec: Option<u64>,
        input_bandwidth_bytes_per_sec: Option<u64>,
        overhead_bandwidth_percent: u8,
    ) -> Self {
        if let Some(value) = max_bandwidth_bytes_per_sec.and_then(NonZeroU64::new) {
            return Self::BytesPerSecond(value);
        }
        input_bandwidth_bytes_per_sec
            .and_then(NonZeroU64::new)
            .map(|input| Self::InputBytesPerSecond {
                input,
                overhead_percent: overhead_bandwidth_percent,
            })
            .unwrap_or_default()
    }

    fn validate(self, field: &'static str) -> Result<(), ConfigError> {
        if let Self::InputBytesPerSecond {
            overhead_percent, ..
        } = self
            && !(5..=100).contains(&overhead_percent)
        {
            return Err(ConfigError::new(
                field,
                "overhead_percent must be 5 through 100 for libsrt interoperability",
            ));
        }
        Ok(())
    }
}

/// Encryption material for one session.
///
/// Normal callers should provide only a passphrase. Explicit salt and SEK are
/// deterministic-test/interoperability escape hatches and are never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptionConfig {
    pub passphrase: String,
    pub key_length: KeyLength,
    pub explicit_salt: Option<[u8; 16]>,
    pub explicit_sek: Option<Vec<u8>>,
}

impl fmt::Debug for EncryptionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionConfig")
            .field("passphrase", &"[REDACTED]")
            .field("key_length", &self.key_length)
            .field("explicit_salt", &self.explicit_salt.map(|_| "[REDACTED]"))
            .field(
                "explicit_sek",
                &self.explicit_sek.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl Drop for EncryptionConfig {
    fn drop(&mut self) {
        self.passphrase.zeroize();
        if let Some(salt) = self.explicit_salt.as_mut() {
            salt.zeroize();
        }
        if let Some(sek) = self.explicit_sek.as_mut() {
            sek.zeroize();
        }
    }
}

impl EncryptionConfig {
    #[must_use]
    pub fn new(passphrase: impl Into<String>) -> Self {
        Self {
            passphrase: passphrase.into(),
            key_length: KeyLength::Aes128,
            explicit_salt: None,
            explicit_sek: None,
        }
    }

    #[must_use]
    pub fn key_length(mut self, key_length: KeyLength) -> Self {
        self.key_length = key_length;
        self
    }

    /// Supply deterministic crypto material. Prefer generated material in
    /// production; this method exists for controlled key management and tests.
    #[must_use]
    pub fn explicit_material(mut self, salt: [u8; 16], sek: Vec<u8>) -> Self {
        self.explicit_salt = Some(salt);
        self.explicit_sek = Some(sek);
        self
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.passphrase.is_empty() {
            return Err(ConfigError::new(
                "session.encryption.passphrase",
                "must not be empty",
            ));
        }
        if !(10..=79).contains(&self.passphrase.len()) {
            return Err(ConfigError::new(
                "session.encryption.passphrase",
                "must be 10 through 79 bytes for libsrt interoperability",
            ));
        }
        if let Some(sek) = &self.explicit_sek
            && sek.len() != self.key_length.len()
        {
            return Err(ConfigError::new(
                "session.encryption.explicit_sek",
                format!("must contain {} bytes", self.key_length.len()),
            ));
        }
        if self.explicit_salt.is_some() != self.explicit_sek.is_some() {
            return Err(ConfigError::new(
                "session.encryption.explicit_material",
                "salt and SEK must be supplied together",
            ));
        }
        Ok(())
    }
}

/// Whether a per-peer listener policy inherits the prepared listener value or
/// deliberately replaces it. `Set(None)` is meaningful for optional values:
/// it explicitly disables the inherited feature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PolicyOverride<T> {
    #[default]
    Inherit,
    Set(T),
}

impl<T> PolicyOverride<T> {
    /// Replace this value only when `higher_priority` makes an explicit
    /// decision. This is the primitive used to compose independent policy
    /// layers without one layer resetting another to listener defaults.
    pub fn overlay(&mut self, higher_priority: Self) {
        if let Self::Set(value) = higher_priority {
            *self = Self::Set(value);
        }
    }
}

/// Secret selected by a listener admission resolver for one peer.
///
/// The value is redacted from diagnostics and zeroized on drop. Unlike
/// [`EncryptionConfig`], it intentionally has no explicit salt/SEK escape
/// hatch: a listener derives session keys from the caller's KM request.
#[derive(Clone, PartialEq, Eq)]
pub struct ListenerEncryptionConfig {
    passphrase: String,
    pub key_length: KeyLength,
}

impl ListenerEncryptionConfig {
    pub fn new(passphrase: impl Into<String>, key_length: KeyLength) -> Result<Self, ConfigError> {
        let value = Self {
            passphrase: passphrase.into(),
            key_length,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !(10..=79).contains(&self.passphrase.len()) {
            return Err(ConfigError::new(
                "listener.policy.encryption.passphrase",
                "must be 10 through 79 bytes for libsrt interoperability",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ListenerEncryptionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerEncryptionConfig")
            .field("passphrase", &"[REDACTED]")
            .field("key_length", &self.key_length)
            .finish()
    }
}

impl Drop for ListenerEncryptionConfig {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

/// Typed overrides selected for a single listener peer after StreamID
/// extraction and cookie validation, but before the CONCLUSION is processed.
///
/// Every field defaults to `Inherit`, so independent policy components can
/// compose by changing only the values they own. For protocol features not
/// represented here, use `PeerTable::admit_with_connection_hook` and the
/// guarded pre-CONCLUSION setters on [`SrtConnection`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListenerPeerPolicy {
    pub encryption: PolicyOverride<Option<ListenerEncryptionConfig>>,
    pub latency: PolicyOverride<Duration>,
    pub bandwidth: PolicyOverride<Bandwidth>,
    pub flow_control: PolicyOverride<FlowControlConfig>,
    pub group: PolicyOverride<Option<GroupConfig>>,
}

impl ListenerPeerPolicy {
    /// Overlay explicit decisions from a higher-priority policy layer.
    /// `Inherit` never erases an earlier decision.
    pub fn overlay(&mut self, higher_priority: Self) -> &mut Self {
        self.encryption.overlay(higher_priority.encryption);
        self.latency.overlay(higher_priority.latency);
        self.bandwidth.overlay(higher_priority.bandwidth);
        self.flow_control.overlay(higher_priority.flow_control);
        self.group.overlay(higher_priority.group);
        self
    }

    #[must_use]
    pub fn with_overlay(mut self, higher_priority: Self) -> Self {
        self.overlay(higher_priority);
        self
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if let PolicyOverride::Set(Some(encryption)) = &self.encryption {
            encryption.validate()?;
        }
        if let PolicyOverride::Set(latency) = &self.latency {
            duration_millis_u16("listener.policy.latency", *latency)?;
        }
        if let PolicyOverride::Set(flow) = &self.flow_control
            && flow.receive_buffer_packets > flow.window_packets
        {
            return Err(ConfigError::new(
                "listener.policy.flow_control.receive_buffer_packets",
                "must not exceed the flow-control window",
            ));
        }
        if let PolicyOverride::Set(Some(group)) = &self.group {
            if group.group_id & SRTGROUP_MASK == 0 {
                return Err(ConfigError::new(
                    "listener.policy.group.group_id",
                    "must contain the SRT group marker; use GroupConfig::new",
                ));
            }
            if group.group_type == GroupType::Undefined {
                return Err(ConfigError::new(
                    "listener.policy.group.group_type",
                    "must be Broadcast or Backup",
                ));
            }
        }
        Ok(())
    }

    /// Apply all selected overrides atomically with respect to protocol input.
    /// This consumes the policy so its passphrase is moved directly into the
    /// connection and is not retained in resolver output.
    pub fn apply_to(mut self, connection: &mut SrtConnection) -> Result<(), ConfigError> {
        self.validate()?;
        if let PolicyOverride::Set(encryption) = &mut self.encryption {
            let (passphrase, key_length) = match encryption {
                Some(value) => {
                    value.validate()?;
                    (
                        Some(std::mem::take(&mut value.passphrase)),
                        value.key_length,
                    )
                }
                None => (None, KeyLength::Aes128),
            };
            connection
                .set_listener_encryption(passphrase, key_length)
                .map_err(|error| {
                    ConfigError::new("listener.policy.encryption", error.to_string())
                })?;
        }
        if let PolicyOverride::Set(latency) = self.latency {
            connection
                .set_listener_latency(duration_millis_u16("listener.policy.latency", latency)?)
                .map_err(|error| ConfigError::new("listener.policy.latency", error.to_string()))?;
        }
        if let PolicyOverride::Set(bandwidth) = self.bandwidth {
            bandwidth.validate("listener.policy.bandwidth")?;
            let (max_bandwidth, input_bandwidth, overhead_percent) =
                bandwidth.as_connection_values();
            connection
                .set_listener_bandwidth_options(max_bandwidth, input_bandwidth, overhead_percent)
                .map_err(|error| {
                    ConfigError::new("listener.policy.bandwidth", error.to_string())
                })?;
        }
        if let PolicyOverride::Set(flow) = self.flow_control {
            connection
                .set_listener_flow_control(
                    flow.window_packets.get(),
                    flow.receive_buffer_packets.get(),
                )
                .map_err(|error| {
                    ConfigError::new("listener.policy.flow_control", error.to_string())
                })?;
        }
        if let PolicyOverride::Set(group) = self.group {
            connection
                .set_listener_group_extension(group.map(Into::into))
                .map_err(|error| ConfigError::new("listener.policy.group", error.to_string()))?;
        }
        Ok(())
    }
}

/// Flow-control and receive-buffer windows, in packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowControlConfig {
    pub window_packets: NonZeroU32,
    pub receive_buffer_packets: NonZeroU32,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        let window = NonZeroU32::new(shiguredo_srt::DEFAULT_FLOW_WINDOW)
            .expect("protocol default flow window is non-zero");
        Self {
            window_packets: window,
            receive_buffer_packets: window,
        }
    }
}

/// Ergonomic SRT bonding metadata. `new` accepts an application-level group
/// number and applies the wire marker bit; `from_wire` preserves raw metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupConfig {
    pub group_id: u32,
    pub group_type: GroupType,
    pub flags: u8,
    pub weight: u16,
}

impl GroupConfig {
    #[must_use]
    pub fn new(group_id: u32, group_type: GroupType) -> Self {
        Self {
            group_id: group_id | SRTGROUP_MASK,
            group_type,
            flags: 0,
            weight: 0,
        }
    }

    #[must_use]
    pub fn from_wire(extension: GroupExtensionData) -> Self {
        extension.into()
    }
}

impl From<GroupConfig> for GroupExtensionData {
    fn from(value: GroupConfig) -> Self {
        Self {
            group_id: value.group_id,
            group_type: value.group_type,
            flags: value.flags,
            weight: value.weight,
        }
    }
}

impl From<GroupExtensionData> for GroupConfig {
    fn from(value: GroupExtensionData) -> Self {
        Self {
            group_id: value.group_id,
            group_type: value.group_type,
            flags: value.flags,
            weight: value.weight,
        }
    }
}

/// Retry cadence and protocol handshake timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeConfig {
    pub retry_interval: Duration,
    pub timeout: Duration,
}

/// Maximum UDP payload policy for one SRT data packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PayloadSize {
    /// Conservative live-stream payload used by the benchmark and common SRT
    /// deployments, avoiding IP fragmentation on ordinary paths.
    #[default]
    Live,
    /// Derive a payload from a path MTU using IPv6 + UDP + SRT header overhead.
    PathMtu(NonZeroU32),
    /// Expert interoperability escape hatch.
    Exact(NonZeroUsize),
}

impl PayloadSize {
    pub fn resolve(self) -> Result<NonZeroUsize, ConfigError> {
        match self {
            Self::Live => Ok(
                NonZeroUsize::new(DEFAULT_MESSAGE_PAYLOAD).expect("default payload is non-zero")
            ),
            Self::Exact(size) => Ok(size),
            Self::PathMtu(mtu) => {
                // 40-byte IPv6 + 8-byte UDP + 16-byte SRT data header. IPv4
                // paths have at least as much room, so one policy is dual-stack safe.
                let payload = usize::try_from(mtu.get())
                    .expect("u32 fits usize on supported targets")
                    .checked_sub(64)
                    .and_then(NonZeroUsize::new)
                    .ok_or_else(|| {
                        ConfigError::new("session.payload_size", "path MTU must exceed 64 bytes")
                    })?;
                Ok(payload)
            }
        }
    }
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            retry_interval: Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            ),
            timeout: Duration::from_micros(shiguredo_srt::DEFAULT_HANDSHAKE_TIMEOUT_MICROS),
        }
    }
}

/// Protocol/session configuration, independent of sockets and runtimes.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    connection: ConnectionOptions,
    pub handshake: HandshakeConfig,
    pub payload_size: PayloadSize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            connection: ConnectionOptions::default(),
            handshake: HandshakeConfig::default(),
            payload_size: PayloadSize::Live,
        }
    }
}

impl SessionConfig {
    #[must_use]
    pub fn from_connection_options(connection: ConnectionOptions) -> Self {
        Self {
            connection,
            ..Self::default()
        }
    }

    /// Complete sans-I/O protocol escape hatch.
    #[must_use]
    pub fn connection_options(&self) -> &ConnectionOptions {
        &self.connection
    }

    /// Mutable sans-I/O protocol escape hatch. Validation still runs when a
    /// caller/listener is prepared.
    pub fn connection_options_mut(&mut self) -> &mut ConnectionOptions {
        &mut self.connection
    }

    #[must_use]
    pub fn into_connection_options(mut self) -> ConnectionOptions {
        std::mem::take(&mut self.connection)
    }

    #[must_use]
    pub fn latency(&self) -> Duration {
        Duration::from_millis(u64::from(self.connection.tsbpd_delay))
    }

    pub fn set_latency(&mut self, latency: Duration) -> Result<&mut Self, ConfigError> {
        self.connection.tsbpd_delay = duration_millis_u16("session.latency", latency)?;
        Ok(self)
    }

    pub fn with_latency(mut self, latency: Duration) -> Result<Self, ConfigError> {
        self.set_latency(latency)?;
        Ok(self)
    }

    #[must_use]
    pub fn bandwidth(&self) -> Bandwidth {
        Bandwidth::from_connection_values(
            self.connection.max_bandwidth_bytes_per_sec,
            self.connection.input_bandwidth_bytes_per_sec,
            self.connection.overhead_bandwidth_percent,
        )
    }

    pub fn set_bandwidth(&mut self, bandwidth: Bandwidth) -> &mut Self {
        let (max_bandwidth, input_bandwidth, overhead_percent) = bandwidth.as_connection_values();
        self.connection.max_bandwidth_bytes_per_sec = max_bandwidth;
        self.connection.input_bandwidth_bytes_per_sec = input_bandwidth;
        self.connection.overhead_bandwidth_percent = overhead_percent;
        self
    }

    pub fn set_stream_id(&mut self, stream_id: Option<String>) -> &mut Self {
        self.connection.stream_id = stream_id;
        self
    }

    pub fn set_group(&mut self, group: Option<GroupConfig>) -> &mut Self {
        self.connection.group_extension = group.map(Into::into);
        self
    }

    pub fn set_flow_control(&mut self, flow: FlowControlConfig) -> &mut Self {
        self.connection.flow_window_packets = flow.window_packets.get();
        self.connection.receive_buffer_packets = flow.receive_buffer_packets.get();
        self.connection.delivery_queue_packets = self
            .connection
            .delivery_queue_packets
            .min(flow.receive_buffer_packets.get())
            .max(1);
        self
    }

    /// Bound DATA events retained for the application. Unread events consume
    /// receive-window capacity, so this is both a memory limit and the
    /// portable replacement for a receiver that stops calling `recv`.
    pub fn set_delivery_queue_packets(&mut self, capacity: NonZeroU32) -> &mut Self {
        self.connection.delivery_queue_packets = capacity.get();
        self
    }

    pub fn set_encryption(&mut self, encryption: Option<EncryptionConfig>) -> &mut Self {
        self.clear_owned_secrets();
        match encryption {
            Some(mut encryption) => {
                self.connection.passphrase = Some(std::mem::take(&mut encryption.passphrase));
                self.connection.key_length = encryption.key_length;
                self.connection.crypto_salt = encryption.explicit_salt.take();
                self.connection.crypto_sek = encryption.explicit_sek.take();
            }
            None => {
                self.connection.passphrase = None;
                self.connection.crypto_salt = None;
                self.connection.crypto_sek = None;
            }
        }
        self
    }

    #[must_use]
    pub fn encryption(&self) -> Option<EncryptionConfig> {
        self.connection
            .passphrase
            .clone()
            .map(|passphrase| EncryptionConfig {
                passphrase,
                key_length: self.connection.key_length,
                explicit_salt: self.connection.crypto_salt,
                explicit_sek: self.connection.crypto_sek.clone(),
            })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.bandwidth().validate("session.bandwidth")?;
        if self.connection.flow_window_packets == 0 {
            return Err(ConfigError::new(
                "session.flow_window_packets",
                "must be non-zero",
            ));
        }
        if self.connection.receive_buffer_packets == 0 {
            return Err(ConfigError::new(
                "session.receive_buffer_packets",
                "must be non-zero",
            ));
        }
        if self.connection.receive_buffer_packets > self.connection.flow_window_packets {
            return Err(ConfigError::new(
                "session.receive_buffer_packets",
                "must not exceed the flow-control window",
            ));
        }
        if self.connection.delivery_queue_packets == 0 {
            return Err(ConfigError::new(
                "session.delivery_queue_packets",
                "must be non-zero",
            ));
        }
        if self.connection.delivery_queue_packets > self.connection.receive_buffer_packets {
            return Err(ConfigError::new(
                "session.delivery_queue_packets",
                "must not exceed the receive buffer",
            ));
        }
        if self
            .connection
            .stream_id
            .as_ref()
            .is_some_and(|stream_id| stream_id.len() > 512)
        {
            return Err(ConfigError::new(
                "session.stream_id",
                "must not exceed 512 bytes",
            ));
        }
        if let Some(group) = self.connection.group_extension {
            if group.group_id & SRTGROUP_MASK == 0 {
                return Err(ConfigError::new(
                    "session.group.group_id",
                    "must contain the SRT group marker; use GroupConfig::new",
                ));
            }
            if group.group_type == GroupType::Undefined {
                return Err(ConfigError::new(
                    "session.group.group_type",
                    "must be Broadcast or Backup",
                ));
            }
        }
        if let Some(encryption) = self.encryption() {
            encryption.validate()?;
        } else if self.connection.crypto_salt.is_some() || self.connection.crypto_sek.is_some() {
            return Err(ConfigError::new(
                "session.encryption",
                "explicit key material requires a passphrase",
            ));
        }
        validate_nonzero_duration(
            "session.handshake.retry_interval",
            self.handshake.retry_interval,
        )?;
        validate_nonzero_duration("session.handshake.timeout", self.handshake.timeout)?;
        if self.handshake.timeout < self.handshake.retry_interval {
            return Err(ConfigError::new(
                "session.handshake.timeout",
                "must not be shorter than retry_interval",
            ));
        }
        self.payload_size.resolve()?;
        Ok(())
    }

    fn materialized_options(&self) -> Result<ConnectionOptions, ConfigError> {
        self.validate()?;
        let mut options = self.connection.clone();
        if options.socket_id == 0 {
            options.socket_id = random_nonzero_u32("session.socket_id")?;
        }
        if options.initial_seq.is_none() {
            options.initial_seq = Some(random_u32("session.initial_seq")? & 0x7fff_ffff);
        }
        Ok(options)
    }

    /// Materialize and retain the caller's initial sequence number. Bonded
    /// callers use this once, then copy it to every physical leg so peers see
    /// one group-wide sequence space from the handshake onward.
    pub fn ensure_initial_seq(&mut self) -> Result<u32, ConfigError> {
        if self.connection.initial_seq.is_none() {
            self.connection.initial_seq = Some(random_u32("session.initial_seq")? & 0x7fff_ffff);
        }
        Ok(self
            .connection
            .initial_seq
            .expect("initial sequence was set"))
    }

    fn clear_owned_secrets(&mut self) {
        if let Some(passphrase) = self.connection.passphrase.as_mut() {
            passphrase.zeroize();
        }
        if let Some(salt) = self.connection.crypto_salt.as_mut() {
            salt.zeroize();
        }
        if let Some(sek) = self.connection.crypto_sek.as_mut() {
            sek.zeroize();
        }
    }

    fn apply_handshake(&self, connection: &mut SrtConnection) {
        connection.set_handshake_timing(
            duration_micros_u64(self.handshake.retry_interval),
            duration_micros_u64(self.handshake.timeout),
        );
    }

    /// Create a caller protocol core, generating identity/sequence values
    /// when their raw options are left at the default sentinel values.
    pub fn caller(&self, now: Timestamp) -> Result<SrtConnection, ConfigError> {
        let mut connection = SrtConnection::new_caller(self.materialized_options()?);
        self.apply_handshake(&mut connection);
        connection
            .connect(now)
            .map_err(|error| ConfigError::new("session.caller", error.to_string()))?;
        Ok(connection)
    }

    /// Create a listener protocol core. Shared listeners normally use
    /// [`PreparedListener::admission_options`] instead.
    pub fn listener(&self) -> Result<SrtConnection, ConfigError> {
        let mut connection = SrtConnection::new_listener(self.materialized_options()?);
        self.apply_handshake(&mut connection);
        Ok(connection)
    }

    /// Enqueue one payload after checking the resolved path/live size. The raw
    /// [`SrtConnection::send`] method remains available when an application
    /// intentionally owns fragmentation or uses a nonstandard wire contract.
    pub fn send(
        &self,
        connection: &mut SrtConnection,
        payload: &[u8],
        now: Timestamp,
    ) -> Result<(), SessionSendError> {
        let maximum = self.payload_size.resolve()?.get();
        if payload.len() > maximum {
            return Err(SessionSendError::PayloadTooLarge {
                actual: payload.len(),
                maximum,
            });
        }
        connection.send(payload, now)?;
        Ok(())
    }
}

impl Drop for SessionConfig {
    fn drop(&mut self) {
        self.clear_owned_secrets();
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WorkerCount {
    #[default]
    Auto,
    Count(NonZeroUsize),
}

impl WorkerCount {
    fn resolve(self, available: NonZeroUsize) -> NonZeroUsize {
        match self {
            Self::Auto => available,
            Self::Count(count) => NonZeroUsize::new(count.get().min(available.get()))
                .expect("clamped worker count remains non-zero"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ListenerTopology {
    #[default]
    Auto,
    PerPort,
    SharedPool {
        listeners: WorkerCount,
    },
    ReusePortMulti {
        acceptors: WorkerCount,
    },
    ReusePortSingle {
        workers: WorkerCount,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BatchingPolicy {
    #[default]
    Auto,
    Disabled,
    MaxDatagrams(NonZeroUsize),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PromotionPolicy {
    #[default]
    Auto,
    Never,
    Relocate,
    Bonded,
    All,
}

impl PromotionPolicy {
    fn resolve(self, topology: ResolvedListenerTopology) -> srt_lifecycle::Promotion {
        match self {
            Self::Auto if matches!(topology, ResolvedListenerTopology::ReusePortMulti { .. }) => {
                srt_lifecycle::Promotion::Relocate
            }
            Self::Auto => srt_lifecycle::Promotion::Never,
            Self::Never => srt_lifecycle::Promotion::Never,
            Self::Relocate => srt_lifecycle::Promotion::Relocate,
            Self::Bonded => srt_lifecycle::Promotion::Bonded,
            Self::All => srt_lifecycle::Promotion::All,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CookieRoutingPolicy {
    #[default]
    Auto,
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SocketBufferConfig {
    #[default]
    Auto,
    SystemDefault,
    Bytes(NonZeroUsize),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportProfile {
    #[default]
    Default,
    LowLatency,
    HighDensity,
}

/// Runtime facts used to resolve `Auto`. Applications with custom adapters can
/// construct this directly instead of pretending to be a built-in runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCapabilities {
    pub available_parallelism: NonZeroUsize,
    pub reuse_port: bool,
    pub receive_batching: bool,
    pub task_scheduler: bool,
}

impl Default for TransportCapabilities {
    fn default() -> Self {
        Self {
            available_parallelism: std::thread::available_parallelism()
                .unwrap_or(NonZeroUsize::MIN),
            reuse_port: cfg!(unix),
            receive_batching: cfg!(target_os = "linux"),
            task_scheduler: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeFlavor {
    Mio,
    Tokio,
    Smol,
    Monoio,
    Glommio,
    Compio,
    Custom(TransportCapabilities),
}

impl RuntimeFlavor {
    #[must_use]
    pub fn capabilities(self) -> TransportCapabilities {
        if let Self::Custom(capabilities) = self {
            return capabilities;
        }
        TransportCapabilities {
            receive_batching: cfg!(target_os = "linux") && matches!(self, Self::Mio),
            task_scheduler: !matches!(self, Self::Mio),
            ..TransportCapabilities::default()
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub topology: ListenerTopology,
    pub workers: WorkerCount,
    pub batching: BatchingPolicy,
    pub promotion: PromotionPolicy,
    pub socket_buffers: SocketBufferConfig,
    pub output_drain: OutputDrainBudget,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            topology: ListenerTopology::Auto,
            workers: WorkerCount::Auto,
            batching: BatchingPolicy::Auto,
            promotion: PromotionPolicy::Auto,
            socket_buffers: SocketBufferConfig::Auto,
            output_drain: OutputDrainBudget::default(),
        }
    }
}

impl TransportConfig {
    #[must_use]
    pub fn for_profile(profile: TransportProfile) -> Self {
        let mut config = Self::default();
        config.apply_profile(profile);
        config
    }

    /// Apply a preset, then freely override individual fields.
    pub fn apply_profile(&mut self, profile: TransportProfile) -> &mut Self {
        *self = match profile {
            TransportProfile::Default => Self::default(),
            TransportProfile::LowLatency => Self {
                topology: ListenerTopology::Auto,
                workers: WorkerCount::Auto,
                batching: BatchingPolicy::Auto,
                promotion: PromotionPolicy::All,
                socket_buffers: SocketBufferConfig::SystemDefault,
                output_drain: OutputDrainBudget::new(32, 16, 128 * 1024),
            },
            TransportProfile::HighDensity => Self {
                topology: ListenerTopology::ReusePortMulti {
                    acceptors: WorkerCount::Auto,
                },
                workers: WorkerCount::Auto,
                batching: BatchingPolicy::Auto,
                promotion: PromotionPolicy::Relocate,
                socket_buffers: SocketBufferConfig::Bytes(
                    NonZeroUsize::new(SOCK_BUF_BYTES).expect("socket buffer default is non-zero"),
                ),
                output_drain: OutputDrainBudget::new(128, 64, 512 * 1024),
            },
        };
        self
    }

    pub fn resolve(
        &self,
        capabilities: TransportCapabilities,
    ) -> Result<ResolvedTransportConfig, ConfigError> {
        validate_output_budget(self.output_drain)?;
        let workers = self.workers.resolve(capabilities.available_parallelism);
        let topology = match self.topology {
            ListenerTopology::Auto if capabilities.reuse_port && workers.get() > 1 => {
                ResolvedListenerTopology::ReusePortMulti { acceptors: workers }
            }
            ListenerTopology::Auto => ResolvedListenerTopology::SharedPool {
                listeners: NonZeroUsize::MIN,
            },
            ListenerTopology::PerPort => ResolvedListenerTopology::PerPort,
            ListenerTopology::SharedPool { listeners } => ResolvedListenerTopology::SharedPool {
                listeners: listeners.resolve(capabilities.available_parallelism),
            },
            ListenerTopology::ReusePortMulti { acceptors } => {
                if !capabilities.reuse_port {
                    return Err(ConfigError::new(
                        "transport.topology",
                        "ReusePortMulti is unsupported by this adapter/platform",
                    ));
                }
                ResolvedListenerTopology::ReusePortMulti {
                    acceptors: acceptors.resolve(capabilities.available_parallelism),
                }
            }
            ListenerTopology::ReusePortSingle { workers } => {
                if !capabilities.reuse_port {
                    return Err(ConfigError::new(
                        "transport.topology",
                        "ReusePortSingle is unsupported by this adapter/platform",
                    ));
                }
                ResolvedListenerTopology::ReusePortSingle {
                    workers: workers.resolve(capabilities.available_parallelism),
                }
            }
        };
        let shared_listener = !matches!(topology, ResolvedListenerTopology::PerPort);
        let batch_size = match self.batching {
            BatchingPolicy::Auto if shared_listener && capabilities.receive_batching => {
                NonZeroUsize::new(DEFAULT_BATCH_SIZE)
            }
            BatchingPolicy::Auto | BatchingPolicy::Disabled => None,
            BatchingPolicy::MaxDatagrams(_) if !shared_listener => {
                return Err(ConfigError::new(
                    "transport.batching",
                    "receive batching requires a shared-listener topology",
                ));
            }
            BatchingPolicy::MaxDatagrams(_) if !capabilities.receive_batching => {
                return Err(ConfigError::new(
                    "transport.batching",
                    "the selected runtime adapter has no batched receive implementation",
                ));
            }
            BatchingPolicy::MaxDatagrams(count) => Some(count),
        };
        // Explicit `All` stays valid on a runtime without a task scheduler
        // (mio): promotion still yields connected sockets there, so it is
        // deliberately not rejected. Previously written as an `if` with an
        // empty body, which reads like an unfinished branch.
        let promotion = self.promotion.resolve(topology);
        let socket_buffer_bytes = match self.socket_buffers {
            SocketBufferConfig::SystemDefault => 0,
            SocketBufferConfig::Bytes(bytes) => bytes.get(),
            SocketBufferConfig::Auto if shared_listener => SOCK_BUF_BYTES,
            SocketBufferConfig::Auto => 0,
        };
        if socket_buffer_bytes > libc::c_int::MAX as usize {
            return Err(ConfigError::new(
                "transport.socket_buffers",
                "exceeds the OS socket-option range",
            ));
        }
        Ok(ResolvedTransportConfig {
            topology,
            workers,
            batch_size,
            promotion,
            socket_buffer_bytes,
            output_drain: self.output_drain,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedListenerTopology {
    PerPort,
    SharedPool { listeners: NonZeroUsize },
    ReusePortMulti { acceptors: NonZeroUsize },
    ReusePortSingle { workers: NonZeroUsize },
}

impl ResolvedListenerTopology {
    #[must_use]
    pub fn listener_socket_count(self) -> NonZeroUsize {
        match self {
            Self::PerPort | Self::ReusePortSingle { .. } => NonZeroUsize::MIN,
            Self::SharedPool { listeners } => listeners,
            Self::ReusePortMulti { acceptors } => acceptors,
        }
    }

    #[must_use]
    pub fn uses_reuse_port(self) -> bool {
        matches!(
            self,
            Self::ReusePortMulti { .. } | Self::ReusePortSingle { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedTransportConfig {
    pub topology: ResolvedListenerTopology,
    pub workers: NonZeroUsize,
    pub batch_size: Option<NonZeroUsize>,
    pub promotion: srt_lifecycle::Promotion,
    /// Zero means preserve the operating-system default.
    pub socket_buffer_bytes: usize,
    pub output_drain: OutputDrainBudget,
}

/// Listener resource and lifecycle policy.
#[derive(Clone, Debug)]
pub struct AdmissionConfig {
    pub limits: PeerTableConfig,
    pub cookie_routing: CookieRoutingPolicy,
    /// Bonded publishers are rejected unless the listener explicitly opts in.
    pub bonded_inputs: BondedInputPolicy,
    pub idle_timeout: Duration,
    /// Aggregate requested socket-buffer memory budget. `None` leaves resource
    /// accounting to the application/container.
    pub socket_memory_budget: Option<NonZeroUsize>,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            limits: PeerTableConfig::default(),
            cookie_routing: CookieRoutingPolicy::Auto,
            bonded_inputs: BondedInputPolicy::Reject,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            socket_memory_budget: None,
        }
    }
}

impl AdmissionConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.limits.max_peers == 0 {
            return Err(ConfigError::new("admission.max_peers", "must be non-zero"));
        }
        if self.limits.max_half_open_peers == 0 {
            return Err(ConfigError::new(
                "admission.max_half_open_peers",
                "must be non-zero",
            ));
        }
        if self.limits.max_established_peers == 0 {
            return Err(ConfigError::new(
                "admission.max_established_peers",
                "must be non-zero",
            ));
        }
        if self.limits.max_peers_per_ip == 0 {
            return Err(ConfigError::new(
                "admission.max_peers_per_ip",
                "must be non-zero",
            ));
        }
        if self.limits.max_half_open_peers > self.limits.max_peers {
            return Err(ConfigError::new(
                "admission.max_half_open_peers",
                "must not exceed max_peers",
            ));
        }
        if self.limits.max_established_peers > self.limits.max_peers {
            return Err(ConfigError::new(
                "admission.max_established_peers",
                "must not exceed max_peers",
            ));
        }
        if self.limits.max_peers_per_ip > self.limits.max_peers {
            return Err(ConfigError::new(
                "admission.max_peers_per_ip",
                "must not exceed max_peers",
            ));
        }
        validate_nonzero_duration("admission.half_open_timeout", self.limits.half_open_timeout)?;
        validate_nonzero_duration("admission.idle_timeout", self.idle_timeout)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectConfig {
    pub max_in_flight: NonZeroUsize,
    pub attempt_deadline: Duration,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            max_in_flight: NonZeroUsize::MIN,
            attempt_deadline: DEFAULT_CONNECT_DEADLINE,
        }
    }
}

impl ConnectConfig {
    fn validate(self) -> Result<(), ConfigError> {
        validate_nonzero_duration("connect.attempt_deadline", self.attempt_deadline)
    }
}

#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    pub session: SessionConfig,
    pub transport: TransportConfig,
    pub admission: AdmissionConfig,
}

impl ListenerConfig {
    #[must_use]
    pub fn builder(bind: SocketAddr) -> ListenerBuilder {
        ListenerBuilder {
            config: Self {
                bind,
                session: SessionConfig::default(),
                transport: TransportConfig::default(),
                admission: AdmissionConfig::default(),
            },
        }
    }

    pub fn prepare(&self, runtime: RuntimeFlavor) -> Result<PreparedListener, ConfigError> {
        self.session.validate()?;
        self.admission.validate()?;
        let transport = self.transport.resolve(runtime.capabilities())?;
        check_socket_memory_budget(&self.admission, transport)?;
        let mut session = self.session.clone();
        let materialized = session.materialized_options()?;
        session.clear_owned_secrets();
        session.connection = materialized;
        let cookie_routing = match self.admission.cookie_routing {
            CookieRoutingPolicy::Auto => transport.topology.uses_reuse_port(),
            CookieRoutingPolicy::Enabled => true,
            CookieRoutingPolicy::Disabled => false,
        };
        Ok(PreparedListener {
            bind: self.bind,
            session,
            transport,
            admission: self.admission.clone(),
            cookie_routing,
        })
    }
}

pub struct ListenerBuilder {
    config: ListenerConfig,
}

impl ListenerBuilder {
    pub fn latency(mut self, latency: Duration) -> Result<Self, ConfigError> {
        self.config.session.set_latency(latency)?;
        Ok(self)
    }

    #[must_use]
    pub fn bandwidth(mut self, bandwidth: Bandwidth) -> Self {
        self.config.session.set_bandwidth(bandwidth);
        self
    }

    #[must_use]
    pub fn encryption(mut self, encryption: EncryptionConfig) -> Self {
        self.config.session.set_encryption(Some(encryption));
        self
    }

    #[must_use]
    pub fn stream_id(mut self, stream_id: impl Into<String>) -> Self {
        self.config.session.set_stream_id(Some(stream_id.into()));
        self
    }

    #[must_use]
    pub fn group(mut self, group: GroupConfig) -> Self {
        self.config.session.set_group(Some(group));
        self
    }

    /// Explicitly choose whether this listener accepts bonded publishers.
    #[must_use]
    pub fn bonded_inputs(mut self, policy: BondedInputPolicy) -> Self {
        self.config.admission.bonded_inputs = policy;
        self
    }

    #[must_use]
    pub fn topology(mut self, topology: ListenerTopology) -> Self {
        self.config.transport.topology = topology;
        self
    }

    #[must_use]
    pub fn max_peers(mut self, max_peers: NonZeroUsize) -> Self {
        let max_peers = max_peers.get();
        self.config.admission.limits.max_peers = max_peers;
        self.config.admission.limits.max_half_open_peers = self
            .config
            .admission
            .limits
            .max_half_open_peers
            .min(max_peers);
        self.config.admission.limits.max_established_peers = self
            .config
            .admission
            .limits
            .max_established_peers
            .min(max_peers);
        self.config.admission.limits.max_peers_per_ip =
            self.config.admission.limits.max_peers_per_ip.min(max_peers);
        self
    }

    #[must_use]
    pub fn session(mut self, session: SessionConfig) -> Self {
        self.config.session = session;
        self
    }

    #[must_use]
    pub fn transport(mut self, transport: TransportConfig) -> Self {
        self.config.transport = transport;
        self
    }

    #[must_use]
    pub fn admission(mut self, admission: AdmissionConfig) -> Self {
        self.config.admission = admission;
        self
    }

    #[must_use]
    pub fn profile(mut self, profile: TransportProfile) -> Self {
        self.config.transport.apply_profile(profile);
        self
    }

    #[must_use]
    pub fn configure_session(mut self, configure: impl FnOnce(&mut SessionConfig)) -> Self {
        configure(&mut self.config.session);
        self
    }

    #[must_use]
    pub fn configure_transport(mut self, configure: impl FnOnce(&mut TransportConfig)) -> Self {
        configure(&mut self.config.transport);
        self
    }

    #[must_use]
    pub fn configure_admission(mut self, configure: impl FnOnce(&mut AdmissionConfig)) -> Self {
        configure(&mut self.config.admission);
        self
    }

    pub fn config_mut(&mut self) -> &mut ListenerConfig {
        &mut self.config
    }

    #[must_use]
    pub fn into_config(self) -> ListenerConfig {
        self.config
    }

    pub fn build(self) -> Result<ListenerConfig, ConfigError> {
        self.config.session.validate()?;
        self.config.admission.validate()?;
        Ok(self.config)
    }
}

#[derive(Clone, Debug)]
pub struct CallerConfig {
    pub remote: SocketAddr,
    pub local_bind: Option<SocketAddr>,
    pub session: SessionConfig,
    pub transport: TransportConfig,
    pub connect: ConnectConfig,
}

impl CallerConfig {
    #[must_use]
    pub fn builder(remote: SocketAddr) -> CallerBuilder {
        CallerBuilder {
            config: Self {
                remote,
                local_bind: None,
                session: SessionConfig::default(),
                transport: TransportConfig::default(),
                connect: ConnectConfig::default(),
            },
        }
    }

    pub fn prepare(&self, runtime: RuntimeFlavor) -> Result<PreparedCaller, ConfigError> {
        self.session.validate()?;
        self.connect.validate()?;
        Ok(PreparedCaller {
            remote: self.remote,
            local_bind: self.local_bind,
            session: self.session.clone(),
            transport: self.transport.resolve(runtime.capabilities())?,
            connect: self.connect,
        })
    }
}

pub struct CallerBuilder {
    config: CallerConfig,
}

impl CallerBuilder {
    pub fn latency(mut self, latency: Duration) -> Result<Self, ConfigError> {
        self.config.session.set_latency(latency)?;
        Ok(self)
    }

    #[must_use]
    pub fn bandwidth(mut self, bandwidth: Bandwidth) -> Self {
        self.config.session.set_bandwidth(bandwidth);
        self
    }

    #[must_use]
    pub fn encryption(mut self, encryption: EncryptionConfig) -> Self {
        self.config.session.set_encryption(Some(encryption));
        self
    }

    #[must_use]
    pub fn stream_id(mut self, stream_id: impl Into<String>) -> Self {
        self.config.session.set_stream_id(Some(stream_id.into()));
        self
    }

    #[must_use]
    pub fn group(mut self, group: GroupConfig) -> Self {
        self.config.session.set_group(Some(group));
        self
    }

    #[must_use]
    pub fn connect_concurrency(mut self, max_in_flight: NonZeroUsize) -> Self {
        self.config.connect.max_in_flight = max_in_flight;
        self
    }

    #[must_use]
    pub fn local_bind(mut self, local_bind: SocketAddr) -> Self {
        self.config.local_bind = Some(local_bind);
        self
    }

    #[must_use]
    pub fn session(mut self, session: SessionConfig) -> Self {
        self.config.session = session;
        self
    }

    #[must_use]
    pub fn transport(mut self, transport: TransportConfig) -> Self {
        self.config.transport = transport;
        self
    }

    #[must_use]
    pub fn connect(mut self, connect: ConnectConfig) -> Self {
        self.config.connect = connect;
        self
    }

    #[must_use]
    pub fn profile(mut self, profile: TransportProfile) -> Self {
        self.config.transport.apply_profile(profile);
        self
    }

    #[must_use]
    pub fn configure_session(mut self, configure: impl FnOnce(&mut SessionConfig)) -> Self {
        configure(&mut self.config.session);
        self
    }

    #[must_use]
    pub fn configure_transport(mut self, configure: impl FnOnce(&mut TransportConfig)) -> Self {
        configure(&mut self.config.transport);
        self
    }

    #[must_use]
    pub fn configure_connect(mut self, configure: impl FnOnce(&mut ConnectConfig)) -> Self {
        configure(&mut self.config.connect);
        self
    }

    pub fn config_mut(&mut self) -> &mut CallerConfig {
        &mut self.config
    }

    #[must_use]
    pub fn into_config(self) -> CallerConfig {
        self.config
    }

    pub fn build(self) -> Result<CallerConfig, ConfigError> {
        self.config.session.validate()?;
        self.config.connect.validate()?;
        Ok(self.config)
    }
}

/// Validated, auto-resolved listener configuration. Runtime adapters may use
/// the socket/protocol parts directly; this type intentionally owns no loop.
#[derive(Clone, Debug)]
pub struct PreparedListener {
    pub bind: SocketAddr,
    pub session: SessionConfig,
    pub transport: ResolvedTransportConfig,
    pub admission: AdmissionConfig,
    cookie_routing: bool,
}

impl PreparedListener {
    #[must_use]
    pub fn cookie_routing(&self) -> bool {
        self.cookie_routing
    }

    #[must_use]
    pub fn peer_table(&self) -> PeerTable {
        PeerTable::with_config(self.admission.limits)
    }

    #[must_use]
    pub fn admission_options(&self) -> AdmissionOptions {
        let options = self.session.connection_options();
        AdmissionOptions {
            socket_id: options.socket_id,
            tsbpd_delay: options.tsbpd_delay,
            cookie_routing: self.cookie_routing,
            bonded_inputs: self.admission.bonded_inputs,
            connection_template: Some(options.clone()),
            handshake_retry_interval: self.session.handshake.retry_interval,
            handshake_timeout: self.session.handshake.timeout,
        }
    }

    /// Bind all ingress sockets described by the resolved topology. SharedPool
    /// advances the port for each listener; reuseport variants share one addr.
    pub fn bind_sockets(&self) -> std::io::Result<Vec<UdpSocket>> {
        let count = self.transport.topology.listener_socket_count().get();
        let reuse_port = self.transport.topology.uses_reuse_port();
        let mut sockets: Vec<UdpSocket> = Vec::with_capacity(count);
        for index in 0..count {
            let address = if reuse_port && index > 0 && self.bind.port() == 0 {
                sockets[0].local_addr()?
            } else if matches!(
                self.transport.topology,
                ResolvedListenerTopology::SharedPool { .. }
            ) {
                let offset = u16::try_from(index).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "shared-pool listener count exceeds port range",
                    )
                })?;
                SocketAddr::new(
                    self.bind.ip(),
                    self.bind.port().checked_add(offset).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "shared-pool address range exceeds port 65535",
                        )
                    })?,
                )
            } else {
                self.bind
            };
            sockets.push(bind_udp(
                address,
                reuse_port,
                self.transport.socket_buffer_bytes,
            )?);
        }
        Ok(sockets)
    }
}

/// Validated, auto-resolved caller and caller-pool configuration.
#[derive(Clone, Debug)]
pub struct PreparedCaller {
    pub remote: SocketAddr,
    pub local_bind: Option<SocketAddr>,
    pub session: SessionConfig,
    pub transport: ResolvedTransportConfig,
    pub connect: ConnectConfig,
}

/// Runtime-native sockets plus the resolved policy that drives their loop.
/// Fields stay public so applications can replace any generated loop/pool.
pub struct RuntimeListener<S> {
    pub prepared: PreparedListener,
    pub sockets: Vec<S>,
}

impl PreparedCaller {
    /// Bind and connect a nonblocking standard UDP socket. Convert it to the
    /// selected runtime's native type, or keep it for a custom adapter.
    pub fn bind_socket(&self) -> std::io::Result<UdpSocket> {
        let local = self
            .local_bind
            .unwrap_or_else(|| unspecified_for(self.remote));
        let socket = bind_udp(local, false, self.transport.socket_buffer_bytes)?;
        socket.connect(self.remote)?;
        Ok(socket)
    }

    /// Build a fresh caller core. Auto identity means each call gets a new
    /// socket ID and initial sequence number, which makes this caller-pool safe.
    pub fn connection(&self, now: Timestamp) -> Result<SrtConnection, ConfigError> {
        self.session.caller(now)
    }
}

fn bind_udp(
    address: SocketAddr,
    reuse_port: bool,
    buffer_bytes: usize,
) -> std::io::Result<UdpSocket> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    set_sock_bufs(socket.as_raw_fd(), buffer_bytes)?;
    Ok(socket.into())
}

fn unspecified_for(remote: SocketAddr) -> SocketAddr {
    match remote.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn check_socket_memory_budget(
    admission: &AdmissionConfig,
    transport: ResolvedTransportConfig,
) -> Result<(), ConfigError> {
    let Some(budget) = admission.socket_memory_budget else {
        return Ok(());
    };
    // Linux may double both SO_RCVBUF and SO_SNDBUF requests. Budget against
    // that conservative effective allocation across every listener socket.
    let requested = transport
        .socket_buffer_bytes
        .saturating_mul(4)
        .saturating_mul(transport.topology.listener_socket_count().get());
    if requested > budget.get() {
        return Err(ConfigError::new(
            "admission.socket_memory_budget",
            format!("{requested} bytes requested for listener send/receive buffers"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_output_budget(budget: OutputDrainBudget) -> Result<(), ConfigError> {
    if budget.max_actions == 0 || budget.max_packets == 0 || budget.max_bytes == 0 {
        return Err(ConfigError::new(
            "transport.output_drain",
            "all action, packet, and byte limits must be non-zero",
        ));
    }
    Ok(())
}

fn validate_nonzero_duration(field: &'static str, duration: Duration) -> Result<(), ConfigError> {
    if duration.is_zero() {
        Err(ConfigError::new(field, "must be non-zero"))
    } else {
        Ok(())
    }
}

fn duration_millis_u16(field: &'static str, duration: Duration) -> Result<u16, ConfigError> {
    let rounded_up_millis = duration.as_micros().div_ceil(1_000);
    u16::try_from(rounded_up_millis)
        .map_err(|_| ConfigError::new(field, format!("must not exceed {} milliseconds", u16::MAX)))
}

fn duration_micros_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn random_u32(field: &'static str) -> Result<u32, ConfigError> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes)
        .map_err(|error| ConfigError::new(field, format!("random generation failed: {error}")))?;
    Ok(u32::from_ne_bytes(bytes))
}

fn random_nonzero_u32(field: &'static str) -> Result<u32, ConfigError> {
    for _ in 0..2 {
        let value = random_u32(field)?;
        if value != 0 {
            return Ok(value);
        }
    }
    Err(ConfigError::new(
        field,
        "random generator returned zero twice",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn encryption_debug_redacts_every_secret() {
        let encryption =
            EncryptionConfig::new("production-secret").explicit_material([7; 16], vec![9; 16]);
        let debug = format!("{encryption:?}");
        assert!(!debug.contains("production-secret"));
        assert!(!debug.contains("7, 7"));
        assert!(!debug.contains("9, 9"));
    }

    #[test]
    fn caller_auto_identity_is_fresh_but_raw_override_is_respected() {
        let session = SessionConfig::default();
        let first = session.caller(Timestamp::default()).expect("first caller");
        let second = session.caller(Timestamp::default()).expect("second caller");
        assert_ne!(first.socket_id(), 0);
        assert_ne!(first.socket_id(), second.socket_id());

        let mut explicit = SessionConfig::default();
        explicit.connection_options_mut().socket_id = 42;
        explicit.connection_options_mut().initial_seq = Some(99);
        let caller = explicit.caller(Timestamp::default()).expect("caller");
        assert_eq!(caller.socket_id(), 42);
    }

    #[test]
    fn explicit_unsupported_batching_fails_instead_of_becoming_a_noop() {
        let config = TransportConfig {
            topology: ListenerTopology::SharedPool {
                listeners: WorkerCount::Count(NonZeroUsize::new(2).expect("non-zero")),
            },
            batching: BatchingPolicy::MaxDatagrams(NonZeroUsize::new(16).expect("non-zero")),
            ..TransportConfig::default()
        };
        let capabilities = TransportCapabilities {
            receive_batching: false,
            ..TransportCapabilities::default()
        };
        let error = config
            .resolve(capabilities)
            .expect_err("unsupported batching");
        assert_eq!(error.field(), "transport.batching");
    }

    #[test]
    fn payload_policy_is_path_derived_with_an_explicit_escape_hatch() {
        assert_eq!(PayloadSize::Live.resolve().expect("live size").get(), 1_316);
        assert_eq!(
            PayloadSize::PathMtu(NonZeroU32::new(1_500).expect("mtu"))
                .resolve()
                .expect("path payload")
                .get(),
            1_436
        );
        assert_eq!(
            PayloadSize::Exact(NonZeroUsize::new(1_200).expect("size"))
                .resolve()
                .expect("exact payload")
                .get(),
            1_200
        );
    }

    #[test]
    fn presets_are_plain_configs_and_remain_overrideable() {
        let mut config = TransportConfig::for_profile(TransportProfile::HighDensity);
        config.promotion = PromotionPolicy::Never;
        config.socket_buffers = SocketBufferConfig::SystemDefault;
        let resolved = config
            .resolve(RuntimeFlavor::Mio.capabilities())
            .expect("resolved profile");
        assert_eq!(resolved.promotion, srt_lifecycle::Promotion::Never);
        assert_eq!(resolved.socket_buffer_bytes, 0);
    }

    #[test]
    fn prepared_listener_carries_full_session_template_into_admission() {
        let mut session = SessionConfig::default();
        session
            .set_encryption(Some(EncryptionConfig::new("ten-characters")))
            .set_stream_id(Some("publish/live".to_owned()));
        let config = ListenerConfig::builder(address(0))
            .session(session)
            .build()
            .expect("listener config");
        let prepared = config.prepare(RuntimeFlavor::Mio).expect("prepared");
        let admission = prepared.admission_options();
        let template = admission
            .connection_template
            .as_ref()
            .expect("session template");
        assert_eq!(template.passphrase.as_deref(), Some("ten-characters"));
        assert_eq!(template.stream_id.as_deref(), Some("publish/live"));
        assert_ne!(template.socket_id, 0);
        assert_eq!(admission.bonded_inputs, BondedInputPolicy::Reject);
    }

    #[test]
    fn listener_requires_an_explicit_bonded_input_opt_in() {
        let config = ListenerConfig::builder(address(0))
            .bonded_inputs(BondedInputPolicy::Accept)
            .build()
            .expect("listener config");
        let prepared = config.prepare(RuntimeFlavor::Mio).expect("prepared");
        assert_eq!(
            prepared.admission_options().bonded_inputs,
            BondedInputPolicy::Accept
        );
    }

    #[test]
    fn socket_budget_accounts_for_both_directions_and_all_listeners() {
        let mut listener = ListenerConfig::builder(address(0)).into_config();
        listener.transport.topology = ListenerTopology::ReusePortMulti {
            acceptors: WorkerCount::Count(NonZeroUsize::new(2).expect("non-zero")),
        };
        listener.transport.socket_buffers =
            SocketBufferConfig::Bytes(NonZeroUsize::new(1_024).expect("non-zero"));
        listener.admission.socket_memory_budget = NonZeroUsize::new(4_095);
        let error = listener
            .prepare(RuntimeFlavor::Mio)
            .expect_err("over budget");
        assert_eq!(error.field(), "admission.socket_memory_budget");
    }

    #[test]
    fn reuseport_ephemeral_bind_keeps_every_acceptor_on_one_port() {
        let mut listener = ListenerConfig::builder(address(0)).into_config();
        listener.transport.topology = ListenerTopology::ReusePortMulti {
            acceptors: WorkerCount::Count(NonZeroUsize::new(2).expect("non-zero")),
        };
        listener.transport.socket_buffers = SocketBufferConfig::SystemDefault;
        let prepared = listener.prepare(RuntimeFlavor::Mio).expect("prepared");
        let sockets = prepared.bind_sockets().expect("reuseport sockets");
        assert_eq!(sockets.len(), 2);
        assert_ne!(sockets[0].local_addr().expect("address").port(), 0);
        assert_eq!(
            sockets[0].local_addr().expect("first address"),
            sockets[1].local_addr().expect("second address")
        );
    }

    #[test]
    fn prepared_caller_binds_and_connects_standard_socket() {
        let receiver = UdpSocket::bind(address(0)).expect("receiver");
        let config = CallerConfig::builder(receiver.local_addr().expect("receiver address"))
            .configure_transport(|transport| {
                transport.socket_buffers = SocketBufferConfig::SystemDefault;
            })
            .build()
            .expect("caller config");
        let prepared = config.prepare(RuntimeFlavor::Mio).expect("prepared caller");
        let socket = prepared.bind_socket().expect("caller socket");
        assert_eq!(
            socket.peer_addr().expect("peer"),
            receiver.local_addr().expect("receiver")
        );
    }

    #[test]
    fn listener_policy_layers_overlay_only_explicit_decisions() {
        let base = ListenerPeerPolicy {
            latency: PolicyOverride::Set(Duration::from_millis(120)),
            bandwidth: PolicyOverride::Set(Bandwidth::BytesPerSecond(
                NonZeroU64::new(10_000_000).expect("bandwidth"),
            )),
            ..ListenerPeerPolicy::default()
        };
        let tenant = ListenerPeerPolicy {
            latency: PolicyOverride::Set(Duration::from_millis(40)),
            ..ListenerPeerPolicy::default()
        };
        let combined = base.with_overlay(tenant);

        assert_eq!(
            combined.latency,
            PolicyOverride::Set(Duration::from_millis(40))
        );
        assert!(matches!(
            combined.bandwidth,
            PolicyOverride::Set(Bandwidth::BytesPerSecond(_))
        ));
    }

    #[test]
    fn input_bandwidth_materializes_as_source_rate_plus_overhead() {
        let mut session = SessionConfig::default();
        let input = NonZeroU64::new(1_000_000).expect("input bandwidth");
        let configured = Bandwidth::InputBytesPerSecond {
            input,
            overhead_percent: 25,
        };
        session.set_bandwidth(configured);

        assert_eq!(session.bandwidth(), configured);
        let options = session.materialized_options().expect("session options");
        assert_eq!(options.max_bandwidth_bytes_per_sec, None);
        assert_eq!(options.input_bandwidth_bytes_per_sec, Some(input.get()));
        assert_eq!(options.overhead_bandwidth_percent, 25);
    }

    #[test]
    fn input_bandwidth_rejects_out_of_range_overhead() {
        let mut session = SessionConfig::default();
        session.set_bandwidth(Bandwidth::InputBytesPerSecond {
            input: NonZeroU64::new(1).expect("input bandwidth"),
            overhead_percent: 101,
        });

        let error = session.validate().expect_err("invalid overhead");
        assert_eq!(error.field(), "session.bandwidth");
    }
}
