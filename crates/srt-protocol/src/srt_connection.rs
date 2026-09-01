//! SRT Connection (sans-I/O pattern).
//!
//! A state machine that manages an SRT connection.
//! I/O happens externally; this struct operates in a buffer-driven way.

use std::collections::VecDeque;
use std::fmt;

use bytes::{Bytes, BytesMut};
use zeroize::{Zeroize, Zeroizing};

use crate::buf::{read_u32, write_u32};
use crate::crypto::{CipherMode, CryptoContext, GCM_TAG_LEN, KeyFlag, KeyLength};
use crate::error::Error;
use crate::message_assembler::MessageAssembler;
use crate::srt_handshake::{
    DEFAULT_FLOW_WINDOW, DEFAULT_MTU, GroupExtensionData, HS_VERSION_5, HandshakePacket,
    HandshakeState, HandshakeType, KmError, KmMessage, MAX_FLOW_WINDOW, SRT_MAGIC_CODE, srt_flags,
};
use crate::srt_packet::{
    ControlPacket, ControlType, DataHeader, DataPacket, SRT_HEADER_SIZE, SrtPacket,
};
use crate::srt_receiver::{LossRange, ReceiverBuffer};
use crate::srt_sender::SenderBuffer;
use crate::stats::ConnectionStats;
use crate::time::Timestamp;

const MAX_NAK_RECORD_SIZE: usize = 8;
const NAK_CHUNK_INITIAL_CAPACITY: usize = 32;
const _: () = assert!(DEFAULT_MTU as usize - SRT_HEADER_SIZE >= MAX_NAK_RECORD_SIZE);

/// A connection's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    /// Caller (initiates the connection).
    Caller,
    /// Listener (waits for the connection).
    Listener,
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Disconnected.
    #[default]
    Disconnected,
    /// INDUCTION phase (Caller).
    Induction,
    /// CONCLUSION phase.
    Conclusion,
    /// Listening (Listener).
    Listening,
    /// Connected.
    Connected,
    /// Closing.
    Closing,
}

/// Timer ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerId {
    /// ACK send timer (10ms).
    Ack,
    /// NAK send timer.
    Nak,
    /// Keepalive timer.
    Keepalive,
    /// Retransmit timeout.
    Retransmit,
    /// Handshake timeout.
    Handshake,
    /// Inactivity timeout (detects missing keepalives).
    Inactivity,
    /// Orderly-close retransmission timeout.
    Shutdown,
}

impl TimerId {
    pub const COUNT: usize = 7;

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const ALL: [TimerId; 7] = [
        TimerId::Ack,
        TimerId::Nak,
        TimerId::Keepalive,
        TimerId::Retransmit,
        TimerId::Handshake,
        TimerId::Inactivity,
        TimerId::Shutdown,
    ];
}

/// Inactivity timeout duration (microseconds).
/// Usually 5 seconds per the SRT spec.
const INACTIVITY_TIMEOUT_MICROS: u64 = 5_000_000;
const SHUTDOWN_RETRY_INTERVAL_MICROS: u64 = 1_000_000;
const SHUTDOWN_TIMEOUT_MICROS: u64 = 5_000_000;
// local patch (crates/srt-protocol/VENDOR.md, not upstream-tracked): use
// libsrt's request cadence with one whole-attempt deadline rather than a
// retry-count approximation that resets between handshake phases.
/// Default minimum spacing between handshake requests. libsrt sends at most
/// one request per 250 ms while a connection attempt is in progress.
pub const DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS: u64 = 250_000;
/// Default deadline for the complete induction + conclusion exchange.
pub const DEFAULT_HANDSHAKE_TIMEOUT_MICROS: u64 = 3_000_000;
const MIN_FLOW_WINDOW_PACKETS: u32 = 32;

/// libsrt-compatible zero padding (4 bytes).
///
/// # Background
///
/// The SRT spec (draft-sharabayko-srt) defines control packets like
/// Keepalive, ACKACK, and Shutdown as carrying no data section (0 bytes).
///
/// # An implementation quirk in libsrt
///
/// libsrt sends every packet as two iovecs, "header + data," via `writev`,
/// but on some platforms `writev` doesn't behave correctly when the data
/// section is 0 bytes. So it adds 4 bytes of zero padding to any packet
/// whose data section would otherwise be 0 bytes.
///
/// ```c
/// // From libsrt/srtcore/packet.cpp
/// case UMSG_KEEPALIVE:
///     // control info field should be none
///     // but "writev" does not allow this
///     m_PacketVector[PV_DATA].set((void*)&m_extra_pad, 4);
///     break;
/// ```
///
/// # Wireshark compatibility
///
/// Wireshark's SRT dissector is also implemented to match libsrt, so a
/// spec-correct 16-byte packet shows up as "Malformed Packet."
///
/// # This library's handling
///
/// For interoperability with libsrt and Wireshark, this library adds the
/// same 4 bytes of zero padding.
///
/// Affected packets:
/// - Keepalive (0x0001)
/// - ACKACK (0x0006)
/// - Shutdown (0x0005)
const LIBSRT_COMPAT_PADDING: [u8; 4] = [0, 0, 0, 0];

/// A connection event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// Connection established.
    Connected,
    /// Data received. The shared payload can be forwarded to
    /// [`SrtConnection::send_shared`] without copying.
    DataReceived {
        payload: Bytes,
        sequence_number: u32,
        message_number: u32,
        timestamp: u32,
        /// Number of SRT DATA packets represented by this reassembled message.
        packet_count: u32,
    },
    /// State changed.
    StateChanged(ConnectionState),
    /// An error occurred.
    Error(String),
    /// Disconnected.
    Disconnected { reason: String },
    /// A key refresh is needed.
    KeyRefreshNeeded { key_length: usize },
}

/// A connection output action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionOutput {
    /// Send a packet.
    SendPacket(Vec<u8>),
    /// Set a timer.
    SetTimer { id: TimerId, duration_micros: u64 },
    /// Clear a timer.
    ClearTimer { id: TimerId },
}

/// Connection options.
#[derive(Clone)]
pub struct ConnectionOptions {
    /// Local socket ID. Zero means auto-assign a random nonzero value.
    pub socket_id: u32,
    /// Initial sequence number.
    pub initial_seq: Option<u32>,
    /// SYN cookie (Listener only).
    pub syn_cookie: Option<u32>,
    /// Passphrase (for encryption).
    pub passphrase: Option<String>,
    /// Salt for encryption.
    pub crypto_salt: Option<[u8; 16]>,
    /// SEK for encryption.
    pub crypto_sek: Option<Vec<u8>>,
    /// Key length.
    pub key_length: KeyLength,
    /// Cipher mode (CTR or GCM).
    pub cipher_mode: CipherMode,
    /// TSBPD delay (ms).
    pub tsbpd_delay: u16,
    /// SRT version.
    pub srt_version: u32,
    /// Stream ID (the identifier the Caller sends to the Listener, up to 512 bytes).
    pub stream_id: Option<String>,
    /// Congestion control mode name declared in the handshake extension
    /// (e.g. "live", "file"). A real libsrt peer that declares a mode
    /// itself refuses to transmit if the other side declares nothing at
    /// all, assuming a live/file mismatch (confirmed by interop testing
    /// against `srt-file-transmit`, which logs "peer DID NOT DECLARE
    /// congctl" and disconnects without sending data). This crate's
    /// receive/delivery path does not itself branch on the mode -- this
    /// field only controls what gets declared and compared on the wire.
    pub congestion_control: String,
    /// Optional libsrt-compatible bonding group metadata.
    pub group_extension: Option<GroupExtensionData>,
    /// Maximum bandwidth (equivalent to `SRTO_MAXBW`, bytes/sec). If `None`,
    /// uses a default equivalent to libsrt's `BW_INFINITE` (1 Gbps) (see
    /// `srt_sender`'s pacing calculation).
    pub max_bandwidth_bytes_per_sec: Option<u64>,
    /// Input stream rate (equivalent to `SRTO_INPUTBW`, bytes/sec). When set
    /// without `max_bandwidth_bytes_per_sec`, pacing includes the configured
    /// retransmission overhead.
    pub input_bandwidth_bytes_per_sec: Option<u64>,
    /// Percentage above input bandwidth reserved for retransmissions
    /// (equivalent to `SRTO_OHEADBW`; libsrt default: 25).
    pub overhead_bandwidth_percent: u8,
    /// Flow-control window advertised in the handshake, in packets. Values
    /// above [`crate::MAX_FLOW_WINDOW`] are clamped during construction.
    pub flow_window_packets: u32,
    /// Local receive-buffer capacity, in packets. Values above
    /// [`crate::MAX_FLOW_WINDOW`] are clamped during construction.
    pub receive_buffer_packets: u32,
    /// Maximum number of delivered DATA events retained for the application.
    ///
    /// Delivered-but-unread packets consume receive-window capacity just like
    /// packets still held by the protocol receiver. This prevents an
    /// application that stops polling events from creating an unbounded queue.
    pub delivery_queue_packets: u32,
}

// Manual Debug (redacting passphrase/crypto_sek) rather than #[derive(Debug)],
// matching upstream shiguredo/srt-rs issue 0070 (not yet in the pulled
// subtree, but already fixed here) -- the same class of leak as 0049's
// CryptoContext::Debug, one layer up in the public ConnectionOptions API.
impl fmt::Debug for ConnectionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionOptions")
            .field("socket_id", &self.socket_id)
            .field("initial_seq", &self.initial_seq)
            .field("syn_cookie", &self.syn_cookie)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .field("crypto_salt", &self.crypto_salt)
            .field(
                "crypto_sek",
                &self.crypto_sek.as_ref().map(|_| "[REDACTED]"),
            )
            .field("key_length", &self.key_length)
            .field("cipher_mode", &self.cipher_mode)
            .field("tsbpd_delay", &self.tsbpd_delay)
            .field("srt_version", &self.srt_version)
            .field("stream_id", &self.stream_id)
            .field("congestion_control", &self.congestion_control)
            .field("group_extension", &self.group_extension)
            .field(
                "max_bandwidth_bytes_per_sec",
                &self.max_bandwidth_bytes_per_sec,
            )
            .field(
                "input_bandwidth_bytes_per_sec",
                &self.input_bandwidth_bytes_per_sec,
            )
            .field(
                "overhead_bandwidth_percent",
                &self.overhead_bandwidth_percent,
            )
            .field("flow_window_packets", &self.flow_window_packets)
            .field("receive_buffer_packets", &self.receive_buffer_packets)
            .field("delivery_queue_packets", &self.delivery_queue_packets)
            .finish()
    }
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            socket_id: 0,
            initial_seq: None,
            syn_cookie: None,
            passphrase: None,
            crypto_salt: None,
            crypto_sek: None,
            key_length: KeyLength::Aes128,
            cipher_mode: CipherMode::Ctr,
            tsbpd_delay: 120,
            srt_version: 0x010500, // 1.5.0
            stream_id: None,
            congestion_control: "live".to_string(),
            group_extension: None,
            max_bandwidth_bytes_per_sec: None,
            input_bandwidth_bytes_per_sec: None,
            overhead_bandwidth_percent: 25,
            flow_window_packets: DEFAULT_FLOW_WINDOW,
            receive_buffer_packets: DEFAULT_FLOW_WINDOW,
            delivery_queue_packets: DEFAULT_FLOW_WINDOW,
        }
    }
}

/// An SRT connection.
pub struct SrtConnection {
    /// Role.
    role: ConnectionRole,
    /// State.
    state: ConnectionState,
    /// Handshake state.
    handshake_state: HandshakeState,
    /// Options.
    options: ConnectionOptions,

    /// Peer socket ID.
    peer_socket_id: u32,
    /// SYN cookie.
    syn_cookie: u32,

    /// Initial sequence number.
    initial_seq: u32,

    /// Encryption context.
    crypto: Option<CryptoContext>,

    /// Send buffer.
    sender: Option<SenderBuffer>,
    /// Receive buffer.
    receiver: Option<ReceiverBuffer>,
    /// Message reassembly.
    assembler: MessageAssembler,
    /// Maximum data payload per SRT packet (MTU minus header).
    max_payload_size: usize,

    /// Event queue.
    event_queue: VecDeque<ConnectionEvent>,
    /// Whether the application has already been asked for a new SEK in the
    /// current refresh cycle. Reset after `provide_new_sek` starts that cycle.
    key_refresh_notified: bool,
    /// DATA events waiting for application consumption. Control/state events
    /// are state-machine bounded; DATA is the unbounded-rate class.
    pending_data_events: u32,
    /// DATA packet positions retained by queued application events. This is
    /// distinct from the event count because one message can span many packets.
    pending_data_packets: u32,
    /// Output queue.
    output_queue: VecDeque<ConnectionOutput>,

    /// Connection start time.
    start_time: Option<Timestamp>,

    /// Last ACK send time.
    last_ack_time: Option<Timestamp>,
    /// Last NAK send time.
    last_nak_time: Option<Timestamp>,
    /// Last packet receipt time (for inactivity-timeout detection).
    last_recv_time: Option<Timestamp>,
    /// Last protocol packet queued for transmission.
    last_send_time: Option<Timestamp>,
    /// Start of an orderly close attempt.
    shutdown_started_at: Option<Timestamp>,
    /// Received KM message (Listener only).
    received_km: Option<KmMessage>,
    /// Stream ID received from the peer (Listener only).
    peer_stream_id: Option<String>,
    /// Congestion control mode name declared by the peer in the handshake
    /// extension, if any.
    peer_congestion_control: Option<String>,
    /// SRT capability flags advertised by the peer's handshake extension.
    peer_srt_flags: Option<u32>,
    /// Peer bonding group metadata.
    peer_group_extension: Option<GroupExtensionData>,
    last_handshake_packet: Option<Vec<u8>>,
    handshake_retry_sequence: u32,
    handshake_started_at: Option<Timestamp>,
    handshake_retry_interval_micros: u64,
    handshake_timeout_micros: u64,
}

impl Drop for SrtConnection {
    fn drop(&mut self) {
        self.clear_config_secrets();
    }
}

fn random_nonzero_socket_id() -> u32 {
    let mut buf = [0u8; 4];
    if getrandom::fill(&mut buf).is_ok() {
        let id = u32::from_ne_bytes(buf);
        if id != 0 {
            return id;
        }
    }
    std::process::id() | 1
}

fn normalize_buffer_options(mut options: ConnectionOptions) -> ConnectionOptions {
    if options.socket_id == 0 {
        options.socket_id = random_nonzero_socket_id();
    }
    options.flow_window_packets = options
        .flow_window_packets
        .clamp(MIN_FLOW_WINDOW_PACKETS, MAX_FLOW_WINDOW);
    options.receive_buffer_packets = options
        .receive_buffer_packets
        .max(MIN_FLOW_WINDOW_PACKETS)
        .min(options.flow_window_packets);
    options.delivery_queue_packets = options
        .delivery_queue_packets
        .max(1)
        .min(options.receive_buffer_packets);
    options
}

impl SrtConnection {
    fn random_bytes(bytes: &mut [u8], label: &str) -> Result<(), Error> {
        getrandom::fill(bytes)
            .map_err(|error| Error::crypto_error(format!("failed to generate {label}: {error}")))
    }

    fn random_array<const N: usize>(label: &str) -> Result<[u8; N], Error> {
        let mut buf = [0u8; N];
        Self::random_bytes(&mut buf, label)?;
        Ok(buf)
    }

    /// Put the handshake into its terminal failed state.
    ///
    /// Every path that abandons a handshake -- rejection, KM failure,
    /// caller-side failure, timeout -- has to do the same four things, and
    /// they were written out four times. The copies had already diverged:
    /// the timeout path did not clear the configured secrets, so a
    /// handshake that timed out left its passphrase, salt, and SEK in
    /// memory while a rejected one did not.
    fn terminate_handshake(&mut self) {
        self.handshake_started_at = None;
        self.handshake_state = HandshakeState::Failed;
        self.set_state(ConnectionState::Disconnected);
        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::Handshake,
        });
        self.clear_config_secrets();
    }

    fn clear_config_secrets(&mut self) {
        if let Some(passphrase) = self.options.passphrase.as_mut() {
            passphrase.zeroize();
        }
        self.options.passphrase = None;
        if let Some(salt) = self.options.crypto_salt.as_mut() {
            salt.zeroize();
        }
        self.options.crypto_salt = None;
        if let Some(sek) = self.options.crypto_sek.as_mut() {
            sek.zeroize();
        }
        self.options.crypto_sek = None;
    }

    /// Create a new connection as a Caller.
    pub fn new_caller(options: ConnectionOptions) -> Self {
        let options = normalize_buffer_options(options);
        let initial_seq = options.initial_seq.unwrap_or(0);
        Self {
            role: ConnectionRole::Caller,
            state: ConnectionState::Disconnected,
            handshake_state: HandshakeState::Initial,
            options,
            peer_socket_id: 0,
            syn_cookie: 0,
            initial_seq,
            crypto: None,
            sender: None,
            receiver: None,
            assembler: MessageAssembler::new(),
            max_payload_size: DEFAULT_MTU as usize - SRT_HEADER_SIZE,
            event_queue: VecDeque::new(),
            key_refresh_notified: false,
            pending_data_events: 0,
            pending_data_packets: 0,
            output_queue: VecDeque::new(),
            start_time: None,
            last_ack_time: None,
            last_nak_time: None,
            last_recv_time: None,
            last_send_time: None,
            shutdown_started_at: None,
            received_km: None,
            peer_stream_id: None,
            peer_congestion_control: None,
            peer_srt_flags: None,
            peer_group_extension: None,
            last_handshake_packet: None,
            handshake_retry_sequence: 0,
            handshake_started_at: None,
            handshake_retry_interval_micros: DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            handshake_timeout_micros: DEFAULT_HANDSHAKE_TIMEOUT_MICROS,
        }
    }

    /// Create a new connection as a Listener.
    pub fn new_listener(options: ConnectionOptions) -> Self {
        let options = normalize_buffer_options(options);
        let initial_seq = options.initial_seq.unwrap_or(0);
        Self {
            role: ConnectionRole::Listener,
            state: ConnectionState::Listening,
            handshake_state: HandshakeState::Initial,
            options,
            peer_socket_id: 0,
            syn_cookie: 0,
            initial_seq,
            crypto: None,
            sender: None,
            receiver: None,
            assembler: MessageAssembler::new(),
            max_payload_size: DEFAULT_MTU as usize - SRT_HEADER_SIZE,
            event_queue: VecDeque::new(),
            key_refresh_notified: false,
            pending_data_events: 0,
            pending_data_packets: 0,
            output_queue: VecDeque::new(),
            start_time: None,
            last_ack_time: None,
            last_nak_time: None,
            last_recv_time: None,
            last_send_time: None,
            shutdown_started_at: None,
            received_km: None,
            peer_stream_id: None,
            peer_congestion_control: None,
            peer_srt_flags: None,
            peer_group_extension: None,
            last_handshake_packet: None,
            handshake_retry_sequence: 0,
            handshake_started_at: None,
            handshake_retry_interval_micros: DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            handshake_timeout_micros: DEFAULT_HANDSHAKE_TIMEOUT_MICROS,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Return this connection's local SRT socket ID.
    ///
    /// The ID is stable for the lifetime of one SRT leg and is carried in the
    /// destination field of peer feedback packets. Callers multiplexing
    /// multiple legs over one UDP tuple can use it to preserve leg identity.
    pub fn socket_id(&self) -> u32 {
        self.options.socket_id
    }

    /// Listener-issued SYN cookie currently expected from the peer.
    #[must_use]
    pub fn syn_cookie(&self) -> u32 {
        self.syn_cookie
    }

    /// Get the Stream ID received from the peer (Listener only).
    pub fn peer_stream_id(&self) -> Option<&str> {
        self.peer_stream_id.as_deref()
    }

    /// Get the congestion control mode name declared by the peer in the
    /// handshake extension, if any (e.g. "live", "file").
    pub fn peer_congestion_control(&self) -> Option<&str> {
        self.peer_congestion_control.as_deref()
    }

    /// Return the bonding group metadata advertised by the peer.
    pub fn peer_group_extension(&self) -> Option<GroupExtensionData> {
        self.peer_group_extension
    }

    /// Return the SRT socket ID advertised by the peer during handshake.
    ///
    /// The peer socket ID is stable for the lifetime of one SRT leg and is
    /// useful as a member identity after GROUP admission. It is not a
    /// replacement for the UDP tuple when routing packets because the first
    /// induction packet must be assigned before this value is known.
    pub fn peer_socket_id(&self) -> u32 {
        self.peer_socket_id
    }

    /// Apply the listener-side policy selected from the incoming StreamID.
    ///
    /// A listener may only change these handshake options while it is still
    /// waiting for the conclusion packet. This mirrors libsrt's accept hook:
    /// the caller's StreamID is known, but KMREQ and the accepted connection
    /// have not been processed yet.
    pub fn set_listener_policy(
        &mut self,
        mut passphrase: Option<String>,
        key_length: KeyLength,
        tsbpd_delay: u16,
        flow_window_packets: u32,
        receive_buffer_packets: u32,
    ) -> Result<(), Error> {
        if let Err(error) = self.ensure_listener_policy_window() {
            if let Some(secret) = passphrase.as_mut() {
                secret.zeroize();
            }
            return Err(error);
        }
        if let Err(error) = Self::validate_flow_control(flow_window_packets, receive_buffer_packets)
        {
            if let Some(secret) = passphrase.as_mut() {
                secret.zeroize();
            }
            return Err(error);
        }
        self.replace_listener_encryption(passphrase, key_length);
        self.options.tsbpd_delay = tsbpd_delay;
        self.set_listener_flow_control_unchecked(flow_window_packets, receive_buffer_packets);
        Ok(())
    }

    /// Select listener encryption after reading the caller's StreamID and
    /// before processing its KM request. Replacing a policy zeroizes the old
    /// secret and clears any caller-side deterministic key material.
    pub fn set_listener_encryption(
        &mut self,
        mut passphrase: Option<String>,
        key_length: KeyLength,
    ) -> Result<(), Error> {
        if let Err(error) = self.ensure_listener_policy_window() {
            if let Some(secret) = passphrase.as_mut() {
                secret.zeroize();
            }
            return Err(error);
        }
        self.replace_listener_encryption(passphrase, key_length);
        Ok(())
    }

    /// Override listener latency during the pre-CONCLUSION policy window.
    pub fn set_listener_latency(&mut self, tsbpd_delay: u16) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        self.options.tsbpd_delay = tsbpd_delay;
        Ok(())
    }

    /// Override listener flow-control and receive windows before CONCLUSION.
    pub fn set_listener_flow_control(
        &mut self,
        flow_window_packets: u32,
        receive_buffer_packets: u32,
    ) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        Self::validate_flow_control(flow_window_packets, receive_buffer_packets)?;
        self.set_listener_flow_control_unchecked(flow_window_packets, receive_buffer_packets);
        Ok(())
    }

    fn validate_flow_control(
        flow_window_packets: u32,
        receive_buffer_packets: u32,
    ) -> Result<(), Error> {
        if flow_window_packets > MAX_FLOW_WINDOW || receive_buffer_packets > MAX_FLOW_WINDOW {
            return Err(Error::invalid_state(format!(
                "flow-control windows cannot exceed {MAX_FLOW_WINDOW} packets"
            )));
        }
        Ok(())
    }

    /// Override listener pacing bandwidth before CONCLUSION.
    pub fn set_listener_bandwidth(
        &mut self,
        max_bandwidth_bytes_per_sec: Option<u64>,
    ) -> Result<(), Error> {
        self.set_listener_bandwidth_options(max_bandwidth_bytes_per_sec, None, 25)
    }

    /// Override listener pacing from `SRTO_MAXBW`, `SRTO_INPUTBW`, and
    /// `SRTO_OHEADBW` before CONCLUSION. An explicit maximum takes precedence
    /// over input-relative pacing, matching libsrt.
    pub fn set_listener_bandwidth_options(
        &mut self,
        max_bandwidth_bytes_per_sec: Option<u64>,
        input_bandwidth_bytes_per_sec: Option<u64>,
        overhead_bandwidth_percent: u8,
    ) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        if input_bandwidth_bytes_per_sec.is_some()
            && !(5..=100).contains(&overhead_bandwidth_percent)
        {
            return Err(Error::invalid_state(
                "input bandwidth overhead must be 5 through 100 percent",
            ));
        }
        self.options.max_bandwidth_bytes_per_sec = max_bandwidth_bytes_per_sec;
        self.options.input_bandwidth_bytes_per_sec = input_bandwidth_bytes_per_sec;
        self.options.overhead_bandwidth_percent = overhead_bandwidth_percent;
        Ok(())
    }

    /// Set or clear listener-side GROUP metadata before CONCLUSION.
    pub fn set_listener_group_extension(
        &mut self,
        group: Option<GroupExtensionData>,
    ) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        self.options.group_extension = group;
        Ok(())
    }

    fn ensure_listener_policy_window(&self) -> Result<(), Error> {
        if self.role != ConnectionRole::Listener || self.state != ConnectionState::Listening {
            return Err(Error::invalid_state(
                "listener policy can only change before conclusion",
            ));
        }
        Ok(())
    }

    fn replace_listener_encryption(&mut self, passphrase: Option<String>, key_length: KeyLength) {
        if let Some(old) = self.options.passphrase.as_mut() {
            old.zeroize();
        }
        if let Some(salt) = self.options.crypto_salt.as_mut() {
            salt.zeroize();
        }
        if let Some(sek) = self.options.crypto_sek.as_mut() {
            sek.zeroize();
        }
        self.options.passphrase = passphrase;
        self.options.crypto_salt = None;
        self.options.crypto_sek = None;
        self.options.key_length = key_length;
    }

    fn set_listener_flow_control_unchecked(
        &mut self,
        flow_window_packets: u32,
        receive_buffer_packets: u32,
    ) {
        self.options.flow_window_packets =
            flow_window_packets.clamp(MIN_FLOW_WINDOW_PACKETS, MAX_FLOW_WINDOW);
        self.options.receive_buffer_packets = receive_buffer_packets
            .max(MIN_FLOW_WINDOW_PACKETS)
            .min(self.options.flow_window_packets);
        self.options.delivery_queue_packets = self
            .options
            .delivery_queue_packets
            .max(1)
            .min(self.options.receive_buffer_packets);
    }

    /// Set listener-side GROUP metadata before processing the conclusion.
    pub fn set_group_extension(&mut self, group: GroupExtensionData) {
        self.options.group_extension = Some(group);
    }

    /// Configure retry spacing and the deadline for the whole handshake.
    ///
    /// Jitter is added only after `retry_interval_micros`, so a retry is
    /// never scheduled earlier than the requested cadence. Both values are
    /// clamped to at least one microsecond and the whole-attempt timeout is
    /// clamped to at least the retry interval.
    pub fn set_handshake_timing(&mut self, retry_interval_micros: u64, timeout_micros: u64) {
        self.handshake_retry_interval_micros = retry_interval_micros.max(1);
        self.handshake_timeout_micros = timeout_micros
            .max(1)
            .max(self.handshake_retry_interval_micros);
    }

    /// Start the connection (Caller only).
    pub fn connect(&mut self, now: Timestamp) -> Result<(), Error> {
        if self.role != ConnectionRole::Caller {
            return Err(Error::invalid_state("only caller can initiate connection"));
        }

        self.start_time = Some(now);
        self.handshake_started_at = Some(now);
        self.handshake_retry_sequence = 0;
        self.send_induction_request(now);
        self.set_state(ConnectionState::Induction);
        self.handshake_state = HandshakeState::InductionSent;
        self.arm_handshake_timer(now);

        Ok(())
    }

    /// Reject the pending listener handshake with an SRT rejection response.
    pub fn reject(&mut self, reason: i32, now: Timestamp) -> Result<(), Error> {
        if self.role != ConnectionRole::Listener
            || self.handshake_state != HandshakeState::InductionReceived
        {
            return Err(Error::invalid_state(
                "only a listener awaiting conclusion can reject a handshake",
            ));
        }
        let handshake =
            HandshakePacket::new_rejection(self.options.socket_id, self.syn_cookie, reason);
        let packet = handshake.encode(self.relative_timestamp(now), self.peer_socket_id);
        let mut bytes = Vec::with_capacity(packet.encoded_size());
        packet.encode(&mut bytes);
        self.queue_handshake_packet(bytes);
        self.terminate_handshake();
        Ok(())
    }

    /// Initialize the send/receive buffers.
    fn init_buffers(&mut self, now: Timestamp, peer_initial_seq: u32, tsbpd_time_base: u64) {
        let mut sender = SenderBuffer::new(
            self.initial_seq,
            self.options.flow_window_packets,
            self.options.tsbpd_delay,
        );
        if let Some(max_bw) = self.options.max_bandwidth_bytes_per_sec {
            sender.set_max_bandwidth(max_bw);
        } else if let Some(input_bw) = self.options.input_bandwidth_bytes_per_sec {
            sender.set_input_bandwidth(input_bw, self.options.overhead_bandwidth_percent);
        }
        self.sender = Some(sender);
        let mut receiver = ReceiverBuffer::with_buffer_size(
            peer_initial_seq,
            self.options.tsbpd_delay,
            now,
            tsbpd_time_base,
            self.options
                .receive_buffer_packets
                .min(self.options.flow_window_packets),
        );
        receiver.set_tsbpd_enabled(self.tsbpd_enabled());
        self.receiver = Some(receiver);
        self.last_ack_time = Some(now);
        self.last_nak_time = Some(now);
    }

    fn flight_capacity_packets(&self) -> u32 {
        self.options
            .flow_window_packets
            .min(self.options.receive_buffer_packets)
    }

    /// Process received data.
    pub fn feed_recv_buf(&mut self, buf: &[u8], now: Timestamp) -> Result<(), Error> {
        if buf.len() < SRT_HEADER_SIZE {
            return Err(Error::insufficient_buffer());
        }

        let packet = SrtPacket::decode(buf)?;
        let (dest_socket_id, is_handshake) = match &packet {
            SrtPacket::Data(packet) => (packet.dest_socket_id, false),
            SrtPacket::Control(packet) => (
                packet.dest_socket_id,
                packet.control_type == ControlType::Handshake,
            ),
        };
        if self.options.socket_id != 0
            && dest_socket_id != self.options.socket_id
            && !(is_handshake
                && dest_socket_id == 0
                && !matches!(
                    self.state,
                    ConnectionState::Connected | ConnectionState::Closing
                ))
        {
            return Err(Error::invalid_data(format!(
                "destination socket ID mismatch: expected {:#x}, got {:#x}",
                self.options.socket_id, dest_socket_id
            )));
        }

        // Only a valid packet for this connection proves peer activity.
        // The inactivity timer is armed once at connect and rearms itself on
        // fire — no per-packet SetTimer output.
        if self.state == ConnectionState::Connected {
            self.last_recv_time = Some(now);
        }

        match packet {
            SrtPacket::Data(data_pkt) => {
                tracing::debug!("received DATA packet, seq={}", data_pkt.sequence_number);
                self.handle_data_packet(data_pkt, now)
            }
            SrtPacket::Control(ctrl_pkt) => self.handle_control_packet(ctrl_pkt, now),
        }
    }

    /// Whether there are packets needing retransmission.
    pub fn has_retransmit(&self) -> bool {
        self.sender.as_ref().is_some_and(|s| s.has_retransmit())
    }

    /// Get a packet to retransmit and add it to the send queue.
    ///
    /// `now` is kept for signature consistency with this Core's other
    /// methods (this method itself no longer uses it -- see
    /// `SenderBuffer::pop_retransmit`'s doc comment for why retransmitted
    /// packets' `sent_time` is no longer updated).
    pub fn process_retransmit(&mut self, now: Timestamp) {
        let dest_socket_id = self.peer_socket_id;
        while let Some((header, payload)) = self
            .sender
            .as_mut()
            .and_then(|s| s.pop_retransmit(dest_socket_id))
        {
            if let Ok(buf) = self.encrypt_to_wire(&header, &payload) {
                self.queue_packet(buf, now);
            }
        }
    }

    /// Process a timer event.
    pub fn handle_timer(&mut self, timer_id: TimerId, now: Timestamp) -> Result<(), Error> {
        match timer_id {
            TimerId::Handshake => self.handle_handshake_timer(now),
            TimerId::Keepalive => self.handle_keepalive_timer(now),
            TimerId::Ack => self.handle_ack_timer(now),
            TimerId::Nak => self.handle_nak_timer(now),
            TimerId::Retransmit => {
                if self.state == ConnectionState::Connected {
                    self.process_retransmit(now);
                }
            }
            TimerId::Inactivity => {
                if self.state == ConnectionState::Connected {
                    let elapsed = self.last_recv_time.map_or(INACTIVITY_TIMEOUT_MICROS, |t| {
                        now.as_micros().saturating_sub(t.as_micros())
                    });
                    if elapsed >= INACTIVITY_TIMEOUT_MICROS {
                        self.event_queue.push_back(ConnectionEvent::Disconnected {
                            reason: "inactivity timeout".to_string(),
                        });
                        self.set_state(ConnectionState::Disconnected);
                    } else {
                        self.output_queue.push_back(ConnectionOutput::SetTimer {
                            id: TimerId::Inactivity,
                            duration_micros: INACTIVITY_TIMEOUT_MICROS - elapsed,
                        });
                    }
                }
            }
            TimerId::Shutdown => self.handle_shutdown_timer(now),
        }
        Ok(())
    }

    fn handle_handshake_timer(&mut self, now: Timestamp) {
        if self.state != ConnectionState::Connected {
            if self.handshake_timed_out(now) {
                self.fail_handshake_timeout();
            } else {
                self.handshake_retry_sequence = self.handshake_retry_sequence.saturating_add(1);
                self.retransmit_handshake();
                self.arm_handshake_timer(now);
            }
        }
    }

    fn handle_keepalive_timer(&mut self, now: Timestamp) {
        if self.state == ConnectionState::Connected {
            if self
                .last_send_time
                .is_none_or(|last_send| now.saturating_sub(last_send) >= 1_000_000)
            {
                self.send_keepalive(now);
            }
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::Keepalive,
                duration_micros: 1_000_000,
            });
        }
    }

    fn handle_ack_timer(&mut self, now: Timestamp) {
        if self.state != ConnectionState::Connected {
            return;
        }
        if self.tlpktdrop_enabled()
            && let Some(receiver) = self.receiver.as_mut()
        {
            for seq in receiver.drop_too_late(now) {
                if let Some(sender) = self.sender.as_mut() {
                    sender.discard_acked(seq);
                }
            }
        }
        self.enqueue_ready_data(now);
        self.send_ack(now);

        if self.tlpktdrop_enabled()
            && let Some(sender) = self.sender.as_mut()
        {
            let dropped_messages = sender.drop_expired(now);
            for msg in &dropped_messages {
                self.send_drop_req(msg.message_number, msg.first_seq, msg.last_seq, now);
            }
        }

        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Ack,
            duration_micros: 10_000,
        });
    }

    fn handle_nak_timer(&mut self, now: Timestamp) {
        if self.state == ConnectionState::Connected && self.periodic_nak_enabled() {
            self.send_periodic_nak(now);
            let interval = self
                .receiver
                .as_ref()
                .map(|r| r.nak_interval())
                .unwrap_or(20_000);
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::Nak,
                duration_micros: interval,
            });
        }
    }

    fn handle_shutdown_timer(&mut self, now: Timestamp) {
        if self.state == ConnectionState::Closing {
            if self
                .shutdown_started_at
                .is_some_and(|started| now.saturating_sub(started) >= SHUTDOWN_TIMEOUT_MICROS)
            {
                self.finish_local_close("shutdown timeout");
            } else {
                self.send_shutdown(now);
                self.output_queue.push_back(ConnectionOutput::SetTimer {
                    id: TimerId::Shutdown,
                    duration_micros: SHUTDOWN_RETRY_INTERVAL_MICROS,
                });
            }
        }
    }

    /// Send data.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<(), Error> {
        self.send_internal(payload.to_vec(), None, now)
    }

    /// Send data from an owned buffer, avoiding a copy.
    pub fn send_owned(&mut self, payload: Vec<u8>, now: Timestamp) -> Result<(), Error> {
        self.send_internal(payload, None, now)
    }

    /// Send shared payload data. Cheaply clones a reference-counted handle
    /// instead of deep-copying the payload — the fan-out path for proxies.
    pub fn send_shared(&mut self, payload: Bytes, now: Timestamp) -> Result<(), Error> {
        self.send_shared_internal(payload, None, now)
    }

    /// Send shared payload with a caller-supplied SRT sequence number.
    pub fn send_shared_with_sequence(
        &mut self,
        payload: Bytes,
        sequence_number: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.send_shared_internal(payload, Some(sequence_number), now)
    }

    /// Send one message with a caller-supplied SRT sequence number.
    pub fn send_with_sequence(
        &mut self,
        payload: &[u8],
        sequence_number: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.send_internal(payload.to_vec(), Some(sequence_number), now)
    }

    /// Send a message that may be larger than one SRT packet.
    ///
    /// The payload is fragmented into multiple packets if it exceeds the
    /// negotiated maximum payload size. The receiver reassembles the
    /// fragments before delivering them as a single `DataReceived` event.
    pub fn send_message(&mut self, payload: &[u8], now: Timestamp) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::invalid_state("not connected"));
        }
        if !self.can_send() {
            return Err(Error::invalid_state("send buffer full"));
        }
        let timestamp = self.relative_timestamp(now);
        let peer_socket_id = self.peer_socket_id;
        let max_payload_size = self.max_payload_size;

        let packets = {
            let sender = self
                .sender
                .as_mut()
                .ok_or_else(|| Error::invalid_state("sender buffer not initialized"))?;
            sender.push_message(payload, max_payload_size, timestamp, peer_socket_id, now)
        };

        if packets.is_empty() {
            return Err(Error::invalid_state("send buffer full"));
        }

        for (header, payload) in packets {
            let buf = self.encrypt_to_wire(&header, &payload)?;
            self.queue_packet(buf, now);
        }

        if let Some(ref mut sender) = self.sender {
            sender.record_send_time(now);
        }

        self.check_km_refresh(now);
        Ok(())
    }

    fn send_internal(
        &mut self,
        payload: Vec<u8>,
        sequence_number: Option<u32>,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::invalid_state("not connected"));
        }

        if !self.can_send() {
            return Err(Error::invalid_state("send buffer full"));
        }

        if let Some(sequence_number) = sequence_number
            && self.next_sequence_number() != Some(sequence_number)
        {
            return Err(Error::invalid_state("sequence number is out of order"));
        }

        let timestamp = self.relative_timestamp(now);
        let peer_socket_id = self.peer_socket_id;

        let packet = {
            let sender = self
                .sender
                .as_mut()
                .ok_or_else(|| Error::invalid_state("sender buffer not initialized"))?;
            match sequence_number {
                Some(sequence_number) => sender.push_with_sequence(
                    payload,
                    timestamp,
                    peer_socket_id,
                    now,
                    sequence_number,
                ),
                None => sender.push(payload, timestamp, peer_socket_id, now),
            }
        };

        if let Some((header, payload)) = packet {
            tracing::debug!(
                "sending DATA packet, seq={}, msg={}, ts={}, dest_socket_id={:#x}, payload_len={}",
                header.sequence_number,
                header.message_number,
                header.timestamp,
                header.dest_socket_id,
                payload.len()
            );

            let buf = self.encrypt_to_wire(&header, &payload)?;
            self.queue_packet(buf, now);

            if let Some(ref mut sender) = self.sender {
                sender.record_send_time(now);
            }
        }

        self.check_km_refresh(now);

        Ok(())
    }

    fn send_shared_internal(
        &mut self,
        payload: Bytes,
        sequence_number: Option<u32>,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::invalid_state("not connected"));
        }
        if !self.can_send() {
            return Err(Error::invalid_state("send buffer full"));
        }

        let timestamp = self.relative_timestamp(now);
        let peer_socket_id = self.peer_socket_id;

        let packet = {
            let sender = self
                .sender
                .as_mut()
                .ok_or_else(|| Error::invalid_state("sender buffer not initialized"))?;
            match sequence_number {
                Some(seq) => {
                    sender.push_shared_with_sequence(payload, timestamp, peer_socket_id, now, seq)
                }
                None => sender.push_shared(payload, timestamp, peer_socket_id, now),
            }
        };

        if let Some((header, payload)) = packet {
            let buf = self.encrypt_to_wire(&header, &payload)?;
            self.queue_packet(buf, now);
            if let Some(ref mut sender) = self.sender {
                sender.record_send_time(now);
            }
        }

        self.check_km_refresh(now);
        Ok(())
    }

    /// Return the next sequence number assigned by the connection.
    pub fn next_sequence_number(&self) -> Option<u32> {
        self.sender.as_ref().map(SenderBuffer::next_sequence_number)
    }

    /// Advance the next expected receive sequence number, discarding any
    /// buffered or in-flight-loss packets it leaves behind.
    ///
    /// Used to align a bonded group member's receive sequence with the
    /// group's logical sequence when it joins or catches up; see
    /// [`crate::SrtGroup::poll_event`].
    pub fn advance_receive_sequence(&mut self, sequence_number: u32, now: Timestamp) {
        let Some(receiver) = self.receiver.as_mut() else {
            return;
        };
        self.assembler.discard_before(sequence_number);
        receiver.advance_expected_sequence(sequence_number);
        self.sync_application_backlog();
        self.enqueue_ready_data(now);
    }

    /// Align this connection's next send sequence number with
    /// `sequence_number`. Fails if packets are already in flight, since
    /// their sequence numbers cannot be retroactively renumbered.
    ///
    /// Used to align a bonded group member's send sequence with the group's
    /// logical sequence; see [`crate::SrtGroup::add_member`].
    pub fn synchronize_send_sequence(&mut self, sequence_number: u32) -> Result<(), Error> {
        let Some(sender) = self.sender.as_mut() else {
            return Err(Error::invalid_state("sender buffer not initialized"));
        };
        if sender.synchronize_next_sequence_number(sequence_number) {
            Ok(())
        } else {
            Err(Error::invalid_state("sender buffer has in-flight packets"))
        }
    }

    /// Whether sending is possible (checks window size only).
    pub fn can_send(&self) -> bool {
        self.sender.as_ref().is_some_and(|s| s.can_send())
    }

    /// Whether sending is possible, including packet pacing.
    pub fn can_send_with_pacing(&self, now: Timestamp) -> bool {
        self.sender
            .as_ref()
            .is_some_and(|s| s.can_send_with_pacing(now))
    }

    /// Time to wait until the next send is possible (microseconds).
    pub fn time_until_send(&self, now: Timestamp) -> u64 {
        self.sender
            .as_ref()
            .map(|s| s.time_until_send(now))
            .unwrap_or(100_000)
    }

    /// Set the packet send interval (microseconds).
    pub fn set_packet_send_period(&mut self, period: u64) {
        if let Some(ref mut sender) = self.sender {
            sender.set_packet_send_period(period);
        }
    }

    /// Get an event.
    pub fn poll_event(&mut self) -> Option<ConnectionEvent> {
        self.poll_event_inner(false)
    }

    pub(crate) fn poll_event_for_group(&mut self) -> Option<ConnectionEvent> {
        self.poll_event_inner(true)
    }

    fn poll_event_inner(&mut self, retain_data_reservation: bool) -> Option<ConnectionEvent> {
        let event = self.event_queue.pop_front()?;
        if let ConnectionEvent::DataReceived { packet_count, .. } = &event {
            self.pending_data_events = self.pending_data_events.saturating_sub(1);
            if !retain_data_reservation {
                self.release_data_reservation(*packet_count);
            }
        }
        Some(event)
    }

    pub(crate) fn release_data_reservation(&mut self, packet_count: u32) {
        debug_assert!(packet_count <= self.pending_data_packets);
        self.pending_data_packets = self.pending_data_packets.saturating_sub(packet_count);
        self.sync_application_backlog();
    }

    /// Get an output.
    pub fn poll_output(&mut self) -> Option<ConnectionOutput> {
        self.output_queue.pop_front()
    }

    /// Disconnect.
    pub fn disconnect(&mut self, now: Timestamp) {
        if self.state == ConnectionState::Connected {
            // Match peer-initiated shutdown: locally requested close must not
            // strand TSBPD-buffered payload if the peer never answers.
            if let Some(receiver) = self.receiver.as_mut() {
                receiver.set_tsbpd_enabled(false);
            }
            self.enqueue_ready_data(now);
            self.send_shutdown(now);
            self.shutdown_started_at = Some(now);
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::Shutdown,
                duration_micros: SHUTDOWN_RETRY_INTERVAL_MICROS,
            });
            self.set_state(ConnectionState::Closing);
        }
    }

    /// Get the sender's statistics.
    pub fn sender_stats(&self) -> Option<crate::srt_sender::SenderStats> {
        self.sender.as_ref().map(|s| s.stats())
    }

    /// Get the receiver's statistics.
    pub fn receiver_stats(&self) -> Option<crate::srt_receiver::ReceiverStats> {
        self.receiver.as_ref().map(|r| r.stats())
    }

    /// Return a non-clearing snapshot of cumulative and instantaneous
    /// connection telemetry.
    ///
    /// Interval counts and rates can be derived without giving this sans-I/O
    /// core a clock via [`ConnectionStats::interval_since`].
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            sender: self.sender_stats(),
            receiver: self.receiver_stats(),
        }
    }

    /// Provide a new SEK and begin key refresh.
    ///
    /// Call this after receiving a `KeyRefreshNeeded` event.
    pub fn provide_new_sek(&mut self, new_sek: &[u8], now: Timestamp) -> Result<(), Error> {
        let Some(ref mut crypto) = self.crypto else {
            return Err(Error::with_reason(
                crate::error::ErrorKind::CryptoError,
                "encryption not enabled",
            ));
        };

        let (key_flag, wrapped_key) = crypto.start_pre_announce(new_sek)?;
        self.key_refresh_notified = false;
        let km_message = KmMessage::new(
            key_flag,
            crypto.key_length(),
            *crypto.salt(),
            wrapped_key,
            crypto.cipher_mode(),
        );
        self.send_km_request(&km_message, now);

        Ok(())
    }

    /// Seed the encrypted-packet count for an accelerated key-refresh test.
    ///
    /// This is available only with the opt-in `test-support` feature. It
    /// permits a black-box peer test to cross the normal refresh boundary
    /// without transmitting 2²⁵ packets; it does not change production
    /// refresh timing.
    #[cfg(feature = "test-support")]
    pub fn seed_encrypted_packet_count_for_test(&mut self, count: u64) -> Result<(), Error> {
        let crypto = self
            .crypto
            .as_mut()
            .ok_or_else(|| Error::crypto_error("encryption not enabled"))?;
        crypto.set_encrypted_packet_count_for_test(count);
        Ok(())
    }

    // ========================================================================
    // Private methods
    // ========================================================================

    fn set_state(&mut self, new_state: ConnectionState) {
        if self.state != new_state {
            self.state = new_state;
            self.event_queue
                .push_back(ConnectionEvent::StateChanged(new_state));
        }
    }

    fn relative_timestamp(&self, now: Timestamp) -> u32 {
        // Returns 0 only when the session clock has not been stamped yet.
        // Both handshake roles stamp start_time before sending any response
        // (see handle_handshake_listener), so responses always carry a real
        // timestamp: a zero stamp would make the caller's TSBPD time base
        // (T_NOW − response timestamp) span its entire handshake instead of
        // ≈RTT_0/2 per spec §4.5.1.1.
        self.start_time
            .map_or(0, |s| now.as_micros().saturating_sub(s.as_micros())) as u32
    }

    /// Move at most the configured amount of protocol-ready DATA into the
    /// application queue. Packets that do not fit deliberately remain in the
    /// receiver, where they continue to consume SRT receive-window capacity.
    fn enqueue_ready_data(&mut self, now: Timestamp) {
        let available = self
            .options
            .delivery_queue_packets
            .saturating_sub(self.pending_data_events) as usize;
        if available == 0 {
            return;
        }

        for _ in 0..available {
            let Some(packet) = self
                .receiver
                .as_mut()
                .and_then(|receiver| receiver.pop_ready(now))
            else {
                break;
            };
            if let Some(msg) = self.assembler.feed(packet) {
                self.event_queue.push_back(ConnectionEvent::DataReceived {
                    payload: msg.payload,
                    sequence_number: msg.first_sequence_number,
                    message_number: msg.message_number,
                    timestamp: msg.timestamp,
                    packet_count: msg.packet_count,
                });
                self.pending_data_events = self.pending_data_events.saturating_add(1);
                self.pending_data_packets =
                    self.pending_data_packets.saturating_add(msg.packet_count);
            }
        }
        self.sync_application_backlog();
    }

    /// Build a wire-ready buffer: header + encrypted payload (+ GCM tag).
    ///
    /// Copies the plaintext into the wire buffer exactly once and encrypts
    /// in place, eliminating the intermediate `DataPacket.payload` copy
    /// that the old `encrypt_packet` + `encode` path required.
    fn encrypt_to_wire(&mut self, header: &DataHeader, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let Some(ref mut crypto) = self.crypto else {
            let mut buf = Vec::with_capacity(SRT_HEADER_SIZE + payload.len());
            let mut hdr = [0u8; SRT_HEADER_SIZE];
            header.write_header(&mut hdr, 0);
            buf.extend_from_slice(&hdr);
            buf.extend_from_slice(payload);
            return Ok(buf);
        };
        match crypto.cipher_mode() {
            CipherMode::Ctr => {
                let mut buf = Vec::with_capacity(SRT_HEADER_SIZE + payload.len());
                buf.extend_from_slice(&[0u8; SRT_HEADER_SIZE]);
                buf.extend_from_slice(payload);
                let key_flag =
                    crypto.encrypt(header.sequence_number, &mut buf[SRT_HEADER_SIZE..])?;
                let mut hdr = [0u8; SRT_HEADER_SIZE];
                header.write_header(&mut hdr, key_flag.to_kk_field());
                buf[..SRT_HEADER_SIZE].copy_from_slice(&hdr);
                Ok(buf)
            }
            CipherMode::Gcm => {
                let enc_flag = crypto.current_key().to_kk_field();
                let mut buf = Vec::with_capacity(SRT_HEADER_SIZE + payload.len() + GCM_TAG_LEN);
                let mut hdr = [0u8; SRT_HEADER_SIZE];
                header.write_header(&mut hdr, enc_flag);
                buf.extend_from_slice(&hdr);
                buf.extend_from_slice(payload);
                let aad = header.gcm_aad(enc_flag);
                let (_, tag) = crypto.encrypt_gcm_detached(
                    header.sequence_number,
                    &aad,
                    &mut buf[SRT_HEADER_SIZE..],
                )?;
                buf.extend_from_slice(&tag);
                Ok(buf)
            }
        }
    }

    fn sync_application_backlog(&mut self) {
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.set_application_backlog_packets(
                self.pending_data_packets
                    .saturating_add(self.assembler.pending_packet_count()),
            );
        }
    }

    fn handle_data_packet(&mut self, mut pkt: DataPacket, now: Timestamp) -> Result<(), Error> {
        if self.state == ConnectionState::Closing {
            self.finish_local_close("peer activity after shutdown");
            return Ok(());
        }
        if self.state != ConnectionState::Connected {
            return Ok(()); // 接続前のデータは無視
        }

        self.decrypt_data_packet(&mut pkt)?;

        // Receive before delivery. Ready packets are moved into the bounded
        // application queue below, so unread application data remains part of
        // the advertised receive window instead of accumulating without bound.
        let (losses, should_ack) = {
            let receiver = match self.receiver.as_mut() {
                Some(r) => r,
                None => return Ok(()),
            };

            let losses = receiver.receive(pkt, now);
            let should_ack = receiver.should_send_ack(now);

            (losses, should_ack)
        };

        // 損失が検出された場合、NAK を送信
        if let Some(loss) = losses {
            let mut control_info = Vec::with_capacity(8);
            encode_loss_range(&mut control_info, loss.first_seq, loss.last_seq);
            self.send_encoded_nak(control_info, now);
        }

        self.enqueue_ready_data(now);

        // Light ACK チェック. This runs after delivery admission so the ACK's
        // available-buffer field includes application backlog.
        if should_ack {
            self.send_ack(now);
        }

        Ok(())
    }

    fn decrypt_data_packet(&mut self, pkt: &mut DataPacket) -> Result<(), Error> {
        // Check the header before cloning the payload: hostile or
        // misconfigured peers should not force an unnecessary allocation.
        if pkt.encryption_flag == 0 {
            if self.crypto.is_some() {
                self.record_undecryptable();
                return Err(Error::crypto_error(
                    "unencrypted DATA packet on encrypted connection",
                ));
            }
            return Ok(());
        }

        if let Err(error) = self.decrypt_encrypted_payload(pkt) {
            self.record_undecryptable();
            return Err(error);
        }
        Ok(())
    }

    fn decrypt_encrypted_payload(&self, pkt: &mut DataPacket) -> Result<(), Error> {
        let Some(crypto) = self.crypto.as_ref() else {
            return Err(Error::crypto_error(
                "encrypted packet but no crypto context",
            ));
        };
        let key_flag = KeyFlag::from_kk_field(pkt.encryption_flag)
            .ok_or_else(|| Error::crypto_error("invalid KK flag"))?;
        let mut payload = std::mem::take(&mut pkt.payload)
            .try_into_mut()
            .unwrap_or_else(BytesMut::from);
        match crypto.cipher_mode() {
            CipherMode::Ctr => {
                crypto.decrypt(pkt.sequence_number, key_flag, &mut payload)?;
            }
            CipherMode::Gcm => {
                let aad = pkt.gcm_aad();
                crypto.decrypt_gcm_detached(pkt.sequence_number, key_flag, &aad, &mut payload)?;
            }
        }
        pkt.payload = payload.freeze();
        Ok(())
    }

    fn record_undecryptable(&mut self) {
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.record_undecryptable();
        }
    }

    fn handle_control_packet(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        tracing::debug!(
            "received control packet, type={:?}, info_len={}",
            pkt.control_type,
            pkt.control_info.len()
        );
        if self.state == ConnectionState::Closing && pkt.control_type != ControlType::Shutdown {
            self.finish_local_close("peer activity after shutdown");
            return Ok(());
        }
        match pkt.control_type {
            ControlType::Handshake => self.handle_handshake(pkt, now),
            ControlType::Keepalive => Ok(()), // キープアライブは特に処理不要
            ControlType::Ack => self.handle_ack(pkt, now),
            ControlType::Nak => self.handle_nak(pkt, now),
            ControlType::Shutdown => self.handle_shutdown(now),
            ControlType::AckAck => self.handle_ackack(pkt, now),
            ControlType::UserDefined => self.handle_user_defined(pkt, now),
            ControlType::DropReq => self.handle_drop_req(pkt, now),
            ControlType::CongestionWarning | ControlType::PeerError => Ok(()),
        }
    }

    fn handle_handshake(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        if self.handshake_timed_out(now) {
            self.fail_handshake_timeout();
            return Ok(());
        }
        let hs = HandshakePacket::decode(&pkt)?;

        match self.role {
            ConnectionRole::Caller => self.handle_handshake_caller(hs, pkt.timestamp, now),
            ConnectionRole::Listener => self.handle_handshake_listener(hs, pkt.timestamp, now),
        }
    }

    fn handle_handshake_caller(
        &mut self,
        hs: HandshakePacket,
        hsreq_timestamp: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        match hs.handshake_type {
            HandshakeType::Induction => self.handle_caller_induction(hs, now),
            HandshakeType::Conclusion => self.handle_caller_conclusion(hs, hsreq_timestamp, now),
            HandshakeType::Rejected => Err(self.fail_caller_handshake(&format!(
                "connection rejected by peer, reason={}",
                hs.reject_reason.unwrap_or(-1)
            ))),
            _ => Ok(()),
        }
    }

    fn handle_caller_induction(
        &mut self,
        hs: HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        if !matches!(
            self.handshake_state,
            HandshakeState::InductionSent | HandshakeState::ConclusionSent
        ) {
            return Ok(());
        }

        if hs.extension_field != SRT_MAGIC_CODE {
            return Err(self.fail_caller_handshake("invalid SRT magic in induction response"));
        }
        if hs.version != HS_VERSION_5 {
            return Err(self.fail_caller_handshake("unsupported SRT version in induction response"));
        }

        self.syn_cookie = hs.syn_cookie;
        self.peer_socket_id = hs.socket_id;
        tracing::debug!(
            "received INDUCTION response, peer_socket_id={:#x}, syn_cookie={:#x}",
            self.peer_socket_id,
            self.syn_cookie
        );

        if self.handshake_state == HandshakeState::InductionSent
            && let Some(ref passphrase) = self.options.passphrase
        {
            self.init_caller_crypto(&hs, passphrase.clone())?;
        }

        self.send_conclusion_request(now)?;
        self.handshake_state = HandshakeState::ConclusionSent;
        self.arm_handshake_timer(now);
        Ok(())
    }

    fn init_caller_crypto(
        &mut self,
        hs: &HandshakePacket,
        passphrase: String,
    ) -> Result<(), Error> {
        let key_length = hs.key_length().unwrap_or(self.options.key_length);
        let salt = match self.options.crypto_salt {
            Some(salt) => salt,
            None => Self::random_array("crypto salt")?,
        };
        let generated_sek;
        let sek = match self.options.crypto_sek.as_deref() {
            Some(sek) => sek,
            None => {
                generated_sek = Zeroizing::new({
                    let mut sek = vec![0u8; key_length.len()];
                    Self::random_bytes(&mut sek, "stream encryption key")?;
                    sek
                });
                generated_sek.as_slice()
            }
        };
        self.crypto = Some(CryptoContext::new_sender(
            &passphrase,
            key_length,
            salt,
            sek,
            self.options.cipher_mode,
        )?);
        Ok(())
    }

    fn handle_caller_conclusion(
        &mut self,
        hs: HandshakePacket,
        hsreq_timestamp: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.handshake_state == HandshakeState::Completed {
            self.retransmit_handshake();
            return Ok(());
        }
        if self.handshake_state != HandshakeState::ConclusionSent {
            return Ok(());
        }

        self.peer_socket_id = hs.socket_id;
        self.peer_group_extension = hs.get_group_extension();
        self.peer_congestion_control = hs.get_congestion_extension();
        self.apply_peer_handshake_extension(&hs);

        tracing::debug!(
            "received CONCLUSION response, peer_initial_seq={}, peer_socket_id={:#x}",
            hs.initial_packet_seq,
            hs.socket_id
        );

        self.validate_caller_kmrsp(&hs)?;

        self.handshake_state = HandshakeState::Completed;
        self.handshake_started_at = None;
        self.set_state(ConnectionState::Connected);
        self.start_time = Some(now);

        let tsbpd_time_base = now.as_micros().saturating_sub(hsreq_timestamp as u64);
        self.init_buffers(now, hs.initial_packet_seq, tsbpd_time_base);

        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::Handshake,
        });
        self.setup_connection_timers();
        self.clear_config_secrets();
        self.event_queue.push_back(ConnectionEvent::Connected);
        Ok(())
    }

    fn validate_caller_kmrsp(&mut self, hs: &HandshakePacket) -> Result<(), Error> {
        match (self.crypto.is_some(), hs.get_km_response()) {
            (true, Ok(Some(_))) | (false, Ok(None)) => Ok(()),
            (true, Ok(None)) => Err(self.fail_caller_handshake("encryption enabled but no KMRSP")),
            (false, Ok(Some(_))) => {
                Err(self.fail_caller_handshake("peer requires encryption but caller is unsecured"))
            }
            (_, Err(km_error)) => {
                let reason = match km_error {
                    KmError::Unsecured => "peer is unsecured",
                    KmError::NoSecret => "peer has no secret",
                    KmError::BadSecret => "peer has wrong secret",
                    KmError::BadCryptoMode => "incompatible crypto mode",
                };
                Err(self.fail_caller_handshake(reason))
            }
        }
    }

    fn handle_handshake_listener(
        &mut self,
        hs: HandshakePacket,
        hsreq_timestamp: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        // Rejection and timeout are terminal for this connection object.
        // A new attempt must get fresh listener state rather than reviving
        // policy-rejected or expired handshake material.
        if self.handshake_state == HandshakeState::Failed {
            return Ok(());
        }
        match hs.handshake_type {
            HandshakeType::Induction => self.handle_listener_induction(hs, now),
            HandshakeType::Conclusion => self.handle_listener_conclusion(hs, hsreq_timestamp, now),
            _ => Ok(()),
        }
    }

    fn handle_listener_induction(
        &mut self,
        hs: HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.handshake_state == HandshakeState::Completed {
            self.retransmit_handshake();
            return Ok(());
        }
        self.peer_socket_id = hs.socket_id;
        self.syn_cookie = self.options.syn_cookie.unwrap_or(0);
        if self.handshake_started_at.is_none() {
            self.handshake_started_at = Some(now);
            self.handshake_retry_sequence = 0;
        }
        // Stamp the session clock before responding so the INDUCTION
        // response carries a real timestamp for the caller's TSBPD base.
        if self.start_time.is_none() {
            self.start_time = Some(now);
        }
        self.send_induction_response(now);
        self.handshake_state = HandshakeState::InductionReceived;
        self.arm_handshake_timer(now);
        Ok(())
    }

    fn handle_listener_conclusion(
        &mut self,
        hs: HandshakePacket,
        hsreq_timestamp: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.handshake_state == HandshakeState::Completed {
            self.retransmit_handshake();
            return Ok(());
        }
        if self.handshake_state != HandshakeState::InductionReceived {
            return Ok(());
        }
        if hs.syn_cookie != self.syn_cookie {
            return Err(Error::handshake_rejected("invalid SYN cookie"));
        }

        self.initial_seq = hs.initial_packet_seq;
        if let Some(stream_id) = hs.get_sid_extension() {
            self.peer_stream_id = Some(stream_id);
        }
        self.peer_group_extension = hs.get_group_extension();
        self.peer_congestion_control = hs.get_congestion_extension();
        self.apply_peer_handshake_extension(&hs);
        self.configure_listener_crypto(&hs, now)?;
        self.complete_listener_handshake(&hs, hsreq_timestamp, now);
        Ok(())
    }

    fn configure_listener_crypto(
        &mut self,
        hs: &HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        if let Some(passphrase) = self.options.passphrase.clone() {
            let Some(km_result) = hs.get_km_request() else {
                return Err(self.fail_listener_km(
                    now,
                    KmError::NoSecret,
                    "encryption required but no KMREQ",
                ));
            };
            let km = km_result?;
            let Some(cipher_mode) = CipherMode::from_km(&km) else {
                return Err(self.fail_listener_km(
                    now,
                    KmError::BadSecret,
                    "inconsistent cipher/auth fields in KMREQ",
                ));
            };
            let crypto = match CryptoContext::new_receiver(
                &passphrase,
                km.salt,
                &km.wrapped_key,
                km.key_flag,
                km.key_length,
                cipher_mode,
            ) {
                Ok(crypto) => crypto,
                Err(_) => {
                    return Err(self.fail_listener_km(
                        now,
                        KmError::BadSecret,
                        "incorrect passphrase or invalid key material",
                    ));
                }
            };
            self.crypto = Some(crypto);
            self.received_km = Some(km);
        } else if hs.get_km_request().is_some() {
            return Err(self.fail_listener_km(
                now,
                KmError::Unsecured,
                "caller requested encryption but listener is unsecured",
            ));
        }
        Ok(())
    }

    fn complete_listener_handshake(
        &mut self,
        hs: &HandshakePacket,
        hsreq_timestamp: u32,
        now: Timestamp,
    ) {
        // The session clock was stamped at INDUCTION, so this response's
        // timestamp lets the caller derive the initial TSBPD time base.
        self.send_conclusion_response(now);
        self.handshake_state = HandshakeState::Completed;
        self.handshake_started_at = None;
        self.set_state(ConnectionState::Connected);

        let tsbpd_time_base = now.as_micros().saturating_sub(hsreq_timestamp as u64);
        self.init_buffers(now, hs.initial_packet_seq, tsbpd_time_base);
        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::Handshake,
        });
        self.setup_connection_timers();
        self.clear_config_secrets();
        self.event_queue.push_back(ConnectionEvent::Connected);
    }

    fn handle_ack(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        if pkt.control_info.len() < 4 {
            return Ok(()); // 不正な ACK
        }

        let mut buf = pkt.control_info.as_slice();
        let ack_seq = crate::buf::read_u32(&mut buf)?;

        tracing::debug!(
            "received ACK, ack_seq={}, type_specific_info={}, control_info_len={}",
            ack_seq,
            pkt.type_specific_info,
            pkt.control_info.len()
        );

        // 送信バッファから ACK されたパケットを削除
        if let Some(ref mut sender) = self.sender {
            let before = sender.packets_in_buffer();
            sender.handle_ack(ack_seq);
            let after = sender.packets_in_buffer();
            tracing::debug!("sender buffer: {} -> {} packets", before, after);
        }

        // A full ACK carries receiver-side instantaneous measurements. Keep
        // the latest complete set so sender-only applications do not need to
        // parse control packets themselves.
        if pkt.control_info.len() >= 28 {
            let mut feedback = &pkt.control_info[4..];
            let rtt_micros = crate::buf::read_u32(&mut feedback)?;
            let rtt_variance_micros = crate::buf::read_u32(&mut feedback)?;
            let available_buffer_packets = crate::buf::read_u32(&mut feedback)?;
            let receiving_rate_packets_per_second = crate::buf::read_u32(&mut feedback)?;
            let link_capacity_packets_per_second = crate::buf::read_u32(&mut feedback)?;
            let receiving_rate_bytes_per_second = crate::buf::read_u32(&mut feedback)?;
            if let Some(sender) = self.sender.as_mut() {
                sender.record_peer_feedback(
                    rtt_micros,
                    rtt_variance_micros,
                    available_buffer_packets,
                    receiving_rate_packets_per_second,
                    link_capacity_packets_per_second,
                    receiving_rate_bytes_per_second,
                );
                // Receive-window flow control: cap in-flight packets at the
                // peer's currently-advertised free buffer capacity, so a
                // filling receive buffer actually throttles the sender
                // instead of only being visible via telemetry. Clamped to
                // the handshake-negotiated flow window rather than applied
                // directly, so a buggy or adversarial peer advertising an
                // inflated available_buffer can only ever shrink the
                // sender's effective window, never grow it past what was
                // already negotiated. (found via upstream shiguredo/srt-rs
                // issue 0075, not yet in the pulled subtree)
                sender.set_flow_window(
                    available_buffer_packets.min(self.options.flow_window_packets),
                );
            }
        }

        // ACKACK only acknowledges Full ACK receipt (draft-sharabayko-srt.md
        // #ctrl-pkt-ack): "The sender only acknowledges the receipt of Full
        // ACK packets." Full ACK's CIF is 28 bytes (7 fields x 4 bytes:
        // ack_seq, RTT, RTTVar, Buffer Size, Packet Rate, Link Capacity, Recv
        // Rate); Small ACK's CIF is 16 bytes (ack_seq through Buffer Size
        // only). This implementation currently only ever produces 4-byte
        // (Light ACK) or 28-byte (Full ACK) CIFs, so `>= 16` and `>= 28` are
        // equivalent today -- but `>= 16` would send a spec-violating ACKACK
        // for a future or peer-originated Small ACK. (found via upstream
        // shiguredo/srt-rs issue 0054, not yet in the pulled subtree)
        if pkt.control_info.len() >= 28 {
            self.send_ackack(pkt.type_specific_info, now);
        }

        Ok(())
    }

    fn handle_nak(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        let loss_ranges = parse_loss_ranges(
            &pkt.control_info,
            usize::try_from(self.flight_capacity_packets()).unwrap_or(usize::MAX),
        )?;

        if let Some(ref mut sender) = self.sender {
            sender.handle_nak_ranges(&loss_ranges);
        }

        // 即座に再送処理
        self.process_retransmit(now);

        Ok(())
    }

    fn handle_ackack(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        let ack_number = pkt.type_specific_info;

        // RTT を更新 (ACK 送信時刻はReceiverBuffer内で管理)
        if let Some(ref mut receiver) = self.receiver {
            receiver.handle_ackack(ack_number, pkt.timestamp, now);
        }

        Ok(())
    }

    fn handle_shutdown(&mut self, now: Timestamp) -> Result<(), Error> {
        // Flush the receive buffer before disconnecting (ignore TSBPD, deliver immediately).
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.set_tsbpd_enabled(false);
        }
        self.enqueue_ready_data(now);

        self.shutdown_started_at = None;
        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::Shutdown,
        });
        self.set_state(ConnectionState::Disconnected);
        self.event_queue.push_back(ConnectionEvent::Disconnected {
            reason: "peer shutdown".to_string(),
        });
        Ok(())
    }

    fn finish_local_close(&mut self, reason: &str) {
        self.shutdown_started_at = None;
        self.output_queue.push_back(ConnectionOutput::ClearTimer {
            id: TimerId::Shutdown,
        });
        self.set_state(ConnectionState::Disconnected);
        self.event_queue.push_back(ConnectionEvent::Disconnected {
            reason: reason.to_owned(),
        });
    }

    fn handle_drop_req(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;

        let message_number = pkt.type_specific_info & 0x03FF_FFFF;
        if pkt.control_info.len() < 8 {
            return Err(Error::invalid_data("DROPREQ CIF too short"));
        }
        let mut buf = &pkt.control_info[..];
        let first_seq = read_u32(&mut buf)?;
        let last_seq = read_u32(&mut buf)?;
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.drop_range(first_seq, last_seq)?;
        } else if first_seq & !SEQUENCE_MASK != 0 || last_seq & !SEQUENCE_MASK != 0 {
            return Err(Error::invalid_data("DROPREQ sequence has high bit set"));
        }
        self.assembler.drop_message(message_number);
        self.enqueue_ready_data(now);
        Ok(())
    }

    fn send_drop_req(
        &mut self,
        message_number: u32,
        first_seq: u32,
        last_seq: u32,
        now: Timestamp,
    ) {
        let timestamp = self.relative_timestamp(now);
        let mut pkt = ControlPacket::new(ControlType::DropReq, timestamp, self.peer_socket_id);
        pkt.type_specific_info = message_number & 0x03FF_FFFF;
        let mut cif = Vec::with_capacity(8);
        write_u32(&mut cif, first_seq);
        write_u32(&mut cif, last_seq);
        pkt.control_info = cif;
        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_packet(buf, now);
    }

    /// Process a UserDefined packet (KM Refresh).
    fn handle_user_defined(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        // Determine KMREQ/KMRSP from the subtype.
        // SRT_CMD_KMREQ = 3, SRT_CMD_KMRSP = 4
        const SRT_CMD_KMREQ: u16 = 3;
        const SRT_CMD_KMRSP: u16 = 4;

        match pkt.subtype {
            SRT_CMD_KMREQ => {
                // Received a KM Refresh request (receiver side).
                let km = KmMessage::decode(&pkt.control_info)?;

                if let Some(ref mut crypto) = self.crypto {
                    // Update to the new SEK.
                    crypto.update_sek(&km.wrapped_key, km.key_flag)?;

                    // Send a KMRSP.
                    self.send_km_response(&km, now);
                } else {
                    // A refresh KMREQ on an unencrypted connection cannot
                    // succeed. Reply immediately rather than leaving the
                    // peer to wait for its own timeout (spec §3.2.1.2).
                    self.send_km_error_response(KmError::NoSecret, now);
                }
            }
            SRT_CMD_KMRSP => {
                // Received a KM Refresh response (sender side).
                // A successful receipt means the peer accepted the new key.
                // No further action needed here (the key switch happens on the sender's own timing).
            }
            _ => {
                // Ignore unknown UserDefined packets.
            }
        }

        Ok(())
    }

    /// Check whether KM Refresh needs to happen and act accordingly.
    fn check_km_refresh(&mut self, _now: Timestamp) {
        // Check whether pre-announcing is needed.
        let Some(ref crypto) = self.crypto else {
            return;
        };

        if crypto.should_pre_announce() && !self.key_refresh_notified {
            // Notify the outside world that a new SEK is needed.
            self.event_queue
                .push_back(ConnectionEvent::KeyRefreshNeeded {
                    key_length: crypto.key_length().len(),
                });
            self.key_refresh_notified = true;
        }

        // Check whether a key switch is needed.
        if let Some(ref mut crypto) = self.crypto {
            if crypto.should_switch_key() {
                crypto.switch_key();
            }

            // Check whether the old key needs to be disposed of.
            if crypto.should_decommission_old_key() {
                crypto.decommission_old_key();
            }
        }
    }

    /// Send a KMREQ packet (KM Refresh).
    fn send_km_request(&mut self, km_message: &KmMessage, now: Timestamp) {
        const SRT_CMD_KMREQ: u16 = 3;

        let pkt = ControlPacket {
            control_type: ControlType::UserDefined,
            subtype: SRT_CMD_KMREQ,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info: km_message.encode(),
        };

        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_packet(buf, now);
    }

    /// Send a KMRSP packet (KM Refresh).
    fn send_km_response(&mut self, km_message: &KmMessage, now: Timestamp) {
        const SRT_CMD_KMRSP: u16 = 4;

        let pkt = ControlPacket {
            control_type: ControlType::UserDefined,
            subtype: SRT_CMD_KMRSP,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info: km_message.encode(),
        };

        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_packet(buf, now);
    }

    /// Send a KM refresh error response (KMRSP with its four-byte state).
    fn send_km_error_response(&mut self, error: KmError, now: Timestamp) {
        const SRT_CMD_KMRSP: u16 = 4;
        let mut control_info = Vec::with_capacity(4);
        write_u32(&mut control_info, error as u32);
        let pkt = ControlPacket {
            control_type: ControlType::UserDefined,
            subtype: SRT_CMD_KMRSP,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info,
        };
        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_packet(buf, now);
    }

    /// Set up timers after the connection is established.
    fn setup_connection_timers(&mut self) {
        // Keepalive timer (1 second).
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Keepalive,
            duration_micros: 1_000_000,
        });

        // ACK timer (10ms).
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Ack,
            duration_micros: 10_000,
        });

        if self.periodic_nak_enabled() {
            // NAK timer (initial value 20ms).
            self.output_queue.push_back(ConnectionOutput::SetTimer {
                id: TimerId::Nak,
                duration_micros: 20_000,
            });
        }

        // Inactivity timer (5 seconds).
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Inactivity,
            duration_micros: INACTIVITY_TIMEOUT_MICROS,
        });
    }

    /// Send an ACK packet.
    fn send_ack(&mut self, now: Timestamp) {
        let receiver = match self.receiver.as_mut() {
            Some(r) => r,
            None => return,
        };

        let ack_info = receiver.generate_ack(now);
        let ack_number = receiver.ack_number();
        receiver.record_ack_sent();
        self.last_ack_time = Some(now);

        let mut control_info = Vec::with_capacity(8);
        write_u32(&mut control_info, ack_info.ack_seq);

        if !ack_info.is_light {
            // Full ACK (per the SRT spec).
            write_u32(&mut control_info, ack_info.rtt);
            write_u32(&mut control_info, ack_info.rtt_var);
            write_u32(&mut control_info, ack_info.available_buffer);
            write_u32(&mut control_info, ack_info.receiving_rate); // packets/sec
            write_u32(&mut control_info, ack_info.link_capacity); // packets/sec
            write_u32(&mut control_info, ack_info.recv_rate); // bytes/sec
        }

        let pkt = ControlPacket {
            control_type: ControlType::Ack,
            subtype: 0,
            type_specific_info: if ack_info.is_light { 0 } else { ack_number },
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info,
        };

        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_packet(buf, now);
    }

    fn send_encoded_nak(&mut self, control_info: Vec<u8>, now: Timestamp) {
        if control_info.is_empty() {
            return;
        }

        debug_assert!(control_info.len() <= self.max_control_info_size());

        if let Some(receiver) = self.receiver.as_mut() {
            receiver.record_nak_sent();
        }

        let packet = encode_nak_packet(
            control_info,
            self.relative_timestamp(now),
            self.peer_socket_id,
        );
        self.queue_packet(packet, now);
    }

    /// Control packets and DATA packets share the configured SRT datagram
    /// budget after their common 16-byte header.
    fn max_control_info_size(&self) -> usize {
        self.max_payload_size
    }

    /// Send a periodic NAK.
    fn send_periodic_nak(&mut self, now: Timestamp) {
        let receiver = match self.receiver.as_ref() {
            Some(r) => r,
            None => return,
        };

        let max_control_info_size = self.max_control_info_size();
        debug_assert!(max_control_info_size >= MAX_NAK_RECORD_SIZE);
        let timestamp = self.relative_timestamp(now);
        let peer_socket_id = self.peer_socket_id;
        let output_queue = &mut self.output_queue;
        let mut chunks = NakChunkEncoder::new(max_control_info_size);
        let mut packets_sent = 0u32;
        receiver.for_each_periodic_nak_range(|loss| {
            if let Some(control_info) = chunks.push(loss) {
                output_queue.push_back(ConnectionOutput::SendPacket(encode_nak_packet(
                    control_info,
                    timestamp,
                    peer_socket_id,
                )));
                packets_sent += 1;
            }
        });
        if let Some(control_info) = chunks.finish() {
            output_queue.push_back(ConnectionOutput::SendPacket(encode_nak_packet(
                control_info,
                timestamp,
                peer_socket_id,
            )));
            packets_sent += 1;
        }

        if packets_sent != 0 {
            self.last_send_time = Some(now);
            if let Some(receiver) = self.receiver.as_mut() {
                receiver.record_naks_sent(packets_sent);
            }
        }
        self.last_nak_time = Some(now);
    }

    /// Send an ACKACK packet.
    ///
    /// ACKACK is the acknowledgment for an ACK, used for RTT calculation.
    /// Per the SRT spec it's a 16-byte packet with a 0-byte data section, but
    /// for libsrt compatibility this sends 20 bytes with 4 bytes of zero
    /// padding added. See [`LIBSRT_COMPAT_PADDING`] for details.
    fn send_ackack(&mut self, ack_number: u32, now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::AckAck,
            subtype: 0,
            type_specific_info: ack_number,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            // libsrt 互換: データ部 0 バイト → 4 バイトゼロパディング
            control_info: LIBSRT_COMPAT_PADDING.to_vec(),
        };

        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_packet(buf, now);
    }

    fn send_induction_request(&mut self, now: Timestamp) {
        let mut hs = HandshakePacket::new_induction_request(self.options.socket_id);
        hs.flow_window = self.flight_capacity_packets();
        let pkt = hs.encode(self.relative_timestamp(now), 0);
        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_handshake_packet(buf);
    }

    /// SRT flags advertised in the CONCLUSION handshake extension.
    ///
    /// CRYPT, PERIODICNAK, and REXMITFLG are always set (legacy
    /// compatibility flags this crate always supports). TSBPDSND/TSBPDRCV
    /// and TLPKTDROP are live-streaming-only per spec: a real libsrt peer
    /// running its Buffer/File API (declared via `congestion_control ==
    /// "file"`) locally rejects a connection where TLPKTDROP is granted
    /// ("SRTO_TLPKTDROP flag can only be used with message API"), found via
    /// interop testing against `srt-file-transmit`. This crate's own
    /// receive/delivery path does not itself branch on these flags -- they
    /// only affect what's declared and checked by the peer.
    fn negotiated_srt_flags(&self) -> u32 {
        let live = self.options.congestion_control != "file";
        let mut flags = srt_flags::CRYPT | srt_flags::PERIODICNAK | srt_flags::REXMITFLG;
        if live {
            flags |= srt_flags::TSBPDSND | srt_flags::TSBPDRCV | srt_flags::TLPKTDROP;
        } else {
            flags |= srt_flags::STREAM;
        }
        flags
    }

    fn apply_peer_handshake_extension(&mut self, hs: &HandshakePacket) {
        let Some(extension) = hs.get_hs_extension() else {
            return;
        };
        self.options.tsbpd_delay = self.options.tsbpd_delay.max(extension.recv_tsbpd_delay);
        self.peer_srt_flags = Some(extension.srt_flags);
    }

    fn negotiated_feature(&self, local_flag: u32, peer_flag: u32) -> bool {
        self.negotiated_srt_flags() & local_flag != 0
            && self
                .peer_srt_flags
                .is_some_and(|flags| flags & peer_flag != 0)
    }

    fn tsbpd_enabled(&self) -> bool {
        self.negotiated_feature(srt_flags::TSBPDRCV, srt_flags::TSBPDSND)
    }

    fn tlpktdrop_enabled(&self) -> bool {
        self.negotiated_feature(srt_flags::TLPKTDROP, srt_flags::TLPKTDROP)
    }

    fn periodic_nak_enabled(&self) -> bool {
        self.negotiated_feature(srt_flags::PERIODICNAK, srt_flags::PERIODICNAK)
    }

    fn send_induction_response(&mut self, now: Timestamp) {
        let encryption_field = if self.options.passphrase.is_some() {
            self.options.key_length.to_encryption_field()
        } else {
            0
        };

        let mut hs = HandshakePacket::new_induction_response(
            self.options.socket_id,
            self.syn_cookie,
            encryption_field,
        );
        hs.flow_window = self.flight_capacity_packets();
        let pkt = hs.encode(self.relative_timestamp(now), self.peer_socket_id);
        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_handshake_packet(buf);
    }

    fn send_conclusion_request(&mut self, now: Timestamp) -> Result<(), Error> {
        let encryption_field = if self.options.passphrase.is_some() {
            self.options.key_length.to_encryption_field()
        } else {
            0
        };

        let has_encryption = self.options.passphrase.is_some();
        tracing::debug!(
            "sending CONCLUSION request, our_initial_seq={}, socket_id={:#x}, syn_cookie={:#x}",
            self.initial_seq,
            self.options.socket_id,
            self.syn_cookie
        );
        let mut hs = HandshakePacket::new_conclusion_request(
            self.options.socket_id,
            self.syn_cookie,
            self.initial_seq,
            encryption_field,
            has_encryption,
        );
        hs.flow_window = self.flight_capacity_packets();

        let flags = self.negotiated_srt_flags();

        hs.add_hs_extension(self.options.srt_version, flags, self.options.tsbpd_delay);

        // Declare our congestion control mode. A real libsrt peer that
        // declares its own mode refuses to transmit if we declare none at
        // all, assuming a live/file mismatch (see ConnectionOptions::congestion_control).
        hs.add_congestion_extension(&self.options.congestion_control);

        // Add a KMREQ extension if encryption is enabled.
        //
        // wrap_sek cannot actually fail on this path today (derive_kek
        // always produces a key_length.len()-byte KEK, and
        // CryptoContext::new_sender already validated the SEK's length), so
        // this is defensive-only, not a live bug -- but propagate rather
        // than silently drop it, matching the KM refresh path
        // (provide_new_sek -> start_pre_announce), which already does.
        // (found via upstream shiguredo/srt-rs issue 0056, not yet in the
        // pulled subtree)
        if let Some(ref crypto) = self.crypto {
            let wrapped_key = crypto.wrap_sek(crypto.current_key())?;
            let km_message = KmMessage::new(
                crypto.current_key(),
                crypto.key_length(),
                *crypto.salt(),
                wrapped_key,
                crypto.cipher_mode(),
            );
            hs.add_km_request(&km_message);
        }

        // Add a SID extension if a Stream ID is set.
        if let Some(ref stream_id) = self.options.stream_id {
            hs.add_sid_extension(stream_id);
        }

        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }

        // A CONCLUSION request is sent with dest_socket_id = 0 (libsrt compatibility).
        let pkt = hs.encode(self.relative_timestamp(now), 0);
        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_handshake_packet(buf);
        Ok(())
    }

    fn send_conclusion_response(&mut self, now: Timestamp) {
        let encryption_field = if self.options.passphrase.is_some() {
            self.options.key_length.to_encryption_field()
        } else {
            0
        };

        let has_encryption = self.options.passphrase.is_some();
        let mut hs = HandshakePacket::new_conclusion_response(
            self.options.socket_id,
            self.syn_cookie,
            self.initial_seq,
            encryption_field,
            has_encryption,
        );
        hs.flow_window = self.flight_capacity_packets();

        let flags = self.negotiated_srt_flags();

        hs.add_hs_response(self.options.srt_version, flags, self.options.tsbpd_delay);

        // Declare our congestion control mode (see send_conclusion_request).
        hs.add_congestion_extension(&self.options.congestion_control);

        // 受信した KMREQ をそのまま KMRSP として返す
        if let Some(ref km) = self.received_km {
            hs.add_km_response(km);
        }

        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }

        let pkt = hs.encode(self.relative_timestamp(now), self.peer_socket_id);
        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_handshake_packet(buf);
    }

    /// Queue a protocol-level KM failure and make the listener attempt
    /// terminal. The caller receives the precise encryption mismatch instead
    /// of timing out or observing an unencrypted downgrade.
    fn fail_listener_km(&mut self, now: Timestamp, error: KmError, reason: &str) -> Error {
        let mut hs = HandshakePacket::new_conclusion_response(
            self.options.socket_id,
            self.syn_cookie,
            self.initial_seq,
            0,
            true,
        );
        hs.flow_window = self.flight_capacity_packets();
        let flags = self.negotiated_srt_flags();
        hs.add_hs_response(self.options.srt_version, flags, self.options.tsbpd_delay);
        hs.add_km_error(error);
        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }
        let packet = hs.encode(self.relative_timestamp(now), self.peer_socket_id);
        let mut bytes = Vec::with_capacity(packet.encoded_size());
        packet.encode(&mut bytes);
        self.queue_handshake_packet(bytes);
        self.terminate_handshake();
        Error::handshake_rejected(reason)
    }

    fn fail_caller_handshake(&mut self, reason: &str) -> Error {
        self.terminate_handshake();
        Error::handshake_rejected(reason)
    }

    fn queue_handshake_packet(&mut self, packet: Vec<u8>) {
        self.last_handshake_packet = Some(packet.clone());
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(packet));
    }

    fn queue_packet(&mut self, packet: Vec<u8>, now: Timestamp) {
        self.last_send_time = Some(now);
        self.output_queue
            .push_back(ConnectionOutput::SendPacket(packet));
    }

    fn retransmit_handshake(&mut self) {
        if let Some(packet) = self.last_handshake_packet.as_ref() {
            self.output_queue
                .push_back(ConnectionOutput::SendPacket(packet.clone()));
        }
    }

    fn handshake_timed_out(&self, now: Timestamp) -> bool {
        self.handshake_started_at
            .is_some_and(|started| now.saturating_sub(started) >= self.handshake_timeout_micros)
    }

    fn fail_handshake_timeout(&mut self) {
        if self.handshake_state == HandshakeState::Failed {
            return;
        }
        self.event_queue
            .push_back(ConnectionEvent::Error("handshake timeout".to_string()));
        self.terminate_handshake();
    }

    fn arm_handshake_timer(&mut self, now: Timestamp) {
        // Spread retries later by up to 20% to desynchronize fan-in without
        // violating libsrt's "at most one request per interval" cadence.
        let jitter = {
            use std::hash::{BuildHasher, Hasher};
            // Not cryptographic: per-connection nondeterministic PRNG via
            // RandomState (&mut self cannot hold state).
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u32(self.options.socket_id);
            hasher.write_u32(self.handshake_retry_sequence);
            hasher.write_u64(self.initial_seq.into());
            hasher.finish()
        };
        let spread = self.handshake_retry_interval_micros / 5;
        let interval = self
            .handshake_retry_interval_micros
            .saturating_add(jitter % spread.saturating_add(1));
        // The final timer is a deadline wake-up, not another early retry.
        let remaining = self
            .handshake_started_at
            .map(|started| {
                started
                    .add_micros(self.handshake_timeout_micros)
                    .saturating_sub(now)
            })
            .unwrap_or(self.handshake_timeout_micros);
        self.output_queue.push_back(ConnectionOutput::SetTimer {
            id: TimerId::Handshake,
            duration_micros: interval.min(remaining),
        });
    }

    /// Send a Keepalive packet.
    ///
    /// Keepalive confirms the connection is still alive. It's sent when no
    /// data has been sent or received for a while, and receiving one lets the
    /// peer confirm the connection is still valid. Per the SRT spec it's a
    /// 16-byte packet with a 0-byte data section, but for libsrt
    /// compatibility this sends 20 bytes with 4 bytes of zero padding added.
    /// See [`LIBSRT_COMPAT_PADDING`] for details.
    fn send_keepalive(&mut self, now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::Keepalive,
            subtype: 0,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            // libsrt compatibility: 0-byte data section -> 4 bytes of zero padding.
            control_info: LIBSRT_COMPAT_PADDING.to_vec(),
        };
        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_packet(buf, now);
    }

    /// Send a Shutdown packet.
    ///
    /// Shutdown announces an orderly connection close. After sending this
    /// packet, the connection transitions to the disconnected state. Per the
    /// SRT spec it's a 16-byte packet with a 0-byte data section, but for
    /// libsrt compatibility this sends 20 bytes with 4 bytes of zero padding
    /// added. See [`LIBSRT_COMPAT_PADDING`] for details.
    fn send_shutdown(&mut self, now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::Shutdown,
            subtype: 0,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            // libsrt compatibility: 0-byte data section -> 4 bytes of zero padding.
            control_info: LIBSRT_COMPAT_PADDING.to_vec(),
        };
        let mut buf = Vec::with_capacity(pkt.encoded_size());
        pkt.encode(&mut buf);
        self.queue_packet(buf, now);
    }
}

/// Parse a loss list (from a NAK packet's control_info).
#[cfg(test)]
fn parse_loss_list(data: &[u8], max_entries: usize) -> Result<Vec<u32>, Error> {
    let ranges = parse_loss_ranges(data, max_entries)?;
    let mut result = Vec::with_capacity(max_entries.min(ranges.len()));
    for range in ranges {
        let mut sequence = range.first_seq;
        loop {
            result.push(sequence);
            if sequence == range.last_seq {
                break;
            }
            sequence = sequence.wrapping_add(1) & 0x7FFF_FFFF;
        }
    }
    Ok(result)
}

fn parse_loss_ranges(data: &[u8], max_entries: usize) -> Result<Vec<LossRange>, Error> {
    if !data.len().is_multiple_of(4) {
        return Err(Error::invalid_data(
            "NAK loss list length is not a multiple of four",
        ));
    }
    let mut result = Vec::with_capacity((data.len() / 4).min(max_entries));
    let mut slice = data;
    let mut remaining = max_entries;

    while !slice.is_empty() && remaining != 0 {
        let word = crate::buf::read_u32(&mut slice)?;
        if word & 0x8000_0000 != 0 {
            if slice.len() < 4 {
                return Err(Error::invalid_data("NAK range is missing its end"));
            }
            let start = word & 0x7FFF_FFFF;
            let end = crate::buf::read_u32(&mut slice)? & 0x7FFF_FFFF;
            let positions = (end.wrapping_sub(start) & 0x7FFF_FFFF) as usize + 1;
            let retained = positions.min(remaining);
            result.push(LossRange {
                first_seq: start,
                last_seq: start.wrapping_add(retained as u32 - 1) & 0x7FFF_FFFF,
            });
            remaining -= retained;
        } else {
            result.push(LossRange {
                first_seq: word,
                last_seq: word,
            });
            remaining -= 1;
        }
    }

    Ok(result)
}

/// Encode a loss list (for a NAK packet's control_info).
/// Consecutive sequence numbers are compressed by encoding them as a range.
#[cfg(test)]
fn encode_loss_list(loss_list: &[u32]) -> Vec<u8> {
    let mut result = Vec::new();

    if loss_list.is_empty() {
        return result;
    }

    // Detect consecutive sequence numbers as a range.
    let mut i = 0;
    while i < loss_list.len() {
        let start = loss_list[i];
        let mut end = start;

        // Look for consecutive sequence numbers.
        while i + 1 < loss_list.len() {
            let next = loss_list[i + 1];
            // Determine consecutiveness, accounting for sequence number wraparound.
            let expected_next = end.wrapping_add(1) & 0x7FFF_FFFF;
            if next == expected_next {
                end = next;
                i += 1;
            } else {
                break;
            }
        }

        encode_loss_range(&mut result, start, end);

        i += 1;
    }

    result
}

fn encode_loss_range(result: &mut Vec<u8>, start: u32, end: u32) {
    if start == end {
        write_u32(result, start & 0x7FFF_FFFF);
    } else {
        write_u32(result, (start & 0x7FFF_FFFF) | 0x8000_0000);
        write_u32(result, end & 0x7FFF_FFFF);
    }
}

struct NakChunkEncoder {
    control_info: Vec<u8>,
    max_control_info_size: usize,
}

impl NakChunkEncoder {
    fn new(max_control_info_size: usize) -> Self {
        assert!(
            max_control_info_size >= MAX_NAK_RECORD_SIZE,
            "SRT datagram budget must fit the largest NAK record"
        );
        Self {
            control_info: Vec::with_capacity(max_control_info_size.min(NAK_CHUNK_INITIAL_CAPACITY)),
            max_control_info_size,
        }
    }

    fn push(&mut self, loss: LossRange) -> Option<Vec<u8>> {
        let record_size = if loss.first_seq == loss.last_seq {
            4
        } else {
            MAX_NAK_RECORD_SIZE
        };
        let full_chunk = (!self.control_info.is_empty()
            && self.control_info.len() + record_size > self.max_control_info_size)
            .then(|| {
                std::mem::replace(
                    &mut self.control_info,
                    // Crossing the first chunk proves this is not the common
                    // sparse case. Pre-size subsequent chunks to avoid
                    // repeating geometric growth for every datagram.
                    Vec::with_capacity(self.max_control_info_size),
                )
            });
        encode_loss_range(&mut self.control_info, loss.first_seq, loss.last_seq);
        full_chunk
    }

    fn finish(self) -> Option<Vec<u8>> {
        (!self.control_info.is_empty()).then_some(self.control_info)
    }
}

fn encode_nak_packet(control_info: Vec<u8>, timestamp: u32, peer_socket_id: u32) -> Vec<u8> {
    let packet = ControlPacket {
        control_type: ControlType::Nak,
        subtype: 0,
        type_specific_info: 0,
        timestamp,
        dest_socket_id: peer_socket_id,
        control_info,
    };
    let mut encoded = Vec::with_capacity(packet.encoded_size());
    packet.encode(&mut encoded);
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GroupType, SRTGROUP_MASK};

    /// Deterministic, non-secret KM salt for protocol test fixtures.
    fn test_km_salt() -> [u8; 16] {
        std::array::from_fn(|index| index as u8)
    }

    #[test]
    fn test_connection_options_default() {
        let opts = ConnectionOptions::default();
        // Sans I/O 化により socket_id は外部から設定する必要がある
        assert_eq!(opts.socket_id, 0);
        assert!(opts.passphrase.is_none());
        assert!(opts.crypto_salt.is_none());
        assert!(opts.crypto_sek.is_none());
        assert_eq!(opts.key_length, KeyLength::Aes128);
    }

    #[test]
    fn test_caller_initial_state() {
        let conn = SrtConnection::new_caller(ConnectionOptions::default());
        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert_eq!(conn.role, ConnectionRole::Caller);
    }

    #[test]
    fn key_refresh_needed_is_emitted_once_until_sek_is_provided() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        let mut crypto = CryptoContext::new_sender(
            "test passphrase",
            KeyLength::Aes128,
            test_km_salt(),
            &[0x24; 16],
            CipherMode::Ctr,
        )
        .expect("valid sender crypto");
        crypto.set_encrypted_packet_count_for_test(
            CryptoContext::KM_REFRESH_PERIOD - CryptoContext::KM_PRE_ANNOUNCE_PERIOD,
        );
        conn.crypto = Some(crypto);

        conn.check_km_refresh(Timestamp::from_micros(1));
        conn.check_km_refresh(Timestamp::from_micros(2));
        assert_eq!(
            conn.event_queue
                .iter()
                .filter(|event| matches!(event, ConnectionEvent::KeyRefreshNeeded { .. }))
                .count(),
            1,
            "the threshold must notify the application once, not once per send"
        );

        conn.provide_new_sek(&[0x25; 16], Timestamp::from_micros(3))
            .expect("application supplies the requested SEK");
        assert!(
            !conn.key_refresh_notified,
            "starting the refresh cycle releases the latch for the next cycle"
        );
    }

    #[test]
    fn refresh_kmreq_without_crypto_gets_nosecret_response() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.peer_socket_id = 0x2000_0002;
        let request = KmMessage::new(
            KeyFlag::Even,
            KeyLength::Aes128,
            test_km_salt(),
            vec![0x24; 24],
            CipherMode::Ctr,
        );

        conn.handle_user_defined(
            ControlPacket {
                control_type: ControlType::UserDefined,
                subtype: 3,
                type_specific_info: 0,
                timestamp: 0,
                dest_socket_id: 0,
                control_info: request.encode(),
            },
            Timestamp::from_micros(1),
        )
        .expect("unsecured refresh KMREQ is answered");

        let Some(ConnectionOutput::SendPacket(bytes)) = conn.poll_output() else {
            panic!("KMRSP NOSECRET is queued");
        };
        let SrtPacket::Control(response) = SrtPacket::decode(&bytes).expect("valid response")
        else {
            panic!("response is a control packet");
        };
        assert_eq!(response.control_type, ControlType::UserDefined);
        assert_eq!(response.subtype, 4, "KMRSP subtype");
        assert_eq!(response.dest_socket_id, 0x2000_0002);
        assert_eq!(
            response.control_info,
            (KmError::NoSecret as u32).to_be_bytes()
        );
    }

    #[test]
    fn handshake_retry_is_not_armed_early() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.connect(Timestamp::from_micros(0))
            .expect("caller connection starts");

        assert!(matches!(
            conn.poll_output(),
            Some(ConnectionOutput::SendPacket(_))
        ));
        let Some(ConnectionOutput::SetTimer {
            id: TimerId::Handshake,
            duration_micros,
        }) = conn.poll_output()
        else {
            panic!("caller arms its handshake retry");
        };
        assert!(duration_micros >= DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS);
        assert!(duration_micros <= DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS * 6 / 5);
    }

    #[test]
    fn handshake_deadline_covers_all_phases() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.connect(Timestamp::from_micros(0))
            .expect("caller connection starts");
        while conn.poll_output().is_some() {}

        conn.handle_timer(
            TimerId::Handshake,
            Timestamp::from_micros(DEFAULT_HANDSHAKE_TIMEOUT_MICROS),
        )
        .expect("deadline processing succeeds");

        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::StateChanged(ConnectionState::Induction))
        ));
        assert!(
            matches!(conn.poll_event(), Some(ConnectionEvent::Error(message)) if message == "handshake timeout")
        );
    }

    #[test]
    fn custom_handshake_timing_is_honored() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.set_handshake_timing(400_000, 900_000);
        conn.connect(Timestamp::from_micros(100_000))
            .expect("caller connection starts");
        let _ = conn.poll_output();
        let Some(ConnectionOutput::SetTimer {
            duration_micros, ..
        }) = conn.poll_output()
        else {
            panic!("caller arms its handshake retry");
        };
        assert!((400_000..=480_000).contains(&duration_micros));

        conn.handle_timer(TimerId::Handshake, Timestamp::from_micros(1_000_000))
            .expect("deadline processing succeeds");
        assert_eq!(conn.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn caller_rejects_induction_response_without_srt_magic() {
        let mut caller = SrtConnection::new_caller(ConnectionOptions::default());
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts induction");
        let mut response = HandshakePacket::new_induction_response(42, 99, 0);
        response.extension_field = 0;

        let error = caller
            .handle_handshake_caller(response, 0, Timestamp::from_micros(1))
            .expect_err("rogue induction response is rejected");

        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert!(error.reason.contains("magic"));
        assert_eq!(caller.state(), ConnectionState::Disconnected);
        assert_eq!(caller.peer_socket_id(), 0);
    }

    #[test]
    fn caller_rejects_legacy_induction_response() {
        let mut caller = SrtConnection::new_caller(ConnectionOptions::default());
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts induction");
        let mut response = HandshakePacket::new_induction_response(42, 99, 0);
        response.version = 4;

        let error = caller
            .handle_handshake_caller(response, 0, Timestamp::from_micros(1))
            .expect_err("legacy induction response is rejected");

        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert!(error.reason.contains("version"));
        assert_eq!(caller.state(), ConnectionState::Disconnected);
        assert_eq!(caller.peer_socket_id(), 0);
    }

    #[test]
    fn handshake_negotiates_the_larger_latency_for_both_peers() {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            tsbpd_delay: 500,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            tsbpd_delay: 120,
            syn_cookie: Some(7),
            ..ConnectionOptions::default()
        });

        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        for round in 0..4 {
            let now = Timestamp::from_micros(round * 10_000);
            while let Some(ConnectionOutput::SendPacket(packet)) = caller.poll_output() {
                listener
                    .feed_recv_buf(&packet, now)
                    .expect("listener accepts packet");
            }
            while let Some(ConnectionOutput::SendPacket(packet)) = listener.poll_output() {
                caller
                    .feed_recv_buf(&packet, now)
                    .expect("caller accepts packet");
            }
            if caller.state() == ConnectionState::Connected
                && listener.state() == ConnectionState::Connected
            {
                break;
            }
        }

        assert_eq!(caller.state(), ConnectionState::Connected);
        assert_eq!(listener.state(), ConnectionState::Connected);
        assert_eq!(caller.options.tsbpd_delay, 500);
        assert_eq!(listener.options.tsbpd_delay, 500);
        assert!(
            caller
                .receiver
                .as_ref()
                .expect("caller receiver")
                .tsbpd_enabled()
        );
        assert!(
            listener
                .receiver
                .as_ref()
                .expect("listener receiver")
                .tsbpd_enabled()
        );
    }

    #[test]
    fn peer_capabilities_disable_optional_live_behaviour() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        let mut peer = HandshakePacket::new_conclusion_request(1, 0, 0, 0, false);
        peer.add_hs_extension(0x010500, srt_flags::CRYPT | srt_flags::REXMITFLG, 120);
        conn.apply_peer_handshake_extension(&peer);
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);

        assert!(!conn.tsbpd_enabled());
        assert!(!conn.tlpktdrop_enabled());
        assert!(!conn.periodic_nak_enabled());
        assert!(!conn.receiver.as_ref().expect("receiver").tsbpd_enabled());
    }

    #[test]
    fn keepalive_waits_for_one_second_of_outbound_idle_time() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        conn.set_state(ConnectionState::Connected);
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        while conn.poll_output().is_some() {}

        conn.send(b"data", Timestamp::from_micros(900_000))
            .expect("connected sender queues data");
        while conn.poll_output().is_some() {}

        conn.handle_timer(TimerId::Keepalive, Timestamp::from_micros(1_500_000))
            .expect("keepalive timer succeeds");
        assert!(std::iter::from_fn(|| conn.poll_output()).all(
            |output| !matches!(output, ConnectionOutput::SendPacket(packet) if matches!(SrtPacket::decode(&packet), Ok(SrtPacket::Control(ControlPacket { control_type: ControlType::Keepalive, .. }))))
        ));

        conn.handle_timer(TimerId::Keepalive, Timestamp::from_micros(1_900_000))
            .expect("keepalive timer succeeds");
        assert!(std::iter::from_fn(|| conn.poll_output()).any(
            |output| matches!(output, ConnectionOutput::SendPacket(packet) if matches!(SrtPacket::decode(&packet), Ok(SrtPacket::Control(ControlPacket { control_type: ControlType::Keepalive, .. }))))
        ));
    }

    #[test]
    fn local_disconnect_flushes_tsbpd_buffered_data() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        conn.set_state(ConnectionState::Connected);
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        conn.receiver
            .as_mut()
            .expect("receiver")
            .set_tsbpd_enabled(true);
        while conn.poll_event().is_some() {}
        while conn.poll_output().is_some() {}

        conn.handle_data_packet(
            DataPacket::new(0, 0, 0, 0, b"queued".to_vec().into()),
            Timestamp::from_micros(1),
        )
        .expect("packet is buffered for TSBPD");
        assert!(conn.poll_event().is_none());

        conn.disconnect(Timestamp::from_micros(2));

        assert!(std::iter::from_fn(|| conn.poll_event()).any(
            |event| matches!(event, ConnectionEvent::DataReceived { payload, .. } if payload.as_ref() == b"queued")
        ));
        assert_eq!(conn.state(), ConnectionState::Closing);
    }

    #[test]
    fn closing_retries_shutdown_until_peer_activity() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        conn.set_state(ConnectionState::Connected);
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        while conn.poll_event().is_some() {}
        while conn.poll_output().is_some() {}

        conn.disconnect(Timestamp::from_micros(0));
        assert_eq!(conn.state(), ConnectionState::Closing);
        assert!(
            std::iter::from_fn(|| conn.poll_output()).any(|output| matches!(
                output,
                ConnectionOutput::SetTimer {
                    id: TimerId::Shutdown,
                    ..
                }
            ))
        );

        conn.handle_timer(TimerId::Shutdown, Timestamp::from_micros(1_000_000))
            .expect("shutdown retry succeeds");
        assert!(std::iter::from_fn(|| conn.poll_output()).any(
            |output| matches!(output, ConnectionOutput::SendPacket(packet) if matches!(SrtPacket::decode(&packet), Ok(SrtPacket::Control(ControlPacket { control_type: ControlType::Shutdown, .. }))))
        ));

        conn.handle_control_packet(
            ControlPacket {
                control_type: ControlType::Keepalive,
                subtype: 0,
                type_specific_info: 0,
                timestamp: 0,
                dest_socket_id: 0,
                control_info: Vec::new(),
            },
            Timestamp::from_micros(1_000_001),
        )
        .expect("peer activity completes close");
        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(
            std::iter::from_fn(|| conn.poll_output()).any(|output| matches!(
                output,
                ConnectionOutput::ClearTimer {
                    id: TimerId::Shutdown
                }
            ))
        );
    }

    #[test]
    fn closing_times_out_after_shutdown_retries() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        conn.set_state(ConnectionState::Connected);
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        while conn.poll_event().is_some() {}
        while conn.poll_output().is_some() {}
        conn.disconnect(Timestamp::from_micros(0));
        while conn.poll_output().is_some() {}

        conn.handle_timer(
            TimerId::Shutdown,
            Timestamp::from_micros(SHUTDOWN_TIMEOUT_MICROS),
        )
        .expect("shutdown timeout succeeds");

        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(std::iter::from_fn(|| conn.poll_event()).any(
            |event| matches!(event, ConnectionEvent::Disconnected { reason } if reason == "shutdown timeout")
        ));
    }

    #[test]
    fn test_listener_initial_state() {
        let conn = SrtConnection::new_listener(ConnectionOptions::default());
        assert_eq!(conn.state(), ConnectionState::Listening);
        assert_eq!(conn.role, ConnectionRole::Listener);
    }

    #[test]
    fn listener_policy_configures_receive_window_before_conclusion() {
        let mut listener = SrtConnection::new_listener(ConnectionOptions::default());
        listener
            .set_listener_policy(None, KeyLength::Aes128, 2_000, 32_768, 8_548)
            .expect("listener policy is still mutable before conclusion");

        listener.init_buffers(Timestamp::from_micros(0), 100, 0);
        let ack = listener
            .receiver
            .as_mut()
            .expect("listener receiver exists")
            .generate_ack(Timestamp::from_micros(0));
        assert_eq!(ack.available_buffer, 8_548);

        listener.send_conclusion_response(Timestamp::from_micros(0));
        let ConnectionOutput::SendPacket(packet) = listener
            .poll_output()
            .expect("listener emits conclusion response")
        else {
            panic!("listener conclusion response is a packet");
        };
        let SrtPacket::Control(control) = SrtPacket::decode(&packet).expect("valid SRT packet")
        else {
            panic!("listener conclusion response is control");
        };
        let handshake = HandshakePacket::decode(&control).expect("valid handshake");
        assert_eq!(handshake.flow_window, 8_548);
    }

    #[test]
    fn connection_options_bound_receive_windows_before_first_loss() {
        for requested in [MAX_FLOW_WINDOW, MAX_FLOW_WINDOW + 1, u32::MAX] {
            let mut connection = SrtConnection::new_caller(ConnectionOptions {
                flow_window_packets: requested,
                receive_buffer_packets: requested,
                ..ConnectionOptions::default()
            });
            let expected = requested.min(MAX_FLOW_WINDOW);
            assert_eq!(connection.options.flow_window_packets, expected);
            assert_eq!(connection.options.receive_buffer_packets, expected);

            connection.init_buffers(Timestamp::default(), 0, 0);
            let receiver = connection.receiver.as_mut().unwrap();
            receiver.set_tsbpd_enabled(false);
            assert_eq!(
                receiver.receive(
                    DataPacket::new(1, 1, 0, 0, Bytes::new()),
                    Timestamp::from_micros(1)
                ),
                Some(crate::srt_receiver::LossRange {
                    first_seq: 0,
                    last_seq: 0,
                })
            );
            assert_eq!(receiver.stats().max_buffer_packets, expected);
        }
    }

    #[test]
    fn listener_flow_control_rejects_windows_above_supported_maximum() {
        let mut listener = SrtConnection::new_listener(ConnectionOptions::default());
        listener
            .set_listener_flow_control(MAX_FLOW_WINDOW, MAX_FLOW_WINDOW)
            .expect("maximum supported windows are accepted");

        for (flow_window, receive_window) in [
            (MAX_FLOW_WINDOW + 1, MAX_FLOW_WINDOW),
            (MAX_FLOW_WINDOW, MAX_FLOW_WINDOW + 1),
            (u32::MAX, u32::MAX),
        ] {
            let error = listener
                .set_listener_flow_control(flow_window, receive_window)
                .expect_err("oversized listener windows are rejected");
            assert_eq!(error.kind, crate::error::ErrorKind::InvalidState);
        }

        let error = listener
            .set_listener_policy(None, KeyLength::Aes128, 120, u32::MAX, u32::MAX)
            .expect_err("combined listener policy uses the same bound");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidState);
    }

    #[test]
    fn unread_data_events_are_bounded_and_consume_receive_window() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            flow_window_packets: 3,
            receive_buffer_packets: 3,
            delivery_queue_packets: 2,
            ..ConnectionOptions::default()
        });
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        let now = Timestamp::from_micros(0);
        conn.init_buffers(now, 0, 0);
        conn.receiver
            .as_mut()
            .expect("connected listener has a receiver")
            .set_tsbpd_enabled(false);

        // The protocol enforces a minimum 32-packet SRT flow window; fill it
        // while keeping only two payloads in the application queue.
        for sequence_number in 0..32 {
            conn.handle_data_packet(
                DataPacket::new(sequence_number, sequence_number, 0, 0, vec![1].into()),
                now,
            )
            .expect("data is accepted");
        }

        assert_eq!(conn.pending_data_events, 2);
        let stats = conn.receiver_stats().expect("receiver stats");
        assert_eq!(stats.packets_in_buffer, 30);
        assert_eq!(stats.available_buffer_packets, 0);

        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::DataReceived { .. })
        ));
        assert_eq!(conn.pending_data_events, 1);
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(10_000))
            .expect("ACK timer drains newly admitted delivery");
        assert_eq!(conn.pending_data_events, 2);
        assert_eq!(
            conn.receiver_stats()
                .expect("receiver stats")
                .available_buffer_packets,
            1
        );
    }

    #[test]
    fn fragmented_application_message_retains_each_receive_position() {
        const PACKETS: u32 = 32;
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            flow_window_packets: PACKETS,
            receive_buffer_packets: PACKETS,
            delivery_queue_packets: 1,
            ..ConnectionOptions::default()
        });
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        let now = Timestamp::from_micros(0);
        conn.init_buffers(now, 0, 0);
        conn.receiver
            .as_mut()
            .expect("connected listener has a receiver")
            .set_tsbpd_enabled(false);

        for sequence_number in 0..PACKETS {
            let position = match sequence_number {
                0 => crate::srt_packet::PacketPosition::First,
                n if n == PACKETS - 1 => crate::srt_packet::PacketPosition::Last,
                _ => crate::srt_packet::PacketPosition::Middle,
            };
            let mut packet = DataPacket::new(sequence_number, 7, 0, 0, vec![1].into());
            packet.position = position;
            conn.handle_data_packet(packet, now)
                .expect("fragment is processed");
        }

        assert_eq!(conn.pending_data_events, 1);
        assert_eq!(conn.pending_data_packets, PACKETS);
        let stats = conn.receiver_stats().expect("receiver stats");
        assert_eq!(stats.packets_in_buffer, 0);
        assert_eq!(stats.available_buffer_packets, 0);

        conn.handle_data_packet(DataPacket::new(PACKETS, 8, 0, 0, vec![2].into()), now)
            .expect("full receiver drops without failing the connection");
        assert_eq!(
            conn.receiver_stats()
                .expect("receiver stats")
                .total_received,
            u64::from(PACKETS)
        );

        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::DataReceived {
                packet_count: PACKETS,
                ..
            })
        ));
        assert_eq!(conn.pending_data_packets, 0);
        assert_eq!(
            conn.receiver_stats()
                .expect("receiver stats")
                .available_buffer_packets,
            PACKETS
        );
    }

    #[test]
    fn delivery_packet_accounting_inline_footprint_stays_bounded() {
        let connection_bytes = std::mem::size_of::<SrtConnection>();
        let event_bytes = std::mem::size_of::<ConnectionEvent>();
        let assembled_bytes = std::mem::size_of::<crate::message_assembler::AssembledMessage>();
        eprintln!("SrtConnection inline footprint: {connection_bytes} bytes");
        eprintln!("ConnectionEvent inline footprint: {event_bytes} bytes");
        eprintln!("AssembledMessage inline footprint: {assembled_bytes} bytes");
        assert!(connection_bytes <= 1_536);
        assert!(event_bytes <= 64);
        assert!(assembled_bytes <= 48);
    }

    #[test]
    fn listener_encryption_replacement_clears_inapplicable_key_material() {
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            passphrase: Some("old-secret-123".to_owned()),
            crypto_salt: Some([7; 16]),
            crypto_sek: Some(vec![9; 16]),
            ..ConnectionOptions::default()
        });
        listener
            .set_listener_encryption(Some("tenant-secret-123".to_owned()), KeyLength::Aes256)
            .expect("listener policy window");

        assert_eq!(
            listener.options.passphrase.as_deref(),
            Some("tenant-secret-123")
        );
        assert_eq!(listener.options.key_length, KeyLength::Aes256);
        assert!(listener.options.crypto_salt.is_none());
        assert!(listener.options.crypto_sek.is_none());

        listener.set_state(ConnectionState::Connected);
        let error = listener
            .set_listener_bandwidth(Some(1_000_000))
            .expect_err("live policy mutation must be rejected");
        assert_eq!(error.kind, crate::ErrorKind::InvalidState);
    }

    #[test]
    fn group_extension_is_only_sent_in_conclusion() {
        let group = GroupExtensionData {
            group_id: SRTGROUP_MASK | 0x1234,
            group_type: GroupType::Backup,
            flags: 0,
            weight: 1,
        };
        let mut conn = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 17,
            group_extension: Some(group),
            ..ConnectionOptions::default()
        });
        conn.connect(Timestamp::from_micros(0))
            .expect("caller connection starts");
        let ConnectionOutput::SendPacket(packet) = conn.poll_output().expect("induction packet")
        else {
            panic!("caller must emit an induction packet");
        };
        let SrtPacket::Control(control) = SrtPacket::decode(&packet).expect("valid SRT packet")
        else {
            panic!("induction must be a control packet");
        };
        let handshake = HandshakePacket::decode(&control).expect("valid handshake");
        assert_eq!(handshake.get_group_extension(), None);

        conn.syn_cookie = 9;
        conn.send_conclusion_request(Timestamp::from_micros(1))
            .expect("caller emits conclusion");
        let packet = loop {
            match conn.poll_output() {
                Some(ConnectionOutput::SendPacket(packet)) => break packet,
                Some(_) => {}
                None => panic!("caller must emit a conclusion packet"),
            }
        };
        let SrtPacket::Control(control) = SrtPacket::decode(&packet).expect("valid SRT packet")
        else {
            panic!("conclusion must be a control packet");
        };
        let handshake = HandshakePacket::decode(&control).expect("valid handshake");
        assert_eq!(handshake.get_group_extension(), Some(group));
    }

    #[test]
    fn validate_kmrsp_rejects_encrypted_caller_without_response() {
        let sek: Vec<u8> = (1..=16).collect();
        let mut conn = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            passphrase: Some("test_passphrase".into()),
            crypto_salt: Some(test_km_salt()),
            crypto_sek: Some(sek.clone()),
            ..Default::default()
        });
        conn.connect(Timestamp::from_micros(0)).unwrap();
        conn.crypto = Some(
            CryptoContext::new_sender(
                "test_passphrase",
                KeyLength::Aes128,
                test_km_salt(),
                &sek,
                CipherMode::Ctr,
            )
            .unwrap(),
        );

        // A CONCLUSION with no KMRSP should fail for an encrypted caller.
        let hs = HandshakePacket {
            version: HS_VERSION_5,
            encryption_field: 0,
            extension_field: 0,
            initial_packet_seq: 0,
            mtu: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Conclusion,
            socket_id: 2,
            syn_cookie: 0,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            extensions: vec![],
            reject_reason: None,
        };
        let result = conn.validate_caller_kmrsp(&hs);
        assert!(result.is_err());
    }

    #[test]
    fn validate_kmrsp_accepts_unencrypted_caller_without_response() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..Default::default()
        });
        conn.connect(Timestamp::from_micros(0)).unwrap();

        let hs = HandshakePacket {
            version: HS_VERSION_5,
            encryption_field: 0,
            extension_field: 0,
            initial_packet_seq: 0,
            mtu: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Conclusion,
            socket_id: 2,
            syn_cookie: 0,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            extensions: vec![],
            reject_reason: None,
        };
        let result = conn.validate_caller_kmrsp(&hs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_loss_list_encode_decode_single() {
        // 単一のシーケンス番号
        let loss_list = vec![100, 200, 300];
        let encoded = encode_loss_list(&loss_list);
        let decoded = parse_loss_list(&encoded, loss_list.len()).expect("valid loss list");
        assert_eq!(decoded, loss_list);
    }

    #[test]
    fn test_loss_list_encode_decode_range() {
        // 連続するシーケンス番号は範囲としてエンコードされる
        let loss_list = vec![100, 101, 102, 103, 200, 201];
        let encoded = encode_loss_list(&loss_list);
        let decoded = parse_loss_list(&encoded, loss_list.len()).expect("valid loss list");
        assert_eq!(decoded, loss_list);
        // 範囲エンコードにより元の 6*4=24 バイトが 3*4=12 バイトに圧縮
        // (100-103 が 8 バイト、200-201 が 8 バイト = 16 バイト)
        assert_eq!(encoded.len(), 16);
    }

    #[test]
    fn test_loss_list_encode_decode_mixed() {
        // 単一と連続の混合
        let loss_list = vec![50, 100, 101, 102, 200];
        let encoded = encode_loss_list(&loss_list);
        let decoded = parse_loss_list(&encoded, loss_list.len()).expect("valid loss list");
        assert_eq!(decoded, loss_list);
    }

    #[test]
    fn test_loss_list_encode_empty() {
        let loss_list: Vec<u32> = vec![];
        let encoded = encode_loss_list(&loss_list);
        assert!(encoded.is_empty());
    }

    #[test]
    fn immediate_and_periodic_naks_encode_dense_loss_as_one_range() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        conn.set_state(ConnectionState::Connected);
        conn.init_buffers(Timestamp::default(), 0, 0);
        while conn.poll_output().is_some() {}

        conn.handle_data_packet(
            DataPacket::new(8_191, 1, 1, 0, Vec::new().into()),
            Timestamp::from_micros(1),
        )
        .expect("the gap is accepted");

        let expected = [0x8000_0000u32.to_be_bytes(), 8_190u32.to_be_bytes()].concat();
        let immediate = std::iter::from_fn(|| conn.poll_output()).find_map(|output| match output {
            ConnectionOutput::SendPacket(bytes) => match SrtPacket::decode(&bytes) {
                Ok(SrtPacket::Control(packet)) if packet.control_type == ControlType::Nak => {
                    Some(packet.control_info)
                }
                _ => None,
            },
            _ => None,
        });
        assert_eq!(immediate.as_deref(), Some(expected.as_slice()));

        conn.send_periodic_nak(Timestamp::from_micros(2));
        let periodic = std::iter::from_fn(|| conn.poll_output()).find_map(|output| match output {
            ConnectionOutput::SendPacket(bytes) => match SrtPacket::decode(&bytes) {
                Ok(SrtPacket::Control(packet)) if packet.control_type == ControlType::Nak => {
                    Some(packet.control_info)
                }
                _ => None,
            },
            _ => None,
        });
        assert_eq!(periodic.as_deref(), Some(expected.as_slice()));
    }

    #[test]
    fn immediate_nak_encodes_loss_range_across_sequence_wrap() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        conn.set_state(ConnectionState::Connected);
        conn.init_buffers(Timestamp::default(), 0x7FFF_FFFC, 0);

        conn.handle_data_packet(
            DataPacket::new(1, 1, 1, 0, Vec::new().into()),
            Timestamp::from_micros(1),
        )
        .expect("the wrapped gap is accepted");

        let control_info =
            std::iter::from_fn(|| conn.poll_output()).find_map(|output| match output {
                ConnectionOutput::SendPacket(bytes) => match SrtPacket::decode(&bytes) {
                    Ok(SrtPacket::Control(packet)) if packet.control_type == ControlType::Nak => {
                        Some(packet.control_info)
                    }
                    _ => None,
                },
                _ => None,
            });
        let decoded = parse_loss_list(
            &control_info.expect("an immediate NAK is emitted"),
            usize::MAX,
        )
        .expect("the wrapped NAK range decodes");
        assert_eq!(
            decoded,
            vec![0x7FFF_FFFC, 0x7FFF_FFFD, 0x7FFF_FFFE, 0x7FFF_FFFF, 0]
        );
    }

    #[test]
    fn nak_chunk_encoder_honors_exact_budget_and_preserves_wrapped_ranges() {
        let ranges = [
            LossRange {
                first_seq: 1,
                last_seq: 1,
            },
            LossRange {
                first_seq: 0x7FFF_FFFE,
                last_seq: 1,
            },
            LossRange {
                first_seq: 3,
                last_seq: 3,
            },
        ];
        let mut encoder = NakChunkEncoder::new(12);
        let mut chunks = Vec::new();
        for range in ranges {
            if let Some(chunk) = encoder.push(range) {
                chunks.push(chunk);
            }
        }
        chunks.extend(encoder.finish());

        assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), [12, 4]);
        assert_eq!(
            parse_loss_list(&chunks[0], usize::MAX).unwrap(),
            [1, 0x7FFF_FFFE, 0x7FFF_FFFF, 0, 1,]
        );
        assert_eq!(parse_loss_list(&chunks[1], usize::MAX).unwrap(), [3]);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "maximum-window scale is covered normally; Miri runs exact chunk boundaries"
    )]
    fn periodic_nak_chunks_maximum_alternating_window_without_wire_loss() {
        let options = ConnectionOptions {
            flow_window_packets: MAX_FLOW_WINDOW,
            receive_buffer_packets: MAX_FLOW_WINDOW,
            ..ConnectionOptions::default()
        };
        let mut conn = SrtConnection::new_listener(options);
        conn.set_state(ConnectionState::Connected);
        conn.init_buffers(Timestamp::default(), 0, 0);
        while conn.poll_output().is_some() {}

        let now = Timestamp::from_micros(1);
        let receiver = conn.receiver.as_mut().unwrap();
        receiver.receive(
            DataPacket::new(MAX_FLOW_WINDOW - 1, 1, 1, 0, Vec::new().into()),
            now,
        );
        for sequence_number in (1..MAX_FLOW_WINDOW - 1).step_by(2) {
            receiver.receive(
                DataPacket::new(sequence_number, 1, 1, 0, Vec::new().into()),
                now,
            );
        }

        conn.send_periodic_nak(Timestamp::from_micros(2));
        let mut decoded = Vec::new();
        let mut wire_packets = 0u64;
        while let Some(output) = conn.poll_output() {
            let ConnectionOutput::SendPacket(bytes) = output else {
                continue;
            };
            let SrtPacket::Control(packet) = SrtPacket::decode(&bytes).unwrap() else {
                continue;
            };
            if packet.control_type != ControlType::Nak {
                continue;
            }
            assert!(bytes.len() <= DEFAULT_MTU as usize);
            decoded.extend(parse_loss_list(&packet.control_info, usize::MAX).unwrap());
            wire_packets += 1;
        }

        let expected: Vec<u32> = (0..MAX_FLOW_WINDOW - 1).step_by(2).collect();
        assert_eq!(decoded, expected);
        assert_eq!(wire_packets, 89);
        assert_eq!(conn.stats().receiver.unwrap().total_naks_sent, wire_packets);
    }

    #[test]
    fn loss_list_limit_clamps_across_ranges_and_singles() {
        let mut encoded = Vec::new();
        write_u32(&mut encoded, 0x8000_0001);
        write_u32(&mut encoded, 3);
        write_u32(&mut encoded, 10);
        write_u32(&mut encoded, 11);

        assert_eq!(
            parse_loss_list(&encoded, 4).expect("loss report is safely clamped"),
            vec![1, 2, 3, 10]
        );
    }

    #[test]
    fn dense_loss_list_stays_compact_while_enforcing_position_limit() {
        let mut encoded = Vec::new();
        write_u32(&mut encoded, 0x8000_0000);
        write_u32(&mut encoded, 65_535);

        assert_eq!(
            parse_loss_ranges(&encoded, 65_536).unwrap(),
            [LossRange {
                first_seq: 0,
                last_seq: 65_535,
            }]
        );
        assert_eq!(
            parse_loss_ranges(&encoded, 32).unwrap(),
            [LossRange {
                first_seq: 0,
                last_seq: 31,
            }]
        );
    }

    #[test]
    fn loss_list_rejects_a_truncated_range() {
        let encoded = 0x8000_0001u32.to_be_bytes();
        let error = parse_loss_list(&encoded, 8).expect_err("range end is required");
        assert_eq!(error.kind, crate::ErrorKind::InvalidData);
    }
}
