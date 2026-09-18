//! SRT Connection (sans-I/O pattern).
//!
//! A state machine that manages an SRT connection.
//! I/O happens externally; this struct operates in a buffer-driven way.

use std::collections::VecDeque;
use std::fmt;

use bytes::{Bytes, BytesMut};
use zeroize::{Zeroize, Zeroizing};

use crate::buf::{read_u32, write_u32};
use crate::crypto_impl::{CipherMode, CryptoContext, GCM_TAG_LEN, KeyFlag, KeyLength};
use crate::error::Error;
use crate::message_assembler::MessageAssembler;
use crate::sender_rto::RtoArm;
use crate::srt_handshake::{
    DEFAULT_FLOW_WINDOW, DEFAULT_MTU, GroupExtensionData, HS_VERSION_5, HandshakePacket,
    HandshakeState, HandshakeType, KmError, KmMessage, MAX_FLOW_WINDOW, SRT_MAGIC_CODE, srt_flags,
};
use crate::srt_packet::{
    ControlPacket, ControlType, DataHeader, DataPacket, DatagramClass, PendingData,
    PendingDatagram, SRT_CMD_KMREQ, SRT_CMD_KMRSP, SRT_HEADER_SIZE, SrtPacket, sequence_less_than,
};
use crate::srt_receiver::{LossRange, ReceiverBuffer};
use crate::srt_sender::SenderBuffer;
use crate::stats::ConnectionStats;
use crate::time::Timestamp;

const MAX_NAK_RECORD_SIZE: usize = 8;
const NAK_CHUNK_INITIAL_CAPACITY: usize = 32;
const _: () = assert!(DEFAULT_MTU as usize - SRT_HEADER_SIZE >= MAX_NAK_RECORD_SIZE);

/// Bytes in one encoded NAK range (`first_seq` + `last_seq`).
pub const NAK_RANGE_BYTES: usize = MAX_NAK_RECORD_SIZE;
/// Control-information bytes in a Light ACK.
pub const LIGHT_ACK_CONTROL_INFO_BYTES: usize = 4;
/// Control-information bytes in a Full ACK.
pub const FULL_ACK_CONTROL_INFO_BYTES: usize = 28;

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
    /// Zero-delay continuation of an already-existing retransmission queue.
    ///
    /// This is *not* a loss timeout: it carries no elapsed time, no backoff and
    /// no notion of loss. It exists so one visit's bounded retransmission work
    /// can schedule the next visit's share of work it deliberately did not do
    /// (`process_retransmit`'s per-visit cap), and it is armed by nothing else.
    /// The sender's actual timeout is [`TimerId::SenderRto`].
    RetransmitContinue,
    /// Handshake timeout.
    Handshake,
    /// Inactivity timeout (detects missing keepalives).
    Inactivity,
    /// Orderly-close retransmission timeout.
    Shutdown,
    /// Sender retransmission timeout.
    ///
    /// The sender's own backstop for a loss that no NAK can name -- a lost
    /// *suffix* of a flight, which no later sequence number exposes. Armed when
    /// DATA is actually submitted, reset by cumulative ACK progress, and
    /// expired work is bounded to one probe; see [`crate::sender::SenderRto`].
    SenderRto,
}

impl TimerId {
    pub const COUNT: usize = 8;

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const ALL: [TimerId; 8] = [
        TimerId::Ack,
        TimerId::Nak,
        TimerId::Keepalive,
        TimerId::RetransmitContinue,
        TimerId::Handshake,
        TimerId::Inactivity,
        TimerId::Shutdown,
        TimerId::SenderRto,
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
/// Smallest flow/receive window the connection will run with. Requests below
/// this are clamped up during construction, so it is the effective floor a
/// deployment planner must model, not merely an internal guard.
pub const MIN_FLOW_WINDOW_PACKETS: u32 = 32;

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
pub const LIBSRT_COMPAT_PADDING_BYTES: usize = 4;
const LIBSRT_COMPAT_PADDING: [u8; LIBSRT_COMPAT_PADDING_BYTES] = [0; LIBSRT_COMPAT_PADDING_BYTES];

/// Keepalive timer interval (microseconds).
pub const KEEPALIVE_INTERVAL_MICROS: u64 = 1_000_000;
/// Periodic NAK timer interval (microseconds).
pub const PERIODIC_NAK_INTERVAL_MICROS: u64 = 20_000;

/// Retained packets one [`SrtConnection::process_retransmit`] visit will
/// encrypt and queue before yielding the remainder to a follow-up visit
/// (P01). Without this cap, a single NAK reporting a large loss range could
/// encrypt and queue the connection's entire retained send window
/// synchronously in one call. This crate cannot depend on srt-transport to
/// enforce it, but the value matches `OutputDrainBudget::default()`'s
/// packet cap there today, by convention rather than any shared type --
/// keep the two in sync by eye if either changes.
const MAX_RETRANSMITS_PER_VISIT: usize = 32;

/// Hard fail-closed limits for protocol outputs retained by the sans-I/O
/// core. The runtime normally drains these every pass; these limits protect
/// direct users that keep feeding packets or firing timers without polling
/// outputs.
pub const MAX_OUTPUT_QUEUE_ACTIONS: usize = 8_192;
pub const MAX_OUTPUT_QUEUE_BYTES: usize = 16 << 20;
const OUTPUT_QUEUE_OVERFLOW_REASON: &str = "protocol output queue limit exceeded";
/// Hard cap for lifecycle and application events retained by the sans-I/O
/// core. DATA events are already limited by the negotiated delivery window;
/// this extra headroom covers state/error notifications without allowing a
/// reconnecting caller that never polls events to grow memory forever.
pub const MAX_EVENT_QUEUE_ACTIONS: usize = MAX_FLOW_WINDOW as usize + 64;
const EVENT_QUEUE_OVERFLOW_REASON: &str = "protocol event queue limit exceeded";

/// Why a connection became disconnected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The peer sent an SRT SHUTDOWN packet.
    PeerShutdown,
    /// The peer stopped sending traffic for the inactivity interval.
    InactivityTimeout,
    /// A local graceful close exceeded its shutdown retry window.
    ShutdownTimeout,
    /// The peer sent traffic after a local close began.
    PeerActivityAfterShutdown,
    /// The bounded protocol output queue overflowed.
    OutputQueueOverflow,
    /// The bounded protocol event queue overflowed.
    EventQueueOverflow,
    /// A protocol error supplied by a lower layer.
    ProtocolError(String),
}

impl DisconnectReason {
    /// Convert a legacy diagnostic string into a typed reason.
    #[must_use]
    pub fn from_message(message: &str) -> Self {
        match message {
            "peer shutdown" => Self::PeerShutdown,
            "inactivity timeout" => Self::InactivityTimeout,
            "shutdown timeout" => Self::ShutdownTimeout,
            "peer activity after shutdown" => Self::PeerActivityAfterShutdown,
            OUTPUT_QUEUE_OVERFLOW_REASON => Self::OutputQueueOverflow,
            EVENT_QUEUE_OVERFLOW_REASON => Self::EventQueueOverflow,
            other => Self::ProtocolError(other.to_owned()),
        }
    }
}

impl From<String> for DisconnectReason {
    fn from(value: String) -> Self {
        Self::from_message(&value)
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::PeerShutdown => "peer shutdown",
            Self::InactivityTimeout => "inactivity timeout",
            Self::ShutdownTimeout => "shutdown timeout",
            Self::PeerActivityAfterShutdown => "peer activity after shutdown",
            Self::OutputQueueOverflow => OUTPUT_QUEUE_OVERFLOW_REASON,
            Self::EventQueueOverflow => EVENT_QUEUE_OVERFLOW_REASON,
            Self::ProtocolError(message) => message,
        };
        f.write_str(message)
    }
}

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
        /// F01: when the sender originally queued this message (the first
        /// fragment's, for a reassembled multi-packet message), converted
        /// into this connection's own local clock domain -- distinct from
        /// `timestamp` (the raw, still-wrapping wire value), from when it
        /// arrived, and from when TSBPD released it. Comparable directly
        /// against a `Timestamp` this same process reads via `now()`.
        source_time: Timestamp,
        /// Number of SRT DATA packets represented by this reassembled message.
        packet_count: u32,
    },
    /// State changed.
    StateChanged(ConnectionState),
    /// An error occurred.
    Error(String),
    /// Disconnected.
    Disconnected { reason: DisconnectReason },
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

/// Metadata for the next pending protocol output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMeta {
    /// The next output is a datagram requiring `wire_len` bytes of storage.
    ///
    /// `class` is what the datagram carries, so a transport can account for
    /// submission by category without parsing bytes it is not supposed to
    /// interpret.
    Datagram {
        wire_len: usize,
        class: DatagramClass,
    },
    /// The next output requests arming a timer.
    SetTimer { id: TimerId, duration_micros: u64 },
    /// The next output requests disarming a timer.
    ClearTimer { id: TimerId },
}

/// Result of materializing the next protocol output into caller-provided storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputInto {
    /// A datagram of `len` bytes was encoded into the buffer and consumed from the connection.
    Datagram {
        len: usize,
        class: DatagramClass,
        /// The source's declared due instant for this datagram in the
        /// microsecond domain of the `now` the application supplies (see
        /// `PendingData::source_due_micros`). `None` for retransmissions and
        /// control datagrams. A transport that hands the datagram to a TX lane
        /// later than this measures the whole deadline-to-wire path, including
        /// the source's own lateness -- see `FirstSubmitLateness` for how the
        /// boundary is defined and what it excludes.
        source_due_micros: Option<u64>,
    },
    /// A timer set action was consumed from the connection.
    SetTimer { id: TimerId, duration_micros: u64 },
    /// A timer clear action was consumed from the connection.
    ClearTimer { id: TimerId },
}

/// Internal queued output action.
#[derive(Debug, Clone, PartialEq, Eq)]
enum QueuedOutput {
    Datagram(PendingDatagram),
    SetTimer { id: TimerId, duration_micros: u64 },
    ClearTimer { id: TimerId },
}

/// Wire-byte cost of one queued output action, for the output queue's byte
/// budget. Timer actions cost nothing; only datagrams occupy the budget.
fn output_bytes(output: &QueuedOutput) -> usize {
    match output {
        QueuedOutput::Datagram(packet) => packet.wire_len(),
        QueuedOutput::SetTimer { .. } | QueuedOutput::ClearTimer { .. } => 0,
    }
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
    /// Stream ID (the identifier the Caller sends to the Listener, capped at
    /// 512 bytes at construction).
    pub stream_id: Option<String>,
    /// Congestion control mode name declared in the handshake extension
    /// (e.g. "live", "file"), capped at 512 bytes at construction. A real
    /// libsrt peer that declares a mode itself refuses to transmit if the
    /// other side declares nothing at all, assuming a live/file mismatch
    /// (confirmed by interop testing against `srt-file-transmit`, which logs
    /// "peer DID NOT DECLARE congctl" and disconnects without sending data).
    /// This crate's receive/delivery path does not itself branch on the mode
    /// -- this field only controls what gets declared and compared on the
    /// wire.
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
    /// Static repay enable. Canonical owner is
    /// `srt_transport::SessionConfig::set_pacing`; do not set directly.
    /// Repay at an instant requires `enabled && demand`: this flag alone
    /// never admits an extra packet, and demand alone cannot turn `Off` on.
    /// Default false preserves the idle-gap contract. Packed with the
    /// overhead byte above so the options footprint does not grow.
    pub pacing_repay: bool,
    /// above [`crate::handshake::MAX_FLOW_WINDOW`] are clamped during construction.
    pub flow_window_packets: u32,
    /// Local receive-buffer capacity, in packets. Values above
    /// [`crate::handshake::MAX_FLOW_WINDOW`] are clamped during construction.
    pub receive_buffer_packets: u32,
    /// Maximum number of delivered DATA events retained for the application.
    ///
    /// Delivered-but-unread packets consume receive-window capacity just like
    /// packets still held by the protocol receiver. This prevents an
    /// application that stops polling events from creating an unbounded queue.
    pub delivery_queue_packets: u32,
    /// Full ACK period in microseconds (Haivision `COMM_SYN` / RFC §3.2.4
    /// default 10 ms).
    ///
    /// Clamped to [`crate::receiver::MIN_ACK_INTERVAL_MICROS`]..=[`crate::receiver::MAX_ACK_INTERVAL_MICROS`]
    /// (10–40 ms) when the connection is constructed. Per-connection, not
    /// process-global. Values above 10 ms are **non-default /
    /// non-RFC-recommended** coalesce and do not retarget NAK/EXP.
    /// High-fan-in evidence target: [`crate::receiver::HIGH_FANIN_ACK_INTERVAL_MICROS`].
    pub ack_interval_micros: u64,
    /// Light ACK packet cadence (Haivision `SELF_CLOCK_INTERVAL` / RFC
    /// recommendation: 64).
    ///
    /// Clamped to [`crate::receiver::MIN_LIGHT_ACK_INTERVAL_PACKETS`]..=[`crate::receiver::MAX_LIGHT_ACK_INTERVAL_PACKETS`]
    /// (64–256) when the connection is constructed. Values above 64 are
    /// **non-default / non-RFC-recommended** coalesce. A receive window
    /// smaller than 64 packets does not Light-ACK; full ACK is the path.
    pub light_ack_interval_packets: u32,
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
            .field("ack_interval_micros", &self.ack_interval_micros)
            .field(
                "light_ack_interval_packets",
                &self.light_ack_interval_packets,
            )
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
            ack_interval_micros: crate::receiver::ACK_INTERVAL_MICROS,
            light_ack_interval_packets: crate::receiver::LIGHT_ACK_INTERVAL_PACKETS,
            pacing_repay: false,
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
    /// Boxed: only encrypted sessions pay the ~136B context (key schedules
    /// now live behind one more pointer inside). Plain sessions stay lean.
    crypto: Option<Box<CryptoContext>>,

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
    /// are state-machine bounded; DATA arrival rate is unbounded but retained
    /// events are capped by the configured delivery/receive windows.
    pending_data_events: u32,
    /// DATA packet positions retained by queued application events. This is
    /// distinct from the event count because one message can span many packets.
    pending_data_packets: u32,
    /// Output queue, bounded by [`MAX_OUTPUT_QUEUE_ACTIONS`] and
    /// [`MAX_OUTPUT_QUEUE_BYTES`]; overflow transitions the core to a
    /// fail-closed disconnected state.
    output_queue: VecDeque<QueuedOutput>,
    output_queue_bytes: usize,
    /// Number of items at the *front* of `output_queue` that were inserted as
    /// priority control actions (see [`Self::queue_priority_output`]), rather
    /// than appended in submission order. Items are only ever removed from the
    /// front, so this stays an accurate count of how many leading slots are
    /// priority actions without re-scanning the queue.
    output_queue_priority: usize,
    /// Outstanding delayed-materialization crypto reservations per key flag.
    /// Incremented when a DATA packet reserves a `TxCryptoStamp` at admission,
    /// decremented when the stamped datagram is materialized via
    /// `poll_output_into` or discarded by an output-queue overflow clear.
    /// Gates old-key decommission so a queued-but-unmaterialized datagram
    /// can never outlive its cipher schedule.
    pending_tx_even: u64,
    pending_tx_odd: u64,
    /// Whether the application has reopened a zero advertised receive
    /// window and the peer has not been told yet. Cleared when a Small/Full
    /// ACK actually carries the new window.
    receive_window_reopen_pending: bool,
    /// Whether the peer closed its send half and this connection is still
    /// delivering what it had already accepted. Terminal on drain.
    peer_shutdown_pending: bool,
    output_overflowed: bool,
    event_overflowed: bool,

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
    /// The peer's advertised SRT flow window (its receive capacity, in
    /// packets); zero means it advertised nothing usable.
    ///
    /// This is the peer's `SRT_FLOW_WINDOW`/flight-flag size from the
    /// handshake. libsrt starts its own send window from exactly this value
    /// (`m_iFlowWindowSize = m_ConnRes.m_iFlightFlagSize`), so the
    /// "negotiated" bound is the smaller of the two peers' declarations.
    peer_flow_window: u32,
    /// Peer bonding group metadata.
    peer_group_extension: Option<GroupExtensionData>,
    last_handshake_packet: Option<ControlPacket>,
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

const MAX_HANDSHAKE_OPTION_BYTES: usize = 512;

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() > max_bytes {
        value.truncate(value.floor_char_boundary(max_bytes));
    }
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
    if let Some(stream_id) = options.stream_id.as_mut() {
        truncate_utf8(stream_id, MAX_HANDSHAKE_OPTION_BYTES);
    }
    truncate_utf8(&mut options.congestion_control, MAX_HANDSHAKE_OPTION_BYTES);
    options.ack_interval_micros =
        crate::receiver::clamp_ack_interval_micros(options.ack_interval_micros);
    options.light_ack_interval_packets =
        crate::receiver::clamp_light_ack_interval_packets(options.light_ack_interval_packets);
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

    /// Release exactly one crypto reservation for `flag`. Releasing more than
    /// was reserved saturates at zero; the counter is a retirement gate, not
    /// an exact leak detector.
    fn release_tx_reservation(&mut self, flag: KeyFlag) {
        let counter = match flag {
            KeyFlag::Even => &mut self.pending_tx_even,
            KeyFlag::Odd => &mut self.pending_tx_odd,
        };
        *counter = counter.saturating_sub(1);
    }

    fn queue_output(&mut self, output: QueuedOutput) {
        if !self.reserve_output_slot(&output) {
            return;
        }
        let bytes = output_bytes(&output);
        self.output_queue_bytes = self.output_queue_bytes.saturating_add(bytes);
        self.output_queue.push_back(output);
    }

    /// Queue a timer set/clear action ahead of any pending datagrams.
    ///
    /// The sender's own retransmission timer (`TimerId::SenderRto`) is armed
    /// or reset from `note_data_submitted`/`on_sender_ack_progress`, which run
    /// *after* the DATA datagram that triggered them has already been queued.
    /// A plain FIFO append then leaves the timer action stuck behind whatever
    /// DATA the transport has not yet had TX capacity to drain -- so a timer
    /// store that is only fed by draining `poll_output_into` never sees the
    /// arm/rearm/clear at all while capacity is exhausted, and the timeout it
    /// exists to run never actually starts. Inserting the action immediately
    /// behind any already-queued priority actions (but ahead of every
    /// datagram) makes it visible to the caller as soon as the datagram that
    /// caused it is polled, regardless of how much output is still queued
    /// behind it.
    fn queue_priority_output(&mut self, output: QueuedOutput) {
        debug_assert!(
            matches!(
                output,
                QueuedOutput::SetTimer { .. } | QueuedOutput::ClearTimer { .. }
            ),
            "priority insertion is only for timer actions, never datagrams"
        );
        if !self.reserve_output_slot(&output) {
            return;
        }
        let bytes = output_bytes(&output);
        self.output_queue_bytes = self.output_queue_bytes.saturating_add(bytes);
        self.output_queue.insert(self.output_queue_priority, output);
        self.output_queue_priority += 1;
    }

    /// Shared overflow accounting for [`Self::queue_output`] and
    /// [`Self::queue_priority_output`]. Returns `false` if the output was
    /// dropped (already overflowed, or this action would overflow now).
    fn reserve_output_slot(&mut self, output: &QueuedOutput) -> bool {
        if self.output_overflowed || self.event_overflowed {
            return false;
        }
        let bytes = output_bytes(output);
        if self.output_queue.len() >= MAX_OUTPUT_QUEUE_ACTIONS
            || self.output_queue_bytes.saturating_add(bytes) > MAX_OUTPUT_QUEUE_BYTES
        {
            self.release_queued_tx_reservations();
            self.output_queue.clear();
            self.output_queue_bytes = 0;
            self.output_queue_priority = 0;
            self.output_overflowed = true;
            self.set_state(ConnectionState::Disconnected);
            self.queue_event(ConnectionEvent::Error(
                OUTPUT_QUEUE_OVERFLOW_REASON.to_string(),
            ));
            self.queue_event(ConnectionEvent::Disconnected {
                reason: DisconnectReason::OutputQueueOverflow,
            });
            return false;
        }
        if let QueuedOutput::Datagram(PendingDatagram::Data(data)) = output
            && let Some(stamp) = data.crypto
        {
            let counter = match stamp.key_flag {
                KeyFlag::Even => &mut self.pending_tx_even,
                KeyFlag::Odd => &mut self.pending_tx_odd,
            };
            *counter = counter.saturating_add(1);
        }
        true
    }

    /// Pop the front of the output queue, keeping the priority-slot count
    /// consistent with what actually remains at the front.
    fn pop_output_front(&mut self) -> Option<QueuedOutput> {
        let popped = self.output_queue.pop_front();
        if popped.is_some() && self.output_queue_priority > 0 {
            self.output_queue_priority -= 1;
        }
        popped
    }

    /// Discard queued DATA output for any sequence this sender no longer
    /// considers live (tombstoned by TLPKTDROP, or already retired by the
    /// cumulative ACK) before it can reach the transport.
    ///
    /// A DATA datagram can sit in `output_queue` behind blocked TX capacity
    /// for an arbitrary time after `SenderBuffer` accepted it -- pacing,
    /// congestion, or simply a caller that has not drained output recently.
    /// If TLPKTDROP tombstones that sequence (or an ACK retires it) while
    /// the datagram is still queued, letting it materialize anyway would
    /// emit media the sender has already told the peer is gone (via
    /// DROPREQ) or has already accounted for as delivered -- and for a
    /// queued *retransmission* specifically, would let a redundant
    /// transmission out after the position it named stopped being
    /// outstanding. Called right after the two events that can invalidate
    /// an already-queued sequence (`SenderBuffer::drop_expired` and
    /// `SenderBuffer::handle_ack`), so `peek_output`/`poll_output_into`
    /// never have to reconsider what is already at the front of the queue.
    fn purge_stale_queued_data(&mut self) {
        let Some(sender) = self.sender.as_ref() else {
            return;
        };
        if self.output_queue.is_empty() {
            return;
        }
        let mut stale_indices: Vec<usize> = Vec::new();
        for (index, output) in self.output_queue.iter().enumerate() {
            if let QueuedOutput::Datagram(PendingDatagram::Data(data)) = output
                && !sender.is_live(data.header.sequence_number)
            {
                stale_indices.push(index);
            }
        }
        for &index in stale_indices.iter().rev() {
            let Some(QueuedOutput::Datagram(pkt)) = self.output_queue.remove(index) else {
                continue;
            };
            self.output_queue_bytes = self.output_queue_bytes.saturating_sub(pkt.wire_len());
            if let PendingDatagram::Data(data) = &pkt
                && let Some(stamp) = data.crypto
            {
                self.release_tx_reservation(stamp.key_flag);
            }
            if index < self.output_queue_priority {
                self.output_queue_priority -= 1;
            }
        }
    }

    fn release_queued_tx_reservations(&mut self) {
        let (mut even, mut odd) = (0u64, 0u64);
        for output in &self.output_queue {
            if let QueuedOutput::Datagram(PendingDatagram::Data(data)) = output
                && let Some(stamp) = data.crypto
            {
                match stamp.key_flag {
                    KeyFlag::Even => even = even.saturating_add(1),
                    KeyFlag::Odd => odd = odd.saturating_add(1),
                }
            }
        }
        self.pending_tx_even = self.pending_tx_even.saturating_sub(even);
        self.pending_tx_odd = self.pending_tx_odd.saturating_sub(odd);
    }

    fn queue_control_packet(&mut self, pkt: ControlPacket, now: Timestamp) {
        self.last_send_time = Some(now);
        self.queue_output(QueuedOutput::Datagram(PendingDatagram::Control(pkt)));
    }

    fn queue_handshake_control_packet(&mut self, pkt: ControlPacket, now: Timestamp) {
        self.last_send_time = Some(now);
        self.last_handshake_packet = Some(pkt.clone());
        self.queue_output(QueuedOutput::Datagram(PendingDatagram::Control(pkt)));
    }

    fn retransmit_handshake(&mut self) {
        if let Some(packet) = self.last_handshake_packet.as_ref() {
            self.queue_output(QueuedOutput::Datagram(PendingDatagram::Control(
                packet.clone(),
            )));
        }
    }

    /// Queue a packet's first transmission.
    ///
    /// The crypto reservation is taken here and recorded on the retained
    /// packet, because a retransmission must reproduce this packet's
    /// protected bytes: same key generation, same sequence-derived counter,
    /// therefore the same ciphertext and tag. This is the reference
    /// behaviour (libsrt stores the first transmission's key-flag bits with
    /// the send-buffer block and re-reads the already-encrypted payload;
    /// Robotweax keeps the protected packet selected on first send), and it
    /// is also what stops a retransmission from consuming a second
    /// first-transmission counter value.
    fn queue_first_transmission(
        &mut self,
        header: DataHeader,
        payload: Bytes,
        source_due_micros: Option<u64>,
        now: Timestamp,
    ) -> Result<(), Error> {
        let crypto = if let Some(ref mut c) = self.crypto {
            Some(c.reserve_tx_stamp()?)
        } else {
            None
        };
        if let Some(ref mut sender) = self.sender {
            sender.note_data_stamp(header.sequence_number, crypto);
        }
        self.enqueue_data_datagram(header, payload, crypto, source_due_micros, now)
    }

    /// Queue a retransmission of an already-transmitted packet.
    ///
    /// The stamp is the one retained from the first transmission, so the
    /// retransmission re-encrypts nothing new: `encrypt_with_stamp`/
    /// `encrypt_gcm_with_stamp` reproduce the original bytes without
    /// advancing the logical TX counter.
    fn queue_retransmission(
        &mut self,
        header: DataHeader,
        payload: Bytes,
        now: Timestamp,
    ) -> Result<(), Error> {
        let crypto = self
            .sender
            .as_ref()
            .and_then(|sender| sender.data_stamp(header.sequence_number));
        if self.crypto.is_some() && crypto.is_none() {
            // Retention and the stamp are recorded together, so this cannot
            // happen; a retransmission without one would go out in the clear
            // on an encrypted connection, which is worse than losing it.
            return Err(Error::invalid_state(
                "retransmission has no retained crypto stamp",
            ));
        }
        // A retransmission has no source deadline: it is due the moment the
        // sender learns it is needed.
        self.enqueue_data_datagram(header, payload, crypto, None, now)
    }

    fn enqueue_data_datagram(
        &mut self,
        header: DataHeader,
        payload: Bytes,
        crypto: Option<crate::crypto_impl::TxCryptoStamp>,
        source_due_micros: Option<u64>,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.last_send_time = Some(now);
        self.queue_output(QueuedOutput::Datagram(PendingDatagram::Data(
            PendingData::new(header, payload, crypto, source_due_micros),
        )));
        // Reservation accounting is owned by `queue_output` so a rejected
        // (overflowed) queue cannot leak a reservation for a packet that was
        // never actually queued.
        Ok(())
    }

    fn check_output_queue(&self) -> Result<(), Error> {
        if self.output_overflowed {
            Err(Error::invalid_state(OUTPUT_QUEUE_OVERFLOW_REASON))
        } else if self.event_overflowed {
            Err(Error::invalid_state(EVENT_QUEUE_OVERFLOW_REASON))
        } else {
            Ok(())
        }
    }

    fn queue_event(&mut self, event: ConnectionEvent) {
        if self.event_overflowed {
            return;
        }
        if self.event_queue.len() < MAX_EVENT_QUEUE_ACTIONS {
            self.event_queue.push_back(event);
            return;
        }

        // Discarding unread DATA events must also release their receive-window
        // reservations; otherwise a terminal connection would retain a fake
        // application backlog until drop. The queue is cleared before the
        // terminal diagnostics are installed, so this path remains bounded.
        let mut dropped_packets = 0u32;
        let mut dropped_events = 0u32;
        while let Some(queued) = self.event_queue.pop_front() {
            if let ConnectionEvent::DataReceived { packet_count, .. } = queued {
                dropped_events = dropped_events.saturating_add(1);
                dropped_packets = dropped_packets.saturating_add(packet_count);
            }
        }
        self.pending_data_events = self.pending_data_events.saturating_sub(dropped_events);
        self.pending_data_packets = self.pending_data_packets.saturating_sub(dropped_packets);
        self.sync_application_backlog();
        self.event_overflowed = true;
        self.state = ConnectionState::Disconnected;
        self.event_queue.push_back(ConnectionEvent::Error(
            EVENT_QUEUE_OVERFLOW_REASON.to_string(),
        ));
        self.event_queue.push_back(ConnectionEvent::Disconnected {
            reason: DisconnectReason::EventQueueOverflow,
        });
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
        self.queue_output(QueuedOutput::ClearTimer {
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
            output_queue_bytes: 0,
            output_queue_priority: 0,
            pending_tx_even: 0,
            pending_tx_odd: 0,
            receive_window_reopen_pending: false,
            peer_shutdown_pending: false,
            output_overflowed: false,
            event_overflowed: false,
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
            peer_flow_window: 0,
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
            output_queue_bytes: 0,
            output_queue_priority: 0,
            pending_tx_even: 0,
            pending_tx_odd: 0,
            receive_window_reopen_pending: false,
            peer_shutdown_pending: false,
            output_overflowed: false,
            event_overflowed: false,
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
            peer_flow_window: 0,
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
        self.check_output_queue()?;
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

        self.check_output_queue()
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
        self.queue_handshake_control_packet(packet, now);
        self.terminate_handshake();
        self.check_output_queue()
    }

    /// The handshake-negotiated static flow window: this sender's own
    /// configured window capped by the peer's advertised receive capacity.
    ///
    /// The two are separate quantities on purpose (libsrt keeps them apart
    /// the same way): our own value bounds the memory and retransmit span we
    /// commit to, and the peer's value bounds what the peer can actually
    /// accept before its receive buffer fills.
    fn negotiated_flow_window(&self) -> u32 {
        if self.peer_flow_window >= 2 {
            self.options.flow_window_packets.min(self.peer_flow_window)
        } else {
            self.options.flow_window_packets
        }
    }

    /// Record the peer's advertised SRT flow window.
    ///
    /// Values below two are not a usable window (libsrt validates the same
    /// range and Robotweax rejects them), so they are treated as "not
    /// advertised" rather than throttling this sender to a single packet in
    /// flight.
    fn note_peer_flow_window(&mut self, advertised: u32) {
        if advertised >= 2 {
            self.peer_flow_window = advertised;
        }
    }

    /// Initialize the send/receive buffers. Demand starts false: static
    /// `pacing_repay` only enables repay, the app must still signal waiting
    /// data via `set_pacing_demand`.
    fn init_buffers(&mut self, now: Timestamp, peer_initial_seq: u32, tsbpd_time_base: u64) {
        let negotiated_window = self.negotiated_flow_window();
        let mut sender = SenderBuffer::new(
            self.initial_seq,
            negotiated_window,
            self.options.tsbpd_delay,
        );
        if let Some(max_bw) = self.options.max_bandwidth_bytes_per_sec {
            sender.set_max_bandwidth(max_bw);
        } else if let Some(input_bw) = self.options.input_bandwidth_bytes_per_sec {
            sender.set_input_bandwidth(input_bw, self.options.overhead_bandwidth_percent);
        }
        sender.set_repay_pacing_debt(false);
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
        receiver.set_ack_coalesce(
            self.options.ack_interval_micros,
            self.options.light_ack_interval_packets,
        );
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
        self.check_output_queue()?;
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

        // The inactivity timer is armed once at connect and rearms itself on
        // fire — no per-packet SetTimer output.
        let result = match packet {
            SrtPacket::Data(data_pkt) => {
                tracing::debug!("received DATA packet, seq={}", data_pkt.sequence_number);
                self.handle_data_packet(data_pkt, now)
            }
            SrtPacket::Control(ctrl_pkt) => self.handle_control_packet(ctrl_pkt, now),
        };
        result?;

        // Only an accepted protocol transition proves peer activity. Generic
        // framing plus a matching destination socket id is not enough: a
        // datagram that decodes but fails its own semantic or authentication
        // validation (a truncated ACK, an unknown ACKACK, an undecryptable
        // DATA body, a malformed key-management command) is rejected above
        // and must not keep an otherwise silent peer alive. Robotweax 0.2.2
        // hardens the same invariant and libsrt's own control parsers reject
        // before touching connection state.
        if self.state == ConnectionState::Connected {
            self.last_recv_time = Some(now);
        }
        self.check_output_queue()
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
    ///
    /// Bounded to `MAX_RETRANSMITS_PER_VISIT` per call (P01): a NAK
    /// reporting a large loss range, or a visit catching up after one,
    /// used to encrypt and queue the connection's entire retained send
    /// window synchronously in a single call. `pop_retransmit` only
    /// removes a sequence from the loss list once it actually returns it,
    /// so stopping early here leaves the remainder exactly where it was --
    /// membership and FIFO ordering are untouched, and a follow-up visit
    /// picks up right where this one left off.
    pub fn process_retransmit(&mut self, now: Timestamp) {
        let dest_socket_id = self.peer_socket_id;
        // This function only *drains* what is already queued: whatever put a
        // sequence in the loss list (a NAK, or the sender timeout's tail probe
        // in `handle_sender_rto_timeout`) decided that. Deciding here would give
        // the sender two independent notions of loss and no timer that can
        // reach either of them.
        // `pop_retransmit` already retires each sequence from the loss list
        // (S02: it does not go back in on an encrypt failure here). Losing
        // that failure silently would make this the one place an ongoing
        // key-schedule problem is indistinguishable from ordinary network
        // loss -- log it so it is observable, without inventing a new
        // retry/requeue policy (that is P01's bounded retransmission work,
        // not this card's). A broken schedule can affect the whole queued
        // loss list in one call, so summarize once per drain (first
        // sequence + count) instead of once per record.
        let mut dropped = 0u32;
        let mut first_dropped_seq = None;
        for _ in 0..MAX_RETRANSMITS_PER_VISIT {
            let Some((header, payload)) = self
                .sender
                .as_mut()
                .and_then(|s| s.pop_retransmit(dest_socket_id))
            else {
                break;
            };
            let seq = header.sequence_number;
            // A retransmission has no source deadline: it is due the moment the
            // sender learns it is needed, so it contributes no lateness sample.
            match self.queue_retransmission(header, payload, now) {
                Ok(()) => {}
                Err(_) => {
                    dropped += 1;
                    first_dropped_seq.get_or_insert(seq);
                }
            }
        }
        if dropped > 0 {
            tracing::error!(
                dropped,
                first_seq = first_dropped_seq,
                "retransmit(s) dropped: packet could not be re-encrypted"
            );
        }
        // P01: this continuation timer is armed here and nowhere else (unlike
        // Ack/Keepalive/Nak, which self-rearm in their own handle_*_timer), so
        // it is this visit's job to schedule the next one when the cap above
        // left work behind. A conforming peer's periodic NAK will usually
        // re-report deferred sequences on its own (`ReceiverBuffer` re-emits
        // its whole loss list every periodic-NAK interval), but this must not
        // *depend* on that -- so the follow-up is armed at `duration_micros: 0`
        // (due immediately, not after a fixed delay): any nonzero fixed
        // interval turns the per-visit cap into a hard aggregate
        // retransmit-rate ceiling (packets-per-visit / interval), an unrelated
        // policy this card has no documented rate to justify. A zero-delay
        // rearm only bounds *work per call*, which is this card's actual
        // charter, and lets the transport's own poll cadence decide how fast
        // the remainder actually goes out.
        //
        // Loss detection is a different mechanism entirely and lives on
        // `TimerId::SenderRto`; this one only continues work already queued.
        if self.has_retransmit() {
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::RetransmitContinue,
                duration_micros: 0,
            });
        }
    }

    /// Handle an expiry of the sender's retransmission timeout.
    ///
    /// local patch (crates/srt-protocol/VENDOR.md, not upstream-tracked): the
    /// sender's own loss timeout; see [`crate::sender::SenderRto`] and
    /// `docs/differential-audit-robotweax.md`.
    ///
    /// This is the sender's own recovery path for a loss the peer cannot name
    /// (a missing suffix of a flight exposes no later sequence number, so no
    /// NAK is ever generated for it). Work here is deliberately bounded to a
    /// single probe: replaying the unacknowledged flight on every expiry turns
    /// an outage into a retransmission storm, and there would be nothing left
    /// for the peer's own selective recovery to add.
    fn handle_sender_rto_timeout(&mut self, now: Timestamp) {
        let Some((outstanding, probe_queued)) = self.sender.as_mut().map(|sender| {
            if !sender.has_outstanding_submitted_data() {
                // Everything actually submitted has been acknowledged (or
                // locally dropped): there is no flight left to time.
                sender.rto_stop();
                (false, false)
            } else {
                // With selective recovery already pending, a blind probe would
                // only widen an in-progress repair. `rto_probe_pending()` is
                // the other half: a probe this timer already queued may still
                // be sitting un-submitted behind blocked TX capacity, and
                // `has_retransmit()` alone cannot tell that apart from
                // "already on the wire" -- it clears the moment the probe is
                // dequeued into connection output, not when it actually
                // leaves the protocol. Queuing another blind probe while the
                // first is still pending would let them accumulate
                // unboundedly during prolonged TX starvation instead of
                // staying bounded at exactly one.
                let queued = if sender.has_retransmit() || sender.rto_probe_pending().is_some() {
                    None
                } else {
                    sender.queue_retransmission_of_newest_submitted()
                };
                if let Some(sequence) = queued {
                    sender.rto_set_probe_pending(sequence);
                }
                (true, queued.is_some())
            }
        }) else {
            return;
        };

        if !outstanding {
            self.queue_priority_output(QueuedOutput::ClearTimer {
                id: TimerId::SenderRto,
            });
            return;
        }

        if probe_queued {
            // Emitted through the bounded per-visit path, exactly like a
            // NAK-driven retransmission, so the probe cannot bypass the cap.
            self.process_retransmit(now);
        }

        if let Some(timeout) = self.sender.as_mut().map(|sender| sender.rto_expire()) {
            self.queue_priority_output(QueuedOutput::SetTimer {
                id: TimerId::SenderRto,
                duration_micros: timeout,
            });
        }
    }

    /// Cumulative ACK progress: restart the sender's retransmission timeout.
    ///
    /// Progress -- not ACK receipt -- is the reset condition. A peer that keeps
    /// acknowledging without advancing `ack_seq` (which a receiver does while
    /// its own window is stalled) must not be able to keep the timeout from ever
    /// firing: that would starve precisely the tail recovery the timeout exists
    /// for. Reporting new RTT/window feedback is likewise not progress.
    fn on_sender_ack_progress(&mut self) {
        let Some(flight_remains) = self
            .sender
            .as_mut()
            .map(|sender| sender.has_outstanding_submitted_data())
        else {
            return;
        };

        if flight_remains {
            if let Some(timeout) = self.sender.as_mut().map(|sender| sender.rto_start()) {
                self.queue_priority_output(QueuedOutput::SetTimer {
                    id: TimerId::SenderRto,
                    duration_micros: timeout,
                });
            }
        } else {
            if let Some(sender) = self.sender.as_mut() {
                sender.rto_stop();
            }
            self.queue_priority_output(QueuedOutput::ClearTimer {
                id: TimerId::SenderRto,
            });
        }
    }

    /// Record that a DATA datagram left the protocol for the transport.
    ///
    /// `poll_output_into` is the boundary that means this: the caller has
    /// already reserved final transport storage (`DatagramSink::acquire`), so a
    /// materialized datagram is no longer droppable by the sender. It is the
    /// only place the protocol learns that a packet was really transmitted, and
    /// therefore the only place that may arm the sender timeout.
    ///
    /// The pending blind probe crossing this same boundary reprograms the epoch
    /// from here: the timeout is time elapsed after DATA was *sent*, and a probe
    /// that sat behind blocked TX capacity until shortly before its deadline
    /// would otherwise fire microseconds after going out and allow a second
    /// blind probe with nothing behind it. The backoff count is preserved --
    /// only cumulative ACK progress may reset that.
    fn note_data_submitted(&mut self, sequence: u32) {
        let Some(arm) = self
            .sender
            .as_mut()
            .map(|sender| sender.note_data_submitted(sequence))
        else {
            return;
        };
        let timeout = match arm {
            RtoArm::Nothing => return,
            RtoArm::Start => self.sender.as_mut().map(|sender| sender.rto_start()),
            RtoArm::Rearm => self.sender.as_mut().map(|sender| sender.rto_rearm()),
        };
        if let Some(timeout) = timeout {
            self.queue_priority_output(QueuedOutput::SetTimer {
                id: TimerId::SenderRto,
                duration_micros: timeout,
            });
        }
    }

    /// Process a timer event.
    pub fn handle_timer(&mut self, timer_id: TimerId, now: Timestamp) -> Result<(), Error> {
        match timer_id {
            TimerId::Handshake => self.handle_handshake_timer(now),
            TimerId::Keepalive => self.handle_keepalive_timer(now),
            TimerId::Ack => self.handle_ack_timer(now),
            TimerId::Nak => self.handle_nak_timer(now),
            TimerId::RetransmitContinue => {
                if self.state == ConnectionState::Connected {
                    self.process_retransmit(now);
                }
            }
            TimerId::SenderRto => {
                if self.state == ConnectionState::Connected {
                    self.handle_sender_rto_timeout(now);
                }
            }
            TimerId::Inactivity => self.handle_inactivity_timer(now),
            TimerId::Shutdown => self.handle_shutdown_timer(now),
        }
        self.check_output_queue()
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
                .is_none_or(|last_send| now.saturating_sub(last_send) >= KEEPALIVE_INTERVAL_MICROS)
            {
                self.send_keepalive(now);
            }
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::Keepalive,
                duration_micros: KEEPALIVE_INTERVAL_MICROS,
            });
        }
    }

    /// Service everything due at `now` on the receive side: locally expire
    /// positions TLPKTDROP has moved past (which also retires them from the
    /// sender's retained span), give up an assembling message that can
    /// never complete because its start fell behind that frontier, and
    /// deliver any TSBPD-ready DATA.
    ///
    /// Both the periodic ACK tick and the inactivity timer's peer-shutdown
    /// drain need exactly this before either one is allowed to decide
    /// whether anything is still outstanding: an inactivity tick that only
    /// inspected deadlines without first pulling ready data into delivery
    /// would see a message's deadline as "already due" and force-close
    /// instead of actually delivering it, purely because it happened to run
    /// before the next ACK tick.
    fn service_receive_deadlines(&mut self, now: Timestamp) {
        if self.tlpktdrop_enabled()
            && let Some(receiver) = self.receiver.as_mut()
        {
            for seq in receiver.drop_too_late(now) {
                if let Some(sender) = self.sender.as_mut() {
                    sender.discard_acked(seq);
                }
            }
        }
        if self.tlpktdrop_enabled()
            && let Some(receiver) = self.receiver.as_ref()
        {
            // TLPKTDROP moves the receive frontier past positions that can
            // never arrive, so a message whose first fragment is now behind
            // that frontier can never be completed either: retire it instead
            // of holding the connection open on it.
            let expected = receiver.expected_sequence();
            self.assembler.discard_before(expected);
        }
        self.enqueue_ready_data(now);
    }

    fn handle_ack_timer(&mut self, now: Timestamp) {
        if self.state != ConnectionState::Connected {
            return;
        }
        self.service_receive_deadlines(now);
        // A pending peer close advances on delivery: the tick is what makes
        // TSBPD deadlines pass.
        self.finish_peer_shutdown_if_drained();
        let emit_ack = self.receive_window_reopen_pending
            || self
                .receiver
                .as_ref()
                .is_none_or(|receiver| receiver.should_emit_timer_ack(now));
        if emit_ack {
            self.send_ack(now);
        }

        if self.tlpktdrop_enabled()
            && let Some(sender) = self.sender.as_mut()
        {
            let dropped_messages = sender.drop_expired(now);
            for msg in &dropped_messages {
                self.send_drop_req(msg.message_number, msg.first_seq, msg.last_seq, now);
            }
            if !dropped_messages.is_empty() {
                // A tombstoned sequence's queued DATA (if any) must never
                // reach the transport, and if TLPKTDROP just gave up the
                // whole flight, the RTO timer has nothing left to time.
                self.purge_stale_queued_data();
                if self
                    .sender
                    .as_ref()
                    .is_some_and(|sender| !sender.has_outstanding_submitted_data())
                {
                    if let Some(sender) = self.sender.as_mut() {
                        sender.rto_stop();
                    }
                    self.queue_priority_output(QueuedOutput::ClearTimer {
                        id: TimerId::SenderRto,
                    });
                }
            }
        }

        self.queue_output(QueuedOutput::SetTimer {
            id: TimerId::Ack,
            duration_micros: self.ack_timer_tick_micros(),
        });
    }

    fn handle_nak_timer(&mut self, now: Timestamp) {
        if self.state == ConnectionState::Connected && self.periodic_nak_enabled() {
            self.send_periodic_nak(now);
            let interval = self
                .receiver
                .as_ref()
                .map(|r| r.nak_interval())
                .unwrap_or(PERIODIC_NAK_INTERVAL_MICROS);
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::Nak,
                duration_micros: interval,
            });
        }
    }

    /// Handle the inactivity deadline.
    ///
    /// Also the bound on a peer-initiated close that has not drained: the peer
    /// is gone, so a buffered tail that still has not become deliverable by
    /// then (an incomplete message, say) is given up rather than keeping the
    /// connection open forever. The terminal reason is still the peer's close.
    fn handle_inactivity_timer(&mut self, now: Timestamp) {
        if self.state != ConnectionState::Connected {
            return;
        }
        let elapsed = self.last_recv_time.map_or(INACTIVITY_TIMEOUT_MICROS, |t| {
            now.as_micros().saturating_sub(t.as_micros())
        });
        if elapsed < INACTIVITY_TIMEOUT_MICROS {
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::Inactivity,
                duration_micros: INACTIVITY_TIMEOUT_MICROS - elapsed,
            });
            return;
        }
        if !self.peer_shutdown_pending {
            self.queue_event(ConnectionEvent::Disconnected {
                reason: DisconnectReason::InactivityTimeout,
            });
            self.set_state(ConnectionState::Disconnected);
            return;
        }
        // Service everything actually due at `now` before deciding anything:
        // a message's TSBPD deadline landing exactly at this inactivity
        // tick must be delivered, not treated as "still pending" only
        // because the periodic ACK tick has not run yet. Without this, two
        // retained messages (say, deadlines 8s and 12s) can be truncated
        // purely by dispatch order -- if this timer is serviced before the
        // ACK timer at exactly the 8s mark, `earliest_pending_deadline`
        // would equal `now` and neither message would ever be delivered.
        self.service_receive_deadlines(now);
        self.finish_peer_shutdown_if_drained();
        if !self.peer_shutdown_pending {
            return;
        }
        // Data was just delivered into the application's event queue above
        // but not yet polled: that is progress, not a stalled drain, and
        // must not be preempted by a terminal event. The periodic ACK tick
        // (already running independently, far more frequently than this
        // timer) keeps re-checking `finish_peer_shutdown_if_drained` as the
        // application polls it down, so no explicit rearm is needed here.
        if self.pending_data_events != 0 {
            return;
        }
        // A configured TSBPD delay can exceed the fixed inactivity timeout:
        // data this receiver still holds may legitimately be waiting for its
        // own future playout deadline, which is not the same thing as a
        // drain that has stalled. Defer to that deadline instead of
        // truncating it -- once it passes, this timer fires again and either
        // the data has been delivered (drained) or TLPKTDROP has retired it.
        // A deadline that is not still in the future here belongs to a
        // packet TLPKTDROP failed to retire because a gap upstream of it
        // blocks delivery -- an impossible incomplete tail, not a legitimate
        // wait -- so the ordinary bounded close below still applies to it.
        if let Some(deadline) = self
            .receiver
            .as_ref()
            .and_then(ReceiverBuffer::earliest_pending_deadline)
            && now < deadline
        {
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::Inactivity,
                duration_micros: deadline.as_micros().saturating_sub(now.as_micros()).max(1),
            });
            return;
        }
        self.finish_local_close(DisconnectReason::PeerShutdown);
    }

    fn handle_shutdown_timer(&mut self, now: Timestamp) {
        if self.state == ConnectionState::Closing {
            if self
                .shutdown_started_at
                .is_some_and(|started| now.saturating_sub(started) >= SHUTDOWN_TIMEOUT_MICROS)
            {
                self.finish_local_close(DisconnectReason::ShutdownTimeout);
            } else {
                self.send_shutdown(now);
                self.queue_output(QueuedOutput::SetTimer {
                    id: TimerId::Shutdown,
                    duration_micros: SHUTDOWN_RETRY_INTERVAL_MICROS,
                });
            }
        }
    }

    /// Send data.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<(), Error> {
        self.validate_send_request(payload.len(), None)?;
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
        self.validate_send_request(payload.len(), Some(sequence_number))?;
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
        self.check_can_encrypt()?;
        let timestamp = self.relative_timestamp(now);
        let peer_socket_id = self.peer_socket_id;
        let max_payload_size = self.effective_max_payload_size();

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

        // One admission instant, so one source due instant: every fragment of
        // this message carries the same source deadline.
        let source_due = Some(now.as_micros());
        for (header, payload) in packets {
            self.queue_first_transmission(header, payload, source_due, now)?;
        }

        if let Some(ref mut sender) = self.sender {
            sender.record_send_time(now);
        }

        self.check_km_refresh(now);
        self.check_output_queue()
    }

    fn send_internal(
        &mut self,
        payload: Vec<u8>,
        sequence_number: Option<u32>,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.validate_send_request(payload.len(), sequence_number)?;

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

            // The source's own declared deadline for this payload, carried to
            // the submission boundary so a transport can measure how late the
            // payload reached the wire relative to the media schedule.
            self.queue_first_transmission(header, payload, Some(now.as_micros()), now)?;
            if let Some(ref mut sender) = self.sender {
                sender.record_send_time(now);
            }
        }

        self.check_km_refresh(now);

        self.check_output_queue()
    }

    fn validate_send_request(
        &self,
        payload_len: usize,
        sequence_number: Option<u32>,
    ) -> Result<(), Error> {
        if self.state != ConnectionState::Connected {
            return Err(Error::invalid_state("not connected"));
        }
        if !self.can_send() {
            return Err(Error::invalid_state("send buffer full"));
        }
        self.check_explicit_sequence(sequence_number)?;
        self.check_can_encrypt()?;
        if payload_len > self.effective_max_payload_size() {
            return Err(Error::invalid_state(
                "payload exceeds the maximum single-packet size; use send_message to fragment it",
            ));
        }
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

        self.check_explicit_sequence(sequence_number)?;
        self.check_can_encrypt()?;
        if payload.len() > self.effective_max_payload_size() {
            return Err(Error::invalid_state(
                "payload exceeds the maximum single-packet size; use send_message to fragment it",
            ));
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

        // `can_send()` and the explicit sequence were both just checked
        // against the same sender this call holds `&mut` over, so the
        // buffer's own internal guard (which would otherwise return `None`
        // here) cannot have changed underneath us: `None` is unreachable.
        // Never let it read as a silent, unaccounted success (I1/I2).
        let Some((header, payload)) = packet else {
            debug_assert!(
                false,
                "push_shared rejected a send after can_send/sequence were already validated"
            );
            return Err(Error::invalid_state(
                "internal invariant violated: push_shared rejected an already-validated send",
            ));
        };
        self.queue_first_transmission(header, payload, Some(now.as_micros()), now)?;
        if let Some(ref mut sender) = self.sender {
            sender.record_send_time(now);
        }

        self.check_km_refresh(now);
        self.check_output_queue()
    }

    /// Reject a caller-supplied explicit send sequence before it reaches the
    /// sender buffer. The buffer's own check further down would otherwise
    /// silently return `None` for a mismatch, which a caller must never be
    /// able to read as successful admission (I1).
    fn check_explicit_sequence(&self, sequence_number: Option<u32>) -> Result<(), Error> {
        if let Some(sequence_number) = sequence_number
            && self.next_sequence_number() != Some(sequence_number)
        {
            return Err(Error::invalid_state("sequence number is out of order"));
        }
        Ok(())
    }

    /// Reject a send before it reaches the sender buffer if encryption
    /// under the current key would fail (S02: the buffer already commits
    /// the packet -- sequence advance, retained payload, retransmit
    /// eligibility -- before `encrypt_to_wire` runs; a mid-rotation key
    /// gap must not become an accepted-then-silently-failed send that a
    /// plain `Err` return can't distinguish from an outright rejection).
    fn check_can_encrypt(&self) -> Result<(), Error> {
        if self
            .crypto
            .as_ref()
            .is_some_and(|crypto| !crypto.can_encrypt_current_key())
        {
            return Err(Error::invalid_state(
                "encryption key schedule not ready for current key",
            ));
        }
        Ok(())
    }

    /// Largest single DATA packet's application payload this connection can
    /// put on the wire without exceeding its configured datagram budget
    /// (`max_payload_size`, SRT header already excluded), accounting for
    /// the current cipher's AEAD tag (GCM appends `GCM_TAG_LEN`; CTR and no
    /// encryption add nothing -- control packets are never encrypted, so
    /// this must not shrink `max_control_info_size`'s budget, which stays
    /// on the raw `max_payload_size`). `send_message` fragments at this
    /// boundary; `send`/`send_owned`/`send_shared` (and their
    /// explicit-sequence variants) reject a payload that exceeds it outright
    /// rather than silently emitting an oversized packet (P03).
    pub fn effective_max_payload_size(&self) -> usize {
        let tag_overhead = match self.crypto.as_deref() {
            Some(crypto) if crypto.cipher_mode() == CipherMode::Gcm => GCM_TAG_LEN,
            _ => 0,
        };
        self.max_payload_size.saturating_sub(tag_overhead)
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

    /// Tell the pacer whether unsent application data is waiting.
    ///
    /// Gated by static `pacing_repay`: `Off` stays off even when waiting.
    /// When true, late service repays missed periods so a loop-while-eligible
    /// caller can emit more than one packet at the same `now`. When false, the
    /// idle-gap contract is restored (exactly one immediate packet).
    pub fn set_pacing_demand(&mut self, waiting: bool) {
        let enabled = self.options.pacing_repay;
        if let Some(sender) = self.sender.as_mut() {
            sender.set_repay_pacing_debt(enabled && waiting);
        }
    }

    /// Discard leftover send-time debt because the application queue is empty.
    /// Matches libsrt clearing `m_tsNextSendTime` when `packUniqueData` finds
    /// nothing to send.
    pub fn discard_idle_pacing_debt(&mut self, now: Timestamp) {
        if let Some(sender) = self.sender.as_mut() {
            sender.discard_idle_pacing_debt(now);
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
        // The application draining the last queued payload can be the event
        // that completes a pending peer close.
        self.finish_peer_shutdown_if_drained();
        Some(event)
    }

    pub(crate) fn release_data_reservation(&mut self, packet_count: u32) {
        debug_assert!(packet_count <= self.pending_data_packets);
        self.pending_data_packets = self.pending_data_packets.saturating_sub(packet_count);
        self.sync_application_backlog();
        self.note_receive_window_reopened();
    }

    /// Schedule an immediate Full ACK when application delivery reopens a
    /// receive window this connection had advertised as zero.
    ///
    /// Without this, the peer stays stopped until the next ACK tick even
    /// though the connection now has room, and nothing in the protocol
    /// requires more DATA from the peer to re-advertise it: the application
    /// freeing its own buffer is the event. The flag is what coalesces a
    /// burst of application releases into one urgent advertisement instead
    /// of one deadline per event.
    fn note_receive_window_reopened(&mut self) {
        if self.receive_window_reopen_pending {
            return;
        }
        if !self
            .receiver
            .as_ref()
            .is_some_and(ReceiverBuffer::receive_window_reopened)
        {
            return;
        }
        self.receive_window_reopen_pending = true;
        // A zero-duration Ack deadline is the existing bounded way to say
        // "now"; the transport's timer store keeps one deadline per id, so
        // even a dropped duplicate collapses to the same instant.
        self.queue_priority_output(QueuedOutput::SetTimer {
            id: TimerId::Ack,
            duration_micros: 0,
        });
    }

    /// Inspect the next pending output without consuming it or modifying connection state.
    #[must_use]
    pub fn peek_output(&self) -> Option<OutputMeta> {
        self.output_queue.front().map(|out| match out {
            QueuedOutput::Datagram(pkt) => OutputMeta::Datagram {
                wire_len: pkt.wire_len(),
                class: pkt.class(),
            },
            QueuedOutput::SetTimer {
                id,
                duration_micros,
            } => OutputMeta::SetTimer {
                id: *id,
                duration_micros: *duration_micros,
            },
            QueuedOutput::ClearTimer { id } => OutputMeta::ClearTimer { id: *id },
        })
    }

    /// Transactionally poll the next output into caller-provided storage.
    ///
    /// If the output is a datagram:
    /// - If `dst.len() < wire_len`: returns `Err(Error::insufficient_buffer())`.
    ///   The output remains in the queue, byte accounting is unchanged, and no
    ///   protocol or crypto state advances.
    /// - If `dst.len() >= wire_len`: encodes directly into `dst`, pops the datagram
    ///   from the output queue, deducts `wire_len` from queue bytes, and returns
    ///   `Ok(Some(OutputInto::Datagram { len: wire_len }))`.
    ///
    /// If the output is a timer action:
    /// - Pops the action from the output queue and returns the action.
    pub fn poll_output_into(&mut self, dst: &mut [u8]) -> Result<Option<OutputInto>, Error> {
        self.check_output_queue()?;
        let front = match self.output_queue.front() {
            Some(f) => f,
            None => return Ok(None),
        };

        match front {
            QueuedOutput::Datagram(pkt) => {
                let wire_len = pkt.wire_len();
                if dst.len() < wire_len {
                    return Err(Error::insufficient_buffer());
                }
                let written = pkt.encode_into(self.crypto.as_deref(), dst)?;
                debug_assert_eq!(written, wire_len);
                let released = match pkt {
                    PendingDatagram::Data(data) => data.crypto.map(|stamp| stamp.key_flag),
                    PendingDatagram::Control(_) => None,
                };
                // The datagram is leaving the protocol for storage the caller
                // has already reserved, so this is the one point where the
                // sender learns the packet was actually transmitted.
                let submitted_sequence = match pkt {
                    PendingDatagram::Data(data) => Some(data.header.sequence_number),
                    PendingDatagram::Control(_) => None,
                };
                let class = pkt.class();
                let source_due_micros = pkt.source_due_micros();
                self.pop_output_front();
                if let Some(flag) = released {
                    self.release_tx_reservation(flag);
                }
                self.output_queue_bytes = self.output_queue_bytes.saturating_sub(wire_len);
                if let Some(sequence) = submitted_sequence {
                    self.note_data_submitted(sequence);
                }
                Ok(Some(OutputInto::Datagram {
                    len: written,
                    class,
                    source_due_micros,
                }))
            }
            QueuedOutput::SetTimer {
                id,
                duration_micros,
            } => {
                let id = *id;
                let duration_micros = *duration_micros;
                self.pop_output_front();
                Ok(Some(OutputInto::SetTimer {
                    id,
                    duration_micros,
                }))
            }
            QueuedOutput::ClearTimer { id } => {
                let id = *id;
                self.pop_output_front();
                Ok(Some(OutputInto::ClearTimer { id }))
            }
        }
    }

    /// Allocating compatibility poll for the simple endpoint surface.
    ///
    /// Implemented on top of [`Self::peek_output`] and [`Self::poll_output_into`].
    ///
    /// Returns `Ok(None)` only when there is genuinely nothing queued. A
    /// transactional failure is reported as `Err`, never as `None`: the
    /// offending output stays queued, so mapping it to `None` would tell a
    /// caller it had drained a packet that is still pending. `Err` here means
    /// the connection's output or event queue overflowed
    /// ([`Self::poll_output_into`]'s `InvalidState`), or materializing the
    /// front datagram failed (`InvalidData`); both are terminal conditions the
    /// caller must handle rather than read as "nothing to send".
    pub fn poll_output(&mut self) -> Result<Option<ConnectionOutput>, Error> {
        let Some(meta) = self.peek_output() else {
            return Ok(None);
        };
        match meta {
            OutputMeta::Datagram { wire_len, .. } => {
                let mut buf = vec![0u8; wire_len];
                match self.poll_output_into(&mut buf)? {
                    Some(OutputInto::Datagram { len, .. }) => {
                        buf.truncate(len);
                        Ok(Some(ConnectionOutput::SendPacket(buf)))
                    }
                    Some(_) => Err(Error::invalid_state(
                        "output variant changed between peek and poll",
                    )),
                    None => Err(Error::invalid_state(
                        "peeked output vanished before it was polled",
                    )),
                }
            }
            OutputMeta::SetTimer { .. } => match self.poll_output_into(&mut [])? {
                Some(OutputInto::SetTimer {
                    id,
                    duration_micros,
                }) => Ok(Some(ConnectionOutput::SetTimer {
                    id,
                    duration_micros,
                })),
                _ => Err(Error::invalid_state(
                    "peeked timer action vanished before it was polled",
                )),
            },
            OutputMeta::ClearTimer { .. } => match self.poll_output_into(&mut [])? {
                Some(OutputInto::ClearTimer { id }) => {
                    Ok(Some(ConnectionOutput::ClearTimer { id }))
                }
                _ => Err(Error::invalid_state(
                    "peeked timer action vanished before it was polled",
                )),
            },
        }
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
            self.queue_output(QueuedOutput::SetTimer {
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

        self.check_output_queue()
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
            self.queue_event(ConnectionEvent::StateChanged(new_state));
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
            let Some((packet, source_time)) = self
                .receiver
                .as_mut()
                .and_then(|receiver| receiver.pop_ready_with_source_time(now))
            else {
                break;
            };
            if let Some(msg) = self.assembler.feed(packet, source_time) {
                self.queue_event(ConnectionEvent::DataReceived {
                    payload: msg.payload,
                    sequence_number: msg.first_sequence_number,
                    message_number: msg.message_number,
                    timestamp: msg.timestamp,
                    source_time: msg.source_time,
                    packet_count: msg.packet_count,
                });
                if self.event_overflowed {
                    break;
                }
                self.pending_data_events = self.pending_data_events.saturating_add(1);
                self.pending_data_packets =
                    self.pending_data_packets.saturating_add(msg.packet_count);
            }
        }
        self.sync_application_backlog();
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
        if self.peer_shutdown_pending {
            // The peer closed its send half: no further DATA is part of this
            // connection's protocol progress. It is rejected rather than
            // ignored, so it cannot bank itself as peer activity either.
            return Err(Error::invalid_state(
                "DATA received after the peer closed its send half",
            ));
        }
        if self.state == ConnectionState::Closing {
            self.finish_local_close(DisconnectReason::PeerActivityAfterShutdown);
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
            self.finish_local_close(DisconnectReason::PeerActivityAfterShutdown);
            return Ok(());
        }
        validate_control_information(&pkt)?;
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
        self.crypto = Some(Box::new(CryptoContext::new_sender(
            &passphrase,
            key_length,
            salt,
            sek,
            self.options.cipher_mode,
        )?));
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
        self.note_peer_flow_window(hs.flow_window);
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

        self.queue_output(QueuedOutput::ClearTimer {
            id: TimerId::Handshake,
        });
        self.setup_connection_timers();
        self.clear_config_secrets();
        self.queue_event(ConnectionEvent::Connected);
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
        self.note_peer_flow_window(hs.flow_window);
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
            self.crypto = Some(Box::new(crypto));
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
        self.queue_output(QueuedOutput::ClearTimer {
            id: TimerId::Handshake,
        });
        self.setup_connection_timers();
        self.clear_config_secrets();
        self.queue_event(ConnectionEvent::Connected);
    }

    fn handle_ack(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        // Shape is validated before dispatch (see
        // `validate_control_information`); this is the last line of defence
        // for the direct callers of this method.
        if pkt.control_info.len() < 4 {
            return Err(Error::invalid_data("ACK control info is too short"));
        }

        let mut buf = pkt.control_info.as_slice();
        let ack_seq = crate::buf::read_u32(&mut buf)?;
        if ack_seq & 0x8000_0000 != 0 {
            return Err(Error::invalid_data(
                "ACK sequence word must not have its high bit set",
            ));
        }

        tracing::debug!(
            "received ACK, ack_seq={}, type_specific_info={}, control_info_len={}",
            ack_seq,
            pkt.type_specific_info,
            pkt.control_info.len()
        );

        // An ACK cannot legitimately name a cumulative position beyond what
        // this sender has actually put on the wire. The *accepted* frontier
        // (`next_sequence_number`) is not the right bound here: #118
        // established that accepted and submitted are different states, and
        // a peer cannot acknowledge DATA still sitting behind this sender's
        // own TX capacity -- only `max_justified_ack_position` (derived from
        // actual first-transmission submission) is. Treating such a position
        // as merely "not current" (as a stale/duplicate ACK is) would still
        // let `set_peer_window` below use it to compute an advertised window
        // end past that frontier, so it is rejected outright rather than
        // silently ignored.
        if let Some(sender) = self.sender.as_ref()
            && sequence_less_than(sender.max_justified_ack_position(), ack_seq)
        {
            return Err(Error::invalid_data(format!(
                "ACK names sequence {ack_seq}, beyond what this sender has actually submitted"
            )));
        }

        // 送信バッファから ACK されたパケットを削除
        let mut ack_progressed = false;
        let mut ack_is_current = false;
        if let Some(ref mut sender) = self.sender {
            let before = sender.packets_in_buffer();
            let oldest_before = sender.oldest_unacked_sequence();
            sender.handle_ack(ack_seq);
            ack_progressed = sender.oldest_unacked_sequence() != oldest_before;
            // A stale or duplicate ACK carries an old cumulative position.
            // It must not move the advertised receive window: doing so would
            // reopen a window the peer has already closed (libsrt keeps this
            // behind `CSeqNo::seqcmp(ackdata_seqno, m_iSndLastAck) >= 0`).
            ack_is_current = !sequence_less_than(ack_seq, oldest_before);
            let after = sender.packets_in_buffer();
            tracing::debug!("sender buffer: {} -> {} packets", before, after);
        }
        // TLPKTDROP may have just tombstoned the only outstanding flight
        // this ACK retired; a queued DATA output for one of those sequences
        // must not survive it (see `purge_stale_queued_data`).
        self.purge_stale_queued_data();

        // RTT, RTTVar, and the advertised receive-buffer size are present in
        // every non-Light ACK size this crate accepts: 16 (Small), 24, 28
        // (Full), and 32 bytes. The pinned Haivision reference
        // (`CUDT::processCtrlAck`, `core.cpp`) folds a Small ACK's RTT into
        // its own estimator exactly the same way, so gating this on the
        // draft's 28-byte Full ACK alone would silently starve the RTO
        // estimator whenever a peer (or a future local encoder) uses the
        // Small form. Applying the window update only when the ACK is
        // current is what stops the stale-credit overrun: the window is an
        // absolute boundary (`ack_seq + free`), so the flight this ACK
        // acknowledges consumes credit rather than restoring it.
        if pkt.control_info.len() >= 16
            && ack_is_current
            && let Some(sender) = self.sender.as_mut()
        {
            let mut feedback = &pkt.control_info[4..16];
            let rtt_micros = crate::buf::read_u32(&mut feedback)?;
            let rtt_variance_micros = crate::buf::read_u32(&mut feedback)?;
            let available_buffer_packets = crate::buf::read_u32(&mut feedback)?;
            sender.set_peer_window(ack_seq, available_buffer_packets);
            // Packet rate / link capacity (24+ bytes) and the legacy
            // receiving byte rate (28+ bytes) are optional telemetry this
            // crate does not otherwise expose; a Small ACK reports zero
            // rather than omitting the call, so the RTT/RTTVar/window
            // feedback above is never skipped for lacking them.
            let (receiving_rate_pps, link_capacity_pps) = if pkt.control_info.len() >= 24 {
                let mut rates = &pkt.control_info[16..24];
                (
                    crate::buf::read_u32(&mut rates)?,
                    crate::buf::read_u32(&mut rates)?,
                )
            } else {
                (0, 0)
            };
            let receiving_rate_bytes_per_second = if pkt.control_info.len() >= 28 {
                crate::buf::read_u32(&mut &pkt.control_info[24..28])?
            } else {
                0
            };
            sender.record_peer_feedback(
                rtt_micros,
                rtt_variance_micros,
                available_buffer_packets,
                receiving_rate_pps,
                link_capacity_pps,
                receiving_rate_bytes_per_second,
            );
        }

        // ACKACK acknowledges receipt of any ACK that named an ACK number.
        // The draft's Full ACK (28 bytes) always does; the pinned Haivision
        // reference (`CUDT::sendCtrl`/`processCtrlAck`, `core.cpp`) also
        // assigns and acknowledges one for its numbered Small ACK (16 bytes)
        // and its 24/32-byte reference-Full variants. `type_specific_info`
        // is exactly that ACK number, and `validate_control_information`
        // already requires it to be nonzero for every accepted size except
        // the unnumbered draft-form Small ACK and the Light ACK (which never
        // carry one), so checking it directly covers every case without
        // branching on length again. (Originally found as upstream
        // shiguredo/srt-rs issue 0054, which only pinned the draft's own
        // `>= 28` rule -- not pinned Haivision's wider acknowledged set.)
        if pkt.type_specific_info != 0 {
            self.send_ackack(pkt.type_specific_info, now);
        }

        // Reset the sender timeout only on cumulative ACK *progress*, and only
        // after the fresh feedback above has been applied, so a restart uses the
        // most recent RTT measurement.
        if ack_progressed {
            self.on_sender_ack_progress();
        }

        Ok(())
    }

    fn handle_nak(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        let loss_ranges = parse_loss_ranges(&pkt.control_info)?;

        // The whole report is validated before any of it is applied; see
        // `SenderBuffer::handle_nak_ranges`. A position inside a message this
        // sender already gave up as too late is answered with the same
        // DROPREQ again -- the peer either lost the first one or still holds
        // the range -- and never with a retransmission of released media.
        let dropped = match self.sender.as_mut() {
            Some(sender) => sender.handle_nak_ranges(&loss_ranges).map_err(|_| {
                Error::invalid_data(
                    "NAK reports a loss position this sender never sent or already retired",
                )
            })?,
            None => Vec::new(),
        };
        for msg in &dropped {
            self.send_drop_req(msg.message_number, msg.first_seq, msg.last_seq, now);
        }

        // 即座に再送処理
        self.process_retransmit(now);

        Ok(())
    }

    fn handle_ackack(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        let ack_number = pkt.type_specific_info;

        // An ACKACK is the peer confirming receipt of a Full ACK this
        // connection sent and has not yet retired: the ACK number is its
        // whole meaning. A number we never sent (or already retired) is not
        // a protocol transition, and must not be banked as peer activity.
        let receiver = self
            .receiver
            .as_mut()
            .ok_or_else(|| Error::invalid_state("ACKACK before the connection has a receiver"))?;
        if !receiver.ack_number_was_sent(ack_number) {
            return Err(Error::invalid_data(format!(
                "ACKACK names ACK number {ack_number}, which was never sent"
            )));
        }

        // RTT を更新 (ACK 送信時刻はReceiverBuffer内で管理)
        receiver.handle_ackack(ack_number, pkt.timestamp, now);

        Ok(())
    }

    /// Handle a peer SHUTDOWN.
    ///
    /// A peer SHUTDOWN closes the peer's *send* half, not this connection's
    /// receive path: data already accepted keeps its TSBPD deadline and is
    /// delivered normally. The terminal event is deferred until the
    /// receiver, the reassembler, and the application queue are all drained,
    /// so an event-driven consumer cannot truncate a stream tail. This is
    /// what Robotweax 0.2.1 fixed ("Deferred peer-shutdown epoll errors until
    /// TSBPD-buffered input is drained") and what its
    /// `compat_runtime_drains_tsbpd_message_after_peer_shutdown` pins.
    fn handle_shutdown(&mut self, now: Timestamp) -> Result<(), Error> {
        // A peer may retransmit SHUTDOWN until it sees this side's answer.
        // Once terminal-pending, every duplicate is ignored: it must not
        // restart the drain, and it must not emit a second terminal event.
        if self.peer_shutdown_pending || self.state == ConnectionState::Disconnected {
            return Ok(());
        }
        if self.state == ConnectionState::Closing {
            // This side already started its own close, which released the
            // receive path itself; the peer's SHUTDOWN merely confirms it.
            self.finish_local_close(DisconnectReason::PeerShutdown);
            return Ok(());
        }

        self.peer_shutdown_pending = true;
        self.shutdown_started_at = None;
        self.queue_output(QueuedOutput::ClearTimer {
            id: TimerId::Shutdown,
        });
        self.enqueue_ready_data(now);
        self.finish_peer_shutdown_if_drained();
        Ok(())
    }

    /// Emit the terminal `PeerShutdown` event once a pending peer close has
    /// nothing left to deliver.
    ///
    /// "Drained" is the receiver holding no deliverable data, the assembler
    /// holding no partial message, and no `DataReceived` event still queued
    /// for the application. A message whose fragments can never be completed
    /// (the peer is gone) does not keep the connection open forever: the
    /// inactivity timer bounds the drain, and TLPKTDROP retires expired
    /// positions the ordinary way.
    fn finish_peer_shutdown_if_drained(&mut self) {
        if !self.peer_shutdown_pending || self.state == ConnectionState::Disconnected {
            return;
        }
        let receiver_drained = self
            .receiver
            .as_ref()
            .is_none_or(ReceiverBuffer::is_delivery_drained);
        if !receiver_drained
            || self.pending_data_events != 0
            || self.assembler.pending_packet_count() != 0
        {
            return;
        }
        self.finish_local_close(DisconnectReason::PeerShutdown);
    }

    fn finish_local_close(&mut self, reason: DisconnectReason) {
        self.shutdown_started_at = None;
        self.queue_output(QueuedOutput::ClearTimer {
            id: TimerId::Shutdown,
        });
        self.set_state(ConnectionState::Disconnected);
        self.queue_event(ConnectionEvent::Disconnected { reason });
    }

    fn handle_drop_req(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;

        let message_number = pkt.type_specific_info & 0x03FF_FFFF;
        // The shape (exactly two 31-bit sequence words) is checked before
        // dispatch; the sequence values themselves are validated before any
        // state changes, so a rejected DROPREQ leaves the receiver untouched.
        let mut buf = &pkt.control_info[..];
        let first_seq = read_u32(&mut buf)?;
        let last_seq = read_u32(&mut buf)?;
        if first_seq & !SEQUENCE_MASK != 0 || last_seq & !SEQUENCE_MASK != 0 {
            return Err(Error::invalid_data("DROPREQ sequence has high bit set"));
        }
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.drop_range(first_seq, last_seq)?;
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
        self.queue_control_packet(pkt, now);
    }

    /// Process a UserDefined packet (KM Refresh).
    fn handle_user_defined(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        // Determine KMREQ/KMRSP from the subtype.
        // SRT_CMD_KMREQ / SRT_CMD_KMRSP live in srt_packet with the class mapping.

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
                // Received a KM Refresh response (sender side). A successful
                // receipt means the peer accepted the new key. No further
                // action needed here (the key switch happens on the sender's
                // own timing). The response is still decoded first: a
                // malformed key-management body is a rejection, not peer
                // activity, whether or not this side acts on its contents.
                let _ = KmMessage::decode(&pkt.control_info)?;
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
            self.queue_event(ConnectionEvent::KeyRefreshNeeded {
                key_length: crypto.key_length().len(),
            });
            self.key_refresh_notified = true;
        }

        // Check whether a key switch is needed.
        if let Some(ref mut crypto) = self.crypto {
            if crypto.should_switch_key() {
                crypto.switch_key();
            }

            // Check whether the old key needs to be disposed of. The old
            // cipher schedule must outlive every queued-but-unmaterialized
            // datagram stamped with its key flag.
            let should_decommission = crypto.should_decommission_old_key();
            let old_flag = crypto.current_key().other();
            let (retained_even, retained_odd) = self
                .sender
                .as_ref()
                .map_or((0, 0), crate::srt_sender::SenderBuffer::retained_stamps);
            // Two independent dependencies on the old generation: datagrams
            // already reserved but not yet materialized, and packets still
            // retained here because the peer has not acknowledged them. A
            // retransmission of a retained packet has to reproduce its
            // original key generation, so retiring it now would make that
            // impossible (Robotweax delays key retirement the same way, and
            // libsrt keeps the block's key flag with the block).
            let outstanding = match old_flag {
                KeyFlag::Even => self
                    .pending_tx_even
                    .saturating_add(u64::from(retained_even)),
                KeyFlag::Odd => self.pending_tx_odd.saturating_add(u64::from(retained_odd)),
            };
            if should_decommission && outstanding == 0 {
                crypto.decommission_old_key();
            }
        }
    }

    /// Send a KMREQ packet (KM Refresh).
    fn send_km_request(&mut self, km_message: &KmMessage, now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::UserDefined,
            subtype: SRT_CMD_KMREQ,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info: km_message.encode(),
        };

        self.queue_control_packet(pkt, now);
    }

    /// Send a KMRSP packet (KM Refresh).
    fn send_km_response(&mut self, km_message: &KmMessage, now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::UserDefined,
            subtype: SRT_CMD_KMRSP,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info: km_message.encode(),
        };

        self.queue_control_packet(pkt, now);
    }

    /// Send a KM refresh error response (KMRSP with its four-byte state).
    fn send_km_error_response(&mut self, error: KmError, now: Timestamp) {
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
        self.queue_control_packet(pkt, now);
    }

    fn ack_timer_tick_micros(&self) -> u64 {
        self.receiver
            .as_ref()
            .map_or_else(
                || crate::receiver::clamp_ack_interval_micros(self.options.ack_interval_micros),
                ReceiverBuffer::ack_timer_tick_micros,
            )
            .min(crate::receiver::ACK_INTERVAL_MICROS)
    }

    /// Set up timers after the connection is established.
    fn setup_connection_timers(&mut self) {
        // Keepalive timer (1 second).
        self.queue_output(QueuedOutput::SetTimer {
            id: TimerId::Keepalive,
            duration_micros: KEEPALIVE_INTERVAL_MICROS,
        });

        // ACK timer always ticks at COMM_SYN (10 ms) for TSBPD/TLPKTDROP.
        // Coalesced ACK only skips sendto on intermediate ticks.
        self.queue_output(QueuedOutput::SetTimer {
            id: TimerId::Ack,
            duration_micros: self.ack_timer_tick_micros(),
        });

        if self.periodic_nak_enabled() {
            // NAK timer (initial value 20ms).
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::Nak,
                duration_micros: PERIODIC_NAK_INTERVAL_MICROS,
            });
        }

        // Inactivity timer (5 seconds).
        self.queue_output(QueuedOutput::SetTimer {
            id: TimerId::Inactivity,
            duration_micros: INACTIVITY_TIMEOUT_MICROS,
        });
    }

    /// Send an ACK packet.
    fn send_ack(&mut self, now: Timestamp) {
        let force_full = self.receive_window_reopen_pending;
        let receiver = match self.receiver.as_mut() {
            Some(r) => r,
            None => return,
        };

        let ack_info = if force_full {
            receiver.generate_full_ack(now)
        } else {
            receiver.generate_ack(now)
        };
        let ack_number = receiver.ack_number();
        receiver.record_ack_sent();
        self.last_ack_time = Some(now);
        // The reopened window is only actually advertised by a Small/Full
        // ACK; a Light ACK that slipped in first leaves the flag set so the
        // next tick sends the full one.
        if !ack_info.is_light {
            self.receive_window_reopen_pending = false;
        }

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

        self.queue_control_packet(pkt, now);
    }

    fn send_encoded_nak(&mut self, control_info: Vec<u8>, now: Timestamp) {
        if control_info.is_empty() {
            return;
        }

        debug_assert!(control_info.len() <= self.max_control_info_size());

        if let Some(receiver) = self.receiver.as_mut() {
            receiver.record_nak_sent();
        }

        let packet = make_nak_packet(
            control_info,
            self.relative_timestamp(now),
            self.peer_socket_id,
        );
        self.queue_control_packet(packet, now);
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
        let mut chunks = NakChunkEncoder::new(max_control_info_size);
        let mut packets = Vec::new();
        receiver.for_each_periodic_nak_range(|loss| {
            if let Some(control_info) = chunks.push(loss) {
                packets.push(make_nak_packet(control_info, timestamp, peer_socket_id));
            }
        });
        if let Some(control_info) = chunks.finish() {
            packets.push(make_nak_packet(control_info, timestamp, peer_socket_id));
        }

        let packets_sent = packets.len() as u32;
        for packet in packets {
            self.queue_control_packet(packet, now);
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

        self.queue_control_packet(pkt, now);
    }

    fn send_induction_request(&mut self, now: Timestamp) {
        let mut hs = HandshakePacket::new_induction_request(self.options.socket_id);
        hs.flow_window = self.flight_capacity_packets();
        let pkt = hs.encode(self.relative_timestamp(now), 0);
        self.queue_handshake_control_packet(pkt, now);
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
        self.queue_handshake_control_packet(pkt, now);
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
        self.queue_handshake_control_packet(pkt, now);
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
        self.queue_handshake_control_packet(pkt, now);
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
        self.queue_handshake_control_packet(packet, now);
        self.terminate_handshake();
        Error::handshake_rejected(reason)
    }

    fn fail_caller_handshake(&mut self, reason: &str) -> Error {
        self.terminate_handshake();
        Error::handshake_rejected(reason)
    }

    fn handshake_timed_out(&self, now: Timestamp) -> bool {
        self.handshake_started_at
            .is_some_and(|started| now.saturating_sub(started) >= self.handshake_timeout_micros)
    }

    fn fail_handshake_timeout(&mut self) {
        if self.handshake_state == HandshakeState::Failed {
            return;
        }
        self.queue_event(ConnectionEvent::Error("handshake timeout".to_string()));
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
        self.queue_output(QueuedOutput::SetTimer {
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
        self.queue_control_packet(pkt, now);
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
        self.queue_control_packet(pkt, now);
    }
}

/// The five SRT control types whose control-information field is a single
/// zero word, because the whole packet is carried in its header.
const NO_ARGUMENT_CONTROLS: [ControlType; 5] = [
    ControlType::AckAck,
    ControlType::Keepalive,
    ControlType::CongestionWarning,
    ControlType::Shutdown,
    ControlType::PeerError,
];

/// Validate a received control packet's control-information field before it
/// is allowed to touch connection state.
///
/// The control-information field is a sequence of 32-bit words
/// (`draft-sharabayko-srt`, control packet layout), so a payload that is not
/// word-aligned is malformed. libsrt encodes every no-argument control with
/// exactly one zero word (`CPacket::pack`'s `m_extra_pad`) and always gives
/// DROPREQ two sequence words, so `srt-rs` accepts exactly those canonical
/// shapes and rejects everything else: a malformed control is a rejection,
/// never "valid peer activity that was ignored".
///
/// An *empty* no-argument payload is accepted as well as the four zero bytes
/// it canonically carries. Robotweax 0.2.2 rejects the empty form outright,
/// but the pinned Haivision decoder imposes no size rule for these types and
/// the draft specifies their data field as empty, so rejecting it would trade
/// interoperability for nothing: an empty no-argument control cannot carry
/// anything, hostile or otherwise.
fn validate_control_information(pkt: &ControlPacket) -> Result<(), Error> {
    let len = pkt.control_info.len();
    if !len.is_multiple_of(4) {
        return Err(Error::invalid_data(format!(
            "control information field is not 32-bit aligned: {len} bytes"
        )));
    }
    if NO_ARGUMENT_CONTROLS.contains(&pkt.control_type) {
        let canonical = len == 4 && pkt.control_info.iter().all(|&byte| byte == 0);
        if len != 0 && !canonical {
            return Err(Error::invalid_data(format!(
                "{:?} control must carry no argument, got {len} bytes",
                pkt.control_type
            )));
        }
        return Ok(());
    }
    if len == 0 {
        return Err(Error::invalid_data(format!(
            "{:?} control has an empty information field",
            pkt.control_type
        )));
    }
    match pkt.control_type {
        ControlType::Ack => validate_ack_shape(pkt.type_specific_info, len),
        // A DROPREQ is exactly the two 31-bit sequence words it names.
        ControlType::DropReq if len != 8 => Err(Error::invalid_data(format!(
            "DROPREQ control info must be 8 bytes, got {len}"
        ))),
        _ => Ok(()),
    }
}

/// Validate one ACK's length/ACK-number combination against the bounded
/// set of shapes the pinned Haivision reference (`899348d8`, `core.cpp`'s
/// `CUDT::sendCtrl`/`processCtrlAck`) actually emits and accepts -- wider
/// than the draft's own three canonical sizes.
///
/// Light (4 bytes) carries only the cumulative position and never an ACK
/// number. Small (16 bytes) adds RTT/RTTVar/advertised-buffer, and comes
/// in two forms Haivision itself produces: the draft's unnumbered form
/// (ACK number 0) and a deployed numbered variant (nonzero) that gets
/// acknowledged with ACKACK -- Robotweax pins a regression for exactly
/// this variant. The reference-Full sizes (24, adding packet
/// rate/capacity; 28, the draft's own Full ACK, adding the receiving byte
/// rate; and libsrt's legacy 32-byte form with one extra, unused field)
/// always carry a nonzero ACK number. Any other aligned length is not a
/// protocol transition this crate (or any pinned reference) actually
/// produces.
fn validate_ack_shape(ack_number: u32, len: usize) -> Result<(), Error> {
    if !matches!(len, 4 | 16 | 24 | 28 | 32) {
        return Err(Error::invalid_data(format!(
            "ACK control info must be 4, 16, 24, 28, or 32 bytes, got {len}"
        )));
    }
    if len == 4 && ack_number != 0 {
        return Err(Error::invalid_data(
            "Light ACK (4-byte CIF) must not carry an ACK number",
        ));
    }
    if len >= 24 && ack_number == 0 {
        return Err(Error::invalid_data(format!(
            "{len}-byte ACK must carry a nonzero ACK number"
        )));
    }
    Ok(())
}

/// Parse a loss list (from a NAK packet's control_info).
#[cfg(test)]
fn parse_loss_list(data: &[u8], _max_entries: usize) -> Result<Vec<u32>, Error> {
    let ranges = parse_loss_ranges(data)?;
    let mut result = Vec::with_capacity(ranges.len());
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

/// Parse a NAK's compact loss list into bounded ranges.
///
/// No truncation and no expansion happen here: a range is returned as a
/// range, so a report that names more positions than the connection can
/// possibly hold is still a *complete* report by the time the sender
/// validates it. Clamping it to whatever fits would let a valid prefix carry
/// an impossible tail past validation.
fn parse_loss_ranges(data: &[u8]) -> Result<Vec<LossRange>, Error> {
    if !data.len().is_multiple_of(4) {
        return Err(Error::invalid_data(
            "NAK loss list length is not a multiple of four",
        ));
    }
    // At most one range per four-byte word, so the datagram size bounds the
    // allocation; the *span* a range may name is the sender's business.
    let mut result = Vec::with_capacity(data.len() / 4);
    let mut slice = data;

    while !slice.is_empty() {
        let word = crate::buf::read_u32(&mut slice)?;
        if word & 0x8000_0000 != 0 {
            if slice.len() < 4 {
                return Err(Error::invalid_data("NAK range is missing its end"));
            }
            let start = word & 0x7FFF_FFFF;
            let end = crate::buf::read_u32(&mut slice)?;
            if end & 0x8000_0000 != 0 {
                // The SRT encoding (and Robotweax) require a range's end
                // word to have its high bit clear -- only the start word's
                // high bit marks a compact range. A second set high bit is
                // not a range this decoder can normalize: masking it off
                // silently would turn a malformed `[1|start] [1|end]` pair
                // into a valid-looking range the peer never actually sent.
                return Err(Error::invalid_data(
                    "NAK range end word must not have its high bit set",
                ));
            }
            result.push(LossRange {
                first_seq: start,
                last_seq: end,
            });
        } else {
            result.push(LossRange {
                first_seq: word,
                last_seq: word,
            });
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

fn make_nak_packet(control_info: Vec<u8>, timestamp: u32, peer_socket_id: u32) -> ControlPacket {
    ControlPacket {
        control_type: ControlType::Nak,
        subtype: 0,
        type_specific_info: 0,
        timestamp,
        dest_socket_id: peer_socket_id,
        control_info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{GroupType, SRTGROUP_MASK};

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
    fn handshake_option_strings_are_bounded_at_construction() {
        let conn = SrtConnection::new_caller(ConnectionOptions {
            stream_id: Some("あ".repeat(200)),
            congestion_control: "live-".to_owned() + &"x".repeat(600),
            ..ConnectionOptions::default()
        });

        let stream_id = conn.options.stream_id.as_deref().expect("stream id");
        assert_eq!(stream_id.len(), 510);
        assert!(conn.options.congestion_control.len() <= MAX_HANDSHAKE_OPTION_BYTES);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "cap-scale loop (MAX_OUTPUT_QUEUE_ACTIONS retries); the fail-closed                   behavior is proven here at full scale outside Miri, and `handle_timer`                   ownership is exercised by the rest of this module under Miri"
    )]
    fn output_queue_overflow_fails_closed_and_stays_bounded() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.connect(Timestamp::default()).expect("start handshake");

        let mut overflow = false;
        for _ in 0..=MAX_OUTPUT_QUEUE_ACTIONS {
            if conn
                .handle_timer(TimerId::Handshake, Timestamp::default())
                .is_err()
            {
                overflow = true;
                break;
            }
        }

        assert!(overflow, "the finite output cap must fail closed");
        assert!(conn.output_queue.len() <= MAX_OUTPUT_QUEUE_ACTIONS);
        assert!(conn.output_queue_bytes <= MAX_OUTPUT_QUEUE_BYTES);
        assert_eq!(conn.state(), ConnectionState::Disconnected);

        let events_after_overflow = conn.event_queue.len();
        for _ in 0..128 {
            assert!(conn.connect(Timestamp::default()).is_err());
        }
        assert_eq!(
            conn.event_queue.len(),
            events_after_overflow,
            "terminal output overflow must reject reconnects without growing events"
        );
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
        conn.crypto = Some(Box::new(crypto));

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

        let Some(ConnectionOutput::SendPacket(bytes)) = conn.poll_output().unwrap() else {
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
            conn.poll_output().unwrap(),
            Some(ConnectionOutput::SendPacket(_))
        ));
        let Some(ConnectionOutput::SetTimer {
            id: TimerId::Handshake,
            duration_micros,
        }) = conn.poll_output().unwrap()
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
        while conn.poll_output().unwrap().is_some() {}

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
        let _ = conn.poll_output().unwrap();
        let Some(ConnectionOutput::SetTimer {
            duration_micros, ..
        }) = conn.poll_output().unwrap()
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

    /// Drive a full caller/listener handshake to `Connected` on both ends,
    /// for tests that only care about post-handshake send behavior.
    fn drive_handshake_to_connected(caller: &mut SrtConnection, listener: &mut SrtConnection) {
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        for round in 0..4 {
            let now = Timestamp::from_micros(round * 10_000);
            while let Some(ConnectionOutput::SendPacket(packet)) = caller.poll_output().unwrap() {
                listener
                    .feed_recv_buf(&packet, now)
                    .expect("listener accepts packet");
            }
            while let Some(ConnectionOutput::SendPacket(packet)) = listener.poll_output().unwrap() {
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
    }

    /// Default-options caller/listener pair, already `Connected`.
    fn connected_pair() -> (SrtConnection, SrtConnection) {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            ..ConnectionOptions::default()
        });
        drive_handshake_to_connected(&mut caller, &mut listener);
        (caller, listener)
    }

    /// Minimal stand-in for a transport timer store: applies the connection's
    /// own `SetTimer`/`ClearTimer` outputs, and fires only the timers whose
    /// deadline has actually elapsed.
    ///
    /// This indirection is the point of the timeout tests. Calling
    /// `handle_timer(TimerId::SenderRto, ..)` by hand would prove the recovery
    /// *action* while leaving the *trigger* -- armed when DATA is really
    /// submitted, fired on elapsed time, reset only by ACK progress --
    /// completely unexercised. `srt-transport`'s `ManualTimerStore` covers the
    /// same property through the real store (see
    /// `crates/srt-transport/tests/tail_recovery.rs`).
    #[derive(Debug, Default)]
    struct TestTimers {
        deadlines: [Option<Timestamp>; TimerId::COUNT],
    }

    impl TestTimers {
        fn apply(&mut self, output: &ConnectionOutput, now: Timestamp) {
            match output {
                ConnectionOutput::SetTimer {
                    id,
                    duration_micros,
                } => self.deadlines[id.index()] = Some(now.add_micros(*duration_micros)),
                ConnectionOutput::ClearTimer { id } => self.deadlines[id.index()] = None,
                ConnectionOutput::SendPacket(_) => {}
            }
        }

        fn is_armed(&self, id: TimerId) -> bool {
            self.deadlines[id.index()].is_some()
        }

        /// Fire every elapsed timer, once each, in `TimerId::ALL` order.
        fn fire_due(&mut self, now: Timestamp, conn: &mut SrtConnection) {
            for &id in &TimerId::ALL {
                if let Some(deadline) = self.deadlines[id.index()]
                    && now.as_micros() >= deadline.as_micros()
                {
                    self.deadlines[id.index()] = None;
                    let _ = conn.handle_timer(id, now);
                }
            }
        }
    }

    /// One scripted flight between a connected caller/listener pair, driven
    /// entirely by the protocol's own outputs.
    struct FlightHarness {
        caller: SrtConnection,
        listener: SrtConnection,
        caller_timers: TestTimers,
        listener_timers: TestTimers,
        now: Timestamp,
        /// Indices, in first-transmission order, of the DATA datagrams the wire
        /// withholds. Every later transmission of the same sequence is a
        /// retransmission and is *not* subject to this.
        dropped_first_transmissions: Vec<usize>,
        first_transmissions: usize,
        /// Sequences of the DATA datagrams the caller submitted, in order.
        first_transmission_seqs: Vec<u32>,
        retransmitted_data: Vec<u32>,
        /// Most recent Full ACK the listener emitted, replayed by the
        /// non-progress storm.
        last_full_ack: Option<Vec<u8>>,
        replayed_full_acks: usize,
        /// Inject one non-progress Full ACK per tick.
        ack_storm: bool,
        /// Stand-in for a transport with no TX capacity left: DATA datagrams
        /// stay in the connection's output queue, un-materialized and therefore
        /// never transmitted.
        tx_blocked: bool,
    }

    impl FlightHarness {
        fn new(dropped_first_transmissions: &[usize]) -> Self {
            let (caller, listener) = connected_pair();
            Self {
                caller,
                listener,
                caller_timers: TestTimers::default(),
                listener_timers: TestTimers::default(),
                now: Timestamp::from_micros(1_000_000),
                dropped_first_transmissions: dropped_first_transmissions.to_vec(),
                first_transmissions: 0,
                first_transmission_seqs: Vec::new(),
                retransmitted_data: Vec::new(),
                last_full_ack: None,
                replayed_full_acks: 0,
                ack_storm: false,
                tx_blocked: false,
            }
        }

        fn send_flight(&mut self, count: usize) {
            for i in 0..count {
                self.caller
                    .send(format!("payload {i}").as_bytes(), self.now)
                    .expect("send admits the payload");
            }
        }

        /// Move everything the caller produced: timer actions into its store,
        /// DATA datagrams onto the wire (subject to loss), everything else to
        /// the listener.
        ///
        /// `tx_blocked` models a transport that has no capacity left. Nothing
        /// behind the datagram it cannot take is applied either -- not even a
        /// timer action -- because that is exactly what the real drain path does
        /// when it stops on a blocked datagram.
        fn drain_caller(&mut self) {
            let Self {
                caller,
                listener,
                caller_timers,
                now,
                dropped_first_transmissions,
                first_transmissions,
                first_transmission_seqs,
                retransmitted_data,
                tx_blocked,
                ..
            } = self;
            loop {
                if *tx_blocked && matches!(caller.peek_output(), Some(OutputMeta::Datagram { .. }))
                {
                    break;
                }
                let Some(output) = caller
                    .poll_output()
                    .expect("exact-size output materializes")
                else {
                    break;
                };
                caller_timers.apply(&output, *now);
                let ConnectionOutput::SendPacket(bytes) = output else {
                    continue;
                };
                if let Ok(SrtPacket::Data(packet)) = SrtPacket::decode(&bytes) {
                    if packet.retransmitted {
                        retransmitted_data.push(packet.sequence_number);
                    } else {
                        let index = *first_transmissions;
                        *first_transmissions += 1;
                        first_transmission_seqs.push(packet.sequence_number);
                        if dropped_first_transmissions.contains(&index) {
                            continue; // lost on the wire, never delivered
                        }
                    }
                }
                listener
                    .feed_recv_buf(&bytes, *now)
                    .expect("listener accepts packet");
            }
        }

        /// Move everything the listener produced, keeping the most recent Full
        /// ACK for the non-progress storm.
        fn drain_listener(&mut self) {
            let Self {
                caller,
                listener,
                listener_timers,
                now,
                last_full_ack,
                ..
            } = self;
            while let Some(output) = listener
                .poll_output()
                .expect("exact-size output materializes")
            {
                listener_timers.apply(&output, *now);
                let ConnectionOutput::SendPacket(bytes) = output else {
                    continue;
                };
                if let Ok(SrtPacket::Control(control)) = SrtPacket::decode(&bytes)
                    && control.control_type == ControlType::Ack
                    && control.control_info.len() >= FULL_ACK_CONTROL_INFO_BYTES
                {
                    *last_full_ack = Some(bytes.clone());
                }
                caller
                    .feed_recv_buf(&bytes, *now)
                    .expect("caller accepts packet");
            }
        }

        /// Advance one 10 ms tick: fire elapsed timers, then move every datagram
        /// and timer action the two endpoints produce.
        fn tick(&mut self) {
            self.now = Timestamp::from_micros(self.now.as_micros() + 10_000);
            let now = self.now;
            self.caller_timers.fire_due(now, &mut self.caller);
            self.listener_timers.fire_due(now, &mut self.listener);
            self.drain_caller();
            self.drain_listener();

            if self.ack_storm
                && let Some(ack) = self.last_full_ack.clone()
            {
                // A valid Full ACK whose `ack_seq` does not move: exactly the
                // condition that must not reset the sender timeout.
                self.caller
                    .feed_recv_buf(&ack, now)
                    .expect("caller accepts a repeated Full ACK");
                self.replayed_full_acks += 1;
            }

            // Events coalesce; drain them so the receiver's own accounting
            // stays live (delivery is read from it, never from event count).
            while self.listener.poll_event().is_some() {}
            while self.caller.poll_event().is_some() {}
        }

        fn run(&mut self, ticks: usize) {
            for _ in 0..ticks {
                self.tick();
            }
        }

        fn delivered(&self) -> u64 {
            self.listener
                .receiver_stats()
                .expect("connected receiver")
                .total_received
        }

        fn retransmits(&self) -> u64 {
            self.caller
                .sender_stats()
                .expect("connected sender")
                .total_retransmits
        }
    }

    const FLIGHT: usize = 4;

    /// Control: with nothing dropped, every payload arrives and the sender
    /// retransmits nothing. Without this the tail tests could pass or fail for a
    /// harness reason instead of the property under test.
    #[test]
    fn an_intact_flight_is_delivered_whole() {
        let mut flight = FlightHarness::new(&[]);
        flight.send_flight(FLIGHT);
        flight.run(400);
        assert_eq!(flight.delivered(), FLIGHT as u64);
        assert_eq!(
            flight.retransmits(),
            0,
            "a lossless flight must not retransmit"
        );
    }

    /// Tail recovery: a lost FINAL data packet must not be stranded, and the
    /// recovery must arrive through the sender's own timeout -- armed by the
    /// submission of DATA and fired by elapsed time, not by this test calling
    /// the timer handler.
    ///
    /// The receiver can only name a loss it has evidence for, and a missing
    /// *suffix* of a flight provides none -- no later sequence number arrives to
    /// expose the gap, so no NAK is generated and the receiver reports no loss
    /// while the payload is simply absent.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "400-tick FlightHarness run (handshake plus hundreds of real protocol   \
                  ticks); correctness is proven here at full scale outside Miri, and     \
                  `an_expiry_with_selective_recovery_pending_does_not_widen_it` exercises \
                  the same SenderRto ownership pattern cheaply under Miri. Run in the    \
                  miri-extended scheduled job."
    )]
    fn a_lost_final_data_packet_is_recovered_by_the_sender() {
        let mut flight = FlightHarness::new(&[FLIGHT - 1]);
        flight.send_flight(FLIGHT);
        flight.run(400);
        assert_eq!(
            flight.delivered(),
            FLIGHT as u64,
            "a lost final DATA datagram must be recovered by the sender's own timeout: \
             the receiver cannot name a gap that no later sequence number exposes, so \
             nothing else will ask for it"
        );
        assert!(
            flight.retransmits() >= 1,
            "recovery must come from a retransmission"
        );
    }

    /// A lost flight *tail* of three packets exposes no later sequence number
    /// either, so the single timeout probe has to do two jobs: repair the newest
    /// packet, and -- by arriving -- give the receiver the later sequence
    /// evidence that turns the two older gaps into nameable ones. One probe is
    /// queued by the timeout, never a replay of the unacknowledged flight.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "200-tick FlightHarness run; correctness is proven here at full scale  \
                  outside Miri. Run in the miri-extended scheduled job."
    )]
    fn a_lost_three_packet_tail_is_recovered_by_one_probe_plus_nak() {
        let mut flight = FlightHarness::new(&[1, 2, 3]);
        flight.send_flight(FLIGHT);
        flight.run(200);
        assert_eq!(flight.delivered(), FLIGHT as u64);
        let flight_seqs = flight.first_transmission_seqs.clone();
        assert_eq!(
            flight.retransmitted_data.first().copied(),
            Some(flight_seqs[3]),
            "the timeout's probe must be the newest submitted packet"
        );
        let mut distinct = flight.retransmitted_data.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct,
            flight_seqs[1..].to_vec(),
            "the probe exposes the two older gaps to NAK recovery, and no more"
        );
        assert!(
            !flight.retransmitted_data.contains(&flight_seqs[0]),
            "the acknowledged packet must never be retransmitted: {:?}",
            flight.retransmitted_data
        );
    }

    /// Item 3's starvation condition: a peer that keeps sending valid Full ACKs
    /// without advancing `ack_seq` (which a receiver does while its own window is
    /// stalled) must not be able to keep the timeout from ever firing.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "200-tick FlightHarness run with a replayed ACK injected every tick;    \
                  correctness is proven here at full scale outside Miri. Run in the      \
                  miri-extended scheduled job."
    )]
    fn a_non_progress_ack_storm_still_reaches_the_tail_timeout() {
        let mut flight = FlightHarness::new(&[FLIGHT - 1]);
        flight.ack_storm = true;
        flight.send_flight(FLIGHT);
        // Enough ticks to cross the initial 320 ms timeout several times over,
        // so the storm covers the whole recovery window.
        flight.run(200);
        assert!(
            flight.replayed_full_acks >= 10,
            "the storm must actually have injected ACKs (injected {})",
            flight.replayed_full_acks
        );
        assert_eq!(
            flight.delivered(),
            FLIGHT as u64,
            "repeated non-progress Full ACKs must not starve the tail timeout"
        );
    }

    /// A packet that has not been transmitted must never be probed: the sender
    /// has no loss evidence about it, and re-sending it would duplicate a
    /// transmission that is still waiting for capacity rather than repair one.
    ///
    /// The first two datagrams are lost on the wire, so the flight stays
    /// outstanding and the timeout stays armed. The next two are accepted by the
    /// protocol but the "transport" stops materializing DATA, so they sit in the
    /// output queue and have never been on the wire. The probe must select the
    /// newest *submitted* packet, not the newest accepted one.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "460-tick FlightHarness run; correctness is proven here at full scale  \
                  outside Miri. Run in the miri-extended scheduled job."
    )]
    fn an_unsubmitted_packet_is_never_selected_by_the_timeout() {
        let mut flight = FlightHarness::new(&[0, 1]);
        flight.send_flight(2);
        // One tick submits both datagrams, which arms the timeout.
        flight.tick();
        assert_eq!(flight.retransmitted_data, Vec::<u32>::new());
        let newest_submitted = flight.first_transmission_seqs[1];

        // Accepted, queued, never submitted: TX capacity is where the protocol
        // boundary stops.
        flight.tx_blocked = true;
        flight.send_flight(2);
        assert_eq!(
            flight.first_transmission_seqs.len(),
            2,
            "a blocked transport must not have materialized the new payloads"
        );
        // Well past the initial 320 ms timeout. The probe is queued while the
        // target decision is made -- i.e. while datagrams 3 and 4 are still
        // un-materialized and 2 is the newest submitted packet.
        flight.run(60);

        // Capacity returns: everything queued goes out, the probe included.
        flight.tx_blocked = false;
        flight.run(400);

        assert_eq!(flight.delivered(), FLIGHT as u64);
        assert_eq!(
            flight.retransmitted_data.first().copied(),
            Some(newest_submitted),
            "the timeout must probe the newest packet that was actually submitted"
        );
        let unsubmitted = &flight.first_transmission_seqs[2..];
        assert!(
            !flight
                .retransmitted_data
                .iter()
                .any(|seq| unsubmitted.contains(seq)),
            "a packet that was still waiting for TX capacity was retransmitted: {:?}",
            flight.retransmitted_data
        );
    }

    /// Once every submitted packet has been acknowledged there is no flight left
    /// to time: the epoch must be disarmed rather than left running into a
    /// pointless probe.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "450-tick FlightHarness run; correctness is proven here at full scale  \
                  outside Miri. Run in the miri-extended scheduled job."
    )]
    fn a_fully_acknowledged_flight_disarms_the_sender_timeout() {
        let mut flight = FlightHarness::new(&[]);
        flight.send_flight(FLIGHT);
        flight.run(50);
        assert_eq!(flight.delivered(), FLIGHT as u64);
        assert!(
            !flight.caller_timers.is_armed(TimerId::SenderRto),
            "an empty flight must leave no sender timeout armed"
        );
        flight.run(400);
        assert_eq!(
            flight.retransmits(),
            0,
            "nothing outstanding means nothing to probe"
        );
    }

    /// With selective (NAK-driven) recovery already pending, an expiry must not
    /// add its probe: the peer has named the loss, so a blind probe would widen
    /// an in-progress repair instead of helping it. The expiry still rearms, with
    /// backoff, because the timeout must keep running as a backstop.
    #[test]
    fn an_expiry_with_selective_recovery_pending_does_not_widen_it() {
        let (mut caller, _listener) = connected_pair();
        let now = Timestamp::from_micros(1_000_000);
        let first = caller.next_sequence_number().expect("connected sender");
        for i in 0..FLIGHT {
            caller
                .send(format!("payload {i}").as_bytes(), now)
                .expect("send admits the payload");
        }

        // Materialize the flight into a timer store: submitting DATA is what arms
        // the timeout, and the store is how these tests observe arming.
        let mut timers = TestTimers::default();
        let mut armed_with = None;
        while let Some(output) = caller.poll_output().unwrap() {
            timers.apply(&output, now);
            if let ConnectionOutput::SetTimer {
                id: TimerId::SenderRto,
                duration_micros,
            } = output
            {
                armed_with = Some(duration_micros);
            }
        }
        assert!(
            timers.is_armed(TimerId::SenderRto),
            "submitting DATA must arm the sender timeout"
        );
        let armed_with = armed_with.expect("the arming action is observable");

        // The peer names the loss of the second packet. No visit drains it yet,
        // so the sender holds a pending selective retransmission.
        caller
            .sender
            .as_mut()
            .expect("connected sender")
            .handle_nak_ranges(&[LossRange {
                first_seq: first + 1,
                last_seq: first + 1,
            }])
            .unwrap();
        assert!(caller.has_retransmit(), "the NAK leaves work pending");

        let expiry = Timestamp::from_micros(now.as_micros() + armed_with + 1);
        timers.fire_due(expiry, &mut caller);
        // What the continuation timer would then do with the queue as it stands.
        caller.process_retransmit(expiry);

        let outputs = drain_outputs(&mut caller);
        let retransmitted: Vec<u32> = outputs
            .iter()
            .filter_map(|output| match output {
                ConnectionOutput::SendPacket(bytes) => match SrtPacket::decode(bytes) {
                    Ok(SrtPacket::Data(packet)) if packet.retransmitted => {
                        Some(packet.sequence_number)
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(
            retransmitted,
            vec![first + 1],
            "the expiry must not widen a pending selective recovery: only the NAK-ed \
             sequence may be retransmitted, never the newest submitted packet"
        );

        let rearmed = outputs
            .into_iter()
            .find_map(|output| match output {
                ConnectionOutput::SetTimer {
                    id: TimerId::SenderRto,
                    duration_micros,
                } => Some(duration_micros),
                _ => None,
            })
            .expect("an expiry with work outstanding must rearm");
        assert!(
            rearmed > armed_with,
            "the rearm must back off ({rearmed} must exceed {armed_with})"
        );
    }

    /// The case in which nothing but the submission trigger can help: the whole
    /// flight is lost, so the receiver never acknowledges anything and ACK
    /// progress -- the other event that arms the timeout -- never happens. If
    /// the timeout were only armed as a side effect of ACK traffic, this stall
    /// would be permanent.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "400-tick FlightHarness run; correctness is proven here at full scale  \
                  outside Miri, and `a_lost_final_data_packet_is_recovered_by_the_sender`\
                  covers the submission-trigger path's ownership pattern when the       \
                  miri-extended job runs it. Run in the miri-extended scheduled job."
    )]
    fn a_flight_lost_in_full_is_recovered_by_the_submission_trigger() {
        let mut flight = FlightHarness::new(&[0, 1, 2, 3]);
        flight.send_flight(FLIGHT);
        flight.run(400);
        assert_eq!(
            flight.delivered(),
            FLIGHT as u64,
            "a flight with no feedback at all must still be recovered by the sender's \
             own timeout, armed when its DATA was submitted"
        );
        assert_eq!(
            flight.retransmitted_data.first().copied(),
            flight.first_transmission_seqs.last().copied(),
            "the probe must be the newest submitted packet"
        );
    }

    /// P01: a single visit must not encrypt/queue an unbounded number of
    /// retransmits. Simulates the worst case directly -- a NAK covering a
    /// loss range far larger than `MAX_RETRANSMITS_PER_VISIT` -- and checks
    /// three things: the first visit caps at exactly the bound, the
    /// uncapped remainder is neither lost nor duplicated once a follow-up
    /// visit runs, and the visit self-schedules that follow-up (the
    /// Retransmit timer is otherwise never armed by anything else).
    #[test]
    fn process_retransmit_bounds_one_visit_and_resumes_the_rest_on_the_next() {
        let (mut caller, _listener) = connected_pair();
        let now = Timestamp::from_micros(0);

        const SENT: usize = MAX_RETRANSMITS_PER_VISIT + 18;
        let first_seq = caller.next_sequence_number().expect("connected sender");
        for i in 0..SENT {
            caller
                .send(format!("payload {i}").as_bytes(), now)
                .expect("send admits the payload");
        }
        // Drain the normal sends to the wire -- this test cares about the
        // *retransmit* path, not the original transmission.
        while caller.poll_output().unwrap().is_some() {}

        // Simulate the peer NAK-ing every one of them in one range.
        let last_seq = first_seq.wrapping_add(SENT as u32 - 1);
        caller
            .sender
            .as_mut()
            .expect("connected sender")
            .handle_nak_ranges(&[LossRange {
                first_seq,
                last_seq,
            }])
            .unwrap();

        caller.process_retransmit(now);

        let mut first_visit_seqs = Vec::new();
        let mut first_visit_rearmed = false;
        while let Some(output) = caller.poll_output().unwrap() {
            match output {
                ConnectionOutput::SendPacket(bytes) => {
                    let SrtPacket::Data(pkt) = SrtPacket::decode(&bytes).expect("valid packet")
                    else {
                        panic!("retransmit must encode as a DATA packet");
                    };
                    first_visit_seqs.push(pkt.sequence_number);
                }
                ConnectionOutput::SetTimer {
                    id: TimerId::RetransmitContinue,
                    ..
                } => first_visit_rearmed = true,
                _ => {}
            }
        }
        assert_eq!(
            first_visit_seqs,
            (0..MAX_RETRANSMITS_PER_VISIT as u32)
                .map(|i| first_seq.wrapping_add(i))
                .collect::<Vec<_>>(),
            "one visit must retransmit exactly the first MAX_RETRANSMITS_PER_VISIT sequences, \
             in order -- not the whole loss list, and not some other subset"
        );
        assert!(
            first_visit_rearmed,
            "leftover work after the cap must self-schedule a follow-up visit -- \
             nothing else ever arms the Retransmit timer"
        );
        assert!(
            caller.has_retransmit(),
            "the uncapped remainder must still be pending, not dropped"
        );

        // The follow-up visit (as if the self-armed timer had just fired).
        caller.process_retransmit(Timestamp::from_micros(1_000));

        let mut second_visit_seqs = Vec::new();
        let mut second_visit_rearmed = false;
        while let Some(output) = caller.poll_output().unwrap() {
            match output {
                ConnectionOutput::SendPacket(bytes) => {
                    let SrtPacket::Data(pkt) = SrtPacket::decode(&bytes).expect("valid packet")
                    else {
                        panic!("retransmit must encode as a DATA packet");
                    };
                    second_visit_seqs.push(pkt.sequence_number);
                }
                ConnectionOutput::SetTimer {
                    id: TimerId::RetransmitContinue,
                    ..
                } => second_visit_rearmed = true,
                _ => {}
            }
        }
        assert_eq!(
            second_visit_seqs,
            (MAX_RETRANSMITS_PER_VISIT as u32..SENT as u32)
                .map(|i| first_seq.wrapping_add(i))
                .collect::<Vec<_>>(),
            "the follow-up visit must retransmit exactly the remaining sequences, in order -- \
             none lost, none duplicated, none reordered"
        );
        assert!(
            !second_visit_rearmed,
            "once the loss list is fully drained there is nothing left to resume"
        );
        assert!(!caller.has_retransmit());
    }

    /// S06 (revalidation, not a fix): `clear_config_secrets` already
    /// zeroizes and drops `ConnectionOptions`' passphrase/salt/SEK once a
    /// live `CryptoContext` has been built from them, on both the caller
    /// and listener handshake paths. This pins that residual
    /// application-facing copy is actually released, not just the
    /// in-context copy inside `CryptoContext` (already covered by its own
    /// `Drop`/rotation zeroization). Not testing the ephemeral
    /// zeroize-then-drop step itself: that would mean reading memory this
    /// code has already freed, which the card explicitly rules out.
    #[test]
    fn handshake_clears_config_secrets_once_crypto_is_established() {
        let sek = vec![0x24u8; 16];
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            passphrase: Some("shared-secret".to_owned()),
            crypto_salt: Some(test_km_salt()),
            crypto_sek: Some(sek.clone()),
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            passphrase: Some("shared-secret".to_owned()),
            crypto_salt: Some(test_km_salt()),
            crypto_sek: Some(sek),
            ..ConnectionOptions::default()
        });
        drive_handshake_to_connected(&mut caller, &mut listener);
        assert!(caller.crypto.is_some(), "caller established a live context");
        assert!(
            listener.crypto.is_some(),
            "listener established a live context"
        );

        for (who, conn) in [("caller", &caller), ("listener", &listener)] {
            assert!(conn.options.passphrase.is_none(), "{who} passphrase");
            assert!(conn.options.crypto_salt.is_none(), "{who} crypto_salt");
            assert!(conn.options.crypto_sek.is_none(), "{who} crypto_sek");
        }
    }

    /// S01: a wrong explicit sequence must be rejected on both the owned
    /// and shared send paths -- the shared path used to have no such
    /// check at all and silently returned `Ok(())` from `push_shared`'s
    /// internal `None` (I1: a rejection must never read as admission).
    /// Confirms the rejection leaves next_seq/output untouched and that a
    /// subsequent correctly-sequenced send on the same path still works.
    #[test]
    fn explicit_sequence_mismatch_is_rejected_on_owned_and_shared_paths() {
        let (mut caller, _listener) = connected_pair();
        while caller.poll_output().unwrap().is_some() {} // drain handshake-tail output (timers, ACKs)

        // Owned path.
        let next = caller.next_sequence_number().expect("connected sender");
        let wrong = next.wrapping_add(1) & 0x7FFF_FFFF;
        let err = caller
            .send_with_sequence(b"owned", wrong, Timestamp::from_micros(100_000))
            .expect_err("owned mismatch is rejected");
        assert_eq!(err.reason, "sequence number is out of order");
        assert_eq!(
            caller.next_sequence_number(),
            Some(next),
            "rejection leaves next_seq unchanged"
        );
        assert!(
            caller.poll_output().unwrap().is_none(),
            "no packet was queued for a rejected send"
        );
        caller
            .send_with_sequence(b"owned", next, Timestamp::from_micros(100_001))
            .expect("correct sequence is accepted");
        assert_eq!(
            caller.next_sequence_number(),
            Some(next.wrapping_add(1) & 0x7FFF_FFFF)
        );
        assert!(matches!(
            caller.poll_output().unwrap(),
            Some(ConnectionOutput::SendPacket(_))
        ));

        // Shared path -- this is the path that previously had no guard.
        let next = caller.next_sequence_number().expect("connected sender");
        let wrong = next.wrapping_add(7) & 0x7FFF_FFFF;
        let err = caller
            .send_shared_with_sequence(
                Bytes::from_static(b"shared"),
                wrong,
                Timestamp::from_micros(100_002),
            )
            .expect_err("shared mismatch is rejected, not silently admitted");
        assert_eq!(err.reason, "sequence number is out of order");
        assert_eq!(
            caller.next_sequence_number(),
            Some(next),
            "rejection leaves next_seq unchanged"
        );
        assert!(
            drain_datagrams(&mut caller).is_empty(),
            "no packet was queued for a rejected shared send"
        );
        caller
            .send_shared_with_sequence(
                Bytes::from_static(b"shared"),
                next,
                Timestamp::from_micros(100_003),
            )
            .expect("correct sequence is accepted on the shared path");
        assert_eq!(
            caller.next_sequence_number(),
            Some(next.wrapping_add(1) & 0x7FFF_FFFF)
        );
        assert!(matches!(
            caller.poll_output().unwrap(),
            Some(ConnectionOutput::SendPacket(_))
        ));
    }

    /// S02: `send`/`send_message`/`send_shared` must reject a packet before
    /// touching sender state if it cannot actually be encrypted, rather
    /// than advancing the sequence and retaining a fragment for
    /// retransmission and only then discovering `encrypt_to_wire` fails.
    /// `drop_current_key_schedule_for_test` reproduces the one realistic
    /// way this happens in production (see `update_sek`'s doc comment)
    /// without driving a full KM wire exchange to a malformed wrapped key.
    #[test]
    fn send_is_rejected_before_admission_when_current_key_cannot_encrypt() {
        let (mut caller, _listener) = connected_pair();
        while caller.poll_output().unwrap().is_some() {}
        caller.crypto = Some(Box::new(
            CryptoContext::new_sender(
                "test_passphrase",
                KeyLength::Aes128,
                test_km_salt(),
                &[0x24; 16],
                CipherMode::Ctr,
            )
            .expect("valid sender crypto"),
        ));
        caller
            .crypto
            .as_mut()
            .unwrap()
            .drop_current_key_schedule_for_test();

        let next = caller.next_sequence_number().expect("connected sender");

        let err = caller
            .send(b"single packet", Timestamp::from_micros(200_000))
            .expect_err("send is rejected, not partially admitted");
        assert!(err.reason.contains("encryption"), "{}", err.reason);
        assert_eq!(caller.next_sequence_number(), Some(next));
        assert!(caller.poll_output().unwrap().is_none());

        // Must exceed effective_max_payload_size (1484 bytes here, plain
        // CTR) so push_message would actually produce multiple fragments
        // -- otherwise this proves nothing beyond the single-packet case
        // above.
        let multi_fragment_payload = vec![0xAA; caller.effective_max_payload_size() * 2 + 37];
        let err = caller
            .send_message(&multi_fragment_payload, Timestamp::from_micros(200_001))
            .expect_err("fragmented message is rejected before any fragment is admitted");
        assert!(err.reason.contains("encryption"), "{}", err.reason);
        assert_eq!(
            caller.next_sequence_number(),
            Some(next),
            "no fragment consumed a sequence number"
        );
        assert!(caller.poll_output().unwrap().is_none());

        let err = caller
            .send_shared(
                Bytes::from_static(b"shared"),
                Timestamp::from_micros(200_002),
            )
            .expect_err("shared send is rejected before admission");
        assert!(err.reason.contains("encryption"), "{}", err.reason);
        assert_eq!(caller.next_sequence_number(), Some(next));
        assert!(caller.poll_output().unwrap().is_none());
    }

    /// P03: GCM's 16-byte tag is real wire overhead on top of the header
    /// and payload; a payload chunked purely against the raw
    /// `max_payload_size` budget (no cipher awareness) would put a packet
    /// on the wire that overshoots the connection's own configured
    /// datagram budget once encrypted. `effective_max_payload_size` must
    /// already exclude it, for both the single-packet and fragmented paths.
    #[test]
    fn gcm_wire_packets_never_exceed_the_datagram_budget() {
        let (mut caller, _listener) = connected_pair();
        while caller.poll_output().unwrap().is_some() {}
        caller.crypto = Some(Box::new(
            CryptoContext::new_sender(
                "test_passphrase",
                KeyLength::Aes128,
                test_km_salt(),
                &[0x24; 16],
                CipherMode::Gcm,
            )
            .expect("valid sender crypto"),
        ));

        let limit = caller.effective_max_payload_size();
        assert_eq!(
            limit,
            caller.max_payload_size - GCM_TAG_LEN,
            "GCM must shrink the effective limit by exactly its tag"
        );

        // Exactly at the limit: the single-packet path accepts it, and the
        // resulting wire packet stays within the raw datagram budget.
        let payload = vec![0xEE; limit];
        caller
            .send(&payload, Timestamp::from_micros(300_000))
            .expect("payload at the effective limit is accepted");
        let ConnectionOutput::SendPacket(packet) =
            caller.poll_output().unwrap().expect("one packet")
        else {
            panic!("expected a data packet");
        };
        assert!(
            packet.len() <= caller.max_payload_size + SRT_HEADER_SIZE,
            "packet of {} bytes exceeds the {}-byte datagram budget",
            packet.len(),
            caller.max_payload_size + SRT_HEADER_SIZE
        );

        // One byte over: the single-packet path must reject outright, not
        // silently emit an oversized datagram.
        let oversized = vec![0xEE; limit + 1];
        let err = caller
            .send(&oversized, Timestamp::from_micros(300_001))
            .expect_err("one byte over the effective limit is rejected");
        assert!(err.reason.contains("exceeds"), "{}", err.reason);
        assert!(drain_datagrams(&mut caller).is_empty());

        // Fragmented path: a message spanning several chunks plus a
        // remainder must still keep every wire packet within budget.
        caller
            .send_message(&vec![0xEE; limit * 2 + 37], Timestamp::from_micros(300_002))
            .expect("fragmented message is accepted");
        let mut fragment_count = 0;
        while let Some(ConnectionOutput::SendPacket(packet)) = caller.poll_output().unwrap() {
            assert!(
                packet.len() <= caller.max_payload_size + SRT_HEADER_SIZE,
                "fragment of {} bytes exceeds the datagram budget",
                packet.len()
            );
            fragment_count += 1;
        }
        assert_eq!(fragment_count, 3, "two full chunks plus one remainder");
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
            while let Some(ConnectionOutput::SendPacket(packet)) = caller.poll_output().unwrap() {
                listener
                    .feed_recv_buf(&packet, now)
                    .expect("listener accepts packet");
            }
            while let Some(ConnectionOutput::SendPacket(packet)) = listener.poll_output().unwrap() {
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
        while conn.poll_output().unwrap().is_some() {}

        conn.send(b"data", Timestamp::from_micros(900_000))
            .expect("connected sender queues data");
        while conn.poll_output().unwrap().is_some() {}

        conn.handle_timer(TimerId::Keepalive, Timestamp::from_micros(1_500_000))
            .expect("keepalive timer succeeds");
        assert!(std::iter::from_fn(|| conn.poll_output().unwrap()).all(
            |output| !matches!(output, ConnectionOutput::SendPacket(packet) if matches!(SrtPacket::decode(&packet), Ok(SrtPacket::Control(ControlPacket { control_type: ControlType::Keepalive, .. }))))
        ));

        conn.handle_timer(TimerId::Keepalive, Timestamp::from_micros(1_900_000))
            .expect("keepalive timer succeeds");
        assert!(std::iter::from_fn(|| conn.poll_output().unwrap()).any(
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
        while conn.poll_output().unwrap().is_some() {}

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
        while conn.poll_output().unwrap().is_some() {}

        conn.disconnect(Timestamp::from_micros(0));
        assert_eq!(conn.state(), ConnectionState::Closing);
        assert!(
            std::iter::from_fn(|| conn.poll_output().unwrap()).any(|output| matches!(
                output,
                ConnectionOutput::SetTimer {
                    id: TimerId::Shutdown,
                    ..
                }
            ))
        );

        conn.handle_timer(TimerId::Shutdown, Timestamp::from_micros(1_000_000))
            .expect("shutdown retry succeeds");
        assert!(std::iter::from_fn(|| conn.poll_output().unwrap()).any(
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
            std::iter::from_fn(|| conn.poll_output().unwrap()).any(|output| matches!(
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
        while conn.poll_output().unwrap().is_some() {}
        conn.disconnect(Timestamp::from_micros(0));
        while conn.poll_output().unwrap().is_some() {}

        conn.handle_timer(
            TimerId::Shutdown,
            Timestamp::from_micros(SHUTDOWN_TIMEOUT_MICROS),
        )
        .expect("shutdown timeout succeeds");

        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(
            std::iter::from_fn(|| conn.poll_event()).any(|event| matches!(
                event,
                ConnectionEvent::Disconnected {
                    reason: DisconnectReason::ShutdownTimeout
                }
            ))
        );
    }

    #[test]
    fn disconnect_reason_is_typed_and_keeps_legacy_display_text() {
        assert!(matches!(
            DisconnectReason::from_message("peer shutdown"),
            DisconnectReason::PeerShutdown
        ));
        assert!(matches!(
            DisconnectReason::from_message("unexpected peer error"),
            DisconnectReason::ProtocolError(message) if message == "unexpected peer error"
        ));
        assert_eq!(
            DisconnectReason::ShutdownTimeout.to_string(),
            "shutdown timeout"
        );
    }

    #[test]
    fn duplicate_shutdowns_do_not_grow_terminal_event_queue() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        conn.set_state(ConnectionState::Connected);
        conn.handle_shutdown(Timestamp::default())
            .expect("first shutdown is accepted");
        let events_after_first = conn.event_queue.len();

        for _ in 0..100_000 {
            conn.handle_shutdown(Timestamp::default())
                .expect("duplicate shutdown is ignored");
        }

        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert_eq!(conn.event_queue.len(), events_after_first);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "cap-scale loop (MAX_EVENT_QUEUE_ACTIONS == MAX_FLOW_WINDOW + 64                   allocations); the fail-closed behavior is proven here at full scale                   outside Miri, and `queue_event` ownership is exercised by the rest of                   this module under Miri"
    )]
    fn event_queue_overflow_fails_closed_and_stays_bounded() {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        for _ in 0..=MAX_EVENT_QUEUE_ACTIONS {
            conn.queue_event(ConnectionEvent::Error("synthetic".to_string()));
        }

        assert!(conn.event_overflowed);
        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(conn.event_queue.len() <= MAX_EVENT_QUEUE_ACTIONS);
        assert!(
            conn.connect(Timestamp::default())
                .expect_err("event overflow is terminal")
                .reason
                .contains(EVENT_QUEUE_OVERFLOW_REASON)
        );

        let events_after_overflow = conn.event_queue.len();
        for _ in 0..128 {
            conn.queue_event(ConnectionEvent::Error("ignored".to_string()));
        }
        assert_eq!(conn.event_queue.len(), events_after_overflow);
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
            .unwrap()
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

    /// Raw ACK datagram with an explicit control-information field.
    ///
    /// `Some(available)` builds a 28-byte Full ACK carrying the receiver's
    /// free receive-buffer size; `None` builds the 4-byte Light ACK, which
    /// carries the cumulative position and nothing else.
    fn ack_datagram(dest_socket_id: u32, ack_seq: u32, available: Option<u32>) -> Vec<u8> {
        let mut control_info = Vec::new();
        write_u32(&mut control_info, ack_seq);
        let ack_number = match available {
            Some(available) => {
                write_u32(&mut control_info, 1_000); // RTT
                write_u32(&mut control_info, 100); // RTTVar
                write_u32(&mut control_info, available); // free receive buffer
                write_u32(&mut control_info, 0); // receiving rate
                write_u32(&mut control_info, 0); // link capacity
                write_u32(&mut control_info, 0); // receive rate
                1
            }
            None => 0,
        };
        let packet = ControlPacket {
            control_type: ControlType::Ack,
            subtype: 0,
            type_specific_info: ack_number,
            timestamp: 0,
            dest_socket_id,
            control_info,
        };
        let mut buf = Vec::new();
        packet.encode(&mut buf).expect("ACK encodes");
        buf
    }

    /// Wire ACK with an explicit CIF length and ACK number, for exercising
    /// the bounded set of shapes `validate_ack_shape` accepts (and rejects).
    fn ack_datagram_with_shape(
        dest_socket_id: u32,
        ack_seq: u32,
        len: usize,
        ack_number: u32,
    ) -> Vec<u8> {
        assert!(len >= 4 && len.is_multiple_of(4));
        let mut control_info = Vec::with_capacity(len);
        write_u32(&mut control_info, ack_seq);
        let mut filler = 100u32;
        while control_info.len() < len {
            write_u32(&mut control_info, filler);
            filler += 1;
        }
        let packet = ControlPacket {
            control_type: ControlType::Ack,
            subtype: 0,
            type_specific_info: ack_number,
            timestamp: 0,
            dest_socket_id,
            control_info,
        };
        let mut buf = Vec::new();
        packet.encode(&mut buf).expect("ACK encodes");
        buf
    }

    /// Drain queued output until exactly one DATA datagram has materialized
    /// (skipping over any already-queued control/timer output ahead of it,
    /// such as the timers `setup_connection_timers` arms at connect), then
    /// stop -- leaving everything after it, including any further DATA,
    /// still queued and unsubmitted.
    fn drain_until_one_data_packet_submitted(conn: &mut SrtConnection) {
        loop {
            let output = conn
                .poll_output()
                .unwrap()
                .expect("a DATA packet is still queued to drain");
            if let ConnectionOutput::SendPacket(bytes) = &output
                && matches!(SrtPacket::decode(bytes), Ok(SrtPacket::Data(_)))
            {
                return;
            }
        }
    }

    /// #118 established that "accepted" and "submitted" are different
    /// sender states: a peer cannot legitimately acknowledge DATA still
    /// sitting behind this sender's own TX capacity. The *accepted*
    /// frontier (`next_sequence_number`) is therefore the wrong bound for
    /// what a peer's ACK may name -- only `max_justified_ack_position`
    /// (derived from actual first-transmission submission) is.
    #[test]
    fn ack_beyond_the_submitted_frontier_is_rejected_even_though_accepted() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);
        let first = caller.next_sequence_number().expect("connected sender");

        for i in 0..4 {
            caller
                .send(format!("payload {i}").as_bytes(), now)
                .expect("the window is open");
        }
        // Materialize only the first of the four accepted packets: the
        // other three are accepted but never actually left the protocol.
        drain_until_one_data_packet_submitted(&mut caller);

        let baseline = caller.stats();
        let last_recv_before = caller.last_recv_time;
        let over_frontier = first.wrapping_add(4); // everything accepted
        let error = caller
            .feed_recv_buf(&ack_datagram(socket_id, over_frontier, Some(8)), now)
            .expect_err("an ACK beyond the submitted frontier is rejected");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(
            caller.last_recv_time, last_recv_before,
            "rejected input must not refresh peer liveness"
        );
        assert_eq!(caller.stats(), baseline, "rejected input changed state");

        // Exactly what was actually submitted is legitimate.
        let at_frontier = first.wrapping_add(1);
        caller
            .feed_recv_buf(&ack_datagram(socket_id, at_frontier, Some(8)), now)
            .expect("an ACK at the submitted frontier is accepted");
        assert_eq!(
            caller.sender.as_ref().unwrap().oldest_unacked_sequence(),
            at_frontier
        );
    }

    /// A NAK loss position beyond the submitted frontier is invalid for
    /// exactly the same reason an ACK beyond it is (see
    /// `ack_beyond_the_submitted_frontier_is_rejected_even_though_accepted`):
    /// a peer cannot have observed the loss of DATA that never left the
    /// protocol.
    #[test]
    fn nak_beyond_the_submitted_frontier_is_rejected_even_though_accepted() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);
        let first = caller.next_sequence_number().expect("connected sender");

        for i in 0..4 {
            caller
                .send(format!("payload {i}").as_bytes(), now)
                .expect("the window is open");
        }
        drain_until_one_data_packet_submitted(&mut caller);

        let baseline = caller.stats();
        let unsubmitted = first.wrapping_add(2);
        let error = caller
            .feed_recv_buf(&nak_datagram(socket_id, &[unsubmitted, unsubmitted]), now)
            .expect_err("a NAK naming an unsubmitted position is rejected");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(caller.stats(), baseline, "rejected input changed state");
    }

    #[test]
    fn ack_sequence_with_high_bit_set_is_rejected() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);
        let baseline = caller.stats();
        let last_recv_before = caller.last_recv_time;

        let hostile = ack_datagram(socket_id, 0x8000_0001, None);
        let error = caller
            .feed_recv_buf(&hostile, now)
            .expect_err("an ACK sequence word with its high bit set is rejected");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(caller.last_recv_time, last_recv_before);
        assert_eq!(caller.stats(), baseline);
    }

    /// The pinned Haivision reference (`899348d8`, `core.cpp`'s
    /// `CUDT::sendCtrl`/`processCtrlAck`) accepts a bounded set of ACK sizes
    /// wider than the draft's own three canonical ones, each with its own
    /// ACK-number rule -- see `validate_ack_shape`'s doc comment.
    #[test]
    fn ack_accepts_the_reference_compatible_size_set_and_rejects_others() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);

        // Accepted: Light (4, TSI 0), both Small forms (16, TSI 0 or
        // nonzero), and every reference-Full size (24/28/32, TSI nonzero).
        for &(len, ack_number) in &[(4usize, 0u32), (16, 0), (16, 7), (24, 7), (28, 7), (32, 7)] {
            let ack_seq = caller.sender.as_ref().unwrap().oldest_unacked_sequence();
            caller
                .feed_recv_buf(
                    &ack_datagram_with_shape(socket_id, ack_seq, len, ack_number),
                    now,
                )
                .unwrap_or_else(|err| {
                    panic!("a {len}-byte ACK (ACK number {ack_number}) must be accepted: {err}")
                });
        }

        // Rejected: neither the draft's three canonical sizes nor
        // Haivision's wider bounded set names these lengths.
        for &len in &[8usize, 12, 20, 36] {
            let ack_seq = caller.sender.as_ref().unwrap().oldest_unacked_sequence();
            let error = caller
                .feed_recv_buf(&ack_datagram_with_shape(socket_id, ack_seq, len, 1), now)
                .expect_err("a non-canonical ACK length must be rejected");
            assert_eq!(
                error.kind,
                crate::error::ErrorKind::InvalidData,
                "{len}-byte ACK"
            );
        }

        // A Light ACK must never carry an ACK number, and every
        // reference-Full size must always carry one.
        let ack_seq = caller.sender.as_ref().unwrap().oldest_unacked_sequence();
        let error = caller
            .feed_recv_buf(&ack_datagram_with_shape(socket_id, ack_seq, 4, 1), now)
            .expect_err("a Light ACK must not carry an ACK number");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        let error = caller
            .feed_recv_buf(&ack_datagram_with_shape(socket_id, ack_seq, 24, 0), now)
            .expect_err("a 24-byte ACK must carry a nonzero ACK number");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
    }

    /// Haivision's deployed numbered Small ACK (16 bytes, nonzero ACK
    /// number) is acknowledged with ACKACK exactly like a Full ACK is;
    /// Robotweax pins a regression for this exact variant.
    #[test]
    fn numbered_small_ack_is_accepted_and_acknowledged_with_ackack() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);
        let ack_seq = caller.sender.as_ref().unwrap().oldest_unacked_sequence();

        caller
            .feed_recv_buf(&ack_datagram_with_shape(socket_id, ack_seq, 16, 42), now)
            .expect("a numbered Small ACK is accepted");

        let ackack = drain_outputs(&mut caller).into_iter().find_map(|output| {
            let ConnectionOutput::SendPacket(bytes) = output else {
                return None;
            };
            match SrtPacket::decode(&bytes) {
                Ok(SrtPacket::Control(pkt)) if pkt.control_type == ControlType::AckAck => {
                    Some(pkt.type_specific_info)
                }
                _ => None,
            }
        });
        assert_eq!(
            ackack,
            Some(42),
            "the numbered Small ACK must be acknowledged with ACKACK naming its ACK number"
        );
    }

    /// The SRT encoding (and Robotweax) require a compact range's END word
    /// to have its high bit clear -- only the START word's high bit marks
    /// the range form. A wire-hostile NAK setting the high bit on both
    /// words must be rejected outright, not silently normalized (by masking
    /// the bit off) into a valid-looking range the peer never actually
    /// sent.
    #[test]
    fn nak_range_with_high_bit_set_on_the_end_word_is_rejected() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);
        let baseline = caller.stats();
        let last_recv_before = caller.last_recv_time;

        let mut control_info = Vec::new();
        write_u32(&mut control_info, 0x8000_0005);
        write_u32(&mut control_info, 0x8000_0007);
        let hostile = control_datagram(socket_id, ControlType::Nak, 0, 0, control_info);

        let error = caller
            .feed_recv_buf(&hostile, now)
            .expect_err("a NAK range whose end word has its high bit set is rejected");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(
            caller.last_recv_time, last_recv_before,
            "rejected input must not refresh peer liveness"
        );
        assert_eq!(caller.stats(), baseline, "rejected input changed state");
    }

    /// The mandated merge condition, end to end over the wire-format ACK
    /// path: a Light ACK must not overrun stale receive-window credit, and a
    /// stale Full ACK must not reopen a window the peer has closed.
    ///
    /// Numbers follow the reference policy (`ack_seq + advertised_free`,
    /// libsrt `processCtrlAck`, Robotweax `09c852b4`): with the receiver's
    /// window full, a Full ACK advertising zero closes new DATA; a stale Full
    /// ACK advertising a large window is ignored; a current Full ACK
    /// advertising four opens exactly four; and a Light ACK that advances
    /// the cumulative acknowledgement by two reopens nothing, because the
    /// boundary it advances toward is fixed.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "full caller/listener handshake plus the wire-ACK path; correctness is       \
                  proven at full scale outside Miri, and the sender-level window regressions \
                  in `srt_sender` cover the same model cheaply under Miri. Run in the       \
                  miri-extended scheduled job."
    )]
    fn light_ack_cannot_overrun_stale_receive_window_credit() {
        let (mut caller, _listener) = connected_pair();
        let now = Timestamp::from_micros(1_000_000);
        let socket_id = caller.socket_id();

        let initial = caller
            .sender
            .as_ref()
            .expect("connected caller has a sender")
            .oldest_unacked_sequence();
        for _ in 0..4 {
            caller
                .send(b"first flight", now)
                .expect("the window is open");
        }
        // An ACK can only justify what actually left the protocol for the
        // transport (#118's accepted/submitted distinction); drain so the
        // ACKs below name positions this sender has actually submitted.
        drain_outputs(&mut caller);
        let flight_end = caller
            .sender
            .as_ref()
            .expect("connected caller has a sender")
            .next_sequence_number();

        // The receiver is full and acknowledges the whole flight: zero free.
        caller
            .feed_recv_buf(&ack_datagram(socket_id, flight_end, Some(0)), now)
            .expect("a current Full ACK is accepted");
        assert_eq!(
            caller.sender.as_ref().unwrap().remaining_window_packets(),
            0
        );
        assert!(!caller.can_send());

        // A stale Full ACK advertising a huge free window must not reopen
        // what the current one closed.
        caller
            .feed_recv_buf(&ack_datagram(socket_id, initial, Some(u32::MAX)), now)
            .expect("a stale Full ACK is accepted and ignored");
        assert_eq!(
            caller.sender.as_ref().unwrap().remaining_window_packets(),
            0
        );
        assert!(!caller.can_send());

        // A current Full ACK advertising four opens exactly four packets.
        caller
            .feed_recv_buf(&ack_datagram(socket_id, flight_end, Some(4)), now)
            .expect("a current Full ACK is accepted");
        assert_eq!(
            caller.sender.as_ref().unwrap().remaining_window_packets(),
            4
        );
        for _ in 0..4 {
            caller.send(b"second flight", now).expect("admitted");
        }
        drain_outputs(&mut caller);
        assert!(!caller.can_send());

        // A Light ACK advances the cumulative ACK by two and advertises
        // nothing. Pre-fix the stale `4` advertisement was compared against
        // the flight of two this ACK left behind, admitting two packets the
        // receiver had never freed.
        let light_end = flight_end + 2;
        caller
            .feed_recv_buf(&ack_datagram(socket_id, light_end, None), now)
            .expect("a Light ACK is accepted");
        assert_eq!(caller.sender.as_ref().unwrap().packets_in_flight(), 2);
        assert_eq!(
            caller.sender.as_ref().unwrap().remaining_window_packets(),
            0
        );
        assert!(!caller.can_send());

        // Only a later Small/Full ACK reopens the window, and only by what
        // it advertises.
        caller
            .feed_recv_buf(&ack_datagram(socket_id, flight_end + 4, Some(2)), now)
            .expect("a current Full ACK is accepted");
        assert_eq!(
            caller.sender.as_ref().unwrap().remaining_window_packets(),
            2
        );
        caller.send(b"reopened", now).expect("admitted");
        caller.send(b"reopened", now).expect("admitted");
        assert!(!caller.can_send());
    }

    /// A receive window that closed to zero must reopen as soon as the
    /// application frees it, without waiting for more DATA from the peer.
    ///
    /// Reference behaviour: Robotweax main pins
    /// `control_timer_immediately_advertises_reopened_receive_window` and
    /// `session_reopens_a_full_receive_window_after_application_delivery`,
    /// and libsrt keeps the same `bNeedFullAck` exception for a freed
    /// receive buffer (`srtcore/core.cpp`, `sendCtrl(UMSG_ACK)`).
    #[test]
    fn a_reopened_receive_window_is_advertised_without_more_data() {
        const WINDOW: u32 = 32;
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            flow_window_packets: WINDOW,
            receive_buffer_packets: WINDOW,
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

        // Fill the receive window: one packet reaches the application queue,
        // the rest stay protocol-side and consume the advertised window.
        for sequence_number in 0..WINDOW {
            conn.handle_data_packet(
                DataPacket::new(sequence_number, sequence_number, 0, 0, vec![1].into()),
                now,
            )
            .expect("data is accepted");
        }
        let expected_seq = conn.receiver.as_ref().unwrap().expected_sequence();

        // Advertise the closed window: a Full ACK carrying zero free space.
        conn.handle_timer(TimerId::Ack, now).expect("ACK tick");
        let closed = drain_acks(&mut conn);
        assert_eq!(closed.len(), 1, "one ACK is emitted for the closed window");
        assert_eq!(full_ack_available(&closed[0]), Some(0));

        // The application consumes the one delivered item. Nothing arrives
        // from the peer afterwards: the reopen has to be advertised on its
        // own.
        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::DataReceived { .. })
        ));
        assert_eq!(
            conn.receiver.as_ref().unwrap().expected_sequence(),
            expected_seq,
            "application capacity must not fabricate delivery progress"
        );
        assert!(
            conn.receive_window_reopen_pending,
            "a zero->positive window change must be marked urgent"
        );
        assert!(
            conn.output_queue.iter().any(|output| matches!(
                output,
                QueuedOutput::SetTimer {
                    id: TimerId::Ack,
                    duration_micros: 0
                }
            )),
            "the reopen must schedule an immediate Ack deadline"
        );

        conn.handle_timer(TimerId::Ack, now.add_micros(1))
            .expect("ACK tick");
        let reopened = drain_acks(&mut conn);
        assert_eq!(reopened.len(), 1, "the reopen emits exactly one ACK");
        // One slot freed by the application, and only one: the other 31
        // packets still occupy the window, and moving one of them into the
        // application queue transfers occupancy rather than freeing it.
        assert_eq!(
            full_ack_available(&reopened[0]),
            Some(1),
            "the reopened window is advertised as a Full ACK"
        );
        assert!(!conn.receive_window_reopen_pending);
    }

    /// Several application releases before the next service visit must
    /// produce one urgent advertisement, not one per release.
    #[test]
    fn a_burst_of_application_releases_coalesces_into_one_urgent_ack() {
        const WINDOW: u32 = 32;
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            flow_window_packets: WINDOW,
            receive_buffer_packets: WINDOW,
            delivery_queue_packets: 4,
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

        for sequence_number in 0..WINDOW {
            conn.handle_data_packet(
                DataPacket::new(sequence_number, sequence_number, 0, 0, vec![1].into()),
                now,
            )
            .expect("data is accepted");
        }
        conn.handle_timer(TimerId::Ack, now).expect("ACK tick");
        let closed = drain_acks(&mut conn);
        assert_eq!(full_ack_available(&closed[0]), Some(0));

        for _ in 0..4 {
            assert!(matches!(
                conn.poll_event(),
                Some(ConnectionEvent::DataReceived { .. })
            ));
        }
        let urgent_deadlines = conn
            .output_queue
            .iter()
            .filter(|output| {
                matches!(
                    output,
                    QueuedOutput::SetTimer {
                        id: TimerId::Ack,
                        duration_micros: 0
                    }
                )
            })
            .count();
        assert_eq!(urgent_deadlines, 1, "four releases must coalesce into one");

        conn.handle_timer(TimerId::Ack, now.add_micros(1))
            .expect("ACK tick");
        let reopened = drain_acks(&mut conn);
        assert_eq!(reopened.len(), 1, "the coalesced reopen sends one ACK");
        assert_eq!(full_ack_available(&reopened[0]), Some(4));
    }

    /// Every Full ACK among the connection's pending outputs, as wire bytes.
    fn drain_acks(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
        let mut acks = Vec::new();
        while let Some(output) = conn.poll_output().expect("output materializes") {
            let ConnectionOutput::SendPacket(bytes) = output else {
                continue;
            };
            if let Ok(SrtPacket::Control(packet)) = SrtPacket::decode(&bytes)
                && packet.control_type == ControlType::Ack
            {
                acks.push(bytes);
            }
        }
        acks
    }

    /// The available-buffer field of a Full ACK, or `None` for a Light ACK.
    fn full_ack_available(datagram: &[u8]) -> Option<u32> {
        let Ok(SrtPacket::Control(packet)) = SrtPacket::decode(datagram) else {
            panic!("an ACK datagram decodes as a control packet");
        };
        (packet.control_info.len() >= 16).then(|| {
            u32::from_be_bytes([
                packet.control_info[12],
                packet.control_info[13],
                packet.control_info[14],
                packet.control_info[15],
            ])
        })
    }

    /// Raw control datagram with an explicit type and information field.
    fn control_datagram(
        dest_socket_id: u32,
        control_type: ControlType,
        subtype: u16,
        type_specific_info: u32,
        control_info: Vec<u8>,
    ) -> Vec<u8> {
        let packet = ControlPacket {
            control_type,
            subtype,
            type_specific_info,
            timestamp: 0,
            dest_socket_id,
            control_info,
        };
        let mut buf = Vec::new();
        packet.encode(&mut buf).expect("control encodes");
        buf
    }

    /// A NAK whose named positions are all TLPKTDROP tombstones is answered
    /// with DROPREQ again -- never with DATA retransmission of released media.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "full caller/listener handshake; correctness is proven outside Miri, and the      \
                  sender-level tombstone regressions cover the same accounting cheaply        \
                  under Miri. Run in the miri-extended scheduled job."
    )]
    fn a_repeated_nak_for_a_dropped_message_is_answered_with_drop_req() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let sent = Timestamp::from_micros(1_000_000);
        for _ in 0..3 {
            caller.send(b"dropped", sent).expect("the window is open");
        }
        let mut sequences = Vec::new();
        while let Some(output) = caller.poll_output().expect("output materializes") {
            if let ConnectionOutput::SendPacket(bytes) = output
                && let Ok(SrtPacket::Data(packet)) = SrtPacket::decode(&bytes)
            {
                sequences.push(packet.sequence_number);
            }
        }
        assert_eq!(sequences.len(), 3, "one datagram per message");

        // Nothing is acknowledged, so TLPKTDROP gives each message up.
        let expired = sent.add_micros(1_000_001);
        caller
            .handle_timer(TimerId::Ack, expired)
            .expect("ACK tick");
        let first = drain_drop_requests(&mut caller);
        assert_eq!(first.len(), 3, "one DROPREQ per dropped message");

        // The peer NAKs one of the dropped sequences: it lost the DROPREQ, or
        // has not retired the range yet.
        caller
            .feed_recv_buf(
                &nak_datagram(socket_id, &[sequences[1], sequences[1]]),
                expired,
            )
            .expect("the loss report is accepted");
        let repeated = drain_drop_requests(&mut caller);
        assert_eq!(repeated.len(), 1, "DROPREQ is sent again");
        assert_eq!(repeated[0], (sequences[1], sequences[1]));

        // And nothing was retransmitted as DATA.
        let mut retransmitted = Vec::new();
        while let Some(output) = caller.poll_output().expect("output materializes") {
            if let ConnectionOutput::SendPacket(bytes) = output
                && let Ok(SrtPacket::Data(packet)) = SrtPacket::decode(&bytes)
                && packet.retransmitted
            {
                retransmitted.push(packet.sequence_number);
            }
        }
        assert!(
            retransmitted.is_empty(),
            "a tombstone must never be DATA-retransmitted: {retransmitted:?}"
        );
    }

    /// Wire NAK with a compact loss list of inclusive ranges.
    fn nak_datagram(dest_socket_id: u32, ranges: &[u32]) -> Vec<u8> {
        assert!(ranges.len().is_multiple_of(2), "pairs of (start, end)");
        let mut control_info = Vec::new();
        for pair in ranges.chunks(2) {
            encode_loss_range(&mut control_info, pair[0], pair[1]);
        }
        control_datagram(dest_socket_id, ControlType::Nak, 0, 0, control_info)
    }

    /// Decode every DROPREQ the connection has queued, as (first, last).
    fn drain_drop_requests(conn: &mut SrtConnection) -> Vec<(u32, u32)> {
        let mut requests = Vec::new();
        while let Some(output) = conn.poll_output().expect("output materializes") {
            let ConnectionOutput::SendPacket(bytes) = output else {
                continue;
            };
            let Ok(SrtPacket::Control(packet)) = SrtPacket::decode(&bytes) else {
                continue;
            };
            if packet.control_type != ControlType::DropReq {
                continue;
            }
            let mut cif = packet.control_info.as_slice();
            let first = read_u32(&mut cif).expect("DROPREQ carries its range");
            let last = read_u32(&mut cif).expect("DROPREQ carries its range");
            requests.push((first, last));
        }
        requests
    }

    /// Sequence numbers of every retransmitted DATA datagram in `outputs`.
    fn retransmitted_sequences(outputs: &[ConnectionOutput]) -> Vec<u32> {
        outputs
            .iter()
            .filter_map(|output| {
                let ConnectionOutput::SendPacket(bytes) = output else {
                    return None;
                };
                match SrtPacket::decode(bytes) {
                    Ok(SrtPacket::Data(pkt)) if pkt.retransmitted => Some(pkt.sequence_number),
                    _ => None,
                }
            })
            .collect()
    }

    /// Sequence numbers of every DATA datagram (first transmission or
    /// retransmission) in `outputs`.
    fn all_data_sequences(outputs: &[ConnectionOutput]) -> Vec<u32> {
        outputs
            .iter()
            .filter_map(|output| {
                let ConnectionOutput::SendPacket(bytes) = output else {
                    return None;
                };
                match SrtPacket::decode(bytes) {
                    Ok(SrtPacket::Data(pkt)) => Some(pkt.sequence_number),
                    _ => None,
                }
            })
            .collect()
    }

    /// Every DROPREQ range's (first, last) in `outputs`.
    fn drop_requests_in(outputs: &[ConnectionOutput]) -> Vec<(u32, u32)> {
        outputs
            .iter()
            .filter_map(|output| {
                let ConnectionOutput::SendPacket(bytes) = output else {
                    return None;
                };
                let Ok(SrtPacket::Control(pkt)) = SrtPacket::decode(bytes) else {
                    return None;
                };
                if pkt.control_type != ControlType::DropReq {
                    return None;
                }
                let mut cif = pkt.control_info.as_slice();
                let first = read_u32(&mut cif).ok()?;
                let last = read_u32(&mut cif).ok()?;
                Some((first, last))
            })
            .collect()
    }

    /// A DATA datagram accepted into `SenderBuffer` but never drained can sit
    /// queued behind blocked TX capacity indefinitely. If TLPKTDROP
    /// tombstones that position before it is ever materialized, the queued
    /// datagram must never reach the transport -- only the DROPREQ that
    /// supersedes it should.
    #[test]
    fn unsubmitted_queued_data_that_expires_never_materializes() {
        let (mut caller, _listener) = connected_pair();
        let now = Timestamp::from_micros(0);
        let first = caller.next_sequence_number().expect("connected sender");

        caller
            .send(b"never leaves the queue", now)
            .expect("accepted");
        // Deliberately never drain: this DATA datagram sits queued,
        // unsubmitted, when it expires below.

        let expired = now.add_micros(1_000_001); // past the 1s TLPKTDROP floor
        caller
            .handle_timer(TimerId::Ack, expired)
            .expect("ACK tick");

        let outputs = drain_outputs(&mut caller);
        assert_eq!(
            drop_requests_in(&outputs),
            vec![(first, first)],
            "the tombstone's DROPREQ must still go out"
        );
        assert!(
            all_data_sequences(&outputs).is_empty(),
            "the tombstoned, never-submitted position must never leave as DATA"
        );
    }

    /// Once TLPKTDROP has tombstoned every submitted entry, the RTO timer
    /// must stop rather than keep probing a flight that no longer exists.
    #[test]
    fn submitted_data_that_expires_never_gets_a_blind_rto_probe() {
        let (mut caller, _listener) = connected_pair();
        let now = Timestamp::from_micros(0);

        caller
            .send(b"submitted then expires", now)
            .expect("accepted");
        drain_until_one_data_packet_submitted(&mut caller);
        let _ = drain_outputs(&mut caller); // whatever SetTimer that submission armed

        let expired = now.add_micros(1_000_001);
        caller
            .handle_timer(TimerId::Ack, expired)
            .expect("ACK tick");

        let cleared_rto = drain_outputs(&mut caller).into_iter().any(|output| {
            matches!(
                output,
                ConnectionOutput::ClearTimer {
                    id: TimerId::SenderRto
                }
            )
        });
        assert!(
            cleared_rto,
            "the RTO timer must be cleared once nothing live remains submitted"
        );

        // Even a stray fire of the timeout (e.g. one already in flight
        // before it was cleared) must not blindly probe the tombstone.
        caller
            .handle_timer(TimerId::SenderRto, expired.add_micros(10_000_000))
            .expect("RTO tick");
        assert!(
            retransmitted_sequences(&drain_outputs(&mut caller)).is_empty(),
            "a tombstoned position must never receive a blind RTO probe"
        );
    }

    /// A retransmission a NAK just queued can still be sitting in the
    /// output queue, undrained, when TLPKTDROP tombstones the same message
    /// out from under it. The queued retransmission must be suppressed, not
    /// sent -- exactly like an ordinary first transmission in the same
    /// position (see `unsubmitted_queued_data_that_expires_never_materializes`).
    #[test]
    fn a_queued_retransmission_that_becomes_tombstoned_before_materializing_is_suppressed() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(0);
        let first = caller.next_sequence_number().expect("connected sender");

        for i in 0..3 {
            caller
                .send(format!("payload {i}").as_bytes(), now)
                .expect("accepted");
        }
        while caller.poll_output().unwrap().is_some() {}

        // The peer NAKs the first packet: a retransmission is queued but not
        // yet drained.
        caller
            .feed_recv_buf(&nak_datagram(socket_id, &[first, first]), now)
            .expect("the loss report is accepted");

        // Before it materializes, the whole flight ages past the TLPKTDROP
        // threshold.
        let expired = now.add_micros(1_000_001);
        caller
            .handle_timer(TimerId::Ack, expired)
            .expect("ACK tick");

        let outputs = drain_outputs(&mut caller);
        assert!(
            retransmitted_sequences(&outputs).is_empty(),
            "a tombstone must never be DATA-retransmitted"
        );
        assert!(
            !drop_requests_in(&outputs).is_empty(),
            "DROPREQ must be emitted for the tombstoned message instead"
        );
    }

    /// A crypto reservation counted when an encrypted DATA datagram was
    /// queued must be released when that datagram is discarded as stale
    /// (TLPKTDROP tombstoning it before it ever materializes) -- not only
    /// when it actually leaves the protocol.
    #[test]
    fn crypto_reservation_returns_when_a_stale_queued_datagram_is_discarded() {
        use crate::crypto::CipherMode;

        let (mut caller, _listener) = encrypted_pair(CipherMode::Gcm);
        let now = Timestamp::from_micros(0);

        caller
            .send(b"never leaves, encrypted", now)
            .expect("accepted");
        // Deliberately never drain: the crypto reservation this queued
        // datagram holds is still outstanding.
        assert_eq!(
            caller.pending_tx_even + caller.pending_tx_odd,
            1,
            "queuing an encrypted DATA datagram reserves its key generation"
        );

        let expired = now.add_micros(1_000_001);
        caller
            .handle_timer(TimerId::Ack, expired)
            .expect("ACK tick");

        assert_eq!(
            caller.pending_tx_even + caller.pending_tx_odd,
            0,
            "the reservation must be released when the stale queued datagram is discarded"
        );
    }

    /// Malformed or hostile control input is rejected *before* it can refresh
    /// peer activity or touch connection state.
    ///
    /// This is the invariant Robotweax 0.2.2 pins with
    /// `compat_runtime_rejects_malformed_controls_without_refreshing_liveness`,
    /// reached here through the real wire decoder rather than by calling the
    /// handlers directly. Also covers ACK/NAK payloads that are well-formed
    /// but semantically impossible (a non-canonical ACK length, or a
    /// cumulative/loss position beyond what this sender has ever
    /// transmitted): those are rejected by the handlers themselves, not by
    /// shape validation, but must leave exactly the same zero footprint.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "full caller/listener handshake plus sixteen malformed controls; correctness  \
                  is proven outside Miri. Run in the miri-extended scheduled job."
    )]
    fn malformed_controls_cannot_refresh_liveness_or_state() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(5_000_000);

        // Positive control: a canonical KEEPALIVE (one zero word, exactly what
        // libsrt's `CPacket::pack` writes and what this crate emits) is peer
        // activity, so the assertions below are not vacuous.
        caller
            .feed_recv_buf(
                &control_datagram(socket_id, ControlType::Keepalive, 0, 0, vec![0; 4]),
                now,
            )
            .expect("a canonical KEEPALIVE is accepted");
        assert_eq!(caller.last_recv_time, Some(now));

        let unaligned_ack = vec![0u8; 6];
        let non_canonical_ack_length = {
            let mut cif = Vec::new();
            write_u32(&mut cif, 0);
            write_u32(&mut cif, 0);
            cif
        };
        let nak_range_without_end = vec![0x80, 0, 0, 0];
        let drop_req_high_bit = {
            let mut cif = Vec::new();
            write_u32(&mut cif, 0x8000_0001);
            write_u32(&mut cif, 1);
            cif
        };
        // Beyond everything this sender has ever put on the wire: a position
        // no peer could legitimately report, in either an ACK's cumulative
        // position or a NAK's loss list.
        let beyond_frontier = caller
            .next_sequence_number()
            .expect("connected sender")
            .wrapping_add(1_000)
            & 0x7FFF_FFFF;
        let future_ack = {
            let mut cif = Vec::new();
            write_u32(&mut cif, beyond_frontier);
            cif
        };
        let malformed: Vec<(&str, Vec<u8>)> = vec![
            (
                "ACK without a cumulative position",
                control_datagram(socket_id, ControlType::Ack, 0, 0, Vec::new()),
            ),
            (
                "ACK with a non-canonical (non 4/16/28-byte) length",
                control_datagram(socket_id, ControlType::Ack, 0, 0, non_canonical_ack_length),
            ),
            (
                "ACK naming a sequence beyond the sender's transmitted frontier",
                control_datagram(socket_id, ControlType::Ack, 0, 0, future_ack),
            ),
            (
                "NAK naming a sequence this sender never sent",
                nak_datagram(socket_id, &[beyond_frontier, beyond_frontier]),
            ),
            (
                "ACK with an unaligned cumulative position",
                control_datagram(socket_id, ControlType::Ack, 0, 0, unaligned_ack),
            ),
            (
                "NAK without a loss range",
                control_datagram(socket_id, ControlType::Nak, 0, 0, Vec::new()),
            ),
            (
                "NAK with an unaligned loss range",
                control_datagram(socket_id, ControlType::Nak, 0, 0, vec![0, 0, 0]),
            ),
            (
                "NAK range missing its end",
                control_datagram(socket_id, ControlType::Nak, 0, 0, nak_range_without_end),
            ),
            (
                "ACKACK naming an ACK that was never sent",
                control_datagram(socket_id, ControlType::AckAck, 0, 99_999, vec![0; 4]),
            ),
            (
                "ACKACK carrying the zero ACK number",
                control_datagram(socket_id, ControlType::AckAck, 0, 0, vec![0; 4]),
            ),
            (
                "ACKACK with a surplus word",
                control_datagram(socket_id, ControlType::AckAck, 0, 1, vec![0; 8]),
            ),
            (
                "KEEPALIVE carrying an argument",
                control_datagram(socket_id, ControlType::Keepalive, 0, 0, vec![1, 0, 0, 0]),
            ),
            (
                "SHUTDOWN carrying an argument",
                control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![1, 0, 0, 0]),
            ),
            (
                "SHUTDOWN with a surplus word",
                control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 8]),
            ),
            (
                "DROPREQ without two sequence words",
                control_datagram(socket_id, ControlType::DropReq, 0, 0, vec![0; 4]),
            ),
            (
                "DROPREQ with a sequence high bit set",
                control_datagram(socket_id, ControlType::DropReq, 0, 0, drop_req_high_bit),
            ),
            (
                "key-management request with an unaligned body",
                control_datagram(
                    socket_id,
                    ControlType::UserDefined,
                    SRT_CMD_KMREQ,
                    0,
                    vec![0; 3],
                ),
            ),
            (
                "key-management request with a truncated body",
                control_datagram(
                    socket_id,
                    ControlType::UserDefined,
                    SRT_CMD_KMREQ,
                    0,
                    vec![0; 4],
                ),
            ),
            (
                "key-management response with a truncated body",
                control_datagram(
                    socket_id,
                    ControlType::UserDefined,
                    SRT_CMD_KMRSP,
                    0,
                    vec![0; 4],
                ),
            ),
        ];

        let baseline = caller.stats();
        let later = now.add_micros(1_000);
        for (label, datagram) in malformed {
            let error = caller
                .feed_recv_buf(&datagram, later)
                .expect_err("malformed control input is rejected");
            assert_eq!(error.kind, crate::error::ErrorKind::InvalidData, "{label}");
            assert_eq!(
                caller.last_recv_time,
                Some(now),
                "{label}: rejected input must not refresh peer liveness"
            );
            assert_eq!(
                caller.stats(),
                baseline,
                "{label}: rejected input changed state"
            );
            assert_eq!(caller.state(), ConnectionState::Connected, "{label}");
        }

        // A well-formed SHUTDOWN is still accepted afterwards, and it is the
        // one control whose acceptance changes state: the negative cases
        // above must not have poisoned the connection.
        caller
            .feed_recv_buf(
                &control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]),
                later,
            )
            .expect("a canonical SHUTDOWN is accepted");
    }

    /// An authenticated DATA packet whose tag or key selector does not verify
    /// is rejected before it can refresh liveness or advance reliability.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "encrypted handshake plus AES-GCM authentication under Miri; correctness is   \
                  proven outside Miri (crypto ownership is covered by the `crypto` module     \
                  tests). Run in the miri-extended scheduled job."
    )]
    fn undecryptable_data_cannot_refresh_liveness_or_advance_reliability() {
        use crate::crypto::CipherMode;

        let (mut caller, mut listener) = encrypted_pair(CipherMode::Gcm);
        let now = Timestamp::from_micros(9_000_000);
        let datagram = capture_data_datagram(&mut caller, b"authenticated payload", now);

        // Liveness baseline from a well-formed packet on the same path.
        listener
            .feed_recv_buf(
                &control_datagram(2, ControlType::Keepalive, 0, 0, vec![0; 4]),
                now,
            )
            .expect("a canonical KEEPALIVE is accepted");
        assert_eq!(listener.last_recv_time, Some(now));
        let before = listener.receiver_stats().expect("receiver stats");

        // Corrupt the GCM tag: the ciphertext still decrypts structurally,
        // only authentication fails.
        let mut bad_tag = datagram.clone();
        *bad_tag.last_mut().expect("a datagram has a tag") ^= 0xFF;
        assert_crypto_rejected(&mut listener, &bad_tag, now);

        // An invalid key selector is equally rejected: `0` would claim the
        // packet is unencrypted on an encrypted connection and `3` is not a
        // valid KK field.
        for flag in [0u8, 3u8] {
            assert_crypto_rejected(&mut listener, &with_key_selector(&datagram, flag), now);
        }

        assert_eq!(
            listener.last_recv_time,
            Some(now),
            "rejected DATA must not refresh peer liveness"
        );
        let after = listener.receiver_stats().expect("receiver stats");
        assert_eq!(after.total_received, before.total_received);
        assert_eq!(after.packets_in_buffer, before.packets_in_buffer);
        assert_eq!(
            after.total_srt_bytes_received,
            before.total_srt_bytes_received
        );
        assert_eq!(listener.state(), ConnectionState::Connected);

        // Positive control: the untampered datagram is accepted, so the
        // rejections above are not an artifact of the fixture.
        listener
            .feed_recv_buf(&datagram, now)
            .expect("the authentic datagram is accepted");
        assert_eq!(
            listener
                .receiver_stats()
                .expect("receiver stats")
                .total_received,
            before.total_received + 1
        );
    }

    /// A connected encrypted pair sharing one passphrase.
    fn encrypted_pair(cipher_mode: CipherMode) -> (SrtConnection, SrtConnection) {
        let sek = vec![0x5Au8; 16];
        let options = |socket_id: u32| ConnectionOptions {
            socket_id,
            passphrase: Some("shared-secret".to_owned()),
            crypto_salt: Some(test_km_salt()),
            crypto_sek: Some(sek.clone()),
            cipher_mode,
            ..ConnectionOptions::default()
        };
        let mut caller = SrtConnection::new_caller(options(1));
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            syn_cookie: Some(7),
            ..options(2)
        });
        drive_handshake_to_connected(&mut caller, &mut listener);
        (caller, listener)
    }

    /// Send one payload and return the DATA datagram the caller put on the
    /// wire for it.
    fn capture_data_datagram(
        caller: &mut SrtConnection,
        payload: &[u8],
        now: Timestamp,
    ) -> Vec<u8> {
        caller.send(payload, now).expect("send");
        let mut datagram = None;
        while let Some(output) = caller.poll_output().expect("output materializes") {
            if let ConnectionOutput::SendPacket(bytes) = output
                && matches!(SrtPacket::decode(&bytes), Ok(SrtPacket::Data(_)))
            {
                datagram = Some(bytes);
            }
        }
        datagram.expect("the payload produced one DATA datagram")
    }

    /// The same datagram with its key-selector field replaced, keeping the
    /// rest of the header intact.
    fn with_key_selector(datagram: &[u8], flag: u8) -> Vec<u8> {
        let mut corrupted = datagram.to_vec();
        // The encryption flag occupies bits 3-4 of byte 4 (`srt_packet`'s
        // header packing: `encryption_flag & 0b11 << 27` of the second word).
        corrupted[4] = (corrupted[4] & !(0b11 << 3)) | (flag << 3);
        match SrtPacket::decode(&corrupted) {
            Ok(SrtPacket::Data(packet)) => assert_eq!(
                packet.encryption_flag, flag,
                "the test corrupts the key selector field"
            ),
            other => panic!("the corrupted datagram must still decode: {other:?}"),
        }
        corrupted
    }

    /// Assert the datagram is rejected as a crypto error and changes nothing.
    fn assert_crypto_rejected(listener: &mut SrtConnection, datagram: &[u8], now: Timestamp) {
        let error = listener
            .feed_recv_buf(datagram, now)
            .expect_err("an unauthenticated DATA body is rejected");
        assert_eq!(error.kind, crate::error::ErrorKind::CryptoError);
    }

    /// A hand-built connected listener with live-mode TSBPD negotiated, a
    /// receive clock that starts at zero, and an optional TLPKTDROP.
    fn tsbpd_listener(
        tsbpd_delay: u16,
        tlpktdrop: bool,
        delivery_queue_packets: u32,
    ) -> SrtConnection {
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay,
            flow_window_packets: 32,
            receive_buffer_packets: 32,
            delivery_queue_packets,
            ..ConnectionOptions::default()
        });
        let mut peer_flags = srt_flags::TSBPDSND;
        if tlpktdrop {
            peer_flags |= srt_flags::TLPKTDROP;
        }
        conn.peer_srt_flags = Some(peer_flags);
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        assert!(conn.tsbpd_enabled(), "the fixture must negotiate TSBPD");
        assert!(conn.tlpktdrop_enabled() == tlpktdrop);
        conn
    }

    /// Peer SHUTDOWN must not bypass or truncate buffered TSBPD delivery:
    /// data already accepted keeps its playout deadline, the terminal event
    /// waits for it, and a duplicate SHUTDOWN changes nothing.
    ///
    /// Reference behaviour: Robotweax 0.2.1 defers the peer-shutdown error
    /// until TSBPD-buffered input is drained, pinned by
    /// `compat_runtime_drains_tsbpd_message_after_peer_shutdown`.
    #[test]
    fn peer_shutdown_drains_tsbpd_data_before_the_terminal_event() {
        const DELAY_MS: u16 = 120;
        let mut conn = tsbpd_listener(DELAY_MS, false, 8);
        let socket_id = conn.options.socket_id;
        let shutdown = control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]);

        // One message, source timestamp 50 us, so its playout deadline is
        // 50 + 120_000 us on this connection's clock.
        let arrived = Timestamp::from_micros(2_000);
        conn.handle_data_packet(
            DataPacket::new(0, 1, 50, 0, b"srt".to_vec().into()),
            arrived,
        )
        .expect("DATA is accepted");
        assert_eq!(conn.pending_data_events, 0, "not due yet");

        conn.feed_recv_buf(&shutdown, arrived)
            .expect("the peer's SHUTDOWN is accepted");
        assert!(conn.peer_shutdown_pending);
        assert_eq!(conn.state(), ConnectionState::Connected, "still draining");
        assert!(conn.poll_event().is_none(), "no event before the deadline");

        // Duplicate SHUTDOWN: a peer retransmits until it sees an answer.
        conn.feed_recv_buf(&shutdown, arrived)
            .expect("a duplicate SHUTDOWN is accepted and ignored");
        assert!(conn.peer_shutdown_pending);

        // One microsecond before the deadline: nothing is released, and the
        // peer's close is not terminal yet.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(120_049))
            .expect("ACK tick");
        assert!(conn.poll_event().is_none(), "still before the deadline");
        assert_eq!(conn.state(), ConnectionState::Connected);

        // At the deadline the payload surfaces normally, and the terminal
        // event is queued *behind* it, never in front of it.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(120_050))
            .expect("ACK tick");
        assert_eq!(
            conn.state(),
            ConnectionState::Connected,
            "the terminal event must wait for the queued payload"
        );
        assert_delivered_payload(&mut conn, b"srt");

        // Draining the application queue completes the close: the state
        // change first, then exactly one terminal event.
        assert_peer_shutdown_terminal(&mut conn);
    }

    /// A configured TSBPD delay that exceeds the fixed inactivity timeout
    /// must not let the inactivity timer preempt it: SHUTDOWN arrives while
    /// data is still legitimately waiting for a playout deadline well past
    /// five seconds, and the connection must defer to that deadline rather
    /// than truncating the drain.
    #[test]
    fn inactivity_timeout_never_preempts_a_tsbpd_deadline_beyond_it() {
        const DELAY_MS: u16 = 8_000; // 8s, past the fixed 5s inactivity timeout.
        let mut conn = tsbpd_listener(DELAY_MS, false, 8);
        let socket_id = conn.options.socket_id;
        let arrived = Timestamp::from_micros(2_000);

        // One message, source timestamp 50 us, so its playout deadline is
        // 50 + 8_000_000 us = 8_000_050 on this connection's clock.
        conn.handle_data_packet(
            DataPacket::new(0, 1, 50, 0, b"srt".to_vec().into()),
            arrived,
        )
        .expect("DATA is accepted");

        conn.feed_recv_buf(
            &control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]),
            arrived,
        )
        .expect("the peer's SHUTDOWN is accepted");
        assert!(conn.peer_shutdown_pending);

        // The fixed inactivity timeout elapses (5s after the last received
        // packet) while the message's own deadline is still ~3s away. The
        // generic timeout must defer to it instead of truncating the drain.
        let inactivity_elapsed = Timestamp::from_micros(2_000 + 5_000_000);
        conn.handle_timer(TimerId::Inactivity, inactivity_elapsed)
            .expect("inactivity tick");
        assert_eq!(
            conn.state(),
            ConnectionState::Connected,
            "a valid TSBPD deadline beyond the inactivity timeout must not be truncated"
        );
        assert!(
            conn.poll_event().is_none(),
            "no terminal event before the message's own deadline"
        );

        // The rearmed inactivity timer must target the message's actual
        // deadline, not fire again immediately.
        let rearmed = drain_outputs(&mut conn).into_iter().find_map(|output| {
            if let ConnectionOutput::SetTimer {
                id: TimerId::Inactivity,
                duration_micros,
            } = output
            {
                Some(duration_micros)
            } else {
                None
            }
        });
        assert_eq!(
            rearmed,
            Some(8_000_050 - (2_000 + 5_000_000)),
            "the inactivity timer must be deferred to the pending TSBPD deadline"
        );

        // At its actual deadline the payload surfaces normally, and only
        // then does the peer close become terminal.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(8_000_050))
            .expect("ACK tick");
        assert_delivered_payload(&mut conn, b"srt");
        assert_peer_shutdown_terminal(&mut conn);
    }

    /// Two retained messages with different TSBPD deadlines must not be
    /// truncated by dispatch order: firing the inactivity timer exactly at
    /// the first message's deadline, before the periodic ACK timer has run,
    /// must still deliver it (a deadline landing exactly on this tick is
    /// not evidence of a stalled drain) and must still retain the second
    /// message until its own later deadline.
    #[test]
    fn inactivity_timer_services_due_deadlines_regardless_of_ack_timer_dispatch_order() {
        const DELAY_MS: u16 = 8_000; // 8s.
        let mut conn = tsbpd_listener(DELAY_MS, false, 8);
        let socket_id = conn.options.socket_id;
        let arrived = Timestamp::from_micros(2_000);

        // Message 1: deadline 50 + 8_000_000 = 8_000_050.
        conn.handle_data_packet(
            DataPacket::new(0, 1, 50, 0, b"first".to_vec().into()),
            arrived,
        )
        .expect("DATA is accepted");
        // Message 2: deadline 4_000_050 + 8_000_000 = 12_000_050 (a later
        // source timestamp under the same configured delay).
        conn.handle_data_packet(
            DataPacket::new(1, 2, 4_000_050, 0, b"second".to_vec().into()),
            arrived,
        )
        .expect("DATA is accepted");

        conn.feed_recv_buf(
            &control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]),
            arrived,
        )
        .expect("the peer's SHUTDOWN is accepted");
        assert!(conn.peer_shutdown_pending);

        // The 5s inactivity timeout fires first and defers to message 1's
        // still-future 8s deadline, exactly like the single-message case.
        conn.handle_timer(
            TimerId::Inactivity,
            Timestamp::from_micros(2_000 + 5_000_000),
        )
        .expect("inactivity tick");
        assert_eq!(conn.state(), ConnectionState::Connected);
        assert!(conn.poll_event().is_none());

        // Deliberately invoke the inactivity timer again exactly AT message
        // 1's deadline, simulating it winning dispatch order over the ACK
        // timer at that same instant. `earliest_pending_deadline` now
        // equals `now`, so a check of only `now < deadline` (without first
        // servicing what's due) would fall straight through to a forced
        // close with neither message ever delivered.
        conn.handle_timer(TimerId::Inactivity, Timestamp::from_micros(8_000_050))
            .expect("inactivity tick exactly at the first deadline");
        assert_eq!(
            conn.state(),
            ConnectionState::Connected,
            "a deadline landing exactly on this tick must be serviced, not treated as stalled"
        );
        assert_delivered_payload(&mut conn, b"first");
        assert!(
            conn.poll_event().is_none(),
            "the second message is not due yet"
        );

        // The second message's later deadline must still be honoured: the
        // connection must not have force-closed and lost it.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(12_000_050))
            .expect("ACK tick");
        assert_delivered_payload(&mut conn, b"second");
        assert_peer_shutdown_terminal(&mut conn);
    }

    /// Assert the next event is the payload the connection delivered.
    fn assert_delivered_payload(conn: &mut SrtConnection, expected: &[u8]) {
        let delivered = conn.poll_event().expect("the payload is delivered");
        assert!(
            matches!(&delivered, ConnectionEvent::DataReceived { payload, .. } if payload.as_ref() == expected),
            "the buffered payload must surface unchanged: {delivered:?}"
        );
    }

    /// Assert the connection closes with exactly one peer-shutdown terminal
    /// event, after the state change.
    fn assert_peer_shutdown_terminal(conn: &mut SrtConnection) {
        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::StateChanged(ConnectionState::Disconnected))
        ));
        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::Disconnected {
                reason: DisconnectReason::PeerShutdown
            })
        ));
        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(conn.poll_event().is_none(), "exactly one terminal event");
    }

    /// Every buffered deadline is honoured before the peer close becomes
    /// terminal, in order, even while the application queue is full.
    #[test]
    fn peer_shutdown_delivers_every_buffered_deadline_before_the_terminal_event() {
        let mut conn = tsbpd_listener(120, false, 1);
        let socket_id = conn.options.socket_id;
        let arrived = Timestamp::from_micros(2_000);

        for (sequence_number, timestamp) in [(0u32, 50u32), (1, 60), (2, 70)] {
            conn.handle_data_packet(
                DataPacket::new(
                    sequence_number,
                    sequence_number,
                    timestamp,
                    0,
                    vec![1].into(),
                ),
                arrived,
            )
            .expect("DATA is accepted");
        }
        conn.feed_recv_buf(
            &control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]),
            arrived,
        )
        .expect("the peer's SHUTDOWN is accepted");

        // All three deadlines have passed, but the application queue admits
        // one message at a time: the rest stay in the receiver, and the
        // drain waits for them.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(120_070))
            .expect("ACK tick");
        let first = conn.poll_event().expect("the first message is delivered");
        assert!(matches!(
            first,
            ConnectionEvent::DataReceived {
                sequence_number: 0,
                ..
            }
        ));
        assert_eq!(conn.state(), ConnectionState::Connected, "more to deliver");

        for (tick, sequence_number) in [(120_071, 1u32), (120_072, 2)] {
            conn.handle_timer(TimerId::Ack, Timestamp::from_micros(tick))
                .expect("ACK tick");
            let event = conn.poll_event().expect("the next message is delivered");
            assert!(
                matches!(
                    event,
                    ConnectionEvent::DataReceived {
                        sequence_number: expected,
                        ..
                    } if expected == sequence_number
                ),
                "messages must surface in order: {event:?}"
            );
        }
        // The last delivery completes the close.
        assert_peer_shutdown_terminal(&mut conn);
    }

    /// TLPKTDROP may legitimately retire a message the peer can no longer
    /// complete; the peer close is terminal once it has.
    #[test]
    fn tlpktdrop_retires_an_incomplete_message_before_the_terminal_event() {
        let mut conn = tsbpd_listener(120, true, 8);
        let socket_id = conn.options.socket_id;
        let arrived = Timestamp::from_micros(2_000);

        // First fragment of a two-fragment message; its partner (3_001) never
        // arrives, and a later message exposes that hole.
        let mut first = DataPacket::new(0, 7, 50, 0, b"frag".to_vec().into());
        first.position = crate::srt_packet::PacketPosition::First;
        conn.handle_data_packet(first, arrived)
            .expect("the first fragment is accepted");
        conn.handle_data_packet(
            DataPacket::new(2, 8, 60, 0, b"tail".to_vec().into()),
            arrived,
        )
        .expect("the later message is accepted");

        conn.feed_recv_buf(
            &control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]),
            arrived,
        )
        .expect("the peer's SHUTDOWN is accepted");

        // Both messages are past their deadlines, but the hole between them
        // has not expired yet: TLPKTDROP's threshold is at least one second.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(500_000))
            .expect("ACK tick");
        assert!(conn.poll_event().is_none(), "the hole has not expired yet");
        assert_eq!(conn.state(), ConnectionState::Connected);

        // Once the hole expires, TLPKTDROP retires it (and with it the
        // message that can never complete), the later message is delivered,
        // and only then does the peer close become terminal.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(1_200_000))
            .expect("ACK tick");
        let delivered = conn
            .poll_event()
            .expect("the complete message is delivered");
        assert!(
            matches!(&delivered, ConnectionEvent::DataReceived { payload, .. } if payload.as_ref() == b"tail"),
            "the complete message must still be delivered: {delivered:?}"
        );
        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::StateChanged(ConnectionState::Disconnected))
        ));
        assert!(matches!(
            conn.poll_event(),
            Some(ConnectionEvent::Disconnected {
                reason: DisconnectReason::PeerShutdown
            })
        ));
        assert!(conn.poll_event().is_none(), "exactly one terminal event");
    }

    /// DATA arriving after the peer closed its send half is not protocol
    /// progress, and cannot refresh peer liveness either.
    #[test]
    fn data_after_peer_shutdown_is_rejected() {
        let mut conn = tsbpd_listener(120, false, 8);
        let socket_id = conn.options.socket_id;
        let arrived = Timestamp::from_micros(2_000);
        conn.feed_recv_buf(
            &control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]),
            arrived,
        )
        .expect("the peer's SHUTDOWN is accepted");
        assert_eq!(
            conn.state(),
            ConnectionState::Disconnected,
            "an empty receiver has nothing to drain, so the close is immediate"
        );

        let error = conn
            .handle_data_packet(
                DataPacket::new(0, 3, 50, 0, b"late".to_vec().into()),
                arrived,
            )
            .expect_err("DATA after SHUTDOWN is rejected");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidState);
        assert_eq!(
            conn.receiver_stats()
                .expect("receiver stats")
                .total_received,
            0
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
        // The protocol-correctness pass grew the inline sender state by the
        // two retained-stamp counters it carries (see
        // `sender_window_is_lazy_and_bounded_at_maximum_window`): 8 bytes,
        // deliberate and bounded, not drift. A later pass grew `SenderBuffer`
        // (embedded inline here) by another 8 bytes for the same reason --
        // see that same test's comment.
        assert!(connection_bytes <= 1_552);
        assert!(event_bytes <= 64);
        // F01 added `source_time: Timestamp` (8 bytes) to preserve a
        // message's original source time through reassembly -- a
        // deliberate, one-time budget increase, not drift.
        assert!(assembled_bytes <= 56);
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
        let ConnectionOutput::SendPacket(packet) =
            conn.poll_output().unwrap().expect("induction packet")
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
            match conn.poll_output().unwrap() {
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
        conn.crypto = Some(Box::new(
            CryptoContext::new_sender(
                "test_passphrase",
                KeyLength::Aes128,
                test_km_salt(),
                &sek,
                CipherMode::Ctr,
            )
            .unwrap(),
        ));

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
        while conn.poll_output().unwrap().is_some() {}

        conn.handle_data_packet(
            DataPacket::new(8_191, 1, 1, 0, Vec::new().into()),
            Timestamp::from_micros(1),
        )
        .expect("the gap is accepted");

        let expected = [0x8000_0000u32.to_be_bytes(), 8_190u32.to_be_bytes()].concat();
        let immediate =
            std::iter::from_fn(|| conn.poll_output().unwrap()).find_map(|output| match output {
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
        let periodic =
            std::iter::from_fn(|| conn.poll_output().unwrap()).find_map(|output| match output {
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
            std::iter::from_fn(|| conn.poll_output().unwrap()).find_map(|output| match output {
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
        while conn.poll_output().unwrap().is_some() {}

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
        while let Some(output) = conn.poll_output().unwrap() {
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

    /// A shortfall in the parser is no longer possible: ranges come out as
    /// ranges, and the whole report is what validation sees.
    #[test]
    fn a_loss_list_of_ranges_and_singles_parses_completely() {
        let mut encoded = Vec::new();
        write_u32(&mut encoded, 0x8000_0001);
        write_u32(&mut encoded, 3);
        write_u32(&mut encoded, 10);
        write_u32(&mut encoded, 11);

        assert_eq!(
            parse_loss_list(&encoded, usize::MAX).expect("loss report parses"),
            vec![1, 2, 3, 10, 11]
        );
    }

    #[test]
    fn a_dense_loss_list_is_returned_as_one_untruncated_range() {
        let mut encoded = Vec::new();
        write_u32(&mut encoded, 0x8000_0000);
        write_u32(&mut encoded, 65_535);

        // Parsing is a wire operation: it must not clamp a range to whatever
        // the connection happens to have room for. A dense report that names
        // more positions than this sender can possibly hold is rejected as a
        // unit downstream, not silently shortened into a valid prefix.
        assert_eq!(
            parse_loss_ranges(&encoded).unwrap(),
            [LossRange {
                first_seq: 0,
                last_seq: 65_535,
            }]
        );
    }

    #[test]
    fn loss_list_rejects_a_truncated_range() {
        let encoded = 0x8000_0001u32.to_be_bytes();
        let error = parse_loss_list(&encoded, 8).expect_err("range end is required");
        assert_eq!(error.kind, crate::ErrorKind::InvalidData);
    }

    fn ack_timer_duration(outputs: impl IntoIterator<Item = ConnectionOutput>) -> Option<u64> {
        outputs.into_iter().find_map(|output| match output {
            ConnectionOutput::SetTimer {
                id: TimerId::Ack,
                duration_micros,
            } => Some(duration_micros),
            _ => None,
        })
    }

    fn drain_outputs(conn: &mut SrtConnection) -> Vec<ConnectionOutput> {
        std::iter::from_fn(|| conn.poll_output().unwrap()).collect()
    }

    /// Drain the queued outputs and return only the datagrams.
    ///
    /// "Nothing was sent" assertions must not be confounded by a queued timer
    /// arm: since the sender timeout arms itself on submission, a connection
    /// with a live flight legitimately has a `SetTimer` action waiting, and that
    /// is not a transmission.
    fn drain_datagrams(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
        drain_outputs(conn)
            .into_iter()
            .filter_map(|output| match output {
                ConnectionOutput::SendPacket(bytes) => Some(bytes),
                ConnectionOutput::SetTimer { .. } | ConnectionOutput::ClearTimer { .. } => None,
            })
            .collect()
    }

    #[test]
    fn connection_options_clamp_ack_coalesce_per_socket() {
        let coalesced = SrtConnection::new_listener(ConnectionOptions {
            ack_interval_micros: 1_000_000,
            light_ack_interval_packets: 65_536,
            ..ConnectionOptions::default()
        });
        assert_eq!(
            coalesced.options.ack_interval_micros,
            crate::receiver::MAX_ACK_INTERVAL_MICROS
        );
        assert_eq!(
            coalesced.options.light_ack_interval_packets,
            crate::receiver::MAX_LIGHT_ACK_INTERVAL_PACKETS
        );

        let defaulted = SrtConnection::new_listener(ConnectionOptions::default());
        assert_eq!(
            defaulted.options.ack_interval_micros,
            crate::receiver::ACK_INTERVAL_MICROS
        );
        assert_eq!(
            defaulted.options.light_ack_interval_packets,
            crate::receiver::LIGHT_ACK_INTERVAL_PACKETS
        );
        assert_ne!(
            coalesced.options.ack_interval_micros, defaulted.options.ack_interval_micros,
            "ACK coalesce is per connection, not process-global"
        );
    }

    #[test]
    fn coalesced_ack_keeps_comm_syn_tick_and_defers_sendto() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            ack_interval_micros: crate::receiver::HIGH_FANIN_ACK_INTERVAL_MICROS,
            light_ack_interval_packets: crate::receiver::HIGH_FANIN_LIGHT_ACK_INTERVAL_PACKETS,
            tsbpd_delay: 0,
            ..ConnectionOptions::default()
        });
        conn.set_state(ConnectionState::Connected);
        let start = Timestamp::from_micros(0);
        conn.init_buffers(start, 0, 0);
        conn.receiver
            .as_mut()
            .expect("receiver")
            .set_tsbpd_enabled(false);
        conn.setup_connection_timers();

        assert_eq!(
            ack_timer_duration(drain_outputs(&mut conn)),
            Some(crate::receiver::ACK_INTERVAL_MICROS)
        );

        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(10_000))
            .expect("10ms TSBPD tick");
        let early = drain_outputs(&mut conn);
        assert_eq!(
            ack_timer_duration(early.iter().cloned()),
            Some(crate::receiver::ACK_INTERVAL_MICROS)
        );
        assert!(
            !early
                .iter()
                .any(|output| matches!(output, ConnectionOutput::SendPacket(_))),
            "coalesced ACK must not emit at the COMM_SYN tick"
        );

        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(40_000))
            .expect("40ms full ACK");
        let due = drain_outputs(&mut conn);
        assert!(
            due.iter()
                .any(|output| matches!(output, ConnectionOutput::SendPacket(_))),
            "full ACK is emitted once the configured interval elapses"
        );
    }

    #[test]
    fn default_ack_timer_still_emits_every_comm_syn() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            ..ConnectionOptions::default()
        });
        conn.set_state(ConnectionState::Connected);
        let start = Timestamp::from_micros(0);
        conn.init_buffers(start, 0, 0);
        conn.receiver
            .as_mut()
            .expect("receiver")
            .set_tsbpd_enabled(false);
        conn.setup_connection_timers();
        let _ = drain_outputs(&mut conn);

        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(10_000))
            .expect("default ACK timer");
        let outputs = drain_outputs(&mut conn);
        assert!(
            outputs
                .iter()
                .any(|output| matches!(output, ConnectionOutput::SendPacket(_))),
            "Haivision-compatible default still emits a full ACK every 10ms"
        );
        assert_eq!(
            ack_timer_duration(outputs),
            Some(crate::receiver::ACK_INTERVAL_MICROS)
        );
    }
}
