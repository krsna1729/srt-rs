//! SRT Connection (sans-I/O pattern).
//!
//! A state machine that manages an SRT connection.
//! I/O happens externally; this struct operates in a buffer-driven way.

use std::collections::VecDeque;
use std::fmt;
use std::ops::ControlFlow;

use bytes::{Bytes, BytesMut};
use zeroize::{Zeroize, Zeroizing};

use crate::buf::{read_u32, write_u32};
use crate::crypto_impl::{
    CipherMode, CryptoContext, GCM_TAG_LEN, KeyFlag, KeyLength, KmKeySelection,
};
use crate::error::Error;
use crate::message_assembler::MessageAssembler;
use crate::sender_rto::RtoArm;
use crate::srt_handshake::{
    DEFAULT_FLOW_WINDOW, DEFAULT_MTU, GroupExtensionData, HS_VERSION_5, HandshakePacket,
    HandshakeState, HandshakeType, IpFamily, KmError, KmMessage, MAX_CONGESTION_NAME_BYTES,
    MAX_FLOW_WINDOW, SRT_MAGIC_CODE, SRT_REJ_CONGESTION, SRT_REJ_CRYPTO, SRT_REJ_FILTER,
    SRT_REJ_GROUP, SRT_REJ_MESSAGEAPI, SRT_REJ_ROGUE, SRT_REJ_VERSION, srt_flags,
};
use crate::srt_packet::{
    ControlPacket, ControlType, DataHeader, DataPacket, DatagramClass, PendingData,
    PendingDatagram, SRT_CMD_KMREQ, SRT_CMD_KMRSP, SRT_HEADER_SIZE, SrtPacket, sequence_less_than,
};
use crate::srt_receiver::{
    GroupReceiveTime, LossRange, MAX_EXPIRED_GAPS_PER_VISIT, ReceiverBuffer,
};
use crate::srt_sender::{
    DroppedMessage, MAX_DROPREQ_PER_NAK, NakReceipt, PeerRateFeedback, SenderBuffer,
};
use crate::stats::ConnectionStats;
use crate::time::Timestamp;

#[derive(Debug, Clone, Copy)]
pub(crate) struct GroupTime {
    start: Timestamp,
    receive: GroupReceiveTime,
}

impl GroupTime {
    pub(crate) fn update_receive(&mut self, time: Self) {
        if time.receive.phase() >= self.receive.phase() {
            self.receive = time.receive;
        }
    }

    pub(crate) fn advance_receive_epoch(&mut self, time: Self) {
        if time.receive.phase() > self.receive.phase() {
            self.receive = time.receive;
        }
    }
}

const MAX_NAK_RECORD_SIZE: usize = 8;
const NAK_CHUNK_INITIAL_CAPACITY: usize = 32;
/// NAK packets one periodic-NAK fire queues. A full-window alternating loss
/// list (`MAX_FLOW_WINDOW / 2` single losses) is 89 packets at the default
/// MTU, measured at ~250 µs of Owner time in one fire (`nak_chunking`
/// `alternating_65536`). Sixteen packets carry ~5,800 single losses or
/// ~2,900 ranges: a default 8,192-packet window is still named in one fire,
/// and the largest list within six.
const MAX_PERIODIC_NAK_PACKETS: usize = 16;
const _: () = assert!(DEFAULT_MTU as usize - SRT_HEADER_SIZE >= MAX_NAK_RECORD_SIZE);

/// Smallest DATA payload this connection can operate with.
///
/// The largest control packet whose size is derived from the negotiated
/// payload budget is a NAK loss record ([`NakChunkEncoder`] is constructed
/// with `max_control_info_size`, which is `max_payload_size`), and a
/// connection that cannot report loss cannot recover it. libsrt's
/// `MinimumMSS` reserves only the 4 bytes it needs "for passing any data";
/// this floor is the stricter, structurally derived one, so a peer MSS that
/// would negotiate a smaller payload is rejected rather than accepted into
/// a session that would later fail to emit a NAK.
const MIN_NEGOTIATED_PAYLOAD_SIZE: usize = MAX_NAK_RECORD_SIZE;

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
    /// Zero-delay continuation of protocol-ready DATA delivery: one
    /// `enqueue_ready_data` visit moves at most `MAX_DELIVERY_PER_VISIT`
    /// packets and schedules the rest here. Carries no elapsed time.
    DeliveryContinue,
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
    pub const COUNT: usize = 9;

    pub const fn index(self) -> usize {
        self as usize
    }

    pub const ALL: [TimerId; 9] = [
        TimerId::Ack,
        TimerId::Nak,
        TimerId::Keepalive,
        TimerId::RetransmitContinue,
        TimerId::DeliveryContinue,
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

// HSv5 requires SRT 1.3.0 or newer. The peer flow-window field is signed
// 32-bit and must advertise at least two packets.
const MIN_HSV5_SRT_VERSION: u32 = 0x010300;
/// Newest SRT version for which libsrt uses its legacy AES-GCM nonce/AAD
/// layout (`crypto.cpp`: peers at or below 1.5.3), which is not supported.
const LEGACY_GCM_MAX_SRT_VERSION: u32 = 0x010503;
const MIN_PEER_FLOW_WINDOW: u32 = 2;

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

/// Ready packets one [`SrtConnection::enqueue_ready_data`] visit moves into
/// the application queue before a zero-delay `DeliveryContinue` visit takes
/// the remainder. Without this cap, a filled gap or an application read could
/// move the connection's whole receive window (up to `DEFAULT_FLOW_WINDOW`
/// packets) in one callback on the Owner thread. A delivery (assembler feed
/// plus event push) is cheaper than a retransmission (encrypt plus queue), so
/// twice `MAX_RETRANSMITS_PER_VISIT` is a similar amount of work per visit;
/// it also equals the transport's `OutputDrainBudget` action count.
pub(crate) const MAX_DELIVERY_PER_VISIT: usize = 64;

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
    /// Application ready: handshake and initial TX key confirmation complete.
    Connected,
    /// One complete message, retaining packet chunks in order. Processing
    /// `payload.chunks()` preserves the message boundary without flattening.
    DataReceived {
        payload: crate::ReceivedPayload,
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

/// Outputs a peer's ACKs and NAKs trigger that are waiting in the output
/// queue (S4).
///
/// A peer can send ACKs and NAKs faster than a transport with no TX capacity
/// drains the queue, and an overflowing queue disconnects. So each such
/// answer waits at most once (DROPREQ answers: at most one report's worth):
/// a later request is answered once the waiting one has gone out, and the
/// peer repeats its requests anyway. libsrt sends these as best-effort
/// datagrams and never queues them (`CUDT::sendCtrl`).
///
/// Set where each is queued (`send_ackack`, `send_drop_req` for every
/// DROPREQ, `arm_retransmit_continue`), cleared when `poll_output_into`
/// hands it to the transport, and reset with the queue on overflow.
#[derive(Debug, Default)]
struct WaitingReplies {
    /// An ACKACK waits.
    ackack: bool,
    /// DROPREQs waiting, TLPKTDROP's own included.
    dropreqs: usize,
    /// A `RetransmitContinue` arm waits.
    retransmit_continue: bool,
}

impl WaitingReplies {
    /// Account for `pkt` leaving the queue for the transport.
    fn sent(&mut self, pkt: &PendingDatagram) {
        if let PendingDatagram::Control(ctrl) = pkt {
            match ctrl.control_type {
                ControlType::AckAck => self.ackack = false,
                ControlType::DropReq => self.dropreqs = self.dropreqs.saturating_sub(1),
                _ => {}
            }
        }
    }

    /// Account for a timer action leaving the queue for the transport.
    fn timer_sent(&mut self, id: TimerId) {
        if id == TimerId::RetransmitContinue {
            self.retransmit_continue = false;
        }
    }
}

/// A DROPREQ datagram's `(first_seq, last_seq)` range, if `pkt` is one.
///
/// `None` for anything else, including a DROPREQ whose control-info somehow
/// fails to parse (shape is already validated before a DROPREQ can reach the
/// output queue, so that case is not expected, only guarded).
fn dropreq_range(pkt: &PendingDatagram) -> Option<(u32, u32)> {
    let PendingDatagram::Control(ctrl) = pkt else {
        return None;
    };
    if ctrl.control_type != ControlType::DropReq {
        return None;
    }
    let mut cif = ctrl.control_info.as_slice();
    crate::buf::read_u32(&mut cif)
        .ok()
        .zip(crate::buf::read_u32(&mut cif).ok())
}

/// Connection options.
#[derive(Clone)]
pub struct ConnectionOptions {
    /// Local socket ID. Zero means auto-assign a random nonzero value.
    pub socket_id: u32,
    /// Initial sequence number. Only its low 31 bits are used: the wire
    /// field is a 31-bit sequence number.
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
    /// 512 bytes at construction). An empty Stream ID is not sent: libsrt
    /// refuses an empty SID block.
    pub stream_id: Option<String>,
    /// Congestion control mode name declared in the handshake extension
    /// (e.g. "live", "file"). It must be 1 to 16 bytes, the names a libsrt
    /// peer accepts (`CSrtConfig::MAX_CONG_LENGTH`): `connect` refuses
    /// another, and a listener refuses callers with `SRT_REJ_CONGESTION`. A real
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
            // Advertise the first version whose AES-GCM nonce and AAD match
            // `crypto::build_gcm_iv` and `DataPacket::gcm_aad`; 1.5.3 and
            // older select libsrt's incompatible legacy AEAD format.
            srt_version: 0x010504,
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

const KM_HISTORY_CAPACITY: usize = 4;

/// Bounded history of this side's acknowledged key-material requests.
///
/// SRT's KM wire format carries only an even/odd selector, not a monotonic
/// generation number. Retaining the last few acknowledged messages lets the
/// connection recognise a delayed or replayed KMRSP for an earlier rotation
/// without growing memory over a connection's lifetime. This is bounded
/// recent-replay rejection, not durable replay protection: after
/// `KM_HISTORY_CAPACITY` further rotations an old message has left the ring.
struct KmHistory {
    entries: [Option<KmMessage>; KM_HISTORY_CAPACITY],
    next: usize,
}

impl Default for KmHistory {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            next: 0,
        }
    }
}

impl KmHistory {
    fn contains(&self, message: &KmMessage) -> bool {
        self.entries.iter().flatten().any(|entry| entry == message)
    }

    fn remember(&mut self, message: KmMessage) {
        self.entries[self.next] = Some(message);
        self.next = (self.next + 1) % KM_HISTORY_CAPACITY;
    }
}

/// Bounded retries for a key-material request the peer has not acknowledged.
///
/// A timeout does not prove the peer never installed the key: after bounded
/// retries the connection closes instead of discarding a possibly-live key
/// and silently continuing with mismatched encryption state.
const KM_REQUEST_MAX_RETRIES: u8 = 4;

/// Retry cadence for an unacknowledged key-material request.
///
/// An srt-rs sender policy, not libsrt's: libsrt resends after 1.5 x SRTT,
/// up to ten times, and switches keys on its packet schedule whether or
/// not the peer answered (`srtcore/crypto.cpp`, `haicrypt/hcrypt_ctx_tx.c`).
/// srt-rs switches only after the matching KMRSP and closes after
/// `KM_REQUEST_MAX_RETRIES` unanswered retries at this fixed cadence.
const KM_REQUEST_RETRY_INTERVAL_MICROS: u64 = 1_000_000;

/// Fresh-salt KEK derivations a connection allows at once (see
/// [`KekDerivationBudget`]).
const KM_KEK_DERIVATION_BURST: u8 = 2;

/// One fresh-salt KEK derivation is restored per this interval.
const KM_KEK_DERIVATION_REFILL_MICROS: u64 = 1_000_000;

/// Bound on PBKDF2 work a peer's KMREQs can cause.
///
/// A KMREQ under a salt with no cached KEK costs one 2048-iteration
/// PBKDF2-HMAC-SHA1 derivation before its wrap can even be checked. A token
/// bucket admits `KM_KEK_DERIVATION_BURST` such derivations at once and
/// restores one per `KM_KEK_DERIVATION_REFILL_MICROS`. Legitimate peers need
/// few: libsrt keeps its salt for the whole session, and Robotweax announces
/// one new salt per direction after connecting. A KMREQ refused here gets
/// no KMRSP and changes nothing, so the peer's own retry installs it once a
/// derivation is available again.
struct KekDerivationBudget {
    tokens: u8,
    /// When `tokens` was last brought up to date.
    updated_at: Option<Timestamp>,
}

impl Default for KekDerivationBudget {
    fn default() -> Self {
        Self {
            tokens: KM_KEK_DERIVATION_BURST,
            updated_at: None,
        }
    }
}

impl KekDerivationBudget {
    /// Take one derivation if available at `now`.
    fn try_take(&mut self, now: Timestamp) -> bool {
        let updated_at = *self.updated_at.get_or_insert(now);
        let restored = now.saturating_sub(updated_at) / KM_KEK_DERIVATION_REFILL_MICROS;
        if restored > 0 {
            let tokens = u64::from(self.tokens).saturating_add(restored);
            self.tokens = u8::try_from(tokens)
                .unwrap_or(u8::MAX)
                .min(KM_KEK_DERIVATION_BURST);
            self.updated_at =
                Some(updated_at.add_micros(restored * KM_KEK_DERIVATION_REFILL_MICROS));
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

/// An outgoing key-material request awaiting its response.
struct PendingKmRequest {
    /// The exact KMREQ to retransmit. A rotation is never re-generated, so a
    /// retry carries byte-identical key material to the original -- the peer
    /// answers a duplicate idempotently rather than installing anything.
    request: KmMessage,
    /// When the next retransmission is due.
    next_retry: Timestamp,
    /// Retransmissions left, or `None` when another mechanism owns the retry:
    /// the handshake resends its whole CONCLUSION (this KMREQ included), so
    /// the connection must not also retransmit it here.
    retries_left: Option<u8>,
}

/// What [`SrtConnection::service_km_retry`] decided to do, computed under a
/// short borrow of the transaction state so the action itself can run
/// without one.
enum KmRetryAction {
    /// Retransmit this exact request.
    Resend(KmMessage),
    /// Close when the peer's installed key is uncertain.
    Close(KmKeySelection),
}

/// Post-handshake KM request/response transaction state.
#[derive(Default)]
struct KmControlState {
    /// Outgoing rotation awaiting acknowledgement (sender side).
    pending: Option<PendingKmRequest>,
    /// Independent initial TX key still needs its runtime KMRSP.
    initial_tx_pending: bool,
    acknowledged: KmHistory,
    /// Bound on the PBKDF2 work inbound KMREQs cause (receiver side).
    kek_derivations: KekDerivationBudget,
}

/// Whether a KM message uses the session's key length and cipher. libsrt
/// likewise rejects a runtime key-length change and a cipher mismatch.
fn km_matches_suite(message: &KmMessage, crypto: &CryptoContext) -> bool {
    message.key_length == crypto.key_length()
        && CipherMode::from_km(message) == Some(crypto.cipher_mode())
}

#[path = "connection_retirement.rs"]
mod retirement;
pub use retirement::ConnectionRetirement;

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
    /// Peer handshake ISN, retained even after the receive cursor advances.
    peer_initial_seq: Option<u32>,

    /// Encryption context.
    /// Boxed: only encrypted sessions pay the context and expanded key
    /// schedules. Plain sessions stay lean.
    crypto: Option<Box<CryptoContext>>,
    /// Bounded KM transaction/replay state, allocated only for encrypted
    /// sessions.
    km_control: Option<Box<KmControlState>>,

    /// Send buffer.
    sender: Option<SenderBuffer>,
    /// Receive buffer.
    receiver: Option<ReceiverBuffer>,
    /// Message reassembly.
    assembler: MessageAssembler,
    /// Maximum data payload per SRT packet (MTU minus header).
    max_payload_size: usize,
    /// Address family of the UDP path, set by the transport; it turns the
    /// peer's IP-layer MSS into a datagram budget.
    ip_family: IpFamily,
    /// The peer's IP, set by the transport and emitted in this side's
    /// handshakes' peer-IP field, as libsrt does (`core.cpp:3782`, `6011`).
    peer_ip: std::net::IpAddr,

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
    /// See [`WaitingReplies`].
    waiting_replies: WaitingReplies,
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
    /// A TLPKTDROP visit stopped at its gap budget with more gaps possibly
    /// due; the next `DeliveryContinue` visit continues it.
    receive_expiry_continues: bool,
    /// When the peer closed its send half, while this connection is still
    /// delivering what it had already accepted. Terminal on drain, and at
    /// most one inactivity timeout later whatever the peer still sends.
    peer_shutdown_at: Option<Timestamp>,
    output_overflowed: bool,
    event_overflowed: bool,

    /// Connection start time.
    start_time: Option<Timestamp>,
    /// A pending group member must inherit RX time before its first DATA,
    /// even if it arrives in the same ingress batch as CONCLUSION.
    pending_group_receive_time: Option<GroupReceiveTime>,

    /// Last ACK send time.
    last_ack_time: Option<Timestamp>,
    /// Last NAK send time.
    last_nak_time: Option<Timestamp>,
    /// Loss sequence the next periodic NAK resumes from (oldest first), when
    /// the last one stopped at `MAX_PERIODIC_NAK_PACKETS`.
    periodic_nak_resume: Option<u32>,
    /// Reused staging for one periodic NAK's packets (the receiver is
    /// borrowed while they are encoded), so a fire does not allocate.
    periodic_nak_packets: Vec<ControlPacket>,
    /// Last packet receipt time (for inactivity-timeout detection).
    last_recv_time: Option<Timestamp>,
    /// Last protocol packet queued for transmission.
    last_send_time: Option<Timestamp>,
    /// Start of an orderly close attempt.
    shutdown_started_at: Option<Timestamp>,
    /// KM request retained only until the listener encodes its handshake
    /// response. Boxed to keep the common connection footprint bounded.
    received_km: Option<Box<KmMessage>>,
    /// Stream ID received from the peer (Listener only).
    peer_stream_id: Option<String>,
    /// Congestion control mode name declared by the peer in the handshake
    /// extension, if any.
    peer_congestion_control: Option<String>,
    /// SRT capability flags advertised by the peer's handshake extension.
    peer_srt_flags: Option<u32>,
    /// Negotiated TSBPD delay of this side's receive direction, in ms.
    ///
    /// HSv5 negotiates each direction separately (libsrt
    /// `m_iTsbPdDelay_ms`): the peer's SND half proposes it.
    rcv_tsbpd_delay: u16,
    /// Negotiated TSBPD delay of the peer's receive direction, in ms: this
    /// side's sender drop horizon (libsrt `m_iPeerTsbPdDelay_ms`), proposed
    /// by the peer's RCV half.
    peer_tsbpd_delay: u16,
    /// SRT version the peer advertised in its HSREQ/HSRSP (libsrt
    /// `SRTO_PEERVERSION`), once the CONCLUSION has been checked.
    peer_srt_version: Option<u32>,
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
    /// Strict wire checker installed by a test fixture
    /// ([`Self::install_wire_checker`]); absent from production builds.
    #[cfg(any(test, feature = "test-support"))]
    wire_checker: Option<Box<crate::test_support::wire_checker::WireChecker>>,
}

impl Drop for SrtConnection {
    fn drop(&mut self) {
        self.clear_config_secrets();
        #[cfg(any(test, feature = "test-support"))]
        self.finish_wire_check();
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SrtConnection {
    /// Close the strict wire transcript: sequence skips must have been
    /// announced by a DROPREQ sent or still queued. Skipped while the test
    /// is already failing, so the first failure is the one reported.
    fn finish_wire_check(&self) {
        let Some(checker) = self.wire_checker.as_deref() else {
            return;
        };
        if std::thread::panicking() {
            return;
        }
        let queued: Vec<(u32, u32)> = self
            .output_queue
            .iter()
            .filter_map(|output| match output {
                QueuedOutput::Datagram(pkt) => dropreq_range(pkt),
                _ => None,
            })
            .collect();
        if let Err(violation) = checker.finish(&queued) {
            panic!("{violation}");
        }
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

/// Refuse an outbound GROUP extension a libsrt peer would refuse.
fn ensure_libsrt_group(group: GroupExtensionData) -> Result<(), Error> {
    if group.is_valid_for_libsrt() {
        return Ok(());
    }
    Err(Error::invalid_data(
        "GROUP extension needs an SRTGROUP_MASK group ID and a libsrt group type \
         (undefined, broadcast or backup)",
    ))
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
    // The handshake carries 31 bits; keep the local identity identical to
    // the wire one so the CONCLUSION response's echo compares equal.
    options.initial_seq = options.initial_seq.map(|seq| seq & 0x7FFF_FFFF);
    if let Some(stream_id) = options.stream_id.as_mut() {
        truncate_utf8(stream_id, MAX_HANDSHAKE_OPTION_BYTES);
    }
    // The congestion name is validated, not truncated: a shortened name
    // would declare a different mode.
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
            self.waiting_replies = WaitingReplies::default();
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
    ///
    /// Only cumulative-ACK progress or a drop changes what is live, so a
    /// duplicate or non-advancing ACK never calls this. One pass removes
    /// every stale entry in place, so a purge costs one visit per queued
    /// output (at most `MAX_OUTPUT_QUEUE_ACTIONS`), never one shift per
    /// removal.
    fn purge_stale_queued_data(&mut self) {
        let Some(sender) = self.sender.as_ref() else {
            return;
        };
        let priority = self.output_queue_priority;
        let (mut index, mut priority_removed, mut bytes) = (0usize, 0usize, 0usize);
        let (mut even, mut odd) = (0u64, 0u64);
        self.output_queue.retain(|output| {
            count_work!(OutputQueueVisits);
            index += 1;
            let QueuedOutput::Datagram(pkt @ PendingDatagram::Data(data)) = output else {
                return true;
            };
            if sender.is_live(data.header.sequence_number) {
                return true;
            }
            bytes += pkt.wire_len();
            priority_removed += usize::from(index <= priority);
            match data.crypto.map(|stamp| stamp.key_flag) {
                Some(KeyFlag::Even) => even += 1,
                Some(KeyFlag::Odd) => odd += 1,
                None => {}
            }
            false
        });
        self.output_queue_bytes = self.output_queue_bytes.saturating_sub(bytes);
        self.output_queue_priority -= priority_removed;
        self.pending_tx_even = self.pending_tx_even.saturating_sub(even);
        self.pending_tx_odd = self.pending_tx_odd.saturating_sub(odd);
    }

    fn purge_stale_queued_data_after_ack(&mut self, ack_progressed: bool) {
        if ack_progressed {
            self.purge_stale_queued_data();
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
            rcv_tsbpd_delay: options.tsbpd_delay,
            peer_tsbpd_delay: options.tsbpd_delay,
            peer_srt_version: None,
            options,
            peer_socket_id: 0,
            syn_cookie: 0,
            initial_seq,
            peer_initial_seq: None,
            crypto: None,
            km_control: None,
            sender: None,
            receiver: None,
            assembler: MessageAssembler::new(),
            max_payload_size: DEFAULT_MTU as usize - SRT_HEADER_SIZE,
            ip_family: IpFamily::V4,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            event_queue: VecDeque::new(),
            key_refresh_notified: false,
            pending_data_events: 0,
            pending_data_packets: 0,
            output_queue: VecDeque::new(),
            output_queue_bytes: 0,
            output_queue_priority: 0,
            waiting_replies: WaitingReplies::default(),
            pending_tx_even: 0,
            pending_tx_odd: 0,
            receive_window_reopen_pending: false,
            receive_expiry_continues: false,
            peer_shutdown_at: None,
            output_overflowed: false,
            event_overflowed: false,
            start_time: None,
            pending_group_receive_time: None,
            last_ack_time: None,
            last_nak_time: None,
            periodic_nak_resume: None,
            periodic_nak_packets: Vec::new(),
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
            #[cfg(any(test, feature = "test-support"))]
            wire_checker: None,
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
            rcv_tsbpd_delay: options.tsbpd_delay,
            peer_tsbpd_delay: options.tsbpd_delay,
            peer_srt_version: None,
            options,
            peer_socket_id: 0,
            syn_cookie: 0,
            initial_seq,
            peer_initial_seq: None,
            crypto: None,
            km_control: None,
            sender: None,
            receiver: None,
            assembler: MessageAssembler::new(),
            max_payload_size: DEFAULT_MTU as usize - SRT_HEADER_SIZE,
            ip_family: IpFamily::V4,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            event_queue: VecDeque::new(),
            key_refresh_notified: false,
            pending_data_events: 0,
            pending_data_packets: 0,
            output_queue: VecDeque::new(),
            output_queue_bytes: 0,
            output_queue_priority: 0,
            waiting_replies: WaitingReplies::default(),
            pending_tx_even: 0,
            pending_tx_odd: 0,
            receive_window_reopen_pending: false,
            receive_expiry_continues: false,
            peer_shutdown_at: None,
            output_overflowed: false,
            event_overflowed: false,
            start_time: None,
            pending_group_receive_time: None,
            last_ack_time: None,
            last_nak_time: None,
            periodic_nak_resume: None,
            periodic_nak_packets: Vec::new(),
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
            #[cfg(any(test, feature = "test-support"))]
            wire_checker: None,
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

    /// Return the SRT version the peer advertised in its handshake
    /// extension (libsrt `SRTO_PEERVERSION`), e.g. `0x010504` for 1.5.4.
    pub fn peer_srt_version(&self) -> Option<u32> {
        self.peer_srt_version
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

    /// Set or clear listener-side GROUP metadata before CONCLUSION. A group
    /// libsrt would refuse ([`GroupExtensionData::is_valid_for_libsrt`]) is
    /// an error.
    pub fn set_listener_group_extension(
        &mut self,
        group: Option<GroupExtensionData>,
    ) -> Result<(), Error> {
        self.ensure_listener_policy_window()?;
        if let Some(group) = group {
            ensure_libsrt_group(group)?;
        }
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
    /// A group libsrt would refuse
    /// ([`GroupExtensionData::is_valid_for_libsrt`]) is an error.
    pub fn set_group_extension(&mut self, group: GroupExtensionData) -> Result<(), Error> {
        ensure_libsrt_group(group)?;
        self.options.group_extension = Some(group);
        Ok(())
    }

    /// Set the peer's UDP address.
    ///
    /// The transport knows the socket address; the handshake does not carry
    /// the path family reliably. It must be set before the peer's CONCLUSION
    /// is processed, because that is where the peer MSS becomes this
    /// connection's datagram budget. Its IP is emitted in this side's
    /// handshakes' peer-IP field, which a libsrt peer records as its own
    /// local address (`srt_getsockname` on an accepted socket, the group
    /// member's `agent`; `core.cpp:4983`, `6055-6057`, `api.cpp:798-805`).
    /// Unset, the path is taken to be IPv4 and the field is `0.0.0.0`.
    pub fn set_peer_address(&mut self, peer: std::net::SocketAddr) {
        self.ip_family = IpFamily::of(&peer);
        self.peer_ip = peer.ip();
    }

    /// Install a strict wire checker
    /// ([`crate::test_support::wire_checker`]) on this connection: every
    /// datagram [`Self::poll_output_into`] materializes is checked against
    /// libsrt's wire rules, and every datagram fed in is recorded as peer
    /// input. A violation panics. Test-only (`test-support` feature).
    ///
    /// The fixture must also report the peer's address
    /// ([`Self::set_peer_address`]), which libsrt always puts in the
    /// handshake.
    ///
    /// # Panics
    ///
    /// Panics if the handshake has already started: the transcript must
    /// begin with the first datagram.
    #[cfg(any(test, feature = "test-support"))]
    pub fn install_wire_checker(&mut self) {
        assert_eq!(
            self.handshake_state,
            HandshakeState::Initial,
            "a strict wire transcript starts before the handshake"
        );
        self.wire_checker = Some(Box::new(
            crate::test_support::wire_checker::WireChecker::new(self.role),
        ));
    }

    /// The installed strict wire checker, if any. Test-only
    /// (`test-support` feature).
    #[cfg(any(test, feature = "test-support"))]
    pub fn wire_checker_mut(
        &mut self,
    ) -> Option<&mut crate::test_support::wire_checker::WireChecker> {
        self.wire_checker.as_deref_mut()
    }

    /// Report `peer` as the transport address unless the test set one.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn default_peer_address(&mut self, peer: std::net::SocketAddr) {
        if self.peer_ip.is_unspecified() {
            self.set_peer_address(peer);
        }
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
        if self.options.passphrase.is_some()
            && self.options.cipher_mode == CipherMode::Gcm
            && self.options.srt_version <= LEGACY_GCM_MAX_SRT_VERSION
        {
            return Err(Error::crypto_error(
                "AES-GCM needs an srt_version of 1.5.4 or newer: libsrt peers use the \
                 unsupported legacy GCM layout with 1.5.3 and older",
            ));
        }
        if !self.congestion_name_is_emittable() {
            return Err(Error::invalid_data(
                "congestion_control must be 1 to 16 bytes, the names libsrt accepts",
            ));
        }
        self.options
            .group_extension
            .map_or(Ok(()), ensure_libsrt_group)?;

        if self.pending_group_receive_time.is_none() {
            self.start_time = Some(now);
        }
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
    fn peer_flow_window_is_usable(flow_window: u32) -> bool {
        (MIN_PEER_FLOW_WINDOW..=i32::MAX as u32).contains(&flow_window)
    }

    fn negotiated_flow_window(&self) -> u32 {
        if self.peer_flow_window >= 2 {
            self.options.flow_window_packets.min(self.peer_flow_window)
        } else {
            self.options.flow_window_packets
        }
    }

    /// Record a peer flow-window advertisement after handshake validation.
    fn note_peer_flow_window(&mut self, advertised: u32) {
        debug_assert!(Self::peer_flow_window_is_usable(advertised));
        self.peer_flow_window = advertised;
    }

    /// Initialize the send/receive buffers. Demand starts false: static
    /// `pacing_repay` only enables repay, the app must still signal waiting
    /// data via `set_pacing_demand`.
    fn init_buffers(&mut self, now: Timestamp, peer_initial_seq: u32, tsbpd_time_base: i64) {
        self.peer_initial_seq = Some(peer_initial_seq & 0x7FFF_FFFF);
        let negotiated_window = self.negotiated_flow_window();
        let mut sender =
            SenderBuffer::new(self.initial_seq, negotiated_window, self.peer_tsbpd_delay);
        if let Some(max_bw) = self.options.max_bandwidth_bytes_per_sec {
            sender.set_max_bandwidth(max_bw);
        } else if let Some(input_bw) = self.options.input_bandwidth_bytes_per_sec {
            sender.set_input_bandwidth(input_bw, self.options.overhead_bandwidth_percent);
        }
        sender.set_repay_pacing_debt(false);
        self.sender = Some(sender);
        let mut receiver = ReceiverBuffer::with_buffer_size(
            peer_initial_seq,
            self.rcv_tsbpd_delay,
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
        if let Some(time) = self.pending_group_receive_time.take() {
            receiver.inherit_group_time(time);
        }
        self.receiver = Some(receiver);
        self.last_ack_time = Some(now);
        self.last_nak_time = Some(now);
        self.periodic_nak_resume = None;
    }

    fn flight_capacity_packets(&self) -> u32 {
        self.options
            .flow_window_packets
            .min(self.options.receive_buffer_packets)
    }

    /// The configured receive window, in packets.
    pub(crate) fn receive_window_packets(&self) -> u32 {
        self.options.receive_buffer_packets
    }

    /// Most payload bytes this connection's send and receive windows can
    /// hold: each window full of packets of the largest payload any peer can
    /// negotiate (`apply_peer_mss` only lowers it). The windows are fixed
    /// before the CONCLUSION is processed (`ensure_listener_policy_window`),
    /// so a listener gets the same value once policy has run as at
    /// retirement, and can reserve it at admission and release it then.
    #[must_use]
    pub fn window_memory_bound_bytes(&self) -> u64 {
        let packets = u64::from(self.options.flow_window_packets)
            + u64::from(self.options.receive_buffer_packets);
        packets * (DEFAULT_MTU as usize - SRT_HEADER_SIZE) as u64
    }

    /// Process received data.
    pub fn feed_recv_buf(&mut self, buf: &[u8], now: Timestamp) -> Result<(), Error> {
        self.check_output_queue()?;
        if buf.len() < SRT_HEADER_SIZE {
            return Err(Error::insufficient_buffer());
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(checker) = self.wire_checker.as_deref_mut() {
            checker.record_received(buf);
        }
        let packet = SrtPacket::decode(buf)?;
        self.feed_decoded(packet, now)
    }

    /// Process a received datagram the caller already owns as `Bytes`: a
    /// DATA payload is a zero-copy slice of `buf` instead of a fresh copy.
    /// For receive paths that land datagrams in refcounted buffers
    /// (`BytesRecvBatch` in srt-transport). The payload keeps `buf`'s
    /// allocation alive until it is delivered and dropped.
    pub fn feed_recv_bytes(&mut self, buf: Bytes, now: Timestamp) -> Result<(), Error> {
        self.check_output_queue()?;
        if buf.len() < SRT_HEADER_SIZE {
            return Err(Error::insufficient_buffer());
        }
        #[cfg(any(test, feature = "test-support"))]
        if let Some(checker) = self.wire_checker.as_deref_mut() {
            checker.record_received(&buf);
        }
        let packet = SrtPacket::decode_bytes(&buf)?;
        self.feed_decoded(packet, now)
    }

    fn feed_decoded(&mut self, packet: SrtPacket, now: Timestamp) -> Result<(), Error> {
        self.apply_pending_group_receive_time();
        let (dest_socket_id, is_handshake) = match &packet {
            SrtPacket::Data(packet) => (packet.dest_socket_id, false),
            SrtPacket::Control(packet) => (
                packet.dest_socket_id,
                packet.control_type == ControlType::Handshake,
            ),
        };
        // A handshake may name socket ID 0 until it is answered: the caller
        // sends every CONCLUSION, retransmissions included, to 0 (libsrt
        // too), so an established listener still receives a repeat whose
        // response was lost that way. `handle_handshake` answers only an
        // exact repeat of the established session's CONCLUSION.
        if self.options.socket_id != 0
            && dest_socket_id != self.options.socket_id
            && !(is_handshake
                && dest_socket_id == 0
                && match self.state {
                    ConnectionState::Connected => self.role == ConnectionRole::Listener,
                    ConnectionState::Closing => false,
                    _ => true,
                })
        {
            return Err(Error::invalid_data(format!(
                "destination socket ID mismatch: expected {:#x}, got {:#x}",
                self.options.socket_id, dest_socket_id
            )));
        }

        // The inactivity timer is armed once at connect and rearms itself on
        // fire — no per-packet SetTimer output.
        let proves_activity = match packet {
            SrtPacket::Data(data_pkt) => {
                tracing::debug!("received DATA packet, seq={}", data_pkt.sequence_number);
                self.handle_data_packet(data_pkt, now).map(|()| true)
            }
            SrtPacket::Control(ctrl_pkt) => self.handle_control_packet(ctrl_pkt, now),
        }?;

        // Only an accepted protocol transition proves peer activity. Generic
        // framing plus a matching destination socket id is not enough: a
        // datagram that decodes but fails its own semantic or authentication
        // validation (a truncated ACK, an unknown ACKACK, an undecryptable
        // DATA body, a malformed key-management command) is rejected above
        // and must not keep an otherwise silent peer alive. Robotweax 0.2.2
        // hardens the same invariant and libsrt's own control parsers reject
        // before touching connection state. A loss report still being
        // validated proves it only once it validates.
        if proves_activity && self.state == ConnectionState::Connected {
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
    /// Bounded to `MAX_RETRANSMITS_PER_VISIT` per call (P01): a NAK
    /// reporting a large loss range, or a visit catching up after one,
    /// used to encrypt and queue the connection's entire retained send
    /// window synchronously in a single call. `pop_retransmit` only
    /// removes a sequence from the loss list once it actually returns it,
    /// so stopping early here leaves the remainder exactly where it was --
    /// membership and FIFO ordering are untouched, and a follow-up visit
    /// picks up right where this one left off.
    ///
    /// Paced: each retransmission takes a slot of the send-period schedule
    /// new data uses (`SenderBuffer::retransmit_pacing_wait`), so a visit
    /// also stops when the schedule has no slot left at `now`.
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
            let Some((header, payload)) = self.sender.as_mut().and_then(|s| {
                if s.retransmit_pacing_wait(now) == 0 {
                    s.pop_retransmit(dest_socket_id, now)
                } else {
                    None
                }
            }) else {
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
        // *depend* on that. The follow-up is due when the pacing schedule has
        // its next slot: at once when the per-visit cap stopped this visit
        // with slots still owed, later when the schedule ran out. The rate is
        // the configured bandwidth, the same ceiling new data has; the
        // per-visit cap only bounds *work per call*.
        //
        // Loss detection is a different mechanism entirely and lives on
        // `TimerId::SenderRto`; this one only continues work already queued.
        //
        // The same continuation finishes a peer loss report too large for
        // one visit (`SenderBuffer::receive_nak`) and drops acknowledged
        // packets a large ACK left (`SenderBuffer::release_acked_packets`),
        // both at once.
        let continue_after = self.sender.as_ref().and_then(|sender| {
            if sender.has_pending_nak() || sender.has_acked_packets_to_release() {
                Some(0)
            } else if sender.has_retransmit() {
                Some(sender.retransmit_pacing_wait(now))
            } else {
                None
            }
        });
        if let Some(delay) = continue_after {
            self.arm_retransmit_continue(delay);
        }
    }

    /// Arm the continuation, unless an arm still waits in the output queue
    /// (see [`WaitingReplies`]): its visit re-arms while work remains.
    fn arm_retransmit_continue(&mut self, duration_micros: u64) {
        if self.waiting_replies.retransmit_continue {
            return;
        }
        self.waiting_replies.retransmit_continue = true;
        self.queue_output(QueuedOutput::SetTimer {
            id: TimerId::RetransmitContinue,
            duration_micros,
        });
    }

    /// Arm the continuation if an ACK left acknowledged packets to drop.
    fn continue_acked_release_later(&mut self) {
        if self
            .sender
            .as_ref()
            .is_some_and(SenderBuffer::has_acked_packets_to_release)
        {
            self.arm_retransmit_continue(0);
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
        self.apply_pending_group_receive_time();
        match timer_id {
            TimerId::Handshake => self.handle_handshake_timer(now),
            TimerId::Keepalive => self.handle_keepalive_timer(now),
            TimerId::Ack => self.handle_ack_timer(now),
            TimerId::Nak => self.handle_nak_timer(now),
            TimerId::RetransmitContinue => {
                let more_acked = self
                    .sender
                    .as_mut()
                    .is_some_and(SenderBuffer::release_acked_packets);
                if self.state == ConnectionState::Connected {
                    self.continue_pending_naks(now);
                    self.process_retransmit(now);
                } else if more_acked {
                    self.arm_retransmit_continue(0);
                }
            }
            TimerId::DeliveryContinue => {
                if self.state != ConnectionState::Disconnected {
                    if std::mem::take(&mut self.receive_expiry_continues) {
                        self.service_receive_deadlines(now);
                    } else {
                        self.enqueue_ready_data(now);
                    }
                    self.finish_peer_shutdown_if_drained();
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
            } else if self.role == ConnectionRole::Listener {
                // A listener answers each request once, as libsrt does
                // (core.cpp:11769-11810); the caller's retransmissions drive
                // any repeat. Resending unprompted would reflect ~12 replies
                // per (possibly forged) request at the claimed source.
                self.arm_handshake_deadline(now);
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
    ///
    /// TLPKTDROP gives up only the gap at the head of the receiver
    /// ([`ReceiverBuffer::drop_too_late`]), so expiry alternates with delivery
    /// the way libsrt's TSBPD thread alternates with its reader
    /// (core.cpp:5669-5703): deliver what is ready, give up the head gap if
    /// its successor is due, deliver what that released, and so on. One
    /// visit gives up at most `MAX_EXPIRED_GAPS_PER_VISIT` gaps and moves at
    /// most `MAX_DELIVERY_PER_VISIT` packets; a visit cut by either budget
    /// continues on a zero-delay `DeliveryContinue` instead of a tick later.
    fn service_receive_deadlines(&mut self, now: Timestamp) {
        if !self.tlpktdrop_enabled() {
            self.enqueue_ready_data(now);
            return;
        }
        let mut budget = MAX_DELIVERY_PER_VISIT;
        let mut gaps = 0;
        loop {
            budget -= self.pop_ready_data(now, budget);
            if budget == 0 || gaps == MAX_EXPIRED_GAPS_PER_VISIT {
                break;
            }
            let Some(gap) = self
                .receiver
                .as_mut()
                .and_then(|receiver| receiver.drop_too_late(now))
            else {
                break;
            };
            gaps += 1;
            // Expiry also retires the positions from the sender's span.
            if let Some(sender) = self.sender.as_mut() {
                sender.discard_acked_within(gap.first_seq, gap.last_seq);
            }
            self.discard_assembly_behind_frontier();
        }
        self.reclaim_retired_assembly();
        self.continue_acked_release_later();
        let cut = budget == 0 || gaps == MAX_EXPIRED_GAPS_PER_VISIT;
        self.receive_expiry_continues |= cut;
        self.continue_delivery_if_cut(cut);
    }

    /// TLPKTDROP moves the receive frontier past positions that can never
    /// arrive, so a message whose first fragment is now behind that frontier
    /// can never be completed either: retire it instead of holding the
    /// connection open on it.
    fn discard_assembly_behind_frontier(&mut self) {
        if let Some(receiver) = self.receiver.as_ref() {
            self.assembler.discard_before(receiver.expected_sequence());
        }
    }

    fn handle_ack_timer(&mut self, now: Timestamp) {
        if self.state != ConnectionState::Connected {
            return;
        }
        // Packets a DROPREQ or forced advance removed are released one
        // bounded visit per tick even when no DATA arrives to do it.
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.release_retired_packets();
        }
        self.service_receive_deadlines(now);
        // An unacknowledged key rotation is serviced here rather than by a
        // timer of its own: this tick is already the connection's periodic
        // service point (TSBPD, TLPKTDROP, deferred peer close), it is armed
        // for the whole connected lifetime, and a retry landing a few
        // milliseconds late is irrelevant at a one-second cadence.
        self.service_km_retry(now);
        if self.state != ConnectionState::Connected {
            return;
        }
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

        self.service_sender_deadlines(now);

        self.queue_output(QueuedOutput::SetTimer {
            id: TimerId::Ack,
            duration_micros: self.ack_timer_tick_micros(),
        });
    }

    fn service_sender_deadlines(&mut self, now: Timestamp) {
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
        // Retiring notified drops may leave acknowledged pages to release.
        self.continue_acked_release_later();
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
        let remaining = self.inactivity_remaining(now);
        if remaining > 0 {
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::Inactivity,
                duration_micros: remaining,
            });
            return;
        }
        if self.peer_shutdown_at.is_none() {
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
        if self.state != ConnectionState::Connected {
            return;
        }
        // A due unread head is also pending delivery, not an impossible
        // tail: the visit budget may have stopped inside a complete
        // fragmented message before it produced an application event.
        // Queued application DATA is progress, not a stalled drain. Revisit
        // expiry after continuation work or application polling: that work
        // can expose an incomplete tail which ACK ticks cannot close.
        if self.pending_data_events != 0
            || self.receive_expiry_continues
            || self
                .receiver
                .as_ref()
                .is_some_and(|receiver| receiver.has_ready_data(now))
        {
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::Inactivity,
                duration_micros: self.ack_timer_tick_micros(),
            });
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

    /// How long until the inactivity timer acts: one inactivity timeout
    /// after the last packet received, and for a peer that closed its send
    /// half no later than one inactivity timeout after its SHUTDOWN. Its
    /// KEEPALIVEs still count as received, but must not hold an undrainable
    /// half-close open forever: the drain is bounded as if the peer had gone
    /// silent at its SHUTDOWN (libsrt gives a broken socket a fixed
    /// countdown, `m_iBrokenCounter`).
    fn inactivity_remaining(&self, now: Timestamp) -> u64 {
        let since = |at: Option<Timestamp>| {
            at.map_or(INACTIVITY_TIMEOUT_MICROS, |at| {
                now.as_micros().saturating_sub(at.as_micros())
            })
        };
        let quiet = since(self.last_recv_time);
        let closing = self
            .peer_shutdown_at
            .map_or(0, |shutdown| since(Some(shutdown)));
        INACTIVITY_TIMEOUT_MICROS.saturating_sub(quiet.max(closing))
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
        self.send_shared_internal(payload, None, now, now)
    }

    /// Send shared payload with a caller-supplied SRT sequence number.
    pub fn send_shared_with_sequence(
        &mut self,
        payload: Bytes,
        sequence_number: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.send_shared_internal(payload, Some(sequence_number), now, now)
    }

    /// Replay group DATA with its original source time in this leg's clock,
    /// while admission, pacing, encryption and service use the current time.
    pub(crate) fn send_shared_with_sequence_at(
        &mut self,
        payload: Bytes,
        sequence_number: u32,
        source_time: Timestamp,
        now: Timestamp,
    ) -> Result<(), Error> {
        self.send_shared_internal(payload, Some(sequence_number), source_time, now)
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
    ///
    /// In live (TSBPD) mode this is an srt-rs extension: libsrt's sender
    /// refuses such a message (`MN_XSIZE`, `core.cpp:7003-7011`). A libsrt
    /// receiver still reassembles it (`CRcvBuffer::updateNonreadPos` and
    /// `readMessage`, `buffer_rcv.cpp`), but its application must read with
    /// a buffer that holds the whole message, or libsrt truncates it.
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
        source_time: Timestamp,
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

        let timestamp = self.relative_timestamp(source_time);
        let peer_socket_id = self.peer_socket_id;

        let packet = {
            let sender = self
                .sender
                .as_mut()
                .ok_or_else(|| Error::invalid_state("sender buffer not initialized"))?;
            match sequence_number {
                Some(seq) => sender.push_shared_with_sequence(
                    payload,
                    timestamp,
                    peer_socket_id,
                    source_time,
                    seq,
                ),
                None => sender.push_shared(payload, timestamp, peer_socket_id, source_time),
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
        self.queue_first_transmission(header, payload, Some(source_time.as_micros()), now)?;
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
        if self.initial_tx_pending() {
            return Err(Error::invalid_state(
                "directional encryption key is not confirmed",
            ));
        }
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

    /// The receive base negotiated by the handshake, before any local drop.
    pub(crate) fn peer_initial_sequence(&self) -> Option<u32> {
        self.peer_initial_seq
    }

    /// The sender half, for a bonded group's Backup bookkeeping.
    pub(crate) fn sender_buffer(&self) -> Option<&SenderBuffer> {
        self.sender.as_ref()
    }

    /// When this connection last received any packet from its peer.
    pub(crate) fn last_recv_time(&self) -> Option<Timestamp> {
        self.last_recv_time
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
            #[cfg(any(test, feature = "test-support"))]
            if let Some(checker) = self.wire_checker.as_deref_mut() {
                checker.note_send_sequence_override(sequence_number);
            }
            Ok(())
        } else {
            Err(Error::invalid_state("sender buffer has in-flight packets"))
        }
    }

    /// Whether sending is possible (window space and confirmed TX key).
    pub fn can_send(&self) -> bool {
        !self.initial_tx_pending() && self.sender.as_ref().is_some_and(|s| s.can_send())
    }

    /// Whether sending is possible, including packet pacing.
    pub fn can_send_with_pacing(&self, now: Timestamp) -> bool {
        !self.initial_tx_pending()
            && self
                .sender
                .as_ref()
                .is_some_and(|s| s.can_send_with_pacing(now))
    }

    pub(crate) fn initial_tx_pending(&self) -> bool {
        self.km_control
            .as_ref()
            .is_some_and(|state| state.initial_tx_pending)
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

    pub(crate) fn poll_event_for_group(
        &mut self,
        now: Timestamp,
        budget: &mut usize,
    ) -> (Option<ConnectionEvent>, bool) {
        let event = self.poll_event_inner(true);
        let live = matches!(
            self.state,
            ConnectionState::Connected | ConnectionState::Closing
        );
        if live {
            // One budget covers every member's raw delivery and retired
            // assembly, including refilling a slot freed by a duplicate.
            let reclaimed = self.assembler.reclaim_retired(*budget);
            *budget -= reclaimed;
            if reclaimed != 0 {
                self.sync_application_backlog();
            }
            *budget -= self.pop_ready_data(now, *budget);
            self.continue_delivery_if_cut(*budget == 0);
            self.apply_pending_group_receive_time();
            self.finish_peer_shutdown_if_drained();
        }
        let event = event.or_else(|| self.poll_event_inner(true));
        let continuation = live
            && (self.assembler.has_retired()
                || (!self.initial_tx_pending()
                    && self.pending_data_events < self.options.delivery_queue_packets
                    && self
                        .receiver
                        .as_ref()
                        .is_some_and(|receiver| receiver.has_ready_data(now))));
        (event, continuation)
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
                // Test-only strict wire check of exactly the bytes that leave
                // the protocol, before any fixture loss or rewrite.
                #[cfg(any(test, feature = "test-support"))]
                crate::test_support::wire_checker::observe_emitted(
                    self.wire_checker.as_deref_mut(),
                    &dst[..written],
                    self.peer_ip,
                );
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
                // Likewise the one point where the sender learns a DROPREQ
                // actually reached the wire: a peer cannot have learned of a
                // drop from one still sitting queued (see
                // `SenderBuffer::note_dropreq_submitted`).
                let dropreq_range = dropreq_range(pkt);
                self.waiting_replies.sent(pkt);
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
                if let Some((first, last)) = dropreq_range
                    && let Some(sender) = self.sender.as_mut()
                {
                    sender.note_dropreq_submitted(first, last);
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
                self.waiting_replies.timer_sent(id);
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
            self.move_ready_data(now, usize::MAX);
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
    ///
    /// Walks the receive buffer (buffered bytes and delivery span), so it
    /// costs O(packets buffered). [`Self::receiver_loss_counters`] reads the
    /// cumulative loss and duplicate counts in O(1).
    pub fn receiver_stats(&self) -> Option<crate::srt_receiver::ReceiverStats> {
        self.receiver.as_ref().map(|r| r.stats())
    }

    /// The receiver's cumulative loss and duplicate counts, in O(1). `None`
    /// before the connection has a receive direction.
    #[must_use]
    pub fn receiver_loss_counters(&self) -> Option<crate::srt_receiver::ReceiverLossCounters> {
        self.receiver.as_ref().map(|r| r.loss_counters())
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
        if self.state != ConnectionState::Connected {
            return Err(Error::invalid_state("not connected"));
        }
        if self
            .km_control
            .as_ref()
            .is_some_and(|state| state.pending.is_some())
        {
            return Err(Error::invalid_state(
                "a key-material request is already awaiting its response",
            ));
        }
        let Some(crypto) = &mut self.crypto else {
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
        let state = self
            .km_control
            .get_or_insert_with(|| Box::new(KmControlState::default()));
        state.pending = Some(PendingKmRequest {
            request: km_message,
            next_retry: now.add_micros(KM_REQUEST_RETRY_INTERVAL_MICROS),
            retries_left: Some(KM_REQUEST_MAX_RETRIES),
        });

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

    pub(crate) fn group_time(&self) -> Option<GroupTime> {
        Some(GroupTime {
            start: self.start_time?,
            receive: self.receiver.as_ref()?.group_time(),
        })
    }

    pub(crate) fn inherit_group_time(&mut self, time: GroupTime) {
        self.start_time = Some(time.start);
        if self
            .pending_group_receive_time
            .is_none_or(|pending| time.receive.phase() >= pending.phase())
        {
            self.pending_group_receive_time = Some(time.receive);
        }
        self.apply_pending_group_receive_time();
    }

    fn apply_pending_group_receive_time(&mut self) {
        let (Some(time), Some(receiver)) = (self.pending_group_receive_time, &mut self.receiver)
        else {
            return;
        };
        if time.phase() > receiver.group_time().phase()
            && (!receiver.group_clock_drained() || self.assembler.pending_packet_count() != 0)
        {
            return;
        }
        receiver.inherit_group_time(time);
        self.pending_group_receive_time = None;
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
    ///
    /// One call moves at most `MAX_DELIVERY_PER_VISIT` packets. A receiver
    /// that released a whole window at once (a filled gap, a TLPKTDROP, an
    /// application read freeing the queue) would otherwise move the window in
    /// one callback on the Owner thread. The remainder is continued by a
    /// zero-delay `DeliveryContinue` visit, like `RetransmitContinue`.
    fn enqueue_ready_data(&mut self, now: Timestamp) {
        self.move_ready_data(now, MAX_DELIVERY_PER_VISIT);
    }

    /// Move up to `cap` ready packets (and never more than the application
    /// queue admits). `disconnect` passes no cap: the peer's SHUTDOWN answer
    /// or its next DATA ends `Closing` at once, before any continuation
    /// visit, so a local close delivers its whole buffered tail in the call
    /// that releases it -- once per connection.
    fn move_ready_data(&mut self, now: Timestamp, cap: usize) {
        self.reclaim_retired_assembly();
        let popped = self.pop_ready_data(now, cap);
        self.continue_delivery_if_cut(popped == cap);
        self.apply_pending_group_receive_time();
    }

    /// Release one visit's budget of a retired partial message.
    fn reclaim_retired_assembly(&mut self) {
        if self.assembler.has_retired() {
            self.assembler.reclaim_retired(MAX_DELIVERY_PER_VISIT);
            self.sync_application_backlog();
        }
    }

    /// Pop up to `cap` ready packets into the application queue (never more
    /// than it admits) and return how many were popped.
    fn pop_ready_data(&mut self, now: Timestamp, cap: usize) -> usize {
        if self.initial_tx_pending() {
            return 0;
        }
        let available = self
            .options
            .delivery_queue_packets
            .saturating_sub(self.pending_data_events) as usize;
        if available == 0 {
            return 0;
        }

        let visit = available.min(cap);
        let mut popped = 0;
        while popped < visit {
            let Some((packet, source_time)) = self
                .receiver
                .as_mut()
                .and_then(|receiver| receiver.pop_ready_with_source_time(now))
            else {
                break;
            };
            popped += 1;
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
        popped
    }

    /// Arm a zero-delay `DeliveryContinue` when a visit was cut by its cap
    /// (not by the queue or the receiver) or a retired partial message is
    /// still being released. A spurious visit finds nothing ready and does
    /// nothing.
    fn continue_delivery_if_cut(&mut self, cut: bool) {
        if (cut || self.assembler.has_retired()) && !self.event_overflowed {
            self.queue_output(QueuedOutput::SetTimer {
                id: TimerId::DeliveryContinue,
                duration_micros: 0,
            });
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
        if self.peer_shutdown_at.is_some() {
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

        // The window-payload reservation (`window_memory_bound_bytes`) charges
        // one retained packet at the constant ceiling, `DEFAULT_MTU -
        // SRT_HEADER_SIZE`, so that is the bound to enforce here, not the
        // negotiated one: `apply_peer_mss` derives its value from this side's
        // view of the path, and a peer behind NAT64 or SIIT may legitimately
        // see a larger family and keep sending up to the constant. A peer that
        // exceeds the constant instead could retain more payload than the
        // reservation charged for it, so that is a protocol violation rather
        // than a loss.
        if pkt.payload.len() > DEFAULT_MTU as usize - SRT_HEADER_SIZE {
            return Err(Error::invalid_state(
                "DATA payload exceeds the constant payload ceiling",
            ));
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

    /// Handle a control packet. Returns whether it proved peer activity.
    fn handle_control_packet(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<bool, Error> {
        tracing::debug!(
            "received control packet, type={:?}, info_len={}",
            pkt.control_type,
            pkt.control_info.len()
        );
        if self.state == ConnectionState::Closing && pkt.control_type != ControlType::Shutdown {
            self.finish_local_close(DisconnectReason::PeerActivityAfterShutdown);
            return Ok(true);
        }
        validate_control_information(&pkt)?;
        match pkt.control_type {
            ControlType::Handshake => self.handle_handshake(pkt, now),
            ControlType::Keepalive => {
                self.handle_keepalive(&pkt);
                Ok(())
            }
            ControlType::Ack => self.handle_ack(pkt, now),
            ControlType::Nak => return self.handle_nak(pkt, now),
            ControlType::Shutdown => self.handle_shutdown(now),
            ControlType::AckAck => self.handle_ackack(pkt, now),
            ControlType::UserDefined => self.handle_user_defined(pkt, now),
            ControlType::DropReq => self.handle_drop_req(pkt, now),
            ControlType::CongestionWarning | ControlType::PeerError => Ok(()),
        }
        .map(|()| true)
    }

    /// A KEEPALIVE's timestamp still tracks the peer clock across the TSBPD
    /// wrap while DATA pauses (libsrt core.cpp:12673).
    fn handle_keepalive(&mut self, pkt: &ControlPacket) {
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.handle_keepalive(pkt.timestamp);
        }
    }

    fn handle_handshake(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        if self.handshake_timed_out(now) {
            self.fail_handshake_timeout();
            return Ok(());
        }
        let hs = HandshakePacket::decode(&pkt)?;

        // A completed connection can receive a retransmitted CONCLUSION
        // (the peer may have missed its response), but a late REJECTION or
        // new INDUCTION must not roll an established session back or cause
        // it to retransmit a handshake for an unrelated peer. Check identity
        // before either role's completed-handshake branch queues output.
        if self.handshake_state == HandshakeState::Completed
            && (hs.handshake_type != HandshakeType::Conclusion
                || hs.version != HS_VERSION_5
                || hs.socket_id != self.peer_socket_id
                || hs.syn_cookie != self.syn_cookie
                || hs.initial_packet_seq != self.initial_seq)
        {
            return Err(Error::invalid_data(
                "late handshake does not match the established session",
            ));
        }

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
        self.reject_unusable_peer_flow_window(&hs, now)?;

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
        self.km_control = Some(Box::new(KmControlState::default()));
        Ok(())
    }

    /// Either role must stop using the shared handshake key for TX:
    /// a legacy peer may still use that key for its own DATA.
    fn prepare_initial_directional_tx(&mut self, now: Timestamp) -> Result<(), Error> {
        let Some(crypto) = self.crypto.as_deref_mut() else {
            return Ok(());
        };
        let mut sek = Zeroizing::new(vec![0; crypto.key_length().len()]);
        Self::random_bytes(&mut sek, "directional stream encryption key")?;
        crypto.prepare_directional_tx(&sek)?;
        let request = KmMessage::new(
            crypto.current_key(),
            crypto.key_length(),
            *crypto.salt(),
            crypto.wrap_sek(crypto.current_key())?,
            crypto.cipher_mode(),
        );
        let state = self.km_control.get_or_insert_with(Box::default);
        state.initial_tx_pending = true;
        state.pending = Some(PendingKmRequest {
            request,
            next_retry: now.add_micros(KM_REQUEST_RETRY_INTERVAL_MICROS),
            retries_left: Some(KM_REQUEST_MAX_RETRIES),
        });
        Ok(())
    }

    fn announce_initial_tx(&mut self, now: Timestamp) {
        if let Some(request) = self
            .km_control
            .as_ref()
            .and_then(|state| state.pending.as_ref())
            .map(|pending| pending.request.clone())
        {
            self.send_km_request(&request, now);
        } else {
            self.queue_event(ConnectionEvent::Connected);
        }
    }

    /// Reject peer versions this HSv5-only implementation cannot negotiate.
    ///
    /// The reference requires HSv5 for SRT 1.3.0 and newer; an HSv5 packet
    /// claiming an older SRT version is malformed, while an HSv4 peer is
    /// below this implementation's minimum supported protocol version.
    fn reject_peer_hsv5_version(
        &mut self,
        hs: &HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        let rejection = if hs.version != HS_VERSION_5 {
            Some((
                SRT_REJ_VERSION,
                format!("peer handshake version {} is not HSv5", hs.version),
            ))
        } else {
            match hs.get_hs_extension() {
                Some(extension) if extension.srt_version >= MIN_HSV5_SRT_VERSION => None,
                Some(extension) => Some((
                    SRT_REJ_ROGUE,
                    format!(
                        "HSv5 requires SRT version 1.3.0 or newer, got {:#08x}",
                        extension.srt_version
                    ),
                )),
                None => Some((
                    SRT_REJ_ROGUE,
                    "HSv5 conclusion has no HS extension".to_owned(),
                )),
            }
        };
        let Some((reason_code, reason)) = rejection else {
            return Ok(());
        };
        match self.role {
            ConnectionRole::Caller => Err(self.fail_caller_handshake(&reason)),
            ConnectionRole::Listener => {
                self.reject(reason_code, now)?;
                Err(Error::handshake_rejected(reason))
            }
        }
    }

    /// Reject an unusable advertised flow window before committing handshake
    /// state. The listener's INDUCTION path validates separately because it
    /// has not yet received the SYN cookie needed for a rejection response.
    fn reject_unusable_peer_flow_window(
        &mut self,
        hs: &HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        if Self::peer_flow_window_is_usable(hs.flow_window) {
            return Ok(());
        }
        let reason = "peer flow window must be between 2 and i32::MAX packets";
        match self.role {
            ConnectionRole::Caller => Err(self.fail_caller_handshake(reason)),
            ConnectionRole::Listener => {
                self.reject(SRT_REJ_ROGUE, now)?;
                Err(Error::handshake_rejected(reason))
            }
        }
    }

    /// Reject a handshake whose advertised MSS this connection cannot
    /// negotiate, before any of its fields are committed.
    ///
    /// Bounds and their derivation live in
    /// [`HandshakePacket::peer_mss_rejection_reason`]. The rejection shape
    /// follows the pinned reference: a caller fails its attempt with
    /// `SRT_REJ_ROGUE` (`CUDT::processConnectResponse` aborts on an
    /// over-large MSS), and a listener answers with an `SRT_REJ_ROGUE`
    /// rejection response while staying able to serve other peers
    /// (`CUDT::acceptAndRespond` on an under-sized one).
    fn reject_peer_mss(&mut self, hs: &HandshakePacket, now: Timestamp) -> Result<(), Error> {
        let min_payload = self.min_negotiated_payload(hs) as u32;
        let Some(reason) = hs.peer_mss_rejection_reason(self.ip_family, min_payload) else {
            return Ok(());
        };
        match self.role {
            ConnectionRole::Caller => Err(self.fail_caller_handshake(&reason)),
            ConnectionRole::Listener => {
                // `reject` refuses a handshake it was not waiting for; this
                // path only runs while awaiting the CONCLUSION.
                self.reject(SRT_REJ_ROGUE, now)?;
                Err(Error::handshake_rejected(reason))
            }
        }
    }

    /// Apply the peer's advertised MSS to this connection's outbound DATA
    /// budget.
    ///
    /// The handshake MTU field is an IP-layer MTU for every reference
    /// implementation, so the peer's receive ceiling for an SRT datagram is
    /// `mss - ip_udp_overhead`; this core's own advertised value is a
    /// datagram budget, which is the other side of the `min`. A peer that
    /// advertised 1500 on an IPv4 path therefore negotiates 1456 bytes of
    /// payload -- exactly libsrt's own `mss - (UDP_HDR_SIZE + HDR_SIZE)` --
    /// instead of this core's local 1484, which a libsrt peer's receive
    /// buffer would truncate.
    fn apply_peer_mss(&mut self, hs: &HandshakePacket) {
        let negotiated_datagram = DEFAULT_MTU.min(hs.peer_max_datagram_size(self.ip_family));
        // Clamped rather than asserted: `reject_peer_mss` is the gate that
        // fails such a peer closed, and this second bound keeps a future
        // path that skipped it from reaching `NakChunkEncoder`'s
        // `max_control_info_size >= MAX_NAK_RECORD_SIZE` precondition.
        self.max_payload_size = (negotiated_datagram as usize)
            .saturating_sub(SRT_HEADER_SIZE)
            .max(MIN_NEGOTIATED_PAYLOAD_SIZE);
    }

    /// Smallest raw DATA payload this connection can operate with: room
    /// for a NAK loss record, and under GCM room for the authentication tag
    /// plus one byte of application data, so a negotiated session can always
    /// carry DATA (`effective_max_payload_size` subtracts the tag).
    fn min_negotiated_payload(&self, hs: &HandshakePacket) -> usize {
        if self.handshake_cipher(hs) == Some(CipherMode::Gcm) {
            MIN_NEGOTIATED_PAYLOAD_SIZE.max(GCM_TAG_LEN + 1)
        } else {
            MIN_NEGOTIATED_PAYLOAD_SIZE
        }
    }

    /// The cipher this handshake negotiates. It is already known when the
    /// CONCLUSION is checked: the caller built its crypto context (or
    /// configured one) before sending, and a listener reads it from the
    /// peer's KMREQ.
    fn handshake_cipher(&self, hs: &HandshakePacket) -> Option<CipherMode> {
        match self.role {
            ConnectionRole::Caller => match self.crypto.as_deref() {
                Some(crypto) => Some(crypto.cipher_mode()),
                None => self
                    .options
                    .passphrase
                    .is_some()
                    .then_some(self.options.cipher_mode),
            },
            ConnectionRole::Listener => hs
                .get_km_request()
                .and_then(Result::ok)
                .and_then(|km| CipherMode::from_km(&km)),
        }
    }

    /// Refuse an AES-GCM session in which either side advertises SRT 1.5.3
    /// or older. libsrt selects its legacy GCM nonce/AAD layout for such a
    /// peer (`core.cpp:6295-6303`, `crypto.cpp:184,500-504`), which this
    /// implementation does not support, so the session would fail to
    /// decrypt. A listener answers `SRT_REJ_CRYPTO`, libsrt's code for
    /// conflicting cryptographic configurations.
    fn reject_legacy_gcm_peer(
        &mut self,
        hs: &HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.handshake_cipher(hs) != Some(CipherMode::Gcm) {
            return Ok(());
        }
        let peer_legacy = hs
            .get_hs_extension()
            .is_some_and(|extension| extension.srt_version <= LEGACY_GCM_MAX_SRT_VERSION);
        if !peer_legacy && self.options.srt_version > LEGACY_GCM_MAX_SRT_VERSION {
            return Ok(());
        }
        Err(self.refuse_peer(
            SRT_REJ_CRYPTO,
            "AES-GCM with an SRT 1.5.3-or-older advertisement selects libsrt's legacy GCM \
             layout, which this implementation does not support",
            now,
        ))
    }

    /// Whether the configured congestion name is one a libsrt peer accepts:
    /// 1 to 16 bytes (`CSrtConfig::MAX_CONG_LENGTH`; `interpretSrtHandshake`
    /// refuses any other, core.cpp:3001-3007).
    fn congestion_name_is_emittable(&self) -> bool {
        (1..=MAX_CONGESTION_NAME_BYTES).contains(&self.options.congestion_control.len())
    }

    /// A listener whose own congestion name libsrt would refuse does not
    /// answer with it: it refuses the caller with `SRT_REJ_CONGESTION`. (A
    /// caller refuses such a name in `connect`, before sending anything.)
    fn reject_unemittable_congestion(&mut self, now: Timestamp) -> Result<(), Error> {
        if self.congestion_name_is_emittable() {
            return Ok(());
        }
        Err(self.refuse_peer(
            SRT_REJ_CONGESTION,
            "configured congestion_control is not 1 to 16 bytes, the names libsrt accepts",
            now,
        ))
    }

    /// A listener answers a GROUP request with its own GROUP extension; one
    /// libsrt would refuse (configured through `ConnectionOptions`) is not
    /// emitted: the caller is refused with `SRT_REJ_GROUP`.
    fn reject_invalid_own_group(
        &mut self,
        hs: &HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        let answers_group = hs.get_group_extension().is_some();
        if !answers_group
            || self
                .options
                .group_extension
                .is_none_or(|group| group.is_valid_for_libsrt())
        {
            return Ok(());
        }
        Err(self.refuse_peer(
            SRT_REJ_GROUP,
            "configured GROUP extension is one libsrt refuses",
            now,
        ))
    }

    /// Reject a handshake in which the peer negotiates packet-filter
    /// behaviour this implementation does not provide.
    ///
    /// Silently skipping the FILTER extension would establish a session whose
    /// two peers disagree about whether recovery filtering exists: the peer
    /// would expect filtered recovery while this side neither filters nor
    /// implements the filter's own protocol. The reference implementation
    /// refuses an unhonourable filter negotiation with `SRT_REJ_FILTER`
    /// rather than approximating it, so this does the same, in the same shape
    /// as [`Self::reject_peer_mss`].
    fn reject_unsupported_packet_filter(
        &mut self,
        hs: &HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        if !hs.has_filter_extension() {
            return Ok(());
        }
        let reason = "peer negotiated a packet filter this implementation does not support";
        match self.role {
            ConnectionRole::Caller => Err(self.fail_caller_handshake(reason)),
            ConnectionRole::Listener => {
                self.reject(SRT_REJ_FILTER, now)?;
                Err(Error::handshake_rejected(reason))
            }
        }
    }

    /// Refuse the handshake in progress: a caller fails its attempt, a
    /// listener answers with an HSv5 rejection carrying `reason_code`.
    fn refuse_peer(&mut self, reason_code: i32, reason: &str, now: Timestamp) -> Error {
        match self.role {
            ConnectionRole::Caller => self.fail_caller_handshake(reason),
            ConnectionRole::Listener => match self.reject(reason_code, now) {
                Ok(()) => Error::handshake_rejected(reason),
                Err(error) => error,
            },
        }
    }

    /// Reject a peer whose HS extension declares the other transmission
    /// API: STREAM set means the stream (file) API, clear the message
    /// (live) API. libsrt refuses the mismatch with `SRT_REJ_MESSAGEAPI`
    /// (`processSrtMsg_HSREQ`) instead of running a session in which the
    /// two peers disagree about message boundaries.
    fn reject_message_api_mismatch(
        &mut self,
        hs: &HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        let Some(extension) = hs.get_hs_extension() else {
            return Ok(());
        };
        let peer_stream = extension.srt_flags & srt_flags::STREAM != 0;
        let local_stream = self.negotiated_srt_flags() & srt_flags::STREAM != 0;
        if peer_stream == local_stream {
            return Ok(());
        }
        let reason = if local_stream {
            "peer declares the message API but this side uses the stream (file) API"
        } else {
            "peer declares the stream API but this side uses the message (live) API"
        };
        Err(self.refuse_peer(SRT_REJ_MESSAGEAPI, reason, now))
    }

    /// Refuse a peer that does not advertise REXMITFLG.
    ///
    /// Without it, DATA bit 26 is part of a legacy 27-bit message number
    /// instead of the retransmission flag this implementation always sets
    /// and decodes. libsrt has advertised it unconditionally in every HSREQ
    /// since 1.2.0 and echoes it in its HSRSP to a requester that sent it
    /// (`fillSrtHandshake_HSREQ`, `fillSrtHandshake_HSRSP`), so every
    /// peer at the 1.3.0 HSv5 floor carries it; one that omits it is
    /// inconsistent with its own version, refused with `SRT_REJ_ROGUE` as
    /// an HSv5 peer claiming a pre-1.3.0 version is.
    fn reject_peer_without_rexmit_flag(
        &mut self,
        hs: &HandshakePacket,
        now: Timestamp,
    ) -> Result<(), Error> {
        if hs
            .get_hs_extension()
            .is_none_or(|extension| extension.srt_flags & srt_flags::REXMITFLG != 0)
        {
            return Ok(());
        }
        Err(self.refuse_peer(
            SRT_REJ_ROGUE,
            "peer does not advertise REXMITFLG, which every SRT 1.3.0+ peer does",
            now,
        ))
    }

    /// A caller that asked for group membership requires the listener's
    /// mirror GROUP extension: one that omits it did not understand the
    /// group, and libsrt's bonded initiator refuses it with `SRT_REJ_GROUP`
    /// (`interpretSrtHandshake`) rather than running the leg ungrouped. A
    /// caller that sent no GROUP is unaffected.
    fn reject_missing_group_response(&mut self, hs: &HandshakePacket) -> Result<(), Error> {
        if self.options.group_extension.is_none() || hs.get_group_extension().is_some() {
            return Ok(());
        }
        Err(self.fail_caller_handshake(
            "peer did not answer this caller's GROUP extension (SRT_REJ_GROUP)",
        ))
    }

    /// Refuse a CONCLUSION response that does not carry this caller's ISN.
    /// A libsrt caller fails its connect with `MN_SECURITY` on that
    /// mismatch (core.cpp:4085-4086), sending nothing to the listener. The
    /// INDUCTION response is not checked: libsrt takes only its cookie,
    /// version and type (`processConnectResponse`).
    fn reject_foreign_response_isn(&mut self, hs: &HandshakePacket) -> Result<(), Error> {
        if hs.initial_packet_seq == self.initial_seq {
            return Ok(());
        }
        Err(self.fail_caller_handshake(
            "CONCLUSION response ISN is not the caller's (libsrt MN_SECURITY)",
        ))
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

        self.reject_peer_hsv5_version(&hs, now)?;
        self.reject_unusable_peer_flow_window(&hs, now)?;
        self.reject_peer_mss(&hs, now)?;
        self.reject_unsupported_packet_filter(&hs, now)?;
        self.reject_message_api_mismatch(&hs, now)?;
        self.reject_peer_without_rexmit_flag(&hs, now)?;
        self.reject_legacy_gcm_peer(&hs, now)?;
        self.reject_missing_group_response(&hs)?;
        self.reject_foreign_response_isn(&hs)?;
        self.apply_peer_mss(&hs);

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
        self.prepare_initial_directional_tx(now)?;

        self.handshake_state = HandshakeState::Completed;
        self.handshake_started_at = None;
        self.set_state(ConnectionState::Connected);
        // `start_time` stays the epoch `connect` stamped: the INDUCTION and
        // CONCLUSION already carried it, and the listener's TSBPD base is
        // derived from that CONCLUSION timestamp (libsrt stamps its start
        // time once, when the socket opens).

        let tsbpd_time_base = now.as_micros() as i64 - i64::from(hsreq_timestamp);
        self.init_buffers(now, hs.initial_packet_seq, tsbpd_time_base);

        self.queue_output(QueuedOutput::ClearTimer {
            id: TimerId::Handshake,
        });
        self.setup_connection_timers();
        self.clear_config_secrets();
        self.announce_initial_tx(now);
        Ok(())
    }

    fn validate_caller_kmrsp(&mut self, hs: &HandshakePacket) -> Result<(), Error> {
        match (self.crypto.is_some(), hs.get_km_response()) {
            (true, Ok(Some(response))) => {
                let Some(state) = self.km_control.as_deref_mut().filter(|state| {
                    state
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.request == response)
                }) else {
                    return Err(self
                        .fail_caller_handshake("KMRSP does not match the caller's pending KMREQ"));
                };
                state.pending = None;
                state.acknowledged.remember(response);
                Ok(())
            }
            (false, Ok(None)) => Ok(()),
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
        if !Self::peer_flow_window_is_usable(hs.flow_window) {
            return Err(Error::invalid_data(
                "peer flow window must be between 2 and i32::MAX packets",
            ));
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
        self.send_induction_response(hs.initial_packet_seq, now);
        self.handshake_state = HandshakeState::InductionReceived;
        self.arm_handshake_deadline(now);
        Ok(())
    }

    /// Start a listener handshake at its CONCLUSION. The INDUCTION was
    /// answered without connection state, with a SYN cookie the caller of
    /// this method has already verified and passed as
    /// [`ConnectionOptions::syn_cookie`]; libsrt likewise keeps nothing
    /// before a CONCLUSION whose cookie checks out (core.cpp:11755-11850).
    /// The CONCLUSION from `peer_socket_id` is then fed as usual. The
    /// session clock starts here, as libsrt's accepted socket's does, so
    /// the CONCLUSION response's timestamp gives the caller its TSBPD base.
    pub fn begin_listener_handshake_at_conclusion(
        &mut self,
        peer_socket_id: u32,
        now: Timestamp,
    ) -> Result<(), Error> {
        if self.role != ConnectionRole::Listener || self.handshake_state != HandshakeState::Initial
        {
            return Err(Error::invalid_state(
                "a stateless listener handshake starts on a fresh listener",
            ));
        }
        self.peer_socket_id = peer_socket_id;
        self.syn_cookie = self.options.syn_cookie.unwrap_or(0);
        self.handshake_started_at = Some(now);
        self.handshake_retry_sequence = 0;
        self.start_time.get_or_insert(now);
        self.handshake_state = HandshakeState::InductionReceived;
        self.arm_handshake_deadline(now);
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
        self.reject_peer_hsv5_version(&hs, now)?;
        self.reject_unusable_peer_flow_window(&hs, now)?;

        self.reject_peer_mss(&hs, now)?;
        self.reject_unsupported_packet_filter(&hs, now)?;
        self.reject_message_api_mismatch(&hs, now)?;
        self.reject_peer_without_rexmit_flag(&hs, now)?;
        self.reject_legacy_gcm_peer(&hs, now)?;
        self.reject_unemittable_congestion(now)?;
        self.reject_invalid_own_group(&hs, now)?;
        self.apply_peer_mss(&hs);
        self.note_peer_flow_window(hs.flow_window);

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
            // The handshake's initial KM announces one key; a both-key
            // message only appears in a runtime refresh.
            let (Some(cipher_mode), Some(key_flag)) = (CipherMode::from_km(&km), km.keys.single())
            else {
                return Err(self.fail_listener_km(
                    now,
                    KmError::BadSecret,
                    "inconsistent cipher/auth fields or key selection in KMREQ",
                ));
            };
            let crypto = match CryptoContext::new_receiver(
                &passphrase,
                km.salt,
                &km.wrapped_key,
                key_flag,
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
            self.km_control = Some(Box::new(KmControlState::default()));
            self.prepare_initial_directional_tx(now)?;
            self.received_km = Some(Box::new(km));
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
        // The KMREQ was already recorded into the replay history when the
        // context was constructed; here it is only released, since the
        // response has echoed it.
        self.received_km = None;
        self.handshake_state = HandshakeState::Completed;
        self.handshake_started_at = None;
        self.set_state(ConnectionState::Connected);

        let tsbpd_time_base = now.as_micros() as i64 - i64::from(hsreq_timestamp);
        self.init_buffers(now, hs.initial_packet_seq, tsbpd_time_base);
        self.queue_output(QueuedOutput::ClearTimer {
            id: TimerId::Handshake,
        });
        self.setup_connection_timers();
        self.clear_config_secrets();
        self.announce_initial_tx(now);
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
        // this sender's peer-justified frontier covers. The *accepted*
        // frontier (`next_sequence_number`) is not the right bound here:
        // #118 established that accepted and submitted are different
        // states, and a peer cannot acknowledge DATA still sitting behind
        // this sender's own TX capacity. Nor is "actually submitted" alone
        // the right bound, as of round 3: a position whose DATA was never
        // submitted can still be peer-justified once the DROPREQ that
        // reports it as dropped has itself crossed the wire (see
        // `SenderBuffer::justified_frontier`), so `max_justified_ack_position`
        // -- DATA-or-DROPREQ submission, not DATA submission alone -- is the
        // actual bound. Treating a beyond-frontier position as merely "not
        // current" (as a stale/duplicate ACK is) would still let
        // `set_peer_window` below use it to compute an advertised window end
        // past that frontier, so it is rejected outright rather than
        // silently ignored.
        if let Some(sender) = self.sender.as_ref()
            && sequence_less_than(sender.max_justified_ack_position(), ack_seq)
        {
            return Err(Error::invalid_data(format!(
                "ACK names sequence {ack_seq}, beyond this sender's peer-justified frontier"
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
        self.continue_acked_release_later();
        // A queued DATA output for a sequence this ACK retired must not
        // survive it (see `purge_stale_queued_data`). An ACK that retired
        // nothing changed nothing that is live, so it skips the purge.
        self.purge_stale_queued_data_after_ack(ack_progressed);

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
            // receiving byte rate (28+ bytes) are a rate section this ACK
            // either carries in full or not at all -- a 16-byte Small ACK
            // has none, and `record_peer_feedback` preserves whatever rate
            // snapshot is already on file rather than zeroing it; a 24-byte
            // ACK replaces the snapshot but has no byte-rate field to give
            // it, represented honestly as `None` rather than a fabricated
            // zero.
            let rate_feedback = if pkt.control_info.len() >= 24 {
                let mut rates = &pkt.control_info[16..24];
                let receiving_rate_packets_per_second = crate::buf::read_u32(&mut rates)?;
                let link_capacity_packets_per_second = crate::buf::read_u32(&mut rates)?;
                let receiving_rate_bytes_per_second = if pkt.control_info.len() >= 28 {
                    Some(crate::buf::read_u32(&mut &pkt.control_info[24..28])?)
                } else {
                    None
                };
                Some(PeerRateFeedback {
                    receiving_rate_packets_per_second,
                    link_capacity_packets_per_second,
                    receiving_rate_bytes_per_second,
                })
            } else {
                None
            };
            sender.record_peer_feedback(
                rtt_micros,
                rtt_variance_micros,
                available_buffer_packets,
                rate_feedback,
            );
        }

        // ACKACK acknowledges receipt of any ACK that named an ACK number.
        // The draft's Full ACK (28 bytes) always does; the pinned Haivision
        // reference (`CUDT::sendCtrl`/`processCtrlAck`, `core.cpp`) also
        // assigns and acknowledges one for its numbered Small ACK (16 bytes)
        // and its 24/32-byte reference-Full variants. `type_specific_info`
        // is exactly that ACK number. libsrt's 31-bit ACK number rolls
        // through zero (`CAckNo::incack`), so a 24/28/32-byte ACK numbered 0
        // is acknowledged too; only the Light ACK and the draft's unnumbered
        // 16-byte form (number 0) carry none. (Originally found as upstream
        // shiguredo/srt-rs issue 0054, which only pinned the draft's own
        // `>= 28` rule -- not pinned Haivision's wider acknowledged set.)
        if ack_names_a_number(&pkt) {
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

    /// Handle a peer NAK. Returns whether the report proved peer activity:
    /// one too large for this visit proves it only once it validates, in
    /// `continue_pending_naks`.
    fn handle_nak(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<bool, Error> {
        let loss_ranges = parse_loss_ranges(&pkt.control_info)?;

        // The whole report is validated before any of it is applied; see
        // `SenderBuffer::receive_nak`. A position inside a message this
        // sender already gave up as too late is answered with the same
        // DROPREQ again -- the peer either lost the first one or still holds
        // the range -- and never with a retransmission of released media.
        let Some(sender) = self.sender.as_mut() else {
            return Ok(true);
        };
        let receipt = sender.receive_nak(loss_ranges, now).map_err(|_| {
            Error::invalid_data(
                "NAK reports a loss position this sender never sent or already retired",
            )
        })?;
        let NakReceipt::Applied(dropped) = receipt else {
            // Deferred: `process_retransmit` arms the continuation. Shed: the
            // peer's periodic NAK reports the losses again.
            self.process_retransmit(now);
            return Ok(false);
        };
        self.answer_drop_reqs(&dropped, now);

        // 即座に再送処理
        self.process_retransmit(now);

        Ok(true)
    }

    /// Continue queued peer loss reports for one visit.
    fn continue_pending_naks(&mut self, now: Timestamp) {
        let Some(sender) = self.sender.as_mut() else {
            return;
        };
        if !sender.has_pending_nak() {
            return;
        }
        let progress = sender.continue_naks();
        self.answer_drop_reqs(&progress.dropped, now);
        if let Some(arrived_at) = progress.credible_at {
            self.last_recv_time = self.last_recv_time.max(Some(arrived_at));
        }
        if progress.rejected != 0 {
            tracing::debug!(
                rejected = progress.rejected,
                "NAK reports a loss position this sender never sent or already retired"
            );
        }
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
        if !receiver.handle_ackack(ack_number, pkt.timestamp, now) {
            return Err(Error::invalid_data(format!(
                "ACKACK names ACK number {ack_number}, which is already acknowledged or retired"
            )));
        }

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
        if self.peer_shutdown_at.is_some() || self.state == ConnectionState::Disconnected {
            return Ok(());
        }
        if self.state == ConnectionState::Closing {
            // This side already started its own close, which released the
            // receive path itself; the peer's SHUTDOWN merely confirms it.
            self.finish_local_close(DisconnectReason::PeerShutdown);
            return Ok(());
        }

        self.peer_shutdown_at = Some(now);
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
        if self.peer_shutdown_at.is_none() || self.state == ConnectionState::Disconnected {
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
        self.waiting_replies.dropreqs += 1;
        self.queue_control_packet(pkt, now);
    }

    /// Answer a peer loss report naming dropped messages with their
    /// DROPREQs, as long as no more than one report's answer
    /// (`MAX_DROPREQ_PER_NAK`) already waits for TX capacity (see
    /// [`WaitingReplies`]).
    fn answer_drop_reqs(&mut self, dropped: &[DroppedMessage], now: Timestamp) {
        for msg in dropped {
            if self.waiting_replies.dropreqs >= MAX_DROPREQ_PER_NAK {
                return;
            }
            self.send_drop_req(msg.message_number, msg.first_seq, msg.last_seq, now);
        }
    }

    /// Process a UserDefined packet (KM Refresh).
    fn handle_user_defined(&mut self, pkt: ControlPacket, now: Timestamp) -> Result<(), Error> {
        match pkt.subtype {
            SRT_CMD_KMREQ => self.handle_km_request(&pkt.control_info, now),
            SRT_CMD_KMRSP => self.handle_km_response(&pkt.control_info, now),
            _ => {
                // Ignore unknown UserDefined packets.
                Ok(())
            }
        }
    }

    /// A peer's key-material request (receiver side).
    ///
    /// The announced keys configure this side's *receive* direction only
    /// (`CryptoContext::install_rx_keys`); the local transmit selector,
    /// keys and counters belong to local rotation. As in libsrt, a valid
    /// request may replace the key under an already-held selector with a
    /// new SEK and/or salt, may carry both keys at once, and is answered
    /// with a KMRSP echoing its exact body -- also when it repeats keys
    /// already installed (the peer retrying after a lost response), in
    /// which case nothing is reinstalled. A request for another key length
    /// or cipher, one refused by the receive-key hardening checks, or one
    /// whose fresh salt exceeds the KEK derivation budget fails closed: no
    /// KMRSP and no state or liveness change.
    fn handle_km_request(&mut self, control_info: &[u8], now: Timestamp) -> Result<(), Error> {
        let km = KmMessage::decode(control_info)?;
        let Some(crypto) = self.crypto.as_deref_mut() else {
            // A refresh KMREQ on an unencrypted connection cannot succeed.
            // Reply immediately rather than leaving the peer to wait for its
            // own timeout (spec §3.2.1.2).
            self.send_km_error_response(KmError::NoSecret, now);
            return Ok(());
        };
        if !km_matches_suite(&km, crypto) {
            return Err(Error::invalid_data(
                "KMREQ does not match the secured session's key length or cipher",
            ));
        }
        if crypto.needs_kek_derivation(&km.salt)
            && !self
                .km_control
                .get_or_insert_with(Box::default)
                .kek_derivations
                .try_take(now)
        {
            return Err(Error::invalid_data(
                "KMREQ salt exceeds the KEK derivation budget",
            ));
        }
        crypto.install_rx_keys(km.keys, km.salt, &km.wrapped_key)?;
        self.send_km_response(control_info, now);
        Ok(())
    }

    /// A peer's acknowledgement of this connection's rotation (sender side).
    ///
    /// Only the exact request that is outstanding completes the transaction:
    /// a duplicate acknowledgement is stale, and one for a different
    /// generation does not prove the peer installed *this* key.
    /// A late response cannot announce readiness after terminal close.
    fn handle_km_response(&mut self, control_info: &[u8], now: Timestamp) -> Result<(), Error> {
        // A one-word KMRSP is the peer reporting a key-material error state.
        // The reference recognises it during an established session and
        // ignores it without changing security state
        // (`CUDT::processSrtMsg_KMRSP`); the pending rotation keeps its own
        // bounded retries. An unknown code is malformed input.
        if let Ok(state) = <[u8; 4]>::try_from(control_info) {
            return KmError::from_state_bytes(state)
                .map(|_| ())
                .ok_or_else(|| Error::invalid_data("unknown KMRSP error code"));
        }
        if self.state != ConnectionState::Connected {
            return Err(Error::invalid_data("KMRSP outside a connected session"));
        }
        let km = KmMessage::decode(control_info)?;
        let state = self
            .km_control
            .as_mut()
            .ok_or_else(|| Error::invalid_data("unsolicited KMRSP"))?;
        if state.acknowledged.contains(&km) {
            return Err(Error::invalid_data("stale or replayed KMRSP"));
        }
        if state
            .pending
            .as_ref()
            .is_none_or(|pending| pending.request != km)
        {
            return Err(Error::invalid_data(
                "KMRSP does not acknowledge the pending KMREQ",
            ));
        }
        state.pending = None;
        state.acknowledged.remember(km);
        if std::mem::take(&mut state.initial_tx_pending) {
            self.queue_event(ConnectionEvent::Connected);
            self.enqueue_ready_data(now);
        }
        Ok(())
    }

    /// Retransmit an unacknowledged key-material request, or close the session.
    ///
    /// A rotation is only complete once the peer confirms it installed the
    /// new key. If retries run out, the peer might have installed the key
    /// while every KMRSP was lost. Discarding it and continuing would leave
    /// peers on different generations, so close instead of reusing its flag.
    fn service_km_retry(&mut self, now: Timestamp) {
        // Decide under one short borrow; resending and closing need `&mut self`.
        let action = match self
            .km_control
            .as_mut()
            .and_then(|state| state.pending.as_mut())
        {
            None => return,
            Some(pending) if now < pending.next_retry => return,
            Some(pending) => match pending.retries_left {
                // The handshake owns this one: it resends the whole
                // CONCLUSION, which carries this same KMREQ.
                None => return,
                // A lost response is indistinguishable from a lost request.
                Some(0) => KmRetryAction::Close(pending.request.keys),
                Some(left) => {
                    pending.retries_left = Some(left - 1);
                    pending.next_retry = now.add_micros(KM_REQUEST_RETRY_INTERVAL_MICROS);
                    KmRetryAction::Resend(pending.request.clone())
                }
            },
        };

        match action {
            KmRetryAction::Resend(request) => self.send_km_request(&request, now),
            KmRetryAction::Close(keys) => {
                if let Some(state) = self.km_control.as_mut() {
                    state.pending = None;
                }
                self.send_shutdown(now);
                self.finish_local_close(DisconnectReason::ProtocolError(
                    "key rotation was not acknowledged".to_owned(),
                ));
                // This side only ever announces one key per rotation.
                if let (Some(crypto), Some(key_flag)) = (self.crypto.as_mut(), keys.single()) {
                    crypto.abandon_pre_announce(key_flag);
                }
            }
        }
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
            // Only once the peer has acknowledged the rotation: switching to
            // a key the receiver never installed would make every subsequent
            // DATA packet undecryptable.
            let rotation_acknowledged = self
                .km_control
                .as_ref()
                .is_none_or(|state| state.pending.is_none());
            if rotation_acknowledged && crypto.should_switch_key() {
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

    /// Send a KMRSP packet (KM Refresh) echoing the accepted KMREQ's exact
    /// body, as libsrt does.
    fn send_km_response(&mut self, request_body: &[u8], now: Timestamp) {
        let pkt = ControlPacket {
            control_type: ControlType::UserDefined,
            subtype: SRT_CMD_KMRSP,
            type_specific_info: 0,
            timestamp: self.relative_timestamp(now),
            dest_socket_id: self.peer_socket_id,
            control_info: request_body.to_vec(),
        };

        self.queue_control_packet(pkt, now);
    }

    /// Send a KM refresh error response: a KMRSP carrying the four-byte KM
    /// state, encoded exactly as the handshake's (`KmError::to_state_bytes`).
    fn send_km_error_response(&mut self, error: KmError, now: Timestamp) {
        let control_info = error.to_state_bytes().to_vec();
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
    ///
    /// One fire queues at most `MAX_PERIODIC_NAK_PACKETS`. A larger loss list
    /// (up to `MAX_FLOW_WINDOW / 2` runs) is reported oldest first across
    /// successive fires from `periodic_nak_resume`, wrapping to the window
    /// base once the newest loss is reported, so the losses nearest their
    /// drop deadline go first, every loss is named within a bounded number
    /// of intervals, and one fire never encodes the whole list.
    fn send_periodic_nak(&mut self, now: Timestamp) {
        let Some(receiver) = self.receiver.as_ref() else {
            return;
        };

        let max_control_info_size = self.max_control_info_size();
        debug_assert!(max_control_info_size >= MAX_NAK_RECORD_SIZE);
        let timestamp = self.relative_timestamp(now);
        let peer_socket_id = self.peer_socket_id;
        let mut packets = std::mem::take(&mut self.periodic_nak_packets);
        let mut resume = self.periodic_nak_resume.take();
        loop {
            let pass = encode_periodic_nak(
                receiver,
                resume,
                max_control_info_size,
                timestamp,
                peer_socket_id,
                &mut packets,
            );
            // Nothing left at or after the resume point (it was repaired):
            // report from the start in this same fire instead of skipping it.
            if pass.reported_any || resume.is_none() {
                self.periodic_nak_resume = pass.resume;
                break;
            }
            resume = None;
        }

        let packets_sent = packets.len() as u32;
        for packet in packets.drain(..) {
            self.queue_control_packet(packet, now);
        }
        self.periodic_nak_packets = packets;

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
    ///
    /// Skipped while an earlier ACKACK still waits for TX capacity (see
    /// [`WaitingReplies`]): the peer measures its RTT from that one.
    fn send_ackack(&mut self, ack_number: u32, now: Timestamp) {
        if self.waiting_replies.ackack {
            return;
        }
        self.waiting_replies.ackack = true;
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
        hs.initial_packet_seq = self.initial_seq;
        hs.flow_window = self.flight_capacity_packets();
        hs.peer_ip = self.peer_ip;
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

    /// Record the peer's HSREQ/HSRSP capabilities and negotiate each
    /// latency direction the way libsrt does
    /// (`processSrtMsg_HSREQ`/`processSrtMsg_HSRSP`): the peer's SND half
    /// concerns this side's receive delay, its RCV half the reverse
    /// direction, each only when the matching TSBPD flag is set. An HSREQ's
    /// halves are proposals the larger of which wins; an HSRSP's halves are
    /// the responder's already-negotiated results.
    fn apply_peer_handshake_extension(&mut self, hs: &HandshakePacket) {
        let configured = self.options.tsbpd_delay;
        self.rcv_tsbpd_delay = configured;
        self.peer_tsbpd_delay = configured;
        let Some(extension) = hs.get_hs_extension() else {
            return;
        };
        let peer_sends = extension.srt_flags & srt_flags::TSBPDSND != 0;
        let peer_receives = extension.srt_flags & srt_flags::TSBPDRCV != 0;
        let (rcv, peer) = match self.role {
            ConnectionRole::Listener => (
                configured.max(extension.send_tsbpd_delay),
                configured.max(extension.recv_tsbpd_delay),
            ),
            ConnectionRole::Caller => (extension.send_tsbpd_delay, extension.recv_tsbpd_delay),
        };
        if peer_sends {
            self.rcv_tsbpd_delay = rcv;
        }
        if peer_receives {
            self.peer_tsbpd_delay = peer;
        }
        self.peer_srt_flags = Some(extension.srt_flags);
        self.peer_srt_version = Some(extension.srt_version);
    }

    /// Flags and (RCV, SND) latency halves of this listener's HSRSP.
    ///
    /// TSBPDSND, and the SND half carrying the peer's negotiated receive
    /// delay, are only answered when the peer declared TSBPDRCV (libsrt
    /// `fillSrtHandshake_HSRSP`).
    fn hs_response_fields(&self) -> (u32, u16, u16) {
        let mut flags = self.negotiated_srt_flags();
        if self
            .peer_srt_flags
            .is_none_or(|peer| peer & srt_flags::TSBPDRCV == 0)
        {
            flags &= !srt_flags::TSBPDSND;
        }
        let snd = if flags & srt_flags::TSBPDSND != 0 {
            self.peer_tsbpd_delay
        } else {
            0
        };
        (flags, self.rcv_tsbpd_delay, snd)
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

    /// When a group stops waiting for the gap ahead of a packet this
    /// connection released, queued by the sender at `source_time`; `None`
    /// when it never does (see `ReceiverBuffer::gives_up_at`).
    pub(crate) fn gives_up_at(&self, source_time: Timestamp) -> Option<Timestamp> {
        if !(self.tsbpd_enabled() && self.tlpktdrop_enabled()) {
            return None;
        }
        self.receiver.as_ref()?.gives_up_at(source_time)
    }

    /// Periodic NAK reports are this side's own receive policy, independent
    /// of the peer's NAKREPORT, which only says whether the peer will send
    /// them to us (libsrt `fillSrtHandshake_HSRSP`, `checkNAKTimer`).
    fn periodic_nak_enabled(&self) -> bool {
        self.negotiated_srt_flags() & srt_flags::PERIODICNAK != 0
    }

    /// Answer an INDUCTION request. The response echoes the request's ISN,
    /// as libsrt answers by rewriting the received handshake in place
    /// (core.cpp:11768-11811); the listener adopts its ISN at CONCLUSION.
    fn send_induction_response(&mut self, request_isn: u32, now: Timestamp) {
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
        hs.initial_packet_seq = request_isn;
        hs.flow_window = self.flight_capacity_packets();
        hs.peer_ip = self.peer_ip;
        let pkt = hs.encode(self.relative_timestamp(now), self.peer_socket_id);
        self.queue_handshake_control_packet(pkt, now);
    }

    /// The INDUCTION response a listener sends without connection state
    /// (libsrt rewrites the request in place and keeps nothing,
    /// core.cpp:11768-11811): addressed to and naming the caller's socket,
    /// echoing its ISN and flow window, carrying `syn_cookie` and, when the
    /// listener requires encryption, its advertised key length. `peer_ip`
    /// fills the peer-IP field ([`Self::set_peer_address`]). Encode it with
    /// [`HandshakePacket::encode`]`(timestamp, request.socket_id)`.
    ///
    /// # Errors
    ///
    /// A request that is not an INDUCTION or whose flow window is unusable,
    /// which a listener with state refuses too.
    pub fn stateless_induction_response(
        request: &HandshakePacket,
        syn_cookie: u32,
        encryption: Option<KeyLength>,
        peer_ip: std::net::IpAddr,
    ) -> Result<HandshakePacket, Error> {
        if request.handshake_type != HandshakeType::Induction {
            return Err(Error::invalid_data("not an INDUCTION request"));
        }
        if !Self::peer_flow_window_is_usable(request.flow_window) {
            return Err(Error::invalid_data(
                "peer flow window must be between 2 and i32::MAX packets",
            ));
        }
        let mut hs = HandshakePacket::new_induction_response(
            request.socket_id,
            syn_cookie,
            encryption.map_or(0, KeyLength::to_encryption_field),
        );
        hs.initial_packet_seq = request.initial_packet_seq;
        hs.flow_window = request.flow_window;
        hs.peer_ip = peer_ip;
        Ok(hs)
    }

    fn send_conclusion_request(&mut self, now: Timestamp) -> Result<(), Error> {
        // Advertise the key length the KMREQ actually uses: the crypto
        // context may have adopted the listener's advertised length, as
        // libsrt's `checkUpdateCryptoKeyLen` updates its own advertisement.
        // A caller with a passphrase built its context at INDUCTION.
        let encryption_field = self
            .crypto
            .as_deref()
            .map_or(0, |crypto| crypto.key_length().to_encryption_field());

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

        hs.add_hs_extension(
            self.options.srt_version,
            flags,
            self.options.tsbpd_delay,
            self.options.tsbpd_delay,
        );

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
        if let Some(crypto) = &self.crypto {
            let wrapped_key = crypto.wrap_sek(crypto.current_key())?;
            let km_message = KmMessage::new(
                crypto.current_key(),
                crypto.key_length(),
                *crypto.salt(),
                wrapped_key,
                crypto.cipher_mode(),
            );
            hs.add_km_request(&km_message);
            // Tracked as pending so a KMRSP that does not acknowledge this
            // request cannot complete the handshake; the handshake's own
            // request retransmission owns the retry (`retries_left: None`),
            // since it resends this same CONCLUSION with the KMREQ in it.
            let state = self
                .km_control
                .get_or_insert_with(|| Box::new(KmControlState::default()));
            state.pending = Some(PendingKmRequest {
                request: km_message,
                next_retry: now.add_micros(KM_REQUEST_RETRY_INTERVAL_MICROS),
                retries_left: None,
            });
        }

        // Add a SID extension if a non-empty Stream ID is set.
        if let Some(stream_id) = self
            .options
            .stream_id
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            hs.add_sid_extension(stream_id);
        }

        if let Some(group) = self.options.group_extension {
            hs.add_group_extension(group);
        }

        // A CONCLUSION request is sent with dest_socket_id = 0 (libsrt compatibility).
        hs.peer_ip = self.peer_ip;
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

        let (flags, rcv_delay, snd_delay) = self.hs_response_fields();
        hs.add_hs_response(self.options.srt_version, flags, rcv_delay, snd_delay);

        // Declare our congestion control mode (see send_conclusion_request).
        hs.add_congestion_extension(&self.options.congestion_control);

        // Echo the caller's KMREQ as the KMRSP.
        if let Some(km) = &self.received_km {
            hs.add_km_response(km.as_ref());
        }

        // A GROUP extension in the RESPONSE names the RECEIVING group and is
        // only meaningful (and, for libsrt callers, only legal) when the caller
        // asked for group membership. A direct caller never gets one, however
        // the listener's policy is configured.
        if let Some(group) = self.options.group_extension
            && self.peer_group_extension.is_some()
        {
            hs.add_group_extension(group);
        }

        hs.peer_ip = self.peer_ip;
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
        let (flags, rcv_delay, snd_delay) = self.hs_response_fields();
        hs.add_hs_response(self.options.srt_version, flags, rcv_delay, snd_delay);
        hs.add_km_error(error);
        // A GROUP extension in the RESPONSE names the RECEIVING group and is
        // only meaningful (and, for libsrt callers, only legal) when the caller
        // asked for group membership. A direct caller never gets one, however
        // the listener's policy is configured.
        if let Some(group) = self.options.group_extension
            && self.peer_group_extension.is_some()
        {
            hs.add_group_extension(group);
        }
        hs.peer_ip = self.peer_ip;
        let packet = hs.encode(self.relative_timestamp(now), self.peer_socket_id);
        self.queue_handshake_control_packet(packet, now);
        self.terminate_handshake();
        Error::crypto_error(reason)
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
        let remaining = self.handshake_time_remaining(now);
        self.queue_output(QueuedOutput::SetTimer {
            id: TimerId::Handshake,
            duration_micros: interval.min(remaining),
        });
    }

    /// Wake only at the end of the attempt: a listener never resends a
    /// handshake response unprompted.
    fn arm_handshake_deadline(&mut self, now: Timestamp) {
        let remaining = self.handshake_time_remaining(now);
        self.queue_output(QueuedOutput::SetTimer {
            id: TimerId::Handshake,
            duration_micros: remaining,
        });
    }

    fn handshake_time_remaining(&self, now: Timestamp) -> u64 {
        self.handshake_started_at
            .map(|started| {
                started
                    .add_micros(self.handshake_timeout_micros)
                    .saturating_sub(now)
            })
            .unwrap_or(self.handshake_timeout_micros)
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
/// set of shapes this implementation deliberately accepts, matching
/// Robotweax's bounded decoder.
///
/// The pinned Haivision reference (`899348d8`, `core.cpp`) draws a sharp
/// line between what it emits and what it accepts: `CUDT::sendCtrl` only
/// ever emits a 4-, 16-, 24-, 28-, or 32-byte ACK CIF, while
/// `CUDT::processCtrlAck` itself accepts any 4-byte Light ACK or any
/// non-Light ACK of at least 16 bytes -- a materially wider receive-side
/// tolerance than what it actually produces. This crate deliberately
/// accepts only the bounded set of sizes pinned Haivision is actually
/// shown to emit -- {4, 16, 24, 28, 32} -- rather than mirroring its
/// permissive receive path.
///
/// Light (4 bytes) carries only the cumulative position and never an ACK
/// number. Small (16 bytes) adds RTT/RTTVar/advertised-buffer, and comes
/// in two forms: the draft's own unnumbered form (ACK number 0), which
/// this crate also accepts, and a deployed numbered variant (nonzero)
/// that pinned Haivision demonstrates emitting and that gets acknowledged
/// with ACKACK -- Robotweax pins a regression for exactly this variant.
/// The reference-Full sizes (24, adding packet rate/capacity; 28, the
/// draft's own Full ACK, adding the receiving byte rate; and libsrt's
/// legacy 32-byte form with one extra, unused field) always carry an ACK
/// number, which may be zero: libsrt's 31-bit number rolls 0x7fff_ffff -> 0
/// (`CAckNo::incack`) and `processCtrlAck` accepts it. Any other aligned
/// length is not a size pinned Haivision is shown to emit.
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
    Ok(())
}

/// Whether an ACK named an ACK number the peer expects ACKACKed: every
/// 24/28/32-byte ACK (zero included, after libsrt's 31-bit wrap) and a
/// numbered 16-byte Small ACK; never a Light ACK or the draft's unnumbered
/// Small form.
fn ack_names_a_number(pkt: &ControlPacket) -> bool {
    pkt.control_info.len() >= 24 || pkt.type_specific_info != 0
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

/// Outcome of one periodic-NAK encoding pass.
struct PeriodicNakPass {
    /// Where the next fire resumes; `None` once the end of the list was
    /// reported.
    resume: Option<u32>,
    /// Whether any loss at or after the requested resume point exists.
    reported_any: bool,
}

/// Encode the receiver's loss runs, oldest first from `resume`, into at
/// most `MAX_PERIODIC_NAK_PACKETS` NAK packets appended to `packets`.
fn encode_periodic_nak(
    receiver: &ReceiverBuffer,
    resume: Option<u32>,
    max_control_info_size: usize,
    timestamp: u32,
    peer_socket_id: u32,
    packets: &mut Vec<ControlPacket>,
) -> PeriodicNakPass {
    let mut chunks = NakChunkEncoder::new(max_control_info_size);
    let mut pass = PeriodicNakPass {
        resume: None,
        reported_any: false,
    };
    receiver.try_for_each_periodic_nak_range_from(resume, |loss| {
        pass.reported_any = true;
        if let Some(control_info) = chunks.push(loss) {
            packets.push(make_nak_packet(control_info, timestamp, peer_socket_id));
            if packets.len() == MAX_PERIODIC_NAK_PACKETS {
                // `loss` opened the chunk that will not be sent this fire.
                pass.resume = Some(loss.first_seq);
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    });
    if pass.resume.is_none()
        && let Some(control_info) = chunks.finish()
    {
        packets.push(make_nak_packet(control_info, timestamp, peer_socket_id));
    }
    pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{
        ExtensionType, GroupType, HandshakeExtension, SRTGROUP_MASK, extension_flags,
    };
    const SEQUENCE_MASK: u32 = 0x7FFF_FFFF;
    use crate::srt_sender::MAX_NAK_POSITIONS_PER_VISIT;
    use crate::test_support::WorkCounters;

    /// Deterministic, non-secret KM salt for protocol test fixtures.
    fn test_km_salt() -> [u8; 16] {
        std::array::from_fn(|index| index as u8)
    }

    /// Deterministic, non-secret key or salt bytes for KM fixtures:
    /// distinct per `tag`, and never zero for a `tag` of at least 0x40.
    fn fixture_key(tag: u8) -> [u8; 16] {
        std::array::from_fn(|index| tag ^ index as u8)
    }

    /// [`fixture_key`] for any key length.
    fn fixture_key_vec(tag: u8, len: usize) -> Vec<u8> {
        (0..len).map(|index| tag ^ index as u8).collect()
    }

    /// Deterministic, non-secret salt for wire-shape fixtures in this module
    /// (same derivation as `test_km_salt`; named for the hostile-control
    /// cases that need a *body*, not a key).
    fn fixture_salt() -> [u8; 16] {
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
            ..ConnectionOptions::default()
        });

        let stream_id = conn.options.stream_id.as_deref().expect("stream id");
        assert_eq!(stream_id.len(), 510);
    }

    /// An empty Stream ID is not sent: libsrt refuses an empty SID block
    /// (core.cpp:2950-2960).
    #[test]
    fn an_empty_stream_id_is_not_emitted() {
        for (stream_id, emitted) in [("", None), ("id", Some("id"))] {
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                socket_id: 1,
                stream_id: Some(stream_id.to_owned()),
                ..ConnectionOptions::default()
            });
            let mut listener = SrtConnection::new_listener(listener_options());
            caller.connect(Timestamp::default()).unwrap();
            listener
                .feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(1))
                .unwrap();
            caller
                .feed_recv_buf(&next_wire(&mut listener), Timestamp::from_micros(2))
                .unwrap();
            let (conclusion, _) = decode_handshake(&next_wire(&mut caller));
            assert_eq!(conclusion.get_sid_extension().as_deref(), emitted);
        }
    }

    /// Congestion names a libsrt peer refuses (empty, or over 16 bytes:
    /// `CSrtConfig::MAX_CONG_LENGTH`, core.cpp:3001-3007), paired with
    /// whether this side may emit them.
    fn congestion_name_cases() -> [(String, bool); 4] {
        [
            (String::new(), false),
            ("live".to_owned(), true),
            ("c".repeat(16), true),
            ("c".repeat(17), false),
        ]
    }

    /// `connect` refuses a congestion name libsrt refuses, before sending.
    #[test]
    fn caller_refuses_a_congestion_name_outside_libsrt_bounds() {
        for (name, emittable) in congestion_name_cases() {
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                congestion_control: name.clone(),
                ..ConnectionOptions::default()
            });
            let started = caller.connect(Timestamp::default());
            assert_eq!(started.is_ok(), emittable, "{name:?}: {started:?}");
            let sent = drain_outputs(&mut caller)
                .iter()
                .any(|output| matches!(output, ConnectionOutput::SendPacket(_)));
            assert_eq!(sent, emittable, "{name:?}");
        }
    }

    /// A listener whose congestion name libsrt refuses answers callers with
    /// `SRT_REJ_CONGESTION` instead of a CONCLUSION response carrying it.
    #[test]
    fn listener_refuses_callers_with_a_congestion_name_outside_libsrt_bounds() {
        for (name, emittable) in congestion_name_cases() {
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                socket_id: 1,
                ..ConnectionOptions::default()
            });
            let mut listener = SrtConnection::new_listener(ConnectionOptions {
                congestion_control: name.clone(),
                ..listener_options()
            });
            caller.connect(Timestamp::default()).unwrap();
            listener
                .feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(1))
                .unwrap();
            caller
                .feed_recv_buf(&next_wire(&mut listener), Timestamp::from_micros(2))
                .unwrap();
            let answered =
                listener.feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(3));
            assert_eq!(answered.is_ok(), emittable, "{name:?}: {answered:?}");
            let expected = (!emittable).then_some(SRT_REJ_CONGESTION);
            assert_eq!(rejection_reason(&mut listener), expected, "{name:?}");
        }
    }

    /// GROUP extensions paired with whether libsrt accepts them
    /// (`interpretGroup`, core.cpp:3317-3331).
    fn group_cases() -> [(GroupExtensionData, bool); 5] {
        let group = |group_id, group_type| GroupExtensionData {
            group_id,
            group_type,
            flags: 0,
            weight: 1,
        };
        [
            (group(SRTGROUP_MASK | 42, GroupType::Broadcast), true),
            (group(SRTGROUP_MASK | 42, GroupType::Backup), true),
            (group(SRTGROUP_MASK | 42, GroupType::Undefined), true),
            (group(42, GroupType::Broadcast), false),
            (group(SRTGROUP_MASK | 42, GroupType::Unknown(3)), false),
        ]
    }

    /// An outbound GROUP libsrt would refuse is a configuration error, on
    /// both setters and at `connect` before anything is sent.
    #[test]
    fn outbound_groups_libsrt_refuses_are_configuration_errors() {
        for (group, valid) in group_cases() {
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                group_extension: Some(group),
                ..ConnectionOptions::default()
            });
            let started = caller.connect(Timestamp::default());
            assert_eq!(started.is_ok(), valid, "{group:?}: {started:?}");
            let sent = drain_outputs(&mut caller)
                .iter()
                .any(|output| matches!(output, ConnectionOutput::SendPacket(_)));
            assert_eq!(sent, valid, "{group:?}");

            let mut listener = SrtConnection::new_listener(listener_options());
            let set = listener.set_group_extension(group);
            assert_eq!(set.is_ok(), valid, "{group:?}");
            let mut listener = SrtConnection::new_listener(listener_options());
            let set = listener.set_listener_group_extension(Some(group));
            assert_eq!(set.is_ok(), valid, "{group:?}");
        }
    }

    /// A listener whose configured GROUP libsrt would refuse answers a
    /// bonded caller with `SRT_REJ_GROUP` instead of emitting it; a direct
    /// caller, which gets no GROUP back, is unaffected.
    #[test]
    fn listener_refuses_bonded_callers_when_its_own_group_is_invalid() {
        let (bonded, _) = group_cases()[0];
        for (caller_group, (group, valid)) in [Some(bonded), None]
            .into_iter()
            .flat_map(|caller_group| group_cases().map(|case| (caller_group, case)))
        {
            let answers = valid || caller_group.is_none();
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                socket_id: 1,
                group_extension: caller_group,
                ..ConnectionOptions::default()
            });
            let mut listener = SrtConnection::new_listener(ConnectionOptions {
                group_extension: Some(group),
                ..listener_options()
            });
            caller.connect(Timestamp::default()).unwrap();
            listener
                .feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(1))
                .unwrap();
            caller
                .feed_recv_buf(&next_wire(&mut listener), Timestamp::from_micros(2))
                .unwrap();
            let answered =
                listener.feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(3));
            assert_eq!(
                answered.is_ok(),
                answers,
                "{caller_group:?} -> {group:?}: {answered:?}"
            );
            let expected = (!answers).then_some(SRT_REJ_GROUP);
            assert_eq!(rejection_reason(&mut listener), expected, "{group:?}");
        }
    }

    /// The first queued control datagram of `control_type`, with its wire.
    fn take_control(
        conn: &mut SrtConnection,
        control_type: ControlType,
    ) -> Option<(Vec<u8>, ControlPacket)> {
        drain_outputs(conn).into_iter().find_map(|output| {
            let ConnectionOutput::SendPacket(wire) = output else {
                return None;
            };
            match SrtPacket::decode(&wire) {
                Ok(SrtPacket::Control(control)) if control.control_type == control_type => {
                    Some((wire, control))
                }
                _ => None,
            }
        })
    }

    /// A Full ACK numbered 0 is a real ACK: libsrt's 31-bit ACK number
    /// rolls 0x7fff_ffff -> 0 (`CAckNo::incack`, common.h:728-735) and
    /// `processCtrlAck` acknowledges it. The peer answers with ACKACK 0 and
    /// the RTT sample lands.
    #[test]
    fn a_full_ack_numbered_zero_gets_its_ackack_and_rtt_sample() {
        let (mut caller, mut listener) = connected_pair();
        let start = Timestamp::from_micros(1_000_000);
        caller.send(b"zero", start).unwrap();
        listener
            .feed_recv_buf(&next_wire(&mut caller), start)
            .unwrap();
        drain_outputs(&mut listener);
        listener
            .receiver
            .as_mut()
            .unwrap()
            .seed_full_acks_sent_for_test(0x7FFF_FFFF);
        listener
            .wire_checker_mut()
            .expect("connected_pair checks the wire")
            .note_seeded_ack_number();

        let ack_time = start.add_micros(20_000);
        listener.handle_timer(TimerId::Ack, ack_time).unwrap();
        let (ack, packet) = take_control(&mut listener, ControlType::Ack).expect("a Full ACK");
        assert!(packet.control_info.len() >= 24, "a Full ACK");
        assert_eq!(packet.type_specific_info, 0, "the number after 0x7fff_ffff");

        caller
            .feed_recv_buf(&ack, ack_time.add_micros(5_000))
            .expect("a Full ACK numbered 0 is accepted");
        let (ackack, packet) =
            take_control(&mut caller, ControlType::AckAck).expect("the ACK is acknowledged");
        assert_eq!(packet.type_specific_info, 0);

        let rtt_before = listener.receiver.as_ref().unwrap().rtt();
        listener
            .feed_recv_buf(&ackack, ack_time.add_micros(10_000))
            .expect("ACKACK 0 names a sent ACK");
        assert_ne!(
            listener.receiver.as_ref().unwrap().rtt(),
            rtt_before,
            "RTT sampled"
        );
    }

    /// A replayed ACKACK is not a protocol transition: it finds its ACK
    /// already acknowledged, takes no RTT sample and is refused, so it is
    /// not banked as peer activity either.
    #[test]
    fn a_replayed_ackack_is_refused_without_an_rtt_sample() {
        let (mut caller, mut listener) = connected_pair();
        let start = Timestamp::from_micros(1_000_000);
        caller.send(b"once", start).unwrap();
        listener
            .feed_recv_buf(&next_wire(&mut caller), start)
            .unwrap();
        drain_outputs(&mut listener);
        let ack_time = start.add_micros(20_000);
        listener.handle_timer(TimerId::Ack, ack_time).unwrap();
        let (ack, _) = take_control(&mut listener, ControlType::Ack).expect("a Full ACK");
        caller
            .feed_recv_buf(&ack, ack_time.add_micros(5_000))
            .expect("ACK accepted");
        let (ackack, _) = take_control(&mut caller, ControlType::AckAck).expect("an ACKACK");
        listener
            .feed_recv_buf(&ackack, ack_time.add_micros(10_000))
            .expect("the first copy matches");
        let rtt = listener.receiver.as_ref().unwrap().rtt();

        let accepted = (1..=3)
            .filter(|copy| {
                listener
                    .feed_recv_buf(&ackack, ack_time.add_micros(10_000 + copy * 1_000_000))
                    .is_ok()
            })
            .count();
        assert_eq!(
            listener.receiver.as_ref().unwrap().rtt(),
            rtt,
            "no RTT sample"
        );
        assert_eq!(accepted, 0, "every copy is refused");
    }

    /// The message-number wrap reaches the wire as `0x03ff_ffff, 1`: libsrt's
    /// `MsgNo` rolls from 1 (`packet.h:184`) and zero is the packet-filter
    /// control identity. Checked end to end by the strict wire checker.
    #[test]
    fn message_numbers_wrap_to_one_on_the_wire() {
        let (mut caller, mut listener) = connected_pair();
        caller
            .sender
            .as_mut()
            .expect("connected sender")
            .seed_next_message_number_for_test(0x03FF_FFFF);
        let now = Timestamp::from_micros(1_000_000);
        let mut numbers = Vec::new();
        for payload in [b"last".as_slice(), b"wrapped"] {
            caller.send(payload, now).unwrap();
            let wire = next_wire(&mut caller);
            let Ok(SrtPacket::Data(data)) = SrtPacket::decode(&wire) else {
                panic!("a DATA packet");
            };
            numbers.push(data.message_number);
            listener.feed_recv_buf(&wire, now).unwrap();
        }
        assert_eq!(numbers, [0x03FF_FFFF, 1]);
    }

    /// Each handshake carries the peer's IP the transport set, as libsrt's
    /// do (`core.cpp:3782`, `6011`); a libsrt peer records it as its own
    /// local address (`core.cpp:4983`, `6055-6057`). A listener requiring a
    /// passphrase answers the unencrypted caller with a KM failure response.
    #[test]
    fn handshakes_carry_the_peer_ip_the_transport_set() {
        let listener_address: std::net::SocketAddr = "192.0.2.1:9000".parse().unwrap();
        let caller_address: std::net::SocketAddr = "[2001:db8::2]:5000".parse().unwrap();
        for passphrase in [None, Some("peer-ip-passphrase".into())] {
            let mut caller = SrtConnection::new_caller(ConnectionOptions::default());
            caller.set_peer_address(listener_address);
            let mut listener = SrtConnection::new_listener(ConnectionOptions {
                passphrase,
                ..listener_options()
            });
            listener.set_peer_address(caller_address);

            let now = Timestamp::from_micros(1_000);
            caller.connect(Timestamp::from_micros(0)).unwrap();
            let induction = next_wire(&mut caller);
            listener.feed_recv_buf(&induction, now).unwrap();
            let induction_response = next_wire(&mut listener);
            caller.feed_recv_buf(&induction_response, now).unwrap();
            let conclusion = next_wire(&mut caller);
            // The passphrase listener refuses with its KM failure response.
            let _ = listener.feed_recv_buf(&conclusion, now);
            let conclusion_response = next_wire(&mut listener);
            for (name, wire, ip) in [
                ("induction", induction, listener_address.ip()),
                (
                    "induction response",
                    induction_response,
                    caller_address.ip(),
                ),
                ("conclusion", conclusion, listener_address.ip()),
                (
                    "conclusion response",
                    conclusion_response,
                    caller_address.ip(),
                ),
            ] {
                assert_eq!(decode_handshake(&wire).0.peer_ip, ip, "{name}");
            }
        }
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
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "constructs a real CryptoContext, deriving its KEK via 2048               \
                  PBKDF2-HMAC-SHA1 iterations (per the SRT spec) under Miri; correctness    \
                  is proven outside Miri, and this property is unrelated to PBKDF2's own    \
                  iteration count. Run in the miri-extended scheduled job."
    )]
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
        conn.set_state(ConnectionState::Connected);

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
        // Same little-endian KM-state word as the handshake KMRSP
        // (`HandshakePacket::add_km_error`): libsrt pre-swaps the native
        // word so the channel's word conversion emits `03 00 00 00`.
        assert_eq!(response.control_info, [0x03, 0x00, 0x00, 0x00]);
        let state = <[u8; 4]>::try_from(response.control_info.as_slice()).expect("one word");
        assert_eq!(KmError::from_state_bytes(state), Some(KmError::NoSecret));
        let mut handshake = HandshakePacket::new_conclusion_request(1, 2, 3, 2, true);
        handshake.add_km_error(KmError::NoSecret);
        assert_eq!(
            handshake
                .extensions
                .last()
                .map(|extension| extension.data.as_slice()),
            Some(response.control_info.as_slice()),
            "runtime and handshake KMRSP share one KM-state encoding"
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

    /// The first datagram `conn` queues.
    fn next_wire(conn: &mut SrtConnection) -> Vec<u8> {
        drain_outputs(conn)
            .into_iter()
            .find_map(|output| match output {
                ConnectionOutput::SendPacket(wire) => Some(wire),
                _ => None,
            })
            .expect("one protocol datagram")
    }

    fn decode_handshake(wire: &[u8]) -> (HandshakePacket, u32) {
        let SrtPacket::Control(packet) = SrtPacket::decode(wire).unwrap() else {
            panic!("handshake control packet");
        };
        (HandshakePacket::decode(&packet).unwrap(), packet.timestamp)
    }

    fn handshake_sequence(wire: &[u8]) -> u32 {
        decode_handshake(wire).0.initial_packet_seq
    }

    fn isn_pair(initial: u32) -> (SrtConnection, SrtConnection) {
        let caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            initial_seq: Some(initial),
            ..Default::default()
        });
        let listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            ..Default::default()
        });
        (caller, listener)
    }

    #[test]
    fn handshake_and_first_data_keep_the_same_initial_sequence() {
        for initial in [17, 0x7fff_fffe] {
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                socket_id: 1,
                initial_seq: Some(initial),
                ..Default::default()
            });
            let mut listener = SrtConnection::new_listener(ConnectionOptions {
                socket_id: 2,
                syn_cookie: Some(7),
                ..Default::default()
            });
            caller.connect(Timestamp::default()).unwrap();
            let induction = next_wire(&mut caller);
            listener
                .feed_recv_buf(&induction, Timestamp::from_micros(1))
                .unwrap();
            caller
                .feed_recv_buf(&next_wire(&mut listener), Timestamp::from_micros(2))
                .unwrap();
            let conclusion = next_wire(&mut caller);
            listener
                .feed_recv_buf(&conclusion, Timestamp::from_micros(3))
                .unwrap();
            caller
                .feed_recv_buf(&next_wire(&mut listener), Timestamp::from_micros(4))
                .unwrap();
            caller
                .send(b"first", Timestamp::from_micros(10_000))
                .unwrap();
            let SrtPacket::Data(first) = SrtPacket::decode(&next_wire(&mut caller)).unwrap() else {
                panic!("the first DATA packet");
            };
            // A cookie-based listener can bind the challenge to the INDUCTION
            // ISN. Neither CONCLUSION nor the first DATA may change that value.
            assert_eq!(
                [
                    handshake_sequence(&induction),
                    handshake_sequence(&conclusion)
                ],
                [first.sequence_number; 2]
            );
            assert_eq!(first.sequence_number, initial);
        }
    }

    /// A listener's INDUCTION response echoes the request's ISN: libsrt
    /// answers by rewriting the received handshake (core.cpp:11768-11811).
    #[test]
    fn listener_induction_response_echoes_the_request_isn() {
        for initial in [17, 0x7fff_fffe] {
            let (mut caller, mut listener) = isn_pair(initial);
            caller.connect(Timestamp::default()).unwrap();
            listener
                .feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(1))
                .unwrap();
            let response = next_wire(&mut listener);
            assert_eq!(handshake_sequence(&response), initial);
        }
    }

    /// T5: a listener answers each handshake request once and leaves any
    /// repeat to the caller's retransmissions, as libsrt does
    /// (core.cpp:11769-11810); its handshake timer only bounds the attempt.
    /// Resending on that timer reflected about a dozen answers per (possibly
    /// forged) INDUCTION at the address it claimed.
    #[test]
    fn a_listener_never_resends_a_handshake_answer_unprompted() {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 0x1111,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 0x2222,
            ..ConnectionOptions::default()
        });
        caller.connect(Timestamp::default()).unwrap();
        listener
            .feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(1))
            .unwrap();
        let mut answers = 0;
        let mut drain = |listener: &mut SrtConnection| {
            while let Some(output) = listener.poll_output().unwrap() {
                if matches!(output, ConnectionOutput::SendPacket(_)) {
                    answers += 1;
                }
            }
        };
        drain(&mut listener);
        let retries = DEFAULT_HANDSHAKE_TIMEOUT_MICROS / DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS;
        for retry in 1..=retries {
            let now = Timestamp::from_micros(1 + retry * DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS);
            listener.handle_timer(TimerId::Handshake, now).unwrap();
            drain(&mut listener);
        }
        assert_eq!(answers, 1, "datagrams the listener sent for one INDUCTION");
    }

    /// A caller refuses a CONCLUSION response carrying another ISN, as a
    /// libsrt caller's connect fails with `MN_SECURITY` (core.cpp:4085).
    #[test]
    fn caller_refuses_a_conclusion_response_with_another_isn() {
        for (response_isn, connects) in [(17, true), (18, false), (0, false)] {
            let (mut caller, mut listener) = isn_pair(17);
            caller.connect(Timestamp::default()).unwrap();
            listener
                .feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(1))
                .unwrap();
            caller
                .feed_recv_buf(&next_wire(&mut listener), Timestamp::from_micros(2))
                .unwrap();
            listener
                .feed_recv_buf(&next_wire(&mut caller), Timestamp::from_micros(3))
                .unwrap();
            let (mut response, timestamp) = decode_handshake(&next_wire(&mut listener));
            response.initial_packet_seq = response_isn;
            let result =
                caller.handle_handshake_caller(response, timestamp, Timestamp::from_micros(4));
            assert_eq!(
                result.is_ok(),
                connects,
                "response ISN {response_isn}: {result:?}"
            );
            let expected = if connects {
                ConnectionState::Connected
            } else {
                ConnectionState::Disconnected
            };
            assert_eq!(caller.state(), expected, "response ISN {response_isn}");
        }
    }

    /// Only the low 31 bits of a configured ISN are used, so the
    /// CONCLUSION response's echo of the wire ISN is the caller's own.
    #[test]
    fn a_configured_isn_above_31_bits_uses_its_wire_value() {
        let (mut caller, mut listener) = isn_pair(0x8000_0011);
        drive_handshake_to_connected(&mut caller, &mut listener);
        assert_eq!(caller.initial_seq, 0x11);
    }

    /// One-way delay of [`group_member_pair`]'s path, each way.
    const GROUP_MEMBER_ONE_WAY_US: u64 = 5_000;

    /// A connected caller/listener pair whose caller is a bonded member
    /// inheriting a group clock that started at zero, so its timestamps
    /// are its own clock (`caller_epoch + t`) while the listener's clock
    /// reads `listener_epoch + t` at the same moment.
    fn group_member_pair(caller_epoch: u64, listener_epoch: u64) -> (SrtConnection, SrtConnection) {
        let caller_at = |t: u64| Timestamp::from_micros(caller_epoch + t);
        let listener_at = |t: u64| Timestamp::from_micros(listener_epoch + t);
        let (group_peer, _) = connected_pair();
        let group_time = group_peer.group_time().expect("connected member clock");
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            ..ConnectionOptions::default()
        });
        caller.inherit_group_time(group_time);
        crate::test_support::wire_checker::check_pair(&mut caller, &mut listener);
        caller.connect(caller_at(0)).expect("caller starts");
        for round in 0..4 {
            let at = round * 2 * GROUP_MEMBER_ONE_WAY_US;
            forward_handshake_round(&mut caller, &mut listener, listener_at(at));
            forward_handshake_round(
                &mut listener,
                &mut caller,
                caller_at(at + GROUP_MEMBER_ONE_WAY_US),
            );
        }
        assert_eq!(caller.state(), ConnectionState::Connected);
        assert_eq!(listener.state(), ConnectionState::Connected);
        let _ = drain_outputs(&mut listener);
        (caller, listener)
    }

    /// The single DATA datagram `conn` queued.
    fn sole_data_datagram(conn: &mut SrtConnection) -> Vec<u8> {
        drain_datagrams(conn)
            .into_iter()
            .find(|bytes| matches!(SrtPacket::decode(bytes), Ok(SrtPacket::Data(_))))
            .expect("DATA sent")
    }

    /// Run delivery at `now` and count the DATA events it released.
    fn deliver_due(conn: &mut SrtConnection, now: Timestamp) -> usize {
        conn.handle_timer(TimerId::DeliveryContinue, now)
            .expect("delivery");
        std::iter::from_fn(|| conn.poll_event())
            .filter(|event| matches!(event, ConnectionEvent::DataReceived { .. }))
            .count()
    }

    /// A bonded member's handshake timestamp is the group's age (libsrt
    /// members share the group start time, group.h:768-782,
    /// core.cpp:3621-3622), which can exceed a freshly started listener's
    /// clock. libsrt derives the peer start on the steady clock and never
    /// clamps it (core.cpp:2253/2490), so the TSBPD base must stay negative
    /// here instead of saturating to zero and holding every packet for the
    /// clock difference.
    #[test]
    fn handshake_timestamp_beyond_the_local_clock_keeps_tsbpd_on_schedule() {
        const CALLER_EPOCH: u64 = 3_600_000_000;
        const LISTENER_EPOCH: u64 = 1_000_000;
        let latency = u64::from(ConnectionOptions::default().tsbpd_delay) * 1_000;
        let (mut caller, mut listener) = group_member_pair(CALLER_EPOCH, LISTENER_EPOCH);

        caller
            .send(b"due", Timestamp::from_micros(CALLER_EPOCH + 100_000))
            .expect("DATA queued");
        let data = sole_data_datagram(&mut caller);
        let arrival = LISTENER_EPOCH + 100_000 + GROUP_MEMBER_ONE_WAY_US;
        listener
            .feed_recv_buf(&data, Timestamp::from_micros(arrival))
            .expect("DATA accepted");
        assert_eq!(
            deliver_due(&mut listener, Timestamp::from_micros(arrival + latency - 1)),
            0,
            "held for its latency"
        );
        assert_eq!(
            deliver_due(&mut listener, Timestamp::from_micros(arrival + latency)),
            1,
            "delivered at its play time, not an hour late"
        );
    }

    /// A DATA pause across the 32-bit timestamp wrap (71.6 minutes into the
    /// sender's clock): no DATA is stamped in the 30 seconds before it, so
    /// only the peer's idle KEEPALIVEs cover the wrap. libsrt feeds every
    /// KEEPALIVE timestamp to `CTsbpdTime::updateBaseTime`
    /// (core.cpp:12673); DATA after the pause must keep its latency instead
    /// of playing on arrival as if it were 71.6 minutes old.
    #[test]
    fn keepalives_carry_the_tsbpd_wrap_across_a_data_pause() {
        const WRAP: u64 = 1 << 32;
        const CALLER_EPOCH: u64 = WRAP - 40_000_000;
        const LISTENER_EPOCH: u64 = 1_000_000;
        let latency = u64::from(ConnectionOptions::default().tsbpd_delay) * 1_000;
        let (mut caller, mut listener) = group_member_pair(CALLER_EPOCH, LISTENER_EPOCH);
        // The strict epoch rule compares raw 32-bit stamps and does not
        // model the 2^32 wrap this test crosses on purpose, so the
        // caller's checker stays out once the handshake is checked.
        caller.wire_checker = None;
        let arrival_of = |caller_us: u64| {
            Timestamp::from_micros(
                LISTENER_EPOCH + caller_us - CALLER_EPOCH + GROUP_MEMBER_ONE_WAY_US,
            )
        };

        let before = CALLER_EPOCH + 100_000;
        caller
            .send(b"before", Timestamp::from_micros(before))
            .expect("DATA queued");
        let data = sole_data_datagram(&mut caller);
        listener
            .feed_recv_buf(&data, arrival_of(before))
            .expect("DATA accepted");
        assert_eq!(
            deliver_due(&mut listener, arrival_of(before).add_micros(latency)),
            1
        );

        let resume = WRAP + 61_000_000;
        for at in (before + 1_000_000..resume).step_by(1_000_000) {
            caller
                .handle_timer(TimerId::Keepalive, Timestamp::from_micros(at))
                .expect("keepalive timer");
            for bytes in drain_datagrams(&mut caller) {
                listener
                    .feed_recv_buf(&bytes, arrival_of(at))
                    .expect("KEEPALIVE accepted");
            }
        }

        caller
            .send(b"after", Timestamp::from_micros(resume))
            .expect("DATA queued");
        let data = sole_data_datagram(&mut caller);
        listener
            .feed_recv_buf(&data, arrival_of(resume))
            .expect("DATA accepted");
        assert_eq!(
            deliver_due(&mut listener, arrival_of(resume).add_micros(latency - 1)),
            0,
            "post-wrap DATA keeps its latency"
        );
        assert_eq!(
            deliver_due(&mut listener, arrival_of(resume).add_micros(latency)),
            1,
            "and plays at its deadline"
        );
    }

    /// Record a DATA packet a test injects below the connection's receive
    /// entry points as the checker's peer input, so rules judged against
    /// received DATA (ACK and NAK frontiers) see it.
    fn record_peer_data(conn: &mut SrtConnection, packet: &DataPacket) {
        let mut wire = vec![0u8; packet.encoded_size()];
        packet.encode_into(&mut wire).expect("fixture DATA encodes");
        if let Some(checker) = conn.wire_checker_mut() {
            checker.record_received(&wire);
        }
    }

    /// Drive a full caller/listener handshake to `Connected` on both ends,
    /// for tests that only care about post-handshake send behavior. Both
    /// ends run under the strict wire checker.
    fn drive_handshake_to_connected(caller: &mut SrtConnection, listener: &mut SrtConnection) {
        crate::test_support::wire_checker::check_pair(caller, listener);
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        for round in 0..4 {
            let now = Timestamp::from_micros(round * 10_000);
            forward_handshake_round(caller, listener, now);
            forward_handshake_round(listener, caller, now);
            if caller.state() == ConnectionState::Connected
                && listener.state() == ConnectionState::Connected
                && !listener.initial_tx_pending()
                && !caller.initial_tx_pending()
            {
                break;
            }
        }
        assert_eq!(caller.state(), ConnectionState::Connected);
        assert_eq!(listener.state(), ConnectionState::Connected);
        assert!(!listener.initial_tx_pending(), "directional TX confirmed");
        assert!(
            !caller.initial_tx_pending(),
            "caller directional TX confirmed"
        );
    }

    /// Default-options caller/listener pair, already `Connected`.
    fn connected_pair() -> (SrtConnection, SrtConnection) {
        connected_pair_with_tsbpd_delay(ConnectionOptions::default().tsbpd_delay)
    }

    /// Caller/listener pair negotiated at `tsbpd_delay` ms, already
    /// `Connected`.
    fn connected_pair_with_tsbpd_delay(tsbpd_delay: u16) -> (SrtConnection, SrtConnection) {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            tsbpd_delay,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            tsbpd_delay,
            ..ConnectionOptions::default()
        });
        drive_handshake_to_connected(&mut caller, &mut listener);
        (caller, listener)
    }

    /// The constant payload ceiling is what the window-payload reservation
    /// charges per retained packet, so a payload at `DEFAULT_MTU -
    /// SRT_HEADER_SIZE` is accepted even when the negotiation landed lower from
    /// this side's view of the path (NAT64 or SIIT), one byte more is a
    /// protocol violation rather than a loss, and the connection survives it.
    #[test]
    fn a_data_payload_above_the_payload_ceiling_is_rejected_not_fatal() {
        let (_caller, mut listener) = connected_pair();
        let ceiling = DEFAULT_MTU as usize - SRT_HEADER_SIZE;
        let now = Timestamp::from_micros(1_000_000);

        let at_ceiling = DataPacket::new(0, 1, 0, 0, vec![0x11u8; ceiling].into());
        listener
            .handle_data_packet(at_ceiling, now)
            .expect("a payload at the constant ceiling is legal");

        // A peer this side sees through a different address family keeps
        // sending at the constant ceiling even though the negotiation landed
        // lower here; that must not be dropped.
        listener.max_payload_size = ceiling - 28;
        let after_lower_negotiation = DataPacket::new(1, 2, 0, 0, vec![0x33u8; ceiling].into());
        listener
            .handle_data_packet(after_lower_negotiation, now)
            .expect("a payload at the ceiling is legal after a lower negotiation");

        let oversized = DataPacket::new(2, 3, 0, 0, vec![0x22u8; ceiling + 1].into());
        let error = listener
            .handle_data_packet(oversized, now)
            .expect_err("a payload above the ceiling is rejected");
        assert!(
            error.to_string().contains("constant payload ceiling"),
            "unexpected error: {error}"
        );
        assert_eq!(
            listener.state(),
            ConnectionState::Connected,
            "an oversized datagram is dropped and counted invalid, not fatal"
        );
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

        /// The armed timer due first, inactivity winning ties.
        fn earliest(&self) -> Option<(TimerId, Timestamp)> {
            TimerId::ALL
                .iter()
                .filter_map(|&id| self.deadlines[id.index()].map(|at| (id, at)))
                .min_by_key(|(id, at)| (at.as_micros(), *id != TimerId::Inactivity, id.index()))
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
            // These tests are about how the sender recovers a loss, so the
            // receiver must still want the packet when it comes back: the
            // latency covers the timeout-driven recovery, as an SRT latency
            // is configured to. The receiver gives up a gap once the packet
            // after it is due, like libsrt.
            let (caller, listener) = connected_pair_with_tsbpd_delay(FLIGHT_TSBPD_DELAY_MS);
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
                ack_storm,
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
                // The ACK storm replays a Full ACK the caller has already
                // ACKACKed, and the listener refuses the repeated ACKACK;
                // every other packet must be accepted.
                if let Err(error) = listener.feed_recv_buf(&bytes, *now) {
                    assert!(
                        *ack_storm
                            && matches!(
                                SrtPacket::decode(&bytes),
                                Ok(SrtPacket::Control(ControlPacket {
                                    control_type: ControlType::AckAck,
                                    ..
                                }))
                            ),
                        "listener accepts packet: {error}"
                    );
                }
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
    /// Above the 320 ms initial sender timeout plus the longest blocked-TX
    /// stretch these tests use (600 ms), below their shortest run (2 s).
    const FLIGHT_TSBPD_DELAY_MS: u16 = 1_000;

    /// Control: with nothing dropped, every payload arrives and the sender
    /// retransmits nothing. Without this the tail tests could pass or fail for a
    /// harness reason instead of the property under test.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "400-tick FlightHarness run, same scale as the tail-recovery tests below;   \
                  correctness is proven here at full scale outside Miri. Run in the          \
                  miri-extended scheduled job."
    )]
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
            .handle_nak_ranges(
                &[LossRange {
                    first_seq: first + 1,
                    last_seq: first + 1,
                }],
                now,
            )
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

        // Simulate the peer NAK-ing every one of them in one range, once the
        // pacing slots those sends took have passed (retransmissions share
        // that schedule).
        let first_visit = Timestamp::from_micros(10_000);
        let last_seq = first_seq.wrapping_add(SENT as u32 - 1);
        caller
            .sender
            .as_mut()
            .expect("connected sender")
            .handle_nak_ranges(
                &[LossRange {
                    first_seq,
                    last_seq,
                }],
                first_visit,
            )
            .unwrap();

        caller.process_retransmit(first_visit);

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
        caller.process_retransmit(Timestamp::from_micros(11_000));

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

    /// Drain `conn`'s output, following each `RetransmitContinue` it arms
    /// after the delay it asks for (as a transport timer store would), and
    /// return every retransmitted DATA as `(emitted at, sequence)`.
    fn drain_retransmissions(conn: &mut SrtConnection, at: &mut u64) -> Vec<(u64, u32)> {
        let mut retransmitted = Vec::new();
        loop {
            let mut continue_after = None;
            while let Some(output) = conn.poll_output().expect("output materializes") {
                match output {
                    ConnectionOutput::SendPacket(bytes) => {
                        if let Ok(SrtPacket::Data(packet)) = SrtPacket::decode(&bytes)
                            && packet.retransmitted
                        {
                            retransmitted.push((*at, packet.sequence_number));
                        }
                    }
                    ConnectionOutput::SetTimer {
                        id: TimerId::RetransmitContinue,
                        duration_micros,
                    } => continue_after = Some(duration_micros),
                    _ => {}
                }
            }
            let Some(delay) = continue_after else {
                return retransmitted;
            };
            *at += delay;
            conn.handle_timer(TimerId::RetransmitContinue, Timestamp::from_micros(*at))
                .expect("continuation");
        }
    }

    /// A caller that sent `count` packets of `payload` bytes at time 0, all
    /// drained to the wire, with no peer ACK.
    fn sent_unacknowledged(count: u32, payload: usize) -> (SrtConnection, u32, u32) {
        let (mut caller, _listener) = connected_pair();
        let first = caller.next_sequence_number().expect("connected sender");
        for _ in 0..count {
            caller
                .send(&vec![0u8; payload], Timestamp::from_micros(0))
                .expect("send admits the payload");
        }
        drain_outputs(&mut caller);
        let last = first.wrapping_add(count - 1) & SEQUENCE_MASK;
        (caller, first, last)
    }

    /// How many outputs waiting in `conn`'s queue `kind` matches.
    fn waiting(conn: &SrtConnection, kind: impl Fn(&QueuedOutput) -> bool) -> usize {
        conn.output_queue
            .iter()
            .filter(|output| kind(output))
            .count()
    }

    fn is_control(control_type: ControlType) -> impl Fn(&QueuedOutput) -> bool {
        move |output| {
            matches!(output, QueuedOutput::Datagram(PendingDatagram::Control(ctrl))
                if ctrl.control_type == control_type)
        }
    }

    fn is_retransmit_continue(output: &QueuedOutput) -> bool {
        matches!(
            output,
            QueuedOutput::SetTimer {
                id: TimerId::RetransmitContinue,
                ..
            }
        )
    }

    /// The sequence of every DATA datagram waiting in `conn`'s queue.
    fn waiting_data(conn: &SrtConnection) -> Vec<u32> {
        conn.output_queue
            .iter()
            .filter_map(|output| match output {
                QueuedOutput::Datagram(PendingDatagram::Data(data)) => {
                    Some(data.header.sequence_number)
                }
                _ => None,
            })
            .collect()
    }

    /// A peer can send ACKs faster than a blocked transport drains the
    /// output queue, and every numbered ACK asks for an ACKACK. One waits at
    /// a time: the peer measures its RTT from the one that goes out, and the
    /// first ACK after it went out gets its own. libsrt sends ACKACK as a
    /// best-effort datagram and never queues it (`CUDT::sendCtrl`).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "cap-scale loop (MAX_OUTPUT_QUEUE_ACTIONS ACKs); proven outside Miri"
    )]
    fn an_ack_storm_while_tx_is_blocked_keeps_one_ackack_waiting() {
        let (mut caller, first, _) = sent_unacknowledged(64, 100);
        let id = caller.socket_id();
        let ack =
            |number| ack_datagram_with_feedback(id, first, number, &[1_000, 100, 64, 0, 0, 0]);
        let at = Timestamp::from_micros(20_000);
        let storm = MAX_OUTPUT_QUEUE_ACTIONS as u32 + 1;
        for number in 1..=storm {
            caller
                .feed_recv_buf(&ack(number), at)
                .expect("a duplicate ACK is accepted");
        }
        assert_eq!(caller.state(), ConnectionState::Connected);
        assert_eq!(waiting(&caller, is_control(ControlType::AckAck)), 1);

        drain_outputs(&mut caller);
        caller
            .feed_recv_buf(&ack(storm + 1), at)
            .expect("a duplicate ACK is accepted");
        assert_eq!(waiting(&caller, is_control(ControlType::AckAck)), 1);
    }

    /// A NAK naming a packet whose retransmission still waits for TX
    /// capacity queues it no second time, however small an RTT the peer
    /// reports: the waiting copy answers it. libsrt has no such state (it
    /// sends a retransmission the moment it takes it off the loss list).
    /// Once the copy has gone out, a later report re-sends.
    #[test]
    fn a_nak_storm_while_tx_is_blocked_queues_each_retransmission_once() {
        let (mut caller, first, last) = sent_unacknowledged(64, 100);
        let id = caller.socket_id();
        // An RTT report of 1 us, repeated until the sender's estimate is
        // down to it, collapses the repeat interval.
        for number in 1..=200 {
            caller
                .feed_recv_buf(
                    &ack_datagram_with_feedback(id, first, number, &[1, 1, 64, 0, 0, 0]),
                    Timestamp::from_micros(10_000),
                )
                .expect("a duplicate ACK is accepted");
        }
        drain_outputs(&mut caller);
        let srtt = caller
            .sender
            .as_ref()
            .expect("sender")
            .rtt_estimate_micros()
            .0;
        assert!(srtt <= 1, "estimate {srtt} us");

        let nak = nak_datagram(id, &[first, last]);
        let mut at = 20_000;
        for _ in 0..200 {
            at += 10;
            caller
                .feed_recv_buf(&nak, Timestamp::from_micros(at))
                .expect("a credible NAK is accepted");
        }
        let mut queued = waiting_data(&caller);
        let waiting_copies = queued.len();
        queued.sort_unstable();
        queued.dedup();
        assert_eq!(
            waiting_copies,
            queued.len(),
            "each retransmission waits once"
        );
        assert_eq!(queued.len(), 64);

        drain_outputs(&mut caller);
        caller
            .feed_recv_buf(&nak, Timestamp::from_micros(at + 10))
            .expect("a credible NAK is accepted");
        assert!(
            !waiting_data(&caller).is_empty(),
            "a report after the copy went out re-sends"
        );
    }

    /// Every NAK runs the retransmit visit, which arms its continuation
    /// while work remains. With TX blocked, one arm waits at a time.
    #[test]
    fn a_nak_storm_while_tx_is_blocked_keeps_one_continuation_waiting() {
        let (mut caller, first, last) = sent_unacknowledged(64, 100);
        let nak = nak_datagram(caller.socket_id(), &[first, last]);
        for _ in 0..100 {
            caller
                .feed_recv_buf(&nak, Timestamp::from_micros(20_000))
                .expect("a credible NAK is accepted");
        }
        assert_eq!(waiting(&caller, is_retransmit_continue), 1);

        // Once it went out, the next visit that leaves work behind arms
        // again: a report past the repeat interval re-queues all 64, more
        // than one visit sends.
        drain_outputs(&mut caller);
        caller
            .feed_recv_buf(&nak, Timestamp::from_micros(1_000_000))
            .expect("a credible NAK is accepted");
        assert_eq!(waiting(&caller, is_retransmit_continue), 1);
    }

    /// A NAK into messages TLPKTDROP gave up is answered with up to
    /// `MAX_DROPREQ_PER_NAK` DROPREQs. With TX blocked, at most one report's
    /// answer waits; a later report is answered once it has gone out (the
    /// peer repeats its NAK until the range is gone).
    #[test]
    fn a_nak_storm_into_dropped_messages_keeps_one_reports_dropreqs_waiting() {
        let (mut caller, first, last) = sent_unacknowledged(64, 100);
        caller
            .handle_timer(TimerId::Ack, Timestamp::from_micros(2_000_000))
            .expect("ACK tick");
        assert_eq!(
            drain_drop_requests(&mut caller).len(),
            64,
            "every message expired"
        );

        let nak = nak_datagram(caller.socket_id(), &[first, last]);
        let at = Timestamp::from_micros(2_000_100);
        for _ in 0..100 {
            caller
                .feed_recv_buf(&nak, at)
                .expect("a NAK into dropped messages is accepted");
        }
        assert_eq!(caller.state(), ConnectionState::Connected);
        assert_eq!(
            waiting(&caller, is_control(ControlType::DropReq)),
            MAX_DROPREQ_PER_NAK
        );

        assert_eq!(drain_drop_requests(&mut caller).len(), MAX_DROPREQ_PER_NAK);
        caller
            .feed_recv_buf(&nak, at)
            .expect("a NAK into dropped messages is accepted");
        assert_eq!(
            waiting(&caller, is_control(ControlType::DropReq)),
            MAX_DROPREQ_PER_NAK
        );
    }

    /// TLPKTDROP gives up a flight the peer never acknowledges (S6). Once
    /// its DROPREQs are out, the next tick retires it as libsrt's
    /// `sndDropTooLate` fake ACK does (core.cpp:6806-6870), so a peer that
    /// stops acknowledging after drops cannot wedge the sender. A later NAK
    /// into the retired drops is answered with a DROPREQ for the range.
    #[test]
    fn drops_the_peer_never_acknowledges_free_the_window() {
        const WINDOW: u32 = 32;
        let (mut caller, _listener) = connected_pair_with_window(WINDOW);
        let first = caller.next_sequence_number().expect("connected sender");
        for _ in 0..WINDOW {
            caller
                .send(b"payload", Timestamp::from_micros(0))
                .expect("the window is open");
        }
        drain_outputs(&mut caller);
        assert!(!caller.can_send(), "the flight fills the window");

        caller
            .handle_timer(TimerId::Ack, Timestamp::from_micros(2_000_000))
            .expect("ACK tick");
        assert_eq!(drain_drop_requests(&mut caller).len(), WINDOW as usize);
        caller
            .handle_timer(TimerId::Ack, Timestamp::from_micros(2_010_000))
            .expect("ACK tick");
        drain_outputs(&mut caller);
        assert!(
            caller.can_send(),
            "the dropped flight no longer holds the window"
        );
        for _ in 0..WINDOW {
            caller
                .send(b"payload", Timestamp::from_micros(2_010_000))
                .expect("the window is open");
        }
        drain_outputs(&mut caller);

        let last = first.wrapping_add(WINDOW - 1) & SEQUENCE_MASK;
        caller
            .feed_recv_buf(
                &nak_datagram(caller.socket_id(), &[first, last]),
                Timestamp::from_micros(2_020_000),
            )
            .expect("a NAK into retired drops is accepted");
        assert_eq!(drain_drop_requests(&mut caller), [(first, last)]);
    }

    /// Retiring a large dropped flight without a peer ACK (S6) leaves
    /// dropping its pages to the retransmit continuation, as a large ACK
    /// does.
    #[test]
    fn retiring_a_large_dropped_flight_leaves_dropping_pages_to_the_continuation() {
        const SENT: u32 = 2_048;
        let (mut caller, _listener) = connected_pair();
        for _ in 0..SENT {
            caller
                .send(&[0u8; 1_000], Timestamp::from_micros(0))
                .expect("send admits the payload");
        }
        drain_outputs(&mut caller);
        caller
            .handle_timer(TimerId::Ack, Timestamp::from_micros(2_000_000))
            .expect("ACK tick");
        assert_eq!(drain_drop_requests(&mut caller).len(), SENT as usize);

        let now = Timestamp::from_micros(2_010_000);
        caller.handle_timer(TimerId::Ack, now).expect("ACK tick");
        let sender = caller.sender.as_ref().expect("connected sender");
        assert_eq!(sender.retained_span(), 0, "the dropped flight retired");
        assert!(sender.has_acked_packets_to_release());
        let arms_continuation = |outputs: &[ConnectionOutput]| {
            outputs.iter().any(|output| {
                matches!(
                    output,
                    ConnectionOutput::SetTimer {
                        id: TimerId::RetransmitContinue,
                        ..
                    }
                )
            })
        };
        assert!(arms_continuation(&drain_outputs(&mut caller)));
        for _ in 0..64 {
            caller
                .handle_timer(TimerId::RetransmitContinue, now)
                .expect("continuation");
            drain_outputs(&mut caller);
            if !caller
                .sender
                .as_ref()
                .expect("connected sender")
                .has_acked_packets_to_release()
            {
                return;
            }
        }
        panic!("the continuation must drain the retired pages");
    }

    /// A NAK repeated before the sender's own RTT estimate has elapsed since
    /// a packet's last retransmission is a report the peer sent before that
    /// retransmission could have reached it, so it re-sends nothing; a NAK
    /// after the interval is evidence the retransmission itself was lost and
    /// re-sends again. libsrt skips such repeats too
    /// (`CUDT::checkRexmitRightTime`, core.cpp:9827-9862).
    #[test]
    fn a_repeated_nak_retransmits_each_loss_once_per_rtt() {
        let (mut caller, first, last) = sent_unacknowledged(64, 100);
        let nak = nak_datagram(caller.socket_id(), &[first, last]);
        let mut at = 10_000;

        caller
            .feed_recv_buf(&nak, Timestamp::from_micros(at))
            .expect("a credible NAK is accepted");
        let burst = drain_retransmissions(&mut caller, &mut at);
        assert_eq!(burst.len(), 64, "the first NAK repairs every loss");
        let mut retransmitted = burst.len();
        for _ in 0..2 {
            caller
                .feed_recv_buf(&nak, Timestamp::from_micros(at))
                .expect("a credible NAK is accepted");
            retransmitted += drain_retransmissions(&mut caller, &mut at).len();
        }
        assert_eq!(retransmitted, 64, "three repeats of one NAK");

        for _ in 0..50 {
            caller
                .feed_recv_buf(&nak, Timestamp::from_micros(at))
                .expect("a credible NAK is accepted");
            retransmitted += drain_retransmissions(&mut caller, &mut at).len();
        }
        assert_eq!(retransmitted, 64, "fifty more repeats at one instant");
        assert_eq!(
            caller.sender_stats().expect("sender").total_lost,
            64,
            "a repeat that queues nothing reports no new loss"
        );

        // The sender has no RTT feedback yet, so its estimate is the initial
        // 100 ms. Pacing spreads the burst, so each packet's interval starts
        // at its own retransmission.
        let srtt = u64::from(
            caller
                .sender
                .as_ref()
                .expect("sender")
                .rtt_estimate_micros()
                .0,
        );
        let first_retransmission = burst[0].0;
        let last_retransmission = burst[burst.len() - 1].0;
        let resent_by = |caller: &mut SrtConnection, at: &mut u64| {
            caller
                .feed_recv_buf(&nak, Timestamp::from_micros(*at))
                .expect("a credible NAK is accepted");
            drain_retransmissions(caller, at)
                .into_iter()
                .map(|(_, seq)| seq)
                .collect::<Vec<_>>()
        };

        // Just inside the earliest retransmission's interval, nothing is due.
        at = first_retransmission + srtt - 1;
        assert_eq!(resent_by(&mut caller, &mut at), Vec::<u32>::new());

        // Halfway through the burst's intervals, exactly the packets
        // retransmitted at least one estimate earlier re-send.
        at = (first_retransmission + last_retransmission) / 2 + srtt;
        let due = |at: u64| {
            burst
                .iter()
                .filter(|&&(emitted, _)| emitted + srtt <= at)
                .map(|&(_, seq)| seq)
                .collect::<Vec<_>>()
        };
        let early = due(at);
        assert!(
            !early.is_empty() && early.len() < 64,
            "{} early",
            early.len()
        );
        assert_eq!(resent_by(&mut caller, &mut at), early);

        // Past the last one's interval, the rest re-send; the half that just
        // went is inside its new interval.
        at = at.max(last_retransmission + srtt);
        let rest = due(at)
            .into_iter()
            .filter(|seq| !early.contains(seq))
            .collect::<Vec<_>>();
        assert_eq!(early.len() + rest.len(), 64);
        assert_eq!(resent_by(&mut caller, &mut at), rest);
        assert_eq!(caller.sender_stats().expect("sender").total_lost, 128);
    }

    /// Retransmissions share the send-period schedule with new data, as
    /// libsrt's `packData` advances `m_tsNextSendTime` for every packet it
    /// sends: one window-wide NAK goes out at the configured rate (after at
    /// most one visit's burst), not as fast as the continuation can run.
    #[test]
    fn retransmissions_are_paced_at_the_configured_bandwidth() {
        const PAYLOAD: usize = 1_000;
        const BYTES_PER_SECOND: u64 = 100_000;
        let (mut caller, first, last) = sent_unacknowledged(64, PAYLOAD);
        caller
            .sender
            .as_mut()
            .expect("sender")
            .set_max_bandwidth(BYTES_PER_SECOND);
        let start = 2_000_000;
        let mut at = start;
        caller
            .feed_recv_buf(
                &nak_datagram(caller.socket_id(), &[first, last]),
                Timestamp::from_micros(at),
            )
            .expect("a credible NAK is accepted");
        let retransmitted = drain_retransmissions(&mut caller, &mut at);
        assert_eq!(retransmitted.len(), 64, "every loss is still repaired");

        // The pacing period is at least one header plus payload at the
        // configured rate.
        let min_period = (PAYLOAD + SRT_HEADER_SIZE) as u64 * 1_000_000 / BYTES_PER_SECOND;
        for window in [0, 50_000, 200_000] {
            let within = retransmitted
                .iter()
                .filter(|&&(emitted, _)| emitted - start <= window)
                .count() as u64;
            assert!(
                within <= MAX_RETRANSMITS_PER_VISIT as u64 + window / min_period + 1,
                "{within} retransmissions within {window} us"
            );
        }
    }

    /// A cumulative ACK of a large flight retires it at once and leaves only
    /// dropping its packets to the retransmit continuation, which stops
    /// re-arming once they are dropped -- also once the connection is
    /// closing and no longer retransmits.
    #[test]
    fn a_large_ack_leaves_dropping_packets_to_the_continuation() {
        for closing in [false, true] {
            drop_a_large_ack_in_bounded_visits(closing);
        }
    }

    fn drop_a_large_ack_in_bounded_visits(closing: bool) {
        const SENT: u32 = 2_048;
        let (mut caller, _listener) = connected_pair();
        let now = Timestamp::from_micros(0);
        let first_seq = caller.next_sequence_number().expect("connected sender");
        for _ in 0..SENT {
            caller
                .send(&[0u8; 1_000], now)
                .expect("send admits the payload");
        }
        drain_outputs(&mut caller);

        let ack_seq = first_seq.wrapping_add(SENT) & 0x7FFF_FFFF;
        caller
            .feed_recv_buf(&ack_datagram(caller.socket_id(), ack_seq, Some(8_192)), now)
            .expect("a current ACK is accepted");
        let sender = caller.sender.as_ref().expect("connected sender");
        assert_eq!(sender.packets_in_flight(), 0);
        assert!(sender.has_acked_packets_to_release());
        let arms_continuation = |outputs: &[ConnectionOutput]| {
            outputs.iter().any(|output| {
                matches!(
                    output,
                    ConnectionOutput::SetTimer {
                        id: TimerId::RetransmitContinue,
                        ..
                    }
                )
            })
        };
        assert!(arms_continuation(&drain_outputs(&mut caller)));
        if closing {
            caller.set_state(ConnectionState::Closing);
        }

        let mut visits = 0;
        loop {
            caller
                .handle_timer(TimerId::RetransmitContinue, now)
                .expect("continuation");
            visits += 1;
            assert!(
                visits <= 64,
                "the continuation must drain the retired pages"
            );
            let more = caller
                .sender
                .as_ref()
                .expect("connected sender")
                .has_acked_packets_to_release();
            assert_eq!(arms_continuation(&drain_outputs(&mut caller)), more);
            if !more {
                break;
            }
        }
        assert!(visits > 1, "closing {closing}: {visits}");
    }

    /// A NAK larger than one visit is finished by the retransmit
    /// continuation, and proves peer activity only once it validated, as of
    /// its arrival; one that fails validation never does.
    #[test]
    fn a_deferred_nak_proves_peer_activity_only_once_it_validates() {
        const SENT: u32 = MAX_NAK_POSITIONS_PER_VISIT + 1_000;
        let (mut caller, _listener) = connected_pair();
        let first_seq = caller.next_sequence_number().expect("connected sender");
        for i in 0..SENT {
            caller
                .send(&i.to_be_bytes(), Timestamp::from_micros(0))
                .expect("send admits the payload");
        }
        drain_outputs(&mut caller);

        let feed_nak = |caller: &mut SrtConnection, ranges: &[(u32, u32)], at: u64| {
            let mut control_info = Vec::new();
            for &(first, last) in ranges {
                encode_loss_range(&mut control_info, first, last);
            }
            let mut bytes = Vec::new();
            make_nak_packet(control_info, 0, caller.socket_id())
                .encode(&mut bytes)
                .expect("wire-format control");
            caller
                .feed_recv_buf(&bytes, Timestamp::from_micros(at))
                .expect("a deferred NAK is not rejected on arrival");
        };
        let finish = |caller: &mut SrtConnection, at: u64| {
            let mut visits = 0;
            while caller.sender.as_ref().unwrap().has_pending_nak() {
                caller
                    .handle_timer(TimerId::RetransmitContinue, Timestamp::from_micros(at))
                    .expect("continuation");
                visits += 1;
            }
            visits
        };
        let last_seq = first_seq.wrapping_add(SENT - 1) & SEQUENCE_MASK;
        let before = caller.last_recv_time;

        // An impossible tail: deferred on arrival, rejected later, and never
        // counted as activity.
        let unsent = first_seq.wrapping_add(SENT + 10) & SEQUENCE_MASK;
        feed_nak(
            &mut caller,
            &[(first_seq, last_seq), (unsent, unsent)],
            10_000,
        );
        assert_eq!(caller.last_recv_time, before);
        assert!(
            drain_outputs(&mut caller).iter().any(|output| matches!(
                output,
                ConnectionOutput::SetTimer {
                    id: TimerId::RetransmitContinue,
                    ..
                }
            )),
            "a deferred report arms its continuation"
        );
        assert!(finish(&mut caller, 20_000) > 0);
        assert_eq!(caller.last_recv_time, before);
        assert!(!caller.has_retransmit());

        // A credible report proves activity as of its arrival, once validated.
        feed_nak(&mut caller, &[(first_seq, last_seq)], 30_000);
        assert_eq!(caller.last_recv_time, before);
        finish(&mut caller, 40_000);
        assert_eq!(caller.last_recv_time, Some(Timestamp::from_micros(30_000)));
        assert!(caller.has_retransmit());
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
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
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
    /// `drop_current_key_schedule_for_test` forces that state directly; no
    /// production path reaches it now that a peer's KM installs only
    /// receive keys, but the pre-admission check must still hold.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "constructs a real CryptoContext, deriving its KEK via 2048               \
                  PBKDF2-HMAC-SHA1 iterations (per the SRT spec) under Miri; correctness    \
                  is proven outside Miri, and this property is unrelated to PBKDF2's own    \
                  iteration count. Run in the miri-extended scheduled job."
    )]
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

    /// libsrt 1.5.3 and older use a different AES-GCM nonce and AAD layout.
    /// A peer that advertises such a version is decrypted in that layout, so
    /// the default HSREQ must name a version that uses our modern format.
    #[test]
    fn gcm_caller_advertises_the_modern_aead_wire_version() {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            passphrase: Some("interop-passphrase".to_owned()),
            cipher_mode: CipherMode::Gcm,
            ..Default::default()
        });
        caller.connect(Timestamp::default()).unwrap();
        while caller.poll_output().unwrap().is_some() {}
        let mut response = HandshakePacket::new_induction_response(2, 7, 2);
        response.flow_window = DEFAULT_FLOW_WINDOW;
        caller
            .handle_handshake_caller(response, 0, Timestamp::from_micros(1))
            .unwrap();
        let conclusion = std::iter::from_fn(|| caller.poll_output().unwrap())
            .find_map(|output| match output {
                ConnectionOutput::SendPacket(wire) => Some(wire),
                _ => None,
            })
            .expect("CONCLUSION");
        let SrtPacket::Control(packet) = SrtPacket::decode(&conclusion).unwrap() else {
            panic!("CONCLUSION is a control packet");
        };
        let version = HandshakePacket::decode(&packet)
            .unwrap()
            .get_hs_extension()
            .unwrap()
            .srt_version;
        assert!(version >= 0x010504, "{version:#08x}");
    }

    /// P03: GCM's 16-byte tag is real wire overhead on top of the header
    /// and payload; a payload chunked purely against the raw
    /// `max_payload_size` budget (no cipher awareness) would put a packet
    /// on the wire that overshoots the connection's own configured
    /// datagram budget once encrypted. `effective_max_payload_size` must
    /// already exclude it, for both the single-packet and fragmented paths.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real AES-GCM encryption of near-MTU payloads under Miri (GHASH/AES          \
                  interpreted byte-by-byte); the size-budget arithmetic under test does not  \
                  depend on Miri's ownership checking and is proven at full scale outside     \
                  it. Run in the miri-extended scheduled job."
    )]
    fn gcm_wire_packets_never_exceed_the_datagram_budget() {
        let (mut caller, _listener) = connected_pair();
        while caller.poll_output().unwrap().is_some() {}
        // The cipher is installed behind the handshake's back, so the KK
        // field has no negotiated key material behind it: not a wire state
        // a peer could observe, so the strict checker stays out.
        caller.wire_checker = None;
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
        assert_eq!(negotiated_delays_micros(&caller), (500_000, 500_000));
        assert_eq!(negotiated_delays_micros(&listener), (500_000, 500_000));
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

    /// A peer without TSBPDSND/TLPKTDROP disables those negotiated live
    /// features, but its missing NAKREPORT does not stop this side's own
    /// periodic loss reports: that flag describes the peer's reporting.
    #[test]
    fn peer_capabilities_disable_optional_live_behaviour() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions::default());
        let mut peer = HandshakePacket::new_conclusion_request(1, 0, 0, 0, false);
        peer.add_hs_extension(0x010500, srt_flags::CRYPT | srt_flags::REXMITFLG, 120, 120);
        conn.apply_peer_handshake_extension(&peer);
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);

        assert!(!conn.tsbpd_enabled());
        assert!(!conn.tlpktdrop_enabled());
        assert!(conn.periodic_nak_enabled());
        assert!(!conn.receiver.as_ref().expect("receiver").tsbpd_enabled());
    }

    /// A libsrt peer with `SRTO_NAKREPORT=0` clears NAKREPORT in its HSREQ.
    /// libsrt keeps reporting its own losses periodically regardless
    /// (`m_config.bRcvNakReport` alone gates `checkNAKTimer`), so this side
    /// must too: after the first NAK is lost, the timer repeats the report.
    #[test]
    fn local_periodic_nak_repeats_losses_when_the_peer_clears_nakreport() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let mut no_nakreport = plain;
        no_nakreport.hs_flags_clear = srt_flags::PERIODICNAK;
        let mut attempt = handshake_with_rewrites(&no_nakreport, &plain, listener_options());
        attempt.listener_result.expect("listener accepts");
        let listener = &mut attempt.listener;
        let first = listener.initial_seq;
        let gap_end = (first + 2) & SEQUENCE_MASK;
        let gap_data = DataPacket::new(gap_end, 1, 1, 0, Vec::new().into());
        record_peer_data(listener, &gap_data);
        listener
            .receiver
            .as_mut()
            .expect("receiver")
            .receive(gap_data, Timestamp::from_micros(10_000));
        drain_outputs(listener);

        listener
            .handle_timer(TimerId::Nak, Timestamp::from_micros(1_000_000))
            .expect("NAK timer");
        let outputs = drain_outputs(listener);
        let naks = outputs
            .iter()
            .filter(|output| {
                matches!(output, ConnectionOutput::SendPacket(bytes)
                    if matches!(SrtPacket::decode(bytes), Ok(SrtPacket::Control(ControlPacket { control_type: ControlType::Nak, .. }))))
            })
            .count();
        assert!(naks > 0, "the outstanding loss is reported again");
        assert!(
            outputs.iter().any(|output| matches!(
                output,
                ConnectionOutput::SetTimer {
                    id: TimerId::Nak,
                    ..
                }
            )),
            "the periodic NAK timer stays armed"
        );
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
            |event| matches!(event, ConnectionEvent::DataReceived { payload, .. } if payload.eq(&b"queued"[..]))
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
    #[cfg_attr(
        miri,
        ignore = "cap-scale loop (100,000 duplicate SHUTDOWNs), same category as the         \
                  neighboring MAX_EVENT_QUEUE_ACTIONS/MAX_OUTPUT_QUEUE_ACTIONS loops; the     \
                  no-growth property is proven here at full scale outside Miri, and           \
                  `handle_shutdown`'s early-return ownership is exercised by the rest of      \
                  this module under Miri"
    )]
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

    /// A filled gap releases far more ready packets than one visit may move:
    /// each visit moves `MAX_DELIVERY_PER_VISIT` and re-arms
    /// `DeliveryContinue`; the visit that empties the receiver does not.
    #[test]
    fn a_released_window_is_delivered_in_bounded_visits() {
        const READY: u32 = 200;
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            flow_window_packets: 256,
            receive_buffer_packets: 256,
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
        for sequence_number in 1..READY {
            conn.handle_data_packet(
                DataPacket::new(sequence_number, sequence_number, 0, 0, vec![1].into()),
                now,
            )
            .expect("data behind the gap is accepted");
        }
        while conn.poll_output().unwrap().is_some() {}
        assert_eq!(conn.pending_data_events, 0, "the gap holds everything back");

        let visit_rearmed = |conn: &mut SrtConnection| {
            let mut rearmed = false;
            while let Some(output) = conn.poll_output().unwrap() {
                if let ConnectionOutput::SetTimer {
                    id: TimerId::DeliveryContinue,
                    duration_micros,
                } = output
                {
                    assert_eq!(duration_micros, 0, "a continuation, not a delay");
                    rearmed = true;
                }
            }
            rearmed
        };
        conn.handle_data_packet(DataPacket::new(0, 0, 0, 0, vec![1].into()), now)
            .expect("the gap fills");
        let mut delivered = vec![conn.pending_data_events];
        let mut rearmed = visit_rearmed(&mut conn);
        while rearmed {
            conn.handle_timer(TimerId::DeliveryContinue, now)
                .expect("continuation visit");
            delivered.push(conn.pending_data_events);
            rearmed = visit_rearmed(&mut conn);
        }
        let cap = MAX_DELIVERY_PER_VISIT as u32;
        assert_eq!(delivered, [cap, 2 * cap, 3 * cap, READY]);
    }

    /// Packets a DROPREQ removed are released by ACK ticks alone: an idle
    /// receiver still frees their storage, one bounded visit per tick.
    #[test]
    fn ack_ticks_release_packets_a_dropreq_removed() {
        const WINDOW: u32 = 1024;
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 120,
            flow_window_packets: WINDOW,
            receive_buffer_packets: WINDOW,
            delivery_queue_packets: WINDOW,
            ..ConnectionOptions::default()
        });
        conn.peer_srt_flags = Some(srt_flags::TSBPDSND);
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        let now = Timestamp::from_micros(0);
        for sequence_number in 0..1_000 {
            conn.handle_data_packet(
                DataPacket::new(sequence_number, 0, 0, 0, vec![1].into()),
                now,
            )
            .expect("in-window data is accepted");
        }
        while conn.poll_output().unwrap().is_some() {}
        let pages = |conn: &SrtConnection| {
            let receiver = conn.receiver.as_ref().unwrap();
            receiver.sparse_pages() + receiver.dense_pages()
        };
        let summary = conn
            .receiver
            .as_mut()
            .unwrap()
            .drop_range(0, 999)
            .expect("valid drop");
        assert_eq!(summary.packets_removed, 1_000);
        assert!(pages(&conn) > 0, "the drop visit releases only its budget");
        let mut ticks = 0;
        while pages(&conn) > 0 {
            ticks += 1;
            assert!(ticks <= 4, "release stalled");
            conn.handle_timer(TimerId::Ack, Timestamp::from_micros(ticks * 10_000))
                .expect("ACK tick");
        }
        assert_eq!(conn.receiver.as_ref().unwrap().expected_sequence(), 1_000);
    }

    /// A TLPKTDROP tick that stops at its gap budget continues on the
    /// zero-delay `DeliveryContinue` visit rather than a tick later, so a
    /// backlog of due gaps is given up as promptly as one uncapped pass.
    #[test]
    fn a_due_gap_backlog_is_given_up_in_continued_visits() {
        const WINDOW: u32 = 512;
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 120,
            flow_window_packets: WINDOW,
            receive_buffer_packets: WINDOW,
            delivery_queue_packets: WINDOW,
            ..ConnectionOptions::default()
        });
        conn.peer_srt_flags = Some(srt_flags::TSBPDSND | srt_flags::TLPKTDROP);
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        let now = Timestamp::from_micros(0);
        // 160 one-packet gaps, each before a packet due at 120 ms.
        for sequence_number in (1..320).step_by(2) {
            conn.handle_data_packet(
                DataPacket::new(sequence_number, sequence_number, 0, 0, vec![1].into()),
                now,
            )
            .expect("data behind each gap is accepted");
        }
        while conn.poll_output().unwrap().is_some() {}

        let expected = |conn: &SrtConnection| conn.receiver.as_ref().unwrap().expected_sequence();
        let continued = |conn: &mut SrtConnection| {
            let mut armed = false;
            while let Some(output) = conn.poll_output().unwrap() {
                armed |= matches!(
                    output,
                    ConnectionOutput::SetTimer {
                        id: TimerId::DeliveryContinue,
                        duration_micros: 0,
                    }
                );
            }
            armed
        };
        let late = Timestamp::from_micros(1_000_000);
        conn.handle_timer(TimerId::Ack, late).expect("ACK tick");
        let mut progress = vec![expected(&conn)];
        while continued(&mut conn) {
            conn.handle_timer(TimerId::DeliveryContinue, late)
                .expect("continuation visit");
            progress.push(expected(&conn));
        }
        let gap = 2 * MAX_EXPIRED_GAPS_PER_VISIT as u32;
        assert_eq!(progress[..3], [gap, 2 * gap, 320]);
        assert_eq!(*progress.last().unwrap(), 320);
        assert_eq!(conn.receiver.as_ref().unwrap().stats().total_dropped, 160);
    }

    #[test]
    fn inactivity_preserves_expiry_work_after_a_fragment_budget_cut() {
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 8_000,
            flow_window_packets: 128,
            receive_buffer_packets: 128,
            ..ConnectionOptions::default()
        });
        conn.peer_srt_flags = Some(srt_flags::TSBPDSND | srt_flags::TLPKTDROP);
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        let arrived = Timestamp::from_micros(0);
        conn.init_buffers(arrived, 0, 0);
        for sequence in 0..MAX_DELIVERY_PER_VISIT as u32 {
            let mut packet = DataPacket::new(sequence, 7, 0, 0, vec![1].into());
            packet.position = if sequence == 0 {
                crate::srt_packet::PacketPosition::First
            } else {
                crate::srt_packet::PacketPosition::Middle
            };
            conn.handle_data_packet(packet, arrived).expect("fragment");
        }
        conn.handle_data_packet(
            DataPacket::new(65, 8, 0, 0, b"tail".to_vec().into()),
            arrived,
        )
        .expect("complete message after the missing last fragment");
        conn.handle_shutdown(arrived).expect("peer shutdown");
        let due = Timestamp::from_micros(8_000_000);
        conn.handle_timer(TimerId::Inactivity, due)
            .expect("deadline");
        conn.handle_timer(TimerId::DeliveryContinue, due)
            .expect("expiry continuation");
        assert_delivered_payload(&mut conn, b"tail");
        assert_peer_shutdown_terminal(&mut conn);
    }

    #[test]
    fn deferred_inactivity_still_closes_an_incomplete_fragment_tail() {
        for tlpktdrop in [false, true] {
            assert_incomplete_tail_reaches_terminal(tlpktdrop);
        }
    }

    fn assert_incomplete_tail_reaches_terminal(tlpktdrop: bool) {
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 8_000,
            flow_window_packets: 128,
            receive_buffer_packets: 128,
            ..ConnectionOptions::default()
        });
        conn.peer_srt_flags =
            Some(srt_flags::TSBPDSND | if tlpktdrop { srt_flags::TLPKTDROP } else { 0 });
        conn.set_state(ConnectionState::Connected);
        let now = Timestamp::default();
        conn.init_buffers(now, 0, 0);
        conn.setup_connection_timers();
        for sequence in 0..=MAX_DELIVERY_PER_VISIT as u32 {
            let mut packet = DataPacket::new(sequence, 7, 0, 0, vec![1].into());
            packet.position = if sequence == 0 {
                crate::srt_packet::PacketPosition::First
            } else {
                crate::srt_packet::PacketPosition::Middle
            };
            conn.handle_data_packet(packet, now)
                .expect("incomplete fragment");
        }
        conn.handle_shutdown(now).expect("peer shutdown");
        let mut timers = TestTimers::default();
        for output in drain_outputs(&mut conn) {
            timers.apply(&output, now);
        }
        // Drive only armed timers; inactivity wins ties at the playout
        // deadline, before ACK or delivery continuation can finish the visit.
        for _ in 0..4_096 {
            let next = TimerId::ALL
                .iter()
                .filter_map(|&id| timers.deadlines[id.index()].map(|at| (id, at)))
                .min_by_key(|(id, at)| (at.as_micros(), *id != TimerId::Inactivity, id.index()));
            let Some((id, at)) = next.filter(|(_, at)| at.as_micros() <= 8_100_000) else {
                break;
            };
            timers.deadlines[id.index()] = None;
            conn.handle_timer(id, at).expect("armed timer");
            for output in drain_outputs(&mut conn) {
                timers.apply(&output, at);
            }
            if conn.state() == ConnectionState::Disconnected {
                break;
            }
        }
        assert_eq!(
            conn.state(),
            ConnectionState::Disconnected,
            "a budget cut must not lose the incomplete-tail expiry; tlpktdrop={tlpktdrop}"
        );
        let events: Vec<_> = std::iter::from_fn(|| conn.poll_event()).collect();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, ConnectionEvent::DataReceived { .. }))
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    event,
                    ConnectionEvent::Disconnected {
                        reason: DisconnectReason::PeerShutdown
                    }
                ))
                .count(),
            1
        );
    }

    #[test]
    fn tlpktdrop_continuations_preserve_a_message_larger_than_one_visit() {
        assert_fragmented_message_survives_delivery_visits(false, TimerId::Ack, true, 256);
    }

    #[test]
    fn tlpktdrop_shutdown_continuations_preserve_a_message_larger_than_one_visit() {
        assert_fragmented_message_survives_delivery_visits(true, TimerId::Ack, true, 256);
    }

    #[test]
    fn inactivity_at_playout_deadline_preserves_a_multi_visit_message() {
        for tlpktdrop in [false, true] {
            for queue in [1, 256] {
                assert_fragmented_message_survives_delivery_visits(
                    true,
                    TimerId::Inactivity,
                    tlpktdrop,
                    queue,
                );
            }
        }
    }

    fn assert_fragmented_message_survives_delivery_visits(
        peer_shutdown: bool,
        first_timer: TimerId,
        tlpktdrop: bool,
        queue: u32,
    ) {
        const PACKETS: u32 = 129;
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: if first_timer == TimerId::Inactivity {
                8_000
            } else {
                120
            },
            flow_window_packets: 256,
            receive_buffer_packets: 256,
            delivery_queue_packets: queue,
            ..ConnectionOptions::default()
        });
        conn.peer_srt_flags =
            Some(srt_flags::TSBPDSND | if tlpktdrop { srt_flags::TLPKTDROP } else { 0 });
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        let arrived = Timestamp::from_micros(0);
        for sequence in 0..PACKETS {
            let mut packet = DataPacket::new(sequence, 7, 0, 0, vec![sequence as u8].into());
            packet.position = match sequence {
                0 => crate::srt_packet::PacketPosition::First,
                n if n == PACKETS - 1 => crate::srt_packet::PacketPosition::Last,
                _ => crate::srt_packet::PacketPosition::Middle,
            };
            conn.handle_data_packet(packet, arrived).expect("fragment");
        }
        if peer_shutdown {
            conn.handle_shutdown(arrived).expect("peer shutdown");
        }
        let due = Timestamp::from_micros(u64::from(conn.options.tsbpd_delay) * 1_000);
        conn.handle_timer(first_timer, due).expect("delivery visit");
        for _ in 0..PACKETS {
            conn.handle_timer(TimerId::DeliveryContinue, due)
                .expect("delivery continuation");
        }
        let Some(ConnectionEvent::DataReceived {
            payload,
            packet_count,
            ..
        }) = conn.poll_event()
        else {
            panic!("complete fragmented message was not delivered");
        };
        assert_eq!(packet_count, PACKETS);
        let delivered: Vec<u8> = payload
            .chunks()
            .flat_map(|chunk| chunk.iter().copied())
            .collect();
        assert_eq!(delivered, (0..PACKETS).map(|n| n as u8).collect::<Vec<_>>());
        if peer_shutdown {
            assert_peer_shutdown_terminal(&mut conn);
        }
    }

    /// A local close releases the whole TSBPD-buffered tail in the call that
    /// closes: the peer's SHUTDOWN answer ends `Closing` before any
    /// `DeliveryContinue` visit could run.
    #[test]
    fn a_local_close_delivers_its_whole_tail_before_the_peer_answers() {
        const BUFFERED: u32 = 200;
        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 10_000,
            flow_window_packets: 256,
            receive_buffer_packets: 256,
            ..ConnectionOptions::default()
        });
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        let now = Timestamp::from_micros(0);
        conn.init_buffers(now, 0, 0);
        conn.receiver
            .as_mut()
            .expect("connected listener has a receiver")
            .set_tsbpd_enabled(true);
        for sequence_number in 0..BUFFERED {
            conn.handle_data_packet(
                DataPacket::new(sequence_number, sequence_number, 0, 0, vec![1].into()),
                now,
            )
            .expect("data is accepted");
        }
        assert_eq!(conn.pending_data_events, 0, "TSBPD holds everything");

        conn.disconnect(now);
        conn.handle_shutdown(now)
            .expect("the peer answers the close");
        assert_eq!(conn.state, ConnectionState::Disconnected);
        assert_eq!(conn.pending_data_events, BUFFERED);
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

    /// Caller/listener pair negotiated at a `window`-packet flow window,
    /// already `Connected`.
    fn connected_pair_with_window(window: u32) -> (SrtConnection, SrtConnection) {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            flow_window_packets: window,
            receive_buffer_packets: window,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            flow_window_packets: window,
            receive_buffer_packets: window,
            ..ConnectionOptions::default()
        });
        drive_handshake_to_connected(&mut caller, &mut listener);
        (caller, listener)
    }

    /// The windows every connection work-bound test compares.
    const WORK_BOUND_WINDOWS: [u32; 3] = [32, DEFAULT_FLOW_WINDOW, MAX_FLOW_WINDOW];

    /// A sender at `window` with `sent` packets accepted, the first half
    /// submitted and NAKed, so the output queue holds the unsubmitted half
    /// followed by the retransmissions of the submitted half. Returns the
    /// first sequence.
    fn queued_output_behind_retransmissions(caller: &mut SrtConnection, sent: u32) -> u32 {
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);
        let first = caller.next_sequence_number().expect("connected sender");
        for i in 0..sent {
            caller
                .send(format!("payload {i}").as_bytes(), now)
                .expect("the window is open");
        }
        for _ in 0..sent / 2 {
            drain_until_one_data_packet_submitted(caller);
        }
        let last = first.wrapping_add(sent / 2 - 1);
        // Not about pacing: every retransmission is queued at `now`.
        caller.set_packet_send_period(0);
        caller
            .feed_recv_buf(&nak_datagram(socket_id, &[first, last]), now)
            .expect("the NAK names submitted packets");
        while caller.has_retransmit() {
            caller.process_retransmit(now);
        }
        first
    }

    /// A duplicate or non-advancing ACK changes nothing that is live, so it
    /// never rescans the queued output; an advancing one purges it in one
    /// pass, one visit per queued action, even when what it retires sits in
    /// the middle of the queue (retransmissions behind unsubmitted DATA).
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "thousands of real sends and polls at three windows; correctness is proven \
                  outside Miri. Run in the miri-extended scheduled job."
    )]
    fn a_non_advancing_ack_does_not_rescan_queued_output() {
        let mut results = Vec::new();
        for window in WORK_BOUND_WINDOWS {
            let (mut caller, _listener) = connected_pair_with_window(window);
            let socket_id = caller.socket_id();
            let now = Timestamp::from_micros(1_000_000);
            let sent = window.min(4_000);
            let first = queued_output_behind_retransmissions(&mut caller, sent);
            let queued = caller.output_queue.len() as u64;
            assert!(queued >= u64::from(sent), "window {window}: {queued}");
            let duplicate = ack_datagram(socket_id, first, Some(window));
            let (_, duplicates) = WorkCounters::measure(|| {
                for _ in 0..100 {
                    caller
                        .feed_recv_buf(&duplicate, now)
                        .expect("a duplicate ACK is accepted");
                }
            });
            let advancing = ack_datagram(socket_id, first.wrapping_add(sent / 4), Some(window));
            let queued = caller.output_queue.len() as u64;
            let retiring = caller
                .output_queue
                .iter()
                .filter(|output| {
                    matches!(
                        output,
                        QueuedOutput::Datagram(PendingDatagram::Data(data))
                            if data.header.sequence_number.wrapping_sub(first) < sent / 4
                    )
                })
                .count();
            assert_eq!(retiring, sent as usize / 4, "window {window}");
            let (_, advance) = WorkCounters::measure(|| caller.feed_recv_buf(&advancing, now));
            let sender = caller.sender.as_ref().expect("connected sender");
            assert!(
                caller.output_queue.iter().all(|output| !matches!(
                    output,
                    QueuedOutput::Datagram(PendingDatagram::Data(data))
                        if !sender.is_live(data.header.sequence_number)
                )),
                "window {window}: the retired retransmissions left the queue"
            );
            results.push((
                window,
                queued,
                duplicates.output_queue_visits,
                advance.output_queue_visits,
            ));
        }
        eprintln!(
            "(window, queued, 100 duplicate ACKs' output visits, advancing ACK's): {results:?}"
        );
        for (window, queued, duplicates, advance) in results {
            assert_eq!(duplicates, 0, "window {window}");
            assert!(advance <= queued + 1, "window {window}");
        }
    }

    /// A connected sender at `window` with `window - queued` packets
    /// submitted and `queued` more accepted but still in the output queue.
    fn sender_with_flight_and_queue(window: u32, queued: u32, now: Timestamp) -> SrtConnection {
        let (mut caller, _listener) = connected_pair_with_window(window);
        let mut datagram = [0u8; 1_500];
        let mut sent = 0;
        while sent < window - queued {
            let burst = (window - queued - sent).min(4_096);
            for _ in 0..burst {
                caller.send(b"payload", now).expect("the window is open");
            }
            while caller
                .poll_output_into(&mut datagram)
                .expect("output materializes")
                .is_some()
            {}
            sent += burst;
        }
        for _ in 0..queued {
            caller.send(b"payload", now).expect("the window is open");
        }
        caller
    }

    /// One send-side entry point the bounded-work proptest drives, with
    /// span-relative arguments (fractions in 1/65,536ths).
    #[derive(Debug, Clone)]
    enum SendWorkAction {
        Send { share: u16 },
        Poll { share: u16 },
        DuplicateAck,
        StaleAck { behind: u16 },
        Ack { ahead: u16 },
        Nak { at: u16, width: u16, overlap: bool },
        Tick { timer: u8, elapsed: u32 },
    }

    fn send_work_action() -> impl proptest::strategy::Strategy<Value = SendWorkAction> {
        use proptest::prelude::*;
        let width = prop_oneof![Just(0u16), Just(u16::MAX), any::<u16>()];
        prop_oneof![
            2 => any::<u16>().prop_map(|share| SendWorkAction::Send { share }),
            2 => any::<u16>().prop_map(|share| SendWorkAction::Poll { share }),
            2 => Just(SendWorkAction::DuplicateAck),
            1 => any::<u16>().prop_map(|behind| SendWorkAction::StaleAck { behind }),
            2 => (0..4_096u16).prop_map(|ahead| SendWorkAction::Ack { ahead }),
            4 => (any::<u16>(), width, any::<bool>())
                .prop_map(|(at, width, overlap)| SendWorkAction::Nak { at, width, overlap }),
            3 => (0..3u8, 0..400_000u32)
                .prop_map(|(timer, elapsed)| SendWorkAction::Tick { timer, elapsed }),
        ]
    }

    /// `fraction` (in 1/65,536ths) of `span`.
    fn span_share(span: u32, fraction: u16) -> u32 {
        ((u64::from(span) * u64::from(fraction)) >> 16) as u32
    }

    /// Per-call work limits every send-side entry point stays within at
    /// every window: one purge of the bounded output queue (and an ACKACK
    /// queued ahead of it); one retransmission visit's pops, one ACK or
    /// tick's compaction step and two checks per position one NAK visit
    /// queues; one NAK visit's positions (a report that validates within
    /// the visit is also committed in it); `MAX_DROPREQ_PER_NAK` DROPREQs
    /// per report a visit finishes; one RTO candidate step.
    const SEND_OUTPUT_LIMIT: u64 = MAX_OUTPUT_QUEUE_ACTIONS as u64 + 1;
    const SEND_LIST_LIMIT: u64 = (MAX_RETRANSMITS_PER_VISIT
        * crate::srt_sender::MAX_STALE_RETRANSMITS_SKIPPED_PER_POP
        + crate::srt_sender::STALE_RETRANSMITS_CHECKED_PER_CALL
        + crate::srt_sender::STALE_RETRANSMITS_CHECKED_PER_PUSH
            * MAX_NAK_POSITIONS_PER_VISIT as usize) as u64;
    const SEND_NAK_LIMIT: u64 = 2 * MAX_NAK_POSITIONS_PER_VISIT as u64;
    const SEND_DROPREQ_LIMIT: u64 =
        (crate::srt_sender::MAX_DROPREQ_PER_NAK * MAX_NAK_POSITIONS_PER_VISIT as usize) as u64;
    /// Binary-search steps over at most a window of drop records, per
    /// position one visit validates.
    const SEND_RECORD_LIMIT: u64 = 17 * MAX_NAK_POSITIONS_PER_VISIT as u64;

    /// Send up to `count` packets, keeping the output queue clear of its
    /// overflow limit.
    fn send_up_to(conn: &mut SrtConnection, count: u32, now: Timestamp) {
        let room = (MAX_OUTPUT_QUEUE_ACTIONS - 512).saturating_sub(conn.output_queue.len());
        for _ in 0..(count as usize).min(room) {
            if conn.send(b"payload", now).is_err() {
                return;
            }
        }
    }

    /// Poll up to `count` outputs.
    fn poll_up_to(conn: &mut SrtConnection, count: u32) {
        for _ in 0..count {
            if conn.poll_output().expect("output materializes").is_none() {
                return;
            }
        }
    }

    /// The loss list a NAK action names inside the submitted span
    /// `oldest..oldest + span`: one range, or three overlapping ones.
    fn work_nak_ranges(oldest: u32, span: u32, at: u16, width: u16, overlap: bool) -> Vec<u32> {
        let last_offset = span.saturating_sub(1);
        let first = span_share(last_offset, at);
        let last = first + span_share(last_offset - first, width);
        let (first, last) = (oldest.wrapping_add(first), oldest.wrapping_add(last));
        let middle = first.wrapping_add(last.wrapping_sub(first) / 2);
        let ranges = if overlap {
            vec![first, middle, first, last, middle, middle]
        } else {
            vec![first, last]
        };
        ranges.into_iter().map(|s| s & SEQUENCE_MASK).collect()
    }

    /// Apply one action and return the work it did.
    fn apply_send_work_action(
        conn: &mut SrtConnection,
        action: &SendWorkAction,
        window: u32,
        clock: &mut u64,
    ) -> WorkCounters {
        let socket_id = conn.socket_id();
        let sender = conn.sender.as_ref().expect("connected sender");
        let oldest = sender.oldest_unacked_sequence();
        let span = sender.max_justified_ack_position().wrapping_sub(oldest) & SEQUENCE_MASK;
        let ack = |position: u32| ack_datagram(socket_id, position & SEQUENCE_MASK, Some(window));
        let now = Timestamp::from_micros(*clock);
        let ((), work) = WorkCounters::measure(|| match *action {
            SendWorkAction::Send { share } => send_up_to(conn, span_share(window, share), now),
            SendWorkAction::Poll { share } => poll_up_to(conn, span_share(window, share)),
            SendWorkAction::DuplicateAck => {
                let _ = conn.feed_recv_buf(&ack(oldest), now);
            }
            SendWorkAction::StaleAck { behind } => {
                let behind = span_share(window, behind).max(1);
                let _ = conn.feed_recv_buf(&ack(oldest.wrapping_sub(behind)), now);
            }
            SendWorkAction::Ack { ahead } => {
                let ahead = span_share(span, ahead).max(u32::from(span > 0));
                let _ = conn.feed_recv_buf(&ack(oldest.wrapping_add(ahead)), now);
            }
            SendWorkAction::Nak { at, width, overlap } => {
                let ranges = work_nak_ranges(oldest, span, at, width, overlap);
                let _ = conn.feed_recv_buf(&nak_datagram(socket_id, &ranges), now);
            }
            SendWorkAction::Tick { timer, elapsed } => {
                *clock += u64::from(elapsed);
                let id = [
                    TimerId::Ack,
                    TimerId::SenderRto,
                    TimerId::RetransmitContinue,
                ][usize::from(timer)];
                let _ = conn.handle_timer(id, Timestamp::from_micros(*clock));
            }
        });
        work
    }

    fn within_send_limits(action: &SendWorkAction, work: &WorkCounters) -> bool {
        let output = match action {
            SendWorkAction::DuplicateAck | SendWorkAction::StaleAck { .. } => 0,
            _ => SEND_OUTPUT_LIMIT,
        };
        work.output_queue_visits <= output
            && work.retransmit_entries_visited <= SEND_LIST_LIMIT
            && work.nak_positions_visited <= SEND_NAK_LIMIT
            && work.dropreq_runs_visited <= SEND_DROPREQ_LIMIT
            && work.sender_record_probes <= SEND_RECORD_LIMIT
            && work.rto_candidate_steps <= 1
    }

    proptest::proptest! {
        // Building a whole 65,536-packet flight is most of a case's cost, so
        // a few long streams cover more than many short ones.
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(6))]

        /// Random send-side streams -- duplicate and stale ACKs over a
        /// large queued output, advancing ACKs, singleton, wide and
        /// overlapping NAKs (into dropped messages once TLPKTDROP ticks
        /// have run), output polling and ACK, RTO and retransmit timer
        /// ticks -- keep every call's work within the same
        /// window-independent limits at W = 32 / 8,192 / 65,536.
        #[test]
        #[cfg_attr(miri, ignore = "window-scale streams; the work bounds are not memory safety")]
        fn send_entry_points_do_window_independent_work(
            actions in proptest::collection::vec(send_work_action(), 1..160),
        ) {
            for window in WORK_BOUND_WINDOWS {
                let mut clock = 1_000_000;
                let queued = (window / 2).min(4_000);
                let mut conn =
                    sender_with_flight_and_queue(window, queued, Timestamp::from_micros(clock));
                for action in &actions {
                    let work = apply_send_work_action(&mut conn, action, window, &mut clock);
                    proptest::prop_assert!(
                        within_send_limits(action, &work),
                        "window {}: {:?} did {:?}", window, action, work
                    );
                }
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

    /// The frontier is a position in the protocol's 31-bit sequence space, so
    /// the wrap behaves like every other position: a position just past the
    /// wrap is not justifiable until its DATA is submitted, and once it is,
    /// an ACK naming the position past the wrap retires the flight while one
    /// position further is refused. A refusal must also leave the sender
    /// untouched -- including the advertised window it would otherwise
    /// compute from the named position -- so the refused ACK at the end here
    /// carries a full 16-byte control-info.
    #[test]
    fn ack_frontier_wraps_with_the_sequence_space() {
        const SEQUENCE_MASK: u32 = 0x7fff_ffff;
        let options = ConnectionOptions {
            initial_seq: Some(SEQUENCE_MASK - 1),
            ..ConnectionOptions::default()
        };
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..options.clone()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            ..options
        });
        drive_handshake_to_connected(&mut caller, &mut listener);

        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);
        let first = caller.next_sequence_number().expect("connected sender");
        assert_eq!(
            first,
            SEQUENCE_MASK - 1,
            "the connection starts one sequence before the wrap"
        );
        caller.send(b"last", now).expect("the window is open");
        caller.send(b"wrapped", now).expect("the window is open");
        let buffered = |caller: &SrtConnection| {
            caller
                .sender_stats()
                .expect("connected sender")
                .packets_in_buffer
        };

        // Both payloads sit in the sender buffer, but only the first has
        // crossed the submission boundary, so the frontier stops at the wrap
        // and position 0 is not justifiable yet. This is the protocol's 31-bit
        // order, not a plain integer compare.
        drain_until_one_data_packet_submitted(&mut caller);
        assert_eq!(buffered(&caller), 2, "both payloads are buffered");
        let refused = caller
            .feed_recv_buf(&ack_datagram(socket_id, 0, Some(8)), now)
            .expect_err("an ACK for a position the peer cannot have seen is refused");
        assert_eq!(refused.kind, crate::error::ErrorKind::InvalidData);
        assert!(
            refused.to_string().contains("peer-justified frontier"),
            "the frontier is what refused it: {refused}"
        );
        assert_eq!(buffered(&caller), 2, "the refused ACK retired nothing");

        // With the second payload submitted too, the walk crosses the wrap
        // and an ACK naming position 0 retires both entries.
        drain_until_one_data_packet_submitted(&mut caller);
        caller
            .feed_recv_buf(&ack_datagram(socket_id, 0, Some(8)), now)
            .expect("an ACK for the position past the wrap is justified");
        assert_eq!(
            buffered(&caller),
            0,
            "the ACK across the wrap retires both entries"
        );

        // One position further is past the frontier again.
        let baseline = caller.stats();
        let sender_baseline = caller.sender_stats();
        let error = caller
            .feed_recv_buf(&ack_datagram_with_shape(socket_id, 1, 16, 1), now)
            .expect_err("the wrap does not widen the frontier");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("peer-justified frontier"),
            "the frontier is what refused it: {error}"
        );
        assert_eq!(caller.stats(), baseline, "the refused ACK changed state");
        assert_eq!(
            caller.sender_stats(),
            sender_baseline,
            "the refused ACK changed no sender accounting"
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

        // A Light ACK must never carry an ACK number. A reference-Full size
        // numbered 0 is libsrt's 31-bit ACK number after its wrap and is
        // accepted (`CAckNo::incack`, `processCtrlAck`).
        let ack_seq = caller.sender.as_ref().unwrap().oldest_unacked_sequence();
        let error = caller
            .feed_recv_buf(&ack_datagram_with_shape(socket_id, ack_seq, 4, 1), now)
            .expect_err("a Light ACK must not carry an ACK number");
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        caller
            .feed_recv_buf(&ack_datagram_with_shape(socket_id, ack_seq, 24, 0), now)
            .expect("a 24-byte ACK numbered 0 is accepted");
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

    /// Wire ACK with an explicit cumulative position, ACK number, and
    /// RTT/RTTVar/window/rate fields, for exercising exactly which fields
    /// each ACK size actually carries. `fields` are the words following
    /// `ack_seq`: `[rtt, rtt_var, window]` for 16 bytes,
    /// `[rtt, rtt_var, window, pps, link]` for 24, or
    /// `[rtt, rtt_var, window, pps, link, byte_rate]` for 28/32.
    fn ack_datagram_with_feedback(
        dest_socket_id: u32,
        ack_seq: u32,
        ack_number: u32,
        fields: &[u32],
    ) -> Vec<u8> {
        let mut control_info = Vec::new();
        write_u32(&mut control_info, ack_seq);
        for &field in fields {
            write_u32(&mut control_info, field);
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

    /// The rate-snapshot quarter of `SenderStats`, for the assertions in
    /// `ack_rate_telemetry_is_preserved_or_honestly_absent_by_size`.
    fn rate_snapshot(
        stats: &crate::sender::SenderStats,
    ) -> (Option<u32>, Option<u32>, Option<u32>, Option<u64>) {
        (
            stats.peer_receiving_rate_packets_per_second,
            stats.peer_link_capacity_packets_per_second,
            stats.peer_receiving_rate_bytes_per_second,
            stats.peer_link_capacity_bytes_per_second,
        )
    }

    /// A 16-byte Small ACK carries no rate section at all, and a 24-byte
    /// ACK carries rate/link but no byte-rate field -- neither must
    /// overwrite or fabricate telemetry the ACK that produced it never
    /// actually reported. Only a 28/32-byte ACK's rate snapshot is
    /// complete.
    #[test]
    fn ack_rate_telemetry_is_preserved_or_honestly_absent_by_size() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);
        let ack_seq = caller.sender.as_ref().unwrap().oldest_unacked_sequence();

        // 1. A 28-byte ACK populates the complete rate snapshot.
        caller
            .feed_recv_buf(
                &ack_datagram_with_feedback(
                    socket_id,
                    ack_seq,
                    1,
                    &[10_000, 500, 60, 1_000, 2_000, 1_500_000],
                ),
                now,
            )
            .expect("a 28-byte ACK is accepted");
        let stats = caller.sender_stats().expect("connected sender");
        assert_eq!(stats.peer_rtt_micros, Some(10_000));
        assert_eq!(stats.peer_available_buffer_packets, Some(60));
        assert_eq!(
            rate_snapshot(&stats),
            (Some(1_000), Some(2_000), Some(1_500_000), Some(3_000_000)),
            "a 28-byte ACK's snapshot must be complete"
        );

        // 2. A later numbered 16-byte Small ACK updates RTT/window only.
        caller
            .feed_recv_buf(
                &ack_datagram_with_feedback(socket_id, ack_seq, 2, &[20_000, 800, 70]),
                now,
            )
            .expect("a numbered 16-byte Small ACK is accepted");
        let stats = caller.sender_stats().expect("connected sender");
        assert_eq!(stats.peer_rtt_micros, Some(20_000), "RTT must update");
        assert_eq!(
            stats.peer_available_buffer_packets,
            Some(70),
            "window must update"
        );
        // 3. Rate telemetry must remain the previously known snapshot, not
        // zero.
        assert_eq!(
            rate_snapshot(&stats),
            (Some(1_000), Some(2_000), Some(1_500_000), Some(3_000_000)),
            "a Small ACK must not overwrite the previous rate snapshot"
        );

        // 4. A 24-byte ACK with different pps/link.
        caller
            .feed_recv_buf(
                &ack_datagram_with_feedback(
                    socket_id,
                    ack_seq,
                    3,
                    &[20_000, 800, 70, 4_000, 8_000],
                ),
                now,
            )
            .expect("a 24-byte ACK is accepted");
        let stats = caller.sender_stats().expect("connected sender");
        // 5. pps/link change; the missing byte-rate (and anything derived
        // from it) must be represented honestly as absent, never fabricated
        // as zero.
        assert_eq!(
            rate_snapshot(&stats),
            (Some(4_000), Some(8_000), None, None),
            "a 24-byte ACK has no byte-rate field, so neither it nor the derived \
             byte-bandwidth may be fabricated as zero"
        );

        // 6. A subsequent 28-byte ACK repopulates the complete snapshot.
        caller
            .feed_recv_buf(
                &ack_datagram_with_feedback(
                    socket_id,
                    ack_seq,
                    4,
                    &[20_000, 800, 70, 5_000, 9_000, 2_500_000],
                ),
                now,
            )
            .expect("a 28-byte ACK is accepted");
        let stats = caller.sender_stats().expect("connected sender");
        assert_eq!(
            rate_snapshot(&stats),
            (Some(5_000), Some(9_000), Some(2_500_000), Some(4_500_000)),
            "a subsequent 28-byte ACK must repopulate the complete snapshot"
        );
    }

    /// A peer's ACK RTT/RTTVar feedback is a raw `u32` field -- any value is
    /// wire-legal. Reaches the same overflow-safe EWMA arithmetic as
    /// `srt_sender::tests::rtt_ewma_never_overflows_on_near_u32_max_peer_feedback`,
    /// through real ACK decoding: a numbered Small ACK (16 bytes) reaches
    /// this path exactly like a Full ACK does since round 2's Haivision
    /// compatibility fix.
    #[test]
    fn ack_wire_feedback_near_u32_max_never_overflows_the_rtt_estimator() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let now = Timestamp::from_micros(1_000_000);

        for _ in 0..8 {
            let ack_seq = caller.sender.as_ref().unwrap().oldest_unacked_sequence();
            let mut control_info = Vec::new();
            write_u32(&mut control_info, ack_seq);
            write_u32(&mut control_info, u32::MAX - 1); // RTT
            write_u32(&mut control_info, u32::MAX - 1); // RTTVar
            write_u32(&mut control_info, 60); // available buffer
            let pkt = ControlPacket {
                control_type: ControlType::Ack,
                subtype: 0,
                type_specific_info: 7, // numbered Small ACK
                timestamp: 0,
                dest_socket_id: socket_id,
                control_info,
            };
            let mut datagram = Vec::new();
            pkt.encode(&mut datagram).expect("ACK encodes");
            caller
                .feed_recv_buf(&datagram, now)
                .expect("a numbered Small ACK with extreme RTT feedback is accepted");
        }

        let timeout = caller.sender.as_ref().unwrap().rto_base_timeout_micros();
        assert!(
            timeout <= crate::sender_rto::MAX_RTO_MICROS,
            "RTO base timeout {timeout} must stay bounded by MAX_RTO_MICROS"
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

    /// Full ACKs a saturated receiver sends in one simulated second, as
    /// `(send time us, advertised window)` pairs.
    ///
    /// The peer refills the window the moment it has room, the application
    /// consumes one packet every `consume_every_us`, and the transport
    /// fires each requested Ack deadline `timer_lateness_us` late. In each
    /// step DATA arrives before a due Ack timer and the application consumes
    /// after it, so a periodic Full ACK sees the window full and every
    /// consume after it can arm a forced reopen: the worst case.
    fn saturated_receiver_full_acks(
        window: u32,
        delivery_queue: u32,
        consume_every_us: u64,
        timer_lateness_us: u64,
    ) -> Vec<(u64, u32)> {
        const STEP_US: u64 = 10;
        const RUN_US: u64 = 1_000_000;

        fn drain(
            conn: &mut SrtConnection,
            now_us: u64,
            timer_lateness_us: u64,
            ack_deadline: &mut Option<u64>,
            full_acks: &mut Vec<(u64, u32)>,
        ) {
            while let Some(output) = conn.poll_output().expect("output materializes") {
                match output {
                    ConnectionOutput::SetTimer {
                        id: TimerId::Ack,
                        duration_micros,
                    } => *ack_deadline = Some(now_us + duration_micros + timer_lateness_us),
                    ConnectionOutput::SendPacket(bytes) => {
                        if let Ok(SrtPacket::Control(packet)) = SrtPacket::decode(&bytes)
                            && packet.control_type == ControlType::Ack
                            && let Some(available) = full_ack_available(&bytes)
                        {
                            full_acks.push((now_us, available));
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut conn = SrtConnection::new_listener(ConnectionOptions {
            tsbpd_delay: 0,
            flow_window_packets: window,
            receive_buffer_packets: window,
            delivery_queue_packets: delivery_queue,
            ..ConnectionOptions::default()
        });
        conn.set_state(ConnectionState::Connected);
        let _ = conn.poll_event();
        conn.init_buffers(Timestamp::from_micros(0), 0, 0);
        conn.receiver
            .as_mut()
            .expect("connected listener has a receiver")
            .set_tsbpd_enabled(false);

        // `init_buffers` does not arm timers; the first tick starts the
        // self-re-arming ACK timer chain, as `setup_connection_timers` would.
        let (mut ack_deadline, mut full_acks) =
            (Some(crate::receiver::ACK_INTERVAL_MICROS), Vec::new());
        drain(
            &mut conn,
            0,
            timer_lateness_us,
            &mut ack_deadline,
            &mut full_acks,
        );
        let (mut received, mut consumed) = (0u32, 0u32);
        for now_us in (STEP_US..=RUN_US).step_by(STEP_US as usize) {
            let now = Timestamp::from_micros(now_us);
            if received - consumed < window {
                conn.handle_data_packet(
                    DataPacket::new(received, received, 0, 0, vec![1].into()),
                    now,
                )
                .expect("data is accepted");
                received += 1;
            }
            if ack_deadline.is_some_and(|deadline| deadline <= now_us) {
                ack_deadline = None;
                conn.handle_timer(TimerId::Ack, now).expect("ACK tick");
            }
            if now_us.is_multiple_of(consume_every_us)
                && matches!(
                    conn.poll_event(),
                    Some(ConnectionEvent::DataReceived { .. })
                )
            {
                consumed += 1;
            }
            drain(
                &mut conn,
                now_us,
                timer_lateness_us,
                &mut ack_deadline,
                &mut full_acks,
            );
        }
        assert!(
            consumed >= (RUN_US / consume_every_us) as u32 * 9 / 10,
            "the application kept consuming at its rate"
        );
        full_acks
    }

    /// The window-reopen Full ACK is keyed to the window a Full ACK
    /// carried, so a receiver the application drains at 50k packets/s
    /// sends at most two Full ACKs in any ACK interval -- the periodic one
    /// that advertised zero and the forced reopen -- and stays inside the
    /// ACKACK history it promises to keep for one second. A Light ACK
    /// carries no window, so one taken at a full window must not arm a
    /// forced Full ACK: that coupled the Full ACK rate to packets/64.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "simulates one second in 10 us steps (100k steps x 4 configurations): over   \
                  90 minutes under Miri, past any job budget. The rate bound is proven      \
                  outside Miri, and it holds no unsafe or ownership pattern the cheaper     \
                  receiver tests do not cover, so the miri-extended job skips it too."
    )]
    fn a_saturated_receiver_sends_at_most_two_full_acks_per_ack_interval() {
        const INTERVAL: u64 = crate::receiver::ACK_INTERVAL_MICROS;
        for (window, delivery_queue, timer_lateness_us) in
            [(128, 64, 0), (128, 64, 500), (32, 1, 0), (256, 256, 3_000)]
        {
            let acks = saturated_receiver_full_acks(window, delivery_queue, 20, timer_lateness_us);
            let label = format!("window {window}, timer {timer_lateness_us} us late");
            let per_interval = acks
                .iter()
                .enumerate()
                .map(|(index, &(start, _))| {
                    acks[index..]
                        .iter()
                        .take_while(|&&(sent, _)| sent < start + INTERVAL)
                        .count()
                })
                .max()
                .unwrap_or(0);
            assert!(
                per_interval <= 2,
                "{label}: {per_interval} Full ACKs in one interval"
            );
            assert!(
                acks.len() <= crate::srt_receiver::MAX_ACK_TIMESTAMPS,
                "{label}: {} Full ACKs in one second outrun the ACKACK history",
                acks.len()
            );
            // The worst case is exercised: a forced reopen Full ACK follows a
            // zero-window Full ACK within the same interval. (It may itself
            // advertise zero when the peer refilled first.)
            assert!(
                acks.windows(2)
                    .any(|pair| pair[0].1 == 0 && pair[1].0 - pair[0].0 < INTERVAL),
                "{label}: the zero-window -> forced-reopen cycle must run"
            );
        }
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
        let socket_id = caller.socket_id();
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

        // A peer that actually received the DROPREQ above (and so advanced
        // its own expected sequence past it, per `ReceiverBuffer::
        // drop_range`) can legitimately cumulative-ACK past this position --
        // its knowledge came from the DROPREQ crossing the wire, not from
        // the DATA that never did.
        caller
            .feed_recv_buf(
                &ack_datagram(socket_id, first.wrapping_add(1), Some(8)),
                expired,
            )
            .expect("an ACK justified by the DROPREQ's own delivery is accepted");
        assert_eq!(
            caller.sender.as_ref().unwrap().oldest_unacked_sequence(),
            first.wrapping_add(1),
            "the tombstone must retire"
        );
        assert!(
            caller.can_send(),
            "sender capacity must reopen once the tombstone retires"
        );
    }

    /// A live, unsubmitted hole blocks the ACK-justified frontier even when
    /// a *later* sequence has already been submitted: `justified_frontier`
    /// cannot jump over it just because something past it advanced. `seq0`
    /// expires (via TLPKTDROP) before its DATA is ever submitted; `seq1`'s
    /// DATA is submitted normally. Until `seq0`'s own DROPREQ crosses the
    /// wire, an ACK through `seq1` must still be rejected -- exactly the
    /// case a naive `max(newest_submitted, dropped_end) + 1` model would
    /// get wrong.
    #[test]
    fn ack_frontier_stops_at_an_unnotified_hole_even_behind_a_later_submission() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let seq0 = caller.next_sequence_number().expect("connected sender");

        // seq0: accepted at t=0, deliberately never drained.
        caller
            .send(b"seq0 never submitted", Timestamp::from_micros(0))
            .expect("accepted");
        // seq1: accepted later (t=900ms), so it will not have aged past the
        // 1s TLPKTDROP floor when seq0 has.
        caller
            .send(b"seq1 submitted", Timestamp::from_micros(900_000))
            .expect("accepted");

        // seq0 ages out; seq1 has not yet. Only seq0 is tombstoned, and its
        // queued DATA is purged, leaving seq1's DATA at the front of the
        // queue.
        let expired = Timestamp::from_micros(1_000_001);
        caller
            .handle_timer(TimerId::Ack, expired)
            .expect("ACK tick");

        // Drain exactly one DATA datagram: seq1's, now at the front. seq0's
        // DROPREQ is still queued behind it, not yet materialized.
        drain_until_one_data_packet_submitted(&mut caller);

        let seq1 = seq0.wrapping_add(1);
        let baseline = caller.stats();
        let error = caller
            .feed_recv_buf(
                &ack_datagram(socket_id, seq1.wrapping_add(1), Some(8)),
                expired,
            )
            .expect_err(
                "an ACK past the still-unnotified seq0 hole is rejected even though seq1 \
                 was submitted",
            );
        assert_eq!(error.kind, crate::error::ErrorKind::InvalidData);
        assert_eq!(caller.stats(), baseline, "rejected input changed state");

        // Once seq0's DROPREQ actually crosses the wire, the same ACK
        // becomes valid: the peer could now legitimately have learned of
        // both positions.
        assert!(
            !drop_requests_in(&drain_outputs(&mut caller)).is_empty(),
            "seq0's DROPREQ must still be queued and now drains"
        );
        caller
            .feed_recv_buf(
                &ack_datagram(socket_id, seq1.wrapping_add(1), Some(8)),
                expired,
            )
            .expect("the same ACK is accepted once the hole's DROPREQ is notified");
        assert_eq!(
            caller.sender.as_ref().unwrap().oldest_unacked_sequence(),
            seq1.wrapping_add(1)
        );
    }

    /// Drain queued output until exactly one DROPREQ has materialized
    /// (skipping over any control/timer output ahead of it), then stop --
    /// leaving everything after it, including any further DROPREQ, still
    /// queued.
    fn drain_until_one_drop_request_submitted(conn: &mut SrtConnection) {
        loop {
            let output = conn
                .poll_output()
                .unwrap()
                .expect("a DROPREQ is still queued to drain");
            if let ConnectionOutput::SendPacket(bytes) = &output
                && let Ok(SrtPacket::Control(pkt)) = SrtPacket::decode(bytes)
                && pkt.control_type == ControlType::DropReq
            {
                return;
            }
        }
    }

    /// `submitted` is a historical fact: once a peer could have received a
    /// sequence's DATA, TLPKTDROP tombstoning that same retained entry
    /// *later* does not make the peer forget it. `seq0` never has its DATA
    /// submitted at all (tombstoned first); `seq1`'s DATA *is* submitted,
    /// and only afterward does `seq1` also age into a tombstone, before its
    /// own DROPREQ has gone out. Once `seq0`'s DROPREQ (the one thing `seq0`
    /// was actually missing) crosses the wire, the peer can legitimately
    /// know both positions -- `seq0` via the DROPREQ, `seq1` via the DATA it
    /// already received -- so `ACK(seq1 + 1)` must be justified without
    /// waiting for `seq1`'s own (separately queued) DROPREQ.
    #[test]
    fn ack_frontier_survives_tlpktdrop_after_the_data_was_already_submitted() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let seq0 = caller.next_sequence_number().expect("connected sender");
        let seq1 = seq0.wrapping_add(1);

        // seq0: accepted at t=0, deliberately never drained.
        caller
            .send(b"seq0 never submitted", Timestamp::from_micros(0))
            .expect("accepted");
        // seq1: accepted later (t=900ms), so it ages out on its own schedule.
        caller
            .send(
                b"seq1 submitted then also expires",
                Timestamp::from_micros(900_000),
            )
            .expect("accepted");

        // seq0 ages out (age 1_000_001 > 1s floor); seq1 has not yet (age
        // 100_001). Only seq0 is tombstoned and purged; seq1's DATA is now
        // at the front of the queue.
        let first_tick = Timestamp::from_micros(1_000_001);
        caller
            .handle_timer(TimerId::Ack, first_tick)
            .expect("ACK tick");

        // Materialize seq1's DATA while seq0's DROPREQ stays queued: seq1 is
        // now a historically-submitted entry.
        drain_until_one_data_packet_submitted(&mut caller);

        // Advance far enough that seq1 (sent at t=900ms) also ages past the
        // 1s floor, without ever draining seq0's still-queued DROPREQ.
        let second_tick = Timestamp::from_micros(1_900_001);
        caller
            .handle_timer(TimerId::Ack, second_tick)
            .expect("ACK tick");
        // seq1 is now: dropped = true, submitted = true, drop_notified =
        // false -- exactly the state the frontier predicate must not treat
        // as unjustified.

        // Materialize only seq0's DROPREQ (queued first); seq1's own
        // DROPREQ (queued by the second tick) stays behind it, undrained.
        drain_until_one_drop_request_submitted(&mut caller);

        assert_eq!(
            caller.sender.as_ref().unwrap().max_justified_ack_position(),
            seq1.wrapping_add(1),
            "seq1's earlier DATA submission must still justify it even though \
             it is now also a tombstone"
        );
        caller
            .feed_recv_buf(
                &ack_datagram(socket_id, seq1.wrapping_add(1), Some(8)),
                second_tick,
            )
            .expect(
                "ACK(seq1 + 1) is justified by seq0's DROPREQ plus seq1's earlier DATA \
                 submission, without waiting for seq1's own DROPREQ",
            );
        assert_eq!(
            caller.sender.as_ref().unwrap().oldest_unacked_sequence(),
            seq1.wrapping_add(1)
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
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "encrypted handshake plus AES-GCM under Miri (dominates this job's time, ~7   \
                  minutes for this one test alone -- GHASH/AES interpreted byte-by-byte);      \
                  correctness is proven outside Miri, and the reservation-accounting property  \
                  itself is unrelated to the cipher (see the plaintext queued-DATA regressions \
                  above). Run in the miri-extended scheduled job."
    )]
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

    fn hostile_control_corpus() -> Vec<(&'static str, Vec<u8>)> {
        include_str!("../tests/corpus/hostile-controls.hex")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| {
                let (label, hex) = line
                    .split_once('|')
                    .expect("hostile corpus entry has a label and hex datagram");
                assert!(hex.len().is_multiple_of(2), "{label}: even hex length");
                let bytes = hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                            .expect("valid hex byte")
                    })
                    .collect();
                (label, bytes)
            })
            .collect()
    }

    /// Malformed or hostile control input is rejected *before* it can refresh
    /// peer activity or touch connection state.
    ///
    /// This is the invariant Robotweax 0.2.2 pins with
    /// `compat_runtime_rejects_malformed_controls_without_refreshing_liveness`,
    /// reached here through the real wire decoder rather than by calling the
    /// handlers directly. Also covers ACK/NAK payloads that are well-formed
    /// but semantically impossible (a non-canonical ACK length, or a
    /// cumulative/loss position beyond this sender's peer-justified
    /// frontier): those are rejected by the handlers themselves, not by
    /// shape validation, but must leave exactly the same zero footprint.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "full caller/listener handshake plus hostile control corpus; correctness is \
                  proven outside Miri. Run in the miri-extended scheduled job."
    )]
    fn malformed_controls_cannot_refresh_liveness_or_state() {
        let (mut caller, _listener) = connected_pair();
        let socket_id = caller.socket_id();
        let _ = drain_outputs(&mut caller);
        while caller.poll_event().is_some() {}
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

        let corpus = hostile_control_corpus();
        let malformed: Vec<(&str, Vec<u8>)> = vec![
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
                // Eight bytes: longer than the one-word error form (which
                // is a valid, ignored KMRSP -- see
                // `a_one_word_kmrsp_error_is_ignored_without_state_change`)
                // and shorter than any KM message.
                "key-management response with a truncated body",
                control_datagram(
                    socket_id,
                    ControlType::UserDefined,
                    SRT_CMD_KMRSP,
                    0,
                    vec![0; 8],
                ),
            ),
        ];

        let baseline = caller.stats();
        let later = now.add_micros(1_000);
        for (label, datagram) in corpus.into_iter().chain(malformed) {
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
            assert!(
                drain_outputs(&mut caller).is_empty(),
                "{label}: rejected input emitted output"
            );
            assert!(
                caller.poll_event().is_none(),
                "{label}: rejected input emitted an application event"
            );
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

    /// A one-word KMRSP is the peer reporting a key-material error state.
    /// The reference ignores it during an established session without
    /// changing security state; here it is accepted as well-formed, changes
    /// nothing, and leaves an outstanding rotation to its own bounded
    /// retries rather than being counted as malformed input.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real AES-CTR handshake and encrypted round trips under Miri; run in the \
                  miri-extended scheduled job"
    )]
    fn a_one_word_kmrsp_error_is_ignored_without_state_change() {
        let (mut caller, mut listener) = encrypted_pair(CipherMode::Ctr);
        for connection in [&mut caller, &mut listener] {
            while connection.poll_event().is_some() {}
            let _ = drain_outputs(connection);
        }
        let now = Timestamp::from_micros(10_000_000);
        caller
            .provide_new_sek(&[0x33; 16], now)
            .expect("rotation starts");
        let _ = drain_outputs(&mut caller);
        let before = km_security_snapshot(&caller);
        let pending_before = caller
            .km_control
            .as_ref()
            .and_then(|state| state.pending.as_ref())
            .map(|pending| pending.request.clone());
        assert!(pending_before.is_some(), "a rotation is outstanding");

        let error_word = (KmError::BadSecret as u32).to_le_bytes().to_vec();
        let datagram = control_datagram(
            caller.socket_id(),
            ControlType::UserDefined,
            SRT_CMD_KMRSP,
            0,
            error_word,
        );
        caller
            .feed_recv_buf(&datagram, now.add_micros(10))
            .expect("a one-word KMRSP error is well-formed");

        assert_eq!(
            km_security_snapshot(&caller),
            before,
            "no security state change"
        );
        assert_eq!(
            caller
                .km_control
                .as_ref()
                .and_then(|state| state.pending.as_ref())
                .map(|pending| pending.request.clone()),
            pending_before,
            "the rotation keeps its own bounded retries"
        );
        assert_encrypted_roundtrip(
            &mut caller,
            &mut listener,
            now.add_micros(20),
            b"after an error KMRSP",
        );
    }

    /// Regression for the post-establishment encryption-state downgrade class
    /// fixed by Haivision in CVE-2026-55868. Every hostile KM control is
    /// rejected transactionally: the secured context, generation histories,
    /// liveness, output, and subsequent encrypted DATA path stay intact.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real AES-CTR handshake and repeated encrypted round trips under Miri; run in \
                  the miri-extended scheduled job"
    )]
    fn hostile_key_management_cannot_downgrade_a_secured_session() {
        let (mut caller, mut listener) = encrypted_pair(CipherMode::Ctr);
        for connection in [&mut caller, &mut listener] {
            while connection.poll_event().is_some() {}
            let _ = drain_outputs(connection);
        }

        let mut tick = 10_000_000;
        assert_encrypted_roundtrip(
            &mut caller,
            &mut listener,
            Timestamp::from_micros(tick),
            b"initial caller data",
        );
        tick += 10;
        assert_encrypted_roundtrip(
            &mut listener,
            &mut caller,
            Timestamp::from_micros(tick),
            b"initial listener data",
        );

        let old_material = current_km_message(&caller);

        // A four-byte KMRSP whose word is not a known KM state (BadSecret
        // written big-endian; the reference's error word is little-endian)
        // is malformed, and must not demote an already-secured sender. The
        // genuine one-word error form is ignored instead:
        // `a_one_word_kmrsp_error_is_ignored_without_state_change`.
        let mut failure = Vec::with_capacity(4);
        write_u32(&mut failure, KmError::BadSecret as u32);
        tick += 10;
        assert_km_control_rejected(
            &mut caller,
            SRT_CMD_KMRSP,
            failure,
            Timestamp::from_micros(tick),
            "delayed handshake KMRSP failure",
        );
        assert_encrypted_roundtrip(
            &mut listener,
            &mut caller,
            Timestamp::from_micros(tick + 1),
            b"after delayed failure",
        );

        tick += 10;
        // A KMRSP body that is a real KM message truncated mid-header: a
        // malformed shape rather than a hard-coded value.
        let mut truncated_response = KmMessage::new(
            KeyFlag::Even,
            KeyLength::Aes128,
            fixture_salt(),
            vec![0x5A; 24],
            CipherMode::Ctr,
        )
        .encode();
        truncated_response.truncate(16);
        assert_km_control_rejected(
            &mut caller,
            SRT_CMD_KMRSP,
            truncated_response,
            Timestamp::from_micros(tick),
            "malformed KMRSP",
        );
        assert_encrypted_roundtrip(
            &mut listener,
            &mut caller,
            Timestamp::from_micros(tick + 1),
            b"after malformed response",
        );

        tick += 10;
        assert_km_control_rejected(
            &mut caller,
            SRT_CMD_KMRSP,
            old_material.encode(),
            Timestamp::from_micros(tick),
            "valid old handshake KMRSP",
        );
        assert_encrypted_roundtrip(
            &mut listener,
            &mut caller,
            Timestamp::from_micros(tick + 1),
            b"after old response",
        );

        // A syntactically valid header that declares no supported AES key
        // length must fail before touching the receiver's key slots.
        let mut malformed_key_length = old_material.encode();
        malformed_key_length[15] = 5; // 20 bytes, not AES-128/192/256.
        tick += 10;
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            malformed_key_length,
            Timestamp::from_micros(tick),
            "KMREQ with malformed key length",
        );
        assert_encrypted_roundtrip(
            &mut caller,
            &mut listener,
            Timestamp::from_micros(tick + 1),
            b"after malformed request",
        );

        // Start a real refresh. While its response is pending, an otherwise
        // valid response carrying different key material must not acknowledge
        // this rotation.
        caller
            .provide_new_sek(&[0x6B; 16], Timestamp::from_micros(tick + 2))
            .expect("start key refresh");
        let request = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        let mut unrelated = key_message_from_datagram(&request);
        unrelated.wrapped_key[0] ^= 0x80;
        tick += 10;
        assert_km_control_rejected(
            &mut caller,
            SRT_CMD_KMRSP,
            unrelated.encode(),
            Timestamp::from_micros(tick),
            "KMRSP for unrelated generation",
        );
        assert_encrypted_roundtrip(
            &mut listener,
            &mut caller,
            Timestamp::from_micros(tick + 1),
            b"while response pending",
        );

        // The matching request/response still succeeds after the attacks.
        listener
            .feed_recv_buf(&request, Timestamp::from_micros(tick + 2))
            .expect("matching KMREQ is accepted");
        let response = take_user_defined_datagram(&mut listener, SRT_CMD_KMRSP);
        caller
            .feed_recv_buf(&response, Timestamp::from_micros(tick + 3))
            .expect("matching KMRSP is accepted");

        tick += 10;
        assert_km_control_rejected(
            &mut caller,
            SRT_CMD_KMRSP,
            key_message_from_datagram(&response).encode(),
            Timestamp::from_micros(tick),
            "duplicated successful KMRSP",
        );
        assert_encrypted_roundtrip(
            &mut listener,
            &mut caller,
            Timestamp::from_micros(tick + 1),
            b"after duplicate response",
        );

        // The handshake's even key is still the listener's current even
        // receive key, so repeating its KM changes nothing and is answered
        // (libsrt answers a cached duplicate too).
        tick += 10;
        let before_repeat = km_security_snapshot(&listener);
        feed_kmreq_expect_echo(
            &mut listener,
            &old_material.encode(),
            Timestamp::from_micros(tick),
        );
        assert_eq!(km_security_snapshot(&listener), before_repeat);

        // Once the peer replaces that even key, replaying the old KM would
        // roll the receive slot back: refused, with nothing changed.
        tick += 10;
        let replacement =
            libsrt_km_body(0b01, test_km_salt(), &[&fixture_key(0x7E)], CipherMode::Ctr);
        feed_kmreq_expect_echo(&mut listener, &replacement, Timestamp::from_micros(tick));
        tick += 10;
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            old_material.encode(),
            Timestamp::from_micros(tick),
            "KMREQ replay of a replaced generation",
        );
        assert_encrypted_roundtrip(
            &mut listener,
            &mut caller,
            Timestamp::from_micros(tick + 1),
            b"after stale request",
        );
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real AES-CTR handshake and late-handshake matrix under Miri; run in the \
                  miri-extended scheduled job"
    )]
    fn late_handshakes_cannot_roll_back_or_retarget_a_connected_session() {
        let (mut caller, mut listener) = encrypted_pair(CipherMode::Ctr);
        let conclusion_request = caller
            .last_handshake_packet
            .clone()
            .expect("caller retained its CONCLUSION request");
        let conclusion_response = listener
            .last_handshake_packet
            .clone()
            .expect("listener retained its CONCLUSION response");

        for (target, valid) in [
            (&mut caller, conclusion_response),
            (&mut listener, conclusion_request),
        ] {
            // Each CONCLUSION keeps the destination it had on the wire: the
            // caller's request names socket 0 (libsrt's does too), so an
            // established listener must still answer a repeat sent that way.
            let _ = drain_outputs(target);
            while target.poll_event().is_some() {}
            let peer_id = target.peer_socket_id;
            let cookie = target.syn_cookie;
            let original = HandshakePacket::decode(&valid).expect("valid conclusion");
            let mut different_socket = original.clone();
            different_socket.socket_id ^= 1;
            let mut different_cookie = original.clone();
            different_cookie.syn_cookie ^= 1;
            let mut different_isn = original.clone();
            different_isn.initial_packet_seq ^= 1;
            let bad = [
                (
                    "late rejection",
                    HandshakePacket::new_rejection(peer_id, cookie, 3)
                        .encode(0, target.socket_id()),
                ),
                (
                    "late induction",
                    HandshakePacket::new_induction_response(peer_id, cookie, 0)
                        .encode(0, target.socket_id()),
                ),
                (
                    "retargeted socket",
                    different_socket.encode(0, target.socket_id()),
                ),
                (
                    "wrong cookie",
                    different_cookie.encode(0, target.socket_id()),
                ),
                ("wrong ISN", different_isn.encode(0, target.socket_id())),
            ];

            let baseline = target.stats();
            let before = km_security_snapshot(target);
            let last_recv_time = target.last_recv_time;
            for (label, datagram) in bad {
                let mut bytes = Vec::new();
                datagram.encode(&mut bytes).expect("wire-format control");
                let error = target
                    .feed_recv_buf(&bytes, Timestamp::from_micros(1_000_000))
                    .expect_err("late handshake mismatch must be rejected");
                assert_eq!(error.kind, crate::error::ErrorKind::InvalidData, "{label}");
                assert_eq!(km_security_snapshot(target), before, "{label}");
                assert_eq!(target.stats(), baseline, "{label}");
                assert_eq!(target.last_recv_time, last_recv_time, "{label}");
                assert!(drain_outputs(target).is_empty(), "{label}: output");
                assert!(target.poll_event().is_none(), "{label}: event");
            }

            let mut truncated = valid.clone();
            truncated.control_info.pop();
            let mut bytes = Vec::new();
            truncated.encode(&mut bytes).expect("wire-format control");
            target
                .feed_recv_buf(&bytes, Timestamp::from_micros(1_000_001))
                .expect_err("truncated late extension must be rejected");
            assert_eq!(km_security_snapshot(target), before);
            assert_eq!(target.last_recv_time, last_recv_time);
            assert!(drain_outputs(target).is_empty());

            // A genuine repeated CONCLUSION remains recoverable after all
            // invalid controls; only it may re-send the retained response.
            let mut bytes = Vec::new();
            valid
                .encode(&mut bytes)
                .expect("valid duplicate conclusion");
            target
                .feed_recv_buf(&bytes, Timestamp::from_micros(1_000_002))
                .expect("same peer may retransmit its CONCLUSION");
            assert!(
                drain_outputs(target)
                    .iter()
                    .any(|output| matches!(output, ConnectionOutput::SendPacket(_))),
                "a genuine duplicate still gets its handshake response"
            );
            assert_eq!(target.state(), ConnectionState::Connected);
        }
        assert_encrypted_roundtrip(
            &mut caller,
            &mut listener,
            Timestamp::from_micros(1_000_010),
            b"post-handshake caller DATA",
        );
        assert_encrypted_roundtrip(
            &mut listener,
            &mut caller,
            Timestamp::from_micros(1_000_020),
            b"post-handshake listener DATA",
        );
    }

    /// Only a listener is addressed by socket 0 once connected (a caller
    /// sends every CONCLUSION there); a connected caller refuses a
    /// handshake sent there.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real AES-CTR handshake under Miri; run in the miri-extended scheduled job"
    )]
    fn a_connected_caller_refuses_a_handshake_addressed_to_socket_zero() {
        let (mut caller, listener) = encrypted_pair(CipherMode::Ctr);
        let mut stray = listener
            .last_handshake_packet
            .clone()
            .expect("listener retained its CONCLUSION response");
        stray.dest_socket_id = 0;
        let mut bytes = Vec::new();
        stray.encode(&mut bytes).expect("wire-format control");
        let _ = drain_outputs(&mut caller);
        caller
            .feed_recv_buf(&bytes, Timestamp::from_micros(1_000_003))
            .expect_err("a connected caller is not addressed by socket 0");
        assert!(drain_outputs(&mut caller).is_empty());
        assert_eq!(caller.state(), ConnectionState::Connected);
    }

    /// A documentation-range peer address on `family`'s path.
    fn path_address(family: IpFamily) -> std::net::SocketAddr {
        match family {
            IpFamily::V4 => "192.0.2.1:9000".parse().unwrap(),
            IpFamily::V6 => "[2001:db8::1]:9000".parse().unwrap(),
        }
    }

    /// One handshake attempt in which the caller and the listener advertise
    /// `caller_mss` and `listener_mss` instead of their constructor defaults,
    /// and both connections are told their path is `family`, as a transport
    /// does from its socket address (`SrtConnection::set_peer_address`).
    struct MssHandshake {
        caller: SrtConnection,
        listener: SrtConnection,
        /// Feeding the caller's rewritten CONCLUSION request to the listener.
        listener_result: Result<(), Error>,
        /// Feeding the listener's rewritten CONCLUSION response to the caller.
        caller_result: Result<(), Error>,
    }

    /// How a test wants in-flight handshake packets rewritten.
    #[derive(Clone, Copy)]
    struct HandshakeRewrite {
        /// Advertised MSS.
        mss: u32,
        /// Path family of the side that sends these packets.
        family: IpFamily,
        /// Add a FILTER extension: a packet-filter *negotiation*.
        filter_extension: bool,
        /// Set `PACKET_FILTER` in the HS extension's `srt_flags`: a
        /// capability *advertisement*, which must stay acceptable on its own.
        packet_filter_flag: bool,
        /// Optional wire-level overrides for handshake regressions.
        flow_window: Option<u32>,
        handshake_version: Option<u32>,
        srt_version: Option<u32>,
        /// HS extension flags to clear, then to set.
        hs_flags_clear: u32,
        hs_flags_set: u32,
        /// HS extension (RCV, SND) latency halves.
        latency: Option<(u16, u16)>,
    }

    impl HandshakeRewrite {
        fn mss(mss: u32, family: IpFamily) -> Self {
            Self {
                mss,
                family,
                filter_extension: false,
                packet_filter_flag: false,
                flow_window: None,
                handshake_version: None,
                srt_version: None,
                hs_flags_clear: 0,
                hs_flags_set: 0,
                latency: None,
            }
        }
    }

    /// Rewrite one handshake packet: its advertised MSS, its peer address,
    /// and optionally its packet-filter advertisement or negotiation.
    fn rewrite_handshake(datagram: &[u8], rewrite: &HandshakeRewrite) -> Vec<u8> {
        let SrtPacket::Control(control) =
            SrtPacket::decode(datagram).expect("handshake datagram decodes")
        else {
            panic!("handshake must be a control packet");
        };
        let mut handshake = HandshakePacket::decode(&control).expect("handshake decodes");
        handshake.mtu = rewrite.mss;
        if let Some(flow_window) = rewrite.flow_window {
            handshake.flow_window = flow_window;
        }
        if let Some(version) = rewrite.handshake_version {
            handshake.version = version;
        }
        if rewrite.packet_filter_flag
            && let Some(extension) = handshake.get_hs_extension()
        {
            handshake
                .extensions
                .retain(|ext| !matches!(ext.ext_type, ExtensionType::HsReq | ExtensionType::HsRsp));
            handshake.add_hs_extension(
                extension.srt_version,
                extension.srt_flags | srt_flags::PACKET_FILTER,
                extension.recv_tsbpd_delay,
                extension.send_tsbpd_delay,
            );
        }
        if rewrite.filter_extension {
            handshake.extensions.push(HandshakeExtension {
                ext_type: ExtensionType::Filter,
                data: b"fec\0".to_vec(),
            });
            handshake.extension_field |= extension_flags::CONFIG;
        }
        for extension in &mut handshake.extensions {
            if matches!(
                extension.ext_type,
                ExtensionType::HsReq | ExtensionType::HsRsp
            ) && extension.data.len() == 12
            {
                rewrite_hs_block(&mut extension.data, rewrite);
            }
        }
        let rewritten = handshake.encode(control.timestamp, control.dest_socket_id);
        let mut bytes = Vec::new();
        rewritten.encode(&mut bytes).expect("re-encodes");
        bytes
    }

    /// Apply a rewrite's version, flag and latency overrides to one raw
    /// 12-byte HSREQ/HSRSP block.
    fn rewrite_hs_block(data: &mut [u8], rewrite: &HandshakeRewrite) {
        if let Some(version) = rewrite.srt_version {
            data[..4].copy_from_slice(&version.to_be_bytes());
        }
        let flags = u32::from_be_bytes(data[4..8].try_into().expect("four bytes"));
        let flags = (flags & !rewrite.hs_flags_clear) | rewrite.hs_flags_set;
        data[4..8].copy_from_slice(&flags.to_be_bytes());
        if let Some((rcv, snd)) = rewrite.latency {
            data[8..10].copy_from_slice(&rcv.to_be_bytes());
            data[10..12].copy_from_slice(&snd.to_be_bytes());
        }
    }

    /// Every handshake packet in the connection's output queue, rewritten.
    fn drain_rewritten_handshakes(
        conn: &mut SrtConnection,
        rewrite: &HandshakeRewrite,
    ) -> Vec<Vec<u8>> {
        let mut rewritten = Vec::new();
        for output in drain_outputs(conn) {
            let ConnectionOutput::SendPacket(bytes) = output else {
                continue;
            };
            let is_handshake = matches!(
                SrtPacket::decode(&bytes),
                Ok(SrtPacket::Control(ControlPacket {
                    control_type: ControlType::Handshake,
                    ..
                }))
            );
            if is_handshake {
                rewritten.push(rewrite_handshake(&bytes, rewrite));
            }
        }
        rewritten
    }

    fn mss_handshake(
        caller_mss: u32,
        listener_mss: u32,
        family: IpFamily,
        listener_options: ConnectionOptions,
    ) -> MssHandshake {
        handshake_with_rewrites(
            &HandshakeRewrite::mss(caller_mss, family),
            &HandshakeRewrite::mss(listener_mss, family),
            listener_options,
        )
    }

    /// Drive one handshake in which each direction's packets are rewritten
    /// independently, so a test can vary what each side advertises.
    fn handshake_with_rewrites(
        caller_rewrite: &HandshakeRewrite,
        listener_rewrite: &HandshakeRewrite,
        listener_options: ConnectionOptions,
    ) -> MssHandshake {
        handshake_with_options(
            caller_rewrite,
            listener_rewrite,
            ConnectionOptions {
                socket_id: 1,
                ..ConnectionOptions::default()
            },
            listener_options,
        )
    }

    fn handshake_with_options(
        caller_rewrite: &HandshakeRewrite,
        listener_rewrite: &HandshakeRewrite,
        caller_options: ConnectionOptions,
        listener_options: ConnectionOptions,
    ) -> MssHandshake {
        let mut caller = SrtConnection::new_caller(caller_options);
        let mut listener = SrtConnection::new_listener(listener_options);
        caller.set_peer_address(path_address(caller_rewrite.family));
        listener.set_peer_address(path_address(listener_rewrite.family));
        // Pristine emissions are checked before the rewrite; the receiving
        // side records the rewritten packets as its peer input.
        crate::test_support::wire_checker::check_pair(&mut caller, &mut listener);
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        let requests = drain_rewritten_handshakes(&mut caller, caller_rewrite);
        assert_eq!(requests.len(), 1, "one INDUCTION request");
        listener
            .feed_recv_buf(&requests[0], Timestamp::from_micros(1_000))
            .expect("listener accepts INDUCTION");
        let responses = drain_rewritten_handshakes(&mut listener, listener_rewrite);
        assert_eq!(responses.len(), 1, "one INDUCTION response");
        caller
            .feed_recv_buf(&responses[0], Timestamp::from_micros(2_000))
            .expect("caller accepts INDUCTION response");

        let conclusions = drain_rewritten_handshakes(&mut caller, caller_rewrite);
        assert_eq!(conclusions.len(), 1, "one CONCLUSION request");
        let listener_result =
            listener.feed_recv_buf(&conclusions[0], Timestamp::from_micros(3_000));

        let caller_result = if listener_result.is_ok() {
            let answers = drain_rewritten_handshakes(&mut listener, listener_rewrite);
            assert_eq!(answers.len(), 1, "one CONCLUSION response");
            caller.feed_recv_buf(&answers[0], Timestamp::from_micros(4_000))
        } else {
            Ok(())
        };

        MssHandshake {
            caller,
            listener,
            listener_result,
            caller_result,
        }
    }

    /// The handshake MTU field is an IP-layer MTU for every reference
    /// implementation, so a peer's advertised value bounds what that peer's
    /// stack can receive. The negotiated payload is `min` of this core's own
    /// datagram budget and the peer's ceiling, and both roles fail closed on
    /// a value outside the derived bounds before committing any state.
    #[test]
    fn peer_mss_bounds_are_derived_from_wire_semantics_and_enforced() {
        let v4 = IpFamily::V4;
        let v6 = IpFamily::V6;

        // Positive and boundary cases: (advertised MSS, path family, negotiated
        // DATA payload). 1500 is the reference default (1456 = 1500 - 28 - 16,
        // libsrt's own `mss - (UDP_HDR_SIZE + HDR_SIZE)`); 52 and 72 are the
        // smallest values that still leave one 8-byte NAK record.
        for (mss, family, expected_payload) in [
            (1500u32, v4, 1456usize),
            (1200, v4, 1156),
            (52, v4, 8),
            (72, v6, 8),
        ] {
            let attempt = mss_handshake(mss, mss, family, listener_options());
            attempt
                .listener_result
                .unwrap_or_else(|error| panic!("listener accepted MSS {mss}: {error}"));
            attempt
                .caller_result
                .unwrap_or_else(|error| panic!("caller accepted MSS {mss}: {error}"));
            for (who, conn) in [("caller", &attempt.caller), ("listener", &attempt.listener)] {
                assert_eq!(conn.state(), ConnectionState::Connected, "{who} MSS {mss}");
                assert_eq!(
                    conn.effective_max_payload_size(),
                    expected_payload,
                    "{who} negotiated payload for MSS {mss}"
                );
            }
        }

        // Negative cases: one byte below the family's derived minimum, the
        // reference's own (weaker) 4-byte floor, and anything above the
        // largest MSS this implementation negotiates. The jumbo case is a
        // deliberate local policy rather than a reference rule: pinned
        // libsrt's *listener* would clamp `min(local, peer)` and accept a
        // jumbo peer, but this stack implements no jumbo/path-MTU
        // negotiation, so it refuses the session instead of clamping it.
        for (mss, family) in [
            (51u32, v4),
            (48, v4),
            (0, v4),
            (71, v6),
            (68, v6),
            (1501, v4),
            (9000, v4),
            (u32::MAX, v4),
        ] {
            assert_unusable_peer_mss_is_refused(mss, family);
        }
    }

    /// The MSS floor includes the cipher's authentication tag: under GCM a
    /// negotiated payload must still carry the 16-byte tag plus one byte of
    /// DATA, so the smallest usable MSS is 28 + 16 + 17 = 61 on IPv4 and 81
    /// on IPv6, against 52 and 72 under CTR (one 8-byte NAK record). At the
    /// exact minimum both roles connect and can send one byte of DATA; one
    /// below it, the listener refuses before committing anything.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "eight real KM handshakes, each deriving its KEK via 2048 PBKDF2-HMAC-SHA1  \
                  iterations per side (per the SRT spec): about 75 minutes under Miri. The   \
                  MSS arithmetic is unrelated to PBKDF2, and the other KM handshake tests    \
                  cover the same code under Miri, so the miri-extended job skips it too."
    )]
    fn the_mss_floor_leaves_room_for_the_gcm_tag_on_both_families() {
        let options = |socket_id: u32, cipher_mode: CipherMode| ConnectionOptions {
            socket_id,
            syn_cookie: (socket_id == 2).then_some(7),
            passphrase: Some("shared-secret".to_owned()),
            crypto_salt: Some(test_km_salt()),
            crypto_sek: Some(vec![0x24u8; 16]),
            cipher_mode,
            ..ConnectionOptions::default()
        };
        for (family, cipher_mode, min_mss, payload_at_min) in [
            (IpFamily::V4, CipherMode::Ctr, 52u32, 8usize),
            (IpFamily::V6, CipherMode::Ctr, 72, 8),
            (IpFamily::V4, CipherMode::Gcm, 61, 1),
            (IpFamily::V6, CipherMode::Gcm, 81, 1),
        ] {
            let at_min = handshake_with_options(
                &HandshakeRewrite::mss(min_mss, family),
                &HandshakeRewrite::mss(min_mss, family),
                options(1, cipher_mode),
                options(2, cipher_mode),
            );
            let case = format!("{family:?} {cipher_mode:?} MSS {min_mss}");
            at_min
                .listener_result
                .unwrap_or_else(|error| panic!("listener accepts {case}: {error}"));
            at_min
                .caller_result
                .unwrap_or_else(|error| panic!("caller accepts {case}: {error}"));
            for (who, conn) in [("caller", &at_min.caller), ("listener", &at_min.listener)] {
                assert_eq!(conn.state(), ConnectionState::Connected, "{who} {case}");
                assert_eq!(
                    conn.effective_max_payload_size(),
                    payload_at_min,
                    "{who} {case}: usable DATA payload at the minimum"
                );
            }

            let below = handshake_with_options(
                &HandshakeRewrite::mss(min_mss - 1, family),
                &HandshakeRewrite::mss(min_mss - 1, family),
                options(1, cipher_mode),
                options(2, cipher_mode),
            );
            let error = below
                .listener_result
                .expect_err("one below the minimum is refused");
            assert_eq!(
                error.kind,
                crate::ErrorKind::HandshakeRejected,
                "{case} - 1"
            );
            assert_eq!(below.listener.state(), ConnectionState::Disconnected);
        }
    }

    /// A peer MSS outside the derived bounds is refused by the listener with
    /// the reference's own rejection code, and nothing about the attempt is
    /// committed.
    fn assert_unusable_peer_mss_is_refused(mss: u32, family: IpFamily) {
        let mut attempt = mss_handshake(mss, mss, family, listener_options());
        let error = attempt
            .listener_result
            .expect_err("listener rejects an unusable peer MSS");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected, "MSS {mss}");
        assert!(
            error.reason.contains("MSS"),
            "the rejection must name the field: {}",
            error.reason
        );
        assert!(
            error.reason.contains("minimum") || error.reason.contains("maximum"),
            "the rejection must name the violated bound: {}",
            error.reason
        );
        assert_eq!(attempt.listener.state(), ConnectionState::Disconnected);
        // Nothing about the attempt was committed: no crypto, no peer
        // stream, no negotiated payload, no session sequence.
        assert!(attempt.listener.crypto.is_none());
        assert!(attempt.listener.peer_stream_id.is_none());
        assert_eq!(
            attempt.listener.max_payload_size,
            DEFAULT_MTU as usize - SRT_HEADER_SIZE
        );
        assert_eq!(attempt.listener.initial_seq, 0);

        // The listener answers with the reference's own rejection code rather
        // than staying silent.
        let rejections: Vec<_> = drain_outputs(&mut attempt.listener)
            .into_iter()
            .filter_map(|output| match output {
                ConnectionOutput::SendPacket(bytes) => Some(bytes),
                _ => None,
            })
            .filter_map(|bytes| match SrtPacket::decode(&bytes) {
                Ok(SrtPacket::Control(control)) => Some(control),
                _ => None,
            })
            .filter(|control| control.control_type == ControlType::Handshake)
            .collect();
        assert_eq!(rejections.len(), 1, "one rejection response for MSS {mss}");
        let rejection = HandshakePacket::decode(&rejections[0]).expect("rejection decodes");
        assert_eq!(rejection.handshake_type, HandshakeType::Rejected);
        assert_eq!(rejection.reject_reason, Some(SRT_REJ_ROGUE));
    }

    /// A caller rejects an unusable listener MSS terminally, and a listener
    /// that rejected one attempt still serves a fresh peer.
    #[test]
    fn an_unusable_listener_mss_fails_the_caller_and_leaves_the_listener_serving() {
        let v4 = IpFamily::V4;
        let attempt = mss_handshake(1500, 40, v4, listener_options());
        attempt
            .listener_result
            .expect("the listener accepts the caller");
        let error = attempt
            .caller_result
            .expect_err("caller rejects the listener's MSS");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert!(
            error.reason.contains("peer MSS 40"),
            "the rejection names the value: {}",
            error.reason
        );
        assert_eq!(attempt.caller.state(), ConnectionState::Disconnected);

        // A fresh listener (the rejected one is terminal by design, like
        // every other rejected handshake) serves the same peer at a legal
        // MSS.
        let accepted = mss_handshake(1500, 1500, v4, listener_options());
        accepted.listener_result.expect("fresh listener accepts");
        accepted.caller_result.expect("caller accepts");
        assert_eq!(accepted.listener.state(), ConnectionState::Connected);
        assert_eq!(accepted.caller.state(), ConnectionState::Connected);
    }

    /// The negotiated minimum payload is not merely accepted: a connection
    /// running at it can still fragment, deliver, and report loss (the NAK
    /// budget is the reason that floor exists, and `NakChunkEncoder` requires
    /// a whole 8-byte record).
    #[test]
    fn a_connection_at_the_negotiated_minimum_still_reports_loss() {
        let v4 = IpFamily::V4;
        let attempt = mss_handshake(52, 52, v4, listener_options());
        attempt.listener_result.expect("listener accepts");
        attempt.caller_result.expect("caller accepts");
        let MssHandshake {
            mut caller,
            mut listener,
            ..
        } = attempt;
        assert_eq!(caller.effective_max_payload_size(), 8);

        let payload = [0xABu8; 40];
        caller
            .send_message(&payload, Timestamp::from_micros(5_000))
            .expect("the message is admitted as fragments");
        let fragments: Vec<Vec<u8>> = drain_outputs(&mut caller)
            .into_iter()
            .filter_map(|output| match output {
                ConnectionOutput::SendPacket(bytes) => Some(bytes),
                _ => None,
            })
            .filter(|bytes| matches!(SrtPacket::decode(bytes), Ok(SrtPacket::Data(_))))
            .collect();
        assert!(
            fragments.len() > 1,
            "an 8-byte payload budget must fragment a 40-byte message, got {}",
            fragments.len()
        );

        // Deliver everything but the second fragment: the gap is only
        // reportable once a later sequence arrives, and the report is a NAK
        // whose 8-byte loss record is exactly the negotiated budget.
        for (index, fragment) in fragments.iter().enumerate() {
            if index == 1 {
                continue;
            }
            listener
                .feed_recv_buf(fragment, Timestamp::from_micros(5_100 + index as u64))
                .expect("a fragment is accepted");
        }
        let nak = drain_outputs(&mut listener).into_iter().find_map(|output| {
            let ConnectionOutput::SendPacket(bytes) = output else {
                return None;
            };
            match SrtPacket::decode(&bytes) {
                Ok(SrtPacket::Control(control)) if control.control_type == ControlType::Nak => {
                    Some(control)
                }
                _ => None,
            }
        });
        let nak = nak.expect("the receiver must report the gap");
        assert!(
            !nak.control_info.is_empty() && nak.control_info.len() <= MAX_NAK_RECORD_SIZE,
            "a NAK must fit the negotiated budget: {} bytes",
            nak.control_info.len()
        );
        assert_eq!(listener.state(), ConnectionState::Connected);
    }

    fn listener_options() -> ConnectionOptions {
        ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            ..ConnectionOptions::default()
        }
    }

    fn take_one_rewritten_handshake(
        conn: &mut SrtConnection,
        rewrite: &HandshakeRewrite,
    ) -> Vec<u8> {
        let mut packets = drain_rewritten_handshakes(conn, rewrite);
        assert_eq!(packets.len(), 1, "one handshake packet");
        packets.remove(0)
    }

    fn rejection_reason(conn: &mut SrtConnection) -> Option<i32> {
        drain_outputs(conn).into_iter().find_map(|output| {
            let ConnectionOutput::SendPacket(bytes) = output else {
                return None;
            };
            let SrtPacket::Control(control) = SrtPacket::decode(&bytes).ok()? else {
                return None;
            };
            (control.control_type == ControlType::Handshake)
                .then(|| HandshakePacket::decode(&control).ok()?.reject_reason)
                .flatten()
        })
    }

    #[test]
    fn peer_flow_window_accepts_two_and_rejects_unusable_induction() {
        let v4 = IpFamily::V4;
        let plain = HandshakeRewrite::mss(1500, v4);
        let mut minimum = plain;
        minimum.flow_window = Some(MIN_PEER_FLOW_WINDOW);
        let accepted = handshake_with_rewrites(&minimum, &minimum, listener_options());
        accepted
            .listener_result
            .expect("two-packet window is valid");
        accepted
            .caller_result
            .expect("two-packet window interoperates");
        for connection in [&accepted.caller, &accepted.listener] {
            assert_eq!(connection.peer_flow_window, MIN_PEER_FLOW_WINDOW);
        }

        for flow_window in [0, 1, 0x8000_0000, u32::MAX] {
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                socket_id: 1,
                ..ConnectionOptions::default()
            });
            caller.set_peer_address(path_address(v4));
            caller
                .connect(Timestamp::from_micros(0))
                .expect("caller starts");
            let request = take_one_rewritten_handshake(&mut caller, &plain);
            let mut malformed = plain;
            malformed.flow_window = Some(flow_window);
            let invalid_request = rewrite_handshake(&request, &malformed);
            let mut listener = SrtConnection::new_listener(listener_options());
            listener.set_peer_address(path_address(v4));
            let error = listener
                .feed_recv_buf(&invalid_request, Timestamp::from_micros(1_000))
                .expect_err("unusable signed flow window is rejected");
            assert_eq!(
                error.kind,
                crate::ErrorKind::InvalidData,
                "{flow_window:#x}"
            );
            assert_eq!(listener.peer_socket_id, 0, "{flow_window:#x}");
            assert!(listener.handshake_started_at.is_none(), "{flow_window:#x}");
            assert!(drain_outputs(&mut listener).is_empty(), "{flow_window:#x}");
            listener
                .feed_recv_buf(&request, Timestamp::from_micros(1_001))
                .expect("malformed stateless induction did not poison listener");
        }
    }

    #[test]
    fn listener_rejects_unusable_flow_window_in_conclusion() {
        let v4 = IpFamily::V4;
        let plain = HandshakeRewrite::mss(1500, v4);
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..ConnectionOptions::default()
        });
        caller.set_peer_address(path_address(v4));
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        let request = take_one_rewritten_handshake(&mut caller, &plain);
        let mut listener = SrtConnection::new_listener(listener_options());
        listener.set_peer_address(path_address(v4));
        listener
            .feed_recv_buf(&request, Timestamp::from_micros(1_000))
            .expect("listener accepts induction");
        let response = take_one_rewritten_handshake(&mut listener, &plain);
        caller
            .feed_recv_buf(&response, Timestamp::from_micros(2_000))
            .expect("caller accepts induction response");
        let conclusion = take_one_rewritten_handshake(&mut caller, &plain);
        let mut malformed = plain;
        malformed.flow_window = Some(0x8000_0000);
        let invalid_conclusion = rewrite_handshake(&conclusion, &malformed);

        let error = listener
            .feed_recv_buf(&invalid_conclusion, Timestamp::from_micros(3_000))
            .expect_err("listener rejects an out-of-range conclusion");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_eq!(listener.peer_flow_window, DEFAULT_FLOW_WINDOW);
        assert_eq!(rejection_reason(&mut listener), Some(SRT_REJ_ROGUE));
        assert_eq!(listener.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn listener_uses_the_conclusion_flow_window_for_sending() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(listener_options());
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        let induction = take_one_rewritten_handshake(&mut caller, &plain);
        listener
            .feed_recv_buf(&induction, Timestamp::from_micros(1_000))
            .expect("listener accepts induction");
        let response = take_one_rewritten_handshake(&mut listener, &plain);
        caller
            .feed_recv_buf(&response, Timestamp::from_micros(2_000))
            .expect("caller accepts induction response");

        let mut final_advertisement = plain;
        final_advertisement.flow_window = Some(2);
        let conclusion = take_one_rewritten_handshake(&mut caller, &final_advertisement);
        listener
            .feed_recv_buf(&conclusion, Timestamp::from_micros(3_000))
            .expect("listener accepts changed final capacity");
        assert_eq!(listener.peer_flow_window, 2);
        assert_eq!(
            listener
                .sender
                .as_ref()
                .expect("send window")
                .negotiated_window(),
            2
        );
        let _ = drain_outputs(&mut listener);
        for n in 0..2 {
            listener
                .send(b"x", Timestamp::from_micros(4_000 + n))
                .expect("the final advertised capacity allows two packets");
        }
        assert!(
            !listener.can_send(),
            "a third packet exceeds the peer's final window"
        );
    }

    #[test]
    fn caller_rejects_unusable_flow_windows_in_both_responses() {
        let v4 = IpFamily::V4;
        let plain = HandshakeRewrite::mss(1500, v4);

        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..ConnectionOptions::default()
        });
        caller.set_peer_address(path_address(v4));
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        let request = take_one_rewritten_handshake(&mut caller, &plain);
        let mut listener = SrtConnection::new_listener(listener_options());
        listener.set_peer_address(path_address(v4));
        listener
            .feed_recv_buf(&request, Timestamp::from_micros(1_000))
            .expect("listener accepts induction");
        let mut malformed = plain;
        malformed.flow_window = Some(1);
        let invalid_response = take_one_rewritten_handshake(&mut listener, &malformed);
        let error = caller
            .feed_recv_buf(&invalid_response, Timestamp::from_micros(2_000))
            .expect_err("caller rejects unusable induction response");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_eq!(caller.peer_flow_window, 0);
        assert_eq!(caller.state(), ConnectionState::Disconnected);

        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..ConnectionOptions::default()
        });
        caller.set_peer_address(path_address(v4));
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        let request = take_one_rewritten_handshake(&mut caller, &plain);
        let mut listener = SrtConnection::new_listener(listener_options());
        listener.set_peer_address(path_address(v4));
        listener
            .feed_recv_buf(&request, Timestamp::from_micros(1_000))
            .expect("listener accepts induction");
        let response = take_one_rewritten_handshake(&mut listener, &plain);
        caller
            .feed_recv_buf(&response, Timestamp::from_micros(2_000))
            .expect("caller accepts induction response");
        let conclusion = take_one_rewritten_handshake(&mut caller, &plain);
        listener
            .feed_recv_buf(&conclusion, Timestamp::from_micros(3_000))
            .expect("listener accepts conclusion");
        let mut malformed = plain;
        malformed.flow_window = Some(1);
        let invalid_response = take_one_rewritten_handshake(&mut listener, &malformed);

        let error = caller
            .feed_recv_buf(&invalid_response, Timestamp::from_micros(4_000))
            .expect_err("caller rejects unusable conclusion response");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_eq!(caller.peer_flow_window, 0);
        assert_eq!(caller.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn hsv5_handshake_enforces_the_srt_1_3_0_version_floor() {
        let v4 = IpFamily::V4;
        let plain = HandshakeRewrite::mss(1500, v4);

        let mut hsv4 = plain;
        hsv4.handshake_version = Some(crate::srt_handshake::HS_VERSION_4);
        let mut attempt = handshake_with_rewrites(&hsv4, &plain, listener_options());
        let error = attempt
            .listener_result
            .expect_err("HSv4 cannot complete this HSv5-only handshake");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_eq!(
            rejection_reason(&mut attempt.listener),
            Some(SRT_REJ_VERSION)
        );

        let mut before_130 = plain;
        before_130.srt_version = Some(0x0001_02ff);
        let mut attempt = handshake_with_rewrites(&before_130, &plain, listener_options());
        let error = attempt
            .listener_result
            .expect_err("HSv5 cannot claim an SRT version below 1.3.0");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_eq!(rejection_reason(&mut attempt.listener), Some(SRT_REJ_ROGUE));

        let mut at_130 = plain;
        at_130.srt_version = Some(0x0001_0300);
        let accepted = handshake_with_rewrites(&at_130, &plain, listener_options());
        accepted.listener_result.expect("SRT 1.3.0 is supported");
        accepted
            .caller_result
            .expect("SRT 1.3.0 completes both ways");

        let mut old_listener = plain;
        old_listener.srt_version = Some(0x0001_02ff);
        let attempt = handshake_with_rewrites(&plain, &old_listener, listener_options());
        attempt
            .listener_result
            .expect("listener accepts the caller's supported version");
        let error = attempt
            .caller_result
            .expect_err("caller rejects a peer below SRT 1.3.0");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_eq!(attempt.caller.state(), ConnectionState::Disconnected);
    }

    /// Negotiated (receive, sender) TSBPD delays of a connected side, read
    /// from the buffers that actually use them.
    fn negotiated_delays_micros(conn: &SrtConnection) -> (u64, u64) {
        let receive = conn.receiver_stats().expect("receiver").tsbpd_delay_micros;
        let send = conn.sender_stats().expect("sender").tsbpd_delay_micros;
        (receive, send)
    }

    /// An asymmetric HSREQ (RCV=20 ms, SND=500 ms) to a 120 ms listener: the
    /// peer's SND half proposes the listener's receive delay (500 wins), its
    /// RCV half the caller's (120 wins), and the HSRSP carries the two
    /// results separately (libsrt `processSrtMsg_HSREQ`,
    /// `fillSrtHandshake_HSRSP`), at every supported HSv5 SRT version.
    #[test]
    fn listener_negotiates_each_latency_direction_from_its_own_hsreq_half() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        for version in [0x0001_0300, 0x0001_0403, 0x0001_0503, 0x0001_0504] {
            let mut asymmetric = plain;
            asymmetric.srt_version = Some(version);
            asymmetric.latency = Some((20, 500));
            let attempt = handshake_with_rewrites(
                &asymmetric,
                &plain,
                ConnectionOptions {
                    tsbpd_delay: 120,
                    ..listener_options()
                },
            );
            attempt.listener_result.expect("listener accepts");
            attempt.caller_result.expect("caller accepts");
            assert_eq!(
                negotiated_delays_micros(&attempt.listener),
                (500_000, 120_000),
                "listener at {version:#x}"
            );
            // The caller adopts the HSRSP halves: SND=120 for its receive
            // direction, RCV=500 for the listener's.
            assert_eq!(
                negotiated_delays_micros(&attempt.caller),
                (120_000, 500_000),
                "caller at {version:#x}"
            );
        }
    }

    /// The inverse, caller-side case: an HSRSP whose RCV=500/SND=120 halves
    /// describe the listener's receive delay and the caller's. The caller
    /// must not raise its own 120 ms receive delay to the listener's 500.
    #[test]
    fn caller_adopts_each_latency_direction_from_its_own_hsrsp_half() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let mut response = plain;
        response.latency = Some((500, 120));
        let attempt = handshake_with_rewrites(&plain, &response, listener_options());
        attempt.listener_result.expect("listener accepts");
        attempt.caller_result.expect("caller accepts");
        assert_eq!(
            negotiated_delays_micros(&attempt.caller),
            (120_000, 500_000)
        );
    }

    /// A peer that does not declare TSBPDRCV gets no TSBPDSND (nor an SND
    /// latency) in the HSRSP: libsrt only answers it when the peer receives
    /// with TSBPD.
    #[test]
    fn hsrsp_answers_tsbpdsnd_only_to_a_peer_declaring_tsbpdrcv() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let mut no_tsbpd_rcv = plain;
        no_tsbpd_rcv.hs_flags_clear = srt_flags::TSBPDRCV;
        let attempt = handshake_with_rewrites(&no_tsbpd_rcv, &plain, listener_options());
        attempt.listener_result.expect("listener accepts");
        attempt.caller_result.expect("caller accepts");
        let response_flags = attempt.caller.peer_srt_flags.expect("HSRSP flags");
        assert_eq!(response_flags & srt_flags::TSBPDSND, 0);
        assert_ne!(response_flags & srt_flags::TSBPDRCV, 0);
        // The withheld SND half is zero: forcing TSBPDSND back on in transit
        // makes the caller adopt exactly what the listener wrote there.
        let mut forced_snd = plain;
        forced_snd.hs_flags_set = srt_flags::TSBPDSND;
        let attempt = handshake_with_rewrites(&no_tsbpd_rcv, &forced_snd, listener_options());
        attempt.caller_result.expect("caller accepts");
        assert_eq!(negotiated_delays_micros(&attempt.caller).0, 0);

        let attempt = handshake_with_rewrites(&plain, &plain, listener_options());
        let response_flags = attempt.caller.peer_srt_flags.expect("HSRSP flags");
        assert_ne!(response_flags & srt_flags::TSBPDSND, 0);
    }

    /// A latency half whose TSBPD flag is clear proposes nothing: a 500 ms
    /// half without TSBPDSND/TSBPDRCV leaves the listener's 120 ms in place.
    #[test]
    fn latency_halves_without_their_tsbpd_flag_are_ignored() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let mut flagless = plain;
        flagless.hs_flags_clear = srt_flags::TSBPDSND | srt_flags::TSBPDRCV;
        flagless.latency = Some((500, 500));
        let attempt = handshake_with_rewrites(&flagless, &plain, listener_options());
        attempt.listener_result.expect("listener accepts");
        assert_eq!(
            negotiated_delays_micros(&attempt.listener),
            (120_000, 120_000)
        );
    }

    /// Options for one side of a message-API matrix case: live (message
    /// API) or file (stream API, STREAM set).
    fn api_options(file: bool, socket_id: u32) -> ConnectionOptions {
        ConnectionOptions {
            socket_id,
            syn_cookie: Some(7),
            congestion_control: if file { "file" } else { "live" }.to_owned(),
            ..ConnectionOptions::default()
        }
    }

    /// A rewrite that sets or clears the HS extension's STREAM flag and
    /// advertises `version`.
    fn stream_rewrite(stream: bool, version: u32) -> HandshakeRewrite {
        let mut rewrite = HandshakeRewrite::mss(1500, IpFamily::V4);
        rewrite.srt_version = Some(version);
        if stream {
            rewrite.hs_flags_set = srt_flags::STREAM;
        } else {
            rewrite.hs_flags_clear = srt_flags::STREAM;
        }
        rewrite
    }

    /// Every local live/file x peer STREAM clear/set combination at SRT
    /// 1.3.0 and 1.5.4: a listener refuses the other transmission API with
    /// `SRT_REJ_MESSAGEAPI` (libsrt `processSrtMsg_HSREQ`) before Connected.
    #[test]
    fn listener_rejects_a_peer_declaring_the_other_transmission_api() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        for version in [0x0001_0300, 0x0001_0504] {
            for (local_file, peer_stream) in
                [(false, false), (false, true), (true, false), (true, true)]
            {
                let case = format!("{version:#x} file={local_file} STREAM={peer_stream}");
                let mut attempt = handshake_with_options(
                    &stream_rewrite(peer_stream, version),
                    &plain,
                    api_options(local_file, 1),
                    api_options(local_file, 2),
                );
                if local_file == peer_stream {
                    attempt.listener_result.expect(&case);
                    assert_eq!(
                        attempt.listener.state(),
                        ConnectionState::Connected,
                        "{case}"
                    );
                    continue;
                }
                let error = attempt.listener_result.expect_err(&case);
                assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected, "{case}");
                assert_ne!(
                    attempt.listener.state(),
                    ConnectionState::Connected,
                    "{case}"
                );
                assert_eq!(
                    rejection_reason(&mut attempt.listener),
                    Some(SRT_REJ_MESSAGEAPI),
                    "{case}"
                );
            }
        }
    }

    /// The same matrix from the caller's side: an HSRSP declaring the other
    /// transmission API fails the caller before Connected.
    #[test]
    fn caller_rejects_a_peer_declaring_the_other_transmission_api() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        for version in [0x0001_0300, 0x0001_0504] {
            for (local_file, peer_stream) in
                [(false, false), (false, true), (true, false), (true, true)]
            {
                let case = format!("{version:#x} file={local_file} STREAM={peer_stream}");
                let attempt = handshake_with_options(
                    &plain,
                    &stream_rewrite(peer_stream, version),
                    api_options(local_file, 1),
                    api_options(local_file, 2),
                );
                attempt.listener_result.expect(&case);
                if local_file == peer_stream {
                    attempt.caller_result.expect(&case);
                    assert_eq!(attempt.caller.state(), ConnectionState::Connected, "{case}");
                } else {
                    let error = attempt.caller_result.expect_err(&case);
                    assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected, "{case}");
                    assert_ne!(attempt.caller.state(), ConnectionState::Connected, "{case}");
                }
            }
        }
    }

    /// A caller that sent GROUP refuses a response without one (libsrt
    /// `SRT_REJ_GROUP`); a direct caller that sent none still connects.
    #[test]
    fn caller_requires_a_group_response_only_when_it_sent_group() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let grouped_caller = ConnectionOptions {
            socket_id: 1,
            group_extension: Some(GroupExtensionData {
                group_id: SRTGROUP_MASK | 0x31,
                group_type: GroupType::Broadcast,
                flags: 0,
                weight: 1,
            }),
            ..ConnectionOptions::default()
        };
        let attempt = handshake_with_options(&plain, &plain, grouped_caller, listener_options());
        attempt.listener_result.expect("listener answers");
        let error = attempt
            .caller_result
            .expect_err("no mirror GROUP in the response");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_ne!(attempt.caller.state(), ConnectionState::Connected);

        let direct = handshake_with_rewrites(&plain, &plain, listener_options());
        direct
            .caller_result
            .expect("a direct caller needs no GROUP");
        assert_eq!(direct.caller.state(), ConnectionState::Connected);
    }

    /// A peer that omits REXMITFLG would read DATA bit 26 as part of a
    /// legacy 27-bit message number, while this side always marks
    /// retransmissions with it. Every SRT 1.3.0+ peer advertises the flag,
    /// so either role refuses one that does not, the listener with
    /// `SRT_REJ_ROGUE`.
    #[test]
    fn a_peer_without_rexmitflg_is_refused_in_both_roles() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let mut no_rexmit = plain;
        no_rexmit.hs_flags_clear = srt_flags::REXMITFLG;

        let mut attempt = handshake_with_rewrites(&no_rexmit, &plain, listener_options());
        let error = attempt
            .listener_result
            .expect_err("listener refuses an HSREQ without REXMITFLG");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_ne!(attempt.listener.state(), ConnectionState::Connected);
        assert_eq!(rejection_reason(&mut attempt.listener), Some(SRT_REJ_ROGUE));

        let attempt = handshake_with_rewrites(&plain, &no_rexmit, listener_options());
        attempt.listener_result.expect("listener accepts");
        let error = attempt
            .caller_result
            .expect_err("caller refuses an HSRSP without REXMITFLG");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_ne!(attempt.caller.state(), ConnectionState::Connected);
    }

    /// Encrypted options for one side of a legacy-GCM boundary case.
    fn cipher_options(socket_id: u32, cipher_mode: CipherMode) -> ConnectionOptions {
        ConnectionOptions {
            socket_id,
            syn_cookie: Some(7),
            passphrase: Some("interop-passphrase".to_owned()),
            cipher_mode,
            ..ConnectionOptions::default()
        }
    }

    /// libsrt uses its legacy GCM layout with a peer at SRT 1.5.3 or older.
    /// A GCM session whose peer advertises 0x010503 is refused in both
    /// roles (listener: `SRT_REJ_CRYPTO`); 0x010504 connects and is
    /// recorded as the peer version; CTR is unaffected.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "constructs a real CryptoContext, deriving its KEK via 2048               \
                  PBKDF2-HMAC-SHA1 iterations (per the SRT spec) under Miri; correctness    \
                  is proven outside Miri, and this property is unrelated to PBKDF2's own    \
                  iteration count. Run in the miri-extended scheduled job."
    )]
    fn gcm_with_a_peer_at_srt_1_5_3_or_older_is_refused_in_both_roles() {
        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let mut legacy = plain;
        legacy.srt_version = Some(0x0001_0503);
        let mut modern = plain;
        modern.srt_version = Some(0x0001_0504);
        let gcm = |id| cipher_options(id, CipherMode::Gcm);

        let mut attempt = handshake_with_options(&legacy, &plain, gcm(1), gcm(2));
        let error = attempt.listener_result.expect_err("legacy GCM caller");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_eq!(
            rejection_reason(&mut attempt.listener),
            Some(SRT_REJ_CRYPTO)
        );
        assert_ne!(attempt.listener.state(), ConnectionState::Connected);

        let attempt = handshake_with_options(&plain, &legacy, gcm(1), gcm(2));
        attempt.listener_result.expect("listener accepts");
        let error = attempt.caller_result.expect_err("legacy GCM listener");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_ne!(attempt.caller.state(), ConnectionState::Connected);

        let attempt = handshake_with_options(&modern, &modern, gcm(1), gcm(2));
        attempt.listener_result.expect("1.5.4 caller");
        attempt.caller_result.expect("1.5.4 listener");
        assert_eq!(attempt.listener.peer_srt_version(), Some(0x0001_0504));
        assert_eq!(attempt.caller.peer_srt_version(), Some(0x0001_0504));

        let ctr = |id| cipher_options(id, CipherMode::Ctr);
        let attempt = handshake_with_options(&legacy, &legacy, ctr(1), ctr(2));
        attempt.listener_result.expect("legacy CTR caller");
        attempt.caller_result.expect("legacy CTR listener");
    }

    /// A local `srt_version` of 1.5.3 or older with GCM would make a libsrt
    /// peer use the legacy layout: a caller refuses it when it starts, a
    /// listener refuses a GCM caller with `SRT_REJ_CRYPTO`.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "constructs a real CryptoContext, deriving its KEK via 2048               \
                  PBKDF2-HMAC-SHA1 iterations (per the SRT spec) under Miri; correctness    \
                  is proven outside Miri, and this property is unrelated to PBKDF2's own    \
                  iteration count. Run in the miri-extended scheduled job."
    )]
    fn a_local_srt_1_5_3_advertisement_cannot_use_gcm() {
        for (version, allowed) in [(0x0001_0503, false), (0x0001_0504, true)] {
            let mut caller = SrtConnection::new_caller(ConnectionOptions {
                srt_version: version,
                ..cipher_options(1, CipherMode::Gcm)
            });
            let started = caller.connect(Timestamp::default());
            assert_eq!(started.is_ok(), allowed, "{version:#x}");
            if let Err(error) = started {
                assert_eq!(error.kind, crate::ErrorKind::CryptoError);
            }
        }
        let mut ctr = SrtConnection::new_caller(ConnectionOptions {
            srt_version: 0x0001_0503,
            ..cipher_options(1, CipherMode::Ctr)
        });
        ctr.connect(Timestamp::default())
            .expect("CTR is unaffected");

        let plain = HandshakeRewrite::mss(1500, IpFamily::V4);
        let mut attempt = handshake_with_options(
            &plain,
            &plain,
            cipher_options(1, CipherMode::Gcm),
            ConnectionOptions {
                srt_version: 0x0001_0503,
                ..cipher_options(2, CipherMode::Gcm)
            },
        );
        attempt
            .listener_result
            .expect_err("a 1.5.3 listener refuses GCM");
        assert_eq!(
            rejection_reason(&mut attempt.listener),
            Some(SRT_REJ_CRYPTO)
        );
    }

    /// A caller configured for AES-128 without a fixed SEK adopts the
    /// listener's advertised AES-256 for its KMREQ; its CONCLUSION
    /// encryption field must advertise that same negotiated length, as
    /// libsrt's `checkUpdateCryptoKeyLen` updates its own advertisement.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "constructs a real CryptoContext, deriving its KEK via 2048               \
                  PBKDF2-HMAC-SHA1 iterations (per the SRT spec) under Miri; correctness    \
                  is proven outside Miri, and this property is unrelated to PBKDF2's own    \
                  iteration count. Run in the miri-extended scheduled job."
    )]
    fn caller_conclusion_advertises_the_key_length_its_kmreq_uses() {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            key_length: KeyLength::Aes128,
            ..cipher_options(1, CipherMode::Ctr)
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            key_length: KeyLength::Aes256,
            ..cipher_options(2, CipherMode::Ctr)
        });
        caller.connect(Timestamp::default()).expect("caller starts");
        for packet in drain_handshakes(&mut caller) {
            listener
                .feed_recv_buf(&packet, Timestamp::from_micros(1_000))
                .expect("INDUCTION");
        }
        for packet in drain_handshakes(&mut listener) {
            caller
                .feed_recv_buf(&packet, Timestamp::from_micros(2_000))
                .expect("INDUCTION response");
        }
        let conclusion = drain_handshakes(&mut caller).pop().expect("CONCLUSION");
        let SrtPacket::Control(control) = SrtPacket::decode(&conclusion).expect("decodes") else {
            panic!("handshake is a control packet");
        };
        let hs = HandshakePacket::decode(&control).expect("handshake decodes");
        let km = hs
            .get_km_request()
            .expect("KMREQ present")
            .expect("KMREQ decodes");
        assert_eq!(km.key_length, KeyLength::Aes256);
        assert_eq!(hs.key_length(), Some(km.key_length));
    }

    fn drain_handshakes(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
        drain_outputs(conn)
            .into_iter()
            .filter_map(|output| match output {
                ConnectionOutput::SendPacket(bytes) => Some(bytes),
                _ => None,
            })
            .collect()
    }

    /// A peer that negotiates packet-filter behaviour gets a refusal, not a
    /// session whose two peers disagree about whether recovery filtering
    /// exists -- while a peer that merely *advertises* the capability flag is
    /// still accepted, and an unknown optional extension stays ignorable
    /// (`test_extension_parsing_unknown_type` pins that decode side).
    #[test]
    fn packet_filter_negotiation_is_refused_but_the_capability_flag_is_not() {
        let v4 = IpFamily::V4;
        let plain = HandshakeRewrite::mss(1500, v4);

        // The FILTER extension is a negotiation: the caller asking for it is
        // refused by the listener with the reference's own reason code.
        let mut asking = plain;
        asking.filter_extension = true;
        let mut attempt = handshake_with_rewrites(&asking, &plain, listener_options());
        let error = attempt
            .listener_result
            .expect_err("a filter negotiation must be refused");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert!(
            error.reason.contains("packet filter"),
            "the rejection names the capability: {}",
            error.reason
        );
        assert_eq!(attempt.listener.state(), ConnectionState::Disconnected);
        assert!(attempt.listener.crypto.is_none());
        assert_eq!(
            attempt.listener.max_payload_size,
            DEFAULT_MTU as usize - SRT_HEADER_SIZE,
            "nothing about the attempt was committed"
        );
        let rejections: Vec<_> = drain_outputs(&mut attempt.listener)
            .into_iter()
            .filter_map(|output| match output {
                ConnectionOutput::SendPacket(bytes) => Some(bytes),
                _ => None,
            })
            .filter_map(|bytes| match SrtPacket::decode(&bytes) {
                Ok(SrtPacket::Control(control)) => Some(control),
                _ => None,
            })
            .filter(|control| control.control_type == ControlType::Handshake)
            .collect();
        assert_eq!(rejections.len(), 1, "one rejection response");
        let rejection = HandshakePacket::decode(&rejections[0]).expect("rejection decodes");
        assert_eq!(rejection.handshake_type, HandshakeType::Rejected);
        assert_eq!(rejection.reject_reason, Some(SRT_REJ_FILTER));

        // The listener answering with one is refused by the caller.
        let attempt = handshake_with_rewrites(&plain, &asking, listener_options());
        attempt
            .listener_result
            .expect("the listener accepts the caller");
        let error = attempt
            .caller_result
            .expect_err("the caller refuses a filter negotiation");
        assert_eq!(error.kind, crate::ErrorKind::HandshakeRejected);
        assert_eq!(attempt.caller.state(), ConnectionState::Disconnected);

        // The capability flag alone is an advertisement, not a negotiation:
        // rejecting it would refuse peers that never asked for filtering.
        let mut advertising = plain;
        advertising.packet_filter_flag = true;
        let attempt = handshake_with_rewrites(&advertising, &advertising, listener_options());
        attempt
            .listener_result
            .expect("listener accepts the advertisement");
        attempt
            .caller_result
            .expect("caller accepts the advertisement");
        assert_eq!(attempt.listener.state(), ConnectionState::Connected);
        assert_eq!(attempt.caller.state(), ConnectionState::Connected);
    }

    /// A lost KMRSP must not lose the rotation: the peer retransmits the same
    /// KMREQ (as libsrt does while awaiting the response), the receiver
    /// answers it again *without* installing anything, and the rotation then
    /// completes. This is the reliability property the hostile-input test
    /// cannot see, because it only ever sends invalid controls.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn a_lost_kmrsp_is_retried_and_the_rotation_completes() {
        let (mut caller, mut listener) = encrypted_pair(CipherMode::Ctr);
        for connection in [&mut caller, &mut listener] {
            while connection.poll_event().is_some() {}
            let _ = drain_outputs(connection);
        }
        let mut now = Timestamp::from_micros(10_000_000);

        // The rotation is announced and installed by the listener.
        caller
            .provide_new_sek(&fixture_key(0x6B), now)
            .expect("start key refresh");
        let first_request = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        listener
            .feed_recv_buf(&first_request, now)
            .expect("the listener installs the announced key");
        let listener_after_install = km_security_snapshot(&listener);
        let announced = key_message_from_datagram(&first_request)
            .keys
            .single()
            .expect("a local rotation announces one key");

        // The response is lost. The retry cadence elapses, and the sender
        // retransmits the *identical* request.
        now = now.add_micros(1_000_001);
        caller
            .handle_timer(TimerId::Ack, now)
            .expect("ACK tick services the pending rotation");
        let retried_request = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        assert_eq!(
            user_defined_control_info(&retried_request),
            user_defined_control_info(&first_request),
            "a retry must carry byte-identical key material"
        );

        // The listener answers the duplicate again, and installs nothing.
        let _ = drain_outputs(&mut listener);
        listener
            .feed_recv_buf(&retried_request, now)
            .expect("a retransmitted KMREQ is answered, not rejected");
        assert_eq!(
            km_security_snapshot(&listener),
            listener_after_install,
            "answering a duplicate must not touch the receiver's key state"
        );
        let response = take_user_defined_datagram(&mut listener, SRT_CMD_KMRSP);

        // The response arrives this time: the transaction closes.
        caller
            .feed_recv_buf(&response, now.add_micros(1))
            .expect("the retried rotation is acknowledged");
        assert!(
            km_security_snapshot(&caller).pending_response.is_none(),
            "a matching KMRSP closes the transaction"
        );
        assert!(
            receives_under(&listener, announced, test_km_salt(), &fixture_key(0x6B)),
            "the receiver holds the announced key"
        );
        assert_encrypted_roundtrip(
            &mut caller,
            &mut listener,
            now.add_micros(2),
            b"after a lost response",
        );
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn exhausting_km_responses_cannot_leave_peers_on_different_keys() {
        let (mut caller, mut listener) = encrypted_pair(CipherMode::Ctr);
        for connection in [&mut caller, &mut listener] {
            while connection.poll_event().is_some() {}
            let _ = drain_outputs(connection);
        }
        let mut now = Timestamp::from_micros(10_000_000);
        caller
            .provide_new_sek(&fixture_key(0x6B), now)
            .expect("caller starts a rotation");
        let first = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        listener
            .feed_recv_buf(&first, now)
            .expect("peer installs new key");
        let _ = take_user_defined_datagram(&mut listener, SRT_CMD_KMRSP);

        for _ in 0..KM_REQUEST_MAX_RETRIES {
            now = now.add_micros(KM_REQUEST_RETRY_INTERVAL_MICROS + 1);
            caller.handle_timer(TimerId::Ack, now).expect("retry tick");
            let retry = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
            assert_eq!(
                user_defined_control_info(&retry),
                user_defined_control_info(&first)
            );
            listener
                .feed_recv_buf(&retry, now)
                .expect("peer answers identical request");
            let _ = take_user_defined_datagram(&mut listener, SRT_CMD_KMRSP);
        }
        now = now.add_micros(KM_REQUEST_RETRY_INTERVAL_MICROS + 1);
        caller
            .handle_timer(TimerId::Ack, now)
            .expect("exhaustion tick");
        assert_ne!(
            caller.state(),
            ConnectionState::Connected,
            "lost responses do not prove the peer lacks the announced key"
        );
        assert!(
            caller.send(b"unsafe DATA", now).is_err(),
            "a connection with uncertain peer key state must stop sending"
        );
    }

    /// A lost KMREQ is retried, and a response eventually permits switchover.
    /// If no response arrives after all retries, the sender cannot know
    /// whether the peer installed the key, so it must close the session.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn a_lost_kmreq_is_retried_and_an_unanswered_rotation_fails_closed() {
        let (mut caller, mut listener) = encrypted_pair(CipherMode::Ctr);
        for connection in [&mut caller, &mut listener] {
            while connection.poll_event().is_some() {}
            let _ = drain_outputs(connection);
        }
        let mut now = Timestamp::from_micros(20_000_000);
        let original_key = caller
            .crypto
            .as_ref()
            .expect("secured caller")
            .current_key();

        // The rotation is announced past the switch threshold, and its first
        // request never reaches the peer.
        caller
            .provide_new_sek(&fixture_key(0x7C), now)
            .expect("start key refresh");
        let dropped = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        caller
            .crypto
            .as_mut()
            .expect("secured caller")
            .set_encrypted_packet_count_for_test(CryptoContext::KM_REFRESH_PERIOD);
        caller.check_km_refresh(now);
        assert_eq!(
            caller
                .crypto
                .as_ref()
                .expect("secured caller")
                .current_key(),
            original_key,
            "the sender must not switch to a key the peer has not acknowledged"
        );

        // The retry reaches the listener, which installs and answers.
        now = now.add_micros(1_000_001);
        caller
            .handle_timer(TimerId::Ack, now)
            .expect("ACK tick retransmits the request");
        let retried = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        assert_eq!(
            user_defined_control_info(&retried),
            user_defined_control_info(&dropped),
            "the retry is the same request"
        );
        listener
            .feed_recv_buf(&retried, now)
            .expect("the listener installs on the retry");
        let response = take_user_defined_datagram(&mut listener, SRT_CMD_KMRSP);
        caller
            .feed_recv_buf(&response, now.add_micros(1))
            .expect("the rotation is acknowledged");

        // Now, and only now, the switch happens, and both sides agree.
        caller.check_km_refresh(now.add_micros(2));
        let switched = caller
            .crypto
            .as_ref()
            .expect("secured caller")
            .current_key();
        assert_ne!(switched, original_key, "the acknowledged rotation switches");
        assert!(
            receives_under(&listener, switched, test_km_salt(), &fixture_key(0x7C)),
            "the receiver holds the sender's new key under the switched selector"
        );
        assert_encrypted_roundtrip(
            &mut caller,
            &mut listener,
            now.add_micros(3),
            b"after a lost request",
        );

        // No response to any attempt: even if every request was dropped,
        // that fact is unknowable locally, so the connection must fail closed.
        while caller.poll_event().is_some() {}
        caller
            .provide_new_sek(&[0x8D; 16], now.add_micros(4))
            .expect("start another refresh");
        let _ = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        let mut tick = now.add_micros(4);
        for _ in 0..=KM_REQUEST_MAX_RETRIES {
            tick = tick.add_micros(KM_REQUEST_RETRY_INTERVAL_MICROS + 1);
            caller.handle_timer(TimerId::Ack, tick).expect("ACK tick");
        }
        assert_eq!(caller.state(), ConnectionState::Disconnected);
        assert!(km_security_snapshot(&caller).pending_response.is_none());
        assert_eq!(
            caller
                .crypto
                .as_ref()
                .expect("secured caller")
                .current_key(),
            switched,
            "an unconfirmed rotation never changes the active send key"
        );
        assert!(
            std::iter::from_fn(|| caller.poll_event()).any(|event| matches!(
                event,
                ConnectionEvent::Disconnected {
                    reason: DisconnectReason::ProtocolError(reason)
                } if reason == "key rotation was not acknowledged"
            ))
        );
        assert!(caller.provide_new_sek(&[0x9E; 16], tick).is_err());
        assert!(drain_outputs(&mut caller).iter().any(|output| {
            let ConnectionOutput::SendPacket(bytes) = output else {
                return false;
            };
            matches!(
                SrtPacket::decode(bytes),
                Ok(SrtPacket::Control(control)) if control.control_type == ControlType::Shutdown
            )
        }));
    }

    /// The passphrase every encrypted test pair shares.
    const KM_FIXTURE_PASSPHRASE: &str = "shared-secret";

    /// A KM body assembled the way libsrt's `hcryptCtx_Tx_AsmKM`
    /// (`haicrypt/hcrypt_ctx_tx.c`) assembles it, independently of
    /// `KmMessage::encode`: the fixed header, the salt, then one AES key
    /// wrap of the selected SEKs -- the even SEK first when both are
    /// announced. The KEK is PBKDF2-HMAC-SHA1 over the salt's last eight
    /// bytes with 2048 iterations (`haicrypt/hcrypt_sa.c`).
    fn libsrt_km_body(kk: u8, salt: [u8; 16], seks: &[&[u8]], cipher_mode: CipherMode) -> Vec<u8> {
        use aes_gcm::KeyInit;
        let key_len = seks[0].len();
        let mut kek = vec![0u8; key_len];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(
            KM_FIXTURE_PASSPHRASE.as_bytes(),
            &salt[8..],
            2048,
            &mut kek,
        );
        let plain = seks.concat();
        let mut wrapped = vec![0u8; plain.len() + 8];
        let wrapped_ok = match key_len {
            16 => aes_kw::KwAes128::new_from_slice(&kek)
                .expect("AES-128 KEK")
                .wrap_key(&plain, &mut wrapped)
                .is_ok(),
            32 => aes_kw::KwAes256::new_from_slice(&kek)
                .expect("AES-256 KEK")
                .wrap_key(&plain, &mut wrapped)
                .is_ok(),
            _ => false,
        };
        assert!(wrapped_ok, "the fixture wraps its SEKs");
        let (cipher, auth) = match cipher_mode {
            CipherMode::Ctr => (2, 0),
            CipherMode::Gcm => (4, 1),
        };
        let key_words = u8::try_from(key_len / 4).expect("AES key length in words");
        let mut body = vec![
            0x12, 0x20, 0x29, kk, 0, 0, 0, 0, cipher, auth, 2, 0, 0, 0, 4, key_words,
        ];
        body.extend_from_slice(&salt);
        body.extend_from_slice(&wrapped);
        body
    }

    /// Whether `connection` decrypts what a sender keyed with `salt`/`sek`
    /// encrypted, when the DATA carries `flag` -- the same decrypt calls
    /// the DATA receive path makes.
    fn receives_under(
        connection: &SrtConnection,
        flag: KeyFlag,
        salt: [u8; 16],
        sek: &[u8],
    ) -> bool {
        let crypto = connection.crypto.as_ref().expect("secured connection");
        let mode = crypto.cipher_mode();
        let key_length = KeyLength::from_len(sek.len()).expect("AES key");
        let mut oracle =
            CryptoContext::new_sender(KM_FIXTURE_PASSPHRASE, key_length, salt, sek, mode)
                .expect("oracle sender");
        let plaintext = b"key-material oracle payload".to_vec();
        let header = fixture_key(0x42);
        match mode {
            CipherMode::Ctr => {
                let mut buffer = plaintext.clone();
                oracle.encrypt(7, &mut buffer).expect("oracle encrypts");
                crypto.decrypt(7, flag, &mut buffer).is_ok() && buffer == plaintext
            }
            CipherMode::Gcm => {
                let (_, sealed) = oracle
                    .encrypt_gcm(7, &header, plaintext.clone())
                    .expect("oracle seals");
                crypto
                    .decrypt_gcm(7, flag, &header, sealed)
                    .is_ok_and(|opened| opened == plaintext)
            }
        }
    }

    /// Feed a runtime KMREQ and require the exact-body KMRSP echo.
    fn feed_kmreq_expect_echo(target: &mut SrtConnection, body: &[u8], now: Timestamp) {
        let _ = drain_outputs(target);
        let datagram = control_datagram(
            target.socket_id(),
            ControlType::UserDefined,
            SRT_CMD_KMREQ,
            0,
            body.to_vec(),
        );
        target
            .feed_recv_buf(&datagram, now)
            .expect("a valid KMREQ is accepted");
        let response = take_user_defined_datagram(target, SRT_CMD_KMRSP);
        assert_eq!(
            user_defined_control_info(&response),
            body,
            "the KMRSP echoes the exact KMREQ body"
        );
    }

    /// Both peers drained of the handshake's events and output.
    fn quiet_encrypted_pair(
        cipher_mode: CipherMode,
        key_length: KeyLength,
    ) -> (SrtConnection, SrtConnection) {
        let (mut caller, mut listener) = encrypted_pair_with(cipher_mode, key_length);
        for connection in [&mut caller, &mut listener] {
            while connection.poll_event().is_some() {}
            let _ = drain_outputs(connection);
        }
        (caller, listener)
    }

    /// KM-3: libsrt's ordinary refresh announces the current and the next
    /// SEK in one KM message (KK = 3, even SEK first) under the unchanged
    /// salt, then the switched-to key alone once the old one is retired.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn libsrt_both_key_announcement_installs_both_receive_slots() {
        for (cipher_mode, key_length) in [
            (CipherMode::Ctr, KeyLength::Aes128),
            (CipherMode::Ctr, KeyLength::Aes256),
            (CipherMode::Gcm, KeyLength::Aes128),
            (CipherMode::Gcm, KeyLength::Aes256),
        ] {
            let (_caller, mut listener) = quiet_encrypted_pair(cipher_mode, key_length);
            let len = key_length.len();
            let (current, next, after) = (
                listener
                    .crypto
                    .as_ref()
                    .unwrap()
                    .key_state_for_test()
                    .rx_even
                    .unwrap()
                    .0,
                fixture_key_vec(0x6C, len),
                fixture_key_vec(0x7E, len),
            );
            let salt = test_km_salt();
            let now = Timestamp::from_micros(10_000_000);

            let even_to_odd = libsrt_km_body(0b11, salt, &[&current, &next], cipher_mode);
            assert_eq!(even_to_odd.len(), 16 + 16 + 2 * len + 8);
            feed_kmreq_expect_echo(&mut listener, &even_to_odd, now);
            assert!(receives_under(&listener, KeyFlag::Even, salt, &current));
            assert!(receives_under(&listener, KeyFlag::Odd, salt, &next));

            // After the switch: the odd key alone, then odd -> even.
            let odd_only = libsrt_km_body(0b10, salt, &[&next], cipher_mode);
            feed_kmreq_expect_echo(&mut listener, &odd_only, now.add_micros(1));
            let odd_to_even = libsrt_km_body(0b11, salt, &[&after, &next], cipher_mode);
            feed_kmreq_expect_echo(&mut listener, &odd_to_even, now.add_micros(2));
            assert!(receives_under(&listener, KeyFlag::Even, salt, &after));
            assert!(receives_under(&listener, KeyFlag::Odd, salt, &next));
        }
    }

    /// KM-2: a peer's key announcement configures this side's receive
    /// direction only. Its own transmit selector and in-flight rotation
    /// stay as they were, even when both sides rotate at once.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn peer_key_announcement_leaves_the_local_transmit_key_unchanged() {
        let (mut caller, mut listener) = quiet_encrypted_pair(CipherMode::Ctr, KeyLength::Aes128);
        let now = Timestamp::from_micros(10_000_000);
        listener
            .provide_new_sek(&fixture_key(0x71), now)
            .expect("the listener starts its own rotation");
        let listener_request = take_user_defined_datagram(&mut listener, SRT_CMD_KMREQ);
        caller
            .provide_new_sek(&fixture_key(0x6B), now)
            .expect("the caller starts its rotation");
        let caller_request = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);

        listener
            .feed_recv_buf(&caller_request, now.add_micros(1))
            .expect("the listener installs the caller's announced key");
        assert!(receives_under(
            &listener,
            KeyFlag::Odd,
            test_km_salt(),
            &fixture_key(0x6B)
        ));
        let listener_crypto = listener.crypto.as_ref().expect("secured listener");
        assert_eq!(listener_crypto.current_key(), KeyFlag::Even);
        assert_eq!(
            listener_crypto.km_refresh_state(),
            crate::crypto_impl::KmRefreshState::PreAnnounce
        );
        assert_eq!(
            listener
                .km_control
                .as_ref()
                .and_then(|state| state.pending.as_ref())
                .map(|pending| pending.request.encode()),
            Some(user_defined_control_info(&listener_request)),
            "the listener's own rotation is still the one awaiting a response"
        );

        let reverse = capture_data_datagram(&mut listener, b"reverse", now.add_micros(2));
        let Ok(SrtPacket::Data(packet)) = SrtPacket::decode(&reverse) else {
            panic!("encrypted send must produce DATA");
        };
        assert_eq!(packet.encryption_flag, KeyFlag::Even.to_kk_field());
        caller
            .feed_recv_buf(&reverse, now.add_micros(3))
            .expect("the caller still decrypts the listener's unchanged key");

        feed_kmreq_expect_echo(
            &mut caller,
            &user_defined_control_info(&listener_request),
            now.add_micros(4),
        );
        assert!(receives_under(
            &caller,
            KeyFlag::Odd,
            test_km_salt(),
            &fixture_key(0x71)
        ));
        assert_eq!(
            caller
                .crypto
                .as_ref()
                .expect("secured caller")
                .current_key(),
            KeyFlag::Even
        );
    }

    /// KM-1: Robotweax replaces the handshake's even key right after
    /// establishment with independently generated material -- a new salt and
    /// SEK under the same selector (`prepare_bidirectional_sender`). libsrt
    /// installs a changed same-selector KM, salt included
    /// (`hcrypt_ctx_rx.c`); so does an SEK-only change.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn same_selector_replacement_after_connect_is_installed() {
        for cipher_mode in [CipherMode::Ctr, CipherMode::Gcm] {
            for (salt, sek) in [
                (fresh_salt(), fixture_key(0x7D)),
                (test_km_salt(), fixture_key(0x7E)),
            ] {
                for caller_is_target in [true, false] {
                    let (mut caller, mut listener) =
                        quiet_encrypted_pair(cipher_mode, KeyLength::Aes128);
                    let (target, peer) = if caller_is_target {
                        (&mut caller, &mut listener)
                    } else {
                        (&mut listener, &mut caller)
                    };
                    assert_same_selector_replacement(target, peer, cipher_mode, salt, &sek);
                }
            }
        }
    }

    fn assert_same_selector_replacement(
        target: &mut SrtConnection,
        peer: &mut SrtConnection,
        cipher_mode: CipherMode,
        salt: [u8; 16],
        sek: &[u8],
    ) {
        let now = Timestamp::from_micros(10_000_000);
        let body = libsrt_km_body(0b01, salt, &[sek], cipher_mode);
        feed_kmreq_expect_echo(target, &body, now);
        assert!(receives_under(target, KeyFlag::Even, salt, sek));
        // The target's independently confirmed TX material is unchanged.
        let reverse = capture_data_datagram(target, b"reverse", now.add_micros(1));
        peer.feed_recv_buf(&reverse, now.add_micros(2))
            .expect("the peer still decrypts the target's independent TX key");
    }

    /// A salt the handshake did not use.
    fn fresh_salt() -> [u8; 16] {
        fixture_key(0xC3)
    }

    /// A CTR KM body for `keys` under [`fresh_salt`].
    fn fresh_salt_km(kk: u8, seks: &[&[u8]]) -> Vec<u8> {
        libsrt_km_body(kk, fresh_salt(), seks, CipherMode::Ctr)
    }

    /// A listener whose even receive key a Robotweax-style peer replaced
    /// twice under [`fresh_salt`]: `fixture_key(0x91)`, then
    /// `fixture_key(0x92)`. The first is now a retired receive key that was
    /// never a transmit key.
    fn listener_with_replaced_even_key() -> (SrtConnection, Timestamp) {
        let (_caller, mut listener) = quiet_encrypted_pair(CipherMode::Ctr, KeyLength::Aes128);
        let now = Timestamp::from_micros(10_000_000);
        feed_kmreq_expect_echo(
            &mut listener,
            &fresh_salt_km(0b01, &[&fixture_key(0x91)]),
            now,
        );
        feed_kmreq_expect_echo(
            &mut listener,
            &fresh_salt_km(0b01, &[&fixture_key(0x92)]),
            now.add_micros(1),
        );
        (listener, now.add_micros(2))
    }

    /// Hardening: this side's own transmit key, reflected back as a KMREQ,
    /// is never installed as a receive key -- verbatim or re-wrapped under
    /// another salt.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn a_reflected_transmit_key_is_not_installed_as_a_receive_key() {
        let (mut caller, _listener) = quiet_encrypted_pair(CipherMode::Ctr, KeyLength::Aes128);
        let now = Timestamp::from_micros(10_000_000);
        caller
            .provide_new_sek(&fixture_key(0x6B), now)
            .expect("the caller starts a rotation");
        let own_request = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        assert_km_control_rejected(
            &mut caller,
            SRT_CMD_KMREQ,
            user_defined_control_info(&own_request),
            now.add_micros(1),
            "own KMREQ reflected",
        );
        assert_km_control_rejected(
            &mut caller,
            SRT_CMD_KMREQ,
            fresh_salt_km(0b10, &[&fixture_key(0x6B)]),
            now.add_micros(2),
            "own key re-wrapped under a fresh salt",
        );
    }

    /// Hardening: the wrap authenticates neither selector nor salt, so a
    /// key already held must keep both.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn a_known_receive_key_cannot_change_selector_or_salt() {
        let (mut listener, now) = listener_with_replaced_even_key();
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            fresh_salt_km(0b10, &[&fixture_key(0x92)]),
            now,
            "current even key announced as odd",
        );
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            libsrt_km_body(0b01, test_km_salt(), &[&fixture_key(0x92)], CipherMode::Ctr),
            now.add_micros(1),
            "current even key under another salt",
        );
    }

    /// Hardening: a recently replaced receive key is not reinstalled,
    /// under either selector.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn a_retired_receive_key_cannot_be_reinstalled() {
        let (mut listener, now) = listener_with_replaced_even_key();
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            fresh_salt_km(0b01, &[&fixture_key(0x91)]),
            now,
            "retired key in its old slot",
        );
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            fresh_salt_km(0b10, &[&fixture_key(0x91)]),
            now.add_micros(1),
            "retired key in the other slot",
        );
    }

    /// Hardening: a both-key announcement cannot install one SEK as both.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn a_both_key_announcement_of_one_key_twice_is_refused() {
        let (mut listener, now) = listener_with_replaced_even_key();
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            fresh_salt_km(0b11, &[&fixture_key(0x93), &fixture_key(0x93)]),
            now,
            "one SEK under both selectors",
        );
    }

    /// An identical repeat of the current KM is answered with the same
    /// KMRSP and reinstalls nothing.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn an_identical_current_kmreq_is_answered_without_reinstalling() {
        let (mut listener, now) = listener_with_replaced_even_key();
        let before = km_security_snapshot(&listener);
        feed_kmreq_expect_echo(
            &mut listener,
            &fresh_salt_km(0b01, &[&fixture_key(0x92)]),
            now,
        );
        assert_eq!(km_security_snapshot(&listener), before);
    }

    /// A KMREQ whose wrap fails under a freshly derived KEK leaves every key
    /// and the cached KEK as they were; the intact request then installs.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn a_failed_unwrap_under_a_fresh_salt_leaves_every_key_untouched() {
        let (_caller, mut listener) = quiet_encrypted_pair(CipherMode::Ctr, KeyLength::Aes128);
        let now = Timestamp::from_micros(10_000_000);
        let intact = fresh_salt_km(0b01, &[&fixture_key(0x91)]);
        let mut corrupted = intact.clone();
        *corrupted.last_mut().expect("wrapped key") ^= 0x01;
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            corrupted,
            now,
            "corrupted wrap under a fresh salt",
        );
        feed_kmreq_expect_echo(&mut listener, &intact, now.add_micros(1));
        assert!(receives_under(
            &listener,
            KeyFlag::Even,
            fresh_salt(),
            &fixture_key(0x91)
        ));
    }

    /// Each fresh salt costs a 2048-iteration PBKDF2 derivation, so a
    /// connection admits `KM_KEK_DERIVATION_BURST` at once and one more per
    /// `KM_KEK_DERIVATION_REFILL_MICROS`. A refused KMREQ is unanswered and
    /// changes nothing; salts with a cached KEK cost nothing; the peer's
    /// retry after the interval installs.
    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) on each side under Miri, which dominates this job's     \
                  time; correctness is proven outside Miri, and this property is unrelated   \
                  to PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
    fn fresh_salt_kek_derivations_are_bounded_per_connection() {
        let (_caller, mut listener) = quiet_encrypted_pair(CipherMode::Ctr, KeyLength::Aes128);
        let now = Timestamp::from_micros(10_000_000);
        let ctr = CipherMode::Ctr;
        let first = libsrt_km_body(0b01, fixture_key(0xA1), &[&fixture_key(0x91)], ctr);
        let second = libsrt_km_body(0b01, fixture_key(0xA2), &[&fixture_key(0x92)], ctr);
        let third = libsrt_km_body(0b01, fixture_key(0xA3), &[&fixture_key(0x93)], ctr);
        feed_kmreq_expect_echo(&mut listener, &first, now);
        feed_kmreq_expect_echo(&mut listener, &second, now.add_micros(1));
        assert_km_control_rejected(
            &mut listener,
            SRT_CMD_KMREQ,
            third.clone(),
            now.add_micros(2),
            "fresh salt beyond the derivation burst",
        );
        feed_kmreq_expect_echo(&mut listener, &second, now.add_micros(3));
        let odd_under_session_salt =
            libsrt_km_body(0b10, test_km_salt(), &[&fixture_key(0x94)], ctr);
        feed_kmreq_expect_echo(&mut listener, &odd_under_session_salt, now.add_micros(4));
        feed_kmreq_expect_echo(
            &mut listener,
            &third,
            now.add_micros(KM_KEK_DERIVATION_REFILL_MICROS + 2),
        );
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real CTR/GCM handshakes"
    )]
    fn initial_bidirectional_crypto_uses_distinct_confirmed_keys() {
        for mode in [CipherMode::Ctr, CipherMode::Gcm] {
            let options = |socket_id| ConnectionOptions {
                socket_id,
                syn_cookie: Some(7),
                passphrase: Some(KM_FIXTURE_PASSPHRASE.to_owned()),
                crypto_salt: Some(test_km_salt()),
                crypto_sek: Some(fixture_key(0x5A).to_vec()),
                cipher_mode: mode,
                tsbpd_delay: 0,
                ..ConnectionOptions::default()
            };
            let mut caller = SrtConnection::new_caller(options(1));
            let mut listener = SrtConnection::new_listener(options(2));
            let now = Timestamp::from_micros(1_000);
            caller.connect(Timestamp::default()).unwrap();
            listener
                .feed_recv_buf(&next_wire(&mut caller), now)
                .unwrap();
            caller
                .feed_recv_buf(&next_wire(&mut listener), now)
                .unwrap();
            listener
                .feed_recv_buf(&next_wire(&mut caller), now)
                .unwrap();
            let (conclusion, request) = capture_initial_listener_key_outputs(&mut listener);
            let request = request.expect("listener announces directional TX material");
            let handshake_key = current_km_message(&caller).encode();
            caller.feed_recv_buf(&conclusion.unwrap(), now).unwrap();
            assert_initial_listener_send_blocked(&mut listener, now);

            assert_km_control_rejected(
                &mut listener,
                SRT_CMD_KMRSP,
                handshake_key.clone(),
                now,
                "the handshake key cannot confirm the independent directional key",
            );
            assert!(
                !caller.can_send(),
                "handshake KMRSP cannot authorize fresh caller TX"
            );
            assert!(
                !std::iter::from_fn(|| caller.poll_event())
                    .any(|event| matches!(event, ConnectionEvent::Connected))
            );
            let caller_request = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
            assert_km_control_rejected(
                &mut caller,
                SRT_CMD_KMRSP,
                handshake_key,
                now,
                "old handshake KMRSP cannot confirm fresh caller TX",
            );
            listener.feed_recv_buf(&caller_request, now).unwrap();
            let caller_confirmation = take_user_defined_datagram(&mut listener, SRT_CMD_KMRSP);
            caller.feed_recv_buf(&caller_confirmation, now).unwrap();
            assert!(
                caller.can_send(),
                "caller confirmed independently of listener"
            );

            // The caller is confirmed first; keep its early DATA bounded
            // behind the listener's independently pending Connected event.
            let payload = b"equal plaintext, equal first sequence";
            let outbound = capture_data_datagram(&mut caller, payload, now);
            listener
                .feed_recv_buf(&outbound, now.add_micros(1))
                .unwrap();
            listener
                .handle_timer(TimerId::DeliveryContinue, now.add_micros(2))
                .unwrap();
            assert!(
                !std::iter::from_fn(|| listener.poll_event()).any(|event| matches!(
                    event,
                    ConnectionEvent::Connected | ConnectionEvent::DataReceived { .. }
                ))
            );
            caller.feed_recv_buf(&request, now.add_micros(3)).unwrap();
            let lost_response = take_user_defined_datagram(&mut caller, SRT_CMD_KMRSP);
            let retry_at = now.add_micros(KM_REQUEST_RETRY_INTERVAL_MICROS + 1);
            listener.handle_timer(TimerId::Ack, retry_at).unwrap();
            let retry = take_user_defined_datagram(&mut listener, SRT_CMD_KMREQ);
            assert_eq!(
                user_defined_control_info(&retry),
                user_defined_control_info(&request)
            );
            assert!(!listener.can_send(), "a lost KMRSP never releases DATA");
            caller.feed_recv_buf(&retry, retry_at).unwrap();
            let response = take_user_defined_datagram(&mut caller, SRT_CMD_KMRSP);
            assert_eq!(
                user_defined_control_info(&response),
                user_defined_control_info(&lost_response)
            );
            listener.feed_recv_buf(&response, retry_at).unwrap();
            let events: Vec<_> = std::iter::from_fn(|| listener.poll_event()).collect();
            let connected = events
                .iter()
                .position(|event| matches!(event, ConnectionEvent::Connected))
                .unwrap();
            let received = events
                .iter()
                .position(|event| matches!(event, ConnectionEvent::DataReceived { .. }))
                .unwrap();
            assert!(connected < received);
            assert_eq!(crypto_event_bytes(events), payload);
            let reverse = capture_data_datagram(&mut listener, payload, retry_at);
            let (SrtPacket::Data(forward), SrtPacket::Data(backward)) = (
                SrtPacket::decode(&outbound).unwrap(),
                SrtPacket::decode(&reverse).unwrap(),
            ) else {
                panic!("DATA in both directions");
            };
            assert_eq!(forward.sequence_number, backward.sequence_number);
            // Exclude GCM's tag: differing AAD can change a tag even when
            // the same nonce produces identical ciphertext.
            assert_ne!(
                &forward.payload[..payload.len()],
                &backward.payload[..payload.len()]
            );
            caller
                .feed_recv_buf(&reverse, retry_at.add_micros(1))
                .unwrap();
            caller
                .handle_timer(TimerId::DeliveryContinue, retry_at.add_micros(2))
                .unwrap();
            assert_eq!(
                crypto_event_bytes(std::iter::from_fn(|| caller.poll_event())),
                payload
            );
        }
    }

    fn capture_initial_listener_key_outputs(
        listener: &mut SrtConnection,
    ) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let mut conclusion = None;
        let mut request = None;
        for output in drain_outputs(listener) {
            if let ConnectionOutput::SendPacket(wire) = output {
                match SrtPacket::decode(&wire).unwrap() {
                    SrtPacket::Control(packet) if packet.control_type == ControlType::Handshake => {
                        conclusion = Some(wire);
                    }
                    SrtPacket::Control(packet) if packet.subtype == SRT_CMD_KMREQ => {
                        request = Some(wire);
                    }
                    _ => panic!("unexpected preconfirmation DATA"),
                }
            }
        }
        (conclusion, request)
    }

    fn assert_initial_listener_send_blocked(listener: &mut SrtConnection, now: Timestamp) {
        assert!(!listener.can_send());
        assert!(!listener.can_send_with_pacing(now));
        let sequence = listener.next_sequence_number();
        assert!(listener.send(b"blocked", now).is_err());
        assert!(listener.send_message(b"blocked", now).is_err());
        assert!(
            listener
                .send_shared(Bytes::from_static(b"blocked"), now)
                .is_err()
        );
        assert_eq!(listener.next_sequence_number(), sequence);
        assert!(drain_outputs(listener).is_empty());
        assert!(
            !std::iter::from_fn(|| listener.poll_event()).any(|event| matches!(
                event,
                ConnectionEvent::Connected | ConnectionEvent::DataReceived { .. }
            ))
        );
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real CTR handshake"
    )]
    fn first_bidirectional_ciphertexts_do_not_reuse_nonce_ctr() {
        assert_first_bidirectional_ciphertexts_do_not_reuse_nonce(CipherMode::Ctr);
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real GCM handshake"
    )]
    fn first_bidirectional_ciphertexts_do_not_reuse_nonce_gcm() {
        assert_first_bidirectional_ciphertexts_do_not_reuse_nonce(CipherMode::Gcm);
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real CTR/GCM handshakes"
    )]
    fn late_initial_kmrsp_cannot_announce_connected_after_terminal_close() {
        for mode in [CipherMode::Ctr, CipherMode::Gcm] {
            for listener_side in [false, true] {
                for peer_shutdown in [false, true] {
                    assert_late_initial_kmrsp_after_close(mode, listener_side, peer_shutdown);
                }
            }
        }
    }

    fn capture_initial_kmrsp(mode: CipherMode, listener_side: bool) -> (SrtConnection, Vec<u8>) {
        let options = |socket_id| ConnectionOptions {
            socket_id,
            syn_cookie: Some(7),
            passphrase: Some(KM_FIXTURE_PASSPHRASE.to_owned()),
            crypto_salt: Some(test_km_salt()),
            crypto_sek: Some(fixture_key(0x5A).to_vec()),
            cipher_mode: mode,
            ..ConnectionOptions::default()
        };
        let mut caller = SrtConnection::new_caller(options(1));
        let mut listener = SrtConnection::new_listener(options(2));
        let now = Timestamp::from_micros(1_000);
        caller.connect(Timestamp::default()).unwrap();
        listener
            .feed_recv_buf(&next_wire(&mut caller), now)
            .unwrap();
        caller
            .feed_recv_buf(&next_wire(&mut listener), now)
            .unwrap();
        listener
            .feed_recv_buf(&next_wire(&mut caller), now)
            .unwrap();
        let mut listener_request = None;
        for output in drain_outputs(&mut listener) {
            if let ConnectionOutput::SendPacket(wire) = output {
                match SrtPacket::decode(&wire).unwrap() {
                    SrtPacket::Control(packet) if packet.control_type == ControlType::Handshake => {
                        caller.feed_recv_buf(&wire, now).unwrap();
                    }
                    SrtPacket::Control(packet) if packet.subtype == SRT_CMD_KMREQ => {
                        listener_request = Some(wire);
                    }
                    _ => panic!("unexpected preconfirmation output"),
                }
            }
        }
        let caller_request = take_user_defined_datagram(&mut caller, SRT_CMD_KMREQ);
        let response = if listener_side {
            caller
                .feed_recv_buf(&listener_request.unwrap(), now)
                .unwrap();
            take_user_defined_datagram(&mut caller, SRT_CMD_KMRSP)
        } else {
            listener.feed_recv_buf(&caller_request, now).unwrap();
            take_user_defined_datagram(&mut listener, SRT_CMD_KMRSP)
        };
        (if listener_side { listener } else { caller }, response)
    }

    fn assert_late_initial_kmrsp_after_close(
        mode: CipherMode,
        listener_side: bool,
        peer_shutdown: bool,
    ) {
        let (mut connection, response) = capture_initial_kmrsp(mode, listener_side);
        let target = &mut connection;
        let now = Timestamp::from_micros(1_000);
        assert!(target.initial_tx_pending());
        assert!(!target.can_send());
        assert!(
            !std::iter::from_fn(|| target.poll_event())
                .any(|event| matches!(event, ConnectionEvent::Connected))
        );
        let terminal_at = now.add_micros(INACTIVITY_TIMEOUT_MICROS + 1);
        let reason = if peer_shutdown {
            let shutdown =
                control_datagram(target.socket_id(), ControlType::Shutdown, 0, 0, Vec::new());
            target.feed_recv_buf(&shutdown, terminal_at).unwrap();
            DisconnectReason::PeerShutdown
        } else {
            target
                .handle_timer(TimerId::Inactivity, terminal_at)
                .unwrap();
            DisconnectReason::InactivityTimeout
        };
        assert_eq!(target.state(), ConnectionState::Disconnected);
        let events: Vec<_> = std::iter::from_fn(|| target.poll_event()).collect();
        assert!(events.contains(&ConnectionEvent::Disconnected { reason }));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, ConnectionEvent::Connected))
        );
        assert_km_control_rejected(
            target,
            SRT_CMD_KMRSP,
            user_defined_control_info(&response),
            terminal_at.add_micros(1),
            "late initial confirmation after terminal close",
        );
        assert!(!target.can_send());
        assert!(target.poll_event().is_none());
    }

    /// Runs against the pre-fix handshake too: the failing inequality
    /// exposes actual nonce reuse, not just the absent new KM transaction.
    fn assert_first_bidirectional_ciphertexts_do_not_reuse_nonce(mode: CipherMode) {
        let (mut caller, mut listener) = quiet_encrypted_pair(mode, KeyLength::Aes128);
        let now = Timestamp::from_micros(10_000_000);
        let plaintext = b"same plaintext in both directions";
        let forward = capture_data_datagram(&mut caller, plaintext, now);
        let reverse = capture_data_datagram(&mut listener, plaintext, now);
        let (SrtPacket::Data(a), SrtPacket::Data(b)) = (
            SrtPacket::decode(&forward).unwrap(),
            SrtPacket::decode(&reverse).unwrap(),
        ) else {
            panic!("DATA in both directions");
        };
        assert_eq!(a.sequence_number, b.sequence_number);
        assert_ne!(
            &a.payload[..plaintext.len()],
            &b.payload[..plaintext.len()],
            "{mode:?} nonce reuse"
        );
        listener.feed_recv_buf(&forward, now.add_micros(1)).unwrap();
        caller.feed_recv_buf(&reverse, now.add_micros(1)).unwrap();
        for connection in [&mut caller, &mut listener] {
            connection
                .handle_timer(TimerId::DeliveryContinue, now.add_micros(200_000))
                .unwrap();
            assert_eq!(
                crypto_event_bytes(std::iter::from_fn(|| connection.poll_event())),
                plaintext
            );
        }
    }

    fn crypto_event_bytes(events: impl IntoIterator<Item = ConnectionEvent>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for event in events {
            if let ConnectionEvent::DataReceived { payload, .. } = event {
                for chunk in payload.chunks() {
                    bytes.extend_from_slice(chunk);
                }
            }
        }
        bytes
    }

    /// Cross normal KM thresholds with real DATA and real receiver ACKs.
    /// Only the counter is accelerated; no key/retention state is injected.
    fn confirm_switch_and_retire(
        sender: &mut SrtConnection,
        receiver: &mut SrtConnection,
        sek: &[u8],
        now: Timestamp,
    ) -> Vec<u8> {
        sender.provide_new_sek(sek, now).unwrap();
        let request = take_user_defined_datagram(sender, SRT_CMD_KMREQ);
        receiver.feed_recv_buf(&request, now).unwrap();
        let response = take_user_defined_datagram(receiver, SRT_CMD_KMRSP);
        sender.feed_recv_buf(&response, now).unwrap();
        sender
            .seed_encrypted_packet_count_for_test(CryptoContext::KM_REFRESH_PERIOD)
            .unwrap();
        let old = capture_data_datagram(sender, b"last old-generation DATA", now);
        receiver.feed_recv_buf(&old, now.add_micros(1)).unwrap();
        receiver
            .handle_timer(TimerId::Ack, now.add_micros(20_000))
            .unwrap();
        for output in drain_outputs(receiver) {
            if let ConnectionOutput::SendPacket(wire) = output {
                sender.feed_recv_buf(&wire, now.add_micros(20_001)).unwrap();
            }
        }
        sender
            .seed_encrypted_packet_count_for_test(CryptoContext::KM_PRE_ANNOUNCE_PERIOD)
            .unwrap();
        let new = capture_data_datagram(sender, b"postannouncement DATA", now.add_micros(20_002));
        receiver
            .feed_recv_buf(&new, now.add_micros(20_003))
            .unwrap();
        receiver
            .handle_timer(TimerId::DeliveryContinue, now.add_micros(200_000))
            .unwrap();
        while receiver.poll_event().is_some() {}
        while sender.poll_event().is_some() {}
        let crypto = sender.crypto.as_ref().unwrap();
        assert_eq!(
            crypto.km_refresh_state(),
            crate::crypto_impl::KmRefreshState::Idle
        );
        let state = crypto.key_state_for_test();
        let retired = match state.tx_current {
            KeyFlag::Even => state.tx_odd,
            KeyFlag::Odd => state.tx_even,
        };
        assert!(
            retired.iter().all(|byte| *byte == 0),
            "old TX schedule retired normally"
        );
        request
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real CTR handshake and refresh"
    )]
    fn retired_transmit_key_reflection_cannot_replace_live_receive_key_ctr() {
        assert_retired_transmit_key_reflection_cannot_replace_live_receive_key(CipherMode::Ctr);
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "real GCM handshake and refresh"
    )]
    fn retired_transmit_key_reflection_cannot_replace_live_receive_key_gcm() {
        assert_retired_transmit_key_reflection_cannot_replace_live_receive_key(CipherMode::Gcm);
    }

    fn assert_retired_transmit_key_reflection_cannot_replace_live_receive_key(mode: CipherMode) {
        let (mut caller, mut listener) = quiet_encrypted_pair(mode, KeyLength::Aes128);
        let now = Timestamp::from_micros(10_000_000);
        confirm_switch_and_retire(&mut listener, &mut caller, &fixture_key(0x71), now);
        let own_odd = confirm_switch_and_retire(
            &mut caller,
            &mut listener,
            &fixture_key(0x6B),
            now.add_micros(300_000),
        );
        confirm_switch_and_retire(
            &mut caller,
            &mut listener,
            &fixture_key(0x7C),
            now.add_micros(600_000),
        );
        let payload = b"authentic peer odd DATA survives retired TX reflection";
        // Protect first, reflect historical KM second, deliver afterwards.
        let peer_data = capture_data_datagram(&mut listener, payload, now.add_micros(900_000));
        assert_km_control_rejected(
            &mut caller,
            SRT_CMD_KMREQ,
            user_defined_control_info(&own_odd),
            now.add_micros(900_001),
            "decommissioned outbound key reflected",
        );
        caller
            .feed_recv_buf(&peer_data, now.add_micros(900_002))
            .unwrap();
        caller
            .handle_timer(TimerId::DeliveryContinue, now.add_micros(1_100_000))
            .unwrap();
        assert_eq!(
            crypto_event_bytes(std::iter::from_fn(|| caller.poll_event())),
            payload
        );
    }

    /// A connected encrypted pair sharing one passphrase.
    fn encrypted_pair(cipher_mode: CipherMode) -> (SrtConnection, SrtConnection) {
        encrypted_pair_with(cipher_mode, KeyLength::Aes128)
    }

    fn encrypted_pair_with(
        cipher_mode: CipherMode,
        key_length: KeyLength,
    ) -> (SrtConnection, SrtConnection) {
        let sek = fixture_key_vec(0x5A, key_length.len());
        let options = |socket_id: u32| ConnectionOptions {
            socket_id,
            passphrase: Some(KM_FIXTURE_PASSPHRASE.to_owned()),
            crypto_salt: Some(test_km_salt()),
            crypto_sek: Some(sek.clone()),
            key_length,
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

    #[derive(Debug, PartialEq, Eq)]
    struct KmSecuritySnapshot {
        state: ConnectionState,
        keys: crate::crypto_impl::KeyStateForTest,
        pending_response: Option<Vec<u8>>,
        initial_tx_pending: bool,
        acknowledged: Vec<Option<Vec<u8>>>,
        acknowledged_next: usize,
    }

    fn km_security_snapshot(connection: &SrtConnection) -> KmSecuritySnapshot {
        let crypto = connection.crypto.as_ref().expect("secured connection");
        let state = connection
            .km_control
            .as_ref()
            .expect("secured KM control state");
        KmSecuritySnapshot {
            state: connection.state(),
            keys: crypto.key_state_for_test(),
            pending_response: state
                .pending
                .as_ref()
                .map(|pending| pending.request.encode()),
            initial_tx_pending: state.initial_tx_pending,
            acknowledged: state
                .acknowledged
                .entries
                .iter()
                .map(|entry| entry.as_ref().map(KmMessage::encode))
                .collect(),
            acknowledged_next: state.acknowledged.next,
        }
    }

    fn current_km_message(connection: &SrtConnection) -> KmMessage {
        let crypto = connection.crypto.as_ref().expect("secured connection");
        KmMessage::new(
            crypto.current_key(),
            crypto.key_length(),
            *crypto.salt(),
            crypto
                .wrap_sek(crypto.current_key())
                .expect("current key wraps"),
            crypto.cipher_mode(),
        )
    }

    fn assert_km_control_rejected(
        target: &mut SrtConnection,
        subtype: u16,
        body: Vec<u8>,
        now: Timestamp,
        label: &str,
    ) {
        let _ = drain_outputs(target);
        assert!(target.poll_event().is_none(), "{label}: stale event");
        let before = km_security_snapshot(target);
        let stats = target.stats();
        let last_recv_time = target.last_recv_time;
        let datagram = control_datagram(
            target.socket_id(),
            ControlType::UserDefined,
            subtype,
            0,
            body,
        );

        target
            .feed_recv_buf(&datagram, now)
            .expect_err("hostile KM control must be rejected");

        assert_eq!(
            km_security_snapshot(target),
            before,
            "{label}: secured KM state changed"
        );
        assert_eq!(
            target.last_recv_time, last_recv_time,
            "{label}: rejected control refreshed liveness"
        );
        assert_eq!(target.stats(), stats, "{label}: telemetry state changed");
        assert!(
            drain_outputs(target).is_empty(),
            "{label}: rejected control emitted output"
        );
        assert!(
            target.poll_event().is_none(),
            "{label}: rejected control emitted an event"
        );
        assert!(
            target
                .crypto
                .as_ref()
                .is_some_and(|crypto| crypto.can_encrypt_current_key()),
            "{label}: active encryption became unusable"
        );
    }

    fn assert_encrypted_roundtrip(
        sender: &mut SrtConnection,
        receiver: &mut SrtConnection,
        now: Timestamp,
        payload: &[u8],
    ) {
        let datagram = capture_data_datagram(sender, payload, now);
        let Ok(SrtPacket::Data(packet)) = SrtPacket::decode(&datagram) else {
            panic!("encrypted send must produce DATA");
        };
        assert_ne!(
            packet.encryption_flag, 0,
            "secured DATA must not be emitted in cleartext"
        );

        let last_recv_time = receiver.last_recv_time;
        let clear = with_key_selector(&datagram, 0);
        let error = receiver
            .feed_recv_buf(&clear, now)
            .expect_err("clear DATA must be rejected on a secured connection");
        assert_eq!(error.kind, crate::error::ErrorKind::CryptoError);
        assert_eq!(
            receiver.last_recv_time, last_recv_time,
            "rejected clear DATA must not refresh liveness"
        );

        let received_before = receiver
            .receiver_stats()
            .expect("connected receiver")
            .total_received;
        receiver
            .feed_recv_buf(&datagram, now.add_micros(1))
            .expect("next authentic encrypted DATA succeeds");
        assert_eq!(
            receiver
                .receiver_stats()
                .expect("connected receiver")
                .total_received,
            received_before + 1,
            "authentic encrypted DATA must enter reliability state"
        );
        while receiver.poll_event().is_some() {}
    }

    fn take_user_defined_datagram(connection: &mut SrtConnection, subtype: u16) -> Vec<u8> {
        for output in drain_outputs(connection) {
            let ConnectionOutput::SendPacket(datagram) = output else {
                continue;
            };
            let matching = matches!(
                SrtPacket::decode(&datagram),
                Ok(SrtPacket::Control(ControlPacket {
                    control_type: ControlType::UserDefined,
                    subtype: packet_subtype,
                    ..
                })) if packet_subtype == subtype
            );
            if matching {
                return datagram;
            }
        }
        panic!("expected UserDefined subtype {subtype:#06x}");
    }

    fn key_message_from_datagram(datagram: &[u8]) -> KmMessage {
        let SrtPacket::Control(control) =
            SrtPacket::decode(datagram).expect("valid KM control datagram")
        else {
            panic!("KM datagram must be a control packet");
        };
        KmMessage::decode(&control.control_info).expect("valid KM message")
    }

    /// The control-information field of a UserDefined datagram: the key
    /// material a retry must reproduce byte-for-byte. The control packet's
    /// own timestamp is deliberately not compared -- it is the send time of
    /// this transmission, and the peer matches duplicates on the KM message,
    /// not on the datagram that carried it.
    fn user_defined_control_info(datagram: &[u8]) -> Vec<u8> {
        let SrtPacket::Control(control) =
            SrtPacket::decode(datagram).expect("valid KM control datagram")
        else {
            panic!("KM datagram must be a control packet");
        };
        control.control_info
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
        assert!(conn.peer_shutdown_at.is_some());
        assert_eq!(conn.state(), ConnectionState::Connected, "still draining");
        assert!(conn.poll_event().is_none(), "no event before the deadline");

        // Duplicate SHUTDOWN: a peer retransmits until it sees an answer.
        conn.feed_recv_buf(&shutdown, arrived)
            .expect("a duplicate SHUTDOWN is accepted and ignored");
        assert!(conn.peer_shutdown_at.is_some());

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
        assert!(conn.peer_shutdown_at.is_some());

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
        assert!(conn.peer_shutdown_at.is_some());

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

    #[test]
    fn replayed_data_cannot_repeat_window_sized_delivery_work() {
        let mut conn = tsbpd_listener(120, false, 32);
        let now = Timestamp::from_micros(2_000);
        let mut replay = Vec::new();
        for sequence in 0..32 {
            let packet = DataPacket::new(
                sequence,
                sequence,
                100_000_000 - sequence,
                conn.options.socket_id,
                Bytes::from_static(b"retained"),
            );
            let mut wire = Vec::new();
            packet.encode(&mut wire).expect("encode DATA");
            conn.feed_recv_buf(&wire, now).expect("receive DATA");
            if sequence == 0 {
                replay = wire;
            }
        }
        let before = crate::test_support::WorkCounters::snapshot();
        for _ in 0..64 {
            conn.feed_recv_buf(&replay, now)
                .expect("receive duplicate DATA");
        }
        let work = crate::test_support::WorkCounters::since(before);
        assert!(work.deadline_probes <= 64);
        let receiver = conn.receiver.as_ref().unwrap();
        assert_eq!(receiver.stats().packets_in_buffer, 32);
        assert_eq!(receiver.stats().total_duplicates, 64);
        assert_eq!(conn.pending_data_events, 0);

        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(100_120_000))
            .expect("release the head and its successors");
        for sequence in 0..32 {
            assert!(matches!(
                conn.poll_event(),
                Some(ConnectionEvent::DataReceived { sequence_number, .. })
                    if sequence_number == sequence
            ));
        }
    }

    #[test]
    fn peer_shutdown_waits_for_the_sequence_head_not_the_minimum_timestamp() {
        let mut conn = tsbpd_listener(8_000, false, 8);
        let arrived = Timestamp::from_micros(2_000);
        for (sequence, timestamp, payload) in
            [(0, 4_000_000, &b"first"[..]), (1, 0, &b"second"[..])]
        {
            conn.handle_data_packet(
                DataPacket::new(sequence, sequence, timestamp, 0, payload.to_vec().into()),
                arrived,
            )
            .expect("receive DATA");
        }
        conn.handle_shutdown(arrived).expect("peer shutdown");
        drain_outputs(&mut conn);
        for now in [5_002_000, 8_000_000] {
            conn.handle_timer(TimerId::Inactivity, Timestamp::from_micros(now))
                .expect("inactivity tick");
            assert_eq!(conn.state(), ConnectionState::Connected);
            assert!(
                conn.poll_event().is_none(),
                "the later sequence cannot bypass the head"
            );
            assert!(drain_outputs(&mut conn).into_iter().any(|output| matches!(
                output,
                ConnectionOutput::SetTimer {
                    id: TimerId::Inactivity,
                    duration_micros,
                } if duration_micros == 12_000_000 - now
            )));
        }
        conn.handle_timer(TimerId::Inactivity, Timestamp::from_micros(12_000_000))
            .expect("head deadline");
        assert_delivered_payload(&mut conn, b"first");
        assert_delivered_payload(&mut conn, b"second");
        assert_peer_shutdown_terminal(&mut conn);
    }

    /// Assert the next event is the payload the connection delivered.
    fn assert_delivered_payload(conn: &mut SrtConnection, expected: &[u8]) {
        let delivered = conn.poll_event().expect("the payload is delivered");
        assert!(
            matches!(&delivered, ConnectionEvent::DataReceived { payload, .. } if payload.eq(expected)),
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

        // The hole is given up when the message after it is due (60 us +
        // 120 ms latency), like libsrt: one tick before, nothing moves.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(120_059))
            .expect("ACK tick");
        assert!(conn.poll_event().is_none(), "the hole has not expired yet");
        assert_eq!(conn.state(), ConnectionState::Connected);

        // Once the later message is due, TLPKTDROP retires the hole (and with
        // it the message that can never complete), the later message is
        // delivered, and only then does the peer close become terminal.
        conn.handle_timer(TimerId::Ack, Timestamp::from_micros(120_060))
            .expect("ACK tick");
        let delivered = conn
            .poll_event()
            .expect("the complete message is delivered");
        assert!(
            matches!(&delivered, ConnectionEvent::DataReceived { payload, .. } if payload.eq(&b"tail"[..])),
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

    /// A peer that sent SHUTDOWN and then keeps sending KEEPALIVEs must not
    /// hold an undrainable half-close open forever. The drain is bounded as
    /// if the peer had gone silent at its SHUTDOWN: here an incomplete
    /// message without TLPKTDROP can never drain, and the connection closes
    /// with the peer's reason one inactivity timeout after the SHUTDOWN.
    #[test]
    fn keepalives_cannot_hold_a_peer_shutdown_drain_open() {
        let mut conn = tsbpd_listener(120, false, 8);
        let socket_id = conn.options.socket_id;
        conn.setup_connection_timers();
        let mut head = DataPacket::new(0, 1, 50, 0, b"head".to_vec().into());
        head.position = crate::srt_packet::PacketPosition::First;
        conn.handle_data_packet(head, Timestamp::from_micros(2_000))
            .expect("the first fragment is accepted");
        let shutdown_at = Timestamp::from_micros(10_000);
        conn.feed_recv_buf(
            &control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]),
            shutdown_at,
        )
        .expect("the peer's SHUTDOWN is accepted");
        assert_eq!(
            conn.state(),
            ConnectionState::Connected,
            "nothing drained yet"
        );

        let mut timers = TestTimers::default();
        for output in drain_outputs(&mut conn) {
            timers.apply(&output, shutdown_at);
        }
        let keepalive = control_datagram(socket_id, ControlType::Keepalive, 0, 0, vec![0; 4]);
        let mut closed_at = None;
        'run: for second in 1..=60 {
            let keepalive_at = shutdown_at.add_micros(second * 1_000_000);
            while let Some((id, due)) = timers.earliest().filter(|(_, due)| *due < keepalive_at) {
                timers.deadlines[id.index()] = None;
                conn.handle_timer(id, due).expect("armed timer");
                for output in drain_outputs(&mut conn) {
                    timers.apply(&output, due);
                }
                if conn.state() == ConnectionState::Disconnected {
                    closed_at = Some(due);
                    break 'run;
                }
            }
            conn.feed_recv_buf(&keepalive, keepalive_at)
                .expect("KEEPALIVE accepted");
            for output in drain_outputs(&mut conn) {
                timers.apply(&output, keepalive_at);
            }
        }
        assert_eq!(
            closed_at,
            Some(shutdown_at.add_micros(INACTIVITY_TIMEOUT_MICROS)),
            "closed one inactivity timeout after the SHUTDOWN"
        );
        let terminal = std::iter::from_fn(|| conn.poll_event())
            .filter(|event| matches!(event, ConnectionEvent::Disconnected { .. }))
            .collect::<Vec<_>>();
        assert!(
            matches!(
                terminal.as_slice(),
                [ConnectionEvent::Disconnected {
                    reason: DisconnectReason::PeerShutdown
                }]
            ),
            "{terminal:?}"
        );
    }

    /// A drain the inactivity tick completes itself (here TLPKTDROP gives
    /// up the message missing its middle fragment) ends with exactly one
    /// terminal event: the tick must stop once the drain closed.
    #[test]
    fn a_drain_completed_by_the_inactivity_tick_emits_one_terminal_event() {
        let mut conn = tsbpd_listener(120, true, 8);
        let socket_id = conn.options.socket_id;
        let arrived = Timestamp::from_micros(2_000);
        for (sequence, timestamp, position) in [
            (0, 50, crate::srt_packet::PacketPosition::First),
            (2, 60, crate::srt_packet::PacketPosition::Last),
        ] {
            let mut packet = DataPacket::new(sequence, 1, timestamp, 0, b"part".to_vec().into());
            packet.position = position;
            conn.handle_data_packet(packet, arrived)
                .expect("fragment accepted");
        }
        conn.feed_recv_buf(
            &control_datagram(socket_id, ControlType::Shutdown, 0, 0, vec![0; 4]),
            Timestamp::from_micros(10_000),
        )
        .expect("the peer's SHUTDOWN is accepted");
        assert_eq!(
            conn.state(),
            ConnectionState::Connected,
            "nothing drained yet"
        );
        drain_outputs(&mut conn);

        conn.handle_timer(TimerId::Inactivity, Timestamp::from_micros(5_010_000))
            .expect("inactivity tick");
        assert_eq!(conn.state(), ConnectionState::Disconnected);
        let events: Vec<_> = std::iter::from_fn(|| conn.poll_event()).collect();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, ConnectionEvent::DataReceived { .. })),
            "{events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ConnectionEvent::Disconnected { .. }))
                .count(),
            1,
            "{events:?}"
        );
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
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "a real KM handshake derives its KEK via 2048 PBKDF2-HMAC-SHA1 iterations   \
                  (per the SRT spec) under Miri, which dominates this job's time;            \
                  correctness is proven outside Miri, and this property is unrelated to      \
                  PBKDF2's own iteration count. Run in the miri-extended scheduled job."
    )]
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

    /// Every handshake packet the listener sends while connecting `caller`,
    /// decoded, so a test can inspect the responder's GROUP extension.
    fn listener_handshakes(
        caller_group: Option<GroupExtensionData>,
        listener_group: GroupExtensionData,
    ) -> Vec<HandshakePacket> {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            group_extension: caller_group,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            group_extension: Some(listener_group),
            ..ConnectionOptions::default()
        });
        caller.connect(Timestamp::from_micros(0)).expect("starts");
        let mut seen = Vec::new();
        for round in 0..4 {
            let now = Timestamp::from_micros(round * 10_000);
            while let Some(ConnectionOutput::SendPacket(packet)) = caller.poll_output().unwrap() {
                listener.feed_recv_buf(&packet, now).expect("listener rx");
            }
            while let Some(ConnectionOutput::SendPacket(packet)) = listener.poll_output().unwrap() {
                if let Ok(SrtPacket::Control(control)) = SrtPacket::decode(&packet)
                    && let Ok(handshake) = HandshakePacket::decode(&control)
                {
                    seen.push(handshake);
                }
                caller.feed_recv_buf(&packet, now).expect("caller rx");
            }
        }
        assert_eq!(caller.state(), ConnectionState::Connected);
        seen
    }

    #[test]
    fn listener_group_identity_is_only_advertised_to_group_callers() {
        let receiver = GroupExtensionData {
            group_id: SRTGROUP_MASK | 0x0A0A,
            group_type: GroupType::Broadcast,
            flags: 0,
            weight: 0,
        };
        let direct = listener_handshakes(None, receiver);
        assert!(!direct.is_empty(), "the listener answered the handshake");
        assert!(
            direct.iter().all(|hs| hs.get_group_extension().is_none()),
            "a direct caller never receives a GROUP response"
        );

        let callers_own = GroupExtensionData {
            group_id: SRTGROUP_MASK | 0x0707,
            group_type: GroupType::Broadcast,
            flags: 0,
            weight: 1,
        };
        let bonded = listener_handshakes(Some(callers_own), receiver);
        let advertised: Vec<_> = bonded
            .iter()
            .filter_map(|hs| hs.get_group_extension())
            .collect();
        assert!(
            !advertised.is_empty(),
            "a group caller gets a GROUP response"
        );
        assert!(
            advertised.iter().all(|g| g.group_id == receiver.group_id),
            "the listener advertises its own receiving group, never the caller's id"
        );
    }

    #[test]
    #[cfg_attr(
        all(miri, not(feature = "miri-extended")),
        ignore = "constructs a real CryptoContext, deriving its KEK via 2048               \
                  PBKDF2-HMAC-SHA1 iterations (per the SRT spec) under Miri; correctness    \
                  is proven outside Miri, and this property is unrelated to PBKDF2's own    \
                  iteration count. Run in the miri-extended scheduled job."
    )]
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

        // The list takes 89 packets; each fire queues at most
        // MAX_PERIODIC_NAK_PACKETS and the next one resumes where it stopped.
        let mut decoded = Vec::new();
        let mut wire_packets = 0u64;
        let mut fires = 0;
        loop {
            fires += 1;
            conn.send_periodic_nak(Timestamp::from_micros(1 + fires));
            let mut this_fire = 0;
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
                this_fire += 1;
            }
            assert!(
                this_fire <= MAX_PERIODIC_NAK_PACKETS,
                "fire {fires}: {this_fire}"
            );
            wire_packets += this_fire as u64;
            if conn.periodic_nak_resume.is_none() {
                break;
            }
        }

        let expected: Vec<u32> = (0..MAX_FLOW_WINDOW - 1).step_by(2).collect();
        assert_eq!(decoded, expected, "every loss named once, in order");
        assert_eq!(wire_packets, 89);
        assert_eq!(fires, 89_u64.div_ceil(MAX_PERIODIC_NAK_PACKETS as u64));
        assert_eq!(conn.stats().receiver.unwrap().total_naks_sent, wire_packets);

        // The fire after the end starts over from the first loss.
        conn.send_periodic_nak(Timestamp::from_micros(100));
        let first = std::iter::from_fn(|| conn.poll_output().unwrap()).find_map(|output| {
            let ConnectionOutput::SendPacket(bytes) = output else {
                return None;
            };
            match SrtPacket::decode(&bytes).unwrap() {
                SrtPacket::Control(packet) if packet.control_type == ControlType::Nak => {
                    Some(parse_loss_list(&packet.control_info, usize::MAX).unwrap()[0])
                }
                _ => None,
            }
        });
        assert_eq!(first, Some(0));
    }

    /// When every loss at or after the resume point was repaired between
    /// fires, the next fire reports from the start instead of sending nothing.
    #[test]
    #[cfg_attr(miri, ignore = "maximum-window scale")]
    fn periodic_nak_restarts_when_its_resume_point_was_repaired() {
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
        while conn.poll_output().unwrap().is_some() {}
        let resume = conn.periodic_nak_resume.expect("the list needs more fires");

        let receiver = conn.receiver.as_mut().unwrap();
        for sequence_number in (resume..MAX_FLOW_WINDOW - 1).step_by(2) {
            receiver.receive(
                DataPacket::new(sequence_number, 1, 1, 0, Vec::new().into()),
                now,
            );
        }
        conn.send_periodic_nak(Timestamp::from_micros(3));
        let naks = std::iter::from_fn(|| conn.poll_output().unwrap())
            .filter(|output| {
                matches!(output, ConnectionOutput::SendPacket(bytes)
                    if matches!(SrtPacket::decode(bytes), Ok(SrtPacket::Control(ControlPacket { control_type: ControlType::Nak, .. }))))
            })
            .count();
        assert!(
            naks > 0,
            "the remaining losses are reported again from the start"
        );
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
    fn forward_handshake_round(from: &mut SrtConnection, to: &mut SrtConnection, now: Timestamp) {
        for output in drain_outputs(from) {
            match output {
                ConnectionOutput::SendPacket(packet) => {
                    to.feed_recv_buf(&packet, now).expect("peer accepts packet");
                }
                ConnectionOutput::SetTimer {
                    id,
                    duration_micros,
                } => {
                    from.queue_output(QueuedOutput::SetTimer {
                        id,
                        duration_micros,
                    });
                }
                ConnectionOutput::ClearTimer { id } => {
                    from.queue_output(QueuedOutput::ClearTimer { id });
                }
            }
        }
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
