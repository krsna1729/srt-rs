//! Strict SRT wire checker for srt-rs-to-srt-rs test fixtures.
//!
//! When both ends of a test are srt-rs, srt-rs's own receiver decides
//! whether a packet was acceptable, so an emitter regression it tolerates
//! passes unnoticed. A [`WireChecker`] instead holds every datagram one
//! endpoint emits to the wire rules libsrt 1.5.7 produces or enforces. It
//! parses the raw big-endian header and CIF words itself and does not
//! reuse `HandshakePacket::decode` or the connection's control validation,
//! so it does not inherit their tolerance.
//!
//! A checker belongs to one endpoint and keeps that endpoint's transcript:
//! its role and handshake phase, the caller ISN and cookie, the socket IDs,
//! the latency halves and REXMITFLG/STREAM flags it negotiated, the
//! metadata of every original DATA packet, its ACK numbers, the ACK numbers
//! it received, and the sequence and drop frontiers it has seen. Two
//! checkers on a connected pair therefore hold one transcript per direction.
//!
//! [`SrtConnection::install_wire_checker`] hooks a checker into the
//! successful datagram branch of [`SrtConnection::poll_output_into`] (which
//! [`SrtConnection::poll_output`] delegates to) and into the receive entry
//! points. It therefore sees each emission before any simulated loss,
//! reordering or rewrite, and records what the endpoint actually received
//! -- including packets a test fabricated or rewrote -- as peer input.
//! Rules that depend on negotiation (REXMITFLG, latency, the ACK numbers an
//! ACKACK may echo, the loss a NAK may report) are judged against those
//! received inputs, not against what the peer endpoint emitted. A violation
//! panics with the rule name, the endpoint, the emission index and a
//! packet summary.
//!
//! The rules are named by the constants in [`rule`]; each cites the libsrt
//! 1.5.7 source it follows (paths under `srtcore/` unless stated, the
//! handshake document being `docs/features/handshake.md`). Profile rules
//! whose desired contract is undecided are [`OptionalRule`]s, off by
//! default.
//!
//! The checker covers the caller/listener handshake srt-rs implements; a
//! rendezvous or HSv4 handshake is reported as an unexpected type.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::{ConnectionRole, SrtConnection};

/// Names of the strict rules, as reported in a [`WireViolation`].
pub mod rule {
    /// A datagram shorter than the 16-byte SRT header.
    pub const HEADER: &str = "header";
    /// Caller INDUCTION: version 4, combined type field `UDT_DGRAM` (2),
    /// cookie 0, destination 0, no extensions, nonzero socket ID, a 31-bit
    /// ISN, and the same identity on every retry (`core.cpp:3764-3796`;
    /// handshake document lines 507-520).
    pub const CALLER_INDUCTION: &str = "caller_induction";
    /// Listener INDUCTION response: version 5, `SRT_MAGIC_CODE` in the
    /// extension field, the request's ISN echoed, addressed to the
    /// caller's socket, no extensions (`core.cpp:11768-11811`, which edits
    /// the received handshake in place).
    pub const INDUCTION_RESPONSE: &str = "induction_response";
    /// Caller CONCLUSION: version 5, the INDUCTION's socket ID and ISN kept,
    /// the response cookie echoed, destination 0 or the responder's ID
    /// (`core.cpp:3781-3796`, `4883-4888`, `4147-4148`).
    pub const CALLER_CONCLUSION: &str = "caller_conclusion";
    /// Listener CONCLUSION response: version 5, the caller's CONCLUSION ISN,
    /// addressed to the caller's socket, nonzero socket ID
    /// (`core.cpp:5995-6011`, `6042-6051`).
    pub const CONCLUSION_RESPONSE: &str = "conclusion_response";
    /// A handshake type srt-rs does not send in its role (no rendezvous
    /// WAVEAHAND/AGREEMENT, no listener-initiated INDUCTION).
    pub const HANDSHAKE_TYPE: &str = "handshake_type";
    /// Extension blocks fill the CIF exactly, use known types, carry each
    /// negotiated quantity at most once, and sit on the side that sends
    /// them: HSREQ/KMREQ/SID from the initiator, HSRSP/KMRSP from the
    /// responder (`core.cpp:1225-1227`, `1288-1290`, `1703-1709`,
    /// `2640-2750`, `2995-3001`).
    pub const EXTENSION_FRAMING: &str = "extension_framing";
    /// Each extension category bit (HSREQ, KMREQ, CONFIG) is set exactly
    /// when a block of that category is present (`core.cpp:1702-1796`).
    pub const EXTENSION_CATEGORIES: &str = "extension_categories";
    /// The HSREQ/HSRSP block is three words, from the right role, with SRT
    /// version at least 1.3.0 (`srt.h:54`, `core.cpp:2290-2296`) and, in an
    /// HSREQ, REXMITFLG set (`core.cpp:1272-1273`).
    pub const HS_BLOCK: &str = "hs_block";
    /// An HSRSP sets REXMITFLG exactly when the HSREQ did
    /// (`core.cpp:1367-1386`).
    pub const REXMIT_NEGOTIATION: &str = "rexmit_negotiation";
    /// An HSRSP declares the same STREAM/message API as the HSREQ; libsrt
    /// refuses a mismatch (`core.cpp:2320-2328`).
    pub const STREAM_FLAG: &str = "stream_flag";
    /// HSRSP latency halves are negotiated per direction: RCV is at least
    /// the request's SND, SND at least the request's RCV
    /// (`core.cpp:2388-2432`, `1314-1333`).
    pub const DIRECTIONAL_LATENCY: &str = "directional_latency";
    /// A four-byte KMRSP is a little-endian `SRT_KM_STATE` word
    /// (`crypto.cpp:347-355`, `core.cpp:1437-1444`).
    pub const KM_STATE_WORD: &str = "km_state_word";
    /// SID is 1-512 bytes, congestion 1-16 bytes
    /// (`core.cpp:2950-2960`, `2995-3015`; `socketconfig.h:217-219`).
    pub const CONFIG_BOUNDS: &str = "config_bounds";
    /// GROUP is at least two words, carries `SRTGROUP_MASK` and a known
    /// type, and appears in a response only for a group request
    /// (`core.cpp:3083-3097`, `3317-3331`, `3384-3394`; `srt.h:942-949`).
    pub const GROUP_VALIDITY: &str = "group_validity";
    /// The peer-IP field holds the transport's peer address in libsrt's
    /// word-swapped layout, never zero (`core.cpp:3782`, `6011`;
    /// `common.cpp:162-175`; `packet.cpp:435-446`).
    pub const PEER_IP: &str = "peer_ip";
    /// The encryption field advertises no key or PBKEYLEN 2/3/4
    /// (`handshake.h:135-151`).
    pub const ENCRYPTION_FIELD: &str = "encryption_field";
    /// Connected DATA and control go to the peer's negotiated socket ID;
    /// nothing is sent before one is known (`core.cpp:8198-8293`, which
    /// also skips SHUTDOWN without a peer ID).
    pub const DESTINATION_SOCKET_ID: &str = "destination_socket_id";
    /// Original DATA starts at the session ISN and advances by one, modulo
    /// 2^31 (`core.cpp:3794-3796`, `6042-6051`; `packet.h:163-176`). It
    /// may skip forward only over packets the sender dropped before sending
    /// them, as libsrt does (`core.cpp:6857-6862`, `10446-10450`). Nothing
    /// else on the wire tells such a skip from a numbering bug, so the
    /// skipped range must be announced by a DROPREQ, sent before or after
    /// the skip or still queued when the connection is dropped.
    pub const DATA_SEQUENCE: &str = "data_sequence";
    /// R is set exactly on retransmissions, and only when the peer
    /// advertised REXMITFLG (`core.cpp:9990-9998`; `packet.h:170-176`).
    pub const R_BIT: &str = "r_bit";
    /// A retransmission repeats its original's boundary, order flag and
    /// message number (`buffer_snd.cpp:193-214`).
    pub const RETRANSMISSION_IDENTITY: &str = "retransmission_identity";
    /// Message number 0 is reserved: libsrt's `MsgNo` rolls from 1
    /// (`packet.h:184`; `buffer_snd.cpp:228-236`; `core.cpp:11082-11108`).
    pub const MESSAGE_NUMBER: &str = "message_number";
    /// Fragments run FIRST, MIDDLE..., LAST on consecutive sequences and
    /// share one message number, order flag and origin time; consecutive
    /// messages use different numbers (`buffer_snd.cpp:193-236`).
    pub const FRAGMENT_SEQUENCE: &str = "fragment_sequence";
    /// KK is 00, 01 or 10 (`packet.h:192-201`), and nonzero only after this
    /// side's handshake carried key material.
    pub const KEY_FLAGS: &str = "key_flags";
    /// Every timestamp is on the one session epoch libsrt stamps from
    /// (`core.cpp:10103-10135`): nothing after the handshake predates this
    /// side's first CONCLUSION-phase handshake, original DATA origin times
    /// do not decrease, and neither do control emission times.
    pub const TIMESTAMP_EPOCH: &str = "timestamp_epoch";
    /// Control subtype is zero except for SRT extended commands, and the
    /// type-specific word is zero where libsrt passes no argument
    /// (`core.cpp:8180-8293`; handshake document lines 179-191).
    pub const CONTROL_HEADER: &str = "control_header";
    /// KEEPALIVE, SHUTDOWN and ACKACK carry nothing but libsrt's optional
    /// four zero padding bytes (`packet.cpp:346-390`).
    pub const CONTROL_PADDING: &str = "control_padding";
    /// An ACK CIF is 4 (Lite), 16 (Small), or 24/28/32 (Full) bytes
    /// (`core.cpp:8572-8606`, `8720-8730`).
    pub const ACK_SHAPE: &str = "ack_shape";
    /// A Lite ACK carries no ACK number (`core.cpp:8399-8402`); numbered
    /// ACKs use libsrt's 31-bit domain and advance by one per ACK
    /// (`common.h:728-735`; `core.cpp:8566-8571`).
    pub const ACK_ID: &str = "ack_id";
    /// The acknowledged sequence is 31-bit and not beyond what this side
    /// received or was told to drop (`core.cpp:8734-8765`).
    pub const ACK_POSITION: &str = "ack_position";
    /// NAK words are singletons or a high-bit range start followed by an
    /// unflagged end, each range forward (`core.cpp:9110-9155`).
    pub const NAK_ENCODING: &str = "nak_encoding";
    /// No reported loss lies beyond the newest DATA this side received; the
    /// sender discards such a report (`core.cpp:9129-9140`).
    pub const NAK_FRONTIER: &str = "nak_frontier";
    /// An ACKACK echoes the number of a numbered ACK this side received
    /// (`core.cpp:8993-9029`).
    pub const ACKACK_ECHO: &str = "ackack_echo";
    /// DROPREQ carries exactly two unflagged sequence endpoints in forward
    /// order (`core.cpp:8290-8293`, `9400-9429`).
    pub const DROPREQ_SHAPE: &str = "dropreq_shape";
    /// Runtime key-material control packets are SRT extended commands
    /// KMREQ (3) or KMRSP (4) with a word-aligned body
    /// (`core.cpp:1437-1444`).
    pub const KM_CONTROL: &str = "km_control";
    /// Optional ([`super::OptionalRule::LiveSinglePacketMessages`]): with
    /// TSBPD negotiated, every DATA packet is a whole message
    /// (`core.cpp:7003-7011`).
    pub const LIVE_SINGLE_PACKET_MESSAGES: &str = "live_single_packet_messages";
}

/// Profile rules that are off by default because the audit left them
/// SUSPECTED or srt-rs deliberately differs from libsrt there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OptionalRule {
    /// libsrt's live sender refuses messages needing more than one packet
    /// (`MN_XSIZE`, `core.cpp:7003-7011`), but its receiver reassembles
    /// them and srt-rs documents live multi-packet messages as an
    /// extension. Checked as [`rule::LIVE_SINGLE_PACKET_MESSAGES`].
    LiveSinglePacketMessages,
}

/// One broken wire rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireViolation {
    /// The rule's name, one of the [`rule`] constants.
    pub rule: &'static str,
    /// What was wrong.
    pub detail: String,
    /// The emitting endpoint's role.
    pub role: ConnectionRole,
    /// One-based index of the offending emission on that endpoint.
    pub emission: u64,
    /// Summary of the offending datagram.
    pub packet: String,
}

impl fmt::Display for WireViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "strict wire rule `{}` violated by the {:?}'s emission #{}: {}\n  packet: {}",
            self.rule, self.role, self.emission, self.detail, self.packet
        )
    }
}

impl std::error::Error for WireViolation {}

/// Address a checked caller's transport reports for its listener.
pub const LISTENER_TEST_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9000));
/// Address a checked listener's transport reports for its caller.
pub const CALLER_TEST_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 5000));

/// Install a checker on each side of a fresh caller/listener pair that has
/// none yet. A side whose transport address the test did not set reports
/// the documentation-range test address for its peer, as a transport
/// would.
///
/// # Panics
///
/// Panics if a connection without a checker has already started its
/// handshake.
pub fn check_pair(caller: &mut SrtConnection, listener: &mut SrtConnection) {
    for (conn, peer) in [
        (caller, LISTENER_TEST_ADDRESS),
        (listener, CALLER_TEST_ADDRESS),
    ] {
        conn.default_peer_address(peer);
        if conn.wire_checker_mut().is_none() {
            conn.install_wire_checker();
        }
    }
}

/// The connection hook: check one emitted datagram, panicking on a
/// violation so the fixture fails at the emission that broke the rule.
pub(crate) fn observe_emitted(checker: Option<&mut WireChecker>, datagram: &[u8], peer_ip: IpAddr) {
    if let Some(checker) = checker
        && let Err(violation) = checker.check_emitted(datagram, peer_ip)
    {
        panic!("{violation}");
    }
}

const HEADER_LEN: usize = 16;
const HANDSHAKE_LEN: usize = 48;
const SEQ_MASK: u32 = 0x7FFF_FFFF;
const HALF_SEQ_SPACE: u32 = 1 << 30;
const MSGNO_MASK: u32 = 0x03FF_FFFF;

const CT_HANDSHAKE: u16 = 0x0000;
const CT_KEEPALIVE: u16 = 0x0001;
const CT_ACK: u16 = 0x0002;
const CT_NAK: u16 = 0x0003;
const CT_SHUTDOWN: u16 = 0x0005;
const CT_ACKACK: u16 = 0x0006;
const CT_DROPREQ: u16 = 0x0007;
const CT_EXTENDED: u16 = 0x7FFF;

const HS_INDUCTION: u32 = 1;
const HS_CONCLUSION: u32 = 0xFFFF_FFFF;
const HS_REJECTION_BASE: u32 = 1000;
const HS_REJECTION_END: u32 = 0xFFFF_FFFD;
const UDT_DGRAM: u32 = 2;
const SRT_MAGIC_CODE: u16 = 0x4A17;

const EXT_HSREQ: u16 = 1;
const EXT_HSRSP: u16 = 2;
const EXT_KMREQ: u16 = 3;
const EXT_KMRSP: u16 = 4;
const EXT_SID: u16 = 5;
const EXT_CONGESTION: u16 = 6;
const EXT_FILTER: u16 = 7;
const EXT_GROUP: u16 = 8;

const CATEGORY_HSREQ: u16 = 0x0001;
const CATEGORY_KMREQ: u16 = 0x0002;
const CATEGORY_CONFIG: u16 = 0x0004;

const FLAG_TSBPDSND: u32 = 0x01;
const FLAG_TSBPDRCV: u32 = 0x02;
const FLAG_REXMIT: u32 = 0x20;
const FLAG_STREAM: u32 = 0x40;
const MIN_SRT_VERSION: u32 = 0x01_03_00;

const MAX_SID_BYTES: usize = 512;
const MAX_CONGESTION_BYTES: usize = 16;
const GROUP_ID_MASK: u32 = 1 << 30;
const GROUP_TYPE_END: u32 = 3;
const MAX_KM_STATE: u32 = 5;
const ACK_SIZES: [usize; 5] = [4, 16, 24, 28, 32];

const PB_MIDDLE: u8 = 0b00;
const PB_LAST: u8 = 0b01;
const PB_FIRST: u8 = 0b10;
const PB_SOLO: u8 = 0b11;

struct Fault {
    rule: &'static str,
    detail: String,
}

type Check = Result<(), Fault>;

fn fault(rule: &'static str, detail: String) -> Fault {
    Fault { rule, detail }
}

/// Return the rule's fault unless `$ok` holds; the detail is formatted
/// only on failure.
macro_rules! ensure {
    ($ok:expr, $rule:expr, $($detail:tt)+) => {
        if !$ok {
            return Err(fault($rule, format!($($detail)+)));
        }
    };
}

fn be_word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn be_half(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn seq_next(seq: u32) -> u32 {
    seq.wrapping_add(1) & SEQ_MASK
}

/// Circular `a <= b` in the 31-bit sequence space.
fn seq_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) & SEQ_MASK < HALF_SEQ_SPACE
}

fn seq_max(a: u32, b: u32) -> u32 {
    if seq_le(a, b) { b } else { a }
}

#[derive(Debug, Clone, Copy)]
struct DataView {
    seq: u32,
    boundary: u8,
    in_order: bool,
    key: u8,
    rexmit: bool,
    msgno: u32,
    timestamp: u32,
    dest: u32,
    payload: usize,
}

struct ControlView<'a> {
    kind: u16,
    subtype: u16,
    info: u32,
    timestamp: u32,
    dest: u32,
    cif: &'a [u8],
}

enum View<'a> {
    Data(DataView),
    Control(ControlView<'a>),
}

fn parse(datagram: &[u8]) -> Option<View<'_>> {
    if datagram.len() < HEADER_LEN {
        return None;
    }
    let first = be_word(datagram, 0);
    let second = be_word(datagram, 4);
    let timestamp = be_word(datagram, 8);
    let dest = be_word(datagram, 12);
    if first & 0x8000_0000 == 0 {
        return Some(View::Data(DataView {
            seq: first,
            boundary: (second >> 30) as u8,
            in_order: second & (1 << 29) != 0,
            key: ((second >> 27) & 0b11) as u8,
            rexmit: second & (1 << 26) != 0,
            msgno: second & MSGNO_MASK,
            timestamp,
            dest,
            payload: datagram.len() - HEADER_LEN,
        }));
    }
    Some(View::Control(ControlView {
        kind: ((first >> 16) & 0x7FFF) as u16,
        subtype: first as u16,
        info: second,
        timestamp,
        dest,
        cif: &datagram[HEADER_LEN..],
    }))
}

#[derive(Debug, Clone)]
struct Block {
    cmd: u16,
    body: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Handshake {
    version: u32,
    encryption: u16,
    extension: u16,
    isn: u32,
    kind: u32,
    socket_id: u32,
    cookie: u32,
    peer_ip: [u8; 16],
    blocks: Vec<Block>,
}

#[derive(Debug, Clone, Copy)]
struct HsBlock {
    cmd: u16,
    version: u32,
    flags: u32,
    rcv: u16,
    snd: u16,
}

fn parse_handshake(cif: &[u8]) -> Result<Handshake, String> {
    if cif.len() < HANDSHAKE_LEN {
        return Err(format!(
            "{}-byte handshake CIF; libsrt's is at least {HANDSHAKE_LEN}",
            cif.len()
        ));
    }
    let mut peer_ip = [0u8; 16];
    peer_ip.copy_from_slice(&cif[32..HANDSHAKE_LEN]);
    Ok(Handshake {
        version: be_word(cif, 0),
        encryption: be_half(cif, 4),
        extension: be_half(cif, 6),
        isn: be_word(cif, 8),
        kind: be_word(cif, 20),
        socket_id: be_word(cif, 24),
        cookie: be_word(cif, 28),
        peer_ip,
        blocks: parse_blocks(&cif[HANDSHAKE_LEN..])?,
    })
}

fn parse_blocks(mut rest: &[u8]) -> Result<Vec<Block>, String> {
    let mut blocks = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(format!("{} bytes trail the extension blocks", rest.len()));
        }
        let cmd = be_half(rest, 0);
        let end = 4 + usize::from(be_half(rest, 2)) * 4;
        let Some(body) = rest.get(4..end) else {
            return Err(format!(
                "extension {cmd} declares {} bytes but {} remain",
                end - 4,
                rest.len() - 4
            ));
        };
        blocks.push(Block {
            cmd,
            body: body.to_vec(),
        });
        rest = &rest[end..];
    }
    Ok(blocks)
}

impl Handshake {
    fn block(&self, cmd: u16) -> Option<&Block> {
        self.blocks.iter().find(|block| block.cmd == cmd)
    }

    fn has(&self, cmd: u16) -> bool {
        self.block(cmd).is_some()
    }

    fn hs_block(&self) -> Option<HsBlock> {
        let block = self
            .blocks
            .iter()
            .find(|block| matches!(block.cmd, EXT_HSREQ | EXT_HSRSP))?;
        (block.body.len() == 12).then(|| HsBlock {
            cmd: block.cmd,
            version: be_word(&block.body, 0),
            flags: be_word(&block.body, 4),
            rcv: be_half(&block.body, 8),
            snd: be_half(&block.body, 10),
        })
    }

    /// Whether the handshake delivers key material: a KMREQ, or a KMRSP
    /// longer than a failure state word.
    fn carries_key_material(&self) -> bool {
        self.blocks.iter().any(|block| match block.cmd {
            EXT_KMREQ => true,
            EXT_KMRSP => block.body.len() > 4,
            _ => false,
        })
    }
}

fn is_rejection(kind: u32) -> bool {
    (HS_REJECTION_BASE..HS_REJECTION_END).contains(&kind)
}

/// libsrt's peer-IP field for `ip`: the address in four native words,
/// each byte-swapped onto the wire by the little-endian host.
fn libsrt_peer_ip(ip: IpAddr) -> [u8; 16] {
    let octets = match ip {
        IpAddr::V4(v4) => {
            let mut octets = [0u8; 16];
            octets[..4].copy_from_slice(&v4.octets());
            octets
        }
        IpAddr::V6(v6) => v6.octets(),
    };
    let mut wire = [0u8; 16];
    for (out, word) in wire.chunks_exact_mut(4).zip(octets.chunks_exact(4)) {
        out.copy_from_slice(&[word[3], word[2], word[1], word[0]]);
    }
    wire
}

fn control_name(kind: u16) -> &'static str {
    match kind {
        CT_HANDSHAKE => "HANDSHAKE",
        CT_KEEPALIVE => "KEEPALIVE",
        CT_ACK => "ACK",
        CT_NAK => "NAK",
        CT_SHUTDOWN => "SHUTDOWN",
        CT_ACKACK => "ACKACK",
        CT_DROPREQ => "DROPREQ",
        CT_EXTENDED => "EXTENDED",
        _ => "CONTROL",
    }
}

fn handshake_kind_name(kind: u32) -> String {
    match kind {
        HS_INDUCTION => "INDUCTION".to_owned(),
        HS_CONCLUSION => "CONCLUSION".to_owned(),
        kind if is_rejection(kind) => format!("REJECTION({})", kind - HS_REJECTION_BASE),
        kind => format!("{kind:#x}"),
    }
}

/// A one-line description of a datagram for violation reports.
fn summarize(datagram: &[u8]) -> String {
    match parse(datagram) {
        None => format!("{}-byte datagram", datagram.len()),
        Some(View::Data(data)) => format!(
            "DATA seq={} msgno={} PP={:02b} O={} KK={:02b} R={} ts={} dst={:#x} payload={}B",
            data.seq,
            data.msgno,
            data.boundary,
            u8::from(data.in_order),
            data.key,
            u8::from(data.rexmit),
            data.timestamp,
            data.dest,
            data.payload
        ),
        Some(View::Control(control)) => summarize_control(&control),
    }
}

fn summarize_control(control: &ControlView<'_>) -> String {
    let mut summary = format!(
        "{} type={:#06x} subtype={} info={:#x} ts={} dst={:#x} cif={}B",
        control_name(control.kind),
        control.kind,
        control.subtype,
        control.info,
        control.timestamp,
        control.dest,
        control.cif.len()
    );
    if control.kind == CT_HANDSHAKE
        && let Ok(hs) = parse_handshake(control.cif)
    {
        let blocks: Vec<u16> = hs.blocks.iter().map(|block| block.cmd).collect();
        let _ = write!(
            summary,
            " [v{} {} isn={} socket={:#x} cookie={:#x} enc={} ext={:#06x} blocks={:?}]",
            hs.version,
            handshake_kind_name(hs.kind),
            hs.isn,
            hs.socket_id,
            hs.cookie,
            hs.encryption,
            hs.extension,
            blocks
        );
    }
    summary
}

/// What this endpoint emitted in its handshakes.
#[derive(Debug, Default)]
struct OwnHandshake {
    /// The caller's INDUCTION identity: (ISN, socket ID).
    induction: Option<(u32, u32)>,
    /// ISN of this side's first CONCLUSION-phase handshake: in HSv5 both
    /// directions' DATA start from it (`core.cpp:6042-6051`).
    session_isn: Option<u32>,
    /// Timestamp of that handshake; nothing sent later predates it.
    epoch_floor: Option<u32>,
    /// Whether this side's handshake carried key material.
    key_material: bool,
    /// HSREQ/HSRSP flags this side emitted.
    hs_flags: Option<u32>,
}

/// What this endpoint received: the peer inputs negotiation-dependent
/// rules are judged against.
#[derive(Debug, Default)]
struct PeerInputs {
    /// Listener: the caller's INDUCTION; caller: the INDUCTION response.
    induction: Option<Handshake>,
    /// Listener: the caller's CONCLUSION; caller: the CONCLUSION response.
    conclusion: Option<Handshake>,
    newest_data: Option<u32>,
    newest_drop: Option<u32>,
    ack_numbers: HashSet<u32>,
}

#[derive(Debug, Clone, Copy)]
struct Original {
    boundary: u8,
    in_order: bool,
    msgno: u32,
}

#[derive(Debug, Clone, Copy)]
struct OpenMessage {
    msgno: u32,
    in_order: bool,
    timestamp: u32,
    next_seq: u32,
}

/// The DATA this endpoint sent.
#[derive(Debug, Default)]
struct DataTranscript {
    next_original: Option<u32>,
    originals: HashMap<u32, Original>,
    open_message: Option<OpenMessage>,
    last_message: Option<u32>,
    last_origin: Option<u32>,
    drops: Vec<(u32, u32)>,
    /// Half-open ranges original DATA skipped that no DROPREQ has covered
    /// yet.
    skipped: Vec<(u32, u32)>,
    /// The newest original DATA sequence sent.
    last_original: Option<u32>,
    /// A bonded send-sequence override awaits its first DATA.
    override_pending: bool,
}

/// Whether `drops` cover every sequence in `[from, to)`.
fn covered(drops: &[(u32, u32)], from: u32, to: u32) -> bool {
    let mut seq = from;
    while seq != to {
        let Some(&(_, last)) = drops
            .iter()
            .find(|&&(first, last)| seq_le(first, seq) && seq_le(seq, last))
        else {
            return false;
        };
        if seq_le(to, seq_next(last)) {
            return true;
        }
        seq = seq_next(last);
    }
    true
}

/// Strict wire checker for one endpoint; see the [module](self) docs.
#[derive(Debug)]
pub struct WireChecker {
    role: ConnectionRole,
    live_single_packet_messages: bool,
    emitted: u64,
    peer_socket_id: Option<u32>,
    own: OwnHandshake,
    peer: PeerInputs,
    data: DataTranscript,
    last_ack_number: Option<u32>,
    last_control_time: Option<u32>,
}

impl WireChecker {
    /// A checker for an endpoint in `role` that has not started its
    /// handshake.
    #[must_use]
    pub fn new(role: ConnectionRole) -> Self {
        Self {
            role,
            live_single_packet_messages: false,
            emitted: 0,
            peer_socket_id: None,
            own: OwnHandshake::default(),
            peer: PeerInputs::default(),
            data: DataTranscript::default(),
            last_ack_number: None,
            last_control_time: None,
        }
    }

    /// Turn on an optional profile rule.
    pub fn enable(&mut self, rule: OptionalRule) {
        match rule {
            OptionalRule::LiveSinglePacketMessages => self.live_single_packet_messages = true,
        }
    }

    /// Number of datagrams checked so far.
    #[must_use]
    pub fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Check one datagram this endpoint emitted, with the peer address its
    /// transport reported.
    ///
    /// # Errors
    ///
    /// The first rule the datagram breaks.
    pub fn check_emitted(&mut self, datagram: &[u8], peer_ip: IpAddr) -> Result<(), WireViolation> {
        self.emitted += 1;
        let outcome = match parse(datagram) {
            None => Err(fault(
                rule::HEADER,
                format!("{} bytes is shorter than the SRT header", datagram.len()),
            )),
            Some(View::Data(data)) => self.check_data(&data),
            Some(View::Control(control)) => self.check_control(&control, peer_ip),
        };
        outcome.map_err(|Fault { rule, detail }| WireViolation {
            rule,
            detail,
            role: self.role,
            emission: self.emitted,
            packet: summarize(datagram),
        })
    }

    /// Record a bonded member's send-sequence override (libsrt
    /// `overrideSndSeqNo`, `core.cpp:10630-10661`): the next original DATA
    /// is stamped `next`. The override itself never reaches the wire; the
    /// DATA that follows it is checked.
    pub fn note_send_sequence_override(&mut self, next: u32) {
        self.data.next_original = Some(next & SEQ_MASK);
        self.data.override_pending = true;
    }

    /// Fixture context: the test seeded this endpoint's ACK-number counter,
    /// so the next numbered ACK starts a new progression. Its 31-bit domain
    /// is still checked.
    pub fn note_seeded_ack_number(&mut self) {
        self.last_ack_number = None;
    }

    /// Final check when the endpoint's connection is dropped: every
    /// sequence range original DATA skipped must be covered by a DROPREQ it
    /// sent or still had queued (`queued_drops`, inclusive ranges).
    ///
    /// # Errors
    ///
    /// A [`rule::DATA_SEQUENCE`] violation naming the unannounced range.
    pub fn finish(&self, queued_drops: &[(u32, u32)]) -> Result<(), WireViolation> {
        let drops: Vec<(u32, u32)> = self
            .data
            .drops
            .iter()
            .chain(queued_drops)
            .copied()
            .collect();
        let Some(&(from, to)) = self
            .data
            .skipped
            .iter()
            .find(|&&(from, to)| !covered(&drops, from, to))
        else {
            return Ok(());
        };
        Err(WireViolation {
            rule: rule::DATA_SEQUENCE,
            detail: format!(
                "original DATA skipped {from}..{to} (exclusive) and no DROPREQ, sent or \
                 queued, announces the drop"
            ),
            role: self.role,
            emission: self.emitted,
            packet: "(checked when the connection was dropped)".to_owned(),
        })
    }

    /// Record one datagram this endpoint received, as peer input.
    pub fn record_received(&mut self, datagram: &[u8]) {
        match parse(datagram) {
            Some(View::Data(data)) => {
                self.peer.newest_data = Some(
                    self.peer
                        .newest_data
                        .map_or(data.seq, |newest| seq_max(newest, data.seq)),
                );
            }
            Some(View::Control(control)) => self.record_control(&control),
            None => {}
        }
    }

    fn record_control(&mut self, control: &ControlView<'_>) {
        match control.kind {
            CT_HANDSHAKE => self.record_handshake(control.cif),
            CT_ACK if control.cif.len() >= 16 => {
                self.peer.ack_numbers.insert(control.info);
            }
            CT_DROPREQ if control.cif.len() == 8 => {
                let last = be_word(control.cif, 4) & SEQ_MASK;
                self.peer.newest_drop = Some(
                    self.peer
                        .newest_drop
                        .map_or(last, |newest| seq_max(newest, last)),
                );
            }
            _ => {}
        }
    }

    fn record_handshake(&mut self, cif: &[u8]) {
        let Ok(hs) = parse_handshake(cif) else {
            return;
        };
        match hs.kind {
            HS_INDUCTION => self.peer.induction = Some(hs),
            HS_CONCLUSION => {
                if self.role == ConnectionRole::Caller && self.peer_socket_id.is_none() {
                    self.peer_socket_id = Some(hs.socket_id);
                }
                self.peer.conclusion = Some(hs);
            }
            _ => {}
        }
    }

    fn peer_hs(&self) -> Option<HsBlock> {
        self.peer.conclusion.as_ref().and_then(Handshake::hs_block)
    }

    fn peer_rexmit(&self) -> bool {
        self.peer_hs()
            .is_some_and(|block| block.flags & FLAG_REXMIT != 0)
    }

    fn check_destination(&self, dest: u32) -> Check {
        let Some(peer) = self.peer_socket_id else {
            return Err(fault(
                rule::DESTINATION_SOCKET_ID,
                "sent before any peer socket ID was negotiated".to_owned(),
            ));
        };
        ensure!(
            dest == peer,
            rule::DESTINATION_SOCKET_ID,
            "addressed to {dest:#x}, but the negotiated peer socket ID is {peer:#x}"
        );
        Ok(())
    }

    fn check_after_epoch(&self, timestamp: u32) -> Check {
        if let Some(floor) = self.own.epoch_floor {
            ensure!(
                timestamp >= floor,
                rule::TIMESTAMP_EPOCH,
                "timestamp {timestamp} predates this side's CONCLUSION-phase handshake at {floor}: \
                 not the session epoch"
            );
        }
        Ok(())
    }

    // ---- DATA ----

    fn check_data(&mut self, data: &DataView) -> Check {
        self.check_destination(data.dest)?;
        ensure!(
            data.msgno != 0,
            rule::MESSAGE_NUMBER,
            "message number 0 is reserved; libsrt's numbers roll from 1"
        );
        ensure!(
            data.key != 0b11,
            rule::KEY_FLAGS,
            "KK=11 is not a key selector"
        );
        ensure!(
            data.key == 0 || self.own.key_material,
            rule::KEY_FLAGS,
            "KK={:02b} but this side's handshake carried no key material",
            data.key
        );
        ensure!(
            !data.rexmit || self.peer_rexmit(),
            rule::R_BIT,
            "R=1 although the peer did not advertise REXMITFLG; libsrt then reads the bit as \
             part of a 27-bit message number"
        );
        match self.data.originals.get(&data.seq).copied() {
            Some(original) => self.check_retransmission(data, original),
            None => self.check_original(data),
        }
    }

    fn check_retransmission(&self, data: &DataView, original: Original) -> Check {
        ensure!(
            data.rexmit == self.peer_rexmit(),
            rule::R_BIT,
            "retransmission of {} has R={} with REXMITFLG {}",
            data.seq,
            u8::from(data.rexmit),
            if self.peer_rexmit() {
                "negotiated"
            } else {
                "not negotiated"
            }
        );
        ensure!(
            data.boundary == original.boundary
                && data.in_order == original.in_order
                && data.msgno == original.msgno,
            rule::RETRANSMISSION_IDENTITY,
            "retransmission of {} changed PP/O/msgno from {:02b}/{}/{}",
            data.seq,
            original.boundary,
            u8::from(original.in_order),
            original.msgno
        );
        Ok(())
    }

    fn check_original(&mut self, data: &DataView) -> Check {
        ensure!(
            !data.rexmit,
            rule::R_BIT,
            "R=1 on the first transmission of {}",
            data.seq
        );
        self.check_original_sequence(data.seq)?;
        self.check_after_epoch(data.timestamp)?;
        if let Some(last) = self.data.last_origin {
            ensure!(
                data.timestamp >= last,
                rule::TIMESTAMP_EPOCH,
                "origin time {} is before the previous original's {last}",
                data.timestamp
            );
        }
        self.check_fragment(data)?;
        self.check_live_profile(data)?;
        self.data.last_origin = Some(data.timestamp);
        self.data.next_original = Some(seq_next(data.seq));
        self.data.last_original = Some(data.seq);
        self.data.originals.insert(
            data.seq,
            Original {
                boundary: data.boundary,
                in_order: data.in_order,
                msgno: data.msgno,
            },
        );
        Ok(())
    }

    fn check_original_sequence(&mut self, seq: u32) -> Check {
        let Some(isn) = self.own.session_isn else {
            return Err(fault(
                rule::DATA_SEQUENCE,
                "DATA before this side's CONCLUSION-phase handshake fixed the ISN".to_owned(),
            ));
        };
        if self.data.override_pending {
            let base = self
                .data
                .last_original
                .unwrap_or(isn.wrapping_sub(1) & SEQ_MASK);
            ensure!(
                seq_le(base, seq),
                rule::DATA_SEQUENCE,
                "first DATA after a bonded send-sequence override is {seq}, behind {base}: \
                 libsrt refuses an override that goes back (`core.cpp:10655-10661`)"
            );
            self.data.override_pending = false;
        }
        let expected = self.data.next_original.unwrap_or(isn);
        if seq == expected {
            return Ok(());
        }
        let what = if self.data.next_original.is_some() {
            "the next sequence"
        } else {
            "the session ISN"
        };
        ensure!(
            seq_le(expected, seq),
            rule::DATA_SEQUENCE,
            "first transmission of {seq} goes back before {what}, {expected}"
        );
        if !covered(&self.data.drops, expected, seq) {
            self.data.skipped.push((expected, seq));
        }
        Ok(())
    }

    fn check_fragment(&mut self, data: &DataView) -> Check {
        match (data.boundary, self.data.open_message) {
            (PB_SOLO | PB_FIRST, Some(open)) => Err(fault(
                rule::FRAGMENT_SEQUENCE,
                format!("message {} ended without its LAST packet", open.msgno),
            )),
            (PB_SOLO | PB_FIRST, None) => self.start_message(data),
            (PB_MIDDLE | PB_LAST, None) => Err(fault(
                rule::FRAGMENT_SEQUENCE,
                format!("PP={:02b} with no FIRST packet before it", data.boundary),
            )),
            (PB_MIDDLE | PB_LAST, Some(open)) => self.continue_message(data, open),
            (boundary, _) => unreachable!("PP is two bits, got {boundary:#b}"),
        }
    }

    fn start_message(&mut self, data: &DataView) -> Check {
        ensure!(
            self.data.last_message != Some(data.msgno),
            rule::FRAGMENT_SEQUENCE,
            "message number {} reused by consecutive messages",
            data.msgno
        );
        self.data.last_message = Some(data.msgno);
        self.data.open_message = (data.boundary == PB_FIRST).then_some(OpenMessage {
            msgno: data.msgno,
            in_order: data.in_order,
            timestamp: data.timestamp,
            next_seq: seq_next(data.seq),
        });
        Ok(())
    }

    fn continue_message(&mut self, data: &DataView, open: OpenMessage) -> Check {
        ensure!(
            data.msgno == open.msgno && data.seq == open.next_seq,
            rule::FRAGMENT_SEQUENCE,
            "fragment {}/msgno {} does not continue message {} at {}",
            data.seq,
            data.msgno,
            open.msgno,
            open.next_seq
        );
        ensure!(
            data.in_order == open.in_order && data.timestamp == open.timestamp,
            rule::FRAGMENT_SEQUENCE,
            "fragment {} changed the message's O/origin time from {}/{}",
            data.seq,
            u8::from(open.in_order),
            open.timestamp
        );
        self.data.open_message = (data.boundary == PB_MIDDLE).then_some(OpenMessage {
            next_seq: seq_next(data.seq),
            ..open
        });
        Ok(())
    }

    fn check_live_profile(&self, data: &DataView) -> Check {
        let live = self
            .own
            .hs_flags
            .is_some_and(|flags| flags & FLAG_TSBPDSND != 0)
            && self
                .peer_hs()
                .is_some_and(|block| block.flags & FLAG_TSBPDRCV != 0);
        ensure!(
            !self.live_single_packet_messages || !live || data.boundary == PB_SOLO,
            rule::LIVE_SINGLE_PACKET_MESSAGES,
            "PP={:02b}: a live (TSBPD) message spans more than one packet",
            data.boundary
        );
        Ok(())
    }

    // ---- control ----

    fn check_control(&mut self, control: &ControlView<'_>, peer_ip: IpAddr) -> Check {
        check_control_header(control)?;
        if control.kind == CT_HANDSHAKE {
            return self.check_handshake(control, peer_ip);
        }
        self.check_destination(control.dest)?;
        self.check_control_time(control.timestamp)?;
        match control.kind {
            CT_KEEPALIVE | CT_SHUTDOWN => check_padding(control),
            CT_ACK => self.check_ack(control),
            CT_NAK => self.check_nak(control),
            CT_ACKACK => self.check_ackack(control),
            CT_DROPREQ => self.check_dropreq(control),
            CT_EXTENDED => check_km_control(control),
            kind => Err(fault(
                rule::CONTROL_HEADER,
                format!("srt-rs has no control type {kind:#06x} to send"),
            )),
        }
    }

    fn check_control_time(&mut self, timestamp: u32) -> Check {
        self.check_after_epoch(timestamp)?;
        if let Some(last) = self.last_control_time {
            ensure!(
                timestamp >= last,
                rule::TIMESTAMP_EPOCH,
                "control timestamp {timestamp} is before the previous control's {last}"
            );
        }
        self.last_control_time = Some(timestamp);
        Ok(())
    }

    fn check_ack(&mut self, control: &ControlView<'_>) -> Check {
        let len = control.cif.len();
        ensure!(
            ACK_SIZES.contains(&len),
            rule::ACK_SHAPE,
            "{len}-byte ACK CIF; libsrt sends 4, 16, 24, 28 or 32"
        );
        self.check_ack_position(be_word(control.cif, 0))?;
        if len == 4 {
            ensure!(
                control.info == 0,
                rule::ACK_ID,
                "Lite ACK carries ACK number {:#x}; libsrt sends none",
                control.info
            );
            return Ok(());
        }
        ensure!(
            control.info & !SEQ_MASK == 0,
            rule::ACK_ID,
            "ACK number {:#x} is outside libsrt's 31-bit domain",
            control.info
        );
        if let Some(last) = self.last_ack_number {
            ensure!(
                control.info == seq_next(last),
                rule::ACK_ID,
                "ACK number {:#x} does not follow {last:#x}",
                control.info
            );
        }
        self.last_ack_number = Some(control.info);
        Ok(())
    }

    fn check_ack_position(&self, acked: u32) -> Check {
        ensure!(
            acked & !SEQ_MASK == 0,
            rule::ACK_POSITION,
            "acknowledged sequence {acked:#x} has the high bit set"
        );
        let Some(isn) = self.own.session_isn else {
            return Err(fault(
                rule::ACK_POSITION,
                "ACK before the session ISN was negotiated".to_owned(),
            ));
        };
        let received = match (self.peer.newest_data, self.peer.newest_drop) {
            (Some(data), Some(drop)) => Some(seq_max(data, drop)),
            (data, drop) => data.or(drop),
        };
        let frontier = received.map_or(isn, seq_next);
        ensure!(
            seq_le(acked, frontier),
            rule::ACK_POSITION,
            "acknowledges up to {acked}, beyond {frontier}: nothing past it was received or dropped"
        );
        Ok(())
    }

    fn check_nak(&self, control: &ControlView<'_>) -> Check {
        let ranges = nak_ranges(control.cif).map_err(|detail| fault(rule::NAK_ENCODING, detail))?;
        let Some(newest) = self.peer.newest_data else {
            return Err(fault(
                rule::NAK_FRONTIER,
                "NAK before any DATA was received".to_owned(),
            ));
        };
        for (first, last) in ranges {
            ensure!(
                seq_le(last, newest),
                rule::NAK_FRONTIER,
                "reports {first}..={last} lost, beyond the newest DATA received, {newest}"
            );
        }
        Ok(())
    }

    fn check_ackack(&self, control: &ControlView<'_>) -> Check {
        check_padding(control)?;
        ensure!(
            self.peer.ack_numbers.contains(&control.info),
            rule::ACKACK_ECHO,
            "echoes ACK number {:#x}, which this side never received",
            control.info
        );
        Ok(())
    }

    fn check_dropreq(&mut self, control: &ControlView<'_>) -> Check {
        ensure!(
            control.cif.len() == 8,
            rule::DROPREQ_SHAPE,
            "{}-byte DROPREQ CIF; libsrt's is 8",
            control.cif.len()
        );
        let first = be_word(control.cif, 0);
        let last = be_word(control.cif, 4);
        ensure!(
            (first | last) & !SEQ_MASK == 0 && seq_le(first, last),
            rule::DROPREQ_SHAPE,
            "range {first:#x}..={last:#x} is flagged or reversed"
        );
        self.data.drops.push((first, last));
        let drops = &self.data.drops;
        self.data
            .skipped
            .retain(|&(from, to)| !covered(drops, from, to));
        Ok(())
    }

    // ---- handshake ----

    fn check_handshake(&mut self, control: &ControlView<'_>, peer_ip: IpAddr) -> Check {
        let hs = parse_handshake(control.cif)
            .map_err(|detail| fault(rule::EXTENSION_FRAMING, detail))?;
        match (self.role, hs.kind) {
            (ConnectionRole::Caller, HS_INDUCTION) => {
                self.check_caller_induction(control, &hs, peer_ip)
            }
            (ConnectionRole::Caller, HS_CONCLUSION) => {
                self.check_caller_conclusion(control, &hs, peer_ip)
            }
            (ConnectionRole::Listener, HS_INDUCTION) => self.check_induction_response(control, &hs),
            (ConnectionRole::Listener, HS_CONCLUSION) => {
                self.check_conclusion_response(control, &hs, peer_ip)
            }
            (_, kind) if is_rejection(kind) => self.check_rejection(control),
            (role, kind) => Err(fault(
                rule::HANDSHAKE_TYPE,
                format!(
                    "a {role:?} sends no {} handshake",
                    handshake_kind_name(kind)
                ),
            )),
        }
    }

    fn check_caller_induction(
        &mut self,
        control: &ControlView<'_>,
        hs: &Handshake,
        peer_ip: IpAddr,
    ) -> Check {
        let combined_type = (u32::from(hs.encryption) << 16) | u32::from(hs.extension);
        ensure!(
            hs.version == 4 && combined_type == UDT_DGRAM,
            rule::CALLER_INDUCTION,
            "version {} type {combined_type:#x}; an HSv5 caller induces with version 4, type 2",
            hs.version
        );
        ensure!(
            hs.cookie == 0 && control.dest == 0 && hs.blocks.is_empty(),
            rule::CALLER_INDUCTION,
            "cookie {:#x}, destination {:#x}, {} extensions; all must be zero",
            hs.cookie,
            control.dest,
            hs.blocks.len()
        );
        ensure!(
            hs.socket_id != 0 && hs.isn & !SEQ_MASK == 0,
            rule::CALLER_INDUCTION,
            "socket ID {:#x} / ISN {:#x}: the ID must be nonzero, the ISN 31-bit",
            hs.socket_id,
            hs.isn
        );
        if let Some((isn, socket)) = self.own.induction {
            ensure!(
                (hs.isn, hs.socket_id) == (isn, socket),
                rule::CALLER_INDUCTION,
                "retry changed ISN/socket from {isn}/{socket:#x}"
            );
        }
        check_peer_ip(hs, peer_ip)?;
        self.own.induction = Some((hs.isn, hs.socket_id));
        Ok(())
    }

    fn check_caller_conclusion(
        &mut self,
        control: &ControlView<'_>,
        hs: &Handshake,
        peer_ip: IpAddr,
    ) -> Check {
        let Some((isn, socket)) = self.own.induction else {
            return Err(fault(
                rule::CALLER_CONCLUSION,
                "CONCLUSION before any INDUCTION".to_owned(),
            ));
        };
        let Some(response) = self.peer.induction.as_ref() else {
            return Err(fault(
                rule::CALLER_CONCLUSION,
                "CONCLUSION before any INDUCTION response".to_owned(),
            ));
        };
        ensure!(
            hs.version == 5 && hs.isn == isn && hs.socket_id == socket,
            rule::CALLER_CONCLUSION,
            "version {}, ISN {}, socket {:#x}; the INDUCTION used ISN {isn}, socket {socket:#x}",
            hs.version,
            hs.isn,
            hs.socket_id
        );
        ensure!(
            hs.cookie == response.cookie,
            rule::CALLER_CONCLUSION,
            "cookie {:#x} does not echo the response's {:#x}",
            hs.cookie,
            response.cookie
        );
        ensure!(
            control.dest == 0 || control.dest == response.socket_id,
            rule::CALLER_CONCLUSION,
            "addressed to {:#x}: neither 0 nor the responder {:#x}",
            control.dest,
            response.socket_id
        );
        check_encryption_field(hs)?;
        self.check_extensions(hs)?;
        check_peer_ip(hs, peer_ip)?;
        self.note_conclusion(hs, control.timestamp);
        Ok(())
    }

    fn check_induction_response(&self, control: &ControlView<'_>, hs: &Handshake) -> Check {
        let Some(request) = self.peer.induction.as_ref() else {
            return Err(fault(
                rule::INDUCTION_RESPONSE,
                "INDUCTION response without a received INDUCTION".to_owned(),
            ));
        };
        ensure!(
            hs.version == 5 && hs.extension == SRT_MAGIC_CODE,
            rule::INDUCTION_RESPONSE,
            "version {} extension field {:#06x}; libsrt answers version 5 with SRT_MAGIC_CODE",
            hs.version,
            hs.extension
        );
        ensure!(
            hs.isn == request.isn,
            rule::INDUCTION_RESPONSE,
            "ISN {} does not echo the request's {}",
            hs.isn,
            request.isn
        );
        ensure!(
            control.dest == request.socket_id && hs.blocks.is_empty(),
            rule::INDUCTION_RESPONSE,
            "addressed to {:#x} (caller {:#x}) with {} extensions",
            control.dest,
            request.socket_id,
            hs.blocks.len()
        );
        check_encryption_field(hs)
    }

    fn check_conclusion_response(
        &mut self,
        control: &ControlView<'_>,
        hs: &Handshake,
        peer_ip: IpAddr,
    ) -> Check {
        let Some(request) = self.peer.conclusion.as_ref() else {
            return Err(fault(
                rule::CONCLUSION_RESPONSE,
                "CONCLUSION response without a received CONCLUSION".to_owned(),
            ));
        };
        ensure!(
            hs.version == 5 && hs.isn == request.isn && hs.socket_id != 0,
            rule::CONCLUSION_RESPONSE,
            "version {}, ISN {}, socket {:#x}; the caller's CONCLUSION had ISN {}",
            hs.version,
            hs.isn,
            hs.socket_id,
            request.isn
        );
        ensure!(
            control.dest == request.socket_id,
            rule::CONCLUSION_RESPONSE,
            "addressed to {:#x}, not the caller's socket {:#x}",
            control.dest,
            request.socket_id
        );
        check_encryption_field(hs)?;
        self.check_extensions(hs)?;
        check_peer_ip(hs, peer_ip)?;
        if self.peer_socket_id.is_none() {
            self.peer_socket_id = Some(control.dest);
        }
        self.note_conclusion(hs, control.timestamp);
        Ok(())
    }

    fn check_rejection(&self, control: &ControlView<'_>) -> Check {
        let requester = self
            .peer
            .conclusion
            .as_ref()
            .or(self.peer.induction.as_ref())
            .map(|hs| hs.socket_id);
        if self.role == ConnectionRole::Listener
            && let Some(requester) = requester
        {
            ensure!(
                control.dest == requester,
                rule::CONCLUSION_RESPONSE,
                "rejection addressed to {:#x}, not the caller's socket {requester:#x}",
                control.dest
            );
        }
        Ok(())
    }

    fn note_conclusion(&mut self, hs: &Handshake, timestamp: u32) {
        self.own.session_isn.get_or_insert(hs.isn);
        self.own.epoch_floor.get_or_insert(timestamp);
        self.own.key_material |= hs.carries_key_material();
        self.own.hs_flags = hs.hs_block().map(|block| block.flags);
    }

    fn check_extensions(&self, hs: &Handshake) -> Check {
        let responder = self.role == ConnectionRole::Listener;
        check_block_placement(hs, responder)?;
        check_categories(hs)?;
        let block = check_hs_block(hs, responder)?;
        if responder {
            let request = self.peer.conclusion.as_ref();
            check_hs_response(block, request.and_then(Handshake::hs_block))?;
            ensure!(
                !hs.has(EXT_GROUP) || request.is_some_and(|request| request.has(EXT_GROUP)),
                rule::GROUP_VALIDITY,
                "GROUP in a response to a CONCLUSION without one"
            );
        }
        check_km_blocks(hs)?;
        check_config_blocks(hs)
    }
}

fn check_control_header(control: &ControlView<'_>) -> Check {
    if control.kind == CT_EXTENDED {
        return Ok(());
    }
    ensure!(
        control.subtype == 0,
        rule::CONTROL_HEADER,
        "subtype {} on a {} packet; only SRT extended commands use it",
        control.subtype,
        control_name(control.kind)
    );
    let argument_free = matches!(
        control.kind,
        CT_HANDSHAKE | CT_KEEPALIVE | CT_NAK | CT_SHUTDOWN
    );
    ensure!(
        !argument_free || control.info == 0,
        rule::CONTROL_HEADER,
        "type-specific word {:#x} on a {} packet; libsrt passes none",
        control.info,
        control_name(control.kind)
    );
    Ok(())
}

fn check_padding(control: &ControlView<'_>) -> Check {
    ensure!(
        control.cif.is_empty() || control.cif == [0; 4],
        rule::CONTROL_PADDING,
        "{} carries {:02x?}; libsrt sends at most four zero bytes",
        control_name(control.kind),
        control.cif
    );
    Ok(())
}

fn check_km_control(control: &ControlView<'_>) -> Check {
    ensure!(
        matches!(control.subtype, EXT_KMREQ | EXT_KMRSP),
        rule::KM_CONTROL,
        "extended command {} is not KMREQ (3) or KMRSP (4)",
        control.subtype
    );
    ensure!(
        !control.cif.is_empty() && control.cif.len().is_multiple_of(4),
        rule::KM_CONTROL,
        "{}-byte key-material body is not whole words",
        control.cif.len()
    );
    if control.subtype == EXT_KMRSP && control.cif.len() == 4 {
        check_km_state(control.cif)?;
    }
    Ok(())
}

fn check_km_state(body: &[u8]) -> Check {
    let state = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    ensure!(
        state <= MAX_KM_STATE,
        rule::KM_STATE_WORD,
        "KMRSP state bytes {body:02x?} are not a little-endian SRT_KM_STATE \
         (big-endian would read {})",
        u32::from_be_bytes([body[0], body[1], body[2], body[3]])
    );
    Ok(())
}

/// Parse NAK loss words into inclusive ranges.
fn nak_ranges(cif: &[u8]) -> Result<Vec<(u32, u32)>, String> {
    if cif.is_empty() || !cif.len().is_multiple_of(4) {
        return Err(format!("{}-byte loss list is not whole words", cif.len()));
    }
    let mut words = cif.chunks_exact(4).map(|word| be_word(word, 0));
    let mut ranges = Vec::new();
    while let Some(word) = words.next() {
        if word & !SEQ_MASK == 0 {
            ranges.push((word, word));
            continue;
        }
        let first = word & SEQ_MASK;
        let Some(last) = words.next() else {
            return Err(format!("range start {first} has no end word"));
        };
        if last & !SEQ_MASK != 0 || !seq_le(first, last) {
            return Err(format!("range {first}..={last:#x} is flagged or reversed"));
        }
        ranges.push((first, last));
    }
    Ok(ranges)
}

fn check_encryption_field(hs: &Handshake) -> Check {
    ensure!(
        matches!(hs.encryption, 0 | 2 | 3 | 4),
        rule::ENCRYPTION_FIELD,
        "encryption field {} is not 0 or PBKEYLEN 2/3/4",
        hs.encryption
    );
    Ok(())
}

fn check_peer_ip(hs: &Handshake, peer_ip: IpAddr) -> Check {
    ensure!(
        !peer_ip.is_unspecified(),
        rule::PEER_IP,
        "the transport reported no peer address, but libsrt always fills this field; the \
         fixture must call set_peer_address"
    );
    let expected = libsrt_peer_ip(peer_ip);
    ensure!(
        hs.peer_ip == expected,
        rule::PEER_IP,
        "field {:02x?} is not libsrt's word-swapped layout of {peer_ip}, {expected:02x?}",
        hs.peer_ip
    );
    Ok(())
}

/// Bit for each negotiated quantity; a request and its response share one.
fn quantity_bit(cmd: u16) -> Option<u8> {
    match cmd {
        EXT_HSREQ | EXT_HSRSP => Some(1 << 0),
        EXT_KMREQ | EXT_KMRSP => Some(1 << 1),
        EXT_SID => Some(1 << 2),
        EXT_CONGESTION => Some(1 << 3),
        EXT_FILTER => Some(1 << 4),
        EXT_GROUP => Some(1 << 5),
        _ => None,
    }
}

fn check_block_placement(hs: &Handshake, responder: bool) -> Check {
    let mut seen = 0u8;
    for block in &hs.blocks {
        let Some(bit) = quantity_bit(block.cmd) else {
            return Err(fault(
                rule::EXTENSION_FRAMING,
                format!("unknown extension type {}", block.cmd),
            ));
        };
        ensure!(
            seen & bit == 0,
            rule::EXTENSION_FRAMING,
            "extension {} repeats a negotiated quantity",
            block.cmd
        );
        seen |= bit;
        let other_role = if responder {
            matches!(block.cmd, EXT_HSREQ | EXT_KMREQ | EXT_SID)
        } else {
            matches!(block.cmd, EXT_HSRSP | EXT_KMRSP)
        };
        ensure!(
            !other_role,
            rule::EXTENSION_FRAMING,
            "extension {} is sent by the other role",
            block.cmd
        );
    }
    Ok(())
}

fn category_of(cmd: u16) -> u16 {
    match cmd {
        EXT_HSREQ | EXT_HSRSP => CATEGORY_HSREQ,
        EXT_KMREQ | EXT_KMRSP => CATEGORY_KMREQ,
        _ => CATEGORY_CONFIG,
    }
}

fn check_categories(hs: &Handshake) -> Check {
    let present = hs
        .blocks
        .iter()
        .fold(0u16, |bits, block| bits | category_of(block.cmd));
    ensure!(
        hs.extension == present,
        rule::EXTENSION_CATEGORIES,
        "extension field {:#06x} but the blocks present need exactly {present:#06x}",
        hs.extension
    );
    Ok(())
}

fn check_hs_block(hs: &Handshake, responder: bool) -> Result<HsBlock, Fault> {
    let expected = if responder { EXT_HSRSP } else { EXT_HSREQ };
    let Some(block) = hs.hs_block().filter(|block| block.cmd == expected) else {
        return Err(fault(
            rule::HS_BLOCK,
            format!("no 12-byte extension {expected} (HSREQ=1, HSRSP=2) for this role"),
        ));
    };
    ensure!(
        block.version >= MIN_SRT_VERSION,
        rule::HS_BLOCK,
        "SRT version {:#08x} is below 1.3.0, the HSv5 minimum",
        block.version
    );
    ensure!(
        responder || block.flags & FLAG_REXMIT != 0,
        rule::HS_BLOCK,
        "HSREQ flags {:#x} lack REXMITFLG, which libsrt always offers",
        block.flags
    );
    Ok(block)
}

fn check_hs_response(response: HsBlock, request: Option<HsBlock>) -> Check {
    let Some(request) = request else {
        return Err(fault(
            rule::HS_BLOCK,
            "HSRSP without a received HSREQ".to_owned(),
        ));
    };
    let mismatch = response.flags ^ request.flags;
    ensure!(
        mismatch & FLAG_REXMIT == 0,
        rule::REXMIT_NEGOTIATION,
        "HSRSP flags {:#x} vs HSREQ {:#x}: REXMITFLG must be answered as offered",
        response.flags,
        request.flags
    );
    ensure!(
        mismatch & FLAG_STREAM == 0,
        rule::STREAM_FLAG,
        "HSRSP flags {:#x} vs HSREQ {:#x}: STREAM differs, which libsrt refuses",
        response.flags,
        request.flags
    );
    check_directional_latency(response, request)
}

fn check_directional_latency(response: HsBlock, request: HsBlock) -> Check {
    if request.flags & FLAG_TSBPDSND != 0 && response.flags & FLAG_TSBPDRCV != 0 {
        ensure!(
            response.rcv >= request.snd,
            rule::DIRECTIONAL_LATENCY,
            "HSRSP RCV {} ms is below the HSREQ SND proposal {} ms",
            response.rcv,
            request.snd
        );
    }
    if request.flags & FLAG_TSBPDRCV != 0 {
        ensure!(
            response.flags & FLAG_TSBPDSND != 0 && response.snd >= request.rcv,
            rule::DIRECTIONAL_LATENCY,
            "HSRSP SND {} ms (flags {:#x}) does not cover the HSREQ RCV {} ms",
            response.snd,
            response.flags,
            request.rcv
        );
    }
    Ok(())
}

fn check_km_blocks(hs: &Handshake) -> Check {
    if let Some(block) = hs.block(EXT_KMRSP)
        && block.body.len() == 4
    {
        check_km_state(&block.body)?;
    }
    Ok(())
}

/// Length of a word-padded string block without its trailing NUL padding.
fn string_len(body: &[u8]) -> usize {
    body.len()
        - body
            .chunks_exact(4)
            .next_back()
            .map_or(0, |word| word.iter().filter(|&&byte| byte == 0).count())
}

fn check_config_blocks(hs: &Handshake) -> Check {
    if let Some(block) = hs.block(EXT_SID) {
        ensure!(
            (1..=MAX_SID_BYTES).contains(&block.body.len()) && string_len(&block.body) > 0,
            rule::CONFIG_BOUNDS,
            "{}-byte SID block; libsrt accepts 1-{MAX_SID_BYTES}",
            block.body.len()
        );
    }
    if let Some(block) = hs.block(EXT_CONGESTION) {
        ensure!(
            (1..=MAX_CONGESTION_BYTES).contains(&block.body.len()) && string_len(&block.body) > 0,
            rule::CONFIG_BOUNDS,
            "{}-byte congestion block; libsrt accepts 1-{MAX_CONGESTION_BYTES}",
            block.body.len()
        );
    }
    match hs.block(EXT_GROUP) {
        Some(block) => check_group(&block.body),
        None => Ok(()),
    }
}

fn check_group(body: &[u8]) -> Check {
    ensure!(
        body.len() >= 8,
        rule::GROUP_VALIDITY,
        "{}-byte GROUP block; libsrt needs two words",
        body.len()
    );
    let group_id = be_word(body, 0);
    let group_type = be_word(body, 4) >> 24;
    ensure!(
        group_id & GROUP_ID_MASK != 0 && group_type < GROUP_TYPE_END,
        rule::GROUP_VALIDITY,
        "group ID {group_id:#x} / type {group_type}: libsrt needs SRTGROUP_MASK and a type \
         below {GROUP_TYPE_END}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::HandshakePacket;
    use crate::{ConnectionOptions, ConnectionOutput, ConnectionState, Timestamp};

    const SOLO: u32 = 0b11 << 30;
    const FIRST: u32 = 0b10 << 30;
    const REXMIT: u32 = 1 << 26;
    const KK_BOTH: u32 = 0b11 << 27;
    const LISTENER_SOCKET: u32 = 2;

    fn drain(conn: &mut SrtConnection) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| conn.poll_output().unwrap())
            .filter_map(|output| match output {
                ConnectionOutput::SendPacket(wire) => Some(wire),
                _ => None,
            })
            .collect()
    }

    /// A connected default pair, both ends checked from the first datagram.
    fn checked_pair() -> (SrtConnection, SrtConnection) {
        let mut caller = SrtConnection::new_caller(ConnectionOptions {
            socket_id: 1,
            ..ConnectionOptions::default()
        });
        let mut listener = SrtConnection::new_listener(ConnectionOptions {
            socket_id: LISTENER_SOCKET,
            syn_cookie: Some(7),
            ..ConnectionOptions::default()
        });
        check_pair(&mut caller, &mut listener);
        let now = Timestamp::default();
        caller.connect(now).unwrap();
        for _ in 0..3 {
            for wire in drain(&mut caller) {
                listener.feed_recv_buf(&wire, now).unwrap();
            }
            for wire in drain(&mut listener) {
                caller.feed_recv_buf(&wire, now).unwrap();
            }
        }
        assert_eq!(caller.state(), ConnectionState::Connected);
        assert_eq!(listener.state(), ConnectionState::Connected);
        (caller, listener)
    }

    fn datagram(first: u32, second: u32, dest: u32, body: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        for word in [first, second, 1_000_000, dest] {
            wire.extend_from_slice(&word.to_be_bytes());
        }
        wire.extend_from_slice(body);
        wire
    }

    /// Original-shaped DATA to the caller's peer.
    fn data(seq: u32, flags_and_msgno: u32) -> Vec<u8> {
        datagram(seq, flags_and_msgno, LISTENER_SOCKET, &[0xAB; 4])
    }

    fn control(kind: u16, subtype: u16, info: u32, cif: &[u8]) -> Vec<u8> {
        let first = 0x8000_0000 | (u32::from(kind) << 16) | u32::from(subtype);
        datagram(first, info, LISTENER_SOCKET, cif)
    }

    fn checker(conn: &mut SrtConnection) -> &mut WireChecker {
        conn.wire_checker_mut().expect("checked fixture")
    }

    fn rule_of(checker: &mut WireChecker, datagram: &[u8]) -> Result<(), &'static str> {
        checker
            .check_emitted(datagram, LISTENER_TEST_ADDRESS.ip())
            .map_err(|violation| violation.rule)
    }

    #[test]
    fn checked_pairs_see_every_handshake_emission() {
        let (mut caller, mut listener) = checked_pair();
        assert_eq!(checker(&mut caller).emitted(), 2, "INDUCTION, CONCLUSION");
        assert_eq!(checker(&mut listener).emitted(), 2, "both responses");
    }

    #[test]
    fn data_rules_hold_each_field_to_libsrt() {
        let (mut caller, _listener) = checked_pair();
        let checker = checker(&mut caller);
        assert_eq!(rule_of(checker, &data(0, SOLO)), Err(rule::MESSAGE_NUMBER));
        assert_eq!(
            rule_of(checker, &data(0, SOLO | KK_BOTH | 1)),
            Err(rule::KEY_FLAGS)
        );
        assert_eq!(
            rule_of(checker, &data(0, SOLO | REXMIT | 1)),
            Err(rule::R_BIT)
        );
        let misaddressed = datagram(0, SOLO | 1, 9, &[0; 4]);
        assert_eq!(
            rule_of(checker, &misaddressed),
            Err(rule::DESTINATION_SOCKET_ID)
        );
        assert_eq!(rule_of(checker, &data(0, SOLO | 1)), Ok(()));
        assert_eq!(rule_of(checker, &data(0, SOLO | REXMIT | 1)), Ok(()));
        assert_eq!(
            rule_of(checker, &data(0, SOLO | REXMIT | 2)),
            Err(rule::RETRANSMISSION_IDENTITY)
        );
        assert_eq!(
            rule_of(checker, &data(SEQ_MASK, SOLO | 2)),
            Err(rule::DATA_SEQUENCE)
        );
        assert_eq!(
            rule_of(checker, &data(1, SOLO | 1)),
            Err(rule::FRAGMENT_SEQUENCE)
        );
    }

    #[test]
    fn a_sequence_skip_needs_a_dropreq_sent_or_queued() {
        let (mut caller, _listener) = checked_pair();
        let checker = checker(&mut caller);
        assert_eq!(rule_of(checker, &data(3, SOLO | 1)), Ok(()));
        assert_eq!(
            checker.finish(&[]).map_err(|violation| violation.rule),
            Err(rule::DATA_SEQUENCE)
        );
        assert!(
            checker.finish(&[(0, 2)]).is_ok(),
            "a queued DROPREQ covers it"
        );
        let mut range = Vec::new();
        range.extend_from_slice(&0u32.to_be_bytes());
        range.extend_from_slice(&2u32.to_be_bytes());
        assert_eq!(rule_of(checker, &control(CT_DROPREQ, 0, 0, &range)), Ok(()));
        assert!(checker.finish(&[]).is_ok(), "the sent DROPREQ covers it");
    }

    #[test]
    fn control_rules_hold_each_field_to_libsrt() {
        let (mut caller, _listener) = checked_pair();
        let checker = checker(&mut caller);
        let full_ack = [0u8; 28];
        assert_eq!(
            rule_of(checker, &control(CT_ACK, 0, 0x8000_0000, &full_ack)),
            Err(rule::ACK_ID)
        );
        assert_eq!(
            rule_of(checker, &control(CT_ACK, 0, 0, &[0; 20])),
            Err(rule::ACK_SHAPE)
        );
        assert_eq!(
            rule_of(checker, &control(CT_ACKACK, 0, 77, &[])),
            Err(rule::ACKACK_ECHO)
        );
        assert_eq!(
            rule_of(checker, &control(CT_KEEPALIVE, 0, 0, &[0, 0, 0, 1])),
            Err(rule::CONTROL_PADDING)
        );
        assert_eq!(
            rule_of(checker, &control(CT_SHUTDOWN, 1, 0, &[])),
            Err(rule::CONTROL_HEADER)
        );
        assert_eq!(
            rule_of(checker, &control(CT_EXTENDED, EXT_KMRSP, 0, &[0, 0, 0, 3])),
            Err(rule::KM_STATE_WORD)
        );
        assert_eq!(
            rule_of(checker, &control(CT_EXTENDED, EXT_KMRSP, 0, &[3, 0, 0, 0])),
            Ok(())
        );
        assert_eq!(
            rule_of(checker, &control(CT_NAK, 0, 0, &[0, 0, 0, 5])),
            Err(rule::NAK_FRONTIER)
        );
        let reversed = [0, 0, 0, 9, 0, 0, 0, 1];
        assert_eq!(
            rule_of(checker, &control(CT_DROPREQ, 0, 0, &reversed)),
            Err(rule::DROPREQ_SHAPE)
        );
    }

    fn induction_request(cookie: u32) -> Vec<u8> {
        let mut hs = HandshakePacket::new_induction_request(1);
        hs.syn_cookie = cookie;
        hs.peer_ip = LISTENER_TEST_ADDRESS.ip();
        let mut wire = Vec::new();
        hs.encode(0, 0).encode(&mut wire).unwrap();
        wire
    }

    #[test]
    fn caller_induction_shape_and_peer_ip_layout() {
        let mut checker = WireChecker::new(ConnectionRole::Caller);
        assert_eq!(
            rule_of(&mut checker, &induction_request(5)),
            Err(rule::CALLER_INDUCTION)
        );
        let mut unswapped = induction_request(0);
        let field = HEADER_LEN + 32..HEADER_LEN + 36;
        unswapped[field].copy_from_slice(&[192, 0, 2, 1]);
        assert_eq!(rule_of(&mut checker, &unswapped), Err(rule::PEER_IP));
        assert_eq!(rule_of(&mut checker, &induction_request(0)), Ok(()));
    }

    #[test]
    fn live_fragmentation_is_an_opt_in_profile_rule() {
        let (mut default_caller, _listener) = checked_pair();
        let default = checker(&mut default_caller);
        assert_eq!(
            rule_of(default, &data(0, FIRST | 1)),
            Ok(()),
            "off by default"
        );
        let (mut live_caller, _listener) = checked_pair();
        let live = checker(&mut live_caller);
        live.enable(OptionalRule::LiveSinglePacketMessages);
        assert_eq!(
            rule_of(live, &data(0, FIRST | 1)),
            Err(rule::LIVE_SINGLE_PACKET_MESSAGES)
        );
    }
}
