//! SRT handshake.
//!
//! Implements the Caller-Listener mode handshake.
//!
//! ## Flow
//!
//! ```text
//! Caller                              Listener
//!   |                                    |
//!   |------ INDUCTION (version=4) ------>|
//!   |<----- INDUCTION (cookie) ----------|
//!   |                                    |
//!   |------ CONCLUSION (HS ext) -------->|
//!   |<----- CONCLUSION (HS ext) ---------|
//!   |                                    |
//! ```

use std::net::IpAddr;

use crate::buf::{
    read_bytes, read_u8, read_u16, read_u32, write_bytes, write_u8, write_u16, write_u32,
};
use crate::crypto_impl::{KeyFlag, KeyLength};
use crate::error::Error;
use crate::srt_packet::{ControlPacket, ControlType, MAX_DATAGRAM_SIZE, SRT_HEADER_SIZE};

/// Handshake version.
pub const HS_VERSION_4: u32 = 4;
/// Handshake version.
pub const HS_VERSION_5: u32 = 5;

/// Default MTU size (the value this implementation advertises).
///
/// Consumed as the SRT datagram budget: `SrtConnection` derives
/// `max_payload_size = DEFAULT_MTU - SRT_HEADER_SIZE`, and protocol tests
/// compare emitted packet lengths against it directly. It is therefore NOT
/// an IPv4 packet MTU -- a deployment on a 1500-byte IPv4 path additionally
/// carries IP and UDP headers, which srt-bench's capacity classifier models
/// separately as a deployment envelope rather than as protocol truth.
///
/// The *advertised* direction is safe under either reading: a reference
/// peer that reads this field as an IP MTU (libsrt's `SRTO_MSS` semantics)
/// sizes its payload at `DEFAULT_MTU - 44` = 1456 bytes, and this core
/// accepts datagrams up to `MAX_DATAGRAM_SIZE`, well beyond that. The
/// *received* direction is not symmetric: a peer's advertised MSS bounds
/// what that peer's stack can receive, so `SrtConnection` negotiates its
/// outbound payload against it (`apply_peer_mss`). See
/// [`IP_UDP_HEADER_SIZE_IPV4`] and [`MAX_PEER_MSS`] for the bounds derived
/// from the pinned reference.
pub const DEFAULT_MTU: u32 = 1500;

/// IP + UDP header bytes ahead of an SRT datagram on an IPv4 path.
///
/// The same quantity as libsrt's `CPacket::UDP_HDR_SIZE` (20 + 8) in the
/// pinned reference (`899348d8`, `srtcore/packet.h`). The handshake's MTU
/// field is an *IP-layer* MTU there, so an SRT datagram may only be
/// `mss - IP_UDP_HEADER_SIZE_IPV4` bytes long.
pub const IP_UDP_HEADER_SIZE_IPV4: u32 = 28;

/// IP + UDP header bytes ahead of an SRT datagram on an IPv6 path
/// (libsrt's `CPacket::UDP_HDR_SIZE_IPv6`: 40 + 8).
pub const IP_UDP_HEADER_SIZE_IPV6: u32 = 48;

/// Address family of the UDP path a connection runs on.
///
/// The handshake MSS field is an IP-layer MTU, so turning it into an SRT
/// datagram budget needs the path's IP + UDP header size. The handshake
/// itself does not say which family the path uses (its peer-address field is
/// advisory: this implementation writes the unspecified IPv4 address there,
/// and libsrt's own `MinimumMSS` keys off the socket's `peer.family()`, not
/// that field), so the transport, which knows the socket address, sets it
/// with `SrtConnection::set_ip_family`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IpFamily {
    /// IPv4 path (28 bytes of IP + UDP). The default when unset.
    #[default]
    V4,
    /// IPv6 path (48 bytes of IP + UDP).
    V6,
}

impl IpFamily {
    /// Classify a socket address by the IP header used for its datagrams.
    /// An IPv4-mapped IPv6 address on a dual-stack socket represents an IPv4
    /// peer and therefore uses the IPv4 overhead.
    pub fn of(address: &std::net::SocketAddr) -> Self {
        match address {
            std::net::SocketAddr::V4(_) => Self::V4,
            std::net::SocketAddr::V6(address) if address.ip().to_ipv4_mapped().is_some() => {
                Self::V4
            }
            std::net::SocketAddr::V6(_) => Self::V6,
        }
    }

    /// IP + UDP header bytes ahead of an SRT datagram on this family.
    pub const fn ip_udp_overhead(self) -> u32 {
        match self {
            Self::V4 => IP_UDP_HEADER_SIZE_IPV4,
            Self::V6 => IP_UDP_HEADER_SIZE_IPV6,
        }
    }
}

/// Largest peer MSS this implementation negotiates.
///
/// The number is libsrt's `CPacket::ETH_MAX_MTU_SIZE` (1500, "Ethernet II,
/// RFC 1191"), which the pinned reference's *caller* enforces: it rejects a
/// larger response MSS outright (`CUDT::processConnectResponse`). Its
/// *listener* is more permissive -- `acceptAndRespond` takes
/// `min(local_mss, peer_mss)` -- and `SRTO_MSS` itself can be configured
/// above 1500 (bounded by the UDP buffers), so two libsrt peers configured
/// with a jumbo MSS can interoperate where this implementation refuses.
///
/// Refusing is therefore a deliberate **local policy**, not a claim about the
/// reference: this stack implements neither path-MTU discovery nor jumbo
/// negotiation, so it cannot honour such a session, and it treats a value
/// above the Ethernet MTU as an unusable handshake (`SRT_REJ_ROGUE`, the code
/// the reference's caller uses for the same field) rather than silently
/// clamping it the way a libsrt listener would.
pub const MAX_PEER_MSS: u32 = 1500;

/// `SRT_REJ_ROGUE`: incorrect data in handshake messages.
///
/// libsrt (`srtcore/srt.h`, zero-based `SRT_REJECT_REASON`) uses this for
/// exactly the two MSS violations below -- a peer MSS below the family's
/// minimum and one above [`MAX_PEER_MSS`].
pub const SRT_REJ_ROGUE: i32 = 4;
/// `SRT_REJ_VERSION`: peer does not meet this implementation's minimum SRT
/// version. Zero-based `SRT_REJECT_REASON` value; wire handshakes carry it as
/// `1000 + reason`.
pub const SRT_REJ_VERSION: i32 = 8;

/// `SRT_REJ_FILTER`: incompatible packet filter.
///
/// The reason the reference implementation refuses a filter negotiation it
/// cannot honour (`CUDT::interpretSrtHandshake` rejects an unparsable or
/// conflicting filter configuration with this code). A peer that sends a
/// FILTER extension is negotiating packet-filter behaviour, not merely
/// advertising that it could support one, so a stack without a filter
/// implementation must refuse the session rather than run one whose two
/// peers disagree about whether recovery filtering exists.
pub const SRT_REJ_FILTER: i32 = 14;

/// Default flow window size.
pub const DEFAULT_FLOW_WINDOW: u32 = 8192;

/// Largest flow/receive window supported by the dense receiver loss bitmap.
///
/// This is an srt-rs implementation limit, not an SRT wire-protocol limit.
///
/// This remains well inside the 31-bit sequence half-range and bounds the
/// bitmap allocation after first loss to 8,320 bytes per connection.
pub const MAX_FLOW_WINDOW: u32 = 65_536;

/// Handshake type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HandshakeType {
    /// DONE (0xFFFFFFFD)
    Done = 0xFFFFFFFD,
    /// AGREEMENT (0xFFFFFFFE)
    Agreement = 0xFFFFFFFE,
    /// CONCLUSION (0xFFFFFFFF)
    Conclusion = 0xFFFFFFFF,
    /// WAVEAHAND (0x00000000)
    Waveahand = 0x00000000,
    /// INDUCTION (0x00000001)
    Induction = 0x00000001,
    /// REJECTED -- sentinel only; the actual numeric reject reason (SRT's
    /// `1000 + SRT_REJECT_REASON`-or-custom-code wire scheme, see
    /// `srtcore/handshake.h`'s `URQFailure`/`RejectReasonForURQ` in the
    /// real libsrt source) is carried separately in
    /// `HandshakePacket::reject_reason`, not in this discriminant. Values
    /// `>= URQ_FAILURE_TYPES` (1000) on the wire all decode to this variant.
    Rejected = 0x0000_03E8, // 1000 = URQ_FAILURE_TYPES
}

impl HandshakeType {
    /// Convert from a u32.
    ///
    /// Any value `>= 1000` is treated as `Rejected` (the caller must
    /// separately compute the actual reject reason as `value - 1000`).
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0xFFFFFFFD => Some(Self::Done),
            0xFFFFFFFE => Some(Self::Agreement),
            0xFFFFFFFF => Some(Self::Conclusion),
            0x00000000 => Some(Self::Waveahand),
            0x00000001 => Some(Self::Induction),
            v if v >= 1000 => Some(Self::Rejected),
            _ => None,
        }
    }
}

/// SRT Magic Code (confirms HSv5).
pub const SRT_MAGIC_CODE: u16 = 0x4A17;

/// Handshake extension flags.
pub mod extension_flags {
    /// HSREQ extension.
    pub const HSREQ: u16 = 0x0001;
    /// KMREQ extension.
    pub const KMREQ: u16 = 0x0002;
    /// CONFIG extension.
    pub const CONFIG: u16 = 0x0004;
}

/// Handshake extension type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtensionType {
    /// Handshake extension request.
    HsReq = 1,
    /// Handshake extension response.
    HsRsp = 2,
    /// Key material request.
    KmReq = 3,
    /// Key material response.
    KmRsp = 4,
    /// Stream ID.
    Sid = 5,
    /// Congestion control.
    Congestion = 6,
    /// Packet filter.
    Filter = 7,
    /// Group.
    Group = 8,
}

impl ExtensionType {
    /// Convert from a u16.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::HsReq),
            2 => Some(Self::HsRsp),
            3 => Some(Self::KmReq),
            4 => Some(Self::KmRsp),
            5 => Some(Self::Sid),
            6 => Some(Self::Congestion),
            7 => Some(Self::Filter),
            8 => Some(Self::Group),
            _ => None,
        }
    }

    /// The `extension_field` bit a handshake must set to carry this
    /// extension: HSREQ/HSRSP under HSREQ, KMREQ/KMRSP under KMREQ, and
    /// every configuration extension under CONFIG.
    fn category_flag(self) -> u16 {
        match self {
            Self::HsReq | Self::HsRsp => extension_flags::HSREQ,
            Self::KmReq | Self::KmRsp => extension_flags::KMREQ,
            Self::Sid | Self::Congestion | Self::Filter | Self::Group => extension_flags::CONFIG,
        }
    }

    /// One bit per negotiated quantity (a request and its response share
    /// one): a handshake may carry each quantity at most once.
    fn uniqueness_bit(self) -> u8 {
        match self {
            Self::HsReq | Self::HsRsp => 1 << 0,
            Self::KmReq | Self::KmRsp => 1 << 1,
            Self::Sid => 1 << 2,
            Self::Congestion => 1 << 3,
            Self::Filter => 1 << 4,
            Self::Group => 1 << 5,
        }
    }
}

/// SRT bonding group type carried by the GROUP handshake extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupType {
    /// No group type was selected.
    Undefined,
    /// Broadcast mode duplicates each message across all active links.
    Broadcast,
    /// Backup mode activates one link and fails over to a standby link.
    Backup,
    /// A group mode this implementation does not schedule, preserved so the
    /// admission layer can reject it explicitly rather than losing metadata.
    Unknown(u8),
}

impl GroupType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Undefined,
            1 => Self::Broadcast,
            2 => Self::Backup,
            value => Self::Unknown(value),
        }
    }

    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Undefined => 0,
            Self::Broadcast => 1,
            Self::Backup => 2,
            Self::Unknown(value) => value,
        }
    }
}

/// SRT bonding group metadata from the two-word GROUP extension.
///
/// The wire layout is the same as libsrt's `SrtHSRequest`:
/// `group_id`, followed by `[type:8][flags:8][weight:16]`, in network order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupExtensionData {
    /// Group identifier. Libsrt marks group IDs with [`SRTGROUP_MASK`].
    pub group_id: u32,
    /// Group scheduling/failover mode.
    pub group_type: GroupType,
    /// Group flags, including [`GFLAG_SYNCONMSG`] when requested.
    pub flags: u8,
    /// Per-link weight used by group scheduling/failover.
    pub weight: u16,
}

/// Libsrt's marker bit for group identifiers.
pub const SRTGROUP_MASK: u32 = 1 << 30;

/// Synchronize group data on message boundaries.
pub const GFLAG_SYNCONMSG: u8 = 0x01;

/// SRT flags.
pub mod srt_flags {
    /// TSBPD send enabled.
    pub const TSBPDSND: u32 = 0x00000001;
    /// TSBPD receive enabled.
    pub const TSBPDRCV: u32 = 0x00000002;
    /// Encryption supported.
    pub const CRYPT: u32 = 0x00000004;
    /// Too-late packet drop enabled.
    pub const TLPKTDROP: u32 = 0x00000008;
    /// Periodic NAK enabled.
    pub const PERIODICNAK: u32 = 0x00000010;
    /// Retransmit flag supported.
    pub const REXMITFLG: u32 = 0x00000020;
    /// Stream mode.
    pub const STREAM: u32 = 0x00000040;
    /// Packet filter supported.
    pub const PACKET_FILTER: u32 = 0x00000080;
}

/// Handshake packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePacket {
    /// Handshake version.
    pub version: u32,
    /// Encryption field.
    pub encryption_field: u16,
    /// Extension field.
    pub extension_field: u16,
    /// Initial packet sequence number.
    pub initial_packet_seq: u32,
    /// MTU size.
    pub mtu: u32,
    /// Flow window size.
    pub flow_window: u32,
    /// Handshake type.
    pub handshake_type: HandshakeType,
    /// SRT socket ID.
    pub socket_id: u32,
    /// SYN cookie.
    pub syn_cookie: u32,
    /// Peer IP address.
    pub peer_ip: IpAddr,
    /// Extensions.
    pub extensions: Vec<HandshakeExtension>,
    /// Reject reason (`Some` only when `handshake_type == Rejected`).
    /// Either an actual SRT_REJECT_REASON value (roughly 0-17), or an
    /// application-defined code based on libsrt's
    /// `SRT_REJC_PREDEFINED`(1000)/`SRT_REJC_USERDEFINED`(2000) buckets.
    /// Encoded on the wire as `1000 + reject_reason`.
    pub reject_reason: Option<i32>,
}

impl HandshakePacket {
    /// Create a new INDUCTION request (Caller).
    pub fn new_induction_request(socket_id: u32) -> Self {
        Self {
            version: HS_VERSION_4,
            encryption_field: 0,
            extension_field: 2, // Magic value for HS v5
            initial_packet_seq: 0,
            mtu: DEFAULT_MTU,
            flow_window: DEFAULT_FLOW_WINDOW,
            handshake_type: HandshakeType::Induction,
            socket_id,
            syn_cookie: 0,
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            extensions: Vec::new(),
            reject_reason: None,
        }
    }

    /// Create a new INDUCTION response (Listener).
    pub fn new_induction_response(socket_id: u32, syn_cookie: u32, encryption_field: u16) -> Self {
        Self {
            version: HS_VERSION_5,
            encryption_field,
            extension_field: SRT_MAGIC_CODE, // Confirms HSv5.
            initial_packet_seq: 0,
            mtu: DEFAULT_MTU,
            flow_window: DEFAULT_FLOW_WINDOW,
            handshake_type: HandshakeType::Induction,
            socket_id,
            syn_cookie,
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            extensions: Vec::new(),
            reject_reason: None,
        }
    }

    /// Create a new CONCLUSION request (Caller).
    pub fn new_conclusion_request(
        socket_id: u32,
        syn_cookie: u32,
        initial_packet_seq: u32,
        encryption_field: u16,
        has_encryption: bool,
    ) -> Self {
        let extension_field = if has_encryption {
            extension_flags::HSREQ | extension_flags::KMREQ
        } else {
            extension_flags::HSREQ
        };
        Self {
            version: HS_VERSION_5,
            encryption_field,
            extension_field,
            initial_packet_seq,
            mtu: DEFAULT_MTU,
            flow_window: DEFAULT_FLOW_WINDOW,
            handshake_type: HandshakeType::Conclusion,
            socket_id,
            syn_cookie,
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            extensions: Vec::new(),
            reject_reason: None,
        }
    }

    /// Create a new CONCLUSION response (Listener).
    pub fn new_conclusion_response(
        socket_id: u32,
        syn_cookie: u32,
        initial_packet_seq: u32,
        encryption_field: u16,
        has_encryption: bool,
    ) -> Self {
        let extension_field = if has_encryption {
            extension_flags::HSREQ | extension_flags::KMREQ
        } else {
            extension_flags::HSREQ
        };
        Self {
            version: HS_VERSION_5,
            encryption_field,
            extension_field,
            initial_packet_seq,
            mtu: DEFAULT_MTU,
            flow_window: DEFAULT_FLOW_WINDOW,
            handshake_type: HandshakeType::Conclusion,
            socket_id,
            syn_cookie,
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            extensions: Vec::new(),
            reject_reason: None,
        }
    }

    /// Create a new REJECTION response (Listener).
    ///
    /// `reason` is either an actual `SRT_REJECT_REASON` value (roughly
    /// 0-17), or an application-defined code based on libsrt's
    /// `SRT_REJC_PREDEFINED`(1000)/`SRT_REJC_USERDEFINED`(2000) buckets
    /// (e.g. this repo's own `SRT_REJX_UNAUTHORIZED = 1401`). Encoded on the
    /// wire as `1000 + reason` (the same formula as `srtcore/handshake.h`'s
    /// `URQFailure`).
    pub fn new_rejection(socket_id: u32, syn_cookie: u32, reason: i32) -> Self {
        Self {
            version: HS_VERSION_5,
            encryption_field: 0,
            extension_field: 0,
            initial_packet_seq: 0,
            mtu: DEFAULT_MTU,
            flow_window: DEFAULT_FLOW_WINDOW,
            handshake_type: HandshakeType::Rejected,
            socket_id,
            syn_cookie,
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            extensions: Vec::new(),
            reject_reason: Some(reason),
        }
    }

    /// Largest SRT datagram (header included) this handshake's advertised
    /// MSS can carry on a `family` path.
    pub fn peer_max_datagram_size(&self, family: IpFamily) -> u32 {
        self.mtu.saturating_sub(family.ip_udp_overhead())
    }

    /// Largest DATA payload this handshake's advertised MSS can carry on a
    /// `family` path: libsrt's own derivation, `m_iMaxDataPayloadSize = mss -
    /// (UDP_HDR_SIZE + HDR_SIZE)`.
    pub fn peer_max_payload_size(&self, family: IpFamily) -> u32 {
        self.peer_max_datagram_size(family)
            .saturating_sub(SRT_HEADER_SIZE as u32)
    }

    /// Why this handshake's advertised MSS is unusable on a `family` path
    /// for a connection that needs at least `min_payload` bytes of DATA
    /// payload, or `None` when it is usable.
    ///
    /// The lower bound is derived from the implementation's own needs
    /// (`min_payload`, which the connection computes from its smallest
    /// mandatory control record and, under GCM, the authentication tag); the
    /// upper one is [`MAX_PEER_MSS`], this implementation's local maximum.
    pub fn peer_mss_rejection_reason(&self, family: IpFamily, min_payload: u32) -> Option<String> {
        let min_mss = family
            .ip_udp_overhead()
            .saturating_add(SRT_HEADER_SIZE as u32)
            .saturating_add(min_payload);
        if self.mtu < min_mss {
            return Some(format!(
                "peer MSS {} is below the minimum {min_mss} for a {family:?} path",
                self.mtu
            ));
        }
        if self.mtu > MAX_PEER_MSS {
            return Some(format!(
                "peer MSS {} exceeds the maximum {MAX_PEER_MSS}",
                self.mtu
            ));
        }
        None
    }

    /// Decode from a control packet.
    #[track_caller]
    pub fn decode(packet: &ControlPacket) -> Result<Self, Error> {
        if packet.control_type != ControlType::Handshake {
            return Err(Error::invalid_data("not a handshake packet"));
        }
        if packet.control_info.len() > MAX_DATAGRAM_SIZE.saturating_sub(SRT_HEADER_SIZE) {
            return Err(Error::invalid_data("SRT datagram exceeds maximum size"));
        }

        let mut buf = packet.control_info.as_slice();
        Error::check_buffer_size(48, buf)?; // Minimum size.

        let version = read_u32(&mut buf)?;
        let encryption_field = read_u16(&mut buf)?;
        let extension_field = read_u16(&mut buf)?;
        let initial_packet_seq = read_u32(&mut buf)?;
        if initial_packet_seq & 0x8000_0000 != 0 {
            return Err(Error::invalid_data(
                "handshake initial sequence must not have its high bit set",
            ));
        }
        let mtu = read_u32(&mut buf)?;
        let flow_window = read_u32(&mut buf)?;
        let handshake_type_raw = read_u32(&mut buf)?;
        let handshake_type = HandshakeType::from_u32(handshake_type_raw).ok_or_else(|| {
            Error::invalid_data(format!("unknown handshake type: {handshake_type_raw:#x}"))
        })?;
        // local patch (crates/srt-protocol/VENDOR.md): a real
        // libsrt rejection response encodes `1000 + reason` in this exact
        // field (`srtcore/handshake.h`'s `URQFailure`/`RejectReasonForURQ`).
        // HandshakeType::from_u32 now maps any `>= 1000` value to the
        // `Rejected` sentinel instead of erroring; recover the actual
        // numeric reason here so callers can distinguish rejection causes
        // (e.g. this repo's SRT_REJX_UNAUTHORIZED=1401) instead of just
        // seeing a generic decode failure.
        //
        // local patch round 2 (found by `cargo fuzz run
        // fuzz_handshake_decode`, crash-063f71ad...): the naive `as i32 -
        // 1000` panics ("attempt to subtract with overflow") for any
        // adversarial handshake_type_raw >= 0x8000_0000 -- casting such a
        // value to i32 already lands near i32::MIN, and subtracting 1000
        // more underflows i32's range. No real libsrt peer sends a value
        // in that range (real reject codes are 0-a few thousand), but a
        // malformed/adversarial packet can carry any u32, and decode()
        // must never panic on attacker-controlled input. Widen to i64
        // (cannot overflow for any u32 input) before narrowing back to the
        // public i32 field via a truncating `as` cast, which never panics.
        let reject_reason = if handshake_type == HandshakeType::Rejected {
            Some((handshake_type_raw as i64 - 1000) as i32)
        } else {
            None
        };
        let socket_id = read_u32(&mut buf)?;
        let syn_cookie = read_u32(&mut buf)?;

        // Peer IP (128 bits = 16 bytes).
        let ip_bytes = read_bytes(&mut buf, 16)?;
        let peer_ip = parse_peer_ip(&ip_bytes);

        let conclusion_v5 = version == HS_VERSION_5 && handshake_type == HandshakeType::Conclusion;
        let extensions = decode_extensions(&mut buf, extension_field, conclusion_v5)?;

        Ok(Self {
            version,
            encryption_field,
            extension_field,
            initial_packet_seq,
            mtu,
            flow_window,
            handshake_type,
            socket_id,
            syn_cookie,
            peer_ip,
            extensions,
            reject_reason,
        })
    }

    /// Encode to a control packet.
    pub fn encode(&self, timestamp: u32, dest_socket_id: u32) -> ControlPacket {
        let mut control_info = Vec::new();

        write_u32(&mut control_info, self.version);
        write_u16(&mut control_info, self.encryption_field);
        write_u16(&mut control_info, self.extension_field);
        write_u32(&mut control_info, self.initial_packet_seq & 0x7FFF_FFFF);
        write_u32(&mut control_info, self.mtu);
        write_u32(&mut control_info, self.flow_window);
        // Rejected's discriminant (1000) is only a sentinel for the
        // decoded-from-wire case; the actual wire value a *rejection we
        // originate* must carry is `1000 + reject_reason` (see
        // `new_rejection`'s doc comment), not the bare discriminant.
        //
        // local patch (same class of bug `cargo fuzz run
        // fuzz_handshake_decode` found on the decode side, see decode()'s
        // comment above): a caller could in principle construct
        // `reject_reason: Some(i32::MAX)` (directly via `new_rejection`,
        // or by re-encoding a packet decoded from adversarial input), and
        // `1000 + i32::MAX` would panic in a checked build. Widen to i64
        // (cannot overflow for any i32 input) before narrowing to the
        // u32 actually written to the wire.
        let handshake_type_wire = if self.handshake_type == HandshakeType::Rejected {
            (1000i64 + self.reject_reason.unwrap_or(0) as i64) as u32
        } else {
            self.handshake_type as u32
        };
        write_u32(&mut control_info, handshake_type_wire);
        write_u32(&mut control_info, self.socket_id);
        write_u32(&mut control_info, self.syn_cookie);

        // Peer IP
        encode_peer_ip(&self.peer_ip, &mut control_info);

        // Extensions.
        for ext in &self.extensions {
            write_u16(&mut control_info, ext.ext_type as u16);
            let len_in_words = ext.data.len().div_ceil(4);
            write_u16(&mut control_info, len_in_words as u16);
            write_bytes(&mut control_info, &ext.data);
            // Padding.
            let padding = len_in_words * 4 - ext.data.len();
            for _ in 0..padding {
                write_u8(&mut control_info, 0);
            }
        }

        ControlPacket {
            control_type: ControlType::Handshake,
            subtype: 0,
            type_specific_info: 0,
            timestamp,
            dest_socket_id,
            control_info,
        }
    }

    /// Add an HSREQ extension.
    pub fn add_hs_extension(&mut self, srt_version: u32, srt_flags: u32, tsbpd_delay: u16) {
        let mut data = Vec::new();
        write_u32(&mut data, srt_version);
        write_u32(&mut data, srt_flags);
        write_u16(&mut data, tsbpd_delay); // Receiver TSBPD delay
        write_u16(&mut data, tsbpd_delay); // Sender TSBPD delay

        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::HsReq,
            data,
        });
        self.extension_field |= extension_flags::HSREQ;
    }

    /// Add an HSRSP extension.
    pub fn add_hs_response(&mut self, srt_version: u32, srt_flags: u32, tsbpd_delay: u16) {
        let mut data = Vec::new();
        write_u32(&mut data, srt_version);
        write_u32(&mut data, srt_flags);
        write_u16(&mut data, tsbpd_delay);
        write_u16(&mut data, tsbpd_delay);

        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::HsRsp,
            data,
        });
        self.extension_field |= extension_flags::HSREQ;
    }

    /// Get the HSREQ/HSRSP extension.
    pub fn get_hs_extension(&self) -> Option<HsExtensionData> {
        for ext in &self.extensions {
            if (ext.ext_type == ExtensionType::HsReq || ext.ext_type == ExtensionType::HsRsp)
                && ext.data.len() == 12
            {
                let mut buf = ext.data.as_slice();
                let srt_version = read_u32(&mut buf).ok()?;
                let srt_flags = read_u32(&mut buf).ok()?;
                let recv_tsbpd_delay = read_u16(&mut buf).ok()?;
                let send_tsbpd_delay = read_u16(&mut buf).ok()?;
                return Some(HsExtensionData {
                    srt_version,
                    srt_flags,
                    recv_tsbpd_delay,
                    send_tsbpd_delay,
                });
            }
        }
        None
    }

    /// Add the libsrt-compatible two-word GROUP extension.
    pub fn add_group_extension(&mut self, group: GroupExtensionData) {
        let mut data = Vec::with_capacity(8);
        write_u32(&mut data, group.group_id);
        let packed = (u32::from(group.group_type.to_u8()) << 24)
            | (u32::from(group.flags) << 16)
            | u32::from(group.weight);
        write_u32(&mut data, packed);

        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::Group,
            data,
        });
        // GROUP is a CONFIG extension in libsrt. There is no independent
        // GROUP bit in the handshake extension flags.
        self.extension_field |= extension_flags::CONFIG;
    }

    /// Read the first valid libsrt-compatible GROUP extension. Later words
    /// are reserved for future group metadata and do not hide the first two.
    pub fn get_group_extension(&self) -> Option<GroupExtensionData> {
        for extension in &self.extensions {
            if extension.ext_type != ExtensionType::Group || extension.data.len() < 8 {
                continue;
            }

            let mut data = extension.data.as_slice();
            let group_id = read_u32(&mut data).ok()?;
            let packed = read_u32(&mut data).ok()?;
            let group_type = GroupType::from_u8((packed >> 24) as u8);

            return Some(GroupExtensionData {
                group_id,
                group_type,
                flags: (packed >> 16) as u8,
                weight: packed as u16,
            });
        }
        None
    }

    /// Get the key length.
    pub fn key_length(&self) -> Option<KeyLength> {
        KeyLength::from_encryption_field(self.encryption_field)
    }

    /// Add a KMREQ extension.
    pub fn add_km_request(&mut self, km_message: &KmMessage) {
        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::KmReq,
            data: km_message.encode(),
        });
        self.extension_field |= extension_flags::KMREQ;
    }

    /// Add a KMRSP extension (success: returns the same KM message).
    pub fn add_km_response(&mut self, km_message: &KmMessage) {
        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::KmRsp,
            data: km_message.encode(),
        });
        self.extension_field |= extension_flags::KMREQ;
    }

    /// Add a KMRSP error extension (failure).
    pub fn add_km_error(&mut self, error: KmError) {
        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::KmRsp,
            // libsrt copies SRT_KM_STATE into the KM payload as a native
            // 32-bit word before the handshake codec performs its own word
            // swapping. The resulting extension bytes are little-endian.
            data: (error as u32).to_le_bytes().to_vec(),
        });
        self.extension_field |= extension_flags::KMREQ;
    }

    /// Get the KMREQ extension.
    pub fn get_km_request(&self) -> Option<Result<KmMessage, Error>> {
        for ext in &self.extensions {
            if ext.ext_type == ExtensionType::KmReq {
                return Some(KmMessage::decode(&ext.data));
            }
        }
        None
    }

    /// Get the KMRSP extension.
    ///
    /// Returns `Ok(Some(KmMessage))` on success, `Err(KmError)` on failure,
    /// and `Ok(None)` if there is no KMRSP extension.
    pub fn get_km_response(&self) -> Result<Option<KmMessage>, KmError> {
        for ext in &self.extensions {
            if ext.ext_type == ExtensionType::KmRsp {
                // An error response is 4 bytes.
                if ext.data.len() == 4 {
                    let error_code =
                        u32::from_le_bytes([ext.data[0], ext.data[1], ext.data[2], ext.data[3]]);
                    if let Some(km_error) = KmError::from_u32(error_code) {
                        return Err(km_error);
                    }
                }
                // A normal KM message.
                match KmMessage::decode(&ext.data) {
                    Ok(km) => return Ok(Some(km)),
                    Err(_) => continue,
                }
            }
        }
        Ok(None)
    }

    /// Add a Stream ID extension.
    ///
    /// The Stream ID is a UTF-8 string, up to 512 bytes, stored as 32-bit
    /// little-endian words.
    pub fn add_sid_extension(&mut self, stream_id: &str) {
        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::Sid,
            data: encode_le_words(stream_id, 512),
        });
        // local patch (crates/srt-protocol/VENDOR.md): real libsrt
        // gates its own extension-scanning loop on the CONFIG bit in
        // extension_field (confirmed at srtcore/core.cpp:2925,12433 --
        // `if (IsSet(ext_flags, CHandShake::HS_EXT_CONFIG))`) and always
        // sets it itself when adding a SID/congestion extension
        // (srtcore/core.cpp:1708 etc). Without this, the SID bytes are
        // correctly on the wire but a real libsrt peer silently never looks
        // for them -- confirmed via live capture against real libsrt
        // (extension present and correctly sized, but srt_getsockflag
        // SRTO_STREAMID on the libsrt side returned empty).
        self.extension_field |= extension_flags::CONFIG;
    }

    /// Get the Stream ID extension.
    ///
    /// The Stream ID is stored as 32-bit little-endian words, so byte order
    /// is restored on decode.
    pub fn get_sid_extension(&self) -> Option<String> {
        for ext in &self.extensions {
            if ext.ext_type == ExtensionType::Sid {
                return decode_le_words(&ext.data);
            }
        }
        None
    }

    /// Add a Congestion extension.
    ///
    /// Specifies the congestion control algorithm. Live streaming uses
    /// "live".
    ///
    /// Stored as 32-bit little-endian words, the same as Stream ID.
    pub fn add_congestion_extension(&mut self, congestion_control: &str) {
        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::Congestion,
            data: encode_le_words(congestion_control, 512),
        });
        // local patch (crates/srt-protocol/VENDOR.md): same CONFIG
        // bit issue as add_sid_extension above -- real libsrt gates parsing
        // of this extension type on the same flag.
        self.extension_field |= extension_flags::CONFIG;
    }

    /// Get the Congestion extension.
    ///
    /// Returns the congestion control algorithm name, e.g. "live", "file".
    pub fn get_congestion_extension(&self) -> Option<String> {
        for ext in &self.extensions {
            if ext.ext_type == ExtensionType::Congestion {
                return decode_le_words(&ext.data);
            }
        }
        None
    }

    /// Whether the peer is negotiating packet-filter behaviour.
    ///
    /// The FILTER extension is a *negotiation*, not a capability
    /// advertisement: a peer that sends it expects the recovery filter it
    /// names to be applied. This implementation has no filter, so a caller
    /// refuses the session ([`SRT_REJ_FILTER`]). The `PACKET_FILTER` flag in
    /// the HS extension's `srt_flags` is the capability advertisement and is
    /// deliberately *not* treated as a negotiation -- the reference
    /// implementation does not reject on the flag alone, and doing so would
    /// over-reject a peer that never asked for filtering.
    pub fn has_filter_extension(&self) -> bool {
        self.extensions
            .iter()
            .any(|ext| ext.ext_type == ExtensionType::Filter)
    }
}

/// Parse the extension block transactionally: every record is framed and
/// validated before any is returned, and the categories declared in
/// `extension_field` must agree with the records in both directions.
///
/// For an HSv5 CONCLUSION (the only handshake that negotiates through
/// extensions; an INDUCTION reuses `extension_field` for the SRT magic),
/// the HS category is mandatory, and a set HSREQ or KMREQ flag must be
/// backed by its record -- the pinned reference rejects both
/// (`CUDT::interpretSrtHandshake`, `SRT_REJ_ROGUE`). A set CONFIG flag is
/// not required to name a *known* record, so a well-framed future CONFIG
/// extension stays forward compatible.
fn decode_extensions(
    buf: &mut &[u8],
    extension_field: u16,
    conclusion_v5: bool,
) -> Result<Vec<HandshakeExtension>, Error> {
    let mut extensions = Vec::new();
    let mut seen = 0u8;
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(Error::invalid_data("truncated handshake extension header"));
        }
        let ext_type_raw = read_u16(buf)?;
        let ext_len = read_u16(buf)? as usize * 4;
        if buf.len() < ext_len {
            return Err(Error::invalid_data("truncated handshake extension body"));
        }
        let (ext_data, rest) = buf.split_at(ext_len);
        *buf = rest;

        let Some(ext_type) = ExtensionType::from_u16(ext_type_raw) else {
            continue;
        };
        if extension_field & ext_type.category_flag() == 0 {
            return Err(Error::invalid_data(format!(
                "{ext_type:?} extension is missing its category flag"
            )));
        }
        if seen & ext_type.uniqueness_bit() != 0 {
            return Err(Error::invalid_data(format!(
                "duplicate {ext_type:?} extension category"
            )));
        }
        validate_extension_data(ext_type, ext_data)?;
        seen |= ext_type.uniqueness_bit();
        extensions.push(HandshakeExtension {
            ext_type,
            data: ext_data.to_vec(),
        });
    }
    if conclusion_v5 {
        require_conclusion_records(extension_field, seen)?;
    }
    Ok(extensions)
}

/// The reverse direction of the category rule for an HSv5 CONCLUSION: the
/// HS category is mandatory, and a set HSREQ or KMREQ flag must be backed
/// by its record (`seen` holds the records' uniqueness bits).
fn require_conclusion_records(extension_field: u16, seen: u8) -> Result<(), Error> {
    if extension_field & extension_flags::HSREQ == 0 {
        return Err(Error::invalid_data(
            "HSv5 CONCLUSION must negotiate the HS extension",
        ));
    }
    for (flag, record) in [
        (extension_flags::HSREQ, ExtensionType::HsReq),
        (extension_flags::KMREQ, ExtensionType::KmReq),
    ] {
        if extension_field & flag != 0 && seen & record.uniqueness_bit() == 0 {
            return Err(Error::invalid_data(format!(
                "{record:?} category flag set without its extension"
            )));
        }
    }
    Ok(())
}

fn validate_extension_data(ext_type: ExtensionType, data: &[u8]) -> Result<(), Error> {
    match ext_type {
        ExtensionType::HsReq | ExtensionType::HsRsp if data.len() != 12 => {
            Err(Error::invalid_data("HS extension must be exactly 12 bytes"))
        }
        ExtensionType::KmReq => KmMessage::decode(data).map(|_| ()),
        ExtensionType::KmRsp if data.len() == 4 => {
            let Ok(code) = <[u8; 4]>::try_from(data) else {
                return Err(Error::invalid_data("KMRSP error payload must be 4 bytes"));
            };
            KmError::from_u32(u32::from_le_bytes(code))
                .map(|_| ())
                .ok_or_else(|| Error::invalid_data("unknown KMRSP error code"))
        }
        ExtensionType::KmRsp => KmMessage::decode(data).map(|_| ()),
        ExtensionType::Group if data.len() < 8 => Err(Error::invalid_data(
            "GROUP extension must be at least 8 bytes",
        )),
        ExtensionType::Sid | ExtensionType::Congestion | ExtensionType::Filter
            if data.len() > 512 =>
        {
            Err(Error::invalid_data("CONFIG extension exceeds 512 bytes"))
        }
        _ => Ok(()),
    }
}

/// Encode a string as 32-bit little-endian words.
///
/// Truncation to `max_len` falls back to the nearest preceding UTF-8 char
/// boundary rather than cutting at a raw byte offset: a mid-character cut
/// produces invalid UTF-8, which then fails to decode back on the peer's
/// `decode_le_words`, silently dropping the whole string. (found via
/// upstream shiguredo/srt-rs issue 0057, not yet in the pulled subtree)
fn encode_le_words(s: &str, max_len: usize) -> Vec<u8> {
    let len = s.floor_char_boundary(max_len);
    let truncated = &s.as_bytes()[..len];

    let padded_len = (len + 3) & !3;
    let mut data = vec![0u8; padded_len];

    for (i, chunk) in truncated.chunks(4).enumerate() {
        let offset = i * 4;
        for (j, &byte) in chunk.iter().enumerate() {
            data[offset + (3 - j)] = byte;
        }
    }

    data
}

/// Decode a string from 32-bit little-endian words.
fn decode_le_words(data: &[u8]) -> Option<String> {
    let mut bytes = Vec::new();

    for chunk in data.chunks(4) {
        for i in (0..chunk.len()).rev() {
            bytes.push(chunk[i]);
        }
    }

    while bytes.last() == Some(&0) {
        bytes.pop();
    }

    String::from_utf8(bytes).ok()
}

/// Handshake extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeExtension {
    /// Extension type.
    pub ext_type: ExtensionType,
    /// Extension data.
    pub data: Vec<u8>,
}

/// HS extension data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HsExtensionData {
    /// SRT version.
    pub srt_version: u32,
    /// SRT flags.
    pub srt_flags: u32,
    /// Receiver TSBPD delay (ms).
    pub recv_tsbpd_delay: u16,
    /// Sender TSBPD delay (ms).
    pub send_tsbpd_delay: u16,
}

/// Parse a peer IP.
fn parse_peer_ip(bytes: &[u8]) -> IpAddr {
    if bytes.len() < 16 {
        return IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    }

    // IPv4 case: the first 4 bytes are the IP, the rest are 0.
    let is_ipv4 = bytes[4..16].iter().all(|&b| b == 0);

    if is_ipv4 {
        IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(bytes);
        IpAddr::V6(std::net::Ipv6Addr::from(octets))
    }
}

/// Encode a peer IP.
fn encode_peer_ip(ip: &IpAddr, buf: &mut Vec<u8>) {
    match ip {
        IpAddr::V4(ipv4) => {
            write_bytes(buf, &ipv4.octets());
            // The remaining 12 bytes are 0.
            for _ in 0..12 {
                write_u8(buf, 0);
            }
        }
        IpAddr::V6(ipv6) => {
            write_bytes(buf, &ipv6.octets());
        }
    }
}

/// Handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeState {
    /// Initial state.
    #[default]
    Initial,
    /// INDUCTION sent (Caller).
    InductionSent,
    /// INDUCTION received (Listener).
    InductionReceived,
    /// CONCLUSION sent.
    ConclusionSent,
    /// Complete.
    Completed,
    /// Failed.
    Failed,
}

/// Key Material message.
///
/// The Key Material structure per SRT spec §3.2.1. Used in the KMREQ/KMRSP
/// handshake extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmMessage {
    /// KM version (V): 3 bits, currently 1.
    pub version: u8,
    /// Packet type (PT): 4 bits, KMmsg = 2.
    pub packet_type: u8,
    /// Key flag (KK): 2 bits.
    pub key_flag: KeyFlag,
    /// KEK index: usually 0 (default stream key).
    pub keki: u32,
    /// Cipher: AES-CTR = 2, AES-GCM = 4.
    pub cipher: u8,
    /// Auth: None = 0, AES-GCM = 1.
    pub auth: u8,
    /// Stream encapsulation (SE): MPEG-TS/SRT = 2.
    pub stream_encapsulation: u8,
    /// Key length.
    pub key_length: KeyLength,
    /// Salt (16 bytes).
    pub salt: [u8; 16],
    /// Wrapped SEK.
    pub wrapped_key: Vec<u8>,
}

/// KM message signature ('HAI' = Haivision).
const KM_SIGNATURE: u16 = 0x2029;

/// KM version.
const KM_VERSION: u8 = 1;

/// Packet type: Key Material Message.
const KM_PACKET_TYPE: u8 = 2;

/// Cipher type values in KM messages.
pub mod cipher_type {
    /// AES-CTR
    pub const AES_CTR: u8 = 2;
    /// AES-GCM (v1.6.0 and later).
    pub const AES_GCM: u8 = 4;
}

/// Authentication type values in KM messages.
pub mod auth_type {
    /// No authentication.
    pub const NONE: u8 = 0;
    /// AES-GCM authentication.
    pub const AES_GCM: u8 = 1;
}

/// Stream encapsulation.
pub mod stream_encapsulation {
    /// MPEG-TS/SRT
    pub const MPEG_TS_SRT: u8 = 2;
}

impl KmMessage {
    /// Create a new KM message.
    pub fn new(
        key_flag: KeyFlag,
        key_length: KeyLength,
        salt: [u8; 16],
        wrapped_key: Vec<u8>,
        cipher_mode: crate::crypto_impl::CipherMode,
    ) -> Self {
        let (cipher, auth) = match cipher_mode {
            crate::crypto_impl::CipherMode::Ctr => (cipher_type::AES_CTR, auth_type::NONE),
            crate::crypto_impl::CipherMode::Gcm => (cipher_type::AES_GCM, auth_type::AES_GCM),
        };
        Self {
            version: KM_VERSION,
            packet_type: KM_PACKET_TYPE,
            key_flag,
            keki: 0,
            cipher,
            auth,
            stream_encapsulation: stream_encapsulation::MPEG_TS_SRT,
            key_length,
            salt,
            wrapped_key,
        }
    }

    /// Encode to a byte buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // First 4 bytes: S(1) | V(3) | PT(4) | Sign(16) | Resv1(6) | KK(2)
        let first_byte = (self.version << 4) | self.packet_type;
        write_u8(&mut buf, first_byte);
        write_u16(&mut buf, KM_SIGNATURE);
        // Resv1 (6 bits) | KK (2 bits)
        write_u8(&mut buf, self.key_flag.to_kk_field());

        // KEKI (32 bits)
        write_u32(&mut buf, self.keki);

        // Cipher (8) | Auth (8) | SE (8) | Resv2 (8)
        write_u8(&mut buf, self.cipher);
        write_u8(&mut buf, self.auth);
        write_u8(&mut buf, self.stream_encapsulation);
        write_u8(&mut buf, 0); // Resv2

        // Resv3 (16) | SLen/4 (8) | KLen/4 (8)
        write_u16(&mut buf, 0); // Resv3
        write_u8(&mut buf, 4); // SLen/4 = 16/4 = 4
        write_u8(&mut buf, (self.key_length.len() / 4) as u8); // KLen/4

        // Salt (16 bytes)
        write_bytes(&mut buf, &self.salt);

        // Wrapped Key
        write_bytes(&mut buf, &self.wrapped_key);

        buf
    }

    /// Decode from a byte slice.
    ///
    /// Split into three steps so each stays reviewable on its own: the fixed
    /// header is *read* (`KmHeader::decode`), its parameters are *validated*
    /// against what this implementation accepts (`KmHeader::validate`), and
    /// only then is the key material read.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < KM_HEADER_LEN {
            return Err(Error::invalid_data("KM message too short"));
        }

        let mut buf = data;
        let header = KmHeader::decode(&mut buf)?;
        header.validate(buf.len())?;

        let salt_bytes = read_bytes(&mut buf, header.salt_len)?;
        // Checked conversion rather than `copy_from_slice`: the length is
        // already validated, but this makes the invariant structural (and
        // leaves no zero-filled salt literal in the decode path).
        let salt: [u8; 16] = salt_bytes
            .try_into()
            .map_err(|_| Error::invalid_data("KM salt is not 16 bytes"))?;
        // Wrapped Key (everything remaining).
        let wrapped_key = buf.to_vec();

        Ok(Self {
            version: header.version,
            packet_type: header.packet_type,
            key_flag: header.key_flag,
            keki: header.keki,
            cipher: header.cipher,
            auth: header.auth,
            stream_encapsulation: header.stream_encapsulation,
            key_length: header.key_length,
            salt,
            wrapped_key,
        })
    }
}

/// Fixed KM header length, before salt and wrapped key.
const KM_HEADER_LEN: usize = 16;

/// The structural fields of a KM message, read but not yet validated.
struct KmHeader {
    version: u8,
    packet_type: u8,
    key_flag: KeyFlag,
    keki: u32,
    cipher: u8,
    auth: u8,
    stream_encapsulation: u8,
    salt_len: usize,
    key_length: KeyLength,
}

impl KmHeader {
    /// Read the fixed 16-byte header.
    ///
    /// Structure only: field extraction plus the rules that make a field
    /// *readable* at all (the reserved bit, the selector bits). Whether the
    /// decoded values are ones this implementation accepts is
    /// [`Self::validate`]'s business.
    fn decode(buf: &mut &[u8]) -> Result<Self, Error> {
        let first_byte = read_u8(buf)?;
        if first_byte & 0x80 != 0 {
            return Err(Error::invalid_data("KM reserved bit is set"));
        }
        let version = (first_byte >> 4) & 0x07;
        let packet_type = first_byte & 0x0F;

        let signature = read_u16(buf)?;
        if signature != KM_SIGNATURE {
            return Err(Error::invalid_data(format!(
                "invalid KM signature: {signature:#06x}, expected {KM_SIGNATURE:#06x}"
            )));
        }

        let kk_byte = read_u8(buf)?;
        if kk_byte & !0b11 != 0 {
            return Err(Error::invalid_data("KM KK reserved bits are set"));
        }
        let key_flag = KeyFlag::from_kk_field(kk_byte)
            .ok_or_else(|| Error::invalid_data("invalid KK field"))?;

        let keki = read_u32(buf)?;
        let cipher = read_u8(buf)?;
        let auth = read_u8(buf)?;
        let stream_encapsulation = read_u8(buf)?;
        let resv2 = read_u8(buf)?;
        let resv3 = read_u16(buf)?;
        let salt_len = read_u8(buf)? as usize * 4;
        let key_len = read_u8(buf)? as usize * 4;

        // Reserved fields are structural: a message that sets one is not the
        // message this format describes, whatever its parameters say.
        if resv2 != 0 || resv3 != 0 {
            return Err(Error::invalid_data("unsupported KM message parameters"));
        }
        let key_length = KeyLength::from_len(key_len)
            .ok_or_else(|| Error::invalid_data(format!("invalid key length: {key_len}")))?;

        Ok(Self {
            version,
            packet_type,
            key_flag,
            keki,
            cipher,
            auth,
            stream_encapsulation,
            salt_len,
            key_length,
        })
    }

    /// Validate the decoded parameters against what this implementation
    /// accepts, and check that the key material has the length they imply.
    fn validate(&self, remaining: usize) -> Result<(), Error> {
        if self.salt_len != 16 {
            return Err(Error::invalid_data(format!(
                "unsupported salt length: {}",
                self.salt_len
            )));
        }
        if self.version != KM_VERSION
            || self.packet_type != KM_PACKET_TYPE
            || self.keki != 0
            || !matches!(
                (self.cipher, self.auth),
                (cipher_type::AES_CTR, auth_type::NONE)
                    | (cipher_type::AES_GCM, auth_type::AES_GCM)
            )
            || self.stream_encapsulation != stream_encapsulation::MPEG_TS_SRT
        {
            return Err(Error::invalid_data("unsupported KM message parameters"));
        }
        let expected_remaining = self.salt_len + self.key_length.len() + 8;
        if remaining != expected_remaining {
            return Err(Error::invalid_data(format!(
                "KM message length mismatch: expected {expected_remaining} bytes after header, got {remaining}"
            )));
        }
        Ok(())
    }
}

/// KM response error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KmError {
    /// Unsecured (the peer encrypts, but the agent has not declared encryption).
    Unsecured = 0,
    /// No secret (the peer has no key to decrypt with).
    NoSecret = 3,
    /// Bad secret (the peer has the wrong key).
    BadSecret = 4,
    /// Bad crypto mode (the peer expects a different encryption mode).
    BadCryptoMode = 5,
}

impl KmError {
    /// Convert from a u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Unsecured),
            3 => Some(Self::NoSecret),
            4 => Some(Self::BadSecret),
            5 => Some(Self::BadCryptoMode),
            _ => None,
        }
    }
}

/// Decode a datagram straight into a [`HandshakePacket`], or `None` if it
/// is not one.
///
/// A listener has to inspect a datagram *before* it has any connection to
/// feed it to -- to route it, or to decide whether to create state at
/// all. Doing that meant reaching for `SrtPacket::decode` and
/// `HandshakePacket::decode` in sequence and knowing that a handshake is
/// always a control packet, which is codec knowledge that belongs here
/// rather than in whatever crate happens to be doing admission.
#[must_use]
pub fn peek_handshake(datagram: &[u8]) -> Option<HandshakePacket> {
    let crate::srt_packet::SrtPacket::Control(control) =
        crate::srt_packet::SrtPacket::decode(datagram).ok()?
    else {
        return None;
    };
    HandshakePacket::decode(&control).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic fixture salt for wire-format tests.
    ///
    /// Deliberately not a literal: this is test material for encoding and
    /// decoding, never a secret, and deriving it makes that explicit (a
    /// hard-coded byte array passed to a key-material constructor reads as a
    /// real salt to static analysis).
    fn fixture_salt() -> [u8; 16] {
        std::array::from_fn(|index| index as u8)
    }

    #[test]
    fn ip_family_uses_ipv4_overhead_for_ipv4_mapped_peers() {
        let mapped = std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()),
            9000,
        );
        assert_eq!(IpFamily::of(&mapped), IpFamily::V4);
        assert_eq!(
            conclusion_with_hs().peer_max_payload_size(IpFamily::of(&mapped)),
            1456
        );

        let native_v6 =
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 9000);
        let mut minimum = conclusion_with_hs();
        minimum.mtu = 52;
        assert_eq!(minimum.peer_max_payload_size(IpFamily::of(&mapped)), 8);
        assert!(
            minimum
                .peer_mss_rejection_reason(IpFamily::of(&mapped), 8)
                .is_none()
        );
        assert!(
            minimum
                .peer_mss_rejection_reason(IpFamily::of(&native_v6), 8)
                .is_some()
        );
    }

    /// The MSS bounds are arithmetic on the wire layout, so they are pinned
    /// independently of any connection: IPv4 costs 28 bytes of IP/UDP and
    /// IPv6 48, on top of the 16-byte SRT header, and the minimum reserves
    /// one 8-byte NAK record.
    #[test]
    fn peer_mss_derivation_is_the_wire_layout_arithmetic() {
        let mut handshake = conclusion_with_hs();

        handshake.mtu = 1500;
        assert_eq!(IpFamily::V4.ip_udp_overhead(), 28);
        assert_eq!(handshake.peer_max_datagram_size(IpFamily::V4), 1472);
        assert_eq!(
            handshake.peer_max_payload_size(IpFamily::V4),
            1456,
            "libsrt's own mss - (UDP_HDR_SIZE + HDR_SIZE)"
        );

        assert_eq!(IpFamily::V6.ip_udp_overhead(), 48);
        assert_eq!(handshake.peer_max_datagram_size(IpFamily::V6), 1452);
        assert_eq!(handshake.peer_max_payload_size(IpFamily::V6), 1436);

        // The advisory peer-address field never decides the family.
        handshake.peer_ip = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert_eq!(handshake.peer_max_payload_size(IpFamily::V4), 1456);

        // Saturating, never panicking, for any wire value.
        for mtu in [0u32, 1, 27, 43, 44] {
            handshake.mtu = mtu;
            assert_eq!(
                handshake.peer_max_payload_size(IpFamily::V4),
                mtu.saturating_sub(44)
            );
        }
        handshake.mtu = u32::MAX;
        assert_eq!(
            handshake.peer_max_payload_size(IpFamily::V4),
            u32::MAX - 44,
            "no overflow at the top of the wire domain"
        );
    }

    /// Rejection bounds: the derived minimum for the path family (and the
    /// implementation's own payload floor), and the local maximum.
    #[test]
    fn peer_mss_rejection_bounds_are_derived_and_inclusive() {
        const MIN_PAYLOAD: u32 = 8;
        let mut handshake = conclusion_with_hs();

        for (mtu, family, accepted) in [
            (52u32, IpFamily::V4, true),
            (51, IpFamily::V4, false),
            (48, IpFamily::V4, false),
            (72, IpFamily::V6, true),
            (71, IpFamily::V6, false),
            (68, IpFamily::V6, false),
            (1500, IpFamily::V4, true),
            (1501, IpFamily::V4, false),
            (u32::MAX, IpFamily::V6, false),
        ] {
            handshake.mtu = mtu;
            let reason = handshake.peer_mss_rejection_reason(family, MIN_PAYLOAD);
            assert_eq!(
                reason.is_none(),
                accepted,
                "MSS {mtu} on {family:?}: {reason:?}"
            );
            if let Some(reason) = reason {
                assert!(reason.contains("MSS"), "{reason}");
            }
        }

        // A larger payload floor moves the minimum with it: 60 = 28 + 16 +
        // 16, so a 16-byte floor accepts exactly 60 and a 17-byte one rejects.
        handshake.mtu = 60;
        assert!(
            handshake
                .peer_mss_rejection_reason(IpFamily::V4, 16)
                .is_none()
        );
        assert!(
            handshake
                .peer_mss_rejection_reason(IpFamily::V4, 17)
                .is_some()
        );
    }

    #[test]
    fn test_handshake_encode_decode() {
        let original = HandshakePacket {
            version: HS_VERSION_5,
            encryption_field: 2,
            extension_field: extension_flags::HSREQ,
            initial_packet_seq: 12345,
            mtu: 1500,
            flow_window: 8192,
            handshake_type: HandshakeType::Conclusion,
            socket_id: 0x12345678,
            syn_cookie: 0xABCDEF01,
            peer_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            extensions: vec![hs_record()],
            reject_reason: None,
        };

        let packet = original.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        assert_eq!(original.version, decoded.version);
        assert_eq!(original.encryption_field, decoded.encryption_field);
        assert_eq!(original.extension_field, decoded.extension_field);
        assert_eq!(original.initial_packet_seq, decoded.initial_packet_seq);
        assert_eq!(original.mtu, decoded.mtu);
        assert_eq!(original.flow_window, decoded.flow_window);
        assert_eq!(original.handshake_type, decoded.handshake_type);
        assert_eq!(original.socket_id, decoded.socket_id);
        assert_eq!(original.syn_cookie, decoded.syn_cookie);
    }

    #[test]
    fn decode_rejects_oversized_control_info() {
        let packet = ControlPacket {
            control_type: ControlType::Handshake,
            subtype: 0,
            type_specific_info: 0,
            timestamp: 0,
            dest_socket_id: 0,
            control_info: vec![0; MAX_DATAGRAM_SIZE],
        };
        let error = HandshakePacket::decode(&packet).expect_err("handshake input is capped");
        assert_eq!(error.kind, crate::ErrorKind::InvalidData);
    }

    #[test]
    fn test_hs_extension() {
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        hs.add_hs_extension(0x010500, srt_flags::TSBPDSND | srt_flags::TSBPDRCV, 120);

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let ext = decoded
            .get_hs_extension()
            .expect("the HS extension should be Some");
        assert_eq!(ext.srt_version, 0x010500);
        assert_eq!(ext.srt_flags, srt_flags::TSBPDSND | srt_flags::TSBPDRCV);
        assert_eq!(ext.recv_tsbpd_delay, 120);
    }

    #[test]
    fn test_km_message_encode_decode() {
        let salt = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let wrapped_key = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        ];

        let original = KmMessage::new(
            KeyFlag::Even,
            KeyLength::Aes128,
            salt,
            wrapped_key.clone(),
            crate::crypto_impl::CipherMode::Ctr,
        );

        let encoded = original.encode();
        let decoded =
            KmMessage::decode(&encoded).expect("decoding an encoded KM message should succeed");

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.packet_type, 2);
        assert_eq!(decoded.key_flag, KeyFlag::Even);
        assert_eq!(decoded.cipher, cipher_type::AES_CTR);
        assert_eq!(decoded.key_length, KeyLength::Aes128);
        assert_eq!(decoded.salt, salt);
        assert_eq!(decoded.wrapped_key, wrapped_key);
    }

    #[test]
    fn test_km_extension_in_handshake() {
        let salt = [0u8; 16];
        let wrapped_key = vec![0u8; 24]; // AES-128 wrapped = 16 + 8

        let km_message = KmMessage::new(
            KeyFlag::Even,
            KeyLength::Aes128,
            salt,
            wrapped_key,
            crate::crypto_impl::CipherMode::Ctr,
        );

        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 2, true);
        hs.add_hs_extension(0x010500, srt_flags::TSBPDSND | srt_flags::CRYPT, 120);
        hs.add_km_request(&km_message);

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        // Get the KM request.
        let km_result = decoded.get_km_request();
        assert!(km_result.is_some());
        let km = km_result
            .expect("the KM request should be Some")
            .expect("decoding the KM message should succeed");
        assert_eq!(km.key_flag, KeyFlag::Even);
        assert_eq!(km.key_length, KeyLength::Aes128);
    }

    #[test]
    fn test_km_error_response() {
        let mut hs = HandshakePacket::new_conclusion_response(1, 2, 3, 0, true);
        hs.add_hs_response(0x010500, 0, 120);
        hs.add_km_error(KmError::BadSecret);
        assert_eq!(
            hs.extensions
                .iter()
                .find(|extension| extension.ext_type == ExtensionType::KmRsp)
                .expect("KMRSP extension")
                .data,
            [4, 0, 0, 0],
            "libsrt copies the status as a little-endian KM payload word"
        );

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let result = decoded.get_km_response();
        assert!(matches!(result, Err(KmError::BadSecret)));
    }

    // local patch (crates/srt-protocol/VENDOR.md): reject-reason
    // wire encode/decode did not exist at all before -- decode() hard-errored
    // on any handshake_type outside the 5 known success values, which is
    // exactly the value range (1000+) a real libsrt rejection response uses.
    #[test]
    fn test_rejection_roundtrip_predefined_reason() {
        // SRT_REJ_BADSECRET = 10 (srtcore/srt.h) -> wire value 1010
        let hs = HandshakePacket::new_rejection(1, 2, 10);
        let packet = hs.encode(1000, 0);
        let decoded =
            HandshakePacket::decode(&packet).expect("reject packets must decode, not error");
        assert_eq!(decoded.handshake_type, HandshakeType::Rejected);
        assert_eq!(decoded.reject_reason, Some(10));
    }

    #[test]
    fn test_rejection_roundtrip_custom_reason() {
        // Matches src/media/srt/listener.rs's own SRT_REJX_UNAUTHORIZED.
        const SRT_REJX_UNAUTHORIZED: i32 = 1401;
        let hs = HandshakePacket::new_rejection(1, 2, SRT_REJX_UNAUTHORIZED);
        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet).expect("reject packets must decode");
        assert_eq!(decoded.reject_reason, Some(SRT_REJX_UNAUTHORIZED));
    }

    #[test]
    fn test_non_rejection_handshake_has_no_reject_reason() {
        let hs = conclusion_with_hs();
        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet).expect("decode should succeed");
        assert_eq!(decoded.reject_reason, None);
    }

    #[test]
    fn test_decode_real_libsrt_wire_value_directly() {
        // Constructs the exact raw wire bytes a real libsrt listener would
        // send for URQFailure(SRT_REJ_UNSECURE=12) -- i.e. this test does
        // not go through this crate's own encode() at all, so it can't be
        // fooled by a matching bug on both sides.
        let mut control_info = Vec::new();
        write_u32(&mut control_info, HS_VERSION_5);
        write_u16(&mut control_info, 0);
        write_u16(&mut control_info, 0);
        write_u32(&mut control_info, 0);
        write_u32(&mut control_info, DEFAULT_MTU);
        write_u32(&mut control_info, DEFAULT_FLOW_WINDOW);
        write_u32(&mut control_info, 1012); // 1000 + SRT_REJ_UNSECURE(12)
        write_u32(&mut control_info, 42);
        write_u32(&mut control_info, 0);
        control_info.extend_from_slice(&[0u8; 16]); // peer_ip
        let packet = ControlPacket {
            control_type: ControlType::Handshake,
            subtype: 0,
            type_specific_info: 0,
            timestamp: 0,
            dest_socket_id: 0,
            control_info,
        };
        let decoded =
            HandshakePacket::decode(&packet).expect("must decode a real reject wire value");
        assert_eq!(decoded.handshake_type, HandshakeType::Rejected);
        assert_eq!(decoded.reject_reason, Some(12));
    }

    // local patch (crates/srt-protocol/VENDOR.md): regression test
    // for a real panic `cargo fuzz run fuzz_handshake_decode` found within
    // its first few thousand of 12M+ iterations (artifact
    // crash-063f71adb17dc4145d5fe833e849110974bde70f): `handshake_type_raw
    // as i32 - 1000` panicked with "attempt to subtract with overflow" for
    // any adversarial handshake_type_raw >= 0x8000_0000. No real libsrt
    // peer sends such a value, but decode() must never panic on
    // attacker-controlled input regardless.
    #[test]
    fn test_decode_adversarial_huge_handshake_type_does_not_panic() {
        for handshake_type_raw in [0x8000_0000u32, 0x8000_0001, 0x8000_03E7, u32::MAX - 3] {
            let mut control_info = Vec::new();
            write_u32(&mut control_info, HS_VERSION_5);
            write_u16(&mut control_info, 0);
            write_u16(&mut control_info, 0);
            write_u32(&mut control_info, 0);
            write_u32(&mut control_info, DEFAULT_MTU);
            write_u32(&mut control_info, DEFAULT_FLOW_WINDOW);
            write_u32(&mut control_info, handshake_type_raw);
            write_u32(&mut control_info, 42);
            write_u32(&mut control_info, 0);
            control_info.extend_from_slice(&[0u8; 16]);
            let packet = ControlPacket {
                control_type: ControlType::Handshake,
                subtype: 0,
                type_specific_info: 0,
                timestamp: 0,
                dest_socket_id: 0,
                control_info,
            };
            // Must not panic; decode() succeeding with some reject_reason
            // value is the only contract for this class of malformed-but-
            // not-out-of-range-per-from_u32 input.
            let decoded = HandshakePacket::decode(&packet)
                .expect("handshake_type_raw >= 1000 always decodes as Rejected, never errors");
            assert_eq!(decoded.handshake_type, HandshakeType::Rejected);
            assert!(decoded.reject_reason.is_some());
        }
    }

    // local patch: symmetric check for the encode-side arithmetic
    // (same class of bug, addition instead of subtraction -- see encode()'s
    // comment). Not found by the fuzzer (fuzzing only exercises decode()),
    // caught by code review of the mirrored logic instead.
    #[test]
    fn test_encode_extreme_reject_reason_does_not_panic() {
        for reason in [i32::MAX, i32::MAX - 1, i32::MIN, 0] {
            let hs = HandshakePacket::new_rejection(1, 2, reason);
            // Must not panic.
            let _packet = hs.encode(1000, 0);
        }
    }

    #[test]
    fn test_sid_extension_basic() {
        let mut hs = conclusion_with_hs();
        hs.add_sid_extension("test_stream");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded.get_sid_extension();
        assert_eq!(sid, Some("test_stream".to_string()));
    }

    // local patch (crates/srt-protocol/VENDOR.md): regression test
    // for a real libsrt interop bug found via live capture -- add_sid_extension
    // wrote the SID bytes correctly but never set the CONFIG bit in
    // extension_field, so this crate's own decode() (which doesn't gate on
    // that flag) round-tripped fine while real libsrt (which does gate on
    // it, srtcore/core.cpp:2925,12433) silently ignored the extension.
    // test_sid_extension_basic above would NOT have caught this: it only
    // proves this crate's encoder and decoder agree with each other, never
    // that a real libsrt-compatible peer would also find the extension.
    #[test]
    fn test_sid_extension_sets_config_flag() {
        let mut hs = conclusion_with_hs();
        assert_eq!(
            hs.extension_field & extension_flags::CONFIG,
            0,
            "CONFIG bit should not be set before any config-type extension is added"
        );
        hs.add_sid_extension("test_stream");
        assert_eq!(
            hs.extension_field & extension_flags::CONFIG,
            extension_flags::CONFIG,
            "real libsrt gates its extension-scanning loop on this bit (srtcore/core.cpp:2925) \
             and always sets it itself when adding a SID/congestion extension (core.cpp:1708) -- \
             without it, a real libsrt peer silently ignores an otherwise-correctly-encoded SID extension"
        );
    }

    #[test]
    fn test_congestion_extension_sets_config_flag() {
        let mut hs = conclusion_with_hs();
        hs.add_congestion_extension("live");
        assert_eq!(
            hs.extension_field & extension_flags::CONFIG,
            extension_flags::CONFIG
        );
    }

    #[test]
    fn test_sid_extension_access_control() {
        let mut hs = conclusion_with_hs();
        hs.add_sid_extension("#!::u=admin,r=live/stream1");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded.get_sid_extension();
        assert_eq!(sid, Some("#!::u=admin,r=live/stream1".to_string()));
    }

    #[test]
    fn test_sid_extension_with_padding() {
        // 5 characters -> padded to 8 bytes.
        let mut hs = conclusion_with_hs();
        hs.add_sid_extension("hello");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded.get_sid_extension();
        assert_eq!(sid, Some("hello".to_string()));
    }

    #[test]
    fn test_sid_extension_exact_4_bytes() {
        // 4 characters -> no padding needed.
        let mut hs = conclusion_with_hs();
        hs.add_sid_extension("test");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded.get_sid_extension();
        assert_eq!(sid, Some("test".to_string()));
    }

    #[test]
    fn test_sid_extension_long_string() {
        // A long string.
        let long_sid = "a".repeat(100);
        let mut hs = conclusion_with_hs();
        hs.add_sid_extension(&long_sid);

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded.get_sid_extension();
        assert_eq!(sid, Some(long_sid));
    }

    // Regression for upstream shiguredo/srt-rs issue 0057: "あ" is 3 bytes in
    // UTF-8, so 171 of them is 513 bytes -- one over the 512-byte extension
    // limit, with the 512-byte truncation point landing mid-character (byte
    // 512 is the middle byte of the 171st "あ", which spans bytes 510..513).
    // A raw-byte truncation at 512 emits an invalid UTF-8 tail, which then
    // fails to round-trip through decode_le_words (returns None), silently
    // losing the whole StreamID instead of just the one truncated character.
    #[test]
    fn test_sid_extension_truncates_on_a_utf8_char_boundary() {
        let long_sid = "あ".repeat(171);
        assert_eq!(long_sid.len(), 513);
        let mut hs = conclusion_with_hs();
        hs.add_sid_extension(&long_sid);

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded
            .get_sid_extension()
            .expect("truncation must land on a char boundary, not silently drop the StreamID");
        assert!(long_sid.starts_with(&sid));
        assert!(sid.len() <= 512);
    }

    #[test]
    fn test_sid_extension_empty() {
        let mut hs = conclusion_with_hs();
        hs.add_sid_extension("");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        // An empty string decodes to `Some("")` (all zero padding).
        let sid = decoded.get_sid_extension();
        assert_eq!(sid, Some("".to_string()));
    }

    #[test]
    fn test_no_sid_extension() {
        let hs = conclusion_with_hs();

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded.get_sid_extension();
        assert!(sid.is_none());
    }

    #[test]
    fn test_congestion_extension_live() {
        let mut hs = conclusion_with_hs();
        hs.add_congestion_extension("live");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let cc = decoded.get_congestion_extension();
        assert_eq!(cc, Some("live".to_string()));
    }

    #[test]
    fn test_congestion_extension_file() {
        // FileCC isn't supported, but it still decodes.
        let mut hs = conclusion_with_hs();
        hs.add_congestion_extension("file");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let cc = decoded.get_congestion_extension();
        assert_eq!(cc, Some("file".to_string()));
    }

    #[test]
    fn test_no_congestion_extension() {
        let hs = conclusion_with_hs();

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let cc = decoded.get_congestion_extension();
        assert!(cc.is_none());
    }

    #[test]
    fn test_congestion_extension_with_sid() {
        // Use the Congestion extension and the SID extension together.
        let mut hs = conclusion_with_hs();
        hs.add_congestion_extension("live");
        hs.add_sid_extension("test_stream");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let cc = decoded.get_congestion_extension();
        assert_eq!(cc, Some("live".to_string()));

        let sid = decoded.get_sid_extension();
        assert_eq!(sid, Some("test_stream".to_string()));
    }

    #[test]
    fn test_group_extension_matches_libsrt_layout() {
        let mut hs = conclusion_with_hs();
        let group = GroupExtensionData {
            group_id: 0x4000_1234,
            group_type: GroupType::Broadcast,
            flags: 0,
            weight: 200,
        };

        hs.add_group_extension(group);

        assert_eq!(
            hs.extension_field & extension_flags::CONFIG,
            extension_flags::CONFIG
        );
        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet).expect("GROUP handshake must round-trip");

        assert_eq!(decoded.get_group_extension(), Some(group));
        assert_eq!(
            decoded
                .extensions
                .iter()
                .find(|extension| extension.ext_type == ExtensionType::Group)
                .map(|extension| extension.data.as_slice()),
            Some(&[0x40, 0x00, 0x12, 0x34, 0x01, 0x00, 0x00, 0xC8][..])
        );
    }

    #[test]
    fn group_extension_ignores_trailing_words_without_losing_membership() {
        let mut hs = conclusion_with_hs();
        let group = GroupExtensionData {
            group_id: SRTGROUP_MASK | 42,
            group_type: GroupType::Backup,
            flags: 1,
            weight: 7,
        };
        hs.add_group_extension(group);
        hs.extensions
            .last_mut()
            .expect("GROUP was appended")
            .data
            .extend_from_slice(&[1, 2, 3, 4]);

        let decoded = HandshakePacket::decode(&hs.encode(0, 0))
            .expect("a word-aligned extended GROUP must decode");
        assert_eq!(decoded.get_group_extension(), Some(group));
    }

    #[test]
    fn unknown_group_type_round_trips_without_becoming_absent() {
        let mut hs = conclusion_with_hs();
        let group = GroupExtensionData {
            group_id: SRTGROUP_MASK | 9,
            group_type: GroupType::Unknown(3),
            flags: 0,
            weight: 1,
        };
        hs.add_group_extension(group);

        assert_eq!(hs.get_group_extension(), Some(group));
    }

    fn valid_extension_data(ext_type: ExtensionType) -> Vec<u8> {
        match ext_type {
            ExtensionType::HsReq | ExtensionType::HsRsp => vec![0; 12],
            ExtensionType::KmReq | ExtensionType::KmRsp => KmMessage::new(
                KeyFlag::Even,
                KeyLength::Aes128,
                fixture_salt(),
                vec![0; 24],
                crate::crypto_impl::CipherMode::Ctr,
            )
            .encode(),
            ExtensionType::Sid | ExtensionType::Congestion => Vec::new(),
            ExtensionType::Filter => b"fec\0".to_vec(),
            ExtensionType::Group => vec![0; 8],
        }
    }

    /// A well-formed HSv5 CONCLUSION request: the HSREQ flag with its record.
    fn conclusion_with_hs() -> HandshakePacket {
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        hs.add_hs_extension(0x0001_0500, 0, 120);
        hs
    }

    fn hs_record() -> HandshakeExtension {
        HandshakeExtension {
            ext_type: ExtensionType::HsReq,
            data: valid_extension_data(ExtensionType::HsReq),
        }
    }

    #[test]
    fn extension_decode_rejects_truncated_headers_and_bodies() {
        let hs = conclusion_with_hs();
        assert!(HandshakePacket::decode(&hs.encode(0, 0)).is_ok());

        let mut partial_header = hs.encode(0, 0);
        partial_header.control_info.extend_from_slice(&[0, 1]);
        assert!(HandshakePacket::decode(&partial_header).is_err());

        let mut partial_body = hs.encode(0, 0);
        write_u16(&mut partial_body.control_info, ExtensionType::HsReq as u16);
        write_u16(&mut partial_body.control_info, 3);
        partial_body.control_info.extend_from_slice(&[0; 8]);
        assert!(HandshakePacket::decode(&partial_body).is_err());
    }

    #[test]
    fn extension_decode_rejects_duplicate_known_categories() {
        let cases = [
            (ExtensionType::HsReq, extension_flags::HSREQ),
            (ExtensionType::KmReq, extension_flags::KMREQ),
            (ExtensionType::Sid, extension_flags::CONFIG),
            (ExtensionType::Congestion, extension_flags::CONFIG),
            (ExtensionType::Filter, extension_flags::CONFIG),
            (ExtensionType::Group, extension_flags::CONFIG),
        ];
        for (ext_type, category) in cases {
            let extension = HandshakeExtension {
                ext_type,
                data: valid_extension_data(ext_type),
            };
            let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
            hs.extension_field = extension_flags::HSREQ | category;
            hs.extensions = if ext_type == ExtensionType::HsReq {
                vec![extension.clone(), extension]
            } else {
                vec![hs_record(), extension.clone(), extension]
            };
            assert!(
                HandshakePacket::decode(&hs.encode(0, 0)).is_err(),
                "{ext_type:?} duplicate must be rejected"
            );
        }

        let mut mixed_hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        mixed_hs.extension_field = extension_flags::HSREQ;
        mixed_hs.extensions = vec![
            HandshakeExtension {
                ext_type: ExtensionType::HsReq,
                data: valid_extension_data(ExtensionType::HsReq),
            },
            HandshakeExtension {
                ext_type: ExtensionType::HsRsp,
                data: valid_extension_data(ExtensionType::HsRsp),
            },
        ];
        assert!(HandshakePacket::decode(&mixed_hs.encode(0, 0)).is_err());
    }

    #[test]
    fn known_extensions_require_their_category_flag() {
        for ext_type in [
            ExtensionType::HsReq,
            ExtensionType::HsRsp,
            ExtensionType::KmReq,
            ExtensionType::KmRsp,
            ExtensionType::Sid,
            ExtensionType::Congestion,
            ExtensionType::Filter,
            ExtensionType::Group,
        ] {
            let mut hs = conclusion_with_hs();
            hs.extension_field = 0;
            hs.extensions.push(HandshakeExtension {
                ext_type,
                data: valid_extension_data(ext_type),
            });
            assert!(
                HandshakePacket::decode(&hs.encode(0, 0)).is_err(),
                "{ext_type:?} without its category bit must be rejected"
            );
        }
    }

    #[test]
    fn unknown_well_framed_extension_remains_ignorable() {
        let hs = conclusion_with_hs();
        let mut packet = hs.encode(0, 0);
        write_u16(&mut packet.control_info, 0x7fff);
        write_u16(&mut packet.control_info, 1);
        packet.control_info.extend_from_slice(&[1, 2, 3, 4]);

        let decoded = HandshakePacket::decode(&packet).expect("unknown framed extension");
        assert_eq!(decoded.extensions.len(), 1, "only the HS record survives");
    }

    /// The category rule holds in both directions for an HSv5 CONCLUSION:
    /// a set HSREQ or KMREQ flag must be backed by its record, and the HS
    /// category itself is mandatory. An INDUCTION (whose `extension_field`
    /// carries the SRT magic) and an unknown CONFIG record are unaffected.
    #[test]
    fn category_flags_require_their_records_in_an_hsv5_conclusion() {
        let unknown_record = |packet: &mut ControlPacket| {
            write_u16(&mut packet.control_info, 0x7fff);
            write_u16(&mut packet.control_info, 1);
            packet.control_info.extend_from_slice(&[1, 2, 3, 4]);
        };

        let hs_flag_no_record = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        assert!(HandshakePacket::decode(&hs_flag_no_record.encode(0, 0)).is_err());

        let mut hs_flag_unknown_only = hs_flag_no_record.encode(0, 0);
        unknown_record(&mut hs_flag_unknown_only);
        assert!(HandshakePacket::decode(&hs_flag_unknown_only).is_err());

        let mut km_flag_no_record = conclusion_with_hs();
        km_flag_no_record.extension_field |= extension_flags::KMREQ;
        assert!(HandshakePacket::decode(&km_flag_no_record.encode(0, 0)).is_err());

        let mut zero_flags = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        zero_flags.extension_field = 0;
        assert!(HandshakePacket::decode(&zero_flags.encode(0, 0)).is_err());

        // CONFIG set with only an unknown CONFIG-range record stays accepted.
        let mut config_unknown = conclusion_with_hs();
        config_unknown.extension_field |= extension_flags::CONFIG;
        let mut packet = config_unknown.encode(0, 0);
        unknown_record(&mut packet);
        assert!(HandshakePacket::decode(&packet).is_ok());

        // An INDUCTION carries the SRT magic in `extension_field`, not flags.
        let induction = HandshakePacket::new_induction_response(1, 2, 3);
        assert!(HandshakePacket::decode(&induction.encode(0, 0)).is_ok());
    }

    #[test]
    fn handshake_isn_high_bit_is_rejected_not_aliased() {
        let hs = conclusion_with_hs();
        let mut packet = hs.encode(0, 0);
        packet.control_info[8..12].copy_from_slice(&0x8000_0003u32.to_be_bytes());
        assert!(HandshakePacket::decode(&packet).is_err());
    }

    #[test]
    fn km_message_requires_the_exact_wrapped_key_length() {
        for key_length in [KeyLength::Aes128, KeyLength::Aes192, KeyLength::Aes256] {
            let encoded = KmMessage::new(
                KeyFlag::Even,
                key_length,
                fixture_salt(),
                vec![0; key_length.len() + 8],
                crate::crypto_impl::CipherMode::Ctr,
            )
            .encode();
            assert!(KmMessage::decode(&encoded).is_ok());
            assert!(KmMessage::decode(&encoded[..encoded.len() - 4]).is_err());

            let mut oversized = encoded;
            oversized.extend_from_slice(&[0; 4]);
            assert!(KmMessage::decode(&oversized).is_err());
        }
    }
}
