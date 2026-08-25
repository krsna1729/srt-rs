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
use crate::crypto::{KeyFlag, KeyLength};
use crate::error::Error;
use crate::srt_packet::{ControlPacket, ControlType};

/// Handshake version.
pub const HS_VERSION_4: u32 = 4;
/// Handshake version.
pub const HS_VERSION_5: u32 = 5;

/// Default MTU size.
pub const DEFAULT_MTU: u32 = 1500;

/// Default flow window size.
pub const DEFAULT_FLOW_WINDOW: u32 = 8192;

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
}

/// SRT bonding group type carried by the GROUP handshake extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupType {
    /// No group type was selected.
    Undefined = 0,
    /// Broadcast mode duplicates each message across all active links.
    Broadcast = 1,
    /// Backup mode activates one link and fails over to a standby link.
    Backup = 2,
}

impl GroupType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Undefined),
            1 => Some(Self::Broadcast),
            2 => Some(Self::Backup),
            _ => None,
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

    /// Decode from a control packet.
    #[track_caller]
    pub fn decode(packet: &ControlPacket) -> Result<Self, Error> {
        if packet.control_type != ControlType::Handshake {
            return Err(Error::invalid_data("not a handshake packet"));
        }

        let mut buf = packet.control_info.as_slice();
        Error::check_buffer_size(48, buf)?; // Minimum size.

        let version = read_u32(&mut buf)?;
        let encryption_field = read_u16(&mut buf)?;
        let extension_field = read_u16(&mut buf)?;
        let initial_packet_seq = read_u32(&mut buf)? & 0x7FFF_FFFF;
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

        // Parse extensions.
        let mut extensions = Vec::new();
        while buf.len() >= 4 {
            let ext_type_raw = read_u16(&mut buf)?;
            let ext_len = read_u16(&mut buf)? as usize * 4; // In 4-byte units.

            if buf.len() < ext_len {
                break;
            }

            let ext_data = read_bytes(&mut buf, ext_len)?;

            if let Some(ext_type) = ExtensionType::from_u16(ext_type_raw) {
                extensions.push(HandshakeExtension {
                    ext_type,
                    data: ext_data,
                });
            }
        }

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
    }

    /// Get the HSREQ/HSRSP extension.
    pub fn get_hs_extension(&self) -> Option<HsExtensionData> {
        for ext in &self.extensions {
            if (ext.ext_type == ExtensionType::HsReq || ext.ext_type == ExtensionType::HsRsp)
                && ext.data.len() >= 12
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
        let packed = (u32::from(group.group_type as u8) << 24)
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

    /// Read the first valid libsrt-compatible GROUP extension.
    pub fn get_group_extension(&self) -> Option<GroupExtensionData> {
        for extension in &self.extensions {
            if extension.ext_type != ExtensionType::Group || extension.data.len() < 8 {
                continue;
            }

            let mut data = extension.data.as_slice();
            let group_id = read_u32(&mut data).ok()?;
            let packed = read_u32(&mut data).ok()?;
            let group_type = GroupType::from_u8((packed >> 24) as u8)?;

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
    }

    /// Add a KMRSP extension (success: returns the same KM message).
    pub fn add_km_response(&mut self, km_message: &KmMessage) {
        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::KmRsp,
            data: km_message.encode(),
        });
    }

    /// Add a KMRSP error extension (failure).
    pub fn add_km_error(&mut self, error: KmError) {
        let mut data = Vec::new();
        write_u32(&mut data, error as u32);
        self.extensions.push(HandshakeExtension {
            ext_type: ExtensionType::KmRsp,
            data,
        });
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
                        u32::from_be_bytes([ext.data[0], ext.data[1], ext.data[2], ext.data[3]]);
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
}

/// Encode a string as 32-bit little-endian words.
fn encode_le_words(s: &str, max_len: usize) -> Vec<u8> {
    let bytes = s.as_bytes();
    let len = bytes.len().min(max_len);
    let truncated = &bytes[..len];

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

/// Cipher.
#[expect(dead_code)]
pub mod cipher_type {
    /// AES-CTR
    pub const AES_CTR: u8 = 2;
    /// AES-GCM (v1.6.0 and later).
    pub const AES_GCM: u8 = 4;
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
    ) -> Self {
        Self {
            version: KM_VERSION,
            packet_type: KM_PACKET_TYPE,
            key_flag,
            keki: 0,
            cipher: cipher_type::AES_CTR,
            auth: 0,
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
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 16 {
            return Err(Error::invalid_data("KM message too short"));
        }

        let mut buf = data;

        // First 4 bytes.
        let first_byte = read_u8(&mut buf)?;
        let version = (first_byte >> 4) & 0x07;
        let packet_type = first_byte & 0x0F;

        let signature = read_u16(&mut buf)?;
        if signature != KM_SIGNATURE {
            return Err(Error::invalid_data(format!(
                "invalid KM signature: {signature:#06x}, expected {KM_SIGNATURE:#06x}"
            )));
        }

        let kk_byte = read_u8(&mut buf)?;
        let key_flag = KeyFlag::from_kk_field(kk_byte)
            .ok_or_else(|| Error::invalid_data("invalid KK field"))?;

        // KEKI
        let keki = read_u32(&mut buf)?;

        // Cipher, Auth, SE, Resv2
        let cipher = read_u8(&mut buf)?;
        let auth = read_u8(&mut buf)?;
        let stream_encapsulation = read_u8(&mut buf)?;
        let _resv2 = read_u8(&mut buf)?;

        // Resv3, SLen/4, KLen/4
        let _resv3 = read_u16(&mut buf)?;
        let slen_div4 = read_u8(&mut buf)? as usize;
        let klen_div4 = read_u8(&mut buf)? as usize;

        let slen = slen_div4 * 4;
        let klen = klen_div4 * 4;

        if slen != 16 {
            return Err(Error::invalid_data(format!(
                "unsupported salt length: {slen}"
            )));
        }

        let key_length = KeyLength::from_len(klen)
            .ok_or_else(|| Error::invalid_data(format!("invalid key length: {klen}")))?;

        // Salt
        if buf.len() < slen {
            return Err(Error::invalid_data("KM message too short for salt"));
        }
        let salt_bytes = read_bytes(&mut buf, slen)?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);

        // Wrapped Key (everything remaining).
        let wrapped_key = buf.to_vec();

        Ok(Self {
            version,
            packet_type,
            key_flag,
            keki,
            cipher,
            auth,
            stream_encapsulation,
            key_length,
            salt,
            wrapped_key,
        })
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
    let crate::SrtPacket::Control(control) = crate::SrtPacket::decode(datagram).ok()? else {
        return None;
    };
    HandshakePacket::decode(&control).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            extensions: Vec::new(),
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

        let original = KmMessage::new(KeyFlag::Even, KeyLength::Aes128, salt, wrapped_key.clone());

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

        let km_message = KmMessage::new(KeyFlag::Even, KeyLength::Aes128, salt, wrapped_key);

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
        hs.add_km_error(KmError::BadSecret);

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
        let hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        hs.add_congestion_extension("live");
        assert_eq!(
            hs.extension_field & extension_flags::CONFIG,
            extension_flags::CONFIG
        );
    }

    #[test]
    fn test_sid_extension_access_control() {
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        hs.add_sid_extension(&long_sid);

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded.get_sid_extension();
        assert_eq!(sid, Some(long_sid));
    }

    #[test]
    fn test_sid_extension_empty() {
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let sid = decoded.get_sid_extension();
        assert!(sid.is_none());
    }

    #[test]
    fn test_congestion_extension_live() {
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
        hs.add_congestion_extension("file");

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let cc = decoded.get_congestion_extension();
        assert_eq!(cc, Some("file".to_string()));
    }

    #[test]
    fn test_no_congestion_extension() {
        let hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);

        let packet = hs.encode(1000, 0);
        let decoded = HandshakePacket::decode(&packet)
            .expect("decoding an encoded handshake packet should succeed");

        let cc = decoded.get_congestion_extension();
        assert!(cc.is_none());
    }

    #[test]
    fn test_congestion_extension_with_sid() {
        // Use the Congestion extension and the SID extension together.
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
        let mut hs = HandshakePacket::new_conclusion_request(1, 2, 3, 0, false);
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
}
