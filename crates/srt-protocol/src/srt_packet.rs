//! Common SRT packet structures.
//!
//! SRT packets are sent as UDP payloads. The F bit (the top bit) distinguishes
//! data packets (0) from control packets (1).

use crate::buf::{read_u32, write_bytes, write_u32};
use crate::error::Error;

/// The minimum SRT packet header size (16 bytes).
pub const SRT_HEADER_SIZE: usize = 16;

/// Packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Data packet (F=0).
    Data,
    /// Control packet (F=1).
    Control,
}

impl PacketType {
    /// Determine the packet type from the first 32 bits.
    pub fn from_first_word(word: u32) -> Self {
        if word & 0x8000_0000 != 0 {
            PacketType::Control
        } else {
            PacketType::Data
        }
    }
}

/// An SRT packet (data or control).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrtPacket {
    /// A data packet.
    Data(DataPacket),
    /// A control packet.
    Control(ControlPacket),
}

impl SrtPacket {
    /// Decode from a byte slice.
    #[track_caller]
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        Error::check_buffer_size(SRT_HEADER_SIZE, buf)?;

        let mut slice = buf;
        let first_word = read_u32(&mut slice)?;

        if PacketType::from_first_word(first_word) == PacketType::Data {
            // Decode as a data packet.
            DataPacket::decode_with_first_word(first_word, buf).map(SrtPacket::Data)
        } else {
            // Decode as a control packet.
            ControlPacket::decode_with_first_word(first_word, buf).map(SrtPacket::Control)
        }
    }

    /// Encode to a byte buffer.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            SrtPacket::Data(pkt) => pkt.encode(buf),
            SrtPacket::Control(pkt) => pkt.encode(buf),
        }
    }
}

/// Read the destination SRT Socket ID from a complete SRT header.
///
/// Applications multiplexing SRT connections over a shared UDP socket use
/// this field to select the receiving physical leg before passing the packet
/// to that leg's protocol state machine. This only inspects the fixed header;
/// it does not decode or copy a payload.
pub fn peek_destination_socket_id(buf: &[u8]) -> Result<u32, Error> {
    Error::check_buffer_size(SRT_HEADER_SIZE, buf)?;
    Ok(u32::from_be_bytes(
        buf[12..16].try_into().expect("fixed header slice"),
    ))
}

/// Packet position flag (PP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketPosition {
    /// The first packet of a message (10b).
    First = 0b10,
    /// A middle packet of a message (00b).
    Middle = 0b00,
    /// The last packet of a message (01b).
    Last = 0b01,
    /// The whole message in a single packet (11b).
    #[default]
    Single = 0b11,
}

impl PacketPosition {
    /// Get the value from a PP field.
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b10 => Self::First,
            0b00 => Self::Middle,
            0b01 => Self::Last,
            0b11 => Self::Single,
            _ => unreachable!(),
        }
    }

    /// Convert to a PP field value.
    pub fn to_bits(self) -> u8 {
        self as u8
    }
}

/// A data packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    /// Packet sequence number (31 bits).
    pub sequence_number: u32,
    /// Packet position flag (PP, 2 bits).
    pub position: PacketPosition,
    /// Order flag (O, 1 bit).
    pub order_flag: bool,
    /// Encryption key flag (KK, 2 bits).
    /// 00b: unencrypted, 01b: even key, 10b: odd key.
    pub encryption_flag: u8,
    /// Retransmitted flag (R, 1 bit).
    pub retransmitted: bool,
    /// Message number (26 bits).
    pub message_number: u32,
    /// Timestamp (microseconds).
    pub timestamp: u32,
    /// Destination socket ID.
    pub dest_socket_id: u32,
    /// Payload.
    pub payload: Vec<u8>,
}

impl DataPacket {
    /// Create a new data packet.
    pub fn new(
        sequence_number: u32,
        message_number: u32,
        timestamp: u32,
        dest_socket_id: u32,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            sequence_number: sequence_number & 0x7FFF_FFFF,
            position: PacketPosition::Single,
            order_flag: false,
            encryption_flag: 0,
            retransmitted: false,
            message_number: message_number & 0x03FF_FFFF,
            timestamp,
            dest_socket_id,
            payload,
        }
    }

    /// Decode from a byte slice, given the already-read first 32 bits.
    #[track_caller]
    fn decode_with_first_word(first_word: u32, buf: &[u8]) -> Result<Self, Error> {
        Error::check_buffer_size(SRT_HEADER_SIZE, buf)?;

        let mut slice = &buf[4..]; // Skip the first 4 bytes.

        let sequence_number = first_word & 0x7FFF_FFFF;

        let second_word = read_u32(&mut slice)?;
        let position = PacketPosition::from_bits(((second_word >> 30) & 0b11) as u8);
        let order_flag = (second_word >> 29) & 1 != 0;
        let encryption_flag = ((second_word >> 27) & 0b11) as u8;
        let retransmitted = (second_word >> 26) & 1 != 0;
        let message_number = second_word & 0x03FF_FFFF;

        let timestamp = read_u32(&mut slice)?;
        let dest_socket_id = read_u32(&mut slice)?;

        let payload = slice.to_vec();

        Ok(Self {
            sequence_number,
            position,
            order_flag,
            encryption_flag,
            retransmitted,
            message_number,
            timestamp,
            dest_socket_id,
            payload,
        })
    }

    /// Encode to a byte buffer.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        // First word: F=0, sequence_number
        let first_word = self.sequence_number & 0x7FFF_FFFF;
        write_u32(buf, first_word);

        // Second word: PP, O, KK, R, message_number
        let second_word = ((self.position.to_bits() as u32) << 30)
            | ((self.order_flag as u32) << 29)
            | ((self.encryption_flag as u32 & 0b11) << 27)
            | ((self.retransmitted as u32) << 26)
            | (self.message_number & 0x03FF_FFFF);
        write_u32(buf, second_word);

        write_u32(buf, self.timestamp);
        write_u32(buf, self.dest_socket_id);
        write_bytes(buf, &self.payload);
    }

    /// Get the encoded size.
    pub fn encoded_size(&self) -> usize {
        SRT_HEADER_SIZE + self.payload.len()
    }

    /// Build the 16-byte header used as AAD for AES-GCM.
    ///
    /// Matches the SRT data packet header layout in network byte order,
    /// with the retransmit flag (R) forced to zero — it can differ between
    /// the original send and a retransmission.
    pub fn gcm_aad(&self) -> [u8; 16] {
        let first_word = self.sequence_number & 0x7FFF_FFFF;
        let second_word = ((self.position.to_bits() as u32) << 30)
            | ((self.order_flag as u32) << 29)
            | ((self.encryption_flag as u32 & 0b11) << 27)
            // R bit forced to 0
            | (self.message_number & 0x03FF_FFFF);
        let mut aad = [0u8; 16];
        aad[0..4].copy_from_slice(&first_word.to_be_bytes());
        aad[4..8].copy_from_slice(&second_word.to_be_bytes());
        aad[8..12].copy_from_slice(&self.timestamp.to_be_bytes());
        aad[12..16].copy_from_slice(&self.dest_socket_id.to_be_bytes());
        aad
    }
}

/// Header metadata for a packet about to be encoded to wire format.
///
/// Carries every field the 16-byte SRT data header needs *except*
/// `encryption_flag`, which is determined by the crypto layer after
/// the header is created.  The payload travels separately as `Bytes`
/// so the wire buffer can be built with a single payload copy.
#[derive(Debug, Clone)]
pub struct DataHeader {
    pub sequence_number: u32,
    pub position: PacketPosition,
    pub order_flag: bool,
    pub retransmitted: bool,
    pub message_number: u32,
    pub timestamp: u32,
    pub dest_socket_id: u32,
}

impl DataHeader {
    /// Write the 16-byte header into `buf`.
    pub fn write_header(&self, buf: &mut [u8; SRT_HEADER_SIZE], encryption_flag: u8) {
        let first_word = self.sequence_number & 0x7FFF_FFFF;
        let second_word = ((self.position.to_bits() as u32) << 30)
            | ((self.order_flag as u32) << 29)
            | ((encryption_flag as u32 & 0b11) << 27)
            | ((self.retransmitted as u32) << 26)
            | (self.message_number & 0x03FF_FFFF);
        buf[0..4].copy_from_slice(&first_word.to_be_bytes());
        buf[4..8].copy_from_slice(&second_word.to_be_bytes());
        buf[8..12].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[12..16].copy_from_slice(&self.dest_socket_id.to_be_bytes());
    }

    /// Build the 16-byte GCM AAD (R bit forced to 0).
    pub fn gcm_aad(&self, encryption_flag: u8) -> [u8; 16] {
        let first_word = self.sequence_number & 0x7FFF_FFFF;
        let second_word = ((self.position.to_bits() as u32) << 30)
            | ((self.order_flag as u32) << 29)
            | ((encryption_flag as u32 & 0b11) << 27)
            | (self.message_number & 0x03FF_FFFF);
        let mut aad = [0u8; 16];
        aad[0..4].copy_from_slice(&first_word.to_be_bytes());
        aad[4..8].copy_from_slice(&second_word.to_be_bytes());
        aad[8..12].copy_from_slice(&self.timestamp.to_be_bytes());
        aad[12..16].copy_from_slice(&self.dest_socket_id.to_be_bytes());
        aad
    }
}

/// Control packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ControlType {
    /// Handshake.
    Handshake = 0x0000,
    /// Keepalive.
    Keepalive = 0x0001,
    /// ACK (acknowledgment).
    Ack = 0x0002,
    /// NAK (loss report).
    Nak = 0x0003,
    /// Congestion warning.
    CongestionWarning = 0x0004,
    /// Shutdown.
    Shutdown = 0x0005,
    /// ACKACK.
    AckAck = 0x0006,
    /// Drop request.
    DropReq = 0x0007,
    /// Peer error.
    PeerError = 0x0008,
    /// User-defined.
    UserDefined = 0x7FFF,
}

impl ControlType {
    /// Get the `ControlType` for a value.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::Handshake),
            0x0001 => Some(Self::Keepalive),
            0x0002 => Some(Self::Ack),
            0x0003 => Some(Self::Nak),
            0x0004 => Some(Self::CongestionWarning),
            0x0005 => Some(Self::Shutdown),
            0x0006 => Some(Self::AckAck),
            0x0007 => Some(Self::DropReq),
            0x0008 => Some(Self::PeerError),
            0x7FFF => Some(Self::UserDefined),
            _ => None,
        }
    }
}

/// A control packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    /// Control type (15 bits).
    pub control_type: ControlType,
    /// Subtype (16 bits).
    pub subtype: u16,
    /// Type-specific information (32 bits).
    pub type_specific_info: u32,
    /// Timestamp (microseconds).
    pub timestamp: u32,
    /// Destination socket ID.
    pub dest_socket_id: u32,
    /// Control Information Field (CIF).
    pub control_info: Vec<u8>,
}

impl ControlPacket {
    /// Create a new control packet.
    pub fn new(control_type: ControlType, timestamp: u32, dest_socket_id: u32) -> Self {
        Self {
            control_type,
            subtype: 0,
            type_specific_info: 0,
            timestamp,
            dest_socket_id,
            control_info: Vec::new(),
        }
    }

    /// Decode from a byte slice, given the already-read first 32 bits.
    #[track_caller]
    fn decode_with_first_word(first_word: u32, buf: &[u8]) -> Result<Self, Error> {
        Error::check_buffer_size(SRT_HEADER_SIZE, buf)?;

        let mut slice = &buf[4..]; // Skip the first 4 bytes.

        let control_type_raw = ((first_word >> 16) & 0x7FFF) as u16;
        let control_type = ControlType::from_u16(control_type_raw).ok_or_else(|| {
            Error::invalid_data(format!("unknown control type: {control_type_raw:#x}"))
        })?;
        let subtype = (first_word & 0xFFFF) as u16;

        let type_specific_info = read_u32(&mut slice)?;
        let timestamp = read_u32(&mut slice)?;
        let dest_socket_id = read_u32(&mut slice)?;

        let control_info = slice.to_vec();

        Ok(Self {
            control_type,
            subtype,
            type_specific_info,
            timestamp,
            dest_socket_id,
            control_info,
        })
    }

    /// Encode to a byte buffer.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        // First word: F=1, control_type, subtype
        let first_word = 0x8000_0000
            | ((self.control_type as u32 & 0x7FFF) << 16)
            | (self.subtype as u32 & 0xFFFF);
        write_u32(buf, first_word);

        write_u32(buf, self.type_specific_info);
        write_u32(buf, self.timestamp);
        write_u32(buf, self.dest_socket_id);
        write_bytes(buf, &self.control_info);
    }

    /// Get the encoded size.
    pub fn encoded_size(&self) -> usize {
        SRT_HEADER_SIZE + self.control_info.len()
    }
}

/// Compare sequence numbers, wraparound-aware (31-bit).
pub(crate) fn sequence_less_than(a: u32, b: u32) -> bool {
    let diff = b.wrapping_sub(a) & 0x7FFF_FFFF;
    diff > 0 && diff < 0x4000_0000
}

/// Compare sequence numbers, wraparound-aware (31-bit).
pub(crate) fn sequence_greater_than(a: u32, b: u32) -> bool {
    sequence_less_than(b, a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_packet_encode_decode() {
        let original = DataPacket {
            sequence_number: 12345,
            position: PacketPosition::Single,
            order_flag: true,
            encryption_flag: 0b10,
            retransmitted: false,
            message_number: 100,
            timestamp: 1000000,
            dest_socket_id: 0x12345678,
            payload: b"Hello, SRT!".to_vec(),
        };

        let mut buf = Vec::new();
        original.encode(&mut buf);

        let decoded =
            match SrtPacket::decode(&buf).expect("decoding an encoded packet should succeed") {
                SrtPacket::Data(pkt) => pkt,
                _ => panic!("expected data packet"),
            };

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_control_packet_encode_decode() {
        let original = ControlPacket {
            control_type: ControlType::Ack,
            subtype: 0,
            type_specific_info: 42,
            timestamp: 2000000,
            dest_socket_id: 0xABCDEF01,
            control_info: vec![1, 2, 3, 4],
        };

        let mut buf = Vec::new();
        original.encode(&mut buf);

        let decoded =
            match SrtPacket::decode(&buf).expect("decoding an encoded packet should succeed") {
                SrtPacket::Control(pkt) => pkt,
                _ => panic!("expected control packet"),
            };

        assert_eq!(original, decoded);
    }

    #[test]
    fn peek_destination_socket_id_reads_the_fixed_header_only() {
        let packet = ControlPacket {
            control_type: ControlType::Ack,
            subtype: 0,
            type_specific_info: 0,
            timestamp: 0,
            dest_socket_id: 0xABCD_1234,
            control_info: vec![0; 1500],
        };
        let mut bytes = Vec::new();
        packet.encode(&mut bytes);
        assert_eq!(
            peek_destination_socket_id(&bytes).expect("complete header"),
            0xABCD_1234
        );
        assert!(peek_destination_socket_id(&bytes[..15]).is_err());
    }

    #[test]
    fn test_packet_position() {
        assert_eq!(PacketPosition::from_bits(0b10), PacketPosition::First);
        assert_eq!(PacketPosition::from_bits(0b00), PacketPosition::Middle);
        assert_eq!(PacketPosition::from_bits(0b01), PacketPosition::Last);
        assert_eq!(PacketPosition::from_bits(0b11), PacketPosition::Single);
    }
}
