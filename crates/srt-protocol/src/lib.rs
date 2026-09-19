pub(crate) mod adaptive_receiver_packet_window;
pub(crate) mod sender_packet_window;

#[allow(dead_code)]
mod buf;
#[path = "crypto.rs"]
mod crypto_impl;
mod error;
mod message_assembler;
mod sender_rto;
mod srt_connection;
mod srt_group;
mod srt_handshake;
mod srt_packet;
mod srt_receiver;
mod srt_sender;
mod stats;
pub mod stream_id;
mod time;

/// Supported sender-side SRT protocol component APIs.
pub mod sender {
    pub use super::sender_rto::{COMM_SYN_MICROS, MAX_RTO_MICROS, RtoArm, SenderRto};
    pub use super::srt_sender::{
        DEFAULT_MAX_BANDWIDTH_BYTES_PER_SEC, DroppedMessage, InvalidNak, SenderBuffer, SenderStats,
    };
}

/// Supported receiver-side SRT protocol component APIs.
pub mod receiver {
    pub use super::srt_receiver::{
        ACK_INTERVAL_MICROS, AckPacket, DropRangeSummary, HIGH_FANIN_ACK_INTERVAL_MICROS,
        HIGH_FANIN_LIGHT_ACK_INTERVAL_PACKETS, LIGHT_ACK_INTERVAL_PACKETS, LossRange,
        MAX_ACK_INTERVAL_MICROS, MAX_LIGHT_ACK_INTERVAL_PACKETS, MIN_ACK_INTERVAL_MICROS,
        MIN_LIGHT_ACK_INTERVAL_PACKETS, NakPacket, ReceiverBuffer, ReceiverStats,
        clamp_ack_interval_micros, clamp_light_ack_interval_packets,
    };
}

/// Supported handshake and extension protocol component APIs.
pub mod handshake {
    pub use super::srt_handshake::{
        DEFAULT_FLOW_WINDOW, DEFAULT_MTU, ExtensionType, GFLAG_SYNCONMSG, GroupExtensionData,
        GroupType, HS_VERSION_4, HS_VERSION_5, HandshakeExtension, HandshakePacket, HandshakeState,
        HandshakeType, HsExtensionData, KmError, KmMessage, MAX_FLOW_WINDOW, SRTGROUP_MASK,
        extension_flags, peek_handshake, srt_flags,
    };
}

/// Supported key-management and encryption protocol component APIs.
pub mod crypto {
    pub use super::crypto_impl::{
        CipherMode, CryptoContext, GCM_TAG_LEN, KeyFlag, KeyLength, KmRefreshState, TxCryptoStamp,
    };
}

/// Supported SRT wire-model APIs. Untyped cursor helpers remain behind the
/// opt-in `raw-codec` feature at the crate root.
pub mod wire {
    pub use super::srt_packet::{
        ControlPacket, ControlType, DataHeader, DataPacket, MAX_DATAGRAM_SIZE, PacketPosition,
        PacketType, SRT_HEADER_SIZE, SrtPacket, peek_destination_socket_id,
    };
}

/// Supported bonded-group protocol component APIs.
pub mod group {
    pub use super::srt_group::{
        GroupDataPoll, GroupEvent, GroupMemberState, GroupMode, GroupPacket, MAX_GROUP_MEMBERS,
        PeerGroupCollision, SrtGroup, SrtGroupMember,
    };
}

#[cfg(feature = "raw-codec")]
pub use buf::{
    read_bytes, read_u8, read_u16, read_u32, read_u64, read_utf8, write_bytes, write_u8, write_u16,
    write_u32, write_u64,
};

pub use error::{Error, ErrorKind};
pub use srt_connection::{
    ConnectionEvent, ConnectionOptions, ConnectionOutput, ConnectionRole, ConnectionState,
    DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS, DEFAULT_HANDSHAKE_TIMEOUT_MICROS, DisconnectReason,
    FULL_ACK_CONTROL_INFO_BYTES, KEEPALIVE_INTERVAL_MICROS, LIBSRT_COMPAT_PADDING_BYTES,
    LIGHT_ACK_CONTROL_INFO_BYTES, MAX_EVENT_QUEUE_ACTIONS, MAX_OUTPUT_QUEUE_ACTIONS,
    MAX_OUTPUT_QUEUE_BYTES, MIN_FLOW_WINDOW_PACKETS, NAK_RANGE_BYTES, OutputInto, OutputMeta,
    PERIODIC_NAK_INTERVAL_MICROS, SrtConnection, TimerId,
};
pub use srt_group::{
    GroupDataPoll, GroupEvent, GroupMemberState, GroupMode, MAX_GROUP_MEMBERS, PeerGroupCollision,
    SrtGroup,
};
pub use srt_packet::DatagramClass;
pub use stats::{
    ConnectionStats, ConnectionStatsInterval, CounterDelta, ReceiverStatsInterval,
    SenderStatsInterval,
};
pub use time::Timestamp;

pub use bytes::Bytes;
