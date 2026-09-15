//! Explicit byte-oriented compatibility helpers.

use crate::identity::{GroupAffinity, HandshakeIdentity, handshake_identity_from_handshake};
use srt_proto::handshake::{GroupExtensionData, peek_handshake};

/// Extract the handshake phase and optional GROUP affinity from one datagram.
#[must_use]
pub fn handshake_route(packet: &[u8]) -> Option<(bool, Option<GroupAffinity>)> {
    let identity = handshake_identity(packet)?;
    Some((identity.is_conclusion, identity.group))
}

/// Decode the StreamID and GROUP identity from a handshake datagram.
#[must_use]
pub fn handshake_identity(packet: &[u8]) -> Option<HandshakeIdentity> {
    // Decoding is the codec crate's job; this function's business is
    // turning a handshake into routing identity.
    let handshake = peek_handshake(packet)?;
    Some(handshake_identity_from_handshake(&handshake))
}

/// Convenience for callers that only need GROUP metadata from a datagram.
#[must_use]
pub fn group_extension_from_packet(packet: &[u8]) -> Option<(GroupExtensionData, Option<String>)> {
    let (_, affinity) = handshake_route(packet)?;
    let affinity = affinity?;
    Some((affinity.extension, affinity.stream_id))
}
