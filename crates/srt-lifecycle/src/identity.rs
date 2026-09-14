//! Runtime-neutral lifecycle identity and routing policy.

use shiguredo_srt::handshake::{GroupExtensionData, HandshakePacket, HandshakeType};

/// Group metadata observed during handshake admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAffinity {
    pub group_id: u32,
    pub stream_id: Option<String>,
    pub extension: GroupExtensionData,
}

/// Caller-claimed handshake identity available before the protocol core
/// processes CONCLUSION. These fields are routing/admission input, not proof of
/// peer identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeIdentity {
    pub is_conclusion: bool,
    pub stream_id: Option<String>,
    pub group: Option<GroupAffinity>,
    /// The SYN cookie carried by this datagram. On a CONCLUSION this is
    /// the value the listener issued during INDUCTION and the caller
    /// echoed back, which makes it the one field on the wire that can
    /// carry listener-chosen routing information through the handshake.
    /// See [`crate::cookie::cookie_for_worker`].
    pub syn_cookie: u32,
}

impl GroupAffinity {
    /// Return the stable logical identity used to keep all physical legs on
    /// one worker. The wire StreamID is normalized only at this boundary.
    #[must_use]
    pub fn logical_key(&self) -> LogicalGroupKey {
        LogicalGroupKey {
            group_id: self.group_id,
            stream_id: normalize_stream_id(self.stream_id.clone()),
        }
    }
}

/// Stable identity for one logical bonded publisher.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogicalGroupKey {
    pub group_id: u32,
    pub stream_id: Option<String>,
}

/// Normalize a wire StreamID for logical group affinity.
#[must_use]
pub fn normalize_stream_id(stream_id: Option<String>) -> Option<String> {
    stream_id.and_then(|stream_id| {
        let normalized = stream_id.trim_matches('\0').trim().to_string();
        (!normalized.is_empty()).then_some(normalized)
    })
}

/// Extract routing identity from an already decoded handshake.
///
/// Admission code uses this form so the same untrusted datagram is decoded
/// once before cookie validation, policy resolution, and protocol processing.
#[must_use]
pub fn handshake_identity_from_handshake(handshake: &HandshakePacket) -> HandshakeIdentity {
    let is_conclusion = matches!(handshake.handshake_type, HandshakeType::Conclusion);
    let stream_id = handshake.get_sid_extension();
    let group = handshake
        .get_group_extension()
        .map(|extension| GroupAffinity {
            group_id: extension.group_id,
            stream_id: stream_id.clone(),
            extension,
        });
    HandshakeIdentity {
        is_conclusion,
        stream_id,
        group,
        syn_cookie: handshake.syn_cookie,
    }
}
