//! Transport-layer destination-aware final-storage sink for outgoing datagrams.
//!
//! # Why the contract is reserve-then-commit
//!
//! The protocol's direct-output path materializes a queued datagram straight
//! into caller-owned storage (`SrtConnection::poll_output_into`). That call
//! consumes the protocol output when it succeeds, so any sink that could still
//! fail *after* the bytes were written would silently lose an already-consumed
//! datagram.
//!
//! The trait is therefore shaped so that cannot happen by construction:
//!
//! ```text
//! acquire -> Ok(None)          : final storage unavailable; protocol output untouched
//! acquire -> Err(_)            : sink refuses this datagram; protocol output untouched
//! acquire -> Ok(Some(slot))    : final transport capacity is now reserved
//! slot.bytes_mut()             : the only way to fill the reserved storage
//! SrtConnection::poll_output_into(bytes) -> Ok : protocol output consumed exactly once
//! slot.commit(len)             : infallible ownership transfer
//! ```
//!
//! There is no post-materialization `Err` and no post-materialization
//! `Exhausted`: every fallible capacity/reservation decision happens in
//! [`DatagramSink::acquire`], before the protocol is touched.

use std::net::SocketAddr;

use crate::admission::LogicalPeerId;
use crate::caller::LogicalCallerId;

/// Which identity space a [`TxAttribution`] id belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TxAttributionKind {
    /// No attribution: the sink was not told which logical session this
    /// datagram belongs to (compatibility sinks, tests, simple endpoints).
    #[default]
    Unattributed,
    /// Id space of [`LogicalCallerId`] (outbound/direct callers and their
    /// bonded groups).
    Caller,
    /// Id space of [`LogicalPeerId`] (admitted publishers and their bonded
    /// groups).
    Peer,
}

/// Opaque transport-level attribution for one submitted datagram.
///
/// A `SocketAddr` is not an identity in a shared SRT Owner: several logical
/// sessions and group legs can share one remote UDP endpoint, and SRT routing
/// distinguishes them by socket/group identity. This token is minted by
/// srt-transport when the datagram is offered, travels with the reservation
/// through the TX pool and the in-flight metadata, and comes back on the
/// completion, so a failure can name the exact logical session and physical
/// leg.
///
/// It is deliberately opaque: the embedding application maps it onto its own
/// objects and never interprets the bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TxAttribution {
    kind: TxAttributionKind,
    id: u64,
    leg: u32,
}

impl TxAttribution {
    /// No attribution.
    pub const UNATTRIBUTED: Self = Self {
        kind: TxAttributionKind::Unattributed,
        id: 0,
        leg: 0,
    };

    /// Attribute to one logical caller, optionally naming its physical leg
    /// (`0` for a direct caller with a single leg).
    #[must_use]
    pub fn caller(id: LogicalCallerId, leg: u32) -> Self {
        Self {
            kind: TxAttributionKind::Caller,
            id: id.as_u64(),
            leg,
        }
    }

    /// Attribute to one logical peer, optionally naming its physical leg.
    #[must_use]
    pub fn peer(id: LogicalPeerId, leg: u32) -> Self {
        Self {
            kind: TxAttributionKind::Peer,
            id: id.as_u64(),
            leg,
        }
    }

    /// Which identity space this token belongs to.
    #[must_use]
    pub fn kind(self) -> TxAttributionKind {
        self.kind
    }

    /// The logical caller this datagram belongs to, if it was a caller.
    #[must_use]
    pub fn caller_id(self) -> Option<LogicalCallerId> {
        (self.kind == TxAttributionKind::Caller).then(|| LogicalCallerId::from_raw(self.id))
    }

    /// The logical peer this datagram belongs to, if it was a peer.
    #[must_use]
    pub fn peer_id(self) -> Option<LogicalPeerId> {
        (self.kind == TxAttributionKind::Peer).then(|| LogicalPeerId::from_raw(self.id))
    }

    /// Physical leg index inside the logical session (`0` for a direct
    /// single-leg session).
    #[must_use]
    pub fn leg(self) -> u32 {
        self.leg
    }

    /// Whether anything was attributed at all.
    #[must_use]
    pub fn is_attributed(self) -> bool {
        self.kind != TxAttributionKind::Unattributed
    }
}

/// A protocol materialization failure: `poll_output_into` refused to produce
/// the peeked datagram.
///
/// This is NOT "nothing to send". The protocol output stays queued in the
/// connection, so the affected session/leg is quarantined and this event is
/// the observable, attributed record of why. One event is produced per
/// affected leg, which is what keeps the path bounded: a quarantined leg is
/// never re-offered, so it cannot re-report the same failure forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolOutputFailure {
    /// Logical session and physical leg the failure belongs to.
    pub attribution: TxAttribution,
    /// Typed protocol error kind.
    pub kind: srt_proto::ErrorKind,
    /// The protocol's own reason string.
    pub reason: String,
}

/// Bounded queue of [`ProtocolOutputFailure`]s awaiting application drain.
///
/// Preallocated and finite: a full queue drops the NEWEST event and counts it,
/// because the oldest events are the ones the application has not acted on yet.
#[derive(Debug)]
pub(crate) struct ProtocolOutputFailureQueue {
    events: std::collections::VecDeque<ProtocolOutputFailure>,
    capacity: usize,
    dropped: u64,
}

/// Capacity of one table's protocol-output failure queue.
pub(crate) const PROTOCOL_OUTPUT_FAILURE_CAPACITY: usize = 64;

impl ProtocolOutputFailureQueue {
    pub(crate) fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            events: std::collections::VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, event: ProtocolOutputFailure) {
        if self.events.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.events.push_back(event);
    }

    /// Move up to `max_events` failures into `out`, oldest first.
    pub(crate) fn drain_into(&mut self, max_events: usize, out: &mut Vec<ProtocolOutputFailure>) {
        for _ in 0..max_events {
            let Some(event) = self.events.pop_front() else {
                break;
            };
            out.push(event);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// One destination offer: where the datagram goes, and what it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramTarget {
    /// Wire destination.
    pub peer: SocketAddr,
    /// Logical identity of the session/leg this datagram belongs to.
    pub attribution: TxAttribution,
}

impl DatagramTarget {
    /// A target with no logical attribution.
    #[must_use]
    pub fn unattributed(peer: SocketAddr) -> Self {
        Self {
            peer,
            attribution: TxAttribution::UNATTRIBUTED,
        }
    }
}

/// What a sink did with one datagram offer, as reported by the bounded drain
/// paths. Fixed-cost and `Copy`, so it never allocates to observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SinkOutcome {
    /// No datagram was offered in this visit.
    #[default]
    None,
    /// The sink accepted the datagram and now owns the committed storage.
    Accepted,
    /// The sink had no capacity; the protocol output is untouched.
    Unavailable,
    /// The sink refused the datagram before materialization; the protocol
    /// output is untouched and `sink_error_kind` says why.
    Rejected,
}

/// Final storage reserved for exactly one datagram.
///
/// A slot is produced by [`DatagramSink::acquire`] and either committed after
/// successful materialization or dropped (releasing the reservation) if the
/// protocol produced nothing.
pub trait DatagramSlot {
    /// The reserved storage. Its length is at least the `wire_len` that was
    /// passed to `acquire`.
    fn bytes_mut(&mut self) -> &mut [u8];

    /// Transfer ownership of the materialized datagram. Infallible by
    /// construction: this is the point of no return, not a second validation
    /// step.
    fn commit(self, len: usize);
}

/// A transport-layer destination-aware final-storage sink for outgoing datagrams.
pub trait DatagramSink {
    /// Storage reserved by [`Self::acquire`].
    type Slot<'a>: DatagramSlot
    where
        Self: 'a;

    /// Reserve final storage for one datagram of `wire_len` bytes.
    ///
    /// * `Ok(Some(slot))` -- capacity is now reserved; the caller materializes
    ///   into `slot.bytes_mut()` and then `commit`s.
    /// * `Ok(None)` -- the sink has no capacity this visit (bounded pool
    ///   exhausted, in-flight limit reached). The protocol output is untouched
    ///   and the caller may retry on a later visit.
    /// * `Err(_)` -- this sink refuses the datagram itself (for example the
    ///   required wire length exceeds the sink's configured ceiling). The
    ///   protocol output is untouched; the error is surfaced through the
    ///   bounded drain result rather than swallowed.
    fn acquire(
        &mut self,
        peer: SocketAddr,
        wire_len: usize,
    ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error>;

    /// Reserve final storage for one datagram that carries logical identity.
    ///
    /// The high-density tables call this so the reservation, the in-flight
    /// metadata and every completion report the same
    /// [`TxAttribution`]. Sinks that have nowhere to keep it ignore it, which
    /// is why this has a default implementation rather than a second sink
    /// trait.
    fn acquire_target(
        &mut self,
        target: DatagramTarget,
        wire_len: usize,
    ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
        self.acquire(target.peer, wire_len)
    }
}

/// Compatibility sink: an unbounded `Vec` of already-materialized datagrams.
///
/// Kept for simple endpoints, tests, and adapters that hand the datagrams to a
/// syscall themselves. The high-density shared Owner does not use it.
impl DatagramSink for Vec<(SocketAddr, Vec<u8>)> {
    type Slot<'a> = VecSlot<'a>;

    fn acquire(
        &mut self,
        peer: SocketAddr,
        wire_len: usize,
    ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
        Ok(Some(VecSlot {
            out: self,
            peer,
            buf: vec![0u8; wire_len],
        }))
    }
}

/// [`DatagramSink`] slot for the `Vec` compatibility sink.
pub struct VecSlot<'a> {
    out: &'a mut Vec<(SocketAddr, Vec<u8>)>,
    peer: SocketAddr,
    buf: Vec<u8>,
}

impl DatagramSlot for VecSlot<'_> {
    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    fn commit(self, len: usize) {
        let mut buf = self.buf;
        buf.truncate(len);
        self.out.push((self.peer, buf));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink with finite capacity, used to prove the acquire/commit ordering
    /// the contract depends on.
    struct FiniteSink {
        capacity: usize,
        pushed: Vec<(SocketAddr, Vec<u8>)>,
    }

    struct FiniteSlot<'a> {
        sink: &'a mut FiniteSink,
        peer: SocketAddr,
        buf: Vec<u8>,
    }

    impl DatagramSlot for FiniteSlot<'_> {
        fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.buf
        }

        fn commit(self, len: usize) {
            let mut buf = self.buf;
            buf.truncate(len);
            self.sink.pushed.push((self.peer, buf));
        }
    }

    impl DatagramSink for FiniteSink {
        type Slot<'a> = FiniteSlot<'a>;

        fn acquire(
            &mut self,
            peer: SocketAddr,
            wire_len: usize,
        ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
            if self.pushed.len() >= self.capacity {
                return Ok(None);
            }
            Ok(Some(FiniteSlot {
                sink: self,
                peer,
                buf: vec![0u8; wire_len],
            }))
        }
    }

    /// A sink that refuses one specific wire length before reserving anything.
    struct CeilingSink {
        ceiling: usize,
    }

    impl DatagramSink for CeilingSink {
        type Slot<'a> = VecSlot<'a>;

        fn acquire(
            &mut self,
            _peer: SocketAddr,
            wire_len: usize,
        ) -> Result<Option<Self::Slot<'_>>, srt_proto::Error> {
            if wire_len > self.ceiling {
                return Err(srt_proto::Error::with_reason(
                    srt_proto::ErrorKind::InvalidData,
                    "datagram exceeds the sink ceiling",
                ));
            }
            Ok(None)
        }
    }

    #[test]
    fn exhausted_acquire_reserves_nothing() {
        let mut sink = FiniteSink {
            capacity: 1,
            pushed: Vec::new(),
        };
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let mut slot = sink.acquire(peer, 4).unwrap().expect("capacity available");
        slot.bytes_mut()[..4].copy_from_slice(b"test");
        slot.commit(4);
        assert_eq!(sink.pushed.len(), 1);

        assert!(
            sink.acquire(peer, 4).unwrap().is_none(),
            "a full sink must report unavailability without reserving storage"
        );
    }

    #[test]
    fn refusing_acquire_reports_a_typed_error() {
        let mut sink = CeilingSink { ceiling: 16 };
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let error = sink
            .acquire(peer, 17)
            .err()
            .expect("an oversized datagram must be refused before materialization");
        assert_eq!(error.kind, srt_proto::ErrorKind::InvalidData);
    }

    #[test]
    fn dropping_a_slot_releases_the_reservation() {
        let mut sink = FiniteSink {
            capacity: 1,
            pushed: Vec::new(),
        };
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        drop(sink.acquire(peer, 4).unwrap().expect("capacity available"));
        assert!(sink.pushed.is_empty(), "an uncommitted slot stores nothing");
        assert!(
            sink.acquire(peer, 4).unwrap().is_some(),
            "dropping a slot must release its capacity"
        );
    }
}
