use crate::{
    DueIndex, GroupConnectionStats, GroupLogicalCounters, InboundGroupStats, IngressTelemetry,
    ListenerPeerPolicy, ManualTimerStore, WorkerMessage, group_connection_stats,
};
use shiguredo_srt::{
    Bytes, ConnectionEvent, ConnectionOptions, ConnectionOutput, SrtConnection, Timestamp,
};
use std::collections::hash_map::Entry as HashEntry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Admission peer table — shared by every reuseport ingress strategy
// ---------------------------------------------------------------------------

/// One connection tracked from admission until it is promoted, relocated,
/// or retired -- serviced off the shared listener socket by SRT Socket-ID
/// dispatch, with the UDP address retained as source validation.
/// Did this `Disconnected` reason mean the ordered close, or something
/// going wrong?
///
/// The sender ends a run by calling `SrtConnection::disconnect`, which
/// emits an SRT SHUTDOWN; the peer reports that as `peer shutdown`. The
/// sender itself gets no event for its own close, so on that side every
/// `Disconnected` is by definition unplanned.
#[must_use]
pub fn is_ordered_close(reason: &str) -> bool {
    reason == "peer shutdown"
}

pub struct AdmissionPeer {
    logical_peer: LogicalPeerId,
    pub conn: SrtConnection,
    pub timers: ManualTimerStore,
    /// Live connected state, feeding `srt_lifecycle::is_terminal`. Goes
    /// false again on `Disconnected`.
    pub connected: bool,
    /// `None` until this peer's first `Connected`, which also makes it
    /// the "has this ever connected" flag. Final success reporting should
    /// use this rather than `connected`: a session that streamed
    /// everything and then tripped the peer-idle timeout is still a
    /// success.
    pub stream_deadline: Option<Instant>,
    pub data_events: u64,
    pub last_data_at: Instant,
    /// This peer went away for a reason other than the ordered close --
    /// an idle timeout, or an error. Distinct from `connected`, which
    /// also goes false on a clean shutdown, and from `stream_deadline`,
    /// which records only that it once connected.
    pub torn_down: bool,
    /// A policy rejection is queued for transmission and this entry must
    /// never accept more input. It is retired after `poll_outbound` drains
    /// the rejection packet.
    rejected: bool,
    admission_established: bool,
    last_datagram_at: Timestamp,
}

impl AdmissionPeer {
    /// Apply one protocol event to this peer's bookkeeping. Returns
    /// `true` exactly once per peer: on the event that is its first-ever
    /// `Connected`, which is the caller's cue to arm `stream_deadline` and
    /// treat the peer as newly admitted (relocation, `--promotion`, etc).
    ///
    /// The single implementation of "what a Connected/DataReceived/
    /// Disconnected event means for one admitted peer" -- previously
    /// hand-copied identically into each of the six runtime adapters'
    /// per-tick admission loops, plus a seventh, slightly different copy
    /// inside `PeerTable::drain_events`.
    pub fn apply_event(&mut self, event: shiguredo_srt::ConnectionEvent) -> bool {
        use shiguredo_srt::ConnectionEvent;
        match event {
            ConnectionEvent::Connected => {
                let first_connect = self.stream_deadline.is_none();
                self.connected = true;
                first_connect
            }
            ConnectionEvent::DataReceived { .. } => {
                self.data_events += 1;
                self.last_data_at = Instant::now();
                false
            }
            ConnectionEvent::Disconnected { reason } => {
                self.torn_down |= !is_ordered_close(&reason);
                self.connected = false;
                false
            }
            _ => false,
        }
    }
}

/// Per-listener settings the table needs to mint new connections and to
/// decide cookie routing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BondedInputPolicy {
    /// Reject GROUP handshakes. This is the safe default: accepting the legs
    /// independently would silently lose the publisher's redundancy contract.
    #[default]
    Reject,
    /// Authenticate and admit GROUP handshakes, then automatically associate
    /// matching legs into one logical ingress stream.
    Accept,
}

#[derive(Clone, Debug)]
pub struct AdmissionOptions {
    pub socket_id: u32,
    pub tsbpd_delay: u16,
    /// Forward a handshake datagram to the acceptor its SYN cookie names.
    /// Off makes a rehashed CONCLUSION strand instead, which is only
    /// useful for measuring what the routing is worth.
    pub cookie_routing: bool,
    /// Whether this listener explicitly accepts bonded SRT publishers.
    pub bonded_inputs: BondedInputPolicy,
    /// Complete session template for peers created on a shared listener.
    /// `None` preserves the legacy socket-id/latency-only construction.
    pub connection_template: Option<ConnectionOptions>,
    pub handshake_retry_interval: Duration,
    pub handshake_timeout: Duration,
}

impl AdmissionOptions {
    /// Compatibility constructor for applications that configure the protocol
    /// connection separately.
    #[must_use]
    pub fn basic(socket_id: u32, tsbpd_delay: u16, cookie_routing: bool) -> Self {
        Self {
            socket_id,
            tsbpd_delay,
            cookie_routing,
            bonded_inputs: BondedInputPolicy::Reject,
            connection_template: None,
            handshake_retry_interval: Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_RETRY_INTERVAL_MICROS,
            ),
            handshake_timeout: Duration::from_micros(
                shiguredo_srt::DEFAULT_HANDSHAKE_TIMEOUT_MICROS,
            ),
        }
    }
}

impl Drop for AdmissionOptions {
    fn drop(&mut self) {
        let Some(template) = self.connection_template.as_mut() else {
            return;
        };
        if let Some(passphrase) = template.passphrase.as_mut() {
            passphrase.zeroize();
        }
        if let Some(salt) = template.crypto_salt.as_mut() {
            salt.zeroize();
        }
        if let Some(sek) = template.crypto_sek.as_mut() {
            sek.zeroize();
        }
    }
}

/// Resource limits for one shared-listener admission table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerTableConfig {
    /// Total half-open plus established peers retained by this table.
    pub max_peers: usize,
    /// Incomplete handshakes retained concurrently.
    pub max_half_open_peers: usize,
    /// Fully established peers retained concurrently.
    pub max_established_peers: usize,
    /// Total peers from one source IP (ports do not bypass this bound).
    pub max_peers_per_ip: usize,
    pub half_open_timeout: Duration,
}

impl Default for PeerTableConfig {
    fn default() -> Self {
        Self {
            max_peers: 4096,
            max_half_open_peers: 1024,
            max_established_peers: 4096,
            // Safe compatibility default: the per-source mechanism is active
            // but no tighter than the table-wide bound until an application
            // chooses a tenant/source policy.
            max_peers_per_ip: 4096,
            half_open_timeout: Duration::from_secs(10),
        }
    }
}

/// Application authorization result for a claimed, not-yet-authenticated
/// handshake identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionDecision {
    Accept,
    Reject { reason: i32 },
}

/// A libsrt-compatible application rejection code.
///
/// The 1000-1999 range is reserved for predefined meanings and 2000-2999 for
/// application-specific reasons. The legacy [`AdmissionDecision`] API remains
/// available when exact wire compatibility requires an unchecked raw value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RejectionReason(i32);

impl RejectionReason {
    pub const BAD_REQUEST: Self = Self(1400);
    pub const UNAUTHORIZED: Self = Self(1401);
    pub const OVERLOAD: Self = Self(1402);
    pub const FORBIDDEN: Self = Self(1403);
    pub const NOT_FOUND: Self = Self(1404);
    pub const BAD_MODE: Self = Self(1405);
    pub const UNACCEPTABLE: Self = Self(1406);
    pub const INTERNAL_ERROR: Self = Self(1500);

    /// Construct an application-owned rejection in libsrt's 2000-2999 range.
    #[must_use]
    pub const fn application(code: u16) -> Option<Self> {
        if code <= 999 {
            Some(Self(2000 + code as i32))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

/// Context made available after cookie validation and before the protocol core
/// processes a caller's CONCLUSION or KM request.
///
/// Every caller-controlled field is untrusted at this point. In particular,
/// StreamID and parsed access-control values are merely credential-validated
/// claims after a selected passphrase successfully validates the KM exchange;
/// SRT passphrase mode is not general peer authentication.
#[derive(Clone, Debug)]
pub struct AdmissionRequest {
    pub peer: std::net::SocketAddr,
    pub claimed_identity: srt_lifecycle::HandshakeIdentity,
    pub handshake: shiguredo_srt::HandshakePacket,
    pub access_control: Option<shiguredo_srt::stream_id::AccessControl>,
}

/// Result of resolving policy for one valid CONCLUSION.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AdmissionResolution {
    #[default]
    Accept,
    Configure(ListenerPeerPolicy),
    Reject {
        reason: RejectionReason,
    },
    /// Leave the half-open peer untouched. A retransmitted CONCLUSION may be
    /// resolved later, but the original hard half-open expiry is not extended.
    Defer,
}

enum AdmissionHookResult {
    Accept,
    Configure(ListenerPeerPolicy),
    Reject(i32),
    Defer,
}

struct DecodedAdmissionDatagram {
    handshake: Option<shiguredo_srt::HandshakePacket>,
    destination_socket_id: u32,
}

struct AdmissionFeedResult {
    fed: bool,
    feed_error_kind: Option<shiguredo_srt::ErrorKind>,
    inserted: bool,
    became_established: bool,
    became_terminal: bool,
}

struct KnownConclusionContext<'a> {
    peer: std::net::SocketAddr,
    physical: Option<PhysicalPeerKey>,
    handshake: Option<&'a shiguredo_srt::HandshakePacket>,
    identity: Option<&'a srt_lifecycle::HandshakeIdentity>,
    now: Timestamp,
    options: &'a AdmissionOptions,
    telemetry: &'a IngressTelemetry,
}

struct AdmissionFeedContext<'a> {
    peer: std::net::SocketAddr,
    data: &'a [u8],
    now: Timestamp,
    options: &'a AdmissionOptions,
    worker_index: usize,
    new_logical_peer: Option<LogicalPeerId>,
}

fn decode_admission_datagram(data: &[u8]) -> Result<DecodedAdmissionDatagram, ()> {
    // Only a CONTROL packet can be a handshake (SRT's F bit, the top bit
    // of the first word). Checking it here keeps `peek_handshake` -- a
    // full `SrtPacket::decode`, which allocates a DATA payload -- off
    // the DATA path, which is every packet of a live stream. Without the
    // guard each datagram is decoded twice and the first payload allocation
    // is discarded on the next line.
    let handshake = is_control_datagram(data)
        .then(|| shiguredo_srt::peek_handshake(data))
        .flatten();
    let destination_socket_id = shiguredo_srt::peek_destination_socket_id(data).map_err(|_| ())?;
    Ok(DecodedAdmissionDatagram {
        handshake,
        destination_socket_id,
    })
}

impl From<AdmissionResolution> for AdmissionHookResult {
    fn from(value: AdmissionResolution) -> Self {
        match value {
            AdmissionResolution::Accept => Self::Accept,
            AdmissionResolution::Configure(policy) => Self::Configure(policy),
            AdmissionResolution::Reject { reason } => Self::Reject(reason.get()),
            AdmissionResolution::Defer => Self::Defer,
        }
    }
}

/// Why an admission datagram was discarded without creating connection state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionDropReason {
    InvalidPacket,
    InvalidCookie,
    StaleConclusion,
    RejectedPeer,
    /// Total peer-table capacity was reached.
    Capacity,
    /// Incomplete-handshake capacity was reached.
    HalfOpenCapacity,
    /// Established-peer capacity was reached.
    EstablishedCapacity,
    /// One source IP reached its configured share.
    SourceCapacity,
}

/// What [`PeerTable::admit`] did with a datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Fed to the peer's connection, creating it if this is its first
    /// packet.
    Fed,
    /// Belongs to another acceptor's half-open handshake; the caller
    /// should send it there as [`WorkerMessage::Handshake`].
    ForwardTo(usize),
    /// The application rejected the conclusion before it became connected.
    Rejected,
    /// Policy resolution intentionally retained the half-open peer without
    /// feeding or extending the CONCLUSION.
    Deferred,
    /// The datagram was invalid, stale, or exceeded the configured bound.
    Dropped(AdmissionDropReason),
}

/// Stable, process-local application handle for one logical SRT connection.
///
/// It deliberately does not expose a UDP address, a physical SRT Socket ID,
/// a wire group ID, or the caller-provided StreamID. One direct connection and
/// one bonded group are both represented by exactly one handle. Retain this
/// value from [`AdmissionEvent::logical_peer`] for steady-state operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogicalPeerId(u64);

/// A logical peer which has been atomically retired from a [`PeerTable`].
///
/// The returned protocol cores let an application choose whether to drop them
/// immediately or retain them for its own post-close accounting.  The table no
/// longer owns any Socket-ID route, timer, admission slot, or event queue for
/// this session.
pub enum RemovedLogicalPeer {
    Direct(Box<RemovedPeerLeg>),
    Group(Vec<RemovedPeerLeg>),
}

/// One physical protocol core returned when retiring a logical peer.
pub struct RemovedPeerLeg {
    pub peer: std::net::SocketAddr,
    pub connection: SrtConnection,
}

/// A newly connected logical peer. `representative_peer` is diagnostic-only;
/// use [`Self::logical_peer`] for every lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewlyConnectedPeer {
    pub logical_peer: LogicalPeerId,
    pub representative_peer: std::net::SocketAddr,
}

#[derive(Clone)]
enum LogicalPeerTarget {
    Direct(PhysicalPeerKey),
    Group(srt_lifecycle::LogicalGroupKey),
}

/// One physical SRT leg on a shared UDP listener.
///
/// The SRT specification permits multiple SRT sockets to share a UDP socket;
/// after the induction handshake their Destination SRT Socket ID, together
/// with the source UDP address, selects the leg. This is deliberately private:
/// applications retain [`LogicalPeerId`] rather than an L4/protocol key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PhysicalPeerKey {
    address: std::net::SocketAddr,
    local_socket_id: u32,
}

/// Snapshot of a direct or bonded logical peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalPeerStats {
    Direct(Box<shiguredo_srt::ConnectionStats>),
    Group(Box<GroupConnectionStats>),
}

/// Borrowed steady-state view of an admitted SRT publisher.
///
/// It deliberately hides whether the peer is one socket or a bonded group:
/// callers use the same StreamID and telemetry operations for both. Physical
/// leg details remain available inside [`LogicalPeerStats::Group`].
pub struct LogicalPeer<'a> {
    table: &'a PeerTable,
    id: LogicalPeerId,
}

impl LogicalPeer<'_> {
    #[must_use]
    pub fn id(&self) -> &LogicalPeerId {
        &self.id
    }

    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        match self.table.logical_peers.get(&self.id)? {
            LogicalPeerTarget::Direct(peer) => self
                .table
                .peers
                .get(peer)
                .and_then(|entry| entry.conn.peer_stream_id()),
            LogicalPeerTarget::Group(key) => key.stream_id.as_deref(),
        }
    }

    /// GROUP metadata used by an application's worker-affinity policy. This
    /// is descriptive only; the logical peer handle remains the session key.
    #[must_use]
    pub fn group_affinity(&self) -> Option<srt_lifecycle::GroupAffinity> {
        match self.table.logical_peers.get(&self.id)? {
            LogicalPeerTarget::Direct(peer) => self.table.peers.get(peer).and_then(|entry| {
                entry
                    .conn
                    .peer_group_extension()
                    .map(|extension| srt_lifecycle::GroupAffinity {
                        group_id: extension.group_id,
                        stream_id: entry.conn.peer_stream_id().map(str::to_owned),
                        extension,
                    })
            }),
            LogicalPeerTarget::Group(key) => {
                self.table
                    .groups
                    .get(key)
                    .map(|_| srt_lifecycle::GroupAffinity {
                        group_id: key.group_id,
                        stream_id: key.stream_id.clone(),
                        extension: self
                            .table
                            .groups
                            .get(key)
                            .and_then(|group| group.group.members().first())
                            .and_then(|member| member.connection().peer_group_extension())
                            .expect("bonded group was admitted from GROUP handshakes"),
                    })
            }
        }
    }

    #[must_use]
    pub fn stats(&self) -> Option<LogicalPeerStats> {
        match self.table.logical_peers.get(&self.id)? {
            LogicalPeerTarget::Direct(peer) => self
                .table
                .peers
                .get(peer)
                .map(|entry| LogicalPeerStats::Direct(Box::new(entry.conn.stats()))),
            LogicalPeerTarget::Group(key) => self.table.groups.get(key).map(|group| {
                LogicalPeerStats::Group(Box::new(group_connection_stats(
                    &group.group,
                    GroupLogicalCounters {
                        payloads_sent: group.logical_payloads_sent,
                        payload_bytes_sent: group.logical_payload_bytes_sent,
                        payloads_received: group.logical_payloads_received,
                        payload_bytes_received: group.logical_payload_bytes_received,
                    },
                    |member_id| {
                        let peer_addr = group.legs.get(&member_id).map(|leg| leg.physical.address);
                        (None, peer_addr)
                    },
                )))
            }),
        }
    }
}

/// Mutable steady-state view of an admitted SRT publisher.
///
/// [`Self::send`] and [`Self::disconnect`] arrange the table's maintenance
/// work, so callers do not need separate direct-peer and group-peer paths.
pub struct LogicalPeerMut<'a> {
    table: &'a mut PeerTable,
    id: LogicalPeerId,
}

impl LogicalPeerMut<'_> {
    #[must_use]
    pub fn id(&self) -> &LogicalPeerId {
        &self.id
    }

    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        match self.table.logical_peers.get(&self.id)? {
            LogicalPeerTarget::Direct(peer) => self
                .table
                .peers
                .get(peer)
                .and_then(|entry| entry.conn.peer_stream_id()),
            LogicalPeerTarget::Group(key) => key.stream_id.as_deref(),
        }
    }

    #[must_use]
    pub fn stats(&self) -> Option<LogicalPeerStats> {
        self.table
            .logical_peer(&self.id)
            .and_then(|peer| peer.stats())
    }

    /// Whether a send can be accepted without violating the group's
    /// Broadcast or Backup semantics.
    pub fn can_send(&mut self) -> bool {
        match self.table.logical_peers.get(&self.id) {
            Some(LogicalPeerTarget::Direct(peer)) => self
                .table
                .peers
                .get(peer)
                .is_some_and(|entry| entry.conn.can_send()),
            Some(LogicalPeerTarget::Group(key)) => self
                .table
                .groups
                .get_mut(key)
                .is_some_and(|group| group.group.can_send()),
            None => false,
        }
    }

    /// Send one logical payload. Broadcast returns one successful physical
    /// leg per healthy active member; Backup returns one selected leg.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, shiguredo_srt::Error> {
        match self.table.logical_peers.get(&self.id).cloned() {
            Some(LogicalPeerTarget::Direct(peer)) => {
                let entry = self.table.peers.get_mut(&peer).ok_or_else(|| {
                    shiguredo_srt::Error::with_reason(
                        shiguredo_srt::ErrorKind::InvalidState,
                        "logical peer no longer exists",
                    )
                })?;
                entry.conn.send(payload, now)?;
                self.table.mark_ready_physical(peer);
                Ok(1)
            }
            Some(LogicalPeerTarget::Group(key)) => {
                let group = self.table.groups.get_mut(&key).ok_or_else(|| {
                    shiguredo_srt::Error::with_reason(
                        shiguredo_srt::ErrorKind::InvalidState,
                        "logical peer no longer exists",
                    )
                })?;
                let legs = group.group.send(payload, now)?;
                group.logical_payloads_sent = group.logical_payloads_sent.saturating_add(1);
                group.logical_payload_bytes_sent = group
                    .logical_payload_bytes_sent
                    .saturating_add(payload.len() as u64);
                Ok(legs)
            }
            None => Err(shiguredo_srt::Error::with_reason(
                shiguredo_srt::ErrorKind::InvalidState,
                "logical peer no longer exists",
            )),
        }
    }

    /// Send shared payload data. Uses reference-counted `Bytes` to avoid
    /// deep-copying the payload for each group leg — the fan-out path.
    pub fn send_shared(
        &mut self,
        payload: Bytes,
        now: Timestamp,
    ) -> Result<usize, shiguredo_srt::Error> {
        let len = payload.len() as u64;
        match self.table.logical_peers.get(&self.id).cloned() {
            Some(LogicalPeerTarget::Direct(peer)) => {
                let entry = self.table.peers.get_mut(&peer).ok_or_else(|| {
                    shiguredo_srt::Error::with_reason(
                        shiguredo_srt::ErrorKind::InvalidState,
                        "logical peer no longer exists",
                    )
                })?;
                entry.conn.send_shared(payload, now)?;
                self.table.mark_ready_physical(peer);
                Ok(1)
            }
            Some(LogicalPeerTarget::Group(key)) => {
                let group = self.table.groups.get_mut(&key).ok_or_else(|| {
                    shiguredo_srt::Error::with_reason(
                        shiguredo_srt::ErrorKind::InvalidState,
                        "logical peer no longer exists",
                    )
                })?;
                let legs = group.group.send_shared(payload, now)?;
                group.logical_payloads_sent = group.logical_payloads_sent.saturating_add(1);
                group.logical_payload_bytes_sent =
                    group.logical_payload_bytes_sent.saturating_add(len);
                Ok(legs)
            }
            None => Err(shiguredo_srt::Error::with_reason(
                shiguredo_srt::ErrorKind::InvalidState,
                "logical peer no longer exists",
            )),
        }
    }

    /// Start an orderly close. A bonded peer closes every leg but remains in
    /// the table until the usual transport lifecycle reaches its terminal
    /// state.
    pub fn disconnect(&mut self, now: Timestamp) {
        match self.table.logical_peers.get(&self.id).cloned() {
            Some(LogicalPeerTarget::Direct(peer)) => {
                if let Some(entry) = self.table.peers.get_mut(&peer) {
                    entry.conn.disconnect(now);
                    self.table.mark_ready_physical(peer);
                }
            }
            Some(LogicalPeerTarget::Group(key)) => {
                if let Some(group) = self.table.groups.get_mut(&key) {
                    group.group.disconnect(now);
                }
            }
            None => {}
        }
    }
}

/// One logical ingress event emitted by an admitted peer or bonded group.
///
/// For an opted-in bonded publisher, `representative_peer` is its first
/// admitted leg and `logical_peer` is the stable session identity. `DataReceived` has already
/// been ordered and deduplicated across legs.
/// Otherwise this is the unmodified protocol event. Production consumers
/// should use [`PeerTable::poll_events`]; the benchmark-only
/// [`PeerTable::drain_events`] adapter remains for its legacy counters and
/// promotion timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionEvent {
    /// Wire diagnostic only; never use this as an application session key.
    pub representative_peer: std::net::SocketAddr,
    pub logical_peer: LogicalPeerId,
    pub event: ConnectionEvent,
}

struct InboundGroupLeg {
    member_id: u32,
    physical: PhysicalPeerKey,
    timers: ManualTimerStore,
}

struct InboundGroup {
    group: shiguredo_srt::SrtGroup,
    legs: HashMap<u32, InboundGroupLeg>,
    representative_peer: std::net::SocketAddr,
    logical_peer: LogicalPeerId,
    connected: bool,
    stream_deadline: Option<Instant>,
    data_events: u64,
    last_data_at: Instant,
    torn_down: bool,
    logical_payloads_received: u64,
    logical_payload_bytes_received: u64,
    logical_payloads_sent: u64,
    logical_payload_bytes_sent: u64,
}

#[derive(Clone, Debug)]
struct GroupMemberHandle {
    key: srt_lifecycle::LogicalGroupKey,
    member_id: u32,
}

/// The peers one acceptor is servicing off its shared listener.
///
/// This is the admission session state machine, minus I/O: it owns the
/// protocol objects and their timers, decides cookie routing, and records
/// telemetry, but never touches a socket. The caller drives the sending.
/// It lives here rather than in srt-lifecycle because it owns clocks and
/// live protocol state, which that crate deliberately does not.
pub struct PeerTable {
    peers: HashMap<PhysicalPeerKey, AdmissionPeer>,
    logical_peers: HashMap<LogicalPeerId, LogicalPeerTarget>,
    next_logical_peer: u64,
    source_counts: HashMap<std::net::IpAddr, usize>,
    half_open_peers: usize,
    established_peers: usize,
    half_open_deadlines: DueIndex<PhysicalPeerKey>,
    deadlines: DueIndex<PhysicalPeerKey>,
    ready: VecDeque<PhysicalPeerKey>,
    ready_set: HashSet<PhysicalPeerKey>,
    event_ready: VecDeque<PhysicalPeerKey>,
    event_ready_set: HashSet<PhysicalPeerKey>,
    groups: HashMap<srt_lifecycle::LogicalGroupKey, InboundGroup>,
    group_peers: HashMap<PhysicalPeerKey, GroupMemberHandle>,
    next_listener_socket_id: u32,
    last_now: Timestamp,
    config: PeerTableConfig,
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::with_config(PeerTableConfig::default())
    }
}

impl PeerTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_config(mut config: PeerTableConfig) -> Self {
        config.max_peers = config.max_peers.max(1);
        config.max_half_open_peers = config.max_half_open_peers.max(1).min(config.max_peers);
        config.max_established_peers = config.max_established_peers.max(1).min(config.max_peers);
        config.max_peers_per_ip = config.max_peers_per_ip.max(1).min(config.max_peers);
        Self {
            peers: HashMap::new(),
            logical_peers: HashMap::new(),
            next_logical_peer: 1,
            source_counts: HashMap::new(),
            half_open_peers: 0,
            established_peers: 0,
            half_open_deadlines: DueIndex::default(),
            deadlines: DueIndex::default(),
            ready: VecDeque::new(),
            ready_set: HashSet::new(),
            event_ready: VecDeque::new(),
            event_ready_set: HashSet::new(),
            groups: HashMap::new(),
            group_peers: HashMap::new(),
            next_listener_socket_id: 0,
            last_now: Timestamp::default(),
            config,
        }
    }

    fn allocate_logical_peer(&mut self, target: LogicalPeerTarget) -> LogicalPeerId {
        let id = LogicalPeerId(self.next_logical_peer);
        self.next_logical_peer = self.next_logical_peer.wrapping_add(1).max(1);
        self.logical_peers.insert(id, target);
        id
    }

    fn detach_peer_for_group(&mut self, peer: &PhysicalPeerKey) -> Option<AdmissionPeer> {
        self.deadlines.remove(peer);
        self.half_open_deadlines.remove(peer);
        self.ready_set.remove(peer);
        self.event_ready_set.remove(peer);
        self.peers.remove(peer)
    }

    fn allocate_listener_socket_id(&mut self, preferred: u32) -> u32 {
        let mut candidate = if self.next_listener_socket_id == 0 {
            preferred.max(1)
        } else {
            self.next_listener_socket_id
        };
        loop {
            if !self
                .peers
                .keys()
                .any(|key| key.local_socket_id == candidate)
                && !self
                    .group_peers
                    .keys()
                    .any(|key| key.local_socket_id == candidate)
            {
                self.next_listener_socket_id = candidate.wrapping_add(1).max(1);
                return candidate;
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
    }

    fn resolve_conclusion_route(
        &self,
        peer: std::net::SocketAddr,
        physical: Option<PhysicalPeerKey>,
        conclusion: Option<&srt_lifecycle::HandshakeIdentity>,
    ) -> Option<PhysicalPeerKey> {
        if physical.is_some() {
            return physical;
        }
        let identity = conclusion?;
        // Some interoperable callers retain zero in the control header for a
        // CONCLUSION. The cookie is the handshake-phase route in that case;
        // it is not used for established DATA/CONTROL traffic, which remains
        // strictly Destination-Socket-ID demultiplexed.
        self.peers
            .iter()
            .find_map(|(key, entry)| {
                (key.address == peer && entry.conn.syn_cookie() == identity.syn_cookie)
                    .then_some(*key)
            })
            .or_else(|| {
                // Legacy/raw callers that bypass `SessionConfig` can advertise
                // socket ID zero during the whole handshake. Preserve that
                // compatibility only when the UDP tuple identifies exactly one
                // half-open leg; shared-four-tuple sessions must materialize a
                // non-zero caller SRT Socket ID and are never guessed by address.
                let mut candidates = self.peers.keys().filter(|key| key.address == peer);
                candidates
                    .next()
                    .copied()
                    .filter(|_| candidates.next().is_none())
            })
    }

    fn stale_conclusion(
        identity: &srt_lifecycle::HandshakeIdentity,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
    ) -> Admit {
        let owner = srt_lifecycle::worker_from_cookie(identity.syn_cookie, worker_count);
        match owner {
            Some(owner) if owner != worker_index => {
                if options.cookie_routing {
                    telemetry.record_cookie_routed();
                    return Admit::ForwardTo(owner);
                }
                // Routing disabled: it will be answered here and fail
                // cookie validation, which is the cost being measured.
                telemetry.record_stranded_conclusion();
            }
            // The cookie names this acceptor, but the peer is gone --
            // it was already promoted off the shared listener, so
            // this is a late or duplicate CONCLUSION rather than a
            // stranded handshake. Conflating the two makes the
            // routing measurement meaningless.
            Some(_) => telemetry.record_promoted_duplicate(),
            None => telemetry.record_stranded_conclusion(),
        }
        Admit::Dropped(AdmissionDropReason::StaleConclusion)
    }

    fn reject_new_peer(
        &self,
        peer: std::net::SocketAddr,
        handshake: Option<&shiguredo_srt::HandshakePacket>,
        telemetry: &IngressTelemetry,
    ) -> Option<Admit> {
        let Some(packet) = handshake else {
            telemetry.record_invalid_datagram();
            return Some(Admit::Dropped(AdmissionDropReason::InvalidPacket));
        };
        if packet.handshake_type != shiguredo_srt::HandshakeType::Induction {
            telemetry.record_invalid_datagram();
            return Some(Admit::Dropped(AdmissionDropReason::InvalidPacket));
        }
        if self.peers.len() >= self.config.max_peers {
            telemetry.record_admission_capacity_drop();
            return Some(Admit::Dropped(AdmissionDropReason::Capacity));
        }
        if self.half_open_count() >= self.config.max_half_open_peers {
            telemetry.record_half_open_capacity_drop();
            return Some(Admit::Dropped(AdmissionDropReason::HalfOpenCapacity));
        }
        if self.peers_for_ip(peer.ip()) >= self.config.max_peers_per_ip {
            telemetry.record_source_capacity_drop();
            return Some(Admit::Dropped(AdmissionDropReason::SourceCapacity));
        }
        None
    }

    fn physical_for_datagram(
        &self,
        address: std::net::SocketAddr,
        destination_socket_id: u32,
        induction_socket_id: Option<u32>,
    ) -> Option<PhysicalPeerKey> {
        if destination_socket_id != 0 {
            return Some(PhysicalPeerKey {
                address,
                local_socket_id: destination_socket_id,
            });
        }
        let caller_socket_id = induction_socket_id?;
        self.peers
            .iter()
            .find_map(|(key, entry)| {
                (key.address == address && entry.conn.peer_socket_id() == caller_socket_id)
                    .then_some(*key)
            })
            .or_else(|| {
                self.group_peers.iter().find_map(|(key, handle)| {
                    let member = self
                        .groups
                        .get(&handle.key)
                        .and_then(|group| group.group.member(handle.member_id))?;
                    (key.address == address
                        && member.connection().peer_socket_id() == caller_socket_id)
                        .then_some(*key)
                })
            })
    }

    fn physical_for_address(&self, address: std::net::SocketAddr) -> Option<PhysicalPeerKey> {
        self.peers
            .keys()
            .chain(self.group_peers.keys())
            .find(|key| key.address == address)
            .copied()
    }

    fn group_admission_allowed(
        &self,
        identity: &srt_lifecycle::HandshakeIdentity,
        handshake: &shiguredo_srt::HandshakePacket,
        options: &AdmissionOptions,
    ) -> bool {
        let Some(group) = identity.group.as_ref() else {
            return true;
        };
        let Some(mode) = shiguredo_srt::GroupMode::from_group_type(group.extension.group_type)
        else {
            return false;
        };
        if options.bonded_inputs != BondedInputPolicy::Accept
            || group.group_id & shiguredo_srt::SRTGROUP_MASK == 0
        {
            return false;
        }
        self.groups
            .get(&group.logical_key())
            .is_none_or(|existing| {
                existing.group.mode() == mode
                    && existing.group.member(handshake.socket_id).is_none()
            })
    }

    fn apply_policy_hook<F>(
        entry: &mut AdmissionPeer,
        request: &AdmissionRequest,
        now: Timestamp,
        telemetry: &IngressTelemetry,
        hook: F,
    ) -> Result<(), Admit>
    where
        F: FnOnce(&AdmissionRequest, &mut SrtConnection) -> AdmissionHookResult,
    {
        match hook(request, &mut entry.conn) {
            AdmissionHookResult::Accept => {}
            AdmissionHookResult::Configure(policy) => {
                if policy.apply_to(&mut entry.conn).is_err() {
                    telemetry.record_policy_error();
                    if entry
                        .conn
                        .reject(RejectionReason::INTERNAL_ERROR.get(), now)
                        .is_err()
                    {
                        telemetry.record_invalid_datagram();
                        return Err(Admit::Dropped(AdmissionDropReason::InvalidPacket));
                    }
                    entry.rejected = true;
                    return Err(Admit::Rejected);
                }
                telemetry.record_policy_configuration();
            }
            AdmissionHookResult::Reject(reason) => {
                if entry.conn.reject(reason, now).is_err() {
                    telemetry.record_invalid_datagram();
                    return Err(Admit::Dropped(AdmissionDropReason::InvalidPacket));
                }
                telemetry.record_policy_rejection();
                entry.rejected = true;
                entry.last_datagram_at = now;
                return Err(Admit::Rejected);
            }
            AdmissionHookResult::Defer => {
                telemetry.record_policy_deferred();
                return Err(Admit::Deferred);
            }
        }
        Ok(())
    }

    fn apply_known_conclusion_policy<F>(
        &mut self,
        context: KnownConclusionContext<'_>,
        hook: F,
    ) -> Option<Admit>
    where
        F: FnOnce(&AdmissionRequest, &mut SrtConnection) -> AdmissionHookResult,
    {
        let KnownConclusionContext {
            peer,
            physical,
            handshake,
            identity,
            now,
            options,
            telemetry,
        } = context;
        let identity = identity?;
        // SEC-04: `known` guarantees `physical.is_some()` and
        // `identity` is derived from `handshake`, so both must be
        // `Some` here. Bind them once with defensive early returns
        // instead of panicking on the network-facing hot path.
        let Some(physical) = physical else {
            debug_assert!(false, "known peer lost physical route");
            return Some(Admit::Dropped(AdmissionDropReason::InvalidPacket));
        };
        let Some(packet) = handshake else {
            debug_assert!(false, "conclusion identity without decoded handshake");
            return Some(Admit::Dropped(AdmissionDropReason::InvalidPacket));
        };
        let group_admission_allowed = self.group_admission_allowed(identity, packet, options);
        if self
            .peers
            .get(&physical)
            .is_some_and(|entry| !entry.admission_established)
            && self.established_count() >= self.config.max_established_peers
        {
            telemetry.record_established_capacity_drop();
            return Some(Admit::Dropped(AdmissionDropReason::EstablishedCapacity));
        }
        let result = {
            let Some(entry) = self.peers.get_mut(&physical) else {
                return Some(Admit::Dropped(AdmissionDropReason::StaleConclusion));
            };
            if entry.rejected {
                return Some(Admit::Dropped(AdmissionDropReason::RejectedPeer));
            }
            if identity.syn_cookie != entry.conn.syn_cookie() {
                telemetry.record_invalid_cookie();
                return Some(Admit::Dropped(AdmissionDropReason::InvalidCookie));
            }
            let request = AdmissionRequest {
                peer,
                claimed_identity: identity.clone(),
                handshake: packet.clone(),
                access_control: identity
                    .stream_id
                    .as_deref()
                    .and_then(shiguredo_srt::stream_id::AccessControl::parse),
            };
            telemetry.record_policy_request();
            if !group_admission_allowed {
                if entry
                    .conn
                    .reject(RejectionReason::BAD_MODE.get(), now)
                    .is_err()
                {
                    telemetry.record_invalid_datagram();
                    return Some(Admit::Dropped(AdmissionDropReason::InvalidPacket));
                }
                telemetry.record_policy_rejection();
                entry.rejected = true;
                entry.last_datagram_at = now;
                Some(Admit::Rejected)
            } else {
                Self::apply_policy_hook(entry, &request, now, telemetry, hook).err()
            }
        };
        if matches!(result, Some(Admit::Rejected)) {
            self.mark_ready_physical(physical);
        }
        result
    }

    fn new_admission_peer(
        logical_peer: LogicalPeerId,
        physical: PhysicalPeerKey,
        peer: std::net::SocketAddr,
        options: &AdmissionOptions,
        worker_index: usize,
        now: Timestamp,
    ) -> AdmissionPeer {
        let mut connection_options = options.connection_template.clone().unwrap_or_default();
        connection_options.socket_id = physical.local_socket_id;
        connection_options.tsbpd_delay = options.tsbpd_delay;
        // Encode who owns this handshake, so a CONCLUSION the kernel
        // rehashes elsewhere can be routed back here.
        connection_options.syn_cookie = Some(srt_lifecycle::cookie_for_worker(
            worker_index,
            peer_entropy(peer),
        ));
        let mut conn = SrtConnection::new_listener(connection_options);
        conn.set_handshake_timing(
            u64::try_from(options.handshake_retry_interval.as_micros()).unwrap_or(u64::MAX),
            u64::try_from(options.handshake_timeout.as_micros()).unwrap_or(u64::MAX),
        );
        AdmissionPeer {
            logical_peer,
            conn,
            timers: ManualTimerStore::new(),
            connected: false,
            stream_deadline: None,
            data_events: 0,
            last_data_at: Instant::now(),
            torn_down: false,
            rejected: false,
            admission_established: false,
            last_datagram_at: now,
        }
    }

    fn feed_admission_datagram(
        &mut self,
        physical: PhysicalPeerKey,
        context: AdmissionFeedContext<'_>,
    ) -> AdmissionFeedResult {
        let AdmissionFeedContext {
            peer,
            data,
            now,
            options,
            worker_index,
            new_logical_peer,
        } = context;
        let mut inserted = false;
        let entry = self.peers.entry(physical).or_insert_with(|| {
            inserted = true;
            let logical_peer = new_logical_peer.unwrap_or_else(|| {
                unreachable!("or_insert_with runs only for new peers, which set new_logical_peer")
            });
            Self::new_admission_peer(logical_peer, physical, peer, options, worker_index, now)
        });
        let feed_result = entry.conn.feed_recv_buf(data, now);
        let feed_error_kind = feed_result.as_ref().err().map(|error| error.kind);
        let fed = feed_result.is_ok();
        if fed {
            entry.last_datagram_at = now;
        }
        let became_established = fed
            && !entry.admission_established
            && entry.conn.state() == shiguredo_srt::ConnectionState::Connected;
        if became_established {
            entry.admission_established = true;
        }
        let became_terminal =
            !fed && entry.conn.state() == shiguredo_srt::ConnectionState::Disconnected;
        if became_terminal {
            entry.rejected = true;
        }
        AdmissionFeedResult {
            fed,
            feed_error_kind,
            inserted,
            became_established,
            became_terminal,
        }
    }

    fn finish_admission_failure(
        &mut self,
        physical: PhysicalPeerKey,
        known: bool,
        conclusion: Option<&srt_lifecycle::HandshakeIdentity>,
        feed: AdmissionFeedResult,
        telemetry: &IngressTelemetry,
    ) -> Admit {
        if conclusion.is_some()
            && matches!(
                feed.feed_error_kind,
                Some(
                    shiguredo_srt::ErrorKind::CryptoError
                        | shiguredo_srt::ErrorKind::HandshakeRejected
                )
            )
        {
            telemetry.record_credential_failure();
        }
        telemetry.record_invalid_datagram();
        if !known {
            let _ = self.remove_physical(physical);
        } else if feed.became_terminal {
            self.mark_ready_physical(physical);
        }
        Admit::Dropped(AdmissionDropReason::InvalidPacket)
    }

    fn finish_admission_success(
        &mut self,
        physical: PhysicalPeerKey,
        now: Timestamp,
        became_established: bool,
    ) -> Admit {
        if became_established {
            self.half_open_peers = self.half_open_peers.saturating_sub(1);
            self.established_peers += 1;
            self.half_open_deadlines.remove(&physical);
            self.adopt_bonded_peer(physical);
        } else if !self
            .peers
            .get(&physical)
            .is_some_and(|entry| entry.admission_established)
        {
            self.half_open_deadlines.set(
                physical,
                now.add_micros(half_open_timeout_micros(self.config.half_open_timeout)),
            );
        }
        self.mark_ready_physical(physical);
        Admit::Fed
    }

    fn adopt_bonded_peer(&mut self, peer: PhysicalPeerKey) {
        let Some(entry) = self.peers.get(&peer) else {
            return;
        };
        let Some(extension) = entry.conn.peer_group_extension() else {
            return;
        };
        let Some(mode) = shiguredo_srt::GroupMode::from_group_type(extension.group_type) else {
            return;
        };
        let affinity = srt_lifecycle::GroupAffinity {
            group_id: extension.group_id,
            stream_id: entry.conn.peer_stream_id().map(str::to_owned),
            extension,
        };
        let key = affinity.logical_key();
        let member_id = entry.conn.peer_socket_id();
        let weight = extension.weight;
        let logical_peer = entry.logical_peer;

        if !self.groups.contains_key(&key) {
            let group = shiguredo_srt::SrtGroup::new(extension.group_id, mode)
                .expect("GROUP handshakes are validated before connection admission");
            self.groups.insert(
                key.clone(),
                InboundGroup {
                    group,
                    legs: HashMap::new(),
                    representative_peer: peer.address,
                    logical_peer,
                    connected: false,
                    stream_deadline: None,
                    data_events: 0,
                    last_data_at: Instant::now(),
                    torn_down: false,
                    logical_payloads_received: 0,
                    logical_payload_bytes_received: 0,
                    logical_payloads_sent: 0,
                    logical_payload_bytes_sent: 0,
                },
            );
            self.logical_peers
                .insert(logical_peer, LogicalPeerTarget::Group(key.clone()));
        } else {
            // This physical leg was briefly a direct peer only while its
            // handshake completed. The existing group's handle remains the
            // sole application-visible logical identity.
            self.logical_peers.remove(&logical_peer);
        }

        let entry = self
            .detach_peer_for_group(&peer)
            .expect("connected GROUP peer remains in the ordinary peer table until adoption");
        let group = self
            .groups
            .get_mut(&key)
            .expect("group was inserted or already existed");
        group
            .group
            .add_member(member_id, weight, entry.conn)
            .expect("duplicate GROUP member IDs are rejected before admission");
        group.legs.insert(
            member_id,
            InboundGroupLeg {
                member_id,
                physical: peer,
                timers: entry.timers,
            },
        );
        self.group_peers
            .insert(peer, GroupMemberHandle { key, member_id });
    }

    fn admit_group_leg(&mut self, peer: PhysicalPeerKey, data: &[u8], now: Timestamp) -> Admit {
        let Some(handle) = self.group_peers.get(&peer).cloned() else {
            return Admit::Dropped(AdmissionDropReason::StaleConclusion);
        };
        let Some(group) = self.groups.get_mut(&handle.key) else {
            return Admit::Dropped(AdmissionDropReason::StaleConclusion);
        };
        let Some(member) = group.group.member_mut(handle.member_id) else {
            return Admit::Dropped(AdmissionDropReason::StaleConclusion);
        };
        match member.connection_mut().feed_recv_buf(data, now) {
            Ok(()) => Admit::Fed,
            Err(_) => Admit::Dropped(AdmissionDropReason::InvalidPacket),
        }
    }

    /// Take one datagram for `peer`.
    ///
    /// `worker_index`/`worker_count` identify this acceptor within the
    /// reuseport group so a CONCLUSION carrying someone else's cookie can
    /// be routed home rather than answered here (cookie validation would
    /// reject it) or dropped (a handshake retry).
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
    ) -> Admit {
        self.admit_with_authorizer(
            peer,
            data,
            now,
            options,
            worker_index,
            worker_count,
            telemetry,
            |_| AdmissionDecision::Accept,
        )
    }

    /// Admit a datagram, authorizing a valid CONCLUSION before it is fed to
    /// the protocol core and can transition to `Connected`.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_authorizer<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
        authorize: F,
    ) -> Admit
    where
        F: FnOnce(&srt_lifecycle::HandshakeIdentity) -> AdmissionDecision,
    {
        self.admit_with_policy_hook(
            peer,
            data,
            now,
            options,
            worker_index,
            worker_count,
            telemetry,
            |request, _connection| match authorize(&request.claimed_identity) {
                AdmissionDecision::Accept => AdmissionHookResult::Accept,
                AdmissionDecision::Reject { reason } => AdmissionHookResult::Reject(reason),
            },
        )
    }

    /// Resolve typed per-peer policy from the caller's claimed identity and
    /// raw handshake context. The resolver runs synchronously in the packet
    /// path and should use bounded, cached work.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_resolver<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
        resolve: F,
    ) -> Admit
    where
        F: FnOnce(&AdmissionRequest) -> AdmissionResolution,
    {
        self.admit_with_policy_hook(
            peer,
            data,
            now,
            options,
            worker_index,
            worker_count,
            telemetry,
            |request, _connection| resolve(request).into(),
        )
    }

    /// Expert pre-CONCLUSION escape hatch.
    ///
    /// This exposes the guarded [`SrtConnection`] setters for protocol options
    /// not modeled by [`ListenerPeerPolicy`]. The hook is invoked only after
    /// capacity and cookie checks and immediately before protocol input. It
    /// must not retain the connection reference or perform unbounded I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_with_connection_hook<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
        hook: F,
    ) -> Admit
    where
        F: FnOnce(&AdmissionRequest, &mut SrtConnection) -> AdmissionResolution,
    {
        self.admit_with_policy_hook(
            peer,
            data,
            now,
            options,
            worker_index,
            worker_count,
            telemetry,
            |request, connection| hook(request, connection).into(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_with_policy_hook<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        worker_count: usize,
        telemetry: &IngressTelemetry,
        hook: F,
    ) -> Admit
    where
        F: FnOnce(&AdmissionRequest, &mut SrtConnection) -> AdmissionHookResult,
    {
        self.last_now = now;
        let expired = self.prune_half_open(now);
        telemetry.record_expired_half_open(expired);
        let DecodedAdmissionDatagram {
            handshake,
            destination_socket_id,
        } = match decode_admission_datagram(data) {
            Ok(decoded) => decoded,
            Err(_) => {
                telemetry.record_invalid_datagram();
                return Admit::Dropped(AdmissionDropReason::InvalidPacket);
            }
        };
        // RFC stream multiplexing routes established SRT sockets by the
        // fixed-header Destination SRT Socket ID. INDUCTION is the sole
        // exception: it targets socket ID zero and carries the caller's
        // source SRT Socket ID in the handshake body.
        let mut physical = self.physical_for_datagram(
            peer,
            destination_socket_id,
            handshake
                .as_ref()
                .filter(|packet| packet.handshake_type == shiguredo_srt::HandshakeType::Induction)
                .map(|packet| packet.socket_id),
        );
        if let Some(physical) = physical
            && self.group_peers.contains_key(&physical)
        {
            return self.admit_group_leg(physical, data, now);
        }
        let identity = handshake
            .as_ref()
            .map(srt_lifecycle::handshake_identity_from_handshake);
        let conclusion = identity.as_ref().filter(|identity| identity.is_conclusion);
        physical = self.resolve_conclusion_route(peer, physical, conclusion);
        let known = physical.is_some_and(|physical| self.peers.contains_key(&physical));

        if !known && let Some(identity) = conclusion {
            return Self::stale_conclusion(
                identity,
                options,
                worker_index,
                worker_count,
                telemetry,
            );
        }

        if !known {
            if let Some(result) = self.reject_new_peer(peer, handshake.as_ref(), telemetry) {
                return result;
            }
        } else if let Some(result) = self.apply_known_conclusion_policy(
            KnownConclusionContext {
                peer,
                physical,
                handshake: handshake.as_ref(),
                identity: conclusion,
                now,
                options,
                telemetry,
            },
            hook,
        ) {
            return result;
        }

        let physical = physical.unwrap_or_else(|| PhysicalPeerKey {
            address: peer,
            local_socket_id: self.allocate_listener_socket_id(options.socket_id),
        });
        let new_logical_peer =
            (!known).then(|| self.allocate_logical_peer(LogicalPeerTarget::Direct(physical)));
        let feed = self.feed_admission_datagram(
            physical,
            AdmissionFeedContext {
                peer,
                data,
                now,
                options,
                worker_index,
                new_logical_peer,
            },
        );
        if feed.inserted {
            *self.source_counts.entry(peer.ip()).or_default() += 1;
            self.half_open_peers += 1;
        }
        if !feed.fed {
            return self.finish_admission_failure(physical, known, conclusion, feed, telemetry);
        }
        self.finish_admission_success(physical, now, feed.became_established)
    }

    /// Remove incomplete handshakes that have stopped making progress.
    pub fn prune_half_open(&mut self, now: Timestamp) -> usize {
        let mut due = Vec::new();
        self.half_open_deadlines.pop_due(now, &mut due);
        let timeout_micros = half_open_timeout_micros(self.config.half_open_timeout);
        let mut count = 0;
        for peer in due {
            let stale = self.peers.get(&peer).is_some_and(|entry| {
                !entry.admission_established
                    && now.saturating_sub(entry.last_datagram_at) >= timeout_micros
            });
            if !stale {
                continue;
            }
            let _ = self.remove_physical(peer);
            count += 1;
        }
        count
    }

    /// [`Self::admit`] plus the send it implies: forward the datagram to
    /// the acceptor its cookie names, or keep it here if that channel is
    /// gone. Dropping it instead would cost a handshake retry.
    ///
    /// The send lives here rather than in each adapter because every one
    /// of them did exactly this, and the routing decision is worthless
    /// without the delivery that follows it.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_and_forward(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        senders: &[std::sync::mpsc::Sender<WorkerMessage>],
        telemetry: &IngressTelemetry,
    ) {
        match self.admit(
            peer,
            data,
            now,
            options,
            worker_index,
            senders.len(),
            telemetry,
        ) {
            Admit::Fed => {}
            Admit::ForwardTo(owner) => {
                let message = WorkerMessage::Handshake {
                    peer,
                    data: data.to_vec(),
                };
                if senders[owner].send(message).is_err() {
                    telemetry.record_cookie_route_failure();
                    // The half-open state existed only on the closed owner;
                    // another acceptor cannot safely synthesize it from a
                    // CONCLUSION. The caller's next handshake attempt starts
                    // with a fresh INDUCTION and cookie.
                }
            }
            Admit::Rejected | Admit::Deferred | Admit::Dropped(_) => {}
        }
    }

    /// Resolver-enabled form of [`Self::admit_and_forward`].
    ///
    /// The resolver is called only on the acceptor that owns the retained
    /// half-open state. A datagram forwarded to another acceptor is resolved
    /// there, so policy and credentials never need to cross worker channels.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_and_forward_with_resolver<F>(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
        options: &AdmissionOptions,
        worker_index: usize,
        senders: &[std::sync::mpsc::Sender<WorkerMessage>],
        telemetry: &IngressTelemetry,
        resolve: F,
    ) -> Admit
    where
        F: FnOnce(&AdmissionRequest) -> AdmissionResolution,
    {
        let result = self.admit_with_resolver(
            peer,
            data,
            now,
            options,
            worker_index,
            senders.len(),
            telemetry,
            resolve,
        );
        if let Admit::ForwardTo(owner) = &result {
            let message = WorkerMessage::Handshake {
                peer,
                data: data.to_vec(),
            };
            if senders[*owner].send(message).is_err() {
                telemetry.record_cookie_route_failure();
                return Admit::Dropped(AdmissionDropReason::StaleConclusion);
            }
        }
        result
    }

    /// Fire due peers' timers and collect what ready peers want to send.
    ///
    /// Timer outputs are applied to the peer's own store; only packets
    /// come back, because sending is the one part of the maintenance tick
    /// that is genuinely per-runtime. `out` is reused across ticks rather
    /// than reallocated -- this runs once per tick per acceptor.
    pub fn poll_outbound(
        &mut self,
        now: Timestamp,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        self.last_now = now;
        out.clear();
        let mut rejected = Vec::new();
        self.mark_due_peers(now);
        self.poll_direct_outbound(now, out, &mut rejected);
        self.remove_rejected_peers(rejected);
        self.poll_group_outbound(now, out);
    }

    fn mark_due_peers(&mut self, now: Timestamp) {
        let mut due = Vec::new();
        self.deadlines.pop_due(now, &mut due);
        for peer in due {
            self.mark_ready_physical(peer);
        }
    }

    fn poll_direct_outbound(
        &mut self,
        now: Timestamp,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
        rejected: &mut Vec<PhysicalPeerKey>,
    ) {
        while let Some(peer) = self.ready.pop_front() {
            self.ready_set.remove(&peer);
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            entry.timers.fire_expired(now, &mut entry.conn);
            while let Some(output) = entry.conn.poll_output() {
                match output {
                    ConnectionOutput::SendPacket(bytes) => out.push((peer.address, bytes)),
                    other => entry.timers.apply_output(&other, now),
                }
            }
            if entry.rejected {
                rejected.push(peer);
                continue;
            }
            if let Some(deadline) = entry.timers.next_deadline() {
                self.deadlines.set(peer, deadline);
            } else {
                self.deadlines.remove(&peer);
            }
        }
    }

    fn remove_rejected_peers(&mut self, rejected: Vec<PhysicalPeerKey>) {
        for peer in rejected {
            let _ = self.remove_physical(peer);
        }
    }

    fn poll_group_outbound(
        &mut self,
        now: Timestamp,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        for group in self.groups.values_mut() {
            let (core, legs) = (&mut group.group, &mut group.legs);
            for leg in legs.values_mut() {
                let member = core
                    .member_mut(leg.member_id)
                    .expect("group I/O legs are built with matching members");
                leg.timers.fire_expired(now, member.connection_mut());
                while let Some(output) = member.connection_mut().poll_output() {
                    match output {
                        ConnectionOutput::SendPacket(bytes) => {
                            out.push((leg.physical.address, bytes));
                        }
                        other => leg.timers.apply_output(&other, now),
                    }
                }
            }
        }
    }

    /// Mark a peer whose protocol state was changed through [`Self::iter_mut`]
    /// as ready for the next indexed maintenance pass.
    fn mark_ready_physical(&mut self, peer: PhysicalPeerKey) {
        self.reconcile_established(peer);
        if self.peers.contains_key(&peer) {
            if self.ready_set.insert(peer) {
                self.ready.push_back(peer);
            }
            if self.event_ready_set.insert(peer) {
                self.event_ready.push_back(peer);
            }
        }
    }

    /// Mark the sole ordinary peer at `peer` ready. Applications using a
    /// shared four-tuple should use [`LogicalPeerMut`] instead; an address
    /// alone does not distinguish multiple physical SRT legs.
    pub fn mark_ready(&mut self, peer: std::net::SocketAddr) {
        if let Some(physical) = self.physical_for_address(peer) {
            self.mark_ready_physical(physical);
        }
    }

    /// Microseconds until any tracked peer's next timer deadline.
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        self.last_now = now;
        let peer_deadline = self
            .deadlines
            .peek_min_deadline()
            .map(|deadline| deadline.saturating_sub(now))
            .unwrap_or(default_us);
        self.groups
            .values()
            .flat_map(|group| group.legs.values())
            .filter_map(|leg| leg.timers.next_deadline())
            .map(|deadline| deadline.saturating_sub(now))
            .min()
            .unwrap_or(peer_deadline)
    }

    /// Drain logical ingress events for production consumers.
    pub fn poll_events(&mut self, out: &mut Vec<AdmissionEvent>) {
        out.clear();
        while let Some(peer) = self.event_ready.pop_front() {
            self.event_ready_set.remove(&peer);
            let Some(entry) = self.peers.get_mut(&peer) else {
                continue;
            };
            while let Some(event) = entry.conn.poll_event() {
                out.push(AdmissionEvent {
                    representative_peer: peer.address,
                    logical_peer: entry.logical_peer,
                    event,
                });
            }
        }
        for group in self.groups.values_mut() {
            while let Some(event) = group.group.poll_event(self.last_now) {
                match event {
                    shiguredo_srt::GroupEvent::MemberConnected { .. } => {
                        if !group.connected {
                            group.connected = true;
                            out.push(AdmissionEvent {
                                representative_peer: group.representative_peer,
                                logical_peer: group.logical_peer,
                                event: ConnectionEvent::Connected,
                            });
                        }
                    }
                    shiguredo_srt::GroupEvent::DataReceived(packet) => {
                        group.logical_payloads_received =
                            group.logical_payloads_received.saturating_add(1);
                        group.data_events = group.data_events.saturating_add(1);
                        group.last_data_at = Instant::now();
                        group.logical_payload_bytes_received = group
                            .logical_payload_bytes_received
                            .saturating_add(packet.payload.len() as u64);
                        out.push(AdmissionEvent {
                            representative_peer: group.representative_peer,
                            logical_peer: group.logical_peer,
                            event: ConnectionEvent::DataReceived {
                                payload: packet.payload,
                                sequence_number: packet.sequence_number,
                                message_number: packet.message_number,
                                timestamp: packet.timestamp,
                            },
                        });
                    }
                    shiguredo_srt::GroupEvent::MemberError { error, .. }
                    | shiguredo_srt::GroupEvent::MemberDisconnected { reason: error, .. }
                        if group.connected
                            && !group.group.members().iter().any(|member| {
                                member.connection().state()
                                    == shiguredo_srt::ConnectionState::Connected
                            }) =>
                    {
                        group.connected = false;
                        group.torn_down |= !is_ordered_close(&error);
                        out.push(AdmissionEvent {
                            representative_peer: group.representative_peer,
                            logical_peer: group.logical_peer,
                            event: ConnectionEvent::Disconnected { reason: error },
                        });
                    }
                    shiguredo_srt::GroupEvent::MemberError { .. }
                    | shiguredo_srt::GroupEvent::MemberDisconnected { .. } => {}
                }
            }
        }
    }

    /// Drain protocol events into per-peer bookkeeping.
    ///
    /// Returns, in `newly_connected`, the peers whose *first* `Connected`
    /// fired on this tick -- the moment a promotion decision is due.
    /// `stream_len` sets each one's stream deadline from now.
    pub fn drain_events(
        &mut self,
        stream_len: Duration,
        newly_connected: &mut Vec<NewlyConnectedPeer>,
    ) {
        newly_connected.clear();
        let mut events = Vec::new();
        self.poll_events(&mut events);
        let deadline = Instant::now() + stream_len;
        for admission_event in events {
            let peer = admission_event.representative_peer;
            let connected = matches!(&admission_event.event, ConnectionEvent::Connected);
            match self
                .logical_peers
                .get(&admission_event.logical_peer)
                .cloned()
            {
                Some(LogicalPeerTarget::Direct(physical)) => {
                    if let Some(entry) = self.peers.get_mut(&physical)
                        && entry.apply_event(admission_event.event)
                    {
                        entry.stream_deadline = Some(deadline);
                        newly_connected.push(NewlyConnectedPeer {
                            logical_peer: admission_event.logical_peer,
                            representative_peer: peer,
                        });
                    }
                }
                Some(LogicalPeerTarget::Group(key)) => {
                    if let Some(group) = self.groups.get_mut(&key)
                        && connected
                        && group.stream_deadline.is_none()
                    {
                        group.stream_deadline = Some(deadline);
                        newly_connected.push(NewlyConnectedPeer {
                            logical_peer: admission_event.logical_peer,
                            representative_peer: peer,
                        });
                    }
                }
                None => {}
            }
        }
        // A group can become connected while its member event is drained by
        // an earlier maintenance pass. Keep the stream clock tied to the
        // persistent logical state as well as to this pass's event batch, so
        // that case cannot leave a completed bonded stream waiting for the
        // handshake deadline.
        for group in self.groups.values_mut() {
            if group.connected && group.stream_deadline.is_none() {
                group.stream_deadline = Some(deadline);
                newly_connected.push(NewlyConnectedPeer {
                    logical_peer: group.logical_peer,
                    representative_peer: group.representative_peer,
                });
            }
        }
    }

    /// Return the steady-state view for either an ordinary connection or an
    /// opted-in bonded group. New consumers should retain this identity from
    /// [`AdmissionEvent::logical_peer`] rather than using a bonded group's
    /// representative socket address as a session key.
    #[must_use]
    pub fn logical_peer(&self, id: &LogicalPeerId) -> Option<LogicalPeer<'_>> {
        match self.logical_peers.get(id)? {
            LogicalPeerTarget::Direct(peer) if self.peers.contains_key(peer) => Some(LogicalPeer {
                table: self,
                id: *id,
            }),
            LogicalPeerTarget::Group(key) if self.groups.contains_key(key) => Some(LogicalPeer {
                table: self,
                id: *id,
            }),
            LogicalPeerTarget::Direct(_) | LogicalPeerTarget::Group(_) => None,
        }
    }

    /// Return the mutable steady-state view for either an ordinary connection
    /// or an opted-in bonded group.
    pub fn logical_peer_mut(&mut self, id: &LogicalPeerId) -> Option<LogicalPeerMut<'_>> {
        self.logical_peer(id)?;
        Some(LogicalPeerMut {
            table: self,
            id: *id,
        })
    }

    /// Atomically retire one logical stream. For a bonded publisher this
    /// removes every physical leg; a late datagram for any returned Socket ID
    /// is ignored and can never recreate the retired group.
    pub fn remove(&mut self, id: LogicalPeerId) -> Option<RemovedLogicalPeer> {
        match self.logical_peers.get(&id).cloned()? {
            LogicalPeerTarget::Direct(peer) => self.remove_direct(peer).map(|entry| {
                RemovedLogicalPeer::Direct(Box::new(RemovedPeerLeg {
                    peer: peer.address,
                    connection: entry.conn,
                }))
            }),
            LogicalPeerTarget::Group(key) => self.remove_group(key),
        }
    }

    /// Benchmark-only physical extraction for the legacy reuseport promotion
    /// experiment. Production integrations use [`Self::remove`] with a
    /// [`LogicalPeerId`].
    #[cfg(feature = "bench-internals")]
    pub fn remove_direct_for_bench(&mut self, peer: std::net::SocketAddr) -> Option<AdmissionPeer> {
        self.physical_for_address(peer)
            .and_then(|physical| self.remove_direct(physical))
    }

    /// Benchmark-only direct-peer iterator for the legacy reuseport
    /// promotion experiment. It is deliberately absent from production builds.
    #[cfg(feature = "bench-internals")]
    pub fn iter_direct_for_bench(
        &mut self,
    ) -> impl Iterator<Item = (&std::net::SocketAddr, &mut AdmissionPeer)> {
        self.peers
            .iter_mut()
            .map(|(physical, entry)| (&physical.address, entry))
    }

    /// Benchmark-only direct peer inspection for the legacy reuseport
    /// promotion experiment. It is deliberately absent from production builds.
    #[cfg(feature = "bench-internals")]
    pub fn direct_for_bench(&self, peer: std::net::SocketAddr) -> Option<&AdmissionPeer> {
        self.physical_for_address(peer)
            .and_then(|physical| self.peers.get(&physical))
    }

    fn remove_physical(&mut self, peer: PhysicalPeerKey) -> Option<AdmissionPeer> {
        if let Some(handle) = self.group_peers.get(&peer).cloned() {
            let _ = self.remove_group(handle.key)?;
            return None;
        }
        self.remove_direct(peer)
    }

    fn remove_direct(&mut self, peer: PhysicalPeerKey) -> Option<AdmissionPeer> {
        self.purge_physical_indexes(peer);
        let removed = self.peers.remove(&peer);
        if let Some(entry) = &removed {
            self.logical_peers.remove(&entry.logical_peer);
            if entry.admission_established {
                self.established_peers = self.established_peers.saturating_sub(1);
            } else {
                self.half_open_peers = self.half_open_peers.saturating_sub(1);
            }
        }
        if removed.is_some()
            && let HashEntry::Occupied(mut entry) = self.source_counts.entry(peer.address.ip())
        {
            let count = entry.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                entry.remove();
            }
        }
        removed
    }

    fn remove_group(&mut self, key: srt_lifecycle::LogicalGroupKey) -> Option<RemovedLogicalPeer> {
        let mut group = self.groups.remove(&key)?;
        self.logical_peers.remove(&group.logical_peer);
        let mut removed = Vec::with_capacity(group.legs.len());
        for (member_id, leg) in std::mem::take(&mut group.legs) {
            let connection = group
                .group
                .remove_member_connection(member_id)
                .expect("group I/O legs are built with matching members");
            self.group_peers.remove(&leg.physical);
            self.purge_physical_indexes(leg.physical);
            self.peers.remove(&leg.physical);
            self.established_peers = self.established_peers.saturating_sub(1);
            self.decrement_source_count(leg.physical.address.ip());
            removed.push(RemovedPeerLeg {
                peer: leg.physical.address,
                connection,
            });
        }
        Some(RemovedLogicalPeer::Group(removed))
    }

    fn decrement_source_count(&mut self, ip: std::net::IpAddr) {
        if let HashEntry::Occupied(mut entry) = self.source_counts.entry(ip) {
            let count = entry.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                entry.remove();
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, peer: &std::net::SocketAddr) -> bool {
        self.physical_for_address(*peer).is_some()
    }

    #[cfg(test)]
    pub(crate) fn get(&self, peer: &std::net::SocketAddr) -> Option<&AdmissionPeer> {
        self.physical_for_address(*peer)
            .and_then(|physical| self.peers.get(&physical))
    }

    #[cfg(test)]
    pub(crate) fn all_group_streams_have_deadlines(&self) -> bool {
        self.groups
            .values()
            .all(|group| group.stream_deadline.is_some())
    }

    fn purge_physical_indexes(&mut self, peer: PhysicalPeerKey) {
        self.deadlines.remove(&peer);
        self.half_open_deadlines.remove(&peer);
        self.ready_set.remove(&peer);
        self.ready.retain(|queued| *queued != peer);
        self.event_ready_set.remove(&peer);
        self.event_ready.retain(|queued| *queued != peer);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len() + self.group_peers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty() && self.group_peers.is_empty()
    }

    #[must_use]
    pub fn half_open_count(&self) -> usize {
        self.half_open_peers
    }

    #[must_use]
    pub fn established_count(&self) -> usize {
        self.established_peers
    }

    /// Snapshot every active bonded ingress with both logical delivery and
    /// per-leg wire telemetry. Ordinary unbonded peers are intentionally not
    /// included: their existing [`AdmissionPeer`] stats retain the normal
    /// single-connection meaning.
    #[must_use]
    pub fn bonded_stats(&self) -> Vec<InboundGroupStats> {
        self.groups
            .iter()
            .map(|(key, group)| InboundGroupStats {
                key: key.clone(),
                ever_connected: group.stream_deadline.is_some(),
                torn_down: group.torn_down,
                connection: group_connection_stats(
                    &group.group,
                    GroupLogicalCounters {
                        payloads_sent: group.logical_payloads_sent,
                        payload_bytes_sent: group.logical_payload_bytes_sent,
                        payloads_received: group.logical_payloads_received,
                        payload_bytes_received: group.logical_payload_bytes_received,
                    },
                    |member_id| {
                        let peer_addr = group.legs.get(&member_id).map(|leg| leg.physical.address);
                        (None, peer_addr)
                    },
                ),
            })
            .collect()
    }

    #[must_use]
    pub fn peers_for_ip(&self, ip: std::net::IpAddr) -> usize {
        self.source_counts.get(&ip).copied().unwrap_or_default()
    }

    fn reconcile_established(&mut self, peer: PhysicalPeerKey) {
        let became_established = self.peers.get_mut(&peer).is_some_and(|entry| {
            if !entry.admission_established
                && entry.conn.state() == shiguredo_srt::ConnectionState::Connected
            {
                entry.admission_established = true;
                true
            } else {
                false
            }
        });
        if became_established {
            self.half_open_peers = self.half_open_peers.saturating_sub(1);
            self.established_peers += 1;
            self.half_open_deadlines.remove(&peer);
        }
    }

    /// Whether every tracked peer is done, so the acceptor can stop.
    /// Vacuously true when empty, so an acceptor that never admitted
    /// anything still exits once its connect window closes.
    #[must_use]
    pub fn all_terminal(
        &self,
        now: Instant,
        connect_deadline: Instant,
        idle_grace: Duration,
    ) -> bool {
        self.peers
            .iter()
            // Bonded physical legs are represented by the one logical group
            // below. Their `AdmissionPeer` bookkeeping deliberately never
            // receives direct events, so counting them here would make a
            // completed group wait for the handshake deadline.
            .filter(|(peer, _)| !self.group_peers.contains_key(peer))
            .all(|(_, p)| {
                srt_lifecycle::is_terminal(
                    p.connected,
                    p.stream_deadline,
                    p.last_data_at,
                    now,
                    connect_deadline,
                    idle_grace,
                )
            })
            && self.groups.values().all(|group| {
                srt_lifecycle::is_terminal(
                    group.connected,
                    group.stream_deadline,
                    group.last_data_at,
                    now,
                    connect_deadline,
                    idle_grace,
                )
            })
    }

    /// Number of application-visible streams with at least one live SRT leg.
    /// A bonded group contributes one even when several member connections
    /// are established on the same UDP tuple.
    #[must_use]
    pub fn logical_connected_count(&self) -> usize {
        let direct = self
            .peers
            .iter()
            .filter(|(peer, entry)| {
                !self.group_peers.contains_key(peer)
                    && entry.conn.state() == shiguredo_srt::ConnectionState::Connected
            })
            .count();
        let groups = self
            .groups
            .values()
            .filter(|group| {
                group.group.members().iter().any(|member| {
                    member.connection().state() == shiguredo_srt::ConnectionState::Connected
                })
            })
            .count();
        direct + groups
    }

    /// Number of logical streams that have completed their initial SRT
    /// handshake, even if an orderly close has already begun.
    #[must_use]
    pub fn logical_started_count(&self) -> usize {
        let direct = self
            .peers
            .iter()
            .filter(|(peer, entry)| {
                !self.group_peers.contains_key(peer) && entry.stream_deadline.is_some()
            })
            .count();
        let groups = self
            .groups
            .values()
            .filter(|group| group.stream_deadline.is_some())
            .count();
        direct + groups
    }
}

impl IntoIterator for PeerTable {
    type Item = (std::net::SocketAddr, AdmissionPeer);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.peers
            .into_iter()
            .map(|(physical, peer)| (physical.address, peer))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Per-peer entropy for the upper bits of a SYN cookie, so cookies differ
/// per connection instead of being one constant per worker.
/// Is this datagram a CONTROL packet?
///
/// SRT's first header word carries the packet type in its top bit: 1 for
/// CONTROL, 0 for DATA (`PacketType::from_first_word`). Only a CONTROL
/// packet can be a handshake, so this is the cheap pre-filter that keeps a
/// full decode off the DATA path. A datagram too short to hold a header is
/// not a handshake either.
fn is_control_datagram(data: &[u8]) -> bool {
    data.first().is_some_and(|byte| byte & 0x80 != 0)
}

fn peer_entropy(peer: std::net::SocketAddr) -> u32 {
    use std::hash::BuildHasher;
    std::collections::hash_map::RandomState::new().hash_one(peer) as u32
}

fn half_open_timeout_micros(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn induction_packet(socket_id: u32) -> Vec<u8> {
        let packet = shiguredo_srt::HandshakePacket::new_induction_request(socket_id).encode(0, 0);
        let mut bytes = Vec::new();
        packet.encode(&mut bytes);
        bytes
    }

    fn default_options() -> AdmissionOptions {
        AdmissionOptions::basic(1, 120, false)
    }

    proptest! {
        #[test]
        fn capacity_limits_never_exceeded(
            max_peers in 2..16usize,
            max_half_open in 1..8usize,
            peer_count in 1..32u16,
        ) {
            let config = PeerTableConfig {
                max_peers,
                max_half_open_peers: max_half_open,
                max_established_peers: max_peers,
                max_peers_per_ip: max_peers,
                half_open_timeout: Duration::from_secs(60),
            };
            let mut table = PeerTable::with_config(config);
            let telemetry = IngressTelemetry::new();
            let options = default_options();

            for i in 0..peer_count {
                let peer = std::net::SocketAddr::from(([10, 0, (i >> 8) as u8, i as u8], 5000));
                let packet = induction_packet(100 + u32::from(i));
                table.admit(
                    peer,
                    &packet,
                    Timestamp::from_micros(u64::from(i) * 1000),
                    &options,
                    0,
                    1,
                    &telemetry,
                );

                let effective_max = config.max_peers.max(1);
                let effective_half_open = config.max_half_open_peers.max(1).min(effective_max);
                prop_assert!(
                    table.len() <= effective_max,
                    "total peers {} > max {}",
                    table.len(),
                    effective_max,
                );
                prop_assert!(
                    table.half_open_count() <= effective_half_open,
                    "half-open {} > max {}",
                    table.half_open_count(),
                    effective_half_open,
                );
            }
        }

        #[test]
        fn per_ip_limit_enforced(
            max_per_ip in 1..4usize,
            attempts in 1..16u16,
        ) {
            let config = PeerTableConfig {
                max_peers: 64,
                max_half_open_peers: 64,
                max_established_peers: 64,
                max_peers_per_ip: max_per_ip,
                half_open_timeout: Duration::from_secs(60),
            };
            let mut table = PeerTable::with_config(config);
            let telemetry = IngressTelemetry::new();
            let options = default_options();

            let mut admitted = 0usize;
            for i in 0..attempts {
                let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 5000 + i));
                let packet = induction_packet(200 + u32::from(i));
                let result = table.admit(
                    peer,
                    &packet,
                    Timestamp::from_micros(u64::from(i) * 1000),
                    &options,
                    0,
                    1,
                    &telemetry,
                );
                if !matches!(result, Admit::Dropped(_)) {
                    admitted += 1;
                }
            }
            let effective_limit = max_per_ip.max(1);
            prop_assert!(
                admitted <= effective_limit,
                "admitted {} from one IP > limit {}",
                admitted,
                effective_limit,
            );
        }
    }

    #[test]
    fn half_open_expiry_frees_slots() {
        let config = PeerTableConfig {
            max_peers: 4,
            max_half_open_peers: 2,
            max_established_peers: 4,
            max_peers_per_ip: 4,
            half_open_timeout: Duration::from_millis(100),
        };
        let mut table = PeerTable::with_config(config);
        let telemetry = IngressTelemetry::new();
        let options = default_options();

        let peer_a = "10.0.0.1:5000".parse().unwrap();
        let peer_b = "10.0.0.2:5000".parse().unwrap();
        let peer_c = "10.0.0.3:5000".parse().unwrap();

        table.admit(
            peer_a,
            &induction_packet(1),
            Timestamp::from_micros(0),
            &options,
            0,
            1,
            &telemetry,
        );
        table.admit(
            peer_b,
            &induction_packet(2),
            Timestamp::from_micros(0),
            &options,
            0,
            1,
            &telemetry,
        );
        assert_eq!(table.half_open_count(), 2);

        let result = table.admit(
            peer_c,
            &induction_packet(3),
            Timestamp::from_micros(0),
            &options,
            0,
            1,
            &telemetry,
        );
        assert!(matches!(
            result,
            Admit::Dropped(AdmissionDropReason::HalfOpenCapacity)
        ));

        let result = table.admit(
            peer_c,
            &induction_packet(3),
            Timestamp::from_micros(200_000),
            &options,
            0,
            1,
            &telemetry,
        );
        assert!(
            !matches!(
                result,
                Admit::Dropped(AdmissionDropReason::HalfOpenCapacity)
            ),
            "after expiry, peer_c should be admitted"
        );
    }
}
