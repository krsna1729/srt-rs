use crate::{
    BatchIoStats, CallerConfig, ConfigError, GroupConfig, ManualTimerStore, OutputDrainBudget,
    OutputDrainReport, RecvBatch, RecvBudget, RecvDrainReport, RuntimeFlavor,
    drain_connected_outputs, drain_recv_fd, sendmsg_connected_batch,
};
use shiguredo_srt::{Bytes, ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::fmt;
use std::os::fd::AsRawFd;

// ---------------------------------------------------------------------------
// Bonded/group caller transport
// ---------------------------------------------------------------------------

/// One outbound leg supplied when constructing a [`GroupConn`]. The socket
/// must be connected and nonblocking; [`GroupConn::caller`] constructs such
/// legs from [`CallerConfig`] when an application does not need custom I/O.
pub struct GroupConnectionLeg {
    pub member_id: u32,
    pub weight: u16,
    pub connection: SrtConnection,
    pub socket: std::net::UdpSocket,
}

/// Configuration for one outbound leg of a bonded caller.
#[derive(Clone, Debug)]
pub struct GroupCallerLeg {
    pub member_id: u32,
    pub weight: u16,
    pub caller: CallerConfig,
}

impl GroupCallerLeg {
    #[must_use]
    pub fn new(member_id: u32, weight: u16, caller: CallerConfig) -> Self {
        Self {
            member_id,
            weight,
            caller,
        }
    }
}

/// Failure while constructing a bonded caller.
#[derive(Debug)]
pub enum GroupBuildError {
    Config(ConfigError),
    Io(std::io::Error),
    Protocol(shiguredo_srt::Error),
    InvalidGroupType,
}

impl fmt::Display for GroupBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
            Self::InvalidGroupType => write!(f, "bond group type must be Broadcast or Backup"),
        }
    }
}

impl std::error::Error for GroupBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::InvalidGroupType => None,
        }
    }
}

impl From<ConfigError> for GroupBuildError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<std::io::Error> for GroupBuildError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<shiguredo_srt::Error> for GroupBuildError {
    fn from(value: shiguredo_srt::Error) -> Self {
        Self::Protocol(value)
    }
}

struct GroupLegIo {
    member_id: u32,
    socket: std::net::UdpSocket,
    timers: ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
    recv_budget: RecvBudget,
}

#[derive(Clone, Copy)]
struct GroupLegPolicy {
    recv_budget: RecvBudget,
    batch_capacity: usize,
}

/// Per-leg I/O work completed by one [`GroupConn::drive`] call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupLegDriveReport {
    pub member_id: u32,
    pub received_datagrams: usize,
    pub output: OutputDrainReport,
    /// Datagrams this leg's socket delivered that `feed_recv_buf` rejected
    /// as malformed or misdirected (T04). Never fatal to the leg or the
    /// group -- the connection's state is untouched by a decode failure,
    /// so these are simply dropped and counted.
    pub malformed_datagrams: usize,
    /// `true` if a genuine recv or send syscall failure on this leg (not
    /// `WouldBlock`, and not a malformed datagram) caused *this* call to
    /// transition the member into [`shiguredo_srt::GroupMemberState::Broken`]
    /// (T04) -- `false` on a call that finds it already `Broken`, so a
    /// consumer watching for a once-per-failure edge (trigger failover,
    /// emit one alert) does not see it re-fire on every later drive.
    pub newly_broken: bool,
}

/// Work completed by one bounded bonded-transport maintenance call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupDriveReport {
    pub legs: Vec<GroupLegDriveReport>,
}

impl GroupDriveReport {
    #[must_use]
    pub fn received_datagrams(&self) -> usize {
        self.legs.iter().map(|leg| leg.received_datagrams).sum()
    }
}

/// Snapshot for one physical bonded leg. Connection counters retain their
/// normal single-SRT meaning and are never deduplicated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupLegStats {
    pub member_id: u32,
    pub weight: u16,
    pub state: shiguredo_srt::GroupMemberState,
    pub local_addr: Option<std::net::SocketAddr>,
    pub peer_addr: Option<std::net::SocketAddr>,
    pub connection: shiguredo_srt::ConnectionStats,
}

/// Group-level telemetry with explicitly separate logical and wire views.
///
/// `logical_*` counts one payload once at the group API boundary. `wire_*`
/// sums all legs, so Broadcast correctly reports duplicated media delivery
/// and retransmissions rather than disguising their network cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupAggregateStats {
    /// Physical legs that have completed their individual SRT handshakes and
    /// are currently eligible for the group's delivery policy. Peers may
    /// admit these asynchronously (notably a libsrt mirror group), so callers
    /// that require a particular redundancy level should keep driving the
    /// group and wait for this count rather than assuming construction makes
    /// every leg ready.
    pub active_legs: usize,
    pub standby_legs: usize,
    pub pending_legs: usize,
    pub unstable_legs: usize,
    pub broken_legs: usize,
    pub logical_payloads_sent: u64,
    pub logical_payload_bytes_sent: u64,
    pub logical_payloads_received: u64,
    pub logical_payload_bytes_received: u64,
    pub wire_unique_packets_sent: u64,
    pub wire_packets_sent: u64,
    pub wire_payload_bytes_sent: u64,
    pub wire_srt_bytes_sent: u64,
    pub wire_packets_retransmitted: u64,
    /// Sum of sender-side loss occurrences reported by peers through NAKs.
    pub wire_sender_packets_lost: u64,
    pub wire_packets_received: u64,
    pub wire_unique_packets_received: u64,
    pub wire_srt_bytes_received: u64,
    /// Sum of receiver-side missing sequence numbers detected on all legs.
    pub wire_receiver_packets_lost: u64,
    pub wire_packets_undecryptable: u64,
}

/// Complete bonded-connection telemetry: one snapshot per leg plus a clearly
/// named aggregate that is safe for dashboards and alerting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupConnectionStats {
    pub group_id: u32,
    pub mode: shiguredo_srt::GroupMode,
    pub aggregate: GroupAggregateStats,
    pub legs: Vec<GroupLegStats>,
}

/// Ingress-facing bonded telemetry. The logical key disambiguates publishers
/// that happen to reuse a wire group ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundGroupStats {
    pub key: srt_lifecycle::LogicalGroupKey,
    /// Whether the logical group completed an SRT connection at least once.
    pub ever_connected: bool,
    /// Whether every leg ended unexpectedly after the group had connected.
    pub torn_down: bool,
    pub connection: GroupConnectionStats,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct GroupLogicalCounters {
    pub(crate) payloads_sent: u64,
    pub(crate) payload_bytes_sent: u64,
    pub(crate) payloads_received: u64,
    pub(crate) payload_bytes_received: u64,
}

pub(crate) fn group_connection_stats(
    group: &shiguredo_srt::SrtGroup,
    logical: GroupLogicalCounters,
    mut addresses: impl FnMut(u32) -> (Option<std::net::SocketAddr>, Option<std::net::SocketAddr>),
) -> GroupConnectionStats {
    let mut aggregate = GroupAggregateStats {
        logical_payloads_sent: logical.payloads_sent,
        logical_payload_bytes_sent: logical.payload_bytes_sent,
        logical_payloads_received: logical.payloads_received,
        logical_payload_bytes_received: logical.payload_bytes_received,
        ..GroupAggregateStats::default()
    };
    let mut legs = Vec::with_capacity(group.members().len());
    for member in group.members() {
        match member.state() {
            shiguredo_srt::GroupMemberState::Active => aggregate.active_legs += 1,
            shiguredo_srt::GroupMemberState::Standby => aggregate.standby_legs += 1,
            shiguredo_srt::GroupMemberState::Pending => aggregate.pending_legs += 1,
            shiguredo_srt::GroupMemberState::Unstable => aggregate.unstable_legs += 1,
            shiguredo_srt::GroupMemberState::Broken => aggregate.broken_legs += 1,
        }
        let connection = member.connection().stats();
        if let Some(sender) = connection.sender {
            aggregate.wire_unique_packets_sent = aggregate
                .wire_unique_packets_sent
                .saturating_add(sender.total_sent);
            aggregate.wire_packets_sent = aggregate
                .wire_packets_sent
                .saturating_add(sender.total_data_packets_sent);
            aggregate.wire_payload_bytes_sent = aggregate
                .wire_payload_bytes_sent
                .saturating_add(sender.total_bytes_sent);
            aggregate.wire_srt_bytes_sent = aggregate
                .wire_srt_bytes_sent
                .saturating_add(sender.total_srt_bytes_sent);
            aggregate.wire_packets_retransmitted = aggregate
                .wire_packets_retransmitted
                .saturating_add(sender.total_retransmits);
            aggregate.wire_sender_packets_lost = aggregate
                .wire_sender_packets_lost
                .saturating_add(sender.total_lost);
        }
        if let Some(receiver) = connection.receiver {
            aggregate.wire_packets_received = aggregate
                .wire_packets_received
                .saturating_add(receiver.total_data_packets_received);
            aggregate.wire_unique_packets_received = aggregate
                .wire_unique_packets_received
                .saturating_add(receiver.total_received);
            aggregate.wire_srt_bytes_received = aggregate
                .wire_srt_bytes_received
                .saturating_add(receiver.total_srt_bytes_received);
            aggregate.wire_receiver_packets_lost = aggregate
                .wire_receiver_packets_lost
                .saturating_add(receiver.total_lost);
            aggregate.wire_packets_undecryptable = aggregate
                .wire_packets_undecryptable
                .saturating_add(receiver.total_undecryptable);
        }
        let (local_addr, peer_addr) = addresses(member.id());
        legs.push(GroupLegStats {
            member_id: member.id(),
            weight: member.weight(),
            state: member.state(),
            local_addr,
            peer_addr,
            connection,
        });
    }
    GroupConnectionStats {
        group_id: group.group_id(),
        mode: group.mode(),
        aggregate,
        legs,
    }
}

/// Runtime-neutral multi-socket driver for an SRT Broadcast or Backup group.
///
/// This is intentionally synchronous and nonblocking. Tokio, smol, mio, and
/// other runtimes can register the exposed leg sockets in their own reactors,
/// then call [`Self::drive`] when any leg is readable or a timer is due. That
/// keeps group semantics in one implementation instead of copying subtly
/// different versions into every runtime adapter.
pub struct GroupConn {
    group: shiguredo_srt::SrtGroup,
    legs: Vec<GroupLegIo>,
    logical_payloads_sent: u64,
    logical_payload_bytes_sent: u64,
    logical_payloads_received: u64,
    logical_payload_bytes_received: u64,
    recv_batch: RecvBatch,
    io_stats: BatchIoStats,
}

impl GroupConn {
    /// Build a group around caller configurations, binding one connected UDP
    /// socket and initiating one SRT handshake for every supplied leg. Every
    /// leg uses one group-wide initial packet sequence, as required by bonded
    /// peers such as libsrt. Construction initiates all handshakes but does
    /// not make every leg active synchronously: keep calling [`Self::drive`]
    /// and use [`GroupConnectionStats::aggregate`]'s `active_legs` count when
    /// an application needs full Broadcast redundancy before sending media.
    pub fn caller(
        group: GroupConfig,
        legs: impl IntoIterator<Item = GroupCallerLeg>,
        runtime: RuntimeFlavor,
        now: Timestamp,
    ) -> Result<Self, GroupBuildError> {
        let mut prepared_legs = Vec::new();
        let mut shared_initial_seq = None;
        for leg in legs {
            let mut caller = leg.caller;
            let group_initial_seq = match shared_initial_seq {
                Some(initial_seq) => initial_seq,
                None => {
                    let generated_initial_seq = caller.session.ensure_initial_seq()?;
                    shared_initial_seq = Some(generated_initial_seq);
                    generated_initial_seq
                }
            };
            caller.session.set_initial_seq(group_initial_seq);
            caller.session.set_group(Some(GroupConfig {
                group_id: group.group_id,
                group_type: group.group_type,
                flags: group.flags,
                weight: leg.weight,
            }));
            let prepared = caller.prepare(runtime)?;
            // Every leg already gets its own dedicated socket by
            // construction (one per group member); `Shared` ownership,
            // which multiplexes several sessions onto one socket, is never
            // meaningful here. Reject it before `bind_socket` can perform
            // any socket I/O: Shared callers are deliberately left
            // unconnected and cannot use this driver's connected send path.
            prepared.require_exclusive()?;
            let policy = GroupLegPolicy {
                recv_budget: prepared.transport.recv_budget,
                batch_capacity: prepared.transport.recv_batch_capacity(),
            };
            prepared_legs.push((
                GroupConnectionLeg {
                    member_id: leg.member_id,
                    weight: leg.weight,
                    connection: prepared.connection(now)?,
                    socket: prepared.bind_socket()?,
                },
                policy,
            ));
        }
        let mode = shiguredo_srt::GroupMode::from_group_type(group.group_type)
            .ok_or(GroupBuildError::InvalidGroupType)?;
        Ok(Self::new_with_policies(
            group.group_id,
            mode,
            prepared_legs,
        )?)
    }

    /// Assemble a group from application-owned protocol cores and connected,
    /// nonblocking sockets. This is the integration point for custom runtimes
    /// and for applications that own their own socket provisioning.
    pub fn new(
        group_id: u32,
        mode: shiguredo_srt::GroupMode,
        legs: impl IntoIterator<Item = GroupConnectionLeg>,
    ) -> Result<Self, shiguredo_srt::Error> {
        Self::new_with_policies(
            group_id,
            mode,
            legs.into_iter().map(|leg| {
                (
                    leg,
                    GroupLegPolicy {
                        recv_budget: RecvBudget::default(),
                        batch_capacity: RecvBatch::DEFAULT_CAPACITY,
                    },
                )
            }),
        )
    }

    fn new_with_policies(
        group_id: u32,
        mode: shiguredo_srt::GroupMode,
        legs: impl IntoIterator<Item = (GroupConnectionLeg, GroupLegPolicy)>,
    ) -> Result<Self, shiguredo_srt::Error> {
        let mut group = shiguredo_srt::SrtGroup::new(group_id, mode)?;
        let mut io_legs = Vec::new();
        let mut batch_capacity = 0usize;
        for (leg, policy) in legs {
            group.add_member(leg.member_id, leg.weight, leg.connection)?;
            batch_capacity = batch_capacity.max(policy.batch_capacity);
            io_legs.push(GroupLegIo {
                member_id: leg.member_id,
                socket: leg.socket,
                timers: ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
                recv_budget: policy.recv_budget,
            });
        }
        let batch_capacity = if io_legs.is_empty() {
            RecvBatch::DEFAULT_CAPACITY
        } else {
            batch_capacity.max(1)
        };
        Ok(Self {
            group,
            legs: io_legs,
            logical_payloads_sent: 0,
            logical_payload_bytes_sent: 0,
            logical_payloads_received: 0,
            logical_payload_bytes_received: 0,
            // D02: one wire datagram is always MTU-bounded (SRT's default
            // path MTU is far under 2 KiB), and every slot uses the same
            // bounded buffer as the non-bonded receive driver. The scratch
            // count is the largest resolved per-leg batch policy so each leg
            // can still receive up to its own configured budget without a
            // per-leg allocation.
            recv_batch: RecvBatch::with_capacity(batch_capacity, RecvBatch::DEFAULT_BUF_LEN),
            io_stats: BatchIoStats::default(),
        })
    }

    #[must_use]
    pub fn group(&self) -> &shiguredo_srt::SrtGroup {
        &self.group
    }

    /// Physical sockets to register with an application's runtime reactor.
    /// Call [`Self::drive`] after readability or at the next timer deadline.
    pub fn leg_sockets(&self) -> impl ExactSizeIterator<Item = (u32, &std::net::UdpSocket)> {
        self.legs.iter().map(|leg| (leg.member_id, &leg.socket))
    }

    /// Microseconds until the earliest leg timer, falling back to
    /// `default_micros` when no timer is armed.
    #[must_use]
    pub fn time_until_next_deadline(&self, now: Timestamp, default_micros: u64) -> u64 {
        self.legs
            .iter()
            .map(|leg| leg.timers.time_until_earliest(now, default_micros))
            .min()
            .unwrap_or(default_micros)
    }

    /// Send one logical payload according to the group's Broadcast or Backup
    /// policy. The return value is the number of physical legs selected.
    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, shiguredo_srt::Error> {
        let legs = self.group.send(payload, now)?;
        self.logical_payloads_sent = self.logical_payloads_sent.saturating_add(1);
        self.logical_payload_bytes_sent = self
            .logical_payload_bytes_sent
            .saturating_add(payload.len() as u64);
        Ok(legs)
    }

    /// Send shared payload data. Uses reference-counted `Bytes` to avoid
    /// deep-copying the payload for each group leg.
    pub fn send_shared(
        &mut self,
        payload: Bytes,
        now: Timestamp,
    ) -> Result<usize, shiguredo_srt::Error> {
        let len = payload.len() as u64;
        let legs = self.group.send_shared(payload, now)?;
        self.logical_payloads_sent = self.logical_payloads_sent.saturating_add(1);
        self.logical_payload_bytes_sent = self.logical_payload_bytes_sent.saturating_add(len);
        Ok(legs)
    }

    /// Whether the next logical payload can be accepted without weakening the
    /// selected Broadcast or Backup delivery contract.
    pub fn can_send(&mut self) -> bool {
        self.group.can_send()
    }

    pub fn can_send_with_pacing(&mut self, now: Timestamp) -> bool {
        self.group.can_send_with_pacing(now)
    }

    pub fn time_until_send(&self, now: Timestamp) -> u64 {
        self.group.time_until_send(now)
    }

    /// Start an orderly close of every physical group leg.
    pub fn disconnect(&mut self, now: Timestamp) {
        self.group.disconnect(now);
    }

    /// Return the next deduplicated, sequence-aligned group payload.
    pub fn poll_data(&mut self, now: Timestamp) -> Option<shiguredo_srt::GroupPacket> {
        let packet = self.group.poll_data(now)?;
        self.logical_payloads_received = self.logical_payloads_received.saturating_add(1);
        self.logical_payload_bytes_received = self
            .logical_payload_bytes_received
            .saturating_add(packet.payload.len() as u64);
        Some(packet)
    }

    #[must_use]
    pub fn io_stats(&self) -> BatchIoStats {
        self.io_stats
    }

    /// Drive timers, nonblocking UDP input, and a bounded output pump for
    /// every leg once. Each leg's resolved receive budget bounds its own
    /// work, so a busy member cannot consume another member's budget.
    ///
    /// `report` is cleared and refilled in place (D02): a caller drives
    /// every tick, so this reuses the caller-owned `Vec`'s capacity instead
    /// of allocating a fresh one per call.
    pub fn drive(
        &mut self,
        now: Timestamp,
        output_budget: OutputDrainBudget,
        report: &mut GroupDriveReport,
    ) -> std::io::Result<()> {
        report.legs.clear();
        {
            let (group, legs, recv_batch, io_stats) = (
                &mut self.group,
                &mut self.legs,
                &mut self.recv_batch,
                &mut self.io_stats,
            );
            for leg in legs {
                let conn = group
                    .member_mut(leg.member_id)
                    .expect("group and I/O legs are built together")
                    .connection_mut();
                leg.timers.fire_expired(now, conn);

                // T04: a malformed or misdirected datagram is a per-packet
                // decode/routing failure -- `feed_recv_buf` leaves the
                // connection's own state untouched, so it is never a
                // reason to break this leg, let alone the group. Only a
                // genuine syscall failure below (not `WouldBlock`, which
                // `drain_recv_fd`/`drain_group_leg_outputs` already fold
                // into their `Ok` reports) marks a leg broken.
                let mut malformed_datagrams = 0usize;
                let recv_result = drain_recv_fd(
                    leg.socket.as_raw_fd(),
                    recv_batch,
                    leg.recv_budget,
                    |_, data| {
                        if conn.feed_recv_buf(data, now).is_err() {
                            malformed_datagrams += 1;
                        }
                    },
                );
                let mut newly_broken = false;
                let received = match recv_result {
                    Ok(received) => {
                        io_stats.record_recv(received);
                        received
                    }
                    Err(_) => {
                        newly_broken = mark_member_broken_if_new(group, leg.member_id);
                        RecvDrainReport::default()
                    }
                };

                // Re-borrow: `mark_member_broken` above needed `group` free
                // of the earlier connection borrow. A leg just marked
                // broken can still legitimately flush queued output (e.g.
                // a final Shutdown control packet), so this is not
                // skipped.
                let conn = group
                    .member_mut(leg.member_id)
                    .expect("group and I/O legs are built together")
                    .connection_mut();
                let output = match drain_group_leg_outputs(conn, leg, now, output_budget) {
                    Ok(output) => {
                        io_stats.record_send(&output);
                        output
                    }
                    Err(_) => {
                        newly_broken |= mark_member_broken_if_new(group, leg.member_id);
                        OutputDrainReport::default()
                    }
                };
                report.legs.push(GroupLegDriveReport {
                    member_id: leg.member_id,
                    malformed_datagrams,
                    newly_broken,
                    received_datagrams: received.datagrams,
                    output,
                });
            }
        }
        self.group.refresh_member_states();
        Ok(())
    }

    /// Snapshot both physical-leg and logical-group telemetry. During setup,
    /// use `aggregate.active_legs` to observe independently completed peer
    /// handshakes. Do not replace the per-leg rows with the aggregate: loss,
    /// RTT, key failures, and path health are inherently leg-specific.
    #[must_use]
    pub fn stats(&self) -> GroupConnectionStats {
        group_connection_stats(
            &self.group,
            GroupLogicalCounters {
                payloads_sent: self.logical_payloads_sent,
                payload_bytes_sent: self.logical_payload_bytes_sent,
                payloads_received: self.logical_payloads_received,
                payload_bytes_received: self.logical_payload_bytes_received,
            },
            |member_id| {
                let io = self
                    .legs
                    .iter()
                    .find(|leg| leg.member_id == member_id)
                    .expect("group and I/O legs are built together");
                (io.socket.local_addr().ok(), io.socket.peer_addr().ok())
            },
        )
    }
}

fn drain_group_leg_outputs(
    conn: &mut SrtConnection,
    leg: &mut GroupLegIo,
    now: Timestamp,
    budget: OutputDrainBudget,
) -> std::io::Result<OutputDrainReport> {
    drain_connected_outputs(
        conn,
        &mut leg.timers,
        &mut leg.pending_outputs,
        now,
        budget,
        |batch| sendmsg_connected_batch(leg.socket.as_raw_fd(), batch),
    )
}

/// Mark `member_id` broken and report whether this call is what actually
/// caused the transition (T04). `SrtGroup::mark_member_broken` returns
/// `true` whenever the member exists, even if it was already `Broken` --
/// so a consumer of `GroupLegDriveReport::newly_broken` watching for a
/// once-per-failure edge (trigger failover, emit one alert) needs this
/// distinction, not "did this call attempt to mark it".
fn mark_member_broken_if_new(group: &mut shiguredo_srt::SrtGroup, member_id: u32) -> bool {
    let was_broken = group
        .member(member_id)
        .is_some_and(|member| member.state() == shiguredo_srt::GroupMemberState::Broken);
    group.mark_member_broken(member_id) && !was_broken
}

#[cfg(test)]
mod group_conn_tests {
    use super::*;
    use crate::{BatchingPolicy, ListenerTopology, SocketBufferConfig, WorkerCount};
    use std::num::NonZeroUsize;

    struct Peer {
        socket: std::net::UdpSocket,
        connection: SrtConnection,
        caller: Option<std::net::SocketAddr>,
    }

    impl Peer {
        fn new() -> Self {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            socket.set_nonblocking(true).expect("peer is nonblocking");
            Self {
                socket,
                connection: SrtConnection::new_listener(shiguredo_srt::ConnectionOptions {
                    tsbpd_delay: 0,
                    ..Default::default()
                }),
                caller: None,
            }
        }

        fn drive(&mut self, now: Timestamp) {
            let mut buffer = [0_u8; 65_536];
            loop {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, caller)) => {
                        self.caller = Some(caller);
                        self.connection
                            .feed_recv_buf(&buffer[..size], now)
                            .expect("group packet decodes");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("peer receive failed: {error}"),
                }
            }
            let Some(caller) = self.caller else {
                return;
            };
            while let Some(output) = self.connection.poll_output() {
                if let ConnectionOutput::SendPacket(packet) = output {
                    self.socket
                        .send_to(&packet, caller)
                        .expect("peer sends protocol response");
                }
            }
        }
    }

    /// T04 (Opus review): `mark_member_broken_if_new` must report the
    /// transition, not "is this member currently broken" --
    /// `SrtGroup::mark_member_broken` itself returns `true` on every call
    /// as long as the member exists, so a naive `newly_broken =
    /// group.mark_member_broken(id)` re-fires on every drive of an
    /// already-broken leg.
    #[test]
    fn mark_member_broken_if_new_only_reports_the_first_transition() {
        let mut group = shiguredo_srt::SrtGroup::new(
            shiguredo_srt::SRTGROUP_MASK | 1,
            shiguredo_srt::GroupMode::Broadcast,
        )
        .expect("group builds");
        group
            .add_member(
                1,
                10,
                SrtConnection::new_caller(shiguredo_srt::ConnectionOptions::default()),
            )
            .expect("member adds");

        assert!(
            mark_member_broken_if_new(&mut group, 1),
            "the first call must report the transition into Broken"
        );
        assert!(
            !mark_member_broken_if_new(&mut group, 1),
            "a member already Broken must not report newly_broken again"
        );
        assert!(
            !mark_member_broken_if_new(&mut group, 404),
            "a nonexistent member must report false, not panic"
        );
    }

    #[test]
    fn bonded_egress_drives_every_leg_on_every_runtime_flavor() {
        for runtime in [
            RuntimeFlavor::Mio,
            RuntimeFlavor::Tokio,
            RuntimeFlavor::Smol,
            RuntimeFlavor::Monoio,
            RuntimeFlavor::Glommio,
            RuntimeFlavor::Compio,
        ] {
            let mut first_peer = Peer::new();
            let mut second_peer = Peer::new();
            let group = GroupConfig::new(42, shiguredo_srt::GroupType::Broadcast);
            let mut conn = GroupConn::caller(
                group,
                [
                    GroupCallerLeg::new(
                        1,
                        10,
                        CallerConfig::builder(
                            first_peer.socket.local_addr().expect("first address"),
                        )
                        .build()
                        .expect("first caller config"),
                    ),
                    GroupCallerLeg::new(
                        2,
                        20,
                        CallerConfig::builder(
                            second_peer.socket.local_addr().expect("second address"),
                        )
                        .build()
                        .expect("second caller config"),
                    ),
                ],
                runtime,
                Timestamp::from_micros(0),
            )
            .expect("bonded caller builds");

            let mut report = GroupDriveReport::default();
            for round in 0..20 {
                let now = Timestamp::from_micros(round * 10_000);
                conn.drive(now, OutputDrainBudget::default(), &mut report)
                    .expect("group sends protocol output");
                first_peer.drive(now);
                second_peer.drive(now);
                conn.drive(now, OutputDrainBudget::default(), &mut report)
                    .expect("group receives protocol output");
                if conn.group().members().iter().all(|member| {
                    member.connection().state() == shiguredo_srt::ConnectionState::Connected
                }) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert!(
                conn.group()
                    .members()
                    .iter()
                    .all(|member| member.connection().state()
                        == shiguredo_srt::ConnectionState::Connected),
                "{runtime:?} group did not connect"
            );
            assert_eq!(
                conn.stats().aggregate.active_legs,
                2,
                "{runtime:?} group driver did not promote connected legs"
            );

            assert_eq!(
                conn.send(b"bonded egress", Timestamp::from_micros(300_000))
                    .unwrap(),
                2
            );
            conn.drive(
                Timestamp::from_micros(300_000),
                OutputDrainBudget::default(),
                &mut report,
            )
            .expect("group sends Broadcast payload");
            first_peer.drive(Timestamp::from_micros(300_000));
            second_peer.drive(Timestamp::from_micros(300_000));

            let stats = conn.stats();
            assert_eq!(stats.group_id, group.group_id);
            assert_eq!(stats.legs.len(), 2);
            assert_eq!(stats.aggregate.active_legs, 2);
            assert_eq!(stats.aggregate.logical_payloads_sent, 1);
            assert_eq!(stats.aggregate.wire_unique_packets_sent, 2);
        }
    }

    /// K01 (Opus review): every group leg already gets its own dedicated
    /// socket, so a leg's `CallerConfig` requesting `Shared` ownership is
    /// never meaningful -- and `bind_socket` leaves such a socket
    /// unconnected, silently breaking this type's connected-socket send
    /// path. `caller()` must reject this at build time, not build a leg
    /// that fails at first send.
    #[test]
    fn caller_rejects_a_shared_ownership_leg_instead_of_building_an_unconnected_socket() {
        let peer = Peer::new();
        let group = GroupConfig::new(44, shiguredo_srt::GroupType::Broadcast);
        let result = GroupConn::caller(
            group,
            [GroupCallerLeg::new(
                1,
                10,
                CallerConfig::builder(peer.socket.local_addr().expect("peer address"))
                    .ownership(crate::SocketOwnership::Shared)
                    .build()
                    .expect("caller config builds"),
            )],
            RuntimeFlavor::Mio,
            Timestamp::from_micros(0),
        );
        match result {
            Ok(_) => {
                panic!("a Shared-ownership leg must be rejected, not silently built unconnected")
            }
            Err(error) => assert!(matches!(error, GroupBuildError::Config(_))),
        }
    }

    #[test]
    fn caller_uses_each_leg_receive_budget_and_largest_batch_capacity() {
        if !RuntimeFlavor::Mio.capabilities().receive_batching {
            return;
        }
        let first_peer = Peer::new();
        let second_peer = Peer::new();
        let first_config = CallerConfig::builder(first_peer.socket.local_addr().expect("address"))
            .configure_transport(|transport| {
                transport.topology = ListenerTopology::SharedPool {
                    listeners: WorkerCount::Count(NonZeroUsize::MIN),
                };
                transport.batching =
                    BatchingPolicy::MaxDatagrams(NonZeroUsize::new(3).expect("batch capacity"));
                transport.recv_budget = RecvBudget::new(1, 2);
                transport.socket_buffers = SocketBufferConfig::SystemDefault;
            })
            .build()
            .expect("first caller config");
        let second_config =
            CallerConfig::builder(second_peer.socket.local_addr().expect("address"))
                .configure_transport(|transport| {
                    transport.topology = ListenerTopology::SharedPool {
                        listeners: WorkerCount::Count(NonZeroUsize::MIN),
                    };
                    transport.batching =
                        BatchingPolicy::MaxDatagrams(NonZeroUsize::new(7).expect("batch capacity"));
                    transport.recv_budget = RecvBudget::new(4, 9);
                    transport.socket_buffers = SocketBufferConfig::SystemDefault;
                })
                .build()
                .expect("second caller config");
        let conn = GroupConn::caller(
            GroupConfig::new(45, shiguredo_srt::GroupType::Broadcast),
            [
                GroupCallerLeg::new(1, 10, first_config),
                GroupCallerLeg::new(2, 20, second_config),
            ],
            RuntimeFlavor::Mio,
            Timestamp::default(),
        )
        .expect("group caller");

        assert_eq!(conn.recv_batch.capacity(), 7);
        assert_eq!(conn.legs[0].recv_budget, RecvBudget::new(1, 2));
        assert_eq!(conn.legs[1].recv_budget, RecvBudget::new(4, 9));
    }

    fn connect_two_leg_group(runtime: RuntimeFlavor) -> (GroupConn, Peer, Peer) {
        let mut first_peer = Peer::new();
        let mut second_peer = Peer::new();
        let group = GroupConfig::new(43, shiguredo_srt::GroupType::Broadcast);
        let mut conn = GroupConn::caller(
            group,
            [
                GroupCallerLeg::new(
                    1,
                    10,
                    CallerConfig::builder(first_peer.socket.local_addr().expect("first address"))
                        .build()
                        .expect("first caller config"),
                ),
                GroupCallerLeg::new(
                    2,
                    20,
                    CallerConfig::builder(second_peer.socket.local_addr().expect("second address"))
                        .build()
                        .expect("second caller config"),
                ),
            ],
            runtime,
            Timestamp::from_micros(0),
        )
        .expect("bonded caller builds");

        let mut report = GroupDriveReport::default();
        for round in 0..20 {
            let now = Timestamp::from_micros(round * 10_000);
            conn.drive(now, OutputDrainBudget::default(), &mut report)
                .expect("group sends protocol output");
            first_peer.drive(now);
            second_peer.drive(now);
            conn.drive(now, OutputDrainBudget::default(), &mut report)
                .expect("group receives protocol output");
            if conn.group().members().iter().all(|member| {
                member.connection().state() == shiguredo_srt::ConnectionState::Connected
            }) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            conn.group()
                .members()
                .iter()
                .all(|member| member.connection().state()
                    == shiguredo_srt::ConnectionState::Connected),
            "group did not connect"
        );
        (conn, first_peer, second_peer)
    }

    /// T04 checkpoint 1/3: sustained malformed input on one leg must never
    /// stop `drive` from servicing the rest of the group, and must never
    /// mark the malformed leg broken -- `feed_recv_buf` rejecting a
    /// datagram leaves the connection's own state untouched.
    #[test]
    fn sustained_malformed_input_on_one_leg_does_not_stop_the_group() {
        let (mut conn, mut first_peer, mut second_peer) = connect_two_leg_group(RuntimeFlavor::Mio);
        let first_addr = *conn
            .leg_sockets()
            .find(|(id, _)| *id == 1)
            .map(|(_, sock)| sock)
            .expect("leg 1 socket")
            .local_addr()
            .as_ref()
            .expect("leg 1 address");

        let mut total_malformed = 0usize;
        let mut report = GroupDriveReport::default();
        for round in 0..10 {
            let now = Timestamp::from_micros(1_000_000 + round * 10_000);
            for _ in 0..3 {
                // The leg's socket is `connect()`-ed to its peer, so the
                // garbage must come from that same peer's socket -- an
                // unrelated third-party sender's datagrams would never
                // reach a connected UDP socket's receive queue at all.
                first_peer
                    .socket
                    .send_to(b"not an srt packet, just garbage bytes", first_addr)
                    .expect("garbage send");
            }
            conn.drive(now, OutputDrainBudget::default(), &mut report)
                .expect("drive must not fail on malformed input");
            let leg1 = report
                .legs
                .iter()
                .find(|leg| leg.member_id == 1)
                .expect("leg 1 report");
            total_malformed += leg1.malformed_datagrams;
            assert!(!leg1.newly_broken, "malformed input must not break the leg");

            assert_eq!(
                conn.group().member(1).expect("member 1").state(),
                shiguredo_srt::GroupMemberState::Active,
                "leg 1 must stay Active through sustained malformed input"
            );

            // The healthy leg keeps making real protocol progress the
            // whole time -- the malformed leg's noise must not starve it.
            second_peer.drive(now);
            first_peer.drive(now);
        }
        assert!(
            total_malformed > 0,
            "the garbage sends must have registered as malformed"
        );

        assert_eq!(
            conn.send(b"still bonded", Timestamp::from_micros(2_000_000))
                .expect("group send still works after sustained malformed input"),
            2
        );
    }

    /// T04 checkpoints 1/2/3: a genuine socket failure on one leg must be
    /// isolated to that leg -- the group refreshes its member states even
    /// though a leg failed, a healthy leg keeps working, and once every
    /// leg has failed the group honestly reports zero active legs rather
    /// than silently doing nothing.
    #[test]
    fn one_leg_socket_failure_is_isolated_and_all_legs_failed_is_reported_honestly() {
        let (mut conn, first_peer, mut second_peer) = connect_two_leg_group(RuntimeFlavor::Mio);

        // Dropping the peer (rather than closing our own leg's fd with
        // `libc::close`) is both a realistic genuine failure and hermetic:
        // `cargo test` runs tests in parallel threads in one process, and a
        // raw `close()` on a still-live `UdpSocket`'s fd leaves a window
        // (until this test's `conn` is dropped) where an unrelated
        // concurrently-running test's own socket bind could be handed that
        // exact fd number, silently stealing its datagrams. Dropping the
        // peer instead never touches our own fd table at all -- the
        // failure comes from a real `ECONNREFUSED` via ICMP once the
        // peer's port stops existing.
        drop(first_peer);

        let mut leg1_broken = false;
        let mut report = GroupDriveReport::default();
        for round in 0..100 {
            let now = Timestamp::from_micros(1_500_000 + round * 10_000);
            let _ = conn.send(b"provoke icmp unreachable on leg 1", now);
            conn.drive(now, OutputDrainBudget::default(), &mut report)
                .expect("drive must not fail just because one leg's peer vanished");
            second_peer.drive(now);
            if conn.group().member(1).expect("member 1").state()
                == shiguredo_srt::GroupMemberState::Broken
            {
                leg1_broken = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(
            leg1_broken,
            "leg 1 must eventually be marked Broken once its peer is unreachable"
        );
        assert_eq!(
            conn.group().member(2).expect("member 2").state(),
            shiguredo_srt::GroupMemberState::Active,
            "the healthy leg must be unaffected by the other leg's failure"
        );

        // `newly_broken` must be a one-time edge, not "is this leg
        // currently broken" -- a leg that failed a while ago must not
        // re-report `newly_broken: true` on every later drive.
        let now = Timestamp::from_micros(2_500_000);
        conn.drive(now, OutputDrainBudget::default(), &mut report)
            .expect("drive on an already-broken leg must not fail");
        let leg1 = report
            .legs
            .iter()
            .find(|leg| leg.member_id == 1)
            .expect("leg 1 report");
        assert!(
            !leg1.newly_broken,
            "a leg already Broken from a prior call must not report newly_broken again"
        );

        let now = Timestamp::from_micros(3_000_000);
        assert_eq!(
            conn.send(b"one leg down", now)
                .expect("send still works with one healthy leg"),
            1
        );
        conn.drive(now, OutputDrainBudget::default(), &mut report)
            .expect("drive still services the healthy leg");
        second_peer.drive(now);
        conn.drive(now, OutputDrainBudget::default(), &mut report)
            .expect("drive still services the healthy leg");
        assert_eq!(conn.stats().aggregate.active_legs, 1);

        // Now the remaining leg's peer vanishes too.
        drop(second_peer);
        let mut all_broken = false;
        for round in 0..100 {
            let now = Timestamp::from_micros(3_500_000 + round * 10_000);
            let _ = conn.send(b"provoke icmp unreachable on leg 2", now);
            conn.drive(now, OutputDrainBudget::default(), &mut report)
                .expect("drive must not fail even when every leg has failed");
            if conn
                .group()
                .members()
                .iter()
                .all(|member| member.state() == shiguredo_srt::GroupMemberState::Broken)
            {
                all_broken = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(
            all_broken,
            "every member must be Broken once every leg's peer is unreachable"
        );
        assert_eq!(
            conn.stats().aggregate.active_legs,
            0,
            "total group failure must be reported honestly as zero active legs"
        );
    }

    // D02's allocation-reuse guarantee for `drive()` is proven in
    // `tests/group_drive_allocation_guard.rs`: a real allocation count
    // across idle calls, not a `Vec::as_ptr()` comparison. An earlier
    // version of this test used `as_ptr()` and passed even against a
    // deliberately reintroduced free-and-reallocate regression, because
    // glibc's allocator handed back the same address for the freed block.
}
