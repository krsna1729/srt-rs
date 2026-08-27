use crate::{
    CallerConfig, ConfigError, GroupConfig, ManualTimerStore, OutputDrainBudget, OutputDrainReport,
    OutputDrainStatus, RuntimeFlavor, collect_output_work, prepend_outputs,
};
use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::fmt;

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
}

/// Per-leg I/O work completed by one [`GroupConn::drive`] call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupLegDriveReport {
    pub member_id: u32,
    pub received_datagrams: usize,
    pub output: OutputDrainReport,
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
        let mut raw_legs = Vec::new();
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
            caller.session.connection_options_mut().initial_seq = Some(group_initial_seq);
            caller.session.set_group(Some(GroupConfig {
                group_id: group.group_id,
                group_type: group.group_type,
                flags: group.flags,
                weight: leg.weight,
            }));
            let prepared = caller.prepare(runtime)?;
            raw_legs.push(GroupConnectionLeg {
                member_id: leg.member_id,
                weight: leg.weight,
                connection: prepared.connection(now)?,
                socket: prepared.bind_socket()?,
            });
        }
        let mode = shiguredo_srt::GroupMode::from_group_type(group.group_type)
            .ok_or(GroupBuildError::InvalidGroupType)?;
        Ok(Self::new(group.group_id, mode, raw_legs)?)
    }

    /// Assemble a group from application-owned protocol cores and connected,
    /// nonblocking sockets. This is the integration point for custom runtimes
    /// and for applications that own their own socket provisioning.
    pub fn new(
        group_id: u32,
        mode: shiguredo_srt::GroupMode,
        legs: impl IntoIterator<Item = GroupConnectionLeg>,
    ) -> Result<Self, shiguredo_srt::Error> {
        let mut group = shiguredo_srt::SrtGroup::new(group_id, mode)?;
        let mut io_legs = Vec::new();
        for leg in legs {
            group.add_member(leg.member_id, leg.weight, leg.connection)?;
            io_legs.push(GroupLegIo {
                member_id: leg.member_id,
                socket: leg.socket,
                timers: ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
            });
        }
        Ok(Self {
            group,
            legs: io_legs,
            logical_payloads_sent: 0,
            logical_payload_bytes_sent: 0,
            logical_payloads_received: 0,
            logical_payload_bytes_received: 0,
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

    /// Whether the next logical payload can be accepted without weakening the
    /// selected Broadcast or Backup delivery contract.
    pub fn can_send(&mut self) -> bool {
        self.group.can_send()
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

    /// Drive timers, nonblocking UDP input, and a bounded output pump for
    /// every leg once. A readable leg may contain up to 64 datagrams per call
    /// to avoid one busy path starving the rest of the group.
    pub fn drive(
        &mut self,
        now: Timestamp,
        output_budget: OutputDrainBudget,
    ) -> std::io::Result<GroupDriveReport> {
        let mut report = GroupDriveReport {
            legs: Vec::with_capacity(self.legs.len()),
        };
        {
            let (group, legs) = (&mut self.group, &mut self.legs);
            for leg in legs {
                let member = group
                    .member_mut(leg.member_id)
                    .expect("group and I/O legs are built together");
                let conn = member.connection_mut();
                leg.timers.fire_expired(now, conn);

                let mut received_datagrams = 0;
                let mut buffer = [0_u8; 65_536];
                for _ in 0..64 {
                    match leg.socket.recv(&mut buffer) {
                        Ok(size) => {
                            received_datagrams += 1;
                            conn.feed_recv_buf(&buffer[..size], now).map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                            })?;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }

                let output = drain_group_leg_outputs(conn, leg, now, output_budget)?;
                report.legs.push(GroupLegDriveReport {
                    member_id: leg.member_id,
                    received_datagrams,
                    output,
                });
            }
        }
        self.group.refresh_member_states();
        Ok(report)
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
    let (mut work, budget_exhausted) = collect_output_work(conn, &mut leg.pending_outputs, budget);
    let mut report = OutputDrainReport {
        status: if budget_exhausted {
            OutputDrainStatus::BudgetExhausted
        } else {
            OutputDrainStatus::Drained
        },
        ..OutputDrainReport::default()
    };
    while let Some(output) = work.pop_front() {
        match output {
            ConnectionOutput::SendPacket(packet) => match leg.socket.send(&packet) {
                Ok(sent) if sent == packet.len() => {
                    report.actions += 1;
                    report.packets += 1;
                    report.bytes += sent;
                }
                Ok(_) => {
                    prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                    leg.pending_outputs
                        .push_front(ConnectionOutput::SendPacket(packet));
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "UDP socket reported a partial datagram send",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                    leg.pending_outputs
                        .push_front(ConnectionOutput::SendPacket(packet));
                    report.status = OutputDrainStatus::Backpressured;
                    return Ok(report);
                }
                Err(error) => {
                    prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                    leg.pending_outputs
                        .push_front(ConnectionOutput::SendPacket(packet));
                    return Err(error);
                }
            },
            timer => {
                leg.timers.apply_output(&timer, now);
                report.actions += 1;
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod group_conn_tests {
    use super::*;

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

            for round in 0..20 {
                let now = Timestamp::from_micros(round * 10_000);
                conn.drive(now, OutputDrainBudget::default())
                    .expect("group sends protocol output");
                first_peer.drive(now);
                second_peer.drive(now);
                conn.drive(now, OutputDrainBudget::default())
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
}
