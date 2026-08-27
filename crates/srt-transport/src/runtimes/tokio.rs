use crate::{
    GroupBuildError, GroupCallerLeg, GroupConnectionLeg, GroupConnectionStats, GroupDriveReport,
    GroupLegDriveReport, GroupLogicalCounters, ManualTimerStore, OutputDrainBudget,
    OutputDrainReport, OutputDrainStatus, collect_output_work, group_connection_stats,
    prepend_outputs,
};
use shiguredo_srt::{ConnectionEvent, ConnectionOutput, GroupMode, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Per-connection state for tokio: protocol + async socket + timer deadlines.
pub struct Conn {
    pub conn: SrtConnection,
    pub sock: UdpSocket,
    timers: crate::ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
}

impl Conn {
    pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
        Self {
            conn,
            sock,
            timers: crate::ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
        }
    }

    /// Fire every timer whose deadline has passed, invoking the protocol.
    ///
    /// Outputs queued by `handle_timer` are drained by the caller's
    /// following `drain_outputs`.
    pub fn fire_expired(&mut self, now: Timestamp) {
        self.timers.fire_expired(now, &mut self.conn);
    }

    /// Compatibility wrapper using [`OutputDrainBudget::default`].
    pub async fn drain_outputs(&mut self, now: Timestamp) -> io::Result<OutputDrainReport> {
        self.drain_outputs_bounded(now, OutputDrainBudget::default())
            .await
    }

    /// Drain a bounded amount of output. A failed datagram and every
    /// action after it remain queued in protocol order for the next tick.
    pub async fn drain_outputs_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
    ) -> io::Result<OutputDrainReport> {
        let (mut work, budget_exhausted) =
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
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
                ConnectionOutput::SendPacket(bytes) => match self.sock.send(&bytes).await {
                    Ok(sent) if sent == bytes.len() => {
                        report.actions += 1;
                        report.packets += 1;
                        report.bytes += sent;
                    }
                    Ok(_) => {
                        prepend_outputs(&mut self.pending_outputs, work.into_iter());
                        self.pending_outputs
                            .push_front(ConnectionOutput::SendPacket(bytes));
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "UDP send completed with a partial datagram",
                        ));
                    }
                    Err(error) => {
                        prepend_outputs(&mut self.pending_outputs, work.into_iter());
                        self.pending_outputs
                            .push_front(ConnectionOutput::SendPacket(bytes));
                        if error.kind() == io::ErrorKind::WouldBlock {
                            report.status = OutputDrainStatus::Backpressured;
                            return Ok(report);
                        }
                        return Err(error);
                    }
                },
                timer => {
                    self.timers.apply_output(&timer, now);
                    report.actions += 1;
                }
            }
        }

        Ok(report)
    }

    #[must_use]
    pub fn has_pending_outputs(&self) -> bool {
        !self.pending_outputs.is_empty()
    }

    /// Recv with timeout, feed to protocol.
    pub async fn recv_with_timeout(&mut self, buf: &mut [u8], timeout: Duration, now: Timestamp) {
        if let Ok(Ok(n)) = tokio::time::timeout(timeout, self.sock.recv(buf)).await {
            let _ = self.conn.feed_recv_buf(&buf[..n], now);
        }
    }

    /// Send one paced packet.
    pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> Result<(), ()> {
        if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
            return Err(());
        }
        self.conn.send(payload, now).map_err(|_| ())?;
        let report = self.drain_outputs(now).await.map_err(|_| ())?;
        (report.status == OutputDrainStatus::Drained)
            .then_some(())
            .ok_or(())
    }

    /// Full event-loop tick: fire timers, recv, drain, send paced.
    pub async fn tick(
        &mut self,
        buf: &mut [u8],
        payload: &[u8],
        now: Timestamp,
    ) -> io::Result<TickResult> {
        self.fire_expired(now);
        self.recv_with_timeout(buf, Duration::from_micros(100), now)
            .await;
        let drained = self.drain_outputs(now).await?;

        let mut sent = 0u64;
        if drained.status == OutputDrainStatus::Drained {
            while self.send_paced(payload, now).await.is_ok() {
                sent += 1;
            }
        }

        let mut events = Vec::new();
        while let Some(ev) = self.conn.poll_event() {
            events.push(ev);
        }

        Ok(TickResult { sent, events })
    }
}

/// Resolve and bind a listener using Tokio-native UDP sockets. Must be
/// called from a Tokio runtime context.
pub fn bind_listener(
    config: &crate::ListenerConfig,
) -> Result<crate::RuntimeListener<UdpSocket>, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Tokio)?;
    let sockets = prepared
        .bind_sockets()?
        .into_iter()
        .map(UdpSocket::from_std)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::RuntimeListener { prepared, sockets })
}

/// Build one configured caller connection and connected Tokio socket.
pub fn caller(
    config: &crate::CallerConfig,
    now: Timestamp,
) -> Result<Conn, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Tokio)?;
    let socket = UdpSocket::from_std(prepared.bind_socket()?)?;
    Ok(Conn::new(prepared.connection(now)?, socket))
}

struct GroupLeg {
    member_id: u32,
    socket: UdpSocket,
    timers: ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
}

/// Tokio-native multi-socket driver for an SRT Broadcast or Backup group.
///
/// This owns Tokio sockets, not a synchronous [`crate::GroupConn`] wrapped
/// in a task. Group sequencing, selection, and telemetry remain in the
/// shared protocol core; this type supplies Tokio's nonblocking socket
/// operations and exposes every leg for readiness registration.
pub struct GroupConn {
    group: shiguredo_srt::SrtGroup,
    legs: Vec<GroupLeg>,
    logical_payloads_sent: u64,
    logical_payload_bytes_sent: u64,
    logical_payloads_received: u64,
    logical_payload_bytes_received: u64,
}

impl GroupConn {
    /// Build a Tokio-native group from application-owned protocol cores
    /// and connected standard UDP sockets.
    pub fn new(
        group_id: u32,
        mode: GroupMode,
        legs: impl IntoIterator<Item = GroupConnectionLeg>,
    ) -> Result<Self, GroupBuildError> {
        let mut group = shiguredo_srt::SrtGroup::new(group_id, mode)?;
        let mut io_legs = Vec::new();
        for leg in legs {
            group.add_member(leg.member_id, leg.weight, leg.connection)?;
            io_legs.push(GroupLeg {
                member_id: leg.member_id,
                socket: UdpSocket::from_std(leg.socket)?,
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

    /// Build a Tokio-native caller with one connected socket per group
    /// leg and begin every SRT handshake. Every leg uses one group-wide
    /// initial packet sequence, as required by bonded peers such as
    /// libsrt.
    pub fn caller(
        group: crate::GroupConfig,
        legs: impl IntoIterator<Item = GroupCallerLeg>,
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
            caller.session.set_group(Some(crate::GroupConfig {
                group_id: group.group_id,
                group_type: group.group_type,
                flags: group.flags,
                weight: leg.weight,
            }));
            let prepared = caller.prepare(crate::RuntimeFlavor::Tokio)?;
            raw_legs.push(GroupConnectionLeg {
                member_id: leg.member_id,
                weight: leg.weight,
                connection: prepared.connection(now)?,
                socket: prepared.bind_socket()?,
            });
        }
        let mode = GroupMode::from_group_type(group.group_type)
            .ok_or(GroupBuildError::InvalidGroupType)?;
        Self::new(group.group_id, mode, raw_legs)
    }

    #[must_use]
    pub fn group(&self) -> &shiguredo_srt::SrtGroup {
        &self.group
    }

    /// Tokio sockets to include in the application's readiness set.
    #[must_use]
    pub fn leg_sockets(&self) -> impl ExactSizeIterator<Item = (u32, &UdpSocket)> {
        self.legs.iter().map(|leg| (leg.member_id, &leg.socket))
    }

    #[must_use]
    pub fn time_until_next_deadline(&self, now: Timestamp, default_micros: u64) -> u64 {
        self.legs
            .iter()
            .map(|leg| leg.timers.time_until_earliest(now, default_micros))
            .min()
            .unwrap_or(default_micros)
    }

    pub fn can_send(&mut self) -> bool {
        self.group.can_send()
    }

    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, shiguredo_srt::Error> {
        let legs = self.group.send(payload, now)?;
        self.logical_payloads_sent = self.logical_payloads_sent.saturating_add(1);
        self.logical_payload_bytes_sent = self
            .logical_payload_bytes_sent
            .saturating_add(payload.len() as u64);
        Ok(legs)
    }

    pub fn disconnect(&mut self, now: Timestamp) {
        self.group.disconnect(now);
    }

    pub fn poll_data(&mut self, now: Timestamp) -> Option<shiguredo_srt::GroupPacket> {
        let packet = self.group.poll_data(now)?;
        self.logical_payloads_received = self.logical_payloads_received.saturating_add(1);
        self.logical_payload_bytes_received = self
            .logical_payload_bytes_received
            .saturating_add(packet.payload.len() as u64);
        Some(packet)
    }

    /// Perform bounded, nonblocking work for every leg. Call after a
    /// Tokio readiness notification or when the next timer is due; this
    /// never blocks one leg waiting for another.
    pub fn drive(
        &mut self,
        now: Timestamp,
        output_budget: OutputDrainBudget,
    ) -> io::Result<GroupDriveReport> {
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
                    match leg.socket.try_recv(&mut buffer) {
                        Ok(size) => {
                            received_datagrams += 1;
                            conn.feed_recv_buf(&buffer[..size], now).map_err(|error| {
                                io::Error::new(io::ErrorKind::InvalidData, error)
                            })?;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
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
    leg: &mut GroupLeg,
    now: Timestamp,
    budget: OutputDrainBudget,
) -> io::Result<OutputDrainReport> {
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
            ConnectionOutput::SendPacket(packet) => match leg.socket.try_send(&packet) {
                Ok(sent) if sent == packet.len() => {
                    report.actions += 1;
                    report.packets += 1;
                    report.bytes += sent;
                }
                Ok(_) => {
                    prepend_outputs(&mut leg.pending_outputs, work.into_iter());
                    leg.pending_outputs
                        .push_front(ConnectionOutput::SendPacket(packet));
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "UDP socket reported a partial datagram send",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
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

pub struct TickResult {
    pub sent: u64,
    pub events: Vec<ConnectionEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_caller_uses_tokio_sockets_and_drives_every_leg() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let first_peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("first peer binds");
            let second_peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("second peer binds");
            first_peer
                .set_nonblocking(true)
                .expect("first peer is nonblocking");
            second_peer
                .set_nonblocking(true)
                .expect("second peer is nonblocking");

            let group = crate::GroupConfig::new(42, shiguredo_srt::GroupType::Broadcast);
            let mut conn = GroupConn::caller(
                group,
                [
                    GroupCallerLeg::new(
                        1,
                        10,
                        crate::CallerConfig::builder(
                            first_peer.local_addr().expect("first address"),
                        )
                        .build()
                        .expect("first caller config"),
                    ),
                    GroupCallerLeg::new(
                        2,
                        20,
                        crate::CallerConfig::builder(
                            second_peer.local_addr().expect("second address"),
                        )
                        .build()
                        .expect("second caller config"),
                    ),
                ],
                Timestamp::from_micros(0),
            )
            .expect("bonded Tokio caller builds");

            assert_eq!(conn.leg_sockets().len(), 2);
            for (_, socket) in conn.leg_sockets() {
                socket.writable().await.expect("leg becomes writable");
            }
            let report = conn
                .drive(Timestamp::from_micros(0), OutputDrainBudget::default())
                .expect("all induction packets are sent");
            assert_eq!(report.legs.len(), 2);
            assert_eq!(
                report
                    .legs
                    .iter()
                    .map(|leg| leg.output.packets)
                    .sum::<usize>(),
                2
            );

            let stats = conn.stats();
            assert_eq!(stats.group_id, group.group_id);
            assert_eq!(stats.legs.len(), 2);
            assert!(stats.legs.iter().all(|leg| leg.peer_addr.is_some()));
        });
    }
}
