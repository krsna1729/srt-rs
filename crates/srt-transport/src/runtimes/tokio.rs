use crate::{
    BatchIoStats, GroupBuildError, GroupCallerLeg, GroupConnectionLeg, GroupConnectionStats,
    GroupDriveReport, GroupLegDriveReport, GroupLogicalCounters, HighResWaiter, ManualTimerStore,
    MonotonicDeadline, OutputDrainBudget, OutputDrainReport, OutputDrainStatus, PacedSendOutcome,
    RecvBatch, RecvBudget, RecvDrainReport, collect_output_work, drain_connected_outputs,
    drain_output_work, group_connection_stats, prepend_outputs, schedule_wait_micros,
    sendmsg_connected_batch,
};
use shiguredo_srt::{Bytes, ConnectionOutput, GroupMode, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::hash::Hash;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Per-connection state for tokio: protocol + async socket + timer deadlines.
pub struct Conn {
    pub conn: SrtConnection,
    pub sock: UdpSocket,
    timers: crate::ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
    recv_batch: RecvBatch,
    io_stats: BatchIoStats,
    output_drain: OutputDrainBudget,
    recv_budget: RecvBudget,
}

impl Conn {
    pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
        Self::with_budgets(
            conn,
            sock,
            OutputDrainBudget::default(),
            RecvBudget::default(),
        )
    }

    /// Like [`Self::new`], but stores the given budgets instead of the
    /// defaults (K02): [`Self::drain_outputs`]/[`Self::recv_with_timeout`]
    /// honor these, not a hardcoded `::default()`, on every call.
    pub fn with_budgets(
        conn: SrtConnection,
        sock: UdpSocket,
        output_drain: OutputDrainBudget,
        recv_budget: RecvBudget,
    ) -> Self {
        Self {
            conn,
            sock,
            timers: crate::ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
            recv_batch: RecvBatch::new(),
            io_stats: BatchIoStats::default(),
            output_drain,
            recv_budget,
        }
    }

    /// Fire every timer whose deadline has passed, invoking the protocol.
    ///
    /// Outputs queued by `handle_timer` are drained by the caller's
    /// following `drain_outputs`.
    pub fn fire_expired(&mut self, now: Timestamp) {
        self.timers.fire_expired(now, &mut self.conn);
    }

    /// Convenience wrapper over [`Self::drain_outputs_bounded`] using this
    /// `Conn`'s stored budget (its configured `TransportConfig::output_drain`
    /// if built via [`caller`], else [`OutputDrainBudget::default`]).
    pub async fn drain_outputs(&mut self, now: Timestamp) -> io::Result<OutputDrainReport> {
        self.drain_outputs_bounded(now, self.output_drain).await
    }

    /// Drain a bounded amount of output. Consecutive packets go out in
    /// one `sendmmsg`; a failed datagram and every action after it remain
    /// queued in protocol order for the next tick.
    pub async fn drain_outputs_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
    ) -> io::Result<OutputDrainReport> {
        let (work, budget_exhausted) =
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
        let report = OutputDrainReport {
            status: if budget_exhausted {
                OutputDrainStatus::BudgetExhausted
            } else {
                OutputDrainStatus::Drained
            },
            ..OutputDrainReport::default()
        };
        let work = if work_has_packets(&work) {
            prepend_outputs(&mut self.pending_outputs, work.into_iter());
            self.sock.writable().await?;
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget).0
        } else {
            work
        };
        let report = drain_output_work(
            work,
            &mut self.pending_outputs,
            &mut self.timers,
            now,
            report,
            |batch| send_connected_ready(&self.sock, batch),
        )?;
        self.io_stats.record_send(&report);
        Ok(report)
    }

    #[must_use]
    pub fn has_pending_outputs(&self) -> bool {
        !self.pending_outputs.is_empty()
    }

    #[must_use]
    pub fn io_stats(&self) -> BatchIoStats {
        self.io_stats
    }

    /// Relative delay until this connection's next paced send or protocol timer.
    ///
    /// Intended for a worker-owned [`HighResWaiter`], not `tokio::time::sleep`
    /// plus a per-task tail-spin (issue #82 A1, rejected).
    #[must_use]
    pub fn schedule_wait(&self, now: Timestamp) -> Duration {
        Duration::from_micros(schedule_wait_micros(
            self.conn.time_until_send(now),
            self.timers.time_until_earliest(now, u64::MAX),
        ))
    }

    /// Publish this connection onto a worker waiter and arm its next deadline.
    ///
    /// Call from a worker thread (or `block_in_place`), not from a Tokio
    /// timer. After [`HighResWaiter::wait`], service every due key. One
    /// packet per visit remains the contract; Route B is out of scope.
    pub fn schedule_on<K>(
        &self,
        waiter: &mut HighResWaiter<K>,
        key: K,
        now: Timestamp,
    ) -> io::Result<()>
    where
        K: Clone + Eq + Hash,
    {
        waiter.register(key.clone(), self.sock.as_raw_fd())?;
        waiter.set_deadline(key, MonotonicDeadline::after(self.schedule_wait(now)));
        Ok(())
    }

    /// Drain every datagram currently readable, feeding the protocol.
    /// Bounded by [`RecvBudget`] so a busy peer cannot starve timers.
    /// Uses Tokio `try_io` so a readiness wake is cleared when empty.
    pub fn recv_ready(
        &mut self,
        now: Timestamp,
        budget: RecvBudget,
    ) -> io::Result<RecvDrainReport> {
        let report = drain_readable(&self.sock, &mut self.recv_batch, budget, |_, data| {
            let _ = self.conn.feed_recv_buf(data, now);
        })?;
        self.io_stats.record_recv(report);
        Ok(report)
    }

    /// Non-blocking `recvmmsg` drain that does not touch Tokio readiness.
    /// Use after an awaited `recv` has already consumed the readable flag.
    pub fn recv_nonblocking(
        &mut self,
        now: Timestamp,
        budget: RecvBudget,
    ) -> io::Result<RecvDrainReport> {
        let report = crate::drain_recv_fd(
            self.sock.as_raw_fd(),
            &mut self.recv_batch,
            budget,
            |_, data| {
                let _ = self.conn.feed_recv_buf(data, now);
            },
        )?;
        self.io_stats.record_recv(report);
        Ok(report)
    }

    /// Wait until readable or `timeout`, then batch-drain into the protocol
    /// using this `Conn`'s stored receive budget. `buf` is unused; the
    /// connection owns a [`RecvBatch`].
    pub async fn recv_with_timeout(&mut self, buf: &mut [u8], timeout: Duration, now: Timestamp) {
        let _ = buf;
        if tokio::time::timeout(timeout, self.sock.readable())
            .await
            .is_ok()
        {
            let _ = self.recv_ready(now, self.recv_budget);
        }
    }

    /// Send one paced packet. See [`PacedSendOutcome`] for what each
    /// outcome means to the caller (S03).
    pub async fn send_paced(&mut self, payload: &[u8], now: Timestamp) -> PacedSendOutcome {
        if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
            return PacedSendOutcome::NotDue;
        }
        if let Err(error) = self.conn.send(payload, now) {
            return PacedSendOutcome::Rejected(error);
        }
        match self.drain_outputs(now).await {
            Ok(report) if report.status == OutputDrainStatus::Drained => PacedSendOutcome::Sent,
            Ok(_) => PacedSendOutcome::Accepted,
            Err(error) => PacedSendOutcome::DriverError(error),
        }
    }

    /// Send one paced shared-payload packet (fan-out path). Once accepted,
    /// the payload is retained by the protocol regardless of drain outcome
    /// -- a future bus caller must not resend it as new data on
    /// `DriverError`/`Accepted`, only on `NotDue`/`Rejected` (S02/S03).
    pub async fn send_shared_paced(&mut self, payload: Bytes, now: Timestamp) -> PacedSendOutcome {
        if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
            return PacedSendOutcome::NotDue;
        }
        if let Err(error) = self.conn.send_shared(payload, now) {
            return PacedSendOutcome::Rejected(error);
        }
        match self.drain_outputs(now).await {
            Ok(report) if report.status == OutputDrainStatus::Drained => PacedSendOutcome::Sent,
            Ok(_) => PacedSendOutcome::Accepted,
            Err(error) => PacedSendOutcome::DriverError(error),
        }
    }
}

/// Receive datagrams via `recvmmsg`, routed through Tokio's `try_io` so
/// readiness is cleared when the socket has nothing left. Bounded so a
/// busy socket cannot starve timers and sibling tasks.
pub fn drain_readable(
    sock: &UdpSocket,
    batch: &mut RecvBatch,
    budget: RecvBudget,
    mut on_datagram: impl FnMut(Option<SocketAddr>, &[u8]),
) -> io::Result<RecvDrainReport> {
    let mut report = RecvDrainReport::default();
    for _ in 0..budget.max_rounds {
        if report.datagrams >= budget.max_datagrams {
            break;
        }
        let requested = (budget.max_datagrams - report.datagrams).min(batch.capacity());
        let result = sock.try_io(tokio::io::Interest::READABLE, || {
            match batch.recv(sock.as_raw_fd(), requested)? {
                0 => Err(io::ErrorKind::WouldBlock.into()),
                n => Ok(n),
            }
        });
        match result {
            Ok(received) => {
                report.syscalls += 1;
                for (addr, data, truncated) in batch.iter(received) {
                    if truncated {
                        report.truncated += 1;
                        continue;
                    }
                    on_datagram(addr, data);
                    report.datagrams += 1;
                }
                if received < requested {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                report.would_block = true;
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(report)
}

fn send_connected_ready(sock: &UdpSocket, batch: &[Vec<u8>]) -> io::Result<usize> {
    sock.try_io(
        tokio::io::Interest::WRITABLE,
        || match sendmsg_connected_batch(sock.as_raw_fd(), batch)? {
            0 if !batch.is_empty() => Err(io::ErrorKind::WouldBlock.into()),
            n => Ok(n),
        },
    )
}

fn work_has_packets(work: &VecDeque<ConnectionOutput>) -> bool {
    work.iter()
        .any(|output| matches!(output, ConnectionOutput::SendPacket(_)))
}

/// A malformed or misdirected datagram is a per-packet decode/routing
/// failure that leaves the connection's own state untouched, so it is
/// counted in `malformed_datagrams` rather than surfaced as an error
/// (T04) -- only a genuine syscall failure from `drain_readable` (never
/// `WouldBlock`, which it already folds into its `Ok` report) is `Err`
/// here.
fn feed_ready(
    sock: &UdpSocket,
    batch: &mut RecvBatch,
    conn: &mut SrtConnection,
    now: Timestamp,
    budget: RecvBudget,
    malformed_datagrams: &mut usize,
) -> io::Result<RecvDrainReport> {
    drain_readable(sock, batch, budget, |_, data| {
        if conn.feed_recv_buf(data, now).is_err() {
            *malformed_datagrams += 1;
        }
    })
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
    Ok(Conn::with_budgets(
        prepared.connection(now)?,
        socket,
        prepared.transport.output_drain,
        prepared.transport.recv_budget,
    ))
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
    recv_batch: RecvBatch,
    io_stats: BatchIoStats,
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
            // D02: see the identical fix and rationale in group_conn.rs's
            // own `GroupConn::new`.
            recv_batch: RecvBatch::new(),
            io_stats: BatchIoStats::default(),
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
            caller.session.set_initial_seq(group_initial_seq);
            caller.session.set_group(Some(crate::GroupConfig {
                group_id: group.group_id,
                group_type: group.group_type,
                flags: group.flags,
                weight: leg.weight,
            }));
            let prepared = caller.prepare(crate::RuntimeFlavor::Tokio)?;
            // Every leg already gets its own dedicated socket by
            // construction (one per group member); `Shared` ownership,
            // which multiplexes several sessions onto one socket, is never
            // meaningful here and `bind_socket` (K01) leaves such a socket
            // unconnected -- silently breaking this type's connected-socket
            // send path instead of failing preparation. Reject it up front.
            if !prepared.transport.exclusive {
                return Err(GroupBuildError::Config(crate::ConfigError::new(
                    "transport.ownership",
                    "a bonded group leg needs its own connected socket; Shared ownership is not supported here",
                )));
            }
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

    #[must_use]
    pub fn io_stats(&self) -> BatchIoStats {
        self.io_stats
    }

    /// Perform bounded, nonblocking work for every leg. Call after a
    /// Tokio readiness notification or when the next timer is due; this
    /// never blocks one leg waiting for another.
    ///
    /// `report` is cleared and refilled in place (D02): a caller drives
    /// every tick, so this reuses the caller-owned `Vec`'s capacity instead
    /// of allocating a fresh one per call.
    pub fn drive(
        &mut self,
        now: Timestamp,
        output_budget: OutputDrainBudget,
        report: &mut GroupDriveReport,
    ) -> io::Result<()> {
        report.legs.clear();
        let recv_budget = RecvBudget::new(2, 64);
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

                let mut malformed_datagrams = 0usize;
                let recv_result = feed_ready(
                    &leg.socket,
                    recv_batch,
                    conn,
                    now,
                    recv_budget,
                    &mut malformed_datagrams,
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
    drain_connected_outputs(
        conn,
        &mut leg.timers,
        &mut leg.pending_outputs,
        now,
        budget,
        |batch| send_connected_ready(&leg.socket, batch),
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
mod tests {
    use super::*;

    /// K02: a `Conn` built via [`caller`] must actually drive with its
    /// configured `TransportConfig::output_drain`, not silently substitute
    /// [`OutputDrainBudget::default`] on every [`Conn::drain_outputs`] call.
    #[test]
    fn caller_constructs_a_conn_that_honors_its_configured_output_drain_budget() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            let remote = peer.local_addr().expect("peer address");

            let config = crate::CallerConfig::builder(remote)
                .configure_transport(|transport| {
                    transport.output_drain = OutputDrainBudget::new(1, 1, 64 * 1024);
                })
                .build()
                .expect("caller config");

            let mut conn =
                super::caller(&config, Timestamp::from_micros(0)).expect("caller builds");

            conn.pending_outputs
                .push_back(ConnectionOutput::SendPacket(b"one".to_vec()));
            conn.pending_outputs
                .push_back(ConnectionOutput::SendPacket(b"two".to_vec()));

            let report = conn
                .drain_outputs(Timestamp::from_micros(0))
                .await
                .expect("drain succeeds");
            assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
            assert!(
                conn.has_pending_outputs(),
                "the second action must remain queued under a 1-action budget"
            );
        });
    }

    /// K02: a `Conn` built via [`caller`] must actually drive receive work
    /// with its configured `TransportConfig::recv_budget`, not silently
    /// substitute [`RecvBudget::default`] on every
    /// [`Conn::recv_with_timeout`] call.
    #[test]
    fn caller_constructs_a_conn_that_honors_its_configured_recv_budget() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            let remote = peer.local_addr().expect("peer address");

            let config = crate::CallerConfig::builder(remote)
                .configure_transport(|transport| {
                    transport.recv_budget = RecvBudget::new(1, 1);
                })
                .build()
                .expect("caller config");
            let mut conn =
                super::caller(&config, Timestamp::from_micros(0)).expect("caller builds");
            let local = conn
                .sock
                .local_addr()
                .expect("conn socket has a local address");

            for _ in 0..3 {
                peer.send_to(b"datagram", local).expect("peer sends");
            }

            let mut buf = [0u8; 64];
            conn.recv_with_timeout(&mut buf, Duration::from_secs(5), Timestamp::from_micros(0))
                .await;

            assert_eq!(
                conn.io_stats().recv_datagrams,
                1,
                "a max_datagrams=1 recv budget must feed exactly one datagram to the protocol"
            );
        });
    }

    /// The pacing schedule now keeps its phase across late service, so it is
    /// worth stating what that does *not* buy at the adapter boundary.
    ///
    /// `SrtConnection` advances the pacing schedule when a packet is queued for
    /// output, not when the datagram reaches the socket, so the protocol cannot
    /// pace on transmit completion. What the adapter guarantees instead is
    /// simple backpressure: while a previous drain left work queued,
    /// `send_paced` refuses a further application send regardless of what the
    /// pacing clock says. That keeps admission from running ahead of a transport
    /// that is not draining.
    #[test]
    fn send_paced_refuses_while_a_previous_drain_is_still_queued() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
            local.set_nonblocking(true).expect("local is nonblocking");
            let sock = UdpSocket::from_std(local).expect("tokio adopts the socket");

            let mut conn = Conn::new(
                SrtConnection::new_caller(shiguredo_srt::ConnectionOptions::default()),
                sock,
            );

            // A queued output is exactly the state a partial or would-block
            // drain leaves behind.
            conn.pending_outputs
                .push_back(ConnectionOutput::SendPacket(b"queued datagram".to_vec()));
            assert!(conn.has_pending_outputs());

            assert!(
                matches!(
                    conn.send_paced(b"payload", Timestamp::from_micros(0)).await,
                    PacedSendOutcome::NotDue
                ),
                "send_paced admitted a packet while output was still queued"
            );
            assert!(
                matches!(
                    conn.send_shared_paced(
                        Bytes::from_static(b"payload"),
                        Timestamp::from_micros(0)
                    )
                    .await,
                    PacedSendOutcome::NotDue
                ),
                "send_shared_paced admitted a packet while output was still queued"
            );

            let _ = peer.local_addr();
        });
    }

    /// Drive a caller/listener pair to `Connected` using pure protocol
    /// calls (no socket I/O needed for the handshake itself).
    fn connected_caller() -> SrtConnection {
        let mut caller = SrtConnection::new_caller(shiguredo_srt::ConnectionOptions {
            socket_id: 1,
            ..Default::default()
        });
        let mut listener = SrtConnection::new_listener(shiguredo_srt::ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            ..Default::default()
        });
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        for round in 0..4 {
            let now = Timestamp::from_micros(round * 10_000);
            while let Some(ConnectionOutput::SendPacket(packet)) = caller.poll_output() {
                listener
                    .feed_recv_buf(&packet, now)
                    .expect("listener accepts packet");
            }
            while let Some(ConnectionOutput::SendPacket(packet)) = listener.poll_output() {
                caller
                    .feed_recv_buf(&packet, now)
                    .expect("caller accepts packet");
            }
            if caller.state() == shiguredo_srt::ConnectionState::Connected {
                break;
            }
        }
        assert_eq!(caller.state(), shiguredo_srt::ConnectionState::Connected);
        caller
    }

    /// S03: `send_paced` must surface a pre-admission protocol rejection
    /// (P03's payload-size limit, here) as `Rejected`, not the old opaque
    /// `Err(())` -- and must not touch sender state or queue any output
    /// for a rejected payload.
    #[test]
    fn send_paced_surfaces_a_protocol_rejection_as_rejected() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
            local
                .connect(peer.local_addr().expect("peer address"))
                .expect("local connects to peer");
            local.set_nonblocking(true).expect("local is nonblocking");
            let sock = UdpSocket::from_std(local).expect("tokio adopts the socket");

            let caller = connected_caller();
            let limit = caller.effective_max_payload_size();
            let next = caller.next_sequence_number().expect("connected sender");
            let mut conn = Conn::new(caller, sock);

            let oversized = vec![0xEE; limit + 1];
            let outcome = conn
                .send_paced(&oversized, Timestamp::from_micros(100_000))
                .await;
            assert!(
                matches!(outcome, PacedSendOutcome::Rejected(_)),
                "expected Rejected, got {outcome:?}"
            );
            assert_eq!(
                conn.conn.next_sequence_number(),
                Some(next),
                "a rejected payload must not advance sender state"
            );
            assert!(
                !conn.has_pending_outputs(),
                "a rejected payload must not queue any output"
            );

            let ok_payload = vec![0xEE; limit];
            let outcome2 = conn
                .send_paced(&ok_payload, Timestamp::from_micros(100_001))
                .await;
            assert!(
                matches!(outcome2, PacedSendOutcome::Sent),
                "expected Sent, got {outcome2:?}"
            );
        });
    }

    /// S04: a task driving `drain_outputs_bounded` can be cancelled at any
    /// `.await`, including while parked on `sock.writable()`. Before the
    /// fix, `collect_output_work` had already popped the packets and timer
    /// actions out of `pending_outputs` into a local `work` queue that only
    /// the async fn's own stack frame owned; dropping that frame mid-await
    /// (exactly what `select!`/`JoinHandle::abort()` do) silently discarded
    /// already-admitted output. The fix stages `work` back into
    /// `pending_outputs` -- the caller-owned field that survives the drop
    /// -- before ever reaching the socket await.
    ///
    /// A bare manual `poll()` on a freshly registered socket's `writable()`
    /// future is a minimal, deterministic readiness boundary: it cannot
    /// observe `Ready` because nothing has driven the reactor's `epoll`
    /// turn yet, so the first poll is guaranteed `Pending`. That gives full
    /// control over the cancellation point without adding any test-only
    /// seam to production code.
    #[test]
    fn drain_outputs_bounded_survives_cancellation_while_parked_on_writable() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        let _guard = runtime.enter();

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
        let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
        local
            .connect(peer.local_addr().expect("peer address"))
            .expect("local connects to peer");
        local.set_nonblocking(true).expect("local is nonblocking");
        peer.set_nonblocking(true).expect("peer is nonblocking");
        let sock = UdpSocket::from_std(local).expect("tokio adopts the socket");

        let mut conn = Conn::new(
            SrtConnection::new_caller(shiguredo_srt::ConnectionOptions::default()),
            sock,
        );
        conn.pending_outputs
            .push_back(ConnectionOutput::SendPacket(b"first".to_vec()));
        conn.pending_outputs
            .push_back(ConnectionOutput::SendPacket(b"second".to_vec()));
        conn.pending_outputs.push_back(ConnectionOutput::SetTimer {
            id: shiguredo_srt::TimerId::Ack,
            duration_micros: 10_000,
        });
        let before: Vec<_> = conn.pending_outputs.iter().cloned().collect();

        let budget = OutputDrainBudget::new(usize::MAX, usize::MAX, usize::MAX);
        let mut future = Box::pin(conn.drain_outputs_bounded(Timestamp::from_micros(0), budget));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let polled = future.as_mut().poll(&mut cx);
        assert!(
            matches!(polled, Poll::Pending),
            "expected the first poll to park on writable() with no reactor turn yet, got {polled:?}"
        );

        // Cancellation: drop the suspended future without ever resuming it.
        drop(future);

        assert_eq!(
            conn.pending_outputs.iter().collect::<Vec<_>>(),
            before.iter().collect::<Vec<_>>(),
            "cancelling before the writable() readiness resolved must leave every \
             queued packet and timer action exactly as staged, in order"
        );

        let mut buf = [0u8; 64];
        assert!(
            matches!(
                peer.recv(&mut buf),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
            ),
            "nothing should have reached the wire before cancellation"
        );
    }

    /// T04 (Opus review): same fix and rationale as group_conn.rs's
    /// `mark_member_broken_if_new_only_reports_the_first_transition`.
    #[test]
    fn mark_member_broken_if_new_only_reports_the_first_transition() {
        let mut group =
            shiguredo_srt::SrtGroup::new(shiguredo_srt::SRTGROUP_MASK | 1, GroupMode::Broadcast)
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
            let mut report = GroupDriveReport::default();
            conn.drive(
                Timestamp::from_micros(0),
                OutputDrainBudget::default(),
                &mut report,
            )
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

    /// K01 (Opus review): same as
    /// `group_conn::group_conn_tests::caller_rejects_a_shared_ownership_leg_instead_of_building_an_unconnected_socket`,
    /// for this Tokio-native `GroupConn::caller`.
    #[test]
    fn group_caller_rejects_a_shared_ownership_leg_instead_of_building_an_unconnected_socket() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
            let remote = peer.local_addr().expect("peer address");
            let group = crate::GroupConfig::new(45, shiguredo_srt::GroupType::Broadcast);
            let result = GroupConn::caller(
                group,
                [GroupCallerLeg::new(
                    1,
                    10,
                    crate::CallerConfig::builder(remote)
                        .ownership(crate::SocketOwnership::Shared)
                        .build()
                        .expect("caller config builds"),
                )],
                Timestamp::from_micros(0),
            );
            match result {
                Ok(_) => panic!(
                    "a Shared-ownership leg must be rejected, not silently built unconnected"
                ),
                Err(error) => assert!(matches!(error, GroupBuildError::Config(_))),
            }
        });
    }

    struct GroupPeer {
        socket: std::net::UdpSocket,
        connection: SrtConnection,
        caller: Option<std::net::SocketAddr>,
    }

    impl GroupPeer {
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
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
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

    async fn connect_two_leg_tokio_group() -> (GroupConn, GroupPeer, GroupPeer) {
        let mut first_peer = GroupPeer::new();
        let mut second_peer = GroupPeer::new();
        let group = crate::GroupConfig::new(44, shiguredo_srt::GroupType::Broadcast);
        let mut conn = GroupConn::caller(
            group,
            [
                GroupCallerLeg::new(
                    1,
                    10,
                    crate::CallerConfig::builder(
                        first_peer.socket.local_addr().expect("first address"),
                    )
                    .build()
                    .expect("first caller config"),
                ),
                GroupCallerLeg::new(
                    2,
                    20,
                    crate::CallerConfig::builder(
                        second_peer.socket.local_addr().expect("second address"),
                    )
                    .build()
                    .expect("second caller config"),
                ),
            ],
            Timestamp::from_micros(0),
        )
        .expect("bonded Tokio caller builds");

        for (_, socket) in conn.leg_sockets() {
            socket.writable().await.expect("leg becomes writable");
        }

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
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
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

    /// T04: same isolation property as
    /// `group_conn::group_conn_tests::sustained_malformed_input_on_one_leg_does_not_stop_the_group`,
    /// exercised against this file's own Tokio-native `GroupConn::drive`
    /// (a separate `feed_ready`-based code path from the generic one).
    #[test]
    fn sustained_malformed_input_on_one_leg_does_not_stop_the_tokio_group() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let (mut conn, mut first_peer, mut second_peer) = connect_two_leg_tokio_group().await;
            let first_addr = conn
                .leg_sockets()
                .find(|(id, _)| *id == 1)
                .map(|(_, sock)| sock)
                .expect("leg 1 socket")
                .local_addr()
                .expect("leg 1 address");

            let mut total_malformed = 0usize;
            let mut report = GroupDriveReport::default();
            for round in 0..10 {
                let now = Timestamp::from_micros(1_000_000 + round * 10_000);
                for _ in 0..3 {
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
        });
    }

    /// T04: same isolation/honest-failure properties as
    /// `group_conn::group_conn_tests::one_leg_socket_failure_is_isolated_and_all_legs_failed_is_reported_honestly`,
    /// exercised against this file's own Tokio-native `GroupConn::drive`.
    #[test]
    fn one_leg_socket_failure_is_isolated_in_the_tokio_group() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let (mut conn, first_peer, mut second_peer) = connect_two_leg_tokio_group().await;

            // Dropping the peer (rather than closing our own registered
            // leg fd) is a realistic genuine failure -- the peer's port
            // stops existing, so a further send to it eventually comes
            // back as a real `ECONNREFUSED` via ICMP, without touching
            // our own socket's live Tokio registration at all.
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
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
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
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
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
        });
    }

    #[test]
    fn drain_readable_clears_a_burst_through_try_io() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
            receiver.set_nonblocking(true).expect("nonblocking");
            let dest = receiver.local_addr().expect("addr");
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
            for payload in [b"x".as_slice(), b"y", b"z"] {
                sender.send_to(payload, dest).expect("send");
            }
            let sock = UdpSocket::from_std(receiver).expect("tokio adopts");
            sock.readable().await.expect("readable");

            let mut batch = RecvBatch::new();
            let mut got = Vec::new();
            let report =
                drain_readable(&sock, &mut batch, RecvBudget::from_rounds(1), |_, data| {
                    got.push(data.to_vec());
                })
                .expect("drain");
            assert_eq!(report.datagrams, 3);
            assert_eq!(report.syscalls, 1);
            assert_eq!(got, [b"x".to_vec(), b"y".to_vec(), b"z".to_vec()]);
        });
    }

    /// T02: `drain_readable` used to always ask `try_io`'s closure for a
    /// whole `RecvBatch::capacity()` batch regardless of the remaining
    /// budget, so a small budget could be overshot within a single
    /// `recvmmsg` call. Every budget the acceptance criteria names must
    /// be an exact per-call ceiling.
    #[test]
    fn drain_readable_never_exceeds_the_recv_budget() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            for max_datagrams in [1usize, 31, 32, 33, 64] {
                let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
                receiver.set_nonblocking(true).expect("nonblocking");
                let dest = receiver.local_addr().expect("addr");
                let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");

                const TOTAL: usize = 100;
                for i in 0..TOTAL {
                    sender.send_to(&[i as u8], dest).expect("send");
                }
                let sock = UdpSocket::from_std(receiver).expect("tokio adopts");
                sock.readable().await.expect("readable");

                let mut batch = RecvBatch::new();
                let mut delivered = Vec::new();
                loop {
                    let mut this_round = Vec::new();
                    let report = drain_readable(
                        &sock,
                        &mut batch,
                        RecvBudget::new(usize::MAX, max_datagrams),
                        |_, data| this_round.push(data[0]),
                    )
                    .expect("drain");
                    assert!(
                        report.datagrams <= max_datagrams,
                        "budget {max_datagrams}: a single drain reported {} datagrams",
                        report.datagrams
                    );
                    if this_round.is_empty() {
                        assert!(
                            report.would_block,
                            "budget {max_datagrams}: an empty round must mean WouldBlock"
                        );
                        break;
                    }
                    delivered.extend(this_round);
                    if delivered.len() >= TOTAL {
                        break;
                    }
                }
                assert_eq!(
                    delivered,
                    (0..TOTAL as u8).collect::<Vec<_>>(),
                    "budget {max_datagrams}: every datagram delivered exactly once, in order"
                );
            }
        });
    }

    /// T02 checkpoint 3: a budget yield must not strand queued datagrams
    /// behind a readiness edge that never re-fires. `try_io`'s contract is
    /// that the readiness flag stays set unless the closure itself returns
    /// `WouldBlock` -- `drain_readable` only ever returns `WouldBlock` from
    /// a real empty `recvmmsg`, never merely because the datagram budget
    /// ran out. So after a budget-exhausted drain, a *fresh* `readable()`
    /// call (not the one already consumed to get here) must resolve
    /// immediately, with no new datagram arriving to generate a new edge,
    /// and the remaining data must still be there to drain.
    #[test]
    fn budget_exhausted_drain_keeps_readiness_armed_without_a_new_edge() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
            receiver.set_nonblocking(true).expect("nonblocking");
            let dest = receiver.local_addr().expect("addr");
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
            const TOTAL: usize = RecvBatch::DEFAULT_CAPACITY + 5;
            for i in 0..TOTAL {
                sender.send_to(&[i as u8], dest).expect("send");
            }
            let sock = UdpSocket::from_std(receiver).expect("tokio adopts");
            sock.readable().await.expect("readable");

            let mut batch = RecvBatch::new();
            let mut first = Vec::new();
            let report = drain_readable(
                &sock,
                &mut batch,
                RecvBudget::new(1, RecvBatch::DEFAULT_CAPACITY),
                |_, data| first.push(data[0]),
            )
            .expect("first drain");
            assert_eq!(first.len(), RecvBatch::DEFAULT_CAPACITY);
            assert!(!report.would_block);

            // No new datagram arrives here -- nothing generates a fresh
            // edge. A truly edge-triggered wait for the next readable()
            // with no intervening data would hang; this must not hang and
            // must not report WouldBlock either, since the remainder is
            // still sitting in the kernel's receive queue.
            tokio::time::timeout(std::time::Duration::from_secs(5), sock.readable())
                .await
                .expect("readiness must still be armed without a new edge")
                .expect("readable");

            let mut rest = Vec::new();
            drain_readable(
                &sock,
                &mut batch,
                RecvBudget::until_would_block(),
                |_, data| rest.push(data[0]),
            )
            .expect("second drain");
            first.extend(rest);
            assert_eq!(first, (0..TOTAL as u8).collect::<Vec<_>>());
        });
    }

    #[test]
    fn drain_outputs_sends_queued_packets_as_one_sendmmsg() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer");
            peer.set_nonblocking(true).expect("nonblocking");
            let dest = peer.local_addr().expect("addr");
            let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local");
            local.set_nonblocking(true).expect("nonblocking");
            local.connect(dest).expect("connect");
            let sock = UdpSocket::from_std(local).expect("tokio adopts");

            let mut conn = Conn::new(
                SrtConnection::new_caller(shiguredo_srt::ConnectionOptions::default()),
                sock,
            );
            conn.pending_outputs.extend([
                ConnectionOutput::SendPacket(b"p1".to_vec()),
                ConnectionOutput::SendPacket(b"p2".to_vec()),
                ConnectionOutput::SendPacket(b"p3".to_vec()),
            ]);
            let report = conn
                .drain_outputs(Timestamp::from_micros(0))
                .await
                .expect("drain");
            assert_eq!(report.packets, 3);
            assert_eq!(report.syscalls, 1);
            assert!(!conn.has_pending_outputs());
            assert_eq!(conn.io_stats().packets_per_visit(), 3.0);

            let mut buf = [0u8; 64];
            for expected in [b"p1".as_slice(), b"p2", b"p3"] {
                let n = peer.recv(&mut buf).expect("recv");
                assert_eq!(&buf[..n], expected);
            }
        });
    }

    #[test]
    fn schedule_on_arms_the_shared_worker_waiter() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
            local.set_nonblocking(true).expect("nonblocking");
            let sock = UdpSocket::from_std(local).expect("tokio adopts the socket");
            let conn = Conn::new(
                SrtConnection::new_caller(shiguredo_srt::ConnectionOptions::default()),
                sock,
            );
            let mut waiter = HighResWaiter::<u32>::new().expect("waiter");
            conn.schedule_on(&mut waiter, 9, Timestamp::from_micros(0))
                .expect("schedule");
            assert_eq!(waiter.deadline_len(), 1);
            assert!(waiter.next_deadline().is_some());
            assert!(conn.schedule_wait(Timestamp::from_micros(0)) > Duration::ZERO);
        });
    }

    // D02's allocation-reuse guarantee for this file's Tokio-native
    // `GroupConn::drive` is proven in
    // `tests/tokio_group_drive_allocation_guard.rs`: a real allocation
    // count across idle calls, not a `Vec::as_ptr()` comparison. An
    // earlier version of this test used `as_ptr()` and passed even against
    // a deliberately reintroduced free-and-reallocate regression, because
    // glibc's allocator handed back the same address for the freed block.
}
