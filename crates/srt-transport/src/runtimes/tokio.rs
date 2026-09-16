use crate::{
    BatchIoStats, GroupBuildError, GroupCallerLeg, GroupConnectionLeg, GroupConnectionStats,
    GroupDriveReport, GroupLegDriveReport, GroupLogicalCounters, HighResWaiter, ManualTimerStore,
    MonotonicDeadline, OutputDrainBudget, OutputDrainReport, OutputDrainStatus, PacedSendOutcome,
    RecvBatch, RecvBudget, RecvDrainReport, collect_output_work, drain_connected_outputs,
    drain_output_work, group_connection_stats, prepend_outputs, schedule_wait_micros,
    sendmsg_connected_batch,
};
use srt_proto::{Bytes, ConnectionOutput, GroupMode, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::hash::Hash;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use zeroize::Zeroize;

/// Per-connection state for tokio: protocol + async socket + timer deadlines.
pub struct Conn {
    conn: SrtConnection,
    sock: UdpSocket,
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

    /// Borrow the protocol state without exposing the adapter's internals.
    #[must_use]
    pub fn protocol(&self) -> &SrtConnection {
        &self.conn
    }

    /// Mutably access protocol state for a scoped custom-driver operation.
    pub fn protocol_mut(&mut self) -> &mut SrtConnection {
        &mut self.conn
    }

    /// Borrow the runtime socket used by this connection.
    #[must_use]
    pub fn socket(&self) -> &UdpSocket {
        &self.sock
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
        Self::with_transport(
            conn,
            sock,
            output_drain,
            recv_budget,
            RecvBatch::DEFAULT_CAPACITY,
        )
    }

    fn with_transport(
        conn: SrtConnection,
        sock: UdpSocket,
        output_drain: OutputDrainBudget,
        recv_budget: RecvBudget,
        batch_capacity: usize,
    ) -> Self {
        Self {
            conn,
            sock,
            timers: crate::ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
            recv_batch: RecvBatch::with_capacity(batch_capacity, RecvBatch::DEFAULT_BUF_LEN),
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
        let budget = budget.intersect(self.output_drain);
        let (work, budget_exhausted) =
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget)
                .map_err(|error| io::Error::other(error.to_string()))?;
        let mut report = OutputDrainReport {
            status: if budget_exhausted {
                OutputDrainStatus::BudgetExhausted
            } else {
                OutputDrainStatus::Drained
            },
            ..OutputDrainReport::default()
        };
        let work = if work_has_packets(&work) {
            // Keep every collected item in the owned pending queue while
            // awaiting readiness. Cancellation must never strand a timer or
            // packet in a local future-owned deque.
            prepend_outputs(&mut self.pending_outputs, work.into_iter());
            self.sock.writable().await?;
            let (work, second_budget_exhausted) =
                collect_output_work(&mut self.conn, &mut self.pending_outputs, budget)
                    .map_err(|error| io::Error::other(error.to_string()))?;
            if second_budget_exhausted {
                report.status = report.status.combine(OutputDrainStatus::BudgetExhausted);
            }
            work
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
    /// timer. After [`HighResWaiter::wait`], service the returned due batch
    /// and repeat immediately while `WaitOutcome::due_remaining` is set. One
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
        waiter.set_deadline(key, MonotonicDeadline::after(self.schedule_wait(now)))
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
    on_datagram: impl FnMut(Option<SocketAddr>, &[u8]),
) -> io::Result<RecvDrainReport> {
    let batch_capacity = batch.capacity();
    drain_readable_with_capacity(sock, batch, budget, batch_capacity, on_datagram)
}

fn drain_readable_with_capacity(
    sock: &UdpSocket,
    batch: &mut RecvBatch,
    budget: RecvBudget,
    batch_capacity: usize,
    mut on_datagram: impl FnMut(Option<SocketAddr>, &[u8]),
) -> io::Result<RecvDrainReport> {
    let mut report = RecvDrainReport::default();
    let batch_capacity = batch_capacity.clamp(1, batch.capacity());
    let mut dequeued = 0usize;
    for _ in 0..budget.max_rounds {
        if dequeued >= budget.max_datagrams {
            break;
        }
        let requested = (budget.max_datagrams - dequeued).min(batch_capacity);
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
                    dequeued += 1;
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
    batch_capacity: usize,
    malformed_datagrams: &mut usize,
) -> io::Result<RecvDrainReport> {
    drain_readable_with_capacity(sock, batch, budget, batch_capacity, |_, data| {
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
    prepared.require_exclusive()?;
    let socket = UdpSocket::from_std(prepared.bind_socket()?)?;
    Ok(Conn::with_transport(
        prepared.connection(now)?,
        socket,
        prepared.transport.output_drain,
        prepared.transport.recv_budget,
        prepared.transport.recv_batch_capacity(),
    ))
}

struct GroupLeg {
    member_id: u32,
    socket: UdpSocket,
    timers: ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
    recv_budget: RecvBudget,
    batch_capacity: usize,
}

struct TokioGroupLeg {
    leg: GroupConnectionLeg,
    recv_budget: RecvBudget,
    batch_capacity: usize,
}

/// Tokio-native multi-socket driver for an SRT Broadcast or Backup group.
///
/// This owns Tokio sockets, not a synchronous [`crate::GroupConn`] wrapped
/// in a task. Group sequencing, selection, and telemetry remain in the
/// shared protocol core; this type supplies Tokio's nonblocking socket
/// operations and exposes every leg for readiness registration.
pub struct GroupConn {
    group: srt_proto::SrtGroup,
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
        Self::new_with_policies(
            group_id,
            mode,
            legs.into_iter().map(|leg| TokioGroupLeg {
                leg,
                recv_budget: RecvBudget::default(),
                batch_capacity: RecvBatch::DEFAULT_CAPACITY,
            }),
        )
    }

    fn new_with_policies(
        group_id: u32,
        mode: GroupMode,
        legs: impl IntoIterator<Item = TokioGroupLeg>,
    ) -> Result<Self, GroupBuildError> {
        let mut group = srt_proto::SrtGroup::new(group_id, mode)?;
        let mut io_legs = Vec::new();
        let mut batch_capacity = 1;
        for TokioGroupLeg {
            leg,
            recv_budget,
            batch_capacity: leg_batch_capacity,
        } in legs
        {
            group.add_member(leg.member_id, leg.weight, leg.connection)?;
            batch_capacity = batch_capacity.max(leg_batch_capacity);
            io_legs.push(GroupLeg {
                member_id: leg.member_id,
                socket: UdpSocket::from_std(leg.socket)?,
                timers: ManualTimerStore::new(),
                pending_outputs: VecDeque::new(),
                recv_budget,
                batch_capacity: leg_batch_capacity.max(1),
            });
        }
        Ok(Self {
            group,
            legs: io_legs,
            logical_payloads_sent: 0,
            logical_payload_bytes_sent: 0,
            logical_payloads_received: 0,
            logical_payload_bytes_received: 0,
            recv_batch: RecvBatch::with_capacity(batch_capacity, RecvBatch::DEFAULT_BUF_LEN),
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
            prepared.require_exclusive()?;
            raw_legs.push(TokioGroupLeg {
                recv_budget: prepared.transport.recv_budget,
                batch_capacity: prepared.transport.recv_batch_capacity(),
                leg: GroupConnectionLeg {
                    member_id: leg.member_id,
                    weight: leg.weight,
                    connection: prepared.connection(now)?,
                    socket: prepared.bind_socket()?,
                },
            });
        }
        let mode = GroupMode::from_group_type(group.group_type)
            .ok_or(GroupBuildError::InvalidGroupType)?;
        Self::new_with_policies(group.group_id, mode, raw_legs)
    }

    #[must_use]
    pub fn group(&self) -> &srt_proto::SrtGroup {
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

    pub fn send(&mut self, payload: &[u8], now: Timestamp) -> Result<usize, srt_proto::Error> {
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
    ) -> Result<usize, srt_proto::Error> {
        let len = payload.len() as u64;
        let legs = self.group.send_shared(payload, now)?;
        self.logical_payloads_sent = self.logical_payloads_sent.saturating_add(1);
        self.logical_payload_bytes_sent = self.logical_payload_bytes_sent.saturating_add(len);
        Ok(legs)
    }

    pub fn disconnect(&mut self, now: Timestamp) {
        self.group.disconnect(now);
    }

    pub fn poll_data(&mut self, now: Timestamp) -> Option<srt_proto::group::GroupPacket> {
        self.poll_data_bounded(now, srt_proto::MAX_GROUP_MEMBERS)
            .packet
    }

    /// Return the next deduplicated payload and whether another immediate
    /// lifecycle-drain pass is required before waiting for new input.
    pub fn poll_data_bounded(
        &mut self,
        now: Timestamp,
        max_events: usize,
    ) -> srt_proto::GroupDataPoll {
        let poll = self.group.poll_data_bounded(now, max_events);
        let Some(packet) = poll.packet.as_ref() else {
            return poll;
        };
        self.logical_payloads_received = self.logical_payloads_received.saturating_add(1);
        self.logical_payload_bytes_received = self
            .logical_payload_bytes_received
            .saturating_add(packet.payload.len() as u64);
        poll
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
                    leg.recv_budget,
                    leg.batch_capacity,
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
fn mark_member_broken_if_new(group: &mut srt_proto::SrtGroup, member_id: u32) -> bool {
    let was_broken = group
        .member(member_id)
        .is_some_and(|member| member.state() == srt_proto::GroupMemberState::Broken);
    group.mark_member_broken(member_id) && !was_broken
}

// ---------------------------------------------------------------------------
// Owner: a single Tokio-driven listener/caller pair (A05)
// ---------------------------------------------------------------------------

/// Send as much of `outbound` as the kernel accepts on an unconnected,
/// possibly-shared socket, retaining the unsent suffix in order -- the
/// Tokio-native counterpart to `send_connected_ready` for a socket with no
/// single destination. `try_io` is synchronous: it always makes one
/// non-blocking attempt regardless of whether `writable()` was awaited
/// first, exactly like `send_connected_ready` and every Mio equivalent.
fn send_destined_ready(
    sock: &UdpSocket,
    outbound: &mut Vec<(SocketAddr, Vec<u8>)>,
    budget: OutputDrainBudget,
) -> io::Result<crate::SendFlushReport> {
    if outbound.is_empty() {
        return Ok(crate::SendFlushReport::default());
    }
    let limit = crate::destined_send_limit(outbound, budget);
    if limit == 0 {
        return Ok(crate::SendFlushReport::default());
    }
    let result = sock.try_io(
        tokio::io::Interest::WRITABLE,
        || match crate::sendmsg_batch(sock.as_raw_fd(), &outbound[..limit])? {
            0 if limit != 0 => Err(io::ErrorKind::WouldBlock.into()),
            n => Ok(n),
        },
    );
    match result {
        Ok(sent) if sent <= limit => {
            outbound.drain(..sent);
            Ok(crate::SendFlushReport {
                sent,
                would_block: sent < limit,
            })
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sendmmsg reported more datagrams than supplied",
        )),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(crate::SendFlushReport {
            would_block: true,
            ..crate::SendFlushReport::default()
        }),
        Err(batch_error) => {
            if is_transient_send_error(&batch_error) {
                return Ok(crate::SendFlushReport {
                    would_block: true,
                    ..crate::SendFlushReport::default()
                });
            }
            // `sendmmsg` reports one error for the whole batch. A malformed
            // destination must not take down every logical session sharing
            // this egress socket, so retry packets individually and retire
            // only the destination that failed. A transient `WouldBlock`
            // keeps the suffix for the next writable wake.
            let mut report = crate::SendFlushReport::default();
            let mut completed = 0;
            while completed < limit {
                let (destination, packet) = &outbound[completed];
                let result = sock.try_io(tokio::io::Interest::WRITABLE, || {
                    sock.try_send_to(packet, *destination)
                });
                match result {
                    Ok(_) => {
                        completed += 1;
                        report.sent = report.sent.saturating_add(1);
                    }
                    Err(error) if is_transient_send_error(&error) => {
                        report.would_block = true;
                        break;
                    }
                    Err(error) if is_destination_send_error(&error) => {
                        // A destination-specific error is isolated to this
                        // packet. Keeping it would make every future visit
                        // fail at the same item and starve healthy peers.
                        completed += 1;
                    }
                    Err(error) => {
                        outbound.drain(..completed);
                        return Err(error);
                    }
                }
            }
            outbound.drain(..completed);
            Ok(report)
        }
    }
}

fn is_transient_send_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || matches!(error.raw_os_error(), Some(libc::ENOBUFS | libc::ENOMEM))
}

fn is_destination_send_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(
            libc::EAFNOSUPPORT
                | libc::EADDRNOTAVAIL
                | libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::ECONNREFUSED
                | libc::EMSGSIZE
        )
    )
}

fn side_output_budget(
    transport: crate::ResolvedTransportConfig,
    caller_budget: crate::OutputDrainBudget,
) -> crate::OutputDrainBudget {
    caller_budget
        .intersect(transport.output_drain)
        .intersect(OutputDrainBudget::new(
            OWNER_MAINTENANCE_MAX_ACTIONS,
            caller_budget.max_packets,
            caller_budget.max_bytes,
        ))
}

fn drive_listener_side(
    side: &mut OwnerListenerSide,
    now: Timestamp,
    remaining: &mut crate::OutputDrainBudget,
    status: crate::OutputDrainStatus,
) -> io::Result<crate::OutputDrainStatus> {
    let was_empty = side.outbound.is_empty();
    let before_len = side.outbound.len();
    let before_bytes: usize = side.outbound.iter().map(|(_, packet)| packet.len()).sum();
    let budget = side_output_budget(side.transport, *remaining);
    let (_, maintenance_visits) =
        side.peers
            .prune_idle_bounded_with_visits(now, side.idle_timeout, budget.max_actions);
    remaining.consume(maintenance_visits, 0, 0);
    let poll_report = side.outbound.is_empty().then(|| {
        let budget = side_output_budget(side.transport, *remaining);
        side.peers
            .poll_outbound_bounded_with_visits(now, budget, &mut side.outbound)
    });
    if let Some((report, visits)) = poll_report {
        remaining.consume(visits, report.packets, report.bytes);
        side.output_pending = report.status == crate::OutputDrainStatus::BudgetExhausted;
    }
    let flush_budget = poll_report
        .map(|(report, _)| OutputDrainBudget::new(report.packets, report.packets, report.bytes))
        .unwrap_or(*remaining);
    let result = drive_side_output(
        &side.socket,
        &mut side.outbound,
        &mut side.write_blocked,
        status,
        poll_report,
        flush_budget,
    );
    if !was_empty {
        let after_bytes: usize = side.outbound.iter().map(|(_, packet)| packet.len()).sum();
        let sent = before_len.saturating_sub(side.outbound.len());
        remaining.consume(sent, sent, before_bytes.saturating_sub(after_bytes));
    }
    result
}

fn drive_caller_side(
    side: &mut OwnerCallerSide,
    expired_callers: &mut VecDeque<crate::LogicalCallerId>,
    now: Timestamp,
    remaining: &mut crate::OutputDrainBudget,
    status: crate::OutputDrainStatus,
) -> io::Result<crate::OutputDrainStatus> {
    let was_empty = side.outbound.is_empty();
    let before_len = side.outbound.len();
    let before_bytes: usize = side.outbound.iter().map(|(_, packet)| packet.len()).sum();
    let budget = side_output_budget(side.transport, *remaining);
    let (expired, maintenance_visits) = side
        .callers
        .poll_expirations_bounded_with_visits(now, budget.max_actions);
    remaining.consume(maintenance_visits, 0, 0);
    for id in expired {
        if expired_callers.len() == OWNER_MAINTENANCE_MAX_ACTIONS {
            expired_callers.pop_front();
        }
        expired_callers.push_back(id);
    }
    let poll_report = side.outbound.is_empty().then(|| {
        let budget = side_output_budget(side.transport, *remaining);
        side.callers
            .table_mut()
            .poll_outbound_bounded_with_visits(now, budget, &mut side.outbound)
    });
    if let Some((report, visits)) = poll_report {
        remaining.consume(visits, report.packets, report.bytes);
        side.output_pending = report.status == crate::OutputDrainStatus::BudgetExhausted;
    }
    let flush_budget = poll_report
        .map(|(report, _)| OutputDrainBudget::new(report.packets, report.packets, report.bytes))
        .unwrap_or(*remaining);
    let result = drive_side_output(
        &side.socket,
        &mut side.outbound,
        &mut side.write_blocked,
        status,
        poll_report,
        flush_budget,
    );
    if !was_empty {
        let after_bytes: usize = side.outbound.iter().map(|(_, packet)| packet.len()).sum();
        let sent = before_len.saturating_sub(side.outbound.len());
        remaining.consume(sent, sent, before_bytes.saturating_sub(after_bytes));
    }
    result
}

/// Combine a side's output-drain report (if one was polled this tick, i.e.
/// `outbound` was empty going in) with its current backpressure state, then
/// attempt to send whatever `outbound` now holds. Shared by both the
/// listener and caller halves of [`Runtime::drive`], which differ only in
/// how they obtain `poll_report`.
fn drive_side_output(
    sock: &UdpSocket,
    outbound: &mut Vec<(SocketAddr, Vec<u8>)>,
    write_blocked: &mut bool,
    mut status: crate::OutputDrainStatus,
    poll_report: Option<(crate::OutputDrainReport, usize)>,
    flush_budget: OutputDrainBudget,
) -> io::Result<crate::OutputDrainStatus> {
    status = match poll_report {
        Some((report, _)) => status.combine(report.status),
        None => status.combine(if *write_blocked {
            crate::OutputDrainStatus::Backpressured
        } else {
            crate::OutputDrainStatus::BudgetExhausted
        }),
    };
    match send_destined_ready(sock, outbound, flush_budget) {
        Ok(report) => {
            *write_blocked = report.would_block;
            if report.would_block {
                status = status.combine(crate::OutputDrainStatus::Backpressured);
            } else if !outbound.is_empty() {
                // A destination-specific send error can retire one packet
                // without setting `would_block`, while a later packet in
                // the same queue remains unsent. Returning `Drained` here
                // would strand that suffix if the caller waits only for a
                // readiness edge. Keep the continuation visible even when
                // the socket itself was writable for the prefix.
                status = status.combine(crate::OutputDrainStatus::BudgetExhausted);
            }
            Ok(status)
        }
        Err(error) => {
            // Destination errors are isolated by `send_destined_ready`;
            // only an impossible internal result reaches this branch.
            *write_blocked = false;
            Err(error)
        }
    }
}

/// A future that awaits `socket.readable()` when present, or never resolves
/// when absent -- lets [`Owner::run_once`]'s `tokio::select!` treat a side
/// that does not exist yet the same as one that is simply never ready,
/// without a separate `if` guard per branch.
async fn readable_or_pending(socket: Option<&UdpSocket>) -> io::Result<()> {
    match socket {
        Some(socket) => socket.readable().await,
        None => std::future::pending().await,
    }
}

async fn writable_or_pending(socket: Option<&UdpSocket>, pending: bool) -> io::Result<()> {
    if !pending {
        return std::future::pending().await;
    }
    match socket {
        Some(socket) => socket.writable().await,
        None => std::future::pending().await,
    }
}

fn receive_continuation(report: RecvDrainReport, budget: RecvBudget) -> bool {
    !report.would_block
        && (report.syscalls >= budget.max_rounds || report.datagrams >= budget.max_datagrams)
}

const OWNER_MAINTENANCE_MAX_ACTIONS: usize = 1024;

fn side_needs_immediate_work(
    recv_pending: bool,
    event_pending: bool,
    output_pending: bool,
    write_blocked: bool,
    outbound_empty: bool,
) -> bool {
    recv_pending || event_pending || (!write_blocked && (output_pending || !outbound_empty))
}

struct OwnerListenerSide {
    socket: UdpSocket,
    peers: crate::PeerTable,
    admission: crate::AdmissionOptions,
    telemetry: crate::IngressTelemetry,
    recv_batch: RecvBatch,
    outbound: Vec<(SocketAddr, Vec<u8>)>,
    idle_timeout: Duration,
    transport: crate::ResolvedTransportConfig,
    recv_pending: bool,
    output_pending: bool,
    event_pending: bool,
    write_blocked: bool,
}

struct OwnerCallerSide {
    socket: UdpSocket,
    callers: crate::CallerPool,
    recv_batch: RecvBatch,
    outbound: Vec<(SocketAddr, Vec<u8>)>,
    transport: crate::ResolvedTransportConfig,
    recv_pending: bool,
    output_pending: bool,
    event_pending: bool,
    write_blocked: bool,
    local_bind: Option<SocketAddr>,
    connect_config: crate::ConnectConfig,
}

/// The Tokio-native counterpart to [`crate::mio_transport::Owner`] (A03,
/// A04): one shared-socket listener side ([`crate::PeerTable`]) and one
/// shared-socket caller side ([`crate::CallerPool`]), driven by Tokio's own
/// async socket readiness (`UdpSocket::readable()`) instead of `mio::Poll`.
/// Every other design decision mirrors the Mio owner exactly -- same
/// `PerPort`-only listener topology, same `SocketOwnership::Shared`
/// requirement for callers, same IPv4-only send path restriction, same
/// finite default caller-pool policy overridable via
/// [`Self::set_caller_pool_policy`], same `idle_timeout` enforcement every
/// tick -- because both owners are assembled from the identical
/// runtime-agnostic tables; only the socket layer differs.
///
/// This is the embeddable core (A05 checkpoint 4): call [`Self::run_once`]
/// in a loop from an application's own spawned task to drive it directly,
/// with no command channel or background task of this crate's own.
/// [`Facade`] is the managed, ergonomic wrapper built on top of exactly
/// this type (A05 checkpoint 1).
pub struct Owner {
    listener: Option<OwnerListenerSide>,
    caller: Option<OwnerCallerSide>,
    caller_pool_policy: Option<(std::num::NonZeroUsize, Duration)>,
    caller_pool_policy_explicit: bool,
    expired_callers: VecDeque<crate::LogicalCallerId>,
    socket_memory_budget: Option<std::num::NonZeroUsize>,
}

impl Default for Owner {
    fn default() -> Self {
        Self::new()
    }
}

impl Owner {
    #[must_use]
    pub fn new() -> Self {
        Self {
            listener: None,
            caller: None,
            caller_pool_policy: None,
            caller_pool_policy_explicit: false,
            expired_callers: VecDeque::new(),
            socket_memory_budget: None,
        }
    }

    /// Set the caller-side `max_in_flight`/`attempt_deadline` policy (A04).
    /// Must be called before the first [`Self::connect`] call.
    pub fn set_caller_pool_policy(
        &mut self,
        max_in_flight: std::num::NonZeroUsize,
        attempt_deadline: Duration,
    ) -> Result<(), crate::RuntimeBuildError> {
        if self.caller.is_some() {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller_pool_policy",
                "must be set before the first connect() call, not after the caller \
                 socket and its pool already exist",
            )));
        }
        if attempt_deadline.is_zero() {
            return Err(crate::ConfigError::new(
                "caller_pool_policy",
                "attempt deadline must be positive",
            )
            .into());
        }
        self.caller_pool_policy = Some((max_in_flight, attempt_deadline));
        self.caller_pool_policy_explicit = true;
        Ok(())
    }

    /// Bind and register this owner's one listener socket. May be called
    /// at most once. Must be called from within a Tokio runtime context
    /// (`UdpSocket::from_std` registers with the current reactor).
    pub fn listen(
        &mut self,
        config: &crate::ListenerConfig,
    ) -> Result<(), crate::RuntimeBuildError> {
        if self.listener.is_some() {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "listener",
                "Owner::listen was already called; this owner drives exactly one listener socket",
            )));
        }
        let prepared = config.prepare(crate::RuntimeFlavor::Tokio)?;
        if !matches!(
            prepared.transport.topology,
            crate::ResolvedListenerTopology::PerPort
        ) {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "listener.transport.topology",
                "Owner drives a single PerPort listener socket; pooled or \
                 reuseport topologies need a multi-acceptor driver, which \
                this card does not build",
            )));
        }
        if prepared.transport.promotion != srt_lifecycle::Promotion::Never {
            return Err(crate::ConfigError::new(
                "listener.transport.promotion",
                "Owner has no relocation target; set promotion to Never",
            )
            .into());
        }
        if !prepared.bind.is_ipv4() {
            // Same reasoning as the Mio owner: sendmsg_batch is IPv4-only
            // and one bad destination fails the whole shared batch.
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "listener.bind",
                "Owner's send path (sendmsg_batch) is IPv4-only; bind an \
                 IPv4 address instead of an IPv6 or dual-stack one",
            )));
        }
        if let Some(budget) = prepared.admission.socket_memory_budget {
            let caller_requested = self
                .caller
                .as_ref()
                .map_or(0, |c| c.transport.socket_buffer_bytes.saturating_mul(4));
            let total = prepared
                .requested_socket_memory_bytes()
                .saturating_add(caller_requested);
            if total > budget.get() {
                return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                    "admission.socket_memory_budget",
                    format!(
                        "{total} bytes requested for combined listener and caller buffers exceeds owner budget of {} bytes",
                        budget.get()
                    ),
                )));
            }
            self.socket_memory_budget = Some(budget);
        }
        let mut sockets = prepared.bind_sockets()?;
        let socket = UdpSocket::from_std(sockets.remove(0))?;
        self.listener = Some(OwnerListenerSide {
            socket,
            admission: prepared.admission_options(),
            idle_timeout: prepared.admission.idle_timeout,
            peers: prepared.peer_table(),
            telemetry: crate::IngressTelemetry::new(),
            recv_batch: RecvBatch::with_capacity(
                prepared.transport.recv_batch_capacity(),
                RecvBatch::DEFAULT_BUF_LEN,
            ),
            outbound: Vec::new(),
            transport: prepared.transport,
            recv_pending: false,
            output_pending: false,
            event_pending: false,
            write_blocked: false,
        });
        Ok(())
    }

    /// Start one outbound session on this owner's shared caller socket,
    /// binding it on the first call. `config.transport.ownership` must be
    /// `Shared` -- see [`crate::mio_transport::Owner::connect`] for the
    /// full reasoning, identical here.
    pub fn connect(
        &mut self,
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<crate::PoolOutcome, crate::RuntimeBuildError> {
        let mut prepared = config.prepare(crate::RuntimeFlavor::Tokio)?;
        if self.caller_pool_policy_explicit
            && let Some((max_in_flight, attempt_deadline)) = self.caller_pool_policy
        {
            prepared.connect.max_in_flight = max_in_flight;
            prepared.connect.attempt_deadline = attempt_deadline;
        }
        if prepared.transport.exclusive {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.transport.ownership",
                "Owner::connect requires SocketOwnership::Shared; an \
                 Exclusive caller connects its own socket to a single \
                 remote and cannot share this owner's one egress socket \
                 with other logical callers",
            )));
        }
        if !config.remote.is_ipv4() {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.remote",
                "Owner's send path (sendmsg_batch) is IPv4-only; connect to \
                 an IPv4 remote address instead",
            )));
        }
        if let Some(side) = self.caller.as_ref() {
            prepared.validate_shared_compatibility(
                side.local_bind,
                side.transport,
                Some(side.connect_config),
            )?;
        }
        if self.caller.is_none() {
            if let Some(budget) = self.socket_memory_budget {
                let listener_requested = self.listener.as_ref().map_or(0, |l| {
                    l.transport
                        .socket_buffer_bytes
                        .saturating_mul(4)
                        .saturating_mul(l.transport.topology.listener_socket_count().get())
                });
                let total =
                    listener_requested.saturating_add(prepared.requested_socket_memory_bytes());
                if total > budget.get() {
                    return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                        "caller.socket_memory_budget",
                        format!(
                            "{total} bytes requested for combined listener and caller buffers exceeds owner budget of {} bytes",
                            budget.get()
                        ),
                    )));
                }
            }
            let socket = UdpSocket::from_std(prepared.bind_socket()?)?;
            let policy = self.caller_pool_policy.unwrap_or((
                prepared.connect.max_in_flight,
                prepared.connect.attempt_deadline,
            ));
            self.caller_pool_policy = Some(policy);
            self.caller = Some(OwnerCallerSide {
                socket,
                // A zero queue capacity, not `CallerPool::new`'s default
                // finite queue: `Facade::connect` documents that it "does
                // not wait for a queued permit" and answers a full pool
                // with `FacadeError::PoolFull` immediately, dropping the
                // request on the `Facade` side. If the pool itself queued
                // that same request, it would later admit it with no
                // `Session`/inbox/control anywhere to claim the resulting
                // connection -- an orphaned session (Opus review finding
                // 3). `Owner::connect` used directly (not through
                // `Facade`) has no such mismatch since its caller already
                // tracks `PoolOutcome::Queued` through the pool's own
                // outcome stream; that path is `mio::Owner`'s, which keeps
                // a real queue.
                callers: crate::CallerPool::with_queue_capacity(policy.0, policy.1, 0),
                recv_batch: RecvBatch::with_capacity(
                    prepared.transport.recv_batch_capacity(),
                    RecvBatch::DEFAULT_BUF_LEN,
                ),
                outbound: Vec::new(),
                transport: prepared.transport,
                recv_pending: false,
                output_pending: false,
                event_pending: false,
                write_blocked: false,
                local_bind: prepared.local_bind,
                connect_config: prepared.connect,
            });
        } else if !self.caller_pool_policy_explicit
            && self.caller_pool_policy
                != Some((
                    prepared.connect.max_in_flight,
                    prepared.connect.attempt_deadline,
                ))
        {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.connect",
                "all callers on a shared owner must use the first caller pool policy",
            )));
        }
        let side = self.caller.as_mut().expect("just ensured above");
        side.callers.connect(prepared, now).map_err(|error| {
            crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.connect",
                error.to_string(),
            ))
        })
    }

    /// Await whichever side becomes readable first (or `timeout`, in case
    /// neither ever does before the next due timer), drain it, then fire
    /// due timers and send every pending output on both sides -- one
    /// complete tick, the async counterpart to
    /// `mio_transport::Owner::poll_io` + `drive` combined into one call
    /// since Tokio's readiness model has no equivalent of `mio::Poll`
    /// returning a batch of ready sockets at once.
    ///
    /// `now` is called only once the readiness wait (or timeout) resolves,
    /// not before -- the same staleness hazard `mio_transport::Owner`'s
    /// Opus review caught applies here too.
    pub async fn run_once(
        &mut self,
        timeout: Duration,
        now: impl Fn() -> Timestamp,
        caller_budget: crate::OutputDrainBudget,
    ) -> io::Result<crate::OutputDrainStatus> {
        let continuation = self.listener.as_ref().is_some_and(|side| {
            side_needs_immediate_work(
                side.recv_pending,
                side.event_pending,
                side.output_pending,
                side.write_blocked,
                side.outbound.is_empty(),
            )
        }) || self.caller.as_ref().is_some_and(|side| {
            side_needs_immediate_work(
                side.recv_pending,
                side.event_pending,
                side.output_pending,
                side.write_blocked,
                side.outbound.is_empty(),
            )
        });
        if continuation {
            // A continuation is deliberately one bounded visit, then a
            // scheduler handoff. This keeps a permanently busy socket from
            // spinning in a single task while still draining it promptly.
            tokio::task::yield_now().await;
        } else {
            tokio::select! {
                result = readable_or_pending(self.listener.as_ref().map(|side| &side.socket)) => {
                    result?;
                }
                result = readable_or_pending(self.caller.as_ref().map(|side| &side.socket)) => {
                    result?;
                }
                result = writable_or_pending(
                    self.listener.as_ref().map(|side| &side.socket),
                    self.listener.as_ref().is_some_and(|side| !side.outbound.is_empty()),
                ) => {
                    result?;
                }
                result = writable_or_pending(
                    self.caller.as_ref().map(|side| &side.socket),
                    self.caller.as_ref().is_some_and(|side| !side.outbound.is_empty()),
                ) => {
                    result?;
                }
                () = tokio::time::sleep(timeout) => {}
            }
        }
        let recv_now = now();
        if let Some(side) = self.listener.as_mut() {
            let (peers, admission, telemetry) = (&mut side.peers, &side.admission, &side.telemetry);
            let report = drain_readable(
                &side.socket,
                &mut side.recv_batch,
                side.transport.recv_budget,
                |addr, data| {
                    let Some(peer) = addr else { return };
                    let _ = peers.admit(peer, data, recv_now, admission, 0, 1, telemetry);
                },
            )?;
            side.recv_pending = receive_continuation(report, side.transport.recv_budget);
        }
        if let Some(side) = self.caller.as_mut() {
            let callers = side.callers.table_mut();
            let report = drain_readable(
                &side.socket,
                &mut side.recv_batch,
                side.transport.recv_budget,
                |addr, data| {
                    let Some(peer) = addr else { return };
                    let _ = callers.feed(peer, data, recv_now);
                },
            )?;
            side.recv_pending = receive_continuation(report, side.transport.recv_budget);
        }
        self.drive(now(), caller_budget)
    }

    /// Fire due timers and send every pending protocol output on both
    /// sides. Synchronous: every send is a single non-blocking `try_io`
    /// attempt, exactly like `mio_transport::Owner::drive`. Ordinarily
    /// called only from [`Self::run_once`]; exposed directly for an
    /// application that wants to drive output on its own schedule (a
    /// dedicated flush before shutdown, say) without waiting on readiness.
    pub fn drive(
        &mut self,
        now: Timestamp,
        caller_budget: crate::OutputDrainBudget,
    ) -> io::Result<crate::OutputDrainStatus> {
        let mut status = crate::OutputDrainStatus::Drained;
        let mut remaining = caller_budget;
        if let Some(side) = self.listener.as_mut() {
            status = drive_listener_side(side, now, &mut remaining, status)?;
        }
        if let Some(side) = self.caller.as_mut() {
            status =
                drive_caller_side(side, &mut self.expired_callers, now, &mut remaining, status)?;
        }
        if (caller_budget.max_actions > 0 && remaining.max_actions == 0)
            || (caller_budget.max_packets > 0 && remaining.max_packets == 0)
            || (caller_budget.max_bytes > 0 && remaining.max_bytes == 0)
        {
            status = status.combine(crate::OutputDrainStatus::BudgetExhausted);
        }
        Ok(status)
    }

    /// Drain admitted-peer lifecycle/data events for the application.
    pub fn poll_listener_events(&mut self, out: &mut Vec<crate::AdmissionEvent>) {
        out.clear();
        let Some(side) = self.listener.as_mut() else {
            return;
        };
        side.peers
            .poll_events_bounded(side.transport.output_drain.max_actions, out);
        side.event_pending = side.peers.has_pending_events();
    }

    /// Drain protocol events (A05) for every direct outbound session --
    /// the caller-side counterpart to [`Self::poll_listener_events`].
    pub fn poll_caller_events(&mut self, out: &mut Vec<crate::CallerEvent>) {
        out.clear();
        let Some(side) = self.caller.as_mut() else {
            return;
        };
        side.callers
            .table_mut()
            .poll_events_bounded(side.transport.output_drain.max_actions, out);
        side.event_pending = side.callers.table().has_pending_events();
    }

    /// Drain bounded caller-pool lifecycle outcomes. A queued request's
    /// [`crate::PoolRequestId`] must be observed here to correlate its later
    /// admission, expiry, failure, or cancellation with the original call.
    pub fn poll_caller_pool_events(&mut self, out: &mut Vec<crate::PoolEvent>) {
        out.clear();
        let Some(side) = self.caller.as_mut() else {
            return;
        };
        side.callers
            .poll_outcomes_bounded(side.transport.output_drain.max_actions, out);
    }

    /// Steady-state handle for one admitted peer: send, stats, orderly close.
    pub fn listener_peer_mut(
        &mut self,
        id: crate::LogicalPeerId,
    ) -> Option<crate::LogicalPeerMut<'_>> {
        self.listener.as_mut()?.peers.logical_peer_mut(&id)
    }

    /// Steady-state handle for one outbound session: send, stats, orderly close.
    pub fn caller_mut(
        &mut self,
        id: crate::LogicalCallerId,
    ) -> Option<crate::LogicalCallerMut<'_>> {
        self.caller
            .as_mut()?
            .callers
            .table_mut()
            .logical_caller_mut(&id)
    }

    /// Atomically retire one admitted peer, reclaiming its table entry.
    pub fn remove_listener_peer(
        &mut self,
        id: crate::LogicalPeerId,
    ) -> Option<crate::RemovedLogicalPeer> {
        self.listener.as_mut()?.peers.remove(id)
    }

    /// Atomically retire one outbound session.
    pub fn remove_caller(
        &mut self,
        id: crate::LogicalCallerId,
    ) -> Option<crate::RemovedLogicalCaller> {
        self.caller.as_mut()?.callers.remove(id)
    }

    /// Return and clear caller attempts retired by the bounded pool deadline.
    /// A facade uses this edge-triggered list to fail cancelled/expired
    /// `connect()` futures and reclaim their routing state.
    pub fn drain_expired_callers(&mut self, out: &mut Vec<crate::LogicalCallerId>) {
        out.clear();
        out.extend(self.expired_callers.drain(..));
    }

    /// The listener socket's bound local address, once [`Self::listen`]
    /// has been called -- useful when binding an ephemeral port (`:0`).
    #[must_use]
    pub fn listener_local_addr(&self) -> Option<SocketAddr> {
        self.listener.as_ref()?.socket.local_addr().ok()
    }

    /// A snapshot of admission-path counters for the listener side, once
    /// [`Self::listen`] has been called.
    #[must_use]
    pub fn listener_telemetry(&self) -> Option<crate::IngressTelemetrySnapshot> {
        Some(self.listener.as_ref()?.telemetry.snapshot())
    }

    /// Effective, currently-observable caller-pool state (A04).
    #[must_use]
    pub fn caller_pool_stats(&self) -> Option<crate::CallerPoolStats> {
        Some(self.caller.as_ref()?.callers.stats())
    }

    /// Number of direct peers currently in the listener-side table -- both
    /// half-open and established -- once [`Self::listen`] has been called.
    #[must_use]
    pub fn listener_peer_count(&self) -> Option<usize> {
        Some(self.listener.as_ref()?.peers.len())
    }

    /// Number of direct logical callers currently in the caller-side
    /// table -- both in-flight and established -- once [`Self::connect`]
    /// has been called at least once.
    #[must_use]
    pub fn caller_count(&self) -> Option<usize> {
        Some(self.caller.as_ref()?.callers.table().len())
    }

    /// Microseconds until either side's next due timer, for sizing
    /// [`Self::run_once`]'s timeout.
    ///
    /// Pending receive, event, and output work returns zero so the next
    /// [`Self::run_once`] call performs a bounded immediate pass. Otherwise
    /// the result is the minimum of the caller-pool, listener-idle, and
    /// protocol timer deadlines, capped by `default_us`.
    #[must_use]
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        let mut wait = default_us;
        if let Some(side) = self.listener.as_mut() {
            match tokio_listener_time_until_deadline(side, now) {
                None => return 0,
                Some(side_wait) => wait = wait.min(side_wait),
            }
        }
        if let Some(side) = self.caller.as_mut() {
            match tokio_caller_time_until_deadline(side, now) {
                None => return 0,
                Some(side_wait) => wait = wait.min(side_wait),
            }
        }
        wait
    }
}

fn tokio_listener_time_until_deadline(side: &mut OwnerListenerSide, now: Timestamp) -> Option<u64> {
    if side.recv_pending || side.event_pending {
        return None;
    }
    let mut wait = side
        .peers
        .time_until_idle_deadline(now, side.idle_timeout, u64::MAX);
    if side.write_blocked {
        return Some(wait);
    }
    if side.output_pending || !side.outbound.is_empty() || side.peers.has_pending_output(now) {
        return None;
    }
    wait = wait.min(side.peers.time_until_next_deadline(now, u64::MAX));
    Some(wait)
}

fn tokio_caller_time_until_deadline(side: &mut OwnerCallerSide, now: Timestamp) -> Option<u64> {
    if side.recv_pending || side.event_pending {
        return None;
    }
    let wait = side.callers.time_until_next_deadline(now, u64::MAX);
    if side.write_blocked {
        return Some(wait);
    }
    if side.output_pending
        || !side.outbound.is_empty()
        || side.callers.table().has_pending_output(now)
    {
        return None;
    }
    Some(wait)
}

// ---------------------------------------------------------------------------
// Facade: a managed, ergonomic async wrapper around Owner (A05)
// ---------------------------------------------------------------------------

/// Why a [`Facade`]/[`Session`] operation failed.
#[derive(Debug)]
pub enum FacadeError {
    /// The driver task is no longer running: it was shut down (every
    /// [`Facade`] and [`Session`] handle dropped), or [`Owner::run_once`]
    /// returned a real I/O error and the task stopped rather than spin on
    /// a socket that may never recover (checkpoint 2's "driver failure"
    /// documented outcome). Every [`Session`]'s `recv()` also resolves to
    /// `None` once this happens, since its inbound channel's sender is
    /// dropped along with the task.
    DriverGone,
    /// The pool was at `max_in_flight` capacity. [`Facade::connect`] does
    /// not wait for a queued permit -- see its own doc comment.
    PoolFull,
    /// The finite command, pending-send, or inbound application queue is
    /// full. Callers can retry after driving/consuming the affected session.
    QueueFull,
    /// F03: this send was still waiting for its destination to accept it
    /// (pacing/window not yet open) when it aged past this crate's pending-
    /// send age bound and was dropped -- an explicit, per-destination
    /// expiry, not a silent stall or an unbounded wait.
    Expired,
    Build(crate::RuntimeBuildError),
    Protocol(srt_proto::Error),
}

impl std::fmt::Display for FacadeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DriverGone => write!(f, "the Facade driver task is no longer running"),
            Self::PoolFull => write!(f, "the caller pool is at max_in_flight capacity"),
            Self::QueueFull => write!(f, "the Facade queue is full"),
            Self::Expired => write!(
                f,
                "this send aged out waiting for its destination to accept it"
            ),
            Self::Build(error) => error.fmt(f),
            Self::Protocol(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for FacadeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::DriverGone | Self::PoolFull | Self::QueueFull | Self::Expired => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum SessionTarget {
    Listener(crate::LogicalPeerId),
    Caller(crate::LogicalCallerId),
}

const FACADE_COMMAND_CAPACITY: usize = 1024;
const FACADE_COMMAND_BYTES: usize = 8 * 1024 * 1024;
const SESSION_COMMAND_CAPACITY: usize = 64;
const SESSION_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_QUOTA_CAS_RETRIES: usize = 16;
/// Fixed per-command byte charge covering a `Command`'s own overhead,
/// added on top of any variable-size payload it carries (a `Send`'s
/// payload) or used alone for commands with none (`Connect`, the
/// telemetry getters) -- without it a flood of tiny commands could still
/// exceed `COMMAND_QUEUE_ITEMS`-style bounds in spirit while reporting
/// almost no byte usage at all.
const COMMAND_OVERHEAD_CHARGE: usize = 32;
const FACADE_ACCEPT_CAPACITY: usize = 1024;
const SESSION_INBOUND_CAPACITY: usize = 1024;
const SESSION_INBOUND_BYTES: usize = 8 * 1024 * 1024;
const SESSION_PENDING_SENDS: usize = 1024;
const SESSION_PENDING_BYTES: usize = 8 * 1024 * 1024;
/// F03: an aggregate ceiling on top of each destination's own bound above
/// -- the per-destination bound alone stops one destination from starving
/// another's headroom, but this Facade's own total memory use still needs
/// a backstop independent of how many destinations happen to be
/// simultaneously backlogged (this project's target dimension is on the
/// order of hundreds of destinations per shard, not thousands each maxed
/// out at once).
const FACADE_PENDING_SENDS_TOTAL: usize = 16 * 1024;
const FACADE_PENDING_BYTES_TOTAL: usize = 64 * 1024 * 1024;
/// F03: how long a send may wait in [`PendingSends`] for its destination's
/// pacing/window to open before it is dropped as [`FacadeError::Expired`]
/// -- an explicit bound so a destination that never recovers cannot hold
/// unadmitted application data forever, distinct from (and enforced far
/// earlier than) any protocol-level TLPKTDROP/ARQ retirement.
const SESSION_PENDING_MAX_AGE: Duration = Duration::from_secs(5);
const DRIVER_COMMAND_QUANTUM: usize = 32;
const SHUTDOWN_MAX_TICKS: usize = 256;
const SHUTDOWN_MAX_TIME: Duration = Duration::from_millis(100);

struct CommandCharge {
    used: Arc<AtomicUsize>,
    amount: usize,
    session: Option<Arc<SessionControl>>,
}

impl Drop for CommandCharge {
    fn drop(&mut self) {
        self.used.fetch_sub(self.amount, Ordering::AcqRel);
        if let Some(session) = &self.session {
            session
                .command_bytes
                .fetch_sub(self.amount, Ordering::AcqRel);
            session.command_items.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn reserve_command_bytes(
    used: &Arc<AtomicUsize>,
    amount: usize,
) -> Result<CommandCharge, FacadeError> {
    if amount > FACADE_COMMAND_BYTES {
        return Err(FacadeError::QueueFull);
    }
    for _ in 0..MAX_QUOTA_CAS_RETRIES {
        let current = used.load(Ordering::Acquire);
        if current > FACADE_COMMAND_BYTES.saturating_sub(amount) {
            return Err(FacadeError::QueueFull);
        }
        if used
            .compare_exchange_weak(
                current,
                current + amount,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return Ok(CommandCharge {
                used: Arc::clone(used),
                amount,
                session: None,
            });
        }
    }
    Err(FacadeError::QueueFull)
}

fn reserve_session_command(
    used: &Arc<AtomicUsize>,
    session: &Arc<SessionControl>,
    amount: usize,
) -> Result<CommandCharge, FacadeError> {
    let mut charge = reserve_command_bytes(used, amount)?;
    let mut item_reserved = false;
    for _ in 0..MAX_QUOTA_CAS_RETRIES {
        let items = session.command_items.load(Ordering::Acquire);
        if items >= SESSION_COMMAND_CAPACITY {
            return Err(FacadeError::QueueFull);
        }
        if session
            .command_items
            .compare_exchange_weak(items, items + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            item_reserved = true;
            break;
        }
    }
    if !item_reserved {
        return Err(FacadeError::QueueFull);
    }
    let mut bytes_reserved = false;
    for _ in 0..MAX_QUOTA_CAS_RETRIES {
        let bytes = session.command_bytes.load(Ordering::Acquire);
        if bytes > SESSION_COMMAND_BYTES.saturating_sub(amount) {
            session.command_items.fetch_sub(1, Ordering::AcqRel);
            return Err(FacadeError::QueueFull);
        }
        if session
            .command_bytes
            .compare_exchange_weak(bytes, bytes + amount, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            bytes_reserved = true;
            break;
        }
    }
    if !bytes_reserved {
        session.command_items.fetch_sub(1, Ordering::AcqRel);
        return Err(FacadeError::QueueFull);
    }
    charge.session = Some(Arc::clone(session));
    Ok(charge)
}

struct SessionControl {
    dropped: AtomicBool,
    close_requested: AtomicBool,
    disconnect_sent: AtomicBool,
    closed: AtomicBool,
    command_items: AtomicUsize,
    command_bytes: AtomicUsize,
    /// Ticks [`reap_session_controls`] has seen this session as
    /// dropped-and-already-disconnect-sent, without yet force-removing it.
    /// Counting real driver-loop ticks (rather than this function calling
    /// `Owner::drive` itself to force one within the same pass) sidesteps
    /// a reproducible regression: an extra `drive()` call from inside this
    /// scan broke `a_closed_sessions_table_entry_is_actually_reclaimed`
    /// (the exact mechanism wasn't pinned down, but the effect was
    /// consistent and immediate) even though every other route to
    /// `Owner::drive` is safe.
    reap_grace_ticks: std::sync::atomic::AtomicU32,
}

impl SessionControl {
    fn new() -> Self {
        Self {
            dropped: AtomicBool::new(false),
            close_requested: AtomicBool::new(false),
            disconnect_sent: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            command_items: AtomicUsize::new(0),
            command_bytes: AtomicUsize::new(0),
            reap_grace_ticks: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn is_unavailable(&self) -> bool {
        self.dropped.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire)
    }
}

struct InboundItem {
    payload: srt_proto::Bytes,
    source_time: Timestamp,
    bytes: Arc<AtomicUsize>,
}

impl Drop for InboundItem {
    fn drop(&mut self) {
        self.bytes.fetch_sub(self.payload.len(), Ordering::AcqRel);
    }
}

impl InboundItem {
    fn into_message(mut self) -> ReceivedMessage {
        let payload = std::mem::replace(&mut self.payload, srt_proto::Bytes::new());
        self.bytes.fetch_sub(payload.len(), Ordering::AcqRel);
        ReceivedMessage {
            payload,
            source_time: self.source_time,
        }
    }
}

enum InboxSend {
    Sent,
    Full,
    Closed,
}

struct SessionInbox {
    tx: tokio::sync::mpsc::Sender<InboundItem>,
    bytes: Arc<AtomicUsize>,
    control: Arc<SessionControl>,
}

impl SessionInbox {
    fn new(control: Arc<SessionControl>) -> (Self, tokio::sync::mpsc::Receiver<InboundItem>) {
        let (tx, rx) = tokio::sync::mpsc::channel(SESSION_INBOUND_CAPACITY);
        let bytes = Arc::new(AtomicUsize::new(0));
        (Self { tx, bytes, control }, rx)
    }

    fn try_send(&self, payload: srt_proto::Bytes, source_time: Timestamp) -> InboxSend {
        if self.control.is_unavailable() {
            return InboxSend::Closed;
        }
        let length = payload.len();
        if length > SESSION_INBOUND_BYTES {
            return InboxSend::Full;
        }
        let mut reserved = false;
        for _ in 0..MAX_QUOTA_CAS_RETRIES {
            let current = self.bytes.load(Ordering::Acquire);
            if current > SESSION_INBOUND_BYTES.saturating_sub(length) {
                return InboxSend::Full;
            }
            if self
                .bytes
                .compare_exchange_weak(
                    current,
                    current + length,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                reserved = true;
                break;
            }
        }
        if !reserved {
            return InboxSend::Full;
        }
        let item = InboundItem {
            payload,
            source_time,
            bytes: Arc::clone(&self.bytes),
        };
        match self.tx.try_send(item) {
            Ok(()) => InboxSend::Sent,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => InboxSend::Full,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => InboxSend::Closed,
        }
    }
}

struct PendingSend {
    payload: Vec<u8>,
    queued_at: Timestamp,
    reply: tokio::sync::oneshot::Sender<Result<(), FacadeError>>,
}

/// One destination's own backlog: `SESSION_PENDING_SENDS`/`_BYTES` are
/// enforced against this queue alone (`items`/`bytes` below), never against
/// every destination's combined total -- F03's "no shared owner awaits one
/// destination's queue capacity": a single stalled destination filling its
/// own bound must leave every other destination's own headroom untouched.
#[derive(Default)]
struct DestinationQueue {
    items: VecDeque<PendingSend>,
    bytes: usize,
}

#[derive(Default)]
struct PendingSends {
    by_target: std::collections::HashMap<SessionTarget, DestinationQueue>,
    /// Combined totals across every destination -- kept in lockstep with
    /// `by_target`'s own per-destination counts/bytes by every mutating
    /// method below, so [`Self::has_capacity`] never has to re-sum the map.
    total_items: usize,
    total_bytes: usize,
    ready: VecDeque<SessionTarget>,
    ready_queued: std::collections::HashSet<SessionTarget>,
    deadlines: crate::DueIndex<SessionTarget>,
}

impl PendingSends {
    fn has_capacity(&self, target: SessionTarget, payload_len: usize) -> bool {
        let queue = self.by_target.get(&target);
        let items = queue.map_or(0, |q| q.items.len());
        let bytes = queue.map_or(0, |q| q.bytes);
        items < SESSION_PENDING_SENDS
            && bytes.saturating_add(payload_len) <= SESSION_PENDING_BYTES
            && self.total_items < FACADE_PENDING_SENDS_TOTAL
            && self.total_bytes.saturating_add(payload_len) <= FACADE_PENDING_BYTES_TOTAL
    }

    /// A target with anything already queued must stay queued: sending a
    /// fresh command straight through the moment pacing allows it, while an
    /// earlier payload for the same target is still waiting in `by_target`,
    /// would reorder that earlier payload behind this one on the wire.
    fn has_pending(&self, target: SessionTarget) -> bool {
        self.by_target.contains_key(&target)
    }

    /// Checked via [`Self::has_capacity`] (both the per-destination and the
    /// aggregate bound) before touching `by_target` at all, so a rejected
    /// push never leaves a spurious empty [`DestinationQueue`] behind. Owns
    /// `reply` outright and resolves it itself either way -- a caller never
    /// needs a second `QueueFull` reply path of its own.
    fn push(
        &mut self,
        target: SessionTarget,
        payload: Vec<u8>,
        queued_at: Timestamp,
        reply: tokio::sync::oneshot::Sender<Result<(), FacadeError>>,
    ) {
        if !self.has_capacity(target, payload.len()) {
            let _ = reply.send(Err(FacadeError::QueueFull));
            return;
        }
        let len = payload.len();
        let queue = self.by_target.entry(target).or_default();
        let was_empty = queue.items.is_empty();
        queue.bytes = queue.bytes.saturating_add(len);
        queue.items.push_back(PendingSend {
            payload,
            queued_at,
            reply,
        });
        self.total_items = self.total_items.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(len);
        if was_empty {
            self.index_front(target, SESSION_PENDING_MAX_AGE);
            self.enqueue_ready(target);
        }
    }

    fn pop(&mut self, target: SessionTarget) -> Option<PendingSend> {
        let queue = self.by_target.get_mut(&target)?;
        let pending = queue.items.pop_front()?;
        queue.bytes = queue.bytes.saturating_sub(pending.payload.len());
        if queue.items.is_empty() {
            self.by_target.remove(&target);
            self.deadlines.remove(&target);
            self.ready_queued.remove(&target);
        } else {
            self.index_front(target, SESSION_PENDING_MAX_AGE);
            self.enqueue_ready(target);
        }
        self.total_items = self.total_items.saturating_sub(1);
        self.total_bytes = self.total_bytes.saturating_sub(pending.payload.len());
        Some(pending)
    }

    fn enqueue_ready(&mut self, target: SessionTarget) {
        if self.by_target.contains_key(&target) && self.ready_queued.insert(target) {
            self.ready.push_back(target);
        }
    }

    fn index_front(&mut self, target: SessionTarget, max_age: Duration) {
        let Some(front) = self
            .by_target
            .get(&target)
            .and_then(|queue| queue.items.front())
        else {
            self.deadlines.remove(&target);
            return;
        };
        let max_age_us = u64::try_from(max_age.as_micros()).unwrap_or(u64::MAX);
        self.deadlines.set(
            target,
            front.queued_at.add_micros(max_age_us.saturating_add(1)),
        );
    }

    /// Pop at most `quantum` deduplicated ready destinations without
    /// scanning the destination map. A destination still backlogged after
    /// its visit is requeued by [`Self::pop`] or [`Self::enqueue_ready`].
    fn drain_targets(&mut self, quantum: usize) -> Vec<SessionTarget> {
        let mut targets = Vec::with_capacity(quantum.min(self.ready.len()));
        while targets.len() < quantum {
            let Some(target) = self.ready.pop_front() else {
                break;
            };
            if !self.ready_queued.remove(&target) || !self.by_target.contains_key(&target) {
                continue;
            }
            targets.push(target);
        }
        targets
    }

    fn fail_target(&mut self, target: SessionTarget) {
        let Some(mut queue) = self.by_target.remove(&target) else {
            return;
        };
        self.deadlines.remove(&target);
        self.ready_queued.remove(&target);
        self.total_items = self.total_items.saturating_sub(queue.items.len());
        self.total_bytes = self.total_bytes.saturating_sub(queue.bytes);
        while let Some(pending) = queue.items.pop_front() {
            let _ = pending
                .reply
                .send(Err(FacadeError::Protocol(session_gone_error())));
        }
    }

    /// F03 checkpoint 2: drop (and report, via each send's own reply
    /// channel) any complete unadmitted message that has waited longer
    /// than `max_age` for its destination to accept it. Oldest-first per
    /// destination (`items` is FIFO), so a destination that recovers mid-
    /// scan keeps whatever is still fresh enough once its stale prefix is
    /// gone.
    fn expire_stale(&mut self, now: Timestamp, max_age: Duration, max_actions: usize) {
        let max_age_us = u64::try_from(max_age.as_micros()).unwrap_or(u64::MAX);
        let mut due = Vec::new();
        for _ in 0..max_actions {
            self.deadlines.pop_due_bounded(now, 1, &mut due);
            let Some(target) = due.pop() else {
                if !self.deadlines.has_due(now) {
                    break;
                }
                continue;
            };
            let stale = self.by_target.get(&target).is_some_and(|queue| {
                queue.items.front().is_some_and(|front| {
                    now.as_micros().saturating_sub(front.queued_at.as_micros()) > max_age_us
                })
            });
            if !stale {
                self.index_front(target, max_age);
                continue;
            }
            if let Some(expired) = self.pop(target) {
                let _ = expired.reply.send(Err(FacadeError::Expired));
            }
        }
    }
}

enum Command {
    Connect {
        config: Box<crate::CallerConfig>,
        reply: tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
        _charge: CommandCharge,
    },
    Send {
        target: SessionTarget,
        payload: Vec<u8>,
        queued_at: Timestamp,
        reply: tokio::sync::oneshot::Sender<Result<(), FacadeError>>,
        _charge: CommandCharge,
    },
    Disconnect {
        target: SessionTarget,
    },
    ListenerTelemetry {
        reply: tokio::sync::oneshot::Sender<Option<crate::IngressTelemetrySnapshot>>,
        _charge: CommandCharge,
    },
    CallerPoolStats {
        reply: tokio::sync::oneshot::Sender<Option<crate::CallerPoolStats>>,
        _charge: CommandCharge,
    },
    ListenerPeerCount {
        reply: tokio::sync::oneshot::Sender<Option<usize>>,
        _charge: CommandCharge,
    },
    CallerCount {
        reply: tokio::sync::oneshot::Sender<Option<usize>>,
        _charge: CommandCharge,
    },
}

/// One payload delivered by [`Session::recv`], paired with when the sender
/// originally queued it (F01: preserving source age through relay APIs).
/// `source_time` is in this session's own local clock domain -- comparable
/// directly against a `Timestamp` this same process reads via `now()`, not
/// against a value from a different connection or process. A relay
/// forwarding this payload onward must carry `source_time` (or an "age so
/// far" derived from it) as its own application-level metadata: the new
/// connection it re-sends on has its own, unrelated wire timestamp epoch.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub payload: srt_proto::Bytes,
    pub source_time: Timestamp,
}

impl ReceivedMessage {
    /// How long ago this message's source time was, relative to `now` (both
    /// in the same connection's clock domain). Saturates to zero rather
    /// than going negative if `now` is somehow earlier than `source_time`
    /// (e.g. a caller comparing against a stale `now` reading).
    #[must_use]
    pub fn age(&self, now: Timestamp) -> std::time::Duration {
        std::time::Duration::from_micros(
            now.as_micros().saturating_sub(self.source_time.as_micros()),
        )
    }
}

/// One admitted or originated SRT session (A05), obtained from
/// [`Facade::accept`] or [`Facade::connect`].
///
/// `recv()` resolves to `None` once the session's `Disconnected` event has
/// been observed *and* every payload already buffered before that has been
/// delivered -- not the instant the connection starts closing. Each
/// session's inbound channel has an item and byte bound. A full queue is
/// isolated to that session and causes it to close; the driver never awaits a
/// slow consumer while servicing other sockets.
pub struct Session {
    target: SessionTarget,
    commands: tokio::sync::mpsc::Sender<Command>,
    command_bytes: Arc<AtomicUsize>,
    control: Arc<SessionControl>,
    inbound: tokio::sync::mpsc::Receiver<InboundItem>,
    start: std::time::Instant,
}

impl Session {
    /// The current time in this session's own driver's clock domain --
    /// the same one every [`ReceivedMessage::source_time`] this `Session`
    /// produces is expressed in (F01), and the same value
    /// [`Facade::now`] would return. A `Session` is designed to outlive
    /// its `Facade` (dropping the `Facade` alone does not end the driver
    /// task while any `Session` remains), so `age()` needs this rather
    /// than requiring the application to keep the `Facade` around just to
    /// call `now()`.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        Timestamp::from_micros(self.start.elapsed().as_micros() as u64)
    }

    /// Send one payload. Resolves once the driver task has actually
    /// attempted the send (not merely queued the request), so a
    /// [`FacadeError::Protocol`] reliably reflects this specific call, not
    /// a stale error from an earlier one.
    pub async fn send(&self, payload: impl Into<Vec<u8>>) -> Result<(), FacadeError> {
        let queued_at = self.now();
        let payload = payload.into();
        let charge = reserve_session_command(
            &self.command_bytes,
            &self.control,
            payload.len().saturating_add(COMMAND_OVERHEAD_CHARGE),
        )?;
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(Command::Send {
                target: self.target,
                payload,
                queued_at,
                reply,
                _charge: charge,
            })
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => FacadeError::QueueFull,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => FacadeError::DriverGone,
            })?;
        reply_rx.await.map_err(|_| FacadeError::DriverGone)?
    }

    /// The next payload this session received, in order, or `None` once
    /// the session has closed and every already-buffered payload has been
    /// delivered.
    pub async fn recv(&mut self) -> Option<ReceivedMessage> {
        self.inbound.recv().await.map(InboundItem::into_message)
    }

    /// Start an orderly close. Fire-and-forget: does not wait for the
    /// close to complete -- await [`Self::recv`] returning `None`, or just
    /// drop this `Session`, to know it eventually has.
    pub fn close(&self) {
        if !self.control.close_requested.swap(true, Ordering::AcqRel) {
            let _ = self.commands.try_send(Command::Disconnect {
                target: self.target,
            });
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.control.dropped.store(true, Ordering::Release);
        // This is a best-effort fast path. If a bounded command queue is
        // full, the driver's control scan below performs the same reclaim
        // without introducing an unbounded drop queue.
        if !self.control.close_requested.swap(true, Ordering::AcqRel) {
            let _ = self.commands.try_send(Command::Disconnect {
                target: self.target,
            });
        }
    }
}

fn session_gone_error() -> srt_proto::Error {
    srt_proto::Error::with_reason(
        srt_proto::ErrorKind::InvalidState,
        "session no longer exists",
    )
}

/// Reasons a pending [`Command::Connect`] never gets a session: the
/// connection failed before ever reaching `Connected` (rejected handshake,
/// timeout, ...), or the driver is stopping and can no longer wait for it.
fn connect_failed_error() -> srt_proto::Error {
    srt_proto::Error::with_reason(
        srt_proto::ErrorKind::InvalidState,
        "connection did not reach Connected",
    )
}

fn handle_command(
    owner: &mut Owner,
    command: Command,
    now: Timestamp,
    pending_connects: &mut std::collections::HashMap<
        crate::LogicalCallerId,
        tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    >,
    connect_checks: &mut VecDeque<crate::LogicalCallerId>,
    pending_sends: &mut PendingSends,
) {
    match command {
        Command::Connect { config, reply, .. } => {
            handle_connect_command(owner, &config, reply, now, pending_connects, connect_checks);
        }
        Command::Send {
            target,
            payload,
            queued_at,
            reply,
            ..
        } => {
            handle_send_command(owner, target, payload, queued_at, reply, now, pending_sends);
        }
        Command::Disconnect { target } => match target {
            SessionTarget::Listener(id) => {
                if let Some(mut peer) = owner.listener_peer_mut(id) {
                    peer.disconnect(now);
                }
            }
            SessionTarget::Caller(id) => {
                if let Some(mut caller) = owner.caller_mut(id) {
                    caller.disconnect(now);
                }
            }
        },
        Command::ListenerTelemetry { reply, .. } => {
            let _ = reply.send(owner.listener_telemetry());
        }
        Command::CallerPoolStats { reply, .. } => {
            let _ = reply.send(owner.caller_pool_stats());
        }
        Command::ListenerPeerCount { reply, .. } => {
            let _ = reply.send(owner.listener_peer_count());
        }
        Command::CallerCount { reply, .. } => {
            let _ = reply.send(owner.caller_count());
        }
    }
}

fn handle_connect_command(
    owner: &mut Owner,
    config: &crate::CallerConfig,
    reply: tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    now: Timestamp,
    pending_connects: &mut std::collections::HashMap<
        crate::LogicalCallerId,
        tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    >,
    connect_checks: &mut VecDeque<crate::LogicalCallerId>,
) {
    if reply.is_closed() {
        return;
    }
    // The reply is deliberately not sent here: an "ergonomic connect"
    // should resolve once the handshake actually completes, not merely
    // once admitted, or `send`/`recv` on a freshly returned `Session`
    // could race the handshake still in flight. Registered here, fulfilled
    // once this id's `Connected` (or `Disconnected`, on failure) event is
    // observed by the caller of `handle_command`.
    match owner.connect(config, now) {
        Ok(crate::PoolOutcome::Admitted(id)) => {
            pending_connects.insert(id, reply);
            connect_checks.push_back(id);
        }
        Ok(crate::PoolOutcome::Queued(_)) | Ok(crate::PoolOutcome::Full) => {
            let _ = reply.send(Err(FacadeError::PoolFull));
        }
        Err(error) => {
            let _ = reply.send(Err(FacadeError::Build(error)));
        }
    }
}

fn handle_send_command(
    owner: &mut Owner,
    target: SessionTarget,
    payload: Vec<u8>,
    queued_at: Timestamp,
    reply: tokio::sync::oneshot::Sender<Result<(), FacadeError>>,
    now: Timestamp,
    pending_sends: &mut PendingSends,
) {
    if reply.is_closed() {
        return;
    }
    let can_send = !pending_sends.has_pending(target)
        && match target {
            SessionTarget::Listener(id) => owner
                .listener_peer_mut(id)
                .is_some_and(|mut peer| peer.can_send_with_pacing(now)),
            SessionTarget::Caller(id) => owner
                .caller_mut(id)
                .is_some_and(|mut caller| caller.can_send_with_pacing(now)),
        };
    if !can_send {
        // `push` checks this target's own backlog and the Facade-wide
        // aggregate (F03) and resolves `reply` itself either way -- a
        // stalled destination can exhaust neither a different, healthy
        // destination's own headroom nor drive the whole Facade past its
        // shared safety ceiling.
        pending_sends.push(target, payload, queued_at, reply);
        return;
    }
    let result = match target {
        SessionTarget::Listener(id) => owner
            .listener_peer_mut(id)
            .ok_or_else(session_gone_error)
            .and_then(|mut peer| peer.send(&payload, now).map(|_| ())),
        SessionTarget::Caller(id) => owner
            .caller_mut(id)
            .ok_or_else(session_gone_error)
            .and_then(|mut caller| caller.send(&payload, now).map(|_| ())),
    };
    let _ = reply.send(result.map_err(FacadeError::Protocol));
}

fn drive_pending_sends(owner: &mut Owner, pending: &mut PendingSends, now: Timestamp) {
    let targets = pending.drain_targets(DRIVER_COMMAND_QUANTUM);
    for target in targets {
        let can_send = match target {
            SessionTarget::Listener(id) => owner
                .listener_peer_mut(id)
                .is_some_and(|mut peer| peer.can_send_with_pacing(now)),
            SessionTarget::Caller(id) => owner
                .caller_mut(id)
                .is_some_and(|mut caller| caller.can_send_with_pacing(now)),
        };
        if !can_send {
            pending.enqueue_ready(target);
            continue;
        }
        let Some(pending_send) = pending.pop(target) else {
            continue;
        };
        if pending_send.reply.is_closed() {
            continue;
        }
        let result = match target {
            SessionTarget::Listener(id) => owner
                .listener_peer_mut(id)
                .ok_or_else(session_gone_error)
                .and_then(|mut peer| peer.send(&pending_send.payload, now).map(|_| ())),
            SessionTarget::Caller(id) => owner
                .caller_mut(id)
                .ok_or_else(session_gone_error)
                .and_then(|mut caller| caller.send(&pending_send.payload, now).map(|_| ())),
        };
        let _ = pending_send
            .reply
            .send(result.map_err(FacadeError::Protocol));
    }
}

fn remove_session_state(
    target: SessionTarget,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    match target {
        SessionTarget::Listener(id) => {
            listener_inboxes.remove(&id);
        }
        SessionTarget::Caller(id) => {
            caller_inboxes.remove(&id);
        }
    }
    if let Some(control) = controls.remove(&target) {
        control.closed.store(true, Ordering::Release);
    }
    pending_sends.fail_target(target);
}

fn reap_session_controls(
    owner: &mut Owner,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    pending_sends: &mut PendingSends,
    control_checks: &mut VecDeque<SessionTarget>,
    now: Timestamp,
) {
    // A grace tick is one driver pass, not one entry in this pass. Requeuing
    // the same control inside the loop would otherwise consume all three
    // grace ticks immediately and force-remove a just-closed session before
    // its queued SHUTDOWN can be driven.
    let checks = control_checks.len().min(DRIVER_COMMAND_QUANTUM);
    for _ in 0..checks {
        let Some(target) = control_checks.pop_front() else {
            break;
        };
        let action = controls.get(&target).and_then(|control| {
            let dropped = control.dropped.load(Ordering::Acquire);
            let close_requested = control.close_requested.load(Ordering::Acquire);
            if dropped && !close_requested {
                return Some(false);
            }
            if close_requested {
                let already_sent = control.disconnect_sent.swap(true, Ordering::AcqRel);
                if !already_sent {
                    return Some(true);
                }
                // An explicit close means the application has elected to
                // stop using this session; a peer may never answer the
                // SHUTDOWN (and waiting for the protocol timeout would pin
                // this entry and its buffered bytes). Force reclaim after a
                // few real driver ticks, whether the handle is subsequently
                // dropped or still held while its recv() observes closure.
                // Counting driver passes rather than requeue iterations keeps
                // this grace period from being consumed in one scan.
                let ticks = control.reap_grace_ticks.fetch_add(1, Ordering::AcqRel);
                if ticks >= REAP_GRACE_TICKS {
                    return Some(false);
                }
            }
            None
        });
        match action {
            Some(true) => reap_send_disconnect(owner, target, now),
            Some(false) => reap_remove_session(
                owner,
                target,
                listener_inboxes,
                caller_inboxes,
                controls,
                pending_sends,
            ),
            None => {}
        }
        if controls.contains_key(&target) {
            control_checks.push_back(target);
        }
    }
}

/// Driver ticks an orderly close is given to actually leave the socket (via
/// whatever ordinary `drive()` call the loop makes on its own) before
/// [`reap_session_controls`] force-removes it.
const REAP_GRACE_TICKS: u32 = 3;

/// Send a graceful disconnect for a dropped-but-not-yet-torn-down session
/// -- the `close_requested` half of [`reap_session_controls`]'s two cases.
fn reap_send_disconnect(owner: &mut Owner, target: SessionTarget, now: Timestamp) {
    match target {
        SessionTarget::Listener(id) => {
            if let Some(mut peer) = owner.listener_peer_mut(id) {
                peer.disconnect(now);
            }
        }
        SessionTarget::Caller(id) => {
            if let Some(mut caller) = owner.caller_mut(id) {
                caller.disconnect(now);
            }
        }
    }
}

/// Tear down a session whose drop was never followed by an explicit
/// disconnect request -- the forceful half of [`reap_session_controls`]'s
/// two cases.
fn reap_remove_session(
    owner: &mut Owner,
    target: SessionTarget,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    match target {
        SessionTarget::Listener(id) => {
            owner.remove_listener_peer(id);
        }
        SessionTarget::Caller(id) => {
            owner.remove_caller(id);
        }
    }
    remove_session_state(
        target,
        listener_inboxes,
        caller_inboxes,
        controls,
        pending_sends,
    );
}

fn fail_cancelled_connects(
    owner: &mut Owner,
    pending_connects: &mut std::collections::HashMap<
        crate::LogicalCallerId,
        tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    >,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
    connect_checks: &mut VecDeque<crate::LogicalCallerId>,
) {
    for _ in 0..DRIVER_COMMAND_QUANTUM {
        let Some(id) = connect_checks.pop_front() else {
            break;
        };
        let cancelled = pending_connects
            .get(&id)
            .is_some_and(|reply| reply.is_closed());
        if cancelled {
            pending_connects.remove(&id);
            owner.remove_caller(id);
            remove_session_state(
                SessionTarget::Caller(id),
                &mut std::collections::HashMap::new(),
                caller_inboxes,
                controls,
                pending_sends,
            );
        } else if pending_connects.contains_key(&id) {
            connect_checks.push_back(id);
        }
    }
}

#[allow(clippy::cognitive_complexity)]
async fn run_driver(
    mut owner: Owner,
    mut commands: tokio::sync::mpsc::Receiver<Command>,
    commands_tx: tokio::sync::mpsc::WeakSender<Command>,
    accept_tx: tokio::sync::mpsc::Sender<Session>,
    command_bytes: Arc<AtomicUsize>,
    start: std::time::Instant,
) {
    // `start` is captured by `Facade::spawn` before this task exists, and
    // exposed there too (`Facade::now`) -- so an application computing a
    // `ReceivedMessage::age` against `source_time` reads `now()` in the
    // exact same clock domain this driver's own `Timestamp`s live in,
    // with no round-trip through the command channel needed.
    let now = || Timestamp::from_micros(start.elapsed().as_micros() as u64);
    let mut listener_inboxes: std::collections::HashMap<crate::LogicalPeerId, SessionInbox> =
        std::collections::HashMap::new();
    let mut caller_inboxes: std::collections::HashMap<crate::LogicalCallerId, SessionInbox> =
        std::collections::HashMap::new();
    let mut pending_connects: std::collections::HashMap<
        crate::LogicalCallerId,
        tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    > = std::collections::HashMap::new();
    let mut controls: std::collections::HashMap<SessionTarget, Arc<SessionControl>> =
        std::collections::HashMap::new();
    let mut control_checks = VecDeque::new();
    let mut connect_checks = VecDeque::new();
    let mut pending_sends = PendingSends::default();
    let mut listener_events = Vec::new();
    let mut caller_events = Vec::new();
    let mut expired_callers = Vec::new();

    loop {
        let wait_us = owner.time_until_next_deadline(now(), 20_000);
        tokio::select! {
            result = owner.run_once(Duration::from_micros(wait_us), now, OutputDrainBudget::default()) => {
                if result.is_err() {
                    // Driver failure (checkpoint 2's documented outcome):
                    // stop rather than spin on a socket that may never
                    // recover. Dropping `owner` (and every inbox sender
                    // with it) makes every live Session's recv() resolve
                    // to None and the accept queue close; dropping
                    // `pending_connects` fails every in-flight connect().
                    break;
                }
            }
            command = commands.recv() => {
                match command {
                    Some(command) => {
                        handle_command(
                            &mut owner,
                            command,
                            now(),
                            &mut pending_connects,
                            &mut connect_checks,
                            &mut pending_sends,
                        );
                        // A command-heavy facade must not starve the owner
                        // socket: drive one bounded maintenance pass after
                        // each command branch before selecting again.
                        let drive_result = owner.drive(now(), OutputDrainBudget::default());
                        if drive_result.is_err() {
                            break;
                        }
                    }
                    None => break, // every Facade/Session handle dropped -> graceful shutdown
                }
            }
        }

        drive_pending_sends(&mut owner, &mut pending_sends, now());
        // F03 checkpoint 2: a destination that never reopens must not hold
        // unadmitted sends forever -- drop anything past its age bound on
        // every tick, same cadence as draining what did become sendable.
        pending_sends.expire_stale(now(), SESSION_PENDING_MAX_AGE, DRIVER_COMMAND_QUANTUM);

        // A4/course correction #9: an attempt CallerPool itself retired
        // for missing its `attempt_deadline` never produces a protocol
        // `ConnectionEvent` at all (its `CallerTable` entry is already
        // gone by the time this reports it) -- without this, a
        // `Facade::connect()` behind a permit that got queued then timed
        // out would never resolve.
        owner.drain_expired_callers(&mut expired_callers);
        for id in expired_callers.drain(..) {
            if let Some(reply) = pending_connects.remove(&id) {
                let _ = reply.send(Err(FacadeError::Protocol(connect_failed_error())));
            }
            remove_session_state(
                SessionTarget::Caller(id),
                &mut listener_inboxes,
                &mut caller_inboxes,
                &mut controls,
                &mut pending_sends,
            );
        }

        // Course correction #4: a dropped `Session`'s best-effort
        // `Command::Disconnect` can itself be lost (a full command queue
        // at the exact moment of drop) -- this scan is the guaranteed
        // fallback, driven by `SessionControl`'s atomics rather than the
        // command channel, so a dropped session is never leaked just
        // because its one cleanup message didn't make it through.
        reap_session_controls(
            &mut owner,
            &mut controls,
            &mut listener_inboxes,
            &mut caller_inboxes,
            &mut pending_sends,
            &mut control_checks,
            now(),
        );
        fail_cancelled_connects(
            &mut owner,
            &mut pending_connects,
            &mut caller_inboxes,
            &mut controls,
            &mut pending_sends,
            &mut connect_checks,
        );

        let sessions = SessionFactory {
            commands_tx: &commands_tx,
            command_bytes: &command_bytes,
            start,
        };

        owner.poll_listener_events(&mut listener_events);
        for event in listener_events.drain(..) {
            route_listener_event(
                &mut owner,
                event,
                now(),
                &sessions,
                &mut listener_inboxes,
                &mut controls,
                &mut pending_sends,
                &mut control_checks,
                &accept_tx,
            );
        }

        owner.poll_caller_events(&mut caller_events);
        for event in caller_events.drain(..) {
            route_caller_event(
                &mut owner,
                event,
                now(),
                &sessions,
                &mut caller_inboxes,
                &mut controls,
                &mut pending_connects,
                &mut pending_sends,
                &mut control_checks,
            );
        }
    }

    // Give queued SHUTDOWN packets a bounded chance to leave. Each tick has
    // the same finite work quantum as steady state; both iterations and wall
    // time are capped so a permanently backpressured socket cannot hold task
    // shutdown forever.
    let shutdown_deadline = std::time::Instant::now() + SHUTDOWN_MAX_TIME;
    for _ in 0..SHUTDOWN_MAX_TICKS {
        if controls.is_empty() || std::time::Instant::now() >= shutdown_deadline {
            break;
        }
        reap_session_controls(
            &mut owner,
            &mut controls,
            &mut listener_inboxes,
            &mut caller_inboxes,
            &mut pending_sends,
            &mut control_checks,
            now(),
        );
        if owner.drive(now(), OutputDrainBudget::default()).is_err() {
            break;
        }
        tokio::task::yield_now().await;
    }
}

/// Bundles what every new `Session` needs from `run_driver` (a weak
/// command sender plus the shared command-byte counter) into one
/// argument, so `route_listener_event`/`route_caller_event` stay under
/// clippy's argument-count ceiling despite each needing several other
/// independent pieces of driver state too.
struct SessionFactory<'a> {
    commands_tx: &'a tokio::sync::mpsc::WeakSender<Command>,
    command_bytes: &'a Arc<AtomicUsize>,
    start: std::time::Instant,
}

impl SessionFactory<'_> {
    /// Mint one new `Session` plus its matching router-side state, or
    /// `None` if every external handle (hence every strong command
    /// sender) is already gone.
    fn mint(&self, target: SessionTarget) -> Option<(Session, SessionInbox, Arc<SessionControl>)> {
        // A weak clone: the driver hands out real senders to sessions it
        // constructs, but must never hold a strong one itself, or
        // `run_driver`'s `commands.recv()` could never observe every
        // external handle dropped.
        let commands = self.commands_tx.upgrade()?;
        let control = Arc::new(SessionControl::new());
        let (inbox, rx) = SessionInbox::new(Arc::clone(&control));
        let session = Session {
            target,
            commands,
            command_bytes: Arc::clone(self.command_bytes),
            control: Arc::clone(&control),
            inbound: rx,
            start: self.start,
        };
        Some((session, inbox, control))
    }
}

/// Route one listener-side event to its `Session`'s inbound channel
/// (`DataReceived`), retire it (`Disconnected`), or mint a new `Session`
/// and hand it to `accept()` (`Connected`) -- split out of [`run_driver`]'s
/// own loop body to keep its cognitive complexity down.
#[allow(clippy::too_many_arguments)]
fn route_listener_event(
    owner: &mut Owner,
    event: crate::AdmissionEvent,
    now: Timestamp,
    sessions: &SessionFactory<'_>,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
    control_checks: &mut VecDeque<SessionTarget>,
    accept_tx: &tokio::sync::mpsc::Sender<Session>,
) {
    let id = event.logical_peer;
    let target = SessionTarget::Listener(id);
    match event.event {
        srt_proto::ConnectionEvent::Connected => route_listener_connected(
            owner,
            id,
            now,
            sessions,
            listener_inboxes,
            controls,
            pending_sends,
            control_checks,
            accept_tx,
            target,
        ),
        srt_proto::ConnectionEvent::DataReceived {
            payload,
            source_time,
            ..
        } => route_listener_data(
            owner,
            id,
            target,
            now,
            payload,
            source_time,
            listener_inboxes,
            controls,
            pending_sends,
        ),
        srt_proto::ConnectionEvent::Disconnected { .. } => route_listener_disconnected(
            owner,
            id,
            target,
            listener_inboxes,
            controls,
            pending_sends,
        ),
        srt_proto::ConnectionEvent::KeyRefreshNeeded { key_length } => {
            route_listener_key_refresh(owner, id, key_length, now);
        }
        srt_proto::ConnectionEvent::StateChanged(_) | srt_proto::ConnectionEvent::Error(_) => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn route_listener_connected(
    owner: &mut Owner,
    id: crate::LogicalPeerId,
    now: Timestamp,
    sessions: &SessionFactory<'_>,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
    control_checks: &mut VecDeque<SessionTarget>,
    accept_tx: &tokio::sync::mpsc::Sender<Session>,
    target: SessionTarget,
) {
    let Some((session, inbox, control)) = sessions.mint(target) else {
        return;
    };
    listener_inboxes.insert(id, inbox);
    controls.insert(target, control);
    control_checks.push_back(target);
    // A full or closed accept queue leaves no application handle for this
    // connection, so retire it immediately and keep the owner bounded.
    if accept_tx.try_send(session).is_err() {
        disconnect_listener_session(
            owner,
            id,
            target,
            now,
            listener_inboxes,
            controls,
            pending_sends,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn route_listener_data(
    owner: &mut Owner,
    id: crate::LogicalPeerId,
    target: SessionTarget,
    now: Timestamp,
    payload: Bytes,
    source_time: Timestamp,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    let deliverable = listener_inboxes
        .get(&id)
        .is_some_and(|inbox| matches!(inbox.try_send(payload, source_time), InboxSend::Sent));
    if !deliverable {
        disconnect_listener_session(
            owner,
            id,
            target,
            now,
            listener_inboxes,
            controls,
            pending_sends,
        );
    }
}

fn disconnect_listener_session(
    owner: &mut Owner,
    id: crate::LogicalPeerId,
    target: SessionTarget,
    now: Timestamp,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    if let Some(mut peer) = owner.listener_peer_mut(id) {
        peer.disconnect(now);
    }
    clear_listener_session(id, target, listener_inboxes, controls, pending_sends);
}

fn clear_listener_session(
    id: crate::LogicalPeerId,
    target: SessionTarget,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    listener_inboxes.remove(&id);
    if let Some(control) = controls.remove(&target) {
        control.closed.store(true, Ordering::Release);
    }
    pending_sends.fail_target(target);
}

fn route_listener_disconnected(
    owner: &mut Owner,
    id: crate::LogicalPeerId,
    target: SessionTarget,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    clear_listener_session(id, target, listener_inboxes, controls, pending_sends);
    owner.remove_listener_peer(id);
}

fn route_listener_key_refresh(
    owner: &mut Owner,
    id: crate::LogicalPeerId,
    key_length: usize,
    now: Timestamp,
) {
    let refreshed = owner
        .listener_peer_mut(id)
        .is_some_and(|mut peer| refresh_key(key_length, |sek| peer.provide_new_sek(sek, now)));
    if !refreshed && let Some(mut peer) = owner.listener_peer_mut(id) {
        peer.disconnect(now);
    }
}

/// Route one caller-side event: fulfill a pending [`Facade::connect`] once
/// it reaches `Connected`, forward `DataReceived` to its `Session`'s
/// inbound channel, or retire it and fail any still-pending connect once
/// the attempt is truly over -- split out of [`run_driver`]'s own loop body
/// to keep its cognitive complexity down.
#[allow(clippy::too_many_arguments)]
fn route_caller_event(
    owner: &mut Owner,
    event: crate::CallerEvent,
    now: Timestamp,
    sessions: &SessionFactory<'_>,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_connects: &mut std::collections::HashMap<
        crate::LogicalCallerId,
        tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    >,
    pending_sends: &mut PendingSends,
    control_checks: &mut VecDeque<SessionTarget>,
) {
    match event.event {
        srt_proto::ConnectionEvent::Connected => route_caller_connected(
            owner,
            event.id,
            now,
            sessions,
            caller_inboxes,
            controls,
            pending_connects,
            pending_sends,
            control_checks,
        ),
        srt_proto::ConnectionEvent::DataReceived {
            payload,
            source_time,
            ..
        } => route_caller_data(
            owner,
            event.id,
            now,
            payload,
            source_time,
            caller_inboxes,
            controls,
            pending_sends,
        ),
        srt_proto::ConnectionEvent::Disconnected { .. } => route_caller_ended(
            owner,
            event.id,
            true,
            caller_inboxes,
            controls,
            pending_connects,
            pending_sends,
        ),
        // A handshake that never reaches `Connected` -- rejected, or
        // timed out -- ends here, not at `ConnectionEvent::Disconnected`:
        // that event is emitted only by a peer's SHUTDOWN or a graceful
        // local close, both of which presuppose the connection was
        // already `Connected` at some point. Without also failing a
        // pending connect on this transition, `Facade::connect()` against
        // any address that never answers (or that actively rejects the
        // handshake) never resolves at all.
        srt_proto::ConnectionEvent::StateChanged(srt_proto::ConnectionState::Disconnected) => {
            route_caller_ended(
                owner,
                event.id,
                true,
                caller_inboxes,
                controls,
                pending_connects,
                pending_sends,
            )
        }
        srt_proto::ConnectionEvent::KeyRefreshNeeded { key_length } => {
            route_caller_key_refresh(owner, event.id, key_length, now);
        }
        srt_proto::ConnectionEvent::StateChanged(_) | srt_proto::ConnectionEvent::Error(_) => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn route_caller_connected(
    owner: &mut Owner,
    id: crate::LogicalCallerId,
    now: Timestamp,
    sessions: &SessionFactory<'_>,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_connects: &mut std::collections::HashMap<
        crate::LogicalCallerId,
        tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    >,
    pending_sends: &mut PendingSends,
    control_checks: &mut VecDeque<SessionTarget>,
) {
    let Some(reply) = pending_connects.remove(&id) else {
        return;
    };
    let target = SessionTarget::Caller(id);
    let Some((session, inbox, control)) = sessions.mint(target) else {
        return;
    };
    caller_inboxes.insert(id, inbox);
    controls.insert(target, control);
    control_checks.push_back(target);
    // A cancelled connect leaves no handle for the established session, so
    // close it immediately instead of retaining an orphaned caller.
    if reply.send(Ok(session)).is_err() {
        disconnect_caller_session(
            owner,
            id,
            target,
            now,
            caller_inboxes,
            controls,
            pending_sends,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn route_caller_data(
    owner: &mut Owner,
    id: crate::LogicalCallerId,
    now: Timestamp,
    payload: Bytes,
    source_time: Timestamp,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    let deliverable = caller_inboxes
        .get(&id)
        .is_some_and(|inbox| matches!(inbox.try_send(payload, source_time), InboxSend::Sent));
    if !deliverable {
        let target = SessionTarget::Caller(id);
        disconnect_caller_session(
            owner,
            id,
            target,
            now,
            caller_inboxes,
            controls,
            pending_sends,
        );
    }
}

fn disconnect_caller_session(
    owner: &mut Owner,
    id: crate::LogicalCallerId,
    target: SessionTarget,
    now: Timestamp,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    if let Some(mut caller) = owner.caller_mut(id) {
        caller.disconnect(now);
    }
    clear_caller_session(id, target, caller_inboxes, controls, pending_sends);
}

fn clear_caller_session(
    id: crate::LogicalCallerId,
    target: SessionTarget,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
) {
    caller_inboxes.remove(&id);
    if let Some(control) = controls.remove(&target) {
        control.closed.store(true, Ordering::Release);
    }
    pending_sends.fail_target(target);
}

fn route_caller_ended(
    owner: &mut Owner,
    id: crate::LogicalCallerId,
    fail_connect: bool,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_connects: &mut std::collections::HashMap<
        crate::LogicalCallerId,
        tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    >,
    pending_sends: &mut PendingSends,
) {
    let target = SessionTarget::Caller(id);
    if fail_connect && let Some(reply) = pending_connects.remove(&id) {
        let _ = reply.send(Err(FacadeError::Protocol(connect_failed_error())));
    }
    clear_caller_session(id, target, caller_inboxes, controls, pending_sends);
    owner.remove_caller(id);
}

fn route_caller_key_refresh(
    owner: &mut Owner,
    id: crate::LogicalCallerId,
    key_length: usize,
    now: Timestamp,
) {
    let refreshed = owner
        .caller_mut(id)
        .is_some_and(|mut caller| refresh_key(key_length, |sek| caller.provide_new_sek(sek, now)));
    if !refreshed && let Some(mut caller) = owner.caller_mut(id) {
        caller.disconnect(now);
    }
}

fn refresh_key(
    key_length: usize,
    provide: impl FnOnce(&[u8]) -> Result<(), srt_proto::Error>,
) -> bool {
    let mut sek = vec![0; key_length];
    let result = getrandom::fill(&mut sek).is_ok() && provide(&sek).is_ok();
    sek.zeroize();
    result
}

/// A managed, ergonomic async facade (A05 checkpoint 1) around [`Owner`]:
/// spawns a background driver task and communicates with it over bounded
/// application-facing handles ([`Session`]) backed by bounded internal
/// command/event channels, so no application call ever awaits behind
/// another session's full queue (checkpoint 2) -- the channels themselves
/// never block a `send`, only the awaiting side ever suspends.
///
/// One `Facade` is one shard (checkpoint 1): an application wanting more
/// concurrency spawns more of them, typically one per listener port or one
/// per worker thread's share of outbound sessions. [`Owner`] remains
/// available directly for an application that already runs its own
/// executor loop and does not want this crate's background task at all
/// (checkpoint 4).
pub struct Facade {
    commands: tokio::sync::mpsc::Sender<Command>,
    command_bytes: Arc<AtomicUsize>,
    accept: tokio::sync::mpsc::Receiver<Session>,
    listener_local_addr: Option<SocketAddr>,
    start: std::time::Instant,
}

impl Facade {
    /// Spawn the background driver task. `listener_config`, if given, is
    /// bound synchronously before the task starts, so a bind failure
    /// surfaces immediately here rather than silently killing the task on
    /// its first tick. Must be called from within a Tokio runtime context.
    ///
    /// Returns the `Facade` handle plus the driver task's `JoinHandle`;
    /// awaiting the latter after dropping every `Facade`/`Session` handle
    /// observes the graceful shutdown complete (checkpoint 2).
    pub fn spawn(
        listener_config: Option<&crate::ListenerConfig>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>), crate::RuntimeBuildError> {
        let mut owner = Owner::new();
        if let Some(config) = listener_config {
            owner.listen(config)?;
        }
        let listener_local_addr = owner.listener_local_addr();
        let command_bytes = Arc::new(AtomicUsize::new(0));
        let (commands_tx, commands_rx) = tokio::sync::mpsc::channel(FACADE_COMMAND_CAPACITY);
        let (accept_tx, accept_rx) = tokio::sync::mpsc::channel(FACADE_ACCEPT_CAPACITY);
        // Captured here, before the driver task exists, and shared with it
        // (rather than each independently calling `Instant::now()`) so
        // `Facade::now()` and the driver's own internal clock never drift
        // apart by even the scheduling delay between this call and the
        // task's first poll.
        let start = std::time::Instant::now();
        let handle = tokio::spawn(run_driver(
            owner,
            commands_rx,
            commands_tx.downgrade(),
            accept_tx,
            Arc::clone(&command_bytes),
            start,
        ));
        Ok((
            Self {
                commands: commands_tx,
                command_bytes,
                accept: accept_rx,
                listener_local_addr,
                start,
            },
            handle,
        ))
    }

    /// The current time in this `Facade`'s own clock domain -- the same
    /// one every [`ReceivedMessage::source_time`] from a `Session` this
    /// `Facade` produced is expressed in (F01). Comparing a `source_time`
    /// from a *different* `Facade`/`Owner` (a different process, or even a
    /// second `Facade` in this one) against this value is meaningless;
    /// each has its own independent clock origin. A pure, synchronous
    /// computation -- no round-trip through the driver task.
    #[must_use]
    pub fn now(&self) -> Timestamp {
        Timestamp::from_micros(self.start.elapsed().as_micros() as u64)
    }

    /// Start one outbound session. `config.transport.ownership` must be
    /// `Shared` (see [`Owner::connect`]). Resolves only once the handshake
    /// actually reaches `Connected` -- not merely once `CallerPool` admits
    /// the attempt -- specifically so `send`/`recv` on the returned
    /// [`Session`] can never race a still-in-flight handshake. A rejected
    /// or timed-out handshake resolves this to
    /// [`FacadeError::Protocol`], never leaves it pending forever.
    ///
    /// Dropping the returned future before it resolves (a `select!`
    /// losing, an enclosing future being cancelled) does not leak the
    /// connection: if this call is cancelled after the driver already
    /// reached `Connected` but before delivering it here, the driver
    /// notices delivery failed and immediately closes that session on
    /// `Owner`'s behalf rather than leaving it live with no handle
    /// anywhere.
    ///
    /// Returns [`FacadeError::PoolFull`], not an async wait, if the caller
    /// pool is at `max_in_flight` (see [`Owner::set_caller_pool_policy`])
    /// or its queue is already full, and [`FacadeError::QueueFull`] if the
    /// shared command channel itself is momentarily full: checkpoint 2
    /// asks that no application call await behind another session's
    /// queue, and a request genuinely has no session to hand back until a
    /// permit or queue slot frees up, so retrying is left to the caller
    /// rather than this method blocking for an unbounded, uncancellable
    /// amount of time.
    pub async fn connect(&self, config: &crate::CallerConfig) -> Result<Session, FacadeError> {
        let charge = reserve_command_bytes(&self.command_bytes, COMMAND_OVERHEAD_CHARGE)?;
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(Command::Connect {
                config: Box::new(config.clone()),
                reply,
                _charge: charge,
            })
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => FacadeError::QueueFull,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => FacadeError::DriverGone,
            })?;
        reply_rx.await.map_err(|_| FacadeError::DriverGone)?
    }

    /// The next newly-admitted inbound session, or `None` once the driver
    /// has stopped (checkpoint 2's "driver failure"/graceful-close
    /// outcomes) and every already-queued acceptance has been delivered.
    pub async fn accept(&mut self) -> Option<Session> {
        self.accept.recv().await
    }

    /// The listener socket's bound local address, if a `listener_config`
    /// was given to [`Self::spawn`] -- useful when binding an ephemeral
    /// port (`:0`).
    #[must_use]
    pub fn listener_local_addr(&self) -> Option<SocketAddr> {
        self.listener_local_addr
    }

    /// A snapshot of admission-path counters for the listener side, once a
    /// `listener_config` was given to [`Self::spawn`]. `None` also if the
    /// driver task is no longer running or the command queue is
    /// momentarily full.
    pub async fn listener_telemetry(&self) -> Option<crate::IngressTelemetrySnapshot> {
        let charge = reserve_command_bytes(&self.command_bytes, COMMAND_OVERHEAD_CHARGE).ok()?;
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(Command::ListenerTelemetry {
                reply,
                _charge: charge,
            })
            .ok()?;
        reply_rx.await.ok()?
    }

    /// Effective, currently-observable caller-pool state (A04), once at
    /// least one [`Self::connect`] has been attempted. `None` also if the
    /// driver task is no longer running or the command queue is
    /// momentarily full.
    pub async fn caller_pool_stats(&self) -> Option<crate::CallerPoolStats> {
        let charge = reserve_command_bytes(&self.command_bytes, COMMAND_OVERHEAD_CHARGE).ok()?;
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(Command::CallerPoolStats {
                reply,
                _charge: charge,
            })
            .ok()?;
        reply_rx.await.ok()?
    }

    /// Number of direct peers currently in the listener-side table -- both
    /// half-open and established. Exists mainly so that a closed
    /// session's table entry (and its buffers) can be observed as
    /// actually reclaimed once its `Disconnected` event is handled,
    /// rather than left resident for the driver task's whole life.
    pub async fn listener_peer_count(&self) -> Option<usize> {
        let charge = reserve_command_bytes(&self.command_bytes, COMMAND_OVERHEAD_CHARGE).ok()?;
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(Command::ListenerPeerCount {
                reply,
                _charge: charge,
            })
            .ok()?;
        reply_rx.await.ok()?
    }

    /// Number of direct logical callers currently in the caller-side
    /// table -- both in-flight and established. See
    /// [`Self::listener_peer_count`] for why this exists.
    pub async fn caller_count(&self) -> Option<usize> {
        let charge = reserve_command_bytes(&self.command_bytes, COMMAND_OVERHEAD_CHARGE).ok()?;
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(Command::CallerCount {
                reply,
                _charge: charge,
            })
            .ok()?;
        reply_rx.await.ok()?
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    use crate::{LogicalCallerState, PoolOutcome, SocketOwnership};

    fn now_ts(start: std::time::Instant) -> Timestamp {
        Timestamp::from_micros(start.elapsed().as_micros() as u64)
    }

    fn listener_config() -> crate::ListenerConfig {
        crate::ListenerConfig::builder("127.0.0.1:0".parse().unwrap())
            .topology(crate::ListenerTopology::PerPort)
            .build()
            .expect("listener config")
    }

    fn shared_caller_config(remote: SocketAddr) -> crate::CallerConfig {
        crate::CallerConfig::builder(remote)
            .ownership(SocketOwnership::Shared)
            .build()
            .expect("caller config")
    }

    #[test]
    fn owner_rejects_listener_promotion_without_a_relocation_target() {
        let mut owner = Owner::new();
        let config = crate::ListenerConfig::builder("127.0.0.1:0".parse().unwrap())
            .topology(crate::ListenerTopology::PerPort)
            .configure_transport(|transport| {
                transport.promotion = crate::PromotionPolicy::All;
            })
            .build()
            .expect("listener config");
        let error = owner
            .listen(&config)
            .expect_err("promotion must be rejected");
        match error {
            crate::RuntimeBuildError::Config(error) => {
                assert_eq!(error.field(), "listener.transport.promotion");
            }
            other => panic!("expected configuration error, got {other:?}"),
        }
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("Tokio runtime builds")
    }

    /// Drive `owner` for up to `timeout`, calling `done` after every tick;
    /// returns as soon as `done` reports true.
    async fn drive_until(
        owner: &mut Owner,
        start: std::time::Instant,
        timeout: Duration,
        mut done: impl FnMut(&mut Owner, Timestamp) -> bool,
    ) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let wait_us = owner.time_until_next_deadline(now_ts(start), 5_000);
            owner
                .run_once(
                    Duration::from_micros(wait_us),
                    || now_ts(start),
                    OutputDrainBudget::default(),
                )
                .await
                .expect("run_once");
            let now = now_ts(start);
            if done(owner, now) {
                return true;
            }
        }
        false
    }

    /// A05: the Tokio-native `Owner` must connect, exchange a known
    /// payload, and close in an orderly way -- the same acceptance round
    /// trip as `mio_transport::Owner`'s own test, proving this is a real
    /// working driver and not just a type that compiles.
    #[test]
    fn owner_connects_sends_receives_and_closes_one_session() {
        test_runtime().block_on(async {
            let start = std::time::Instant::now();
            let mut owner = Owner::new();
            owner.listen(&listener_config()).expect("listen");
            let listen_addr = owner.listener_local_addr().expect("listener bound");

            let PoolOutcome::Admitted(caller_id) = owner
                .connect(&shared_caller_config(listen_addr), now_ts(start))
                .expect("connect")
            else {
                panic!("the default pool admits the first connect() immediately")
            };

            let mut peer_id = None;
            let connected =
                drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
                    let mut events = Vec::new();
                    owner.poll_listener_events(&mut events);
                    for event in events {
                        if let srt_proto::ConnectionEvent::Connected = event.event {
                            peer_id = Some(event.logical_peer);
                        }
                    }
                    peer_id.is_some()
                        && owner.caller_mut(caller_id).and_then(|c| c.state())
                            == Some(LogicalCallerState::Connected)
                })
                .await;
            assert!(connected, "caller and listener must both reach Connected");
            let peer_id = peer_id.expect("listener admitted the caller");

            owner
                .caller_mut(caller_id)
                .expect("caller session still exists")
                .send(b"known message", now_ts(start))
                .expect("caller sends");

            let mut received = None;
            let got_data = drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
                let mut events = Vec::new();
                owner.poll_listener_events(&mut events);
                for event in events {
                    if event.logical_peer == peer_id
                        && let srt_proto::ConnectionEvent::DataReceived { payload, .. } =
                            event.event
                    {
                        received = Some(payload.to_vec());
                    }
                }
                received.is_some()
            })
            .await;
            assert!(got_data, "listener must receive the caller's payload");
            assert_eq!(received.expect("checked above"), b"known message");

            owner
                .caller_mut(caller_id)
                .expect("caller session still exists")
                .disconnect(now_ts(start));

            let mut saw_disconnect = false;
            let closed = drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
                let mut events = Vec::new();
                owner.poll_listener_events(&mut events);
                for event in events {
                    if event.logical_peer == peer_id
                        && matches!(event.event, srt_proto::ConnectionEvent::Disconnected { .. })
                    {
                        saw_disconnect = true;
                    }
                }
                saw_disconnect
            })
            .await;
            assert!(closed, "listener must observe the caller's orderly close");
        });
    }

    /// A05: `Owner::connect` must reject an `Exclusive`-ownership config,
    /// same reasoning as `mio_transport::Owner::connect`.
    #[test]
    fn connect_rejects_exclusive_ownership() {
        test_runtime().block_on(async {
            let mut owner = Owner::new();
            let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
            let config = crate::CallerConfig::builder(remote)
                .build()
                .expect("caller config");
            let result = owner.connect(&config, Timestamp::from_micros(0));
            assert!(
                result.is_err(),
                "Exclusive ownership must be rejected, not silently accepted"
            );
        });
    }

    #[test]
    fn owner_enforces_socket_memory_budget_across_listener_and_caller() {
        test_runtime().block_on(async {
            let mut owner = Owner::new();
            let mut config = listener_config();
            config.transport.socket_buffers =
                crate::SocketBufferConfig::Bytes(std::num::NonZeroUsize::new(1_024).unwrap());
            config.admission.socket_memory_budget = std::num::NonZeroUsize::new(5_000);
            owner.listen(&config).expect("listener fits budget");

            let mut caller_cfg = shared_caller_config("127.0.0.1:9".parse().unwrap());
            caller_cfg.transport.socket_buffers =
                crate::SocketBufferConfig::Bytes(std::num::NonZeroUsize::new(1_024).unwrap());
            let err = owner
                .connect(&caller_cfg, Timestamp::default())
                .expect_err("combined listener + caller buffers must exceed budget");
            match err {
                crate::RuntimeBuildError::Config(err) => {
                    assert_eq!(err.field(), "caller.socket_memory_budget");
                }
                other => panic!("expected ConfigError, got {other:?}"),
            }
        });
    }
}

#[cfg(test)]
mod facade_tests {
    use super::*;
    use crate::SocketOwnership;
    use std::time::Duration;

    fn listener_config() -> crate::ListenerConfig {
        crate::ListenerConfig::builder("127.0.0.1:0".parse().unwrap())
            .topology(crate::ListenerTopology::PerPort)
            .build()
            .expect("listener config")
    }

    fn shared_caller_config(remote: SocketAddr) -> crate::CallerConfig {
        crate::CallerConfig::builder(remote)
            .ownership(SocketOwnership::Shared)
            .build()
            .expect("caller config")
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("Tokio runtime builds")
    }

    async fn with_timeout<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("operation must complete within the test deadline")
    }

    /// A05: the full ergonomic round trip -- connect, send, receive on the
    /// admitted side via `accept()`, and an orderly close observed as
    /// `recv()` returning `None`.
    #[test]
    fn facade_connects_sends_receives_and_closes() {
        test_runtime().block_on(async {
            let (mut facade, _handle) = Facade::spawn(Some(&listener_config())).expect("spawn");
            let listen_addr = facade.listener_local_addr().expect("listener bound");

            let caller_session = with_timeout(facade.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect");
            let mut listener_session = with_timeout(facade.accept())
                .await
                .expect("accept yields the admitted session");

            with_timeout(caller_session.send(b"known message".to_vec()))
                .await
                .expect("send");
            let received = with_timeout(listener_session.recv())
                .await
                .expect("listener session receives the payload");
            assert_eq!(received.payload.as_ref(), b"known message");

            caller_session.close();
            let closed = with_timeout(listener_session.recv()).await;
            assert!(
                closed.is_none(),
                "recv() must resolve to None once the session has closed"
            );
        });
    }

    /// A05 checkpoint 2: one session's inbound backlog (nobody ever calls
    /// `recv()` on it) must not block another, unrelated session's own
    /// send/receive round trip -- proof that per-session channels are
    /// actually independent, not a shared bottleneck.
    #[test]
    fn one_slow_consumer_does_not_block_another_session() {
        test_runtime().block_on(async {
            let (mut facade, _handle) = Facade::spawn(Some(&listener_config())).expect("spawn");
            let listen_addr = facade.listener_local_addr().expect("listener bound");

            let slow_caller = with_timeout(facade.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect slow");
            let active_caller = with_timeout(facade.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect active");

            let mut slow_listener_session =
                with_timeout(facade.accept()).await.expect("accept slow");
            let mut active_listener_session =
                with_timeout(facade.accept()).await.expect("accept active");

            // The "slow" caller floods a large, growing backlog nobody
            // ever reads on the listener side, *concurrently* with the
            // active pair's own round trips -- not before them, which
            // would only prove a pre-existing backlog doesn't block (a
            // shared round-robin queue could pass that trivially). Each
            // active round trip is also latency-bounded, not just
            // eventually successful, since a shared/bounded design could
            // still finish every round trip while visibly delayed by the
            // other session's traffic.
            const BACKLOG: usize = 500;
            let flood = tokio::spawn(async move {
                for i in 0..BACKLOG {
                    let _ = slow_caller.send(format!("backlog {i}").into_bytes()).await;
                }
                slow_caller
            });

            for i in 0..20 {
                let started = std::time::Instant::now();
                with_timeout(active_caller.send(format!("active {i}").into_bytes()))
                    .await
                    .expect("active caller sends");
                let received = with_timeout(active_listener_session.recv())
                    .await
                    .expect("active listener session receives");
                assert_eq!(
                    received.payload.as_ref(),
                    format!("active {i}").into_bytes()
                );
                assert!(
                    started.elapsed() < Duration::from_millis(500),
                    "active round trip {i} took {:?} -- the slow session's concurrent \
                     backlog must not delay it, not just eventually let it finish",
                    started.elapsed()
                );
            }

            let slow_caller = with_timeout(flood).await.expect("flood task completes");
            drop(slow_caller);

            // The slow session's backlog is all still there, in order,
            // once someone finally reads it -- nothing was dropped.
            for i in 0..BACKLOG {
                let payload = with_timeout(slow_listener_session.recv())
                    .await
                    .expect("slow session's backlog is preserved");
                assert_eq!(
                    payload.payload.as_ref(),
                    format!("backlog {i}").into_bytes()
                );
            }
        });
    }

    /// A05 checkpoint 2: dropping a `Session` (the application loses
    /// interest, or a handle just goes out of scope) must not crash or
    /// hang the driver task -- a later, unrelated session must still work
    /// normally afterward.
    #[test]
    fn dropping_a_session_does_not_disrupt_the_driver() {
        test_runtime().block_on(async {
            let (mut facade, _handle) = Facade::spawn(Some(&listener_config())).expect("spawn");
            let listen_addr = facade.listener_local_addr().expect("listener bound");

            let first_caller = with_timeout(facade.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect first");
            let first_listener_session = with_timeout(facade.accept()).await.expect("accept first");
            drop(first_caller);
            drop(first_listener_session);

            let second_caller = with_timeout(facade.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect second");
            let mut second_listener_session =
                with_timeout(facade.accept()).await.expect("accept second");
            with_timeout(second_caller.send(b"after a drop".to_vec()))
                .await
                .expect("second caller sends");
            let received = with_timeout(second_listener_session.recv())
                .await
                .expect("second session still works after the first was dropped");
            assert_eq!(received.payload.as_ref(), b"after a drop");
        });
    }

    /// A05 checkpoint 2: dropping every `Facade`/`Session` handle must let
    /// the driver task end on its own (graceful shutdown), not hang
    /// forever waiting for a command that will never come.
    #[test]
    fn dropping_every_facade_handle_ends_the_driver_task() {
        test_runtime().block_on(async {
            let (facade, handle) = Facade::spawn(Some(&listener_config())).expect("spawn");
            drop(facade);
            with_timeout(handle)
                .await
                .expect("driver task joins cleanly");
        });
    }

    /// Opus review (A05): a handshake that never gets a reply -- the most
    /// common real-world `connect()` failure -- must resolve once it times
    /// out, not hang forever. A rejected or timed-out handshake ends at
    /// `ConnectionState::Disconnected` without ever emitting the distinct
    /// `ConnectionEvent::Disconnected` (that event fires only for a peer's
    /// SHUTDOWN or a graceful local close of an already-`Connected`
    /// session), so a pending connect has to resolve on that state
    /// transition specifically, not just the event of the same name.
    #[test]
    fn connect_to_an_address_that_never_answers_does_not_hang_forever() {
        test_runtime().block_on(async {
            let (facade, _handle) = Facade::spawn(None).expect("spawn");
            // A real bound socket that never sends a single reply --
            // unlike an unbound port, this cannot be short-circuited by an
            // immediate ICMP port-unreachable, so the handshake genuinely
            // has to run out its own retry/timeout budget.
            let black_hole = std::net::UdpSocket::bind("127.0.0.1:0").expect("black hole binds");
            let remote = black_hole.local_addr().expect("address");

            let result = tokio::time::timeout(
                Duration::from_secs(10),
                facade.connect(&shared_caller_config(remote)),
            )
            .await
            .expect("connect() must resolve within the test deadline, not hang forever");
            assert!(
                result.is_err(),
                "a handshake that never gets a reply must resolve as an error, not Ok"
            );
            drop(black_hole);
        });
    }

    /// Opus review (A05): an orderly close must actually reach the wire
    /// before the driver task ends -- `close()` only queues the SHUTDOWN
    /// into `Owner`'s own output queue, and nothing sent it if every
    /// handle (including the one whose drop triggers shutdown) went away
    /// before the driver's loop got another turn to call `drive()`.
    /// Deliberately does not call `recv()` (or anything else) on the
    /// closing side between `close()` and dropping every handle, unlike
    /// `facade_connects_sends_receives_and_closes`, which happens to give
    /// the driver a flush window by awaiting `recv()` first and so cannot
    /// catch this on its own.
    #[test]
    fn graceful_close_delivers_its_shutdown_before_the_driver_task_ends() {
        test_runtime().block_on(async {
            let (mut server, _server_handle) =
                Facade::spawn(Some(&listener_config())).expect("spawn server");
            let listen_addr = server.listener_local_addr().expect("listener bound");
            let (client, client_handle) = Facade::spawn(None).expect("spawn client");

            let caller_session = with_timeout(client.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect");
            let mut listener_session = with_timeout(server.accept()).await.expect("accept");

            caller_session.close();
            drop(caller_session);
            drop(client);
            with_timeout(client_handle)
                .await
                .expect("client driver task joins cleanly");

            let closed = with_timeout(listener_session.recv()).await;
            assert!(
                closed.is_none(),
                "the listener must observe the close even though the client's driver \
                 task already ended by the time it checks"
            );
        });
    }

    /// Opus review (A05): once a session's `Disconnected` event is
    /// handled, its table entry (and buffers) must actually be reclaimed
    /// from `Owner` -- not just the `Facade`'s own inbox map -- or a
    /// long-lived `Facade` serving a stream of short sessions leaks one
    /// entry per closed session for the rest of the driver task's life.
    #[test]
    fn a_closed_sessions_table_entry_is_actually_reclaimed() {
        test_runtime().block_on(async {
            let (mut server, _server_handle) =
                Facade::spawn(Some(&listener_config())).expect("spawn server");
            let listen_addr = server.listener_local_addr().expect("listener bound");
            let (client, _client_handle) = Facade::spawn(None).expect("spawn client");

            let caller_session = with_timeout(client.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect");
            let mut listener_session = with_timeout(server.accept()).await.expect("accept");
            assert_eq!(with_timeout(server.listener_peer_count()).await, Some(1));
            assert_eq!(with_timeout(client.caller_count()).await, Some(1));

            caller_session.close();
            let closed = with_timeout(listener_session.recv()).await;
            assert!(closed.is_none(), "the listener must observe the close");

            // Give the client side's own Disconnected event a moment to be
            // observed and routed too (it is delivered to the driver on
            // its own schedule, independent of the listener side above).
            for _ in 0..50 {
                if with_timeout(client.caller_count()).await == Some(0) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            assert_eq!(
                with_timeout(server.listener_peer_count()).await,
                Some(0),
                "the closed peer's table entry must be reclaimed, not left resident"
            );
            assert_eq!(
                with_timeout(client.caller_count()).await,
                Some(0),
                "the closed caller's table entry must be reclaimed, not left resident"
            );
        });
    }

    /// Opus review finding 5: a session that is `close()`d and then
    /// dropped, with no live handle left anywhere to ever observe the
    /// matching `Disconnected` event, must still be reclaimed even when
    /// the peer can never answer -- not pinned in `Owner`'s table (and its
    /// `SessionInbox`'s buffered bytes) forever. Simulated here by
    /// dropping the whole server `Facade` before closing the caller side,
    /// so nothing is left to ever send back an acknowledgement.
    #[test]
    fn a_closed_then_dropped_session_is_reclaimed_even_when_the_peer_never_answers() {
        test_runtime().block_on(async {
            let (mut server, server_handle) =
                Facade::spawn(Some(&listener_config())).expect("spawn server");
            let listen_addr = server.listener_local_addr().expect("listener bound");
            let (client, _client_handle) = Facade::spawn(None).expect("spawn client");

            let caller_session = with_timeout(client.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect");
            let listener_session = with_timeout(server.accept()).await.expect("accept");
            assert_eq!(with_timeout(client.caller_count()).await, Some(1));

            // The peer becomes permanently unreachable: every server-side
            // handle (the `Facade` and the accepted `Session` alike, since
            // a `Session` holds its own strong sender to the same driver)
            // is gone, so its driver task ends and nothing is left to
            // ever process (let alone answer) the caller's SHUTDOWN.
            drop(server);
            drop(listener_session);
            with_timeout(server_handle)
                .await
                .expect("server driver task joins cleanly");

            caller_session.close();
            drop(caller_session);

            for _ in 0..200 {
                if with_timeout(client.caller_count()).await == Some(0) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                with_timeout(client.caller_count()).await,
                Some(0),
                "a closed-then-dropped session against an unreachable peer must \
                 still be force-reclaimed, not pinned forever waiting for a \
                 Disconnected event that can never arrive"
            );
        });
    }

    /// F01 acceptance criterion: a relay forwarding a message across two
    /// hops (source -> relay -> destination) must preserve its original
    /// source age, not reset it at the republish. Delays injected both
    /// before and after the relay's own forwarding send must both show up
    /// in the age finally observed at the destination.
    ///
    /// `source_time` only survives one connection: the relay's own egress
    /// leg to the destination has a completely independent clock epoch
    /// from its ingress leg, so the relay must carry the ingress age
    /// forward as application data (an 8-byte little-endian micros prefix
    /// here), not expect the wire protocol to do it. See
    /// `examples/tokio_relay.rs` for the same pattern written as a
    /// standalone demonstration.
    #[test]
    fn relayed_message_preserves_source_age_across_both_injected_delays() {
        test_runtime().block_on(async {
            let (source, _source_handle) = Facade::spawn(None).expect("spawn source facade");
            let (mut relay, _relay_handle) =
                Facade::spawn(Some(&listener_config())).expect("spawn relay facade");
            let relay_listen_addr = relay.listener_local_addr().expect("relay listener bound");
            let (mut destination, _destination_handle) =
                Facade::spawn(Some(&listener_config())).expect("spawn destination facade");
            let destination_listen_addr = destination
                .listener_local_addr()
                .expect("destination listener bound");

            let source_session =
                with_timeout(source.connect(&shared_caller_config(relay_listen_addr)))
                    .await
                    .expect("source connects to relay");
            let mut relay_ingress = with_timeout(relay.accept())
                .await
                .expect("relay accepts source");
            let relay_egress =
                with_timeout(relay.connect(&shared_caller_config(destination_listen_addr)))
                    .await
                    .expect("relay connects onward to destination");
            let mut destination_session = with_timeout(destination.accept())
                .await
                .expect("destination accepts relay");

            with_timeout(source_session.send(b"live payload".to_vec()))
                .await
                .expect("source sends");
            let received = with_timeout(relay_ingress.recv())
                .await
                .expect("relay receives from source");

            // Delay injected BEFORE the relay republishes: simulates the
            // relay holding/processing the message for a while.
            tokio::time::sleep(Duration::from_millis(150)).await;
            let age_before_republish = received.age(relay.now());
            let mut envelope = (age_before_republish.as_micros() as u64)
                .to_le_bytes()
                .to_vec();
            envelope.extend_from_slice(&received.payload);
            with_timeout(relay_egress.send(envelope))
                .await
                .expect("relay forwards to destination");

            // Delay injected AFTER publication: simulates a slow consumer
            // at the destination.
            tokio::time::sleep(Duration::from_millis(150)).await;
            let forwarded = with_timeout(destination_session.recv())
                .await
                .expect("destination receives from relay");
            let age_bytes: [u8; 8] = forwarded.payload[..8]
                .try_into()
                .expect("envelope carries an 8-byte micros age prefix");
            let carried_age = Duration::from_micros(u64::from_le_bytes(age_bytes));
            let transit_age = forwarded.age(destination.now());
            let total_age = carried_age + transit_age;

            assert_eq!(&forwarded.payload[8..], b"live payload");
            assert!(
                age_before_republish >= Duration::from_millis(140),
                "age captured before republish must reflect its injected delay, \
                 got {age_before_republish:?}"
            );
            assert!(
                transit_age >= Duration::from_millis(140),
                "age captured after republish must reflect its injected delay, \
                 got {transit_age:?}"
            );
            assert!(
                total_age >= Duration::from_millis(280),
                "total observed age at the destination must reflect BOTH \
                 injected delays, not just the more recent one (a reset-at-\
                 republish bug would show roughly transit_age alone here): \
                 got {total_age:?}"
            );
        });
    }

    /// F01 / Opus review: a `Session` is designed to outlive its `Facade`
    /// (dropping the `Facade` alone does not end the driver task while any
    /// `Session` remains -- see `dropping_a_session_does_not_disrupt_the_
    /// driver`'s sibling `dropping_every_facade_handle_ends_the_driver_
    /// task`), so an application computing `ReceivedMessage::age` must not
    /// need to keep the `Facade` around just to call `now()`. `Session`
    /// gets its own `now()`, sharing the same clock origin.
    #[test]
    fn session_now_keeps_working_after_its_facade_is_dropped() {
        test_runtime().block_on(async {
            let (mut server, _server_handle) =
                Facade::spawn(Some(&listener_config())).expect("spawn server");
            let listen_addr = server.listener_local_addr().expect("listener bound");
            let (client, _client_handle) = Facade::spawn(None).expect("spawn client");

            let caller_session = with_timeout(client.connect(&shared_caller_config(listen_addr)))
                .await
                .expect("connect");
            let mut listener_session = with_timeout(server.accept()).await.expect("accept");

            with_timeout(caller_session.send(b"payload".to_vec()))
                .await
                .expect("send");
            let received = with_timeout(listener_session.recv()).await.expect("recv");

            // Drop every Facade handle for the listener side -- only the
            // Session itself is left holding this driver open.
            drop(server);
            drop(client);

            let age = received.age(listener_session.now());
            assert!(
                age < Duration::from_secs(1),
                "age computed via Session::now() after dropping the Facade \
                 should still be a small, sane value, got {age:?}"
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestReply = (
        tokio::sync::oneshot::Sender<Result<(), FacadeError>>,
        tokio::sync::oneshot::Receiver<Result<(), FacadeError>>,
    );

    fn test_reply() -> TestReply {
        tokio::sync::oneshot::channel()
    }

    /// Pushes and asserts the send was actually queued (its reply is still
    /// unresolved), not rejected as `QueueFull` -- `push` no longer returns
    /// a `Result` since it resolves `reply` itself either way.
    fn push_expect_queued(
        pending: &mut PendingSends,
        target: SessionTarget,
        payload: Vec<u8>,
        queued_at: Timestamp,
    ) -> tokio::sync::oneshot::Receiver<Result<(), FacadeError>> {
        let (reply, mut rx) = test_reply();
        pending.push(target, payload, queued_at, reply);
        assert!(
            rx.try_recv().is_err(),
            "expected this push to be queued, not immediately rejected"
        );
        rx
    }

    /// F03: `PendingSends` previously enforced `SESSION_PENDING_SENDS`/
    /// `_BYTES` against the combined total across every destination, not
    /// each destination's own backlog -- despite the constant names (and
    /// `SESSION_INBOUND_CAPACITY`'s existing genuinely-per-session
    /// enforcement) implying a per-destination bound. A single stalled
    /// destination filling that shared total made `has_capacity` return
    /// `false` for a completely different, healthy destination too, i.e.
    /// exactly the "shared owner awaits one destination's queue capacity"
    /// anti-pattern this card's checkpoint 4 forbids. Reverting the
    /// per-target queue back to a shared counter reproduces this: pushing
    /// `SESSION_PENDING_SENDS` items to target A alone then makes this
    /// assertion for target B fail. Covers both dimensions independently
    /// (items and bytes), since a fix that only re-scoped one of the two
    /// would still leave the other globally shared.
    #[test]
    fn one_destinations_backlog_does_not_consume_another_destinations_capacity() {
        let mut pending = PendingSends::default();
        let target_a = SessionTarget::Caller(crate::LogicalCallerId::for_test(0));
        let target_b = SessionTarget::Caller(crate::LogicalCallerId::for_test(1));
        let now = Timestamp::from_micros(0);

        for _ in 0..SESSION_PENDING_SENDS {
            push_expect_queued(&mut pending, target_a, vec![0u8; 4], now);
        }
        assert!(
            !pending.has_capacity(target_a, 4),
            "target A's own item-count bound must be reached"
        );
        assert!(
            pending.has_capacity(target_b, 4),
            "target B is untouched by A's item-count backlog and must still \
             have its own full headroom"
        );
        push_expect_queued(&mut pending, target_b, vec![0u8; 4], now);

        // Same isolation, the byte dimension: a fix that only re-scoped
        // the item-count check would still leave bytes globally shared.
        let mut pending = PendingSends::default();
        push_expect_queued(
            &mut pending,
            target_a,
            vec![0u8; SESSION_PENDING_BYTES],
            now,
        );
        assert!(
            !pending.has_capacity(target_a, 1),
            "target A's own byte bound must be reached"
        );
        assert!(
            pending.has_capacity(target_b, SESSION_PENDING_BYTES),
            "target B's own byte headroom must be untouched by A's backlog"
        );
    }

    /// F03: on top of each destination's own bound, an aggregate ceiling
    /// (`FACADE_PENDING_SENDS_TOTAL`/`_BYTES_TOTAL`) still bounds this
    /// Facade's total memory use regardless of how many destinations are
    /// simultaneously backlogged -- re-scoping the bound to be
    /// per-destination-only would otherwise let unlimited destinations
    /// each holding their own full `SESSION_PENDING_SENDS` backlog grow
    /// this Facade's memory without bound.
    #[test]
    fn an_aggregate_ceiling_still_bounds_total_memory_across_many_destinations() {
        let mut pending = PendingSends::default();
        let now = Timestamp::from_micros(0);
        let mut id = 0u64;
        while pending.total_items < FACADE_PENDING_SENDS_TOTAL {
            let target = SessionTarget::Caller(crate::LogicalCallerId::for_test(id));
            id += 1;
            push_expect_queued(&mut pending, target, vec![0u8; 4], now);
        }
        let fresh_target = SessionTarget::Caller(crate::LogicalCallerId::for_test(id));
        assert!(
            !pending.has_capacity(fresh_target, 4),
            "a brand-new destination with no backlog of its own must still be \
             rejected once the Facade-wide aggregate ceiling is reached"
        );
        let (reply, mut rx) = test_reply();
        pending.push(fresh_target, vec![0u8; 4], now, reply);
        assert!(
            matches!(rx.try_recv(), Ok(Err(FacadeError::QueueFull))),
            "push must itself reply QueueFull, not silently drop the reply"
        );
    }

    /// F03 checkpoint 2: a send that has waited longer than
    /// `SESSION_PENDING_MAX_AGE` for its destination to accept it is
    /// dropped and reported back via its own reply channel -- an explicit
    /// expiry, not an unbounded wait. A fresher item for the same
    /// destination, queued after the stale one, is untouched, and the
    /// per-destination/aggregate byte accounting reflects the eviction
    /// (not just the `VecDeque` contents) so a subsequent push isn't
    /// wrongly rejected against inflated leftover byte counts.
    #[test]
    fn expire_stale_drops_only_what_has_aged_past_the_bound_and_reports_it() {
        let mut pending = PendingSends::default();
        let target = SessionTarget::Caller(crate::LogicalCallerId::for_test(0));
        let queued_at = Timestamp::from_micros(0);

        let mut stale_rx = push_expect_queued(&mut pending, target, b"stale".to_vec(), queued_at);
        let fresh_at = Timestamp::from_micros(SESSION_PENDING_MAX_AGE.as_micros() as u64 - 1);
        let mut fresh_rx = push_expect_queued(&mut pending, target, b"fresh".to_vec(), fresh_at);

        let past_bound = Timestamp::from_micros(SESSION_PENDING_MAX_AGE.as_micros() as u64 + 1);
        pending.expire_stale(
            past_bound,
            SESSION_PENDING_MAX_AGE,
            FACADE_PENDING_SENDS_TOTAL,
        );

        let outcome = stale_rx.try_recv().expect("stale send got a reply");
        assert!(
            matches!(outcome, Err(FacadeError::Expired)),
            "expected Expired, got {outcome:?}"
        );
        assert!(
            fresh_rx.try_recv().is_err(),
            "the fresher item must not have been expired or replied to yet"
        );
        assert_eq!(
            pending.total_bytes,
            b"fresh".len(),
            "expiring the stale entry must decrement the tracked byte totals \
             by exactly its own size, not leave them inflated"
        );
        assert!(
            pending.has_capacity(target, SESSION_PENDING_BYTES - b"fresh".len()),
            "the destination's own DestinationQueue byte count, not just the \
             aggregate, must be decremented by exactly the expired item's \
             size -- a leftover-inflated per-destination count would wrongly \
             reject a push that should fit in what's actually now free"
        );
        let popped = pending.pop(target).expect("the fresh item is still queued");
        assert_eq!(popped.payload, b"fresh");
    }

    /// F03: every item past the age bound is dropped in one pass, not just
    /// the first -- and once a destination's entire backlog has expired,
    /// it must stop being tracked at all (`has_pending` false), not linger
    /// as an empty entry that would otherwise keep consuming a slot in
    /// `drive_pending_sends`' every-tick service quantum for nothing.
    #[test]
    fn expire_stale_clears_every_stale_item_and_forgets_a_fully_expired_destination() {
        let mut pending = PendingSends::default();
        let target = SessionTarget::Caller(crate::LogicalCallerId::for_test(0));
        let queued_at = Timestamp::from_micros(0);

        let mut rx_a = push_expect_queued(&mut pending, target, b"a".to_vec(), queued_at);
        let mut rx_b = push_expect_queued(&mut pending, target, b"b".to_vec(), queued_at);
        let mut rx_c = push_expect_queued(&mut pending, target, b"c".to_vec(), queued_at);

        let past_bound = Timestamp::from_micros(SESSION_PENDING_MAX_AGE.as_micros() as u64 + 1);
        pending.expire_stale(
            past_bound,
            SESSION_PENDING_MAX_AGE,
            FACADE_PENDING_SENDS_TOTAL,
        );

        for rx in [&mut rx_a, &mut rx_b, &mut rx_c] {
            assert!(
                matches!(rx.try_recv(), Ok(Err(FacadeError::Expired))),
                "every stale item must be expired in one pass, not just the first"
            );
        }
        assert!(
            !pending.has_pending(target),
            "a destination with nothing left after expiry must not still be tracked"
        );
        assert_eq!(pending.total_items, 0);
        assert_eq!(pending.total_bytes, 0);
    }

    /// F03: an item exactly at the age bound is not yet expired -- `expire_stale`
    /// drops items strictly older than `max_age`, not "at least as old as".
    #[test]
    fn an_item_exactly_at_the_age_bound_is_not_yet_expired() {
        let mut pending = PendingSends::default();
        let target = SessionTarget::Caller(crate::LogicalCallerId::for_test(0));
        let queued_at = Timestamp::from_micros(0);
        let mut rx = push_expect_queued(&mut pending, target, b"item".to_vec(), queued_at);

        let exactly_at_bound = Timestamp::from_micros(SESSION_PENDING_MAX_AGE.as_micros() as u64);
        pending.expire_stale(
            exactly_at_bound,
            SESSION_PENDING_MAX_AGE,
            FACADE_PENDING_SENDS_TOTAL,
        );

        assert!(
            rx.try_recv().is_err(),
            "an item exactly at the age bound must not be expired yet"
        );
    }

    /// F05: closing a session while a `Session::send` is still queued in
    /// `PendingSends` must resolve that send instead of leaking it.
    /// `fail_target` replies `Protocol(session-gone)`, drops the byte/item
    /// accounting, and forgets the destination, while another destination's
    /// backlog is untouched. Unit-level (no sockets): the live close paths
    /// (`clear_listener_session`/`clear_caller_session`) all funnel here.
    #[test]
    fn close_with_queued_sends_fails_only_the_closed_destination() {
        let mut pending = PendingSends::default();
        let target = SessionTarget::Caller(crate::LogicalCallerId::for_test(0));
        let other = SessionTarget::Caller(crate::LogicalCallerId::for_test(1));
        let now = Timestamp::from_micros(0);
        let mut rx_a = push_expect_queued(&mut pending, target, b"a".to_vec(), now);
        let mut rx_b = push_expect_queued(&mut pending, target, b"b".to_vec(), now);
        let mut other_rx = push_expect_queued(&mut pending, other, b"other".to_vec(), now);
        assert_eq!(pending.total_items, 3);
        pending.fail_target(target);
        for rx in [&mut rx_a, &mut rx_b] {
            assert!(
                matches!(rx.try_recv(), Ok(Err(FacadeError::Protocol(_)))),
                "a send queued on a closed session must resolve, not leak"
            );
        }
        assert!(
            other_rx.try_recv().is_err(),
            "another destination's queued send must be untouched by this close"
        );
        assert!(
            !pending.has_pending(target),
            "a fully failed destination must stop being tracked"
        );
        assert!(pending.has_pending(other));
        assert_eq!(pending.total_items, 1);
        assert_eq!(pending.total_bytes, b"other".len());
        assert!(
            pending.has_capacity(target, SESSION_PENDING_BYTES),
            "the closed destination's byte accounting must be released"
        );
        pending.fail_target(target);
        assert_eq!(pending.total_items, 1);
        assert_eq!(pending.total_bytes, b"other".len());
    }

    /// Revalidates the historical F03 command-channel fairness finding:
    /// one destination flooding `Session::send()` commands is bounded by its
    /// per-session quota (`SESSION_COMMAND_CAPACITY = 64`, `SESSION_COMMAND_BYTES = 1 MiB`),
    /// leaving ample headroom in the shared channel (`FACADE_COMMAND_CAPACITY = 1024`,
    /// `FACADE_COMMAND_BYTES = 8 MiB`) so a sibling healthy destination is not starved.
    #[test]
    fn flooding_session_cannot_starve_sibling_session_command_headroom() {
        let shared_bytes = Arc::new(AtomicUsize::new(0));
        let session_a = Arc::new(SessionControl::new());
        let session_b = Arc::new(SessionControl::new());
        let (commands_tx, mut commands_rx) = tokio::sync::mpsc::channel(FACADE_COMMAND_CAPACITY);

        // Session A floods up to its item limit
        let mut charges_a = Vec::new();
        for _ in 0..SESSION_COMMAND_CAPACITY {
            let charge =
                reserve_session_command(&shared_bytes, &session_a, COMMAND_OVERHEAD_CHARGE)
                    .expect("session A within quota");
            commands_tx
                .try_send(Command::Disconnect {
                    target: SessionTarget::Caller(crate::LogicalCallerId::for_test(0)),
                })
                .expect("channel has room");
            charges_a.push(charge);
        }
        // Session A is now blocked by its own quota:
        let err = match reserve_session_command(&shared_bytes, &session_a, COMMAND_OVERHEAD_CHARGE)
        {
            Ok(_) => panic!("session A must hit QueueFull once its quota is reached"),
            Err(err) => err,
        };
        assert!(matches!(err, FacadeError::QueueFull));

        // But Session B is completely untouched and can still reserve and send commands:
        let charge_b = reserve_session_command(&shared_bytes, &session_b, COMMAND_OVERHEAD_CHARGE)
            .expect("session B must have full admission headroom despite session A's flood");
        commands_tx
            .try_send(Command::Disconnect {
                target: SessionTarget::Caller(crate::LogicalCallerId::for_test(1)),
            })
            .expect("channel has room for session B");
        drop(charge_b);

        // Also test the byte quota dimension:
        let session_c = Arc::new(SessionControl::new());
        let large_charge =
            reserve_session_command(&shared_bytes, &session_c, SESSION_COMMAND_BYTES)
                .expect("session C reserves up to its byte quota");
        let byte_err = match reserve_session_command(&shared_bytes, &session_c, 1) {
            Ok(_) => panic!("session C must hit byte QueueFull"),
            Err(err) => err,
        };
        assert!(matches!(byte_err, FacadeError::QueueFull));

        // Session B still has headroom for smaller commands under the shared byte bound:
        let charge_b2 = reserve_session_command(&shared_bytes, &session_b, 1024)
            .expect("session B can still reserve bytes within shared limit");
        drop(charge_b2);
        drop(large_charge);

        // Once Session A's charges drop (as commands are processed), Session A can reserve again:
        charges_a.clear();
        assert_eq!(session_a.command_items.load(Ordering::Acquire), 0);
        let fresh_charge =
            reserve_session_command(&shared_bytes, &session_a, COMMAND_OVERHEAD_CHARGE)
                .expect("session A recovers once previous commands complete");
        drop(fresh_charge);

        // Drain the dummy commands so channels close cleanly
        while commands_rx.try_recv().is_ok() {}
    }

    /// F03: `drive_pending_sends`' every-tick service quantum
    /// (`DRIVER_COMMAND_QUANTUM`) previously always took the same first N
    /// targets in a `HashMap`'s (call-to-call stable) iteration order --
    /// with more backlogged destinations than the quantum, any destination
    /// past that cut was starved forever, not just delayed. `drain_targets`
    /// must rotate its start point so repeated calls eventually cover
    /// every destination, not the same prefix every time.
    #[test]
    fn drain_targets_rotates_so_every_destination_is_eventually_serviced() {
        let mut pending = PendingSends::default();
        let now = Timestamp::from_micros(0);
        const DESTINATIONS: u64 = 100;
        const QUANTUM: usize = 32;
        for id in 0..DESTINATIONS {
            let target = SessionTarget::Caller(crate::LogicalCallerId::for_test(id));
            push_expect_queued(&mut pending, target, vec![0u8; 4], now);
        }

        let mut seen = std::collections::HashSet::new();
        for _ in 0..(DESTINATIONS as usize).div_ceil(QUANTUM) + 2 {
            for target in pending.drain_targets(QUANTUM) {
                seen.insert(target);
            }
        }
        assert_eq!(
            seen.len(),
            DESTINATIONS as usize,
            "every backlogged destination must be visited within a bounded \
             number of ticks, not just the first {QUANTUM}"
        );
    }

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
                SrtConnection::new_caller(srt_proto::ConnectionOptions::default()),
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
        let mut caller = SrtConnection::new_caller(srt_proto::ConnectionOptions {
            socket_id: 1,
            ..Default::default()
        });
        let mut listener = SrtConnection::new_listener(srt_proto::ConnectionOptions {
            socket_id: 2,
            syn_cookie: Some(7),
            ..Default::default()
        });
        caller
            .connect(Timestamp::from_micros(0))
            .expect("caller starts");
        for round in 0..4 {
            let now = Timestamp::from_micros(round * 10_000);
            while let Some(ConnectionOutput::SendPacket(packet)) = caller
                .poll_output()
                .expect("exact-size output materializes")
            {
                listener
                    .feed_recv_buf(&packet, now)
                    .expect("listener accepts packet");
            }
            while let Some(ConnectionOutput::SendPacket(packet)) = listener
                .poll_output()
                .expect("exact-size output materializes")
            {
                caller
                    .feed_recv_buf(&packet, now)
                    .expect("caller accepts packet");
            }
            if caller.state() == srt_proto::ConnectionState::Connected {
                break;
            }
        }
        assert_eq!(caller.state(), srt_proto::ConnectionState::Connected);
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
            SrtConnection::new_caller(srt_proto::ConnectionOptions::default()),
            sock,
        );
        conn.pending_outputs
            .push_back(ConnectionOutput::SendPacket(b"first".to_vec()));
        conn.pending_outputs
            .push_back(ConnectionOutput::SendPacket(b"second".to_vec()));
        conn.pending_outputs.push_back(ConnectionOutput::SetTimer {
            id: srt_proto::TimerId::Ack,
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
        let mut group = srt_proto::SrtGroup::new(
            srt_proto::handshake::SRTGROUP_MASK | 1,
            GroupMode::Broadcast,
        )
        .expect("group builds");
        group
            .add_member(
                1,
                10,
                SrtConnection::new_caller(srt_proto::ConnectionOptions::default()),
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

            let group = crate::GroupConfig::new(42, srt_proto::handshake::GroupType::Broadcast);
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
            let group = crate::GroupConfig::new(45, srt_proto::handshake::GroupType::Broadcast);
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

    #[test]
    fn tokio_group_preserves_each_leg_receive_budget_and_batch_capacity() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let first_peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("first peer binds");
            let second_peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("second peer binds");
            let first_config =
                crate::CallerConfig::builder(first_peer.local_addr().expect("first address"))
                    .configure_transport(|transport| {
                        transport.batching = crate::BatchingPolicy::MaxDatagrams(
                            std::num::NonZeroUsize::new(3).expect("batch capacity"),
                        );
                        transport.recv_budget = RecvBudget::new(1, 2);
                    })
                    .build()
                    .expect("first caller config");
            let second_config =
                crate::CallerConfig::builder(second_peer.local_addr().expect("second address"))
                    .configure_transport(|transport| {
                        transport.batching = crate::BatchingPolicy::MaxDatagrams(
                            std::num::NonZeroUsize::new(7).expect("batch capacity"),
                        );
                        transport.recv_budget = RecvBudget::new(4, 9);
                    })
                    .build()
                    .expect("second caller config");
            let conn = GroupConn::caller(
                crate::GroupConfig::new(46, srt_proto::handshake::GroupType::Broadcast),
                [
                    GroupCallerLeg::new(1, 10, first_config),
                    GroupCallerLeg::new(2, 20, second_config),
                ],
                Timestamp::from_micros(0),
            )
            .expect("group caller");

            assert_eq!(conn.recv_batch.capacity(), 7);
            assert_eq!(conn.legs[0].recv_budget, RecvBudget::new(1, 2));
            assert_eq!(conn.legs[1].recv_budget, RecvBudget::new(4, 9));
            assert_eq!(conn.legs[0].batch_capacity, 3);
            assert_eq!(conn.legs[1].batch_capacity, 7);
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
                connection: SrtConnection::new_listener(srt_proto::ConnectionOptions {
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
            while let Some(output) = self
                .connection
                .poll_output()
                .expect("exact-size output materializes")
            {
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
        let group = crate::GroupConfig::new(44, srt_proto::handshake::GroupType::Broadcast);
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
            if conn
                .group()
                .members()
                .iter()
                .all(|member| member.connection().state() == srt_proto::ConnectionState::Connected)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(
            conn.group()
                .members()
                .iter()
                .all(|member| member.connection().state() == srt_proto::ConnectionState::Connected),
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
                    srt_proto::GroupMemberState::Active,
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
                    == srt_proto::GroupMemberState::Broken
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
                srt_proto::GroupMemberState::Active,
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
                    .all(|member| member.state() == srt_proto::GroupMemberState::Broken)
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

    #[test]
    fn drain_readable_counts_truncated_dequeues_against_the_recv_budget() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime builds");
        runtime.block_on(async {
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
            receiver.set_nonblocking(true).expect("nonblocking");
            let dest = receiver.local_addr().expect("addr");
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
            sender
                .send_to(&vec![0xA5; RecvBatch::DEFAULT_BUF_LEN + 1], dest)
                .expect("oversized datagram");
            sender
                .send_to(b"complete", dest)
                .expect("complete datagram");

            let sock = UdpSocket::from_std(receiver).expect("tokio adopts");
            sock.readable().await.expect("readable");
            let mut batch = RecvBatch::new();
            let mut delivered = Vec::new();
            let first = drain_readable(&sock, &mut batch, RecvBudget::new(1, 1), |_, data| {
                delivered.push(data.to_vec());
            })
            .expect("truncated drain");
            assert_eq!(first.datagrams, 0);
            assert_eq!(first.truncated, 1);
            assert!(delivered.is_empty());

            let second = drain_readable(&sock, &mut batch, RecvBudget::new(1, 1), |_, data| {
                delivered.push(data.to_vec());
            })
            .expect("remaining drain");
            assert_eq!(second.datagrams, 1);
            assert_eq!(delivered, vec![b"complete".to_vec()]);
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

            let batch_capacity = batch.capacity();
            let mut rest = Vec::new();
            drain_readable(
                &sock,
                &mut batch,
                RecvBudget::for_datagrams(TOTAL, batch_capacity),
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
                SrtConnection::new_caller(srt_proto::ConnectionOptions::default()),
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
                SrtConnection::new_caller(srt_proto::ConnectionOptions::default()),
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
