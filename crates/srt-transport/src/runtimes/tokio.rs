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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
        let budget = budget.intersect(self.output_drain);
        let (work, budget_exhausted) =
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
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
                collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
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
) -> io::Result<crate::SendFlushReport> {
    if outbound.is_empty() {
        return Ok(crate::SendFlushReport::default());
    }
    let result = sock.try_io(
        tokio::io::Interest::WRITABLE,
        || match crate::sendmsg_batch(sock.as_raw_fd(), outbound)? {
            0 if !outbound.is_empty() => Err(io::ErrorKind::WouldBlock.into()),
            n => Ok(n),
        },
    );
    match crate::apply_send_result(outbound, result) {
        Ok(report) => Ok(report),
        Err(_) => {
            // `sendmmsg` reports one error for the whole batch. A malformed
            // destination must not take down every logical session sharing
            // this egress socket, so retry packets individually and retire
            // only the destination that failed. A transient `WouldBlock`
            // keeps the suffix for the next writable wake.
            let mut report = crate::SendFlushReport::default();
            let index = 0;
            while index < outbound.len() {
                let (destination, packet) = &outbound[index];
                let result = sock.try_io(tokio::io::Interest::WRITABLE, || {
                    sock.try_send_to(packet, *destination)
                });
                match result {
                    Ok(_) => {
                        outbound.remove(index);
                        report.sent = report.sent.saturating_add(1);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        report.would_block = true;
                        break;
                    }
                    Err(_) => {
                        // A destination-specific error is isolated to this
                        // packet. Keeping it would make every future visit
                        // fail at the same item and starve healthy peers.
                        outbound.remove(index);
                    }
                }
            }
            Ok(report)
        }
    }
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
    poll_report: Option<crate::OutputDrainReport>,
) -> io::Result<crate::OutputDrainStatus> {
    status = match poll_report {
        Some(report) => status.combine(report.status),
        None => status.combine(if *write_blocked {
            crate::OutputDrainStatus::Backpressured
        } else {
            crate::OutputDrainStatus::BudgetExhausted
        }),
    };
    match send_destined_ready(sock, outbound) {
        Ok(report) => {
            *write_blocked = report.would_block;
            if report.would_block {
                status = status.combine(crate::OutputDrainStatus::Backpressured);
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

struct OwnerListenerSide {
    socket: UdpSocket,
    peers: crate::PeerTable,
    admission: crate::AdmissionOptions,
    telemetry: crate::IngressTelemetry,
    recv_batch: RecvBatch,
    outbound: Vec<(SocketAddr, Vec<u8>)>,
    idle_timeout: Duration,
    recv_budget: RecvBudget,
    output_drain: OutputDrainBudget,
    recv_pending: bool,
    write_blocked: bool,
}

struct OwnerCallerSide {
    socket: UdpSocket,
    callers: crate::CallerPool,
    recv_batch: RecvBatch,
    outbound: Vec<(SocketAddr, Vec<u8>)>,
    recv_budget: RecvBudget,
    output_drain: OutputDrainBudget,
    recv_pending: bool,
    write_blocked: bool,
    local_bind: Option<SocketAddr>,
    socket_buffer_bytes: usize,
}

/// The Tokio-native counterpart to [`crate::mio_transport::Owner`] (A03,
/// A04): one shared-socket listener side ([`crate::PeerTable`]) and one
/// shared-socket caller side ([`crate::CallerPool`]), driven by Tokio's own
/// async socket readiness (`UdpSocket::readable()`) instead of `mio::Poll`.
/// Every other design decision mirrors the Mio owner exactly -- same
/// `PerPort`-only listener topology, same `SocketOwnership::Shared`
/// requirement for callers, same IPv4-only send path restriction, same
/// effectively-unbounded default caller-pool policy overridable via
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
    expired_callers: Vec<crate::LogicalCallerId>,
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
            expired_callers: Vec::new(),
        }
    }

    /// Opt into real `max_in_flight`/`attempt_deadline` enforcement (A04)
    /// on the caller side, instead of the effectively-unbounded default.
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
        if !prepared.bind.is_ipv4() {
            // Same reasoning as the Mio owner: sendmsg_batch is IPv4-only
            // and one bad destination fails the whole shared batch.
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "listener.bind",
                "Owner's send path (sendmsg_batch) is IPv4-only; bind an \
                 IPv4 address instead of an IPv6 or dual-stack one",
            )));
        }
        let mut sockets = prepared.bind_sockets()?;
        let socket = UdpSocket::from_std(sockets.remove(0))?;
        self.listener = Some(OwnerListenerSide {
            socket,
            admission: prepared.admission_options(),
            idle_timeout: prepared.admission.idle_timeout,
            peers: prepared.peer_table(),
            telemetry: crate::IngressTelemetry::new(),
            recv_batch: RecvBatch::new(),
            outbound: Vec::new(),
            recv_budget: prepared.transport.recv_budget,
            output_drain: prepared.transport.output_drain,
            recv_pending: false,
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
        let prepared = config.prepare(crate::RuntimeFlavor::Tokio)?;
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
        if let Some(side) = self.caller.as_ref()
            && (side.local_bind != prepared.local_bind
                || side.socket_buffer_bytes != prepared.transport.socket_buffer_bytes)
        {
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.transport",
                "later Shared callers must use the first caller socket's local bind and socket buffer configuration",
            )));
        }
        if self.caller.is_none() {
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
                recv_batch: RecvBatch::new(),
                outbound: Vec::new(),
                recv_budget: prepared.transport.recv_budget,
                output_drain: prepared.transport.output_drain,
                recv_pending: false,
                write_blocked: false,
                local_bind: prepared.local_bind,
                socket_buffer_bytes: prepared.transport.socket_buffer_bytes,
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
        let continuation = self.listener.as_ref().is_some_and(|side| side.recv_pending)
            || self.caller.as_ref().is_some_and(|side| side.recv_pending);
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
                side.recv_budget,
                |addr, data| {
                    let Some(peer) = addr else { return };
                    let _ = peers.admit(peer, data, recv_now, admission, 0, 1, telemetry);
                },
            )?;
            side.recv_pending = receive_continuation(report, side.recv_budget);
        }
        if let Some(side) = self.caller.as_mut() {
            let callers = side.callers.table_mut();
            let report = drain_readable(
                &side.socket,
                &mut side.recv_batch,
                side.recv_budget,
                |addr, data| {
                    let Some(peer) = addr else { return };
                    let _ = callers.feed(peer, data, recv_now);
                },
            )?;
            side.recv_pending = receive_continuation(report, side.recv_budget);
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
        if let Some(side) = self.listener.as_mut() {
            side.peers.prune_idle(now, side.idle_timeout);
            let budget = caller_budget.intersect(side.output_drain);
            let poll_report = if side.outbound.is_empty() {
                Some(
                    side.peers
                        .poll_outbound_bounded(now, budget, &mut side.outbound),
                )
            } else {
                None
            };
            status = drive_side_output(
                &side.socket,
                &mut side.outbound,
                &mut side.write_blocked,
                status,
                poll_report,
            )?;
        }
        if let Some(side) = self.caller.as_mut() {
            let expired = side.callers.poll_expirations(now);
            self.expired_callers.extend(expired);
            let budget = caller_budget.intersect(side.output_drain);
            let poll_report = if side.outbound.is_empty() {
                Some(side.callers.table_mut().poll_outbound_bounded(
                    now,
                    budget,
                    &mut side.outbound,
                ))
            } else {
                None
            };
            status = drive_side_output(
                &side.socket,
                &mut side.outbound,
                &mut side.write_blocked,
                status,
                poll_report,
            )?;
        }
        Ok(status)
    }

    /// Drain admitted-peer lifecycle/data events for the application.
    pub fn poll_listener_events(&mut self, out: &mut Vec<crate::AdmissionEvent>) {
        out.clear();
        let Some(side) = self.listener.as_mut() else {
            return;
        };
        side.peers.poll_events(out);
    }

    /// Drain protocol events (A05) for every direct outbound session --
    /// the caller-side counterpart to [`Self::poll_listener_events`].
    pub fn poll_caller_events(&mut self, out: &mut Vec<crate::CallerEvent>) {
        out.clear();
        let Some(side) = self.caller.as_mut() else {
            return;
        };
        side.callers.table_mut().poll_events(out);
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
        self.caller.as_mut()?.callers.table_mut().remove(id)
    }

    /// Return and clear caller attempts retired by the bounded pool deadline.
    /// A facade uses this edge-triggered list to fail cancelled/expired
    /// `connect()` futures and reclaim their routing state.
    pub fn drain_expired_callers(&mut self, out: &mut Vec<crate::LogicalCallerId>) {
        out.clear();
        out.append(&mut self.expired_callers);
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
    /// Opus review finding 4: this does not fold in
    /// `has_pending_output`/`has_pending_events` the way `mio_transport`'s
    /// equivalent does, so a `BudgetExhausted` drain or output queued
    /// between ticks is not guaranteed an immediate revisit -- a real
    /// latency/throughput note under sustained load. A fix was attempted
    /// (routing both sides through their ready-queue `has_pending_output`
    /// the same way `mio_transport::Owner` does) but reproducibly made
    /// `a_closed_sessions_table_entry_is_actually_reclaimed` fail: the
    /// caller-side close no longer completed within the test's budget,
    /// and the exact mechanism was not pinned down before this pass ran
    /// out of budget to investigate further (the reported deadline at the
    /// point of the stall was a genuine, large, and correctly-decreasing
    /// value from `CallerPool::time_until_next_deadline` itself, not an
    /// obviously wrong number -- something earlier in the close sequence
    /// stops progressing before that point is reached). Left as the
    /// original, narrower calculation rather than ship a change that
    /// regresses an existing, previously-passing test; tracked as an open
    /// follow-up, not a numbered card.
    #[must_use]
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        let listener = self
            .listener
            .as_mut()
            .map(|side| side.peers.time_until_next_deadline(now, u64::MAX));
        let caller = self
            .caller
            .as_ref()
            .map(|side| side.callers.table().time_until_next_deadline(now, u64::MAX));
        let pending_output = self
            .listener
            .as_ref()
            .is_some_and(|side| !side.outbound.is_empty() && !side.write_blocked)
            || self
                .caller
                .as_ref()
                .is_some_and(|side| !side.outbound.is_empty() && !side.write_blocked);
        let next = match (listener, caller) {
            (Some(a), Some(b)) => a.min(b).min(default_us),
            (Some(a), None) | (None, Some(a)) => a.min(default_us),
            (None, None) => default_us,
        };
        if pending_output { 0 } else { next }
    }
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
    Build(crate::RuntimeBuildError),
    Protocol(shiguredo_srt::Error),
}

impl std::fmt::Display for FacadeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DriverGone => write!(f, "the Facade driver task is no longer running"),
            Self::PoolFull => write!(f, "the caller pool is at max_in_flight capacity"),
            Self::QueueFull => write!(f, "the Facade queue is full"),
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
            Self::DriverGone | Self::PoolFull | Self::QueueFull => None,
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
const DRIVER_COMMAND_QUANTUM: usize = 32;

struct CommandCharge {
    used: Arc<AtomicUsize>,
    amount: usize,
}

impl Drop for CommandCharge {
    fn drop(&mut self) {
        self.used.fetch_sub(self.amount, Ordering::AcqRel);
    }
}

fn reserve_command_bytes(
    used: &Arc<AtomicUsize>,
    amount: usize,
) -> Result<CommandCharge, FacadeError> {
    if amount > FACADE_COMMAND_BYTES {
        return Err(FacadeError::QueueFull);
    }
    loop {
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
            });
        }
    }
}

struct SessionControl {
    dropped: AtomicBool,
    close_requested: AtomicBool,
    disconnect_sent: AtomicBool,
    closed: AtomicBool,
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
            reap_grace_ticks: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn is_unavailable(&self) -> bool {
        self.dropped.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire)
    }
}

struct InboundItem {
    payload: shiguredo_srt::Bytes,
    bytes: Arc<AtomicUsize>,
}

impl Drop for InboundItem {
    fn drop(&mut self) {
        self.bytes.fetch_sub(self.payload.len(), Ordering::AcqRel);
    }
}

impl InboundItem {
    fn into_payload(mut self) -> shiguredo_srt::Bytes {
        let payload = std::mem::replace(&mut self.payload, shiguredo_srt::Bytes::new());
        self.bytes.fetch_sub(payload.len(), Ordering::AcqRel);
        payload
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

    fn try_send(&self, payload: shiguredo_srt::Bytes) -> InboxSend {
        if self.control.is_unavailable() {
            return InboxSend::Closed;
        }
        let length = payload.len();
        if length > SESSION_INBOUND_BYTES {
            return InboxSend::Full;
        }
        loop {
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
                break;
            }
        }
        let item = InboundItem {
            payload,
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
    reply: tokio::sync::oneshot::Sender<Result<(), FacadeError>>,
}

#[derive(Default)]
struct PendingSends {
    by_target: std::collections::HashMap<SessionTarget, VecDeque<PendingSend>>,
    items: usize,
    bytes: usize,
}

impl PendingSends {
    fn has_capacity(&self, payload_len: usize) -> bool {
        self.items < SESSION_PENDING_SENDS
            && self.bytes.saturating_add(payload_len) <= SESSION_PENDING_BYTES
    }

    /// A target with anything already queued must stay queued: sending a
    /// fresh command straight through the moment pacing allows it, while an
    /// earlier payload for the same target is still waiting in `by_target`,
    /// would reorder that earlier payload behind this one on the wire.
    fn has_pending(&self, target: SessionTarget) -> bool {
        self.by_target.contains_key(&target)
    }

    fn push(
        &mut self,
        target: SessionTarget,
        payload: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<Result<(), FacadeError>>,
    ) -> Result<(), FacadeError> {
        if self.items >= SESSION_PENDING_SENDS
            || self.bytes.saturating_add(payload.len()) > SESSION_PENDING_BYTES
        {
            return Err(FacadeError::QueueFull);
        }
        self.bytes = self.bytes.saturating_add(payload.len());
        self.items += 1;
        self.by_target
            .entry(target)
            .or_default()
            .push_back(PendingSend { payload, reply });
        Ok(())
    }

    fn pop(&mut self, target: SessionTarget) -> Option<PendingSend> {
        let queue = self.by_target.get_mut(&target)?;
        let pending = queue.pop_front()?;
        self.items = self.items.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(pending.payload.len());
        if queue.is_empty() {
            self.by_target.remove(&target);
        }
        Some(pending)
    }

    fn targets(&self) -> impl Iterator<Item = SessionTarget> + '_ {
        self.by_target.keys().copied()
    }

    fn fail_target(&mut self, target: SessionTarget) {
        while let Some(pending) = self.pop(target) {
            let _ = pending
                .reply
                .send(Err(FacadeError::Protocol(session_gone_error())));
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
}

impl Session {
    /// Send one payload. Resolves once the driver task has actually
    /// attempted the send (not merely queued the request), so a
    /// [`FacadeError::Protocol`] reliably reflects this specific call, not
    /// a stale error from an earlier one.
    pub async fn send(&self, payload: impl Into<Vec<u8>>) -> Result<(), FacadeError> {
        let payload = payload.into();
        let charge = reserve_command_bytes(
            &self.command_bytes,
            payload.len().saturating_add(COMMAND_OVERHEAD_CHARGE),
        )?;
        let (reply, reply_rx) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(Command::Send {
                target: self.target,
                payload,
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
    pub async fn recv(&mut self) -> Option<shiguredo_srt::Bytes> {
        self.inbound.recv().await.map(InboundItem::into_payload)
    }

    /// Start an orderly close. Fire-and-forget: does not wait for the
    /// close to complete -- await [`Self::recv`] returning `None`, or just
    /// drop this `Session`, to know it eventually has.
    pub fn close(&self) {
        self.control.close_requested.store(true, Ordering::Release);
        let _ = self.commands.try_send(Command::Disconnect {
            target: self.target,
        });
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.control.dropped.store(true, Ordering::Release);
        // This is a best-effort fast path. If a bounded command queue is
        // full, the driver's control scan below performs the same reclaim
        // without introducing an unbounded drop queue.
        let _ = self.commands.try_send(Command::Disconnect {
            target: self.target,
        });
    }
}

fn session_gone_error() -> shiguredo_srt::Error {
    shiguredo_srt::Error::with_reason(
        shiguredo_srt::ErrorKind::InvalidState,
        "session no longer exists",
    )
}

/// Reasons a pending [`Command::Connect`] never gets a session: the
/// connection failed before ever reaching `Connected` (rejected handshake,
/// timeout, ...), or the driver is stopping and can no longer wait for it.
fn connect_failed_error() -> shiguredo_srt::Error {
    shiguredo_srt::Error::with_reason(
        shiguredo_srt::ErrorKind::InvalidState,
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
    pending_sends: &mut PendingSends,
) {
    match command {
        Command::Connect { config, reply, .. } => {
            handle_connect_command(owner, &config, reply, now, pending_connects);
        }
        Command::Send {
            target,
            payload,
            reply,
            ..
        } => {
            handle_send_command(owner, target, payload, reply, now, pending_sends);
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
        if !pending_sends.has_capacity(payload.len()) {
            // The queue owns no reply once this branch returns, so make
            // backpressure explicit to this exact caller. `payload` is
            // dropped with the failed command.
            let _ = reply.send(Err(FacadeError::QueueFull));
        } else {
            let _ = pending_sends.push(target, payload, reply);
        }
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
    let targets = pending
        .targets()
        .take(DRIVER_COMMAND_QUANTUM)
        .collect::<Vec<_>>();
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
    now: Timestamp,
) {
    let targets = controls
        .iter()
        .filter_map(|(target, control)| {
            let dropped = control.dropped.load(Ordering::Acquire);
            let close_requested = control.close_requested.load(Ordering::Acquire);
            if dropped && !close_requested {
                return Some((*target, false));
            }
            if close_requested {
                let already_sent = control.disconnect_sent.swap(true, Ordering::AcqRel);
                if !already_sent {
                    return Some((*target, true));
                }
                // Every external handle is gone too: nothing is left to
                // ever observe the matching `Disconnected` event, which
                // may never arrive at all against an unreachable or
                // non-responsive peer. Rather than pin this entry -- and
                // its `SessionInbox`'s buffered bytes -- forever, force it
                // once this scan has seen the same dropped-and-sent state
                // for a few driver ticks in a row (Opus review finding 5):
                // that's enough real ticks for the SHUTDOWN `drive()`
                // already queued on some ordinary iteration to have had a
                // real dispatch attempt, without this function forcing an
                // out-of-band `drive()` call of its own -- doing that
                // reproducibly broke
                // `a_closed_sessions_table_entry_is_actually_reclaimed`.
                if dropped {
                    let ticks = control.reap_grace_ticks.fetch_add(1, Ordering::AcqRel);
                    if ticks >= REAP_GRACE_TICKS {
                        return Some((*target, false));
                    }
                }
            }
            None
        })
        .collect::<Vec<_>>();
    for (target, orderly) in targets {
        if orderly {
            reap_send_disconnect(owner, target, now);
        } else {
            reap_remove_session(
                owner,
                target,
                listener_inboxes,
                caller_inboxes,
                controls,
                pending_sends,
            );
        }
    }
}

/// Driver ticks a dropped session's orderly close is given to actually
/// leave the socket (via whatever ordinary `drive()` call the loop makes
/// on its own) before [`reap_session_controls`] force-removes it.
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
) {
    let cancelled = pending_connects
        .iter()
        .filter_map(|(id, reply)| reply.is_closed().then_some(*id))
        .collect::<Vec<_>>();
    for id in cancelled {
        pending_connects.remove(&id);
        owner.remove_caller(id);
        remove_session_state(
            SessionTarget::Caller(id),
            &mut std::collections::HashMap::new(),
            caller_inboxes,
            controls,
            pending_sends,
        );
    }
}

async fn run_driver(
    mut owner: Owner,
    mut commands: tokio::sync::mpsc::Receiver<Command>,
    commands_tx: tokio::sync::mpsc::WeakSender<Command>,
    accept_tx: tokio::sync::mpsc::Sender<Session>,
    command_bytes: Arc<AtomicUsize>,
) {
    let start = std::time::Instant::now();
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
                        handle_command(&mut owner, command, now(), &mut pending_connects, &mut pending_sends);
                    }
                    None => break, // every Facade/Session handle dropped -> graceful shutdown
                }
            }
        }

        drive_pending_sends(&mut owner, &mut pending_sends, now());

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
            now(),
        );
        fail_cancelled_connects(
            &mut owner,
            &mut pending_connects,
            &mut caller_inboxes,
            &mut controls,
            &mut pending_sends,
        );

        let sessions = SessionFactory {
            commands_tx: &commands_tx,
            command_bytes: &command_bytes,
        };

        owner.poll_listener_events(&mut listener_events);
        for event in listener_events.drain(..) {
            route_listener_event(
                &mut owner,
                event,
                &sessions,
                &mut listener_inboxes,
                &mut controls,
                &mut pending_sends,
                &accept_tx,
            );
        }

        owner.poll_caller_events(&mut caller_events);
        for event in caller_events.drain(..) {
            route_caller_event(
                &mut owner,
                event,
                &sessions,
                &mut caller_inboxes,
                &mut controls,
                &mut pending_connects,
                &mut pending_sends,
            );
        }
    }

    // The loop above can `break` with a just-queued SHUTDOWN (from a
    // `Command::Disconnect` this same tick handled, or the very last thing
    // an application did before dropping every handle) still sitting in
    // `Owner`'s own output queue -- `drive()` is what actually attempts the
    // send, and nothing after the `break` ever called it again. One more
    // synchronous attempt here is enough for the overwhelmingly common
    // case (a UDP send essentially never blocks), closing the gap between
    // "close() was requested" and "the driver task ended" that graceful
    // shutdown depends on.
    let _ = owner.drive(now(), OutputDrainBudget::default());
}

/// Bundles what every new `Session` needs from `run_driver` (a weak
/// command sender plus the shared command-byte counter) into one
/// argument, so `route_listener_event`/`route_caller_event` stay under
/// clippy's argument-count ceiling despite each needing several other
/// independent pieces of driver state too.
struct SessionFactory<'a> {
    commands_tx: &'a tokio::sync::mpsc::WeakSender<Command>,
    command_bytes: &'a Arc<AtomicUsize>,
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
        };
        Some((session, inbox, control))
    }
}

/// Route one listener-side event to its `Session`'s inbound channel
/// (`DataReceived`), retire it (`Disconnected`), or mint a new `Session`
/// and hand it to `accept()` (`Connected`) -- split out of [`run_driver`]'s
/// own loop body to keep its cognitive complexity down.
fn route_listener_event(
    owner: &mut Owner,
    event: crate::AdmissionEvent,
    sessions: &SessionFactory<'_>,
    listener_inboxes: &mut std::collections::HashMap<crate::LogicalPeerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_sends: &mut PendingSends,
    accept_tx: &tokio::sync::mpsc::Sender<Session>,
) {
    let target = SessionTarget::Listener(event.logical_peer);
    match event.event {
        shiguredo_srt::ConnectionEvent::Connected => {
            let Some((session, inbox, control)) = sessions.mint(target) else {
                return;
            };
            listener_inboxes.insert(event.logical_peer, inbox);
            controls.insert(target, control);
            // `accept_tx.try_send` fails once the `Facade` (which owns
            // the matching receiver) is gone, or once `FACADE_ACCEPT_CAPACITY`
            // admitted-but-undrained sessions are already queued -- in
            // either case this session has no handle anywhere that will
            // ever claim it, so retire it from `Owner` immediately rather
            // than leaking it the same way a cancelled `connect()` would
            // (see `route_caller_event`).
            if accept_tx.try_send(session).is_err() {
                listener_inboxes.remove(&event.logical_peer);
                controls.remove(&target);
                pending_sends.fail_target(target);
                owner.remove_listener_peer(event.logical_peer);
            }
        }
        shiguredo_srt::ConnectionEvent::DataReceived { payload, .. } => {
            // A full or closed inbox retires this session exactly like a
            // genuine `Disconnected` below (course correction #1): a
            // consumer that fell far enough behind is disconnected, not
            // grown without bound or silently starved forever.
            let deliverable = listener_inboxes
                .get(&event.logical_peer)
                .is_some_and(|inbox| matches!(inbox.try_send(payload), InboxSend::Sent));
            if !deliverable {
                listener_inboxes.remove(&event.logical_peer);
                controls.remove(&target);
                pending_sends.fail_target(target);
                owner.remove_listener_peer(event.logical_peer);
            }
        }
        shiguredo_srt::ConnectionEvent::Disconnected { .. } => {
            listener_inboxes.remove(&event.logical_peer);
            if let Some(control) = controls.remove(&target) {
                control.closed.store(true, Ordering::Release);
            }
            pending_sends.fail_target(target);
            // A `disconnect()` alone (this event firing) only transitions
            // protocol state; the table entry and its buffers stay
            // resident until something calls `remove` (see
            // `Owner::remove_listener_peer`'s own doc comment). The
            // `Facade` is the only application code that ever sees this
            // peer, so it must be the one to retire it, or a long-lived
            // `Facade` serving many short sessions leaks one table entry
            // per closed session for the rest of the driver task's life.
            owner.remove_listener_peer(event.logical_peer);
        }
        shiguredo_srt::ConnectionEvent::StateChanged(_)
        | shiguredo_srt::ConnectionEvent::Error(_)
        | shiguredo_srt::ConnectionEvent::KeyRefreshNeeded { .. } => {}
    }
}

/// Route one caller-side event: fulfill a pending [`Facade::connect`] once
/// it reaches `Connected`, forward `DataReceived` to its `Session`'s
/// inbound channel, or retire it and fail any still-pending connect once
/// the attempt is truly over -- split out of [`run_driver`]'s own loop body
/// to keep its cognitive complexity down.
fn route_caller_event(
    owner: &mut Owner,
    event: crate::CallerEvent,
    sessions: &SessionFactory<'_>,
    caller_inboxes: &mut std::collections::HashMap<crate::LogicalCallerId, SessionInbox>,
    controls: &mut std::collections::HashMap<SessionTarget, Arc<SessionControl>>,
    pending_connects: &mut std::collections::HashMap<
        crate::LogicalCallerId,
        tokio::sync::oneshot::Sender<Result<Session, FacadeError>>,
    >,
    pending_sends: &mut PendingSends,
) {
    match event.event {
        shiguredo_srt::ConnectionEvent::Connected => {
            let Some(reply) = pending_connects.remove(&event.id) else {
                return;
            };
            let target = SessionTarget::Caller(event.id);
            let Some((session, inbox, control)) = sessions.mint(target) else {
                return;
            };
            caller_inboxes.insert(event.id, inbox);
            controls.insert(target, control);
            // `reply.send` fails only if `Facade::connect`'s own future
            // was already dropped (cancelled) before this arrived -- the
            // connection is fully established with no handle anywhere
            // and nothing left to ever close it, so tear it down here
            // rather than leak it silently for the driver's whole life.
            if reply.send(Ok(session)).is_err() {
                caller_inboxes.remove(&event.id);
                controls.remove(&target);
                owner.remove_caller(event.id);
            }
        }
        shiguredo_srt::ConnectionEvent::DataReceived { payload, .. } => {
            // See `route_listener_event`'s identical handling for why a
            // failed delivery retires the session instead of growing its
            // backlog or silently discarding data forever.
            let deliverable = caller_inboxes
                .get(&event.id)
                .is_some_and(|inbox| matches!(inbox.try_send(payload), InboxSend::Sent));
            if !deliverable {
                let target = SessionTarget::Caller(event.id);
                caller_inboxes.remove(&event.id);
                controls.remove(&target);
                pending_sends.fail_target(target);
                owner.remove_caller(event.id);
            }
        }
        shiguredo_srt::ConnectionEvent::Disconnected { .. } => {
            let target = SessionTarget::Caller(event.id);
            if let Some(reply) = pending_connects.remove(&event.id) {
                let _ = reply.send(Err(FacadeError::Protocol(connect_failed_error())));
            }
            caller_inboxes.remove(&event.id);
            if let Some(control) = controls.remove(&target) {
                control.closed.store(true, Ordering::Release);
            }
            pending_sends.fail_target(target);
            // See `route_listener_event`'s identical call for why this
            // must happen here rather than never.
            owner.remove_caller(event.id);
        }
        // A handshake that never reaches `Connected` -- rejected, or
        // timed out -- ends here, not at `ConnectionEvent::Disconnected`:
        // that event is emitted only by a peer's SHUTDOWN or a graceful
        // local close, both of which presuppose the connection was
        // already `Connected` at some point. Without also failing a
        // pending connect on this transition, `Facade::connect()` against
        // any address that never answers (or that actively rejects the
        // handshake) never resolves at all.
        shiguredo_srt::ConnectionEvent::StateChanged(
            shiguredo_srt::ConnectionState::Disconnected,
        ) => {
            let target = SessionTarget::Caller(event.id);
            if let Some(reply) = pending_connects.remove(&event.id) {
                let _ = reply.send(Err(FacadeError::Protocol(connect_failed_error())));
            }
            caller_inboxes.remove(&event.id);
            if let Some(control) = controls.remove(&target) {
                control.closed.store(true, Ordering::Release);
            }
            pending_sends.fail_target(target);
            owner.remove_caller(event.id);
        }
        shiguredo_srt::ConnectionEvent::StateChanged(_)
        | shiguredo_srt::ConnectionEvent::Error(_)
        | shiguredo_srt::ConnectionEvent::KeyRefreshNeeded { .. } => {}
    }
}

/// A managed, ergonomic async facade (A05 checkpoint 1) around [`Owner`]:
/// spawns a background driver task and communicates with it over bounded
/// application-facing handles ([`Session`]) backed by unbounded internal
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
        let handle = tokio::spawn(run_driver(
            owner,
            commands_rx,
            commands_tx.downgrade(),
            accept_tx,
            Arc::clone(&command_bytes),
        ));
        Ok((
            Self {
                commands: commands_tx,
                command_bytes,
                accept: accept_rx,
                listener_local_addr,
            },
            handle,
        ))
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
                panic!("default pool policy is unbounded, so connect() must admit immediately")
            };

            let mut peer_id = None;
            let connected =
                drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
                    let mut events = Vec::new();
                    owner.poll_listener_events(&mut events);
                    for event in events {
                        if let shiguredo_srt::ConnectionEvent::Connected = event.event {
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
                        && let shiguredo_srt::ConnectionEvent::DataReceived { payload, .. } =
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
                        && matches!(
                            event.event,
                            shiguredo_srt::ConnectionEvent::Disconnected { .. }
                        )
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
            assert_eq!(received.as_ref(), b"known message");

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
                assert_eq!(received.as_ref(), format!("active {i}").into_bytes());
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
                assert_eq!(payload.as_ref(), format!("backlog {i}").into_bytes());
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
            assert_eq!(received.as_ref(), b"after a drop");
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
