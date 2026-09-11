use crate::{
    OutputDrainBudget, OutputDrainReport, OutputDrainStatus, PacedSendOutcome, collect_output_work,
    prepend_outputs,
};
use shiguredo_srt::{Bytes, ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

/// `crate::bind_reuseport` plus registration with the *current*
/// glommio executor's reactor -- must be called from inside a running
/// `LocalExecutor` (glommio's `From<socket2::Socket>` conversion looks
/// up the thread-local executor). Kept here rather than in bench code
/// so the `socket2` conversion detail doesn't need its own dependency
/// in srt-bench.
pub fn bind_reuseport(port: u16, sock_buf_bytes: usize) -> io::Result<glommio::net::UdpSocket> {
    from_std(crate::bind_reuseport(port, sock_buf_bytes)?)
}

/// Register an already-bound (and, for a handoff, already-connected)
/// `std::net::UdpSocket` with the *current* glommio executor's
/// reactor. Same executor-context requirement as `bind_reuseport`.
pub fn from_std(socket: std::net::UdpSocket) -> io::Result<glommio::net::UdpSocket> {
    Ok(glommio::net::UdpSocket::from(
        socket2_glommio::Socket::from(socket),
    ))
}

/// Per-connection state for glommio: protocol + borrowed-buffer socket + timer deadlines.
pub struct Conn {
    pub conn: SrtConnection,
    pub sock: glommio::net::UdpSocket,
    timers: crate::ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
}

impl Conn {
    pub fn new(conn: SrtConnection, sock: glommio::net::UdpSocket) -> Self {
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

    pub async fn drain_outputs(&mut self, now: Timestamp) -> io::Result<OutputDrainReport> {
        self.drain_outputs_bounded(now, OutputDrainBudget::default())
            .await
    }

    pub async fn drain_outputs_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
    ) -> io::Result<OutputDrainReport> {
        let (work, exhausted) =
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
        // S05: stage every collected action back into the driver-owned queue
        // before the first per-item await. `self.pending_outputs` is popped
        // from directly below, one action at a time, so a task cancelled
        // while a send is in flight loses at most the one datagram
        // glommio's reactor has already dispatched (or may be about to) --
        // never the not-yet-submitted remainder, which stays durable
        // throughout. glommio copies `bytes` into its own owned `DmaBuffer`
        // before ever awaiting (see `GlommioDatagram::send`), so there is
        // no use-after-free risk either way; we just don't know, on
        // cancellation, whether that copy's datagram reached the wire, and
        // deliberately don't try to requeue it -- SRT's own retransmission
        // covers a genuinely lost packet, and requeuing a datagram that was
        // already dispatched risks sending a duplicate. The loop below is
        // bounded to exactly the `budget`-capped count `collect_output_work`
        // already computed -- `self.pending_outputs` itself may hold more
        // behind these, left by a prior cap.
        let budget_count = work.len();
        prepend_outputs(&mut self.pending_outputs, work.into_iter());
        let mut report = OutputDrainReport {
            status: if exhausted {
                OutputDrainStatus::BudgetExhausted
            } else {
                OutputDrainStatus::Drained
            },
            ..Default::default()
        };
        for _ in 0..budget_count {
            let Some(out) = self.pending_outputs.pop_front() else {
                break;
            };
            match out {
                ConnectionOutput::SendPacket(bytes) => match self.sock.send(&bytes).await {
                    Ok(sent) if sent == bytes.len() => {
                        report.actions += 1;
                        report.packets += 1;
                        report.bytes += sent;
                    }
                    Ok(_) => {
                        // The op completed (not cancelled): we observed the
                        // result, so it is safe to requeue exactly this
                        // datagram at the front.
                        self.pending_outputs
                            .push_front(ConnectionOutput::SendPacket(bytes));
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "UDP send completed with a partial datagram",
                        ));
                    }
                    Err(error) => {
                        self.pending_outputs
                            .push_front(ConnectionOutput::SendPacket(bytes));
                        return Err(io::Error::other(error.to_string()));
                    }
                },
                other => {
                    self.timers.apply_output(&other, now);
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

    pub async fn recv_with_timeout(&mut self, buf: &mut [u8], timeout: Duration, now: Timestamp) {
        let recv_fut = async { self.sock.recv_from(buf).await.ok() };
        let timer_fut = async {
            glommio::timer::sleep(timeout).await;
            None
        };
        if let Some((n, _addr)) = futures_lite::future::or(recv_fut, timer_fut).await {
            let _ = self.conn.feed_recv_buf(&buf[..n], now);
        }
    }

    pub fn try_recv(
        &self,
        buf: &mut [u8],
    ) -> Option<std::io::Result<(usize, std::net::SocketAddr)>> {
        match futures_lite::future::block_on(futures_lite::future::poll_once(
            self.sock.recv_from(buf),
        )) {
            Some(Ok((n, addr))) => Some(Ok((n, addr))),
            Some(Err(e)) => Some(Err(e.into())),
            None => None,
        }
    }

    /// See [`PacedSendOutcome`] for what each outcome means (S03).
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

    /// Once accepted, the payload is retained by the protocol regardless of
    /// drain outcome -- a future bus caller must not resend it as new data
    /// on `DriverError`/`Accepted`, only on `NotDue`/`Rejected` (S02/S03).
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
            while matches!(self.send_paced(payload, now).await, PacedSendOutcome::Sent) {
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

/// Resolve and bind a listener on the current Glommio executor.
pub fn bind_listener(
    config: &crate::ListenerConfig,
) -> Result<crate::RuntimeListener<glommio::net::UdpSocket>, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Glommio)?;
    let sockets = prepared
        .bind_sockets()?
        .into_iter()
        .map(from_std)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::RuntimeListener { prepared, sockets })
}

/// Build one configured caller connection on the current Glommio executor.
pub fn caller(
    config: &crate::CallerConfig,
    now: Timestamp,
) -> Result<Conn, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Glommio)?;
    let socket = from_std(prepared.bind_socket()?)?;
    Ok(Conn::new(prepared.connection(now)?, socket))
}

pub struct TickResult {
    pub sent: u64,
    pub events: Vec<ConnectionEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S05 (Opus review): same fix and rationale as compio's
    /// `drain_outputs_bounded_does_not_exceed_the_budget_even_with_a_backlog`.
    /// Unlike the cancellation test below, this one is fully deterministic
    /// on this platform: the "yolo" synchronous fast path always completes
    /// the drain in one poll (see that test's doc for why), so there is no
    /// Pending/Ready ambiguity here.
    #[test]
    fn drain_outputs_bounded_does_not_exceed_the_budget_even_with_a_backlog() {
        glommio::LocalExecutorBuilder::default()
            .spawn(|| async move {
                let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
                let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
                local
                    .connect(peer.local_addr().expect("peer address"))
                    .expect("local connects to peer");
                peer.set_nonblocking(true).expect("peer is nonblocking");
                let sock = from_std(local).expect("glommio adopts the socket");

                let mut conn = Conn::new(
                    SrtConnection::new_caller(shiguredo_srt::ConnectionOptions::default()),
                    sock,
                );
                for i in 0..5u8 {
                    conn.pending_outputs
                        .push_back(ConnectionOutput::SendPacket(vec![i]));
                }

                let budget = OutputDrainBudget::new(usize::MAX, 2, usize::MAX);
                let report = conn
                    .drain_outputs_bounded(Timestamp::from_micros(0), budget)
                    .await
                    .expect("drain succeeds");
                assert_eq!(
                    report.packets, 2,
                    "a budget of 2 packets must send exactly 2, not the whole backlog"
                );
                assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
                assert_eq!(
                    conn.pending_outputs.len(),
                    3,
                    "the remaining 3 packets must still be queued, not sent or dropped"
                );

                let mut buf = [0u8; 64];
                let mut received = 0usize;
                while peer.recv(&mut buf).is_ok() {
                    received += 1;
                }
                assert_eq!(
                    received, 2,
                    "exactly 2 datagrams must have reached the wire"
                );
            })
            .expect("glommio executor spawns")
            .join()
            .expect("glommio executor runs to completion");
    }

    /// S05: same fix and rationale as compio's
    /// `drain_outputs_bounded_survives_cancellation_of_an_in_flight_send`.
    ///
    /// `glommio::send` copies the caller's slice into its own owned
    /// `DmaBuffer` before ever awaiting, and `Source::drop` defers buffer
    /// reclamation until the kernel completion arrives for anything
    /// already dispatched -- so there is no use-after-free hazard from
    /// cancelling here regardless of timing. `futures_lite::poll_once`
    /// polls the drain future exactly once and drops it immediately after
    /// (whether it was Ready or Pending), with no other `.await` in
    /// between -- so nothing else, including glommio's own io_uring
    /// submit/park step, can run in the gap.
    ///
    /// glommio also has a "yolo" fast path that tries a direct, synchronous
    /// send before ever touching io_uring; on Linux, a UDP send to a
    /// loopback peer essentially never blocks at the socket level
    /// (verified empirically -- even a minimum `SO_SNDBUF` and thousands
    /// of back-to-back sends never produced `WouldBlock`), so in practice
    /// this branch always completes the whole drain in this one poll and
    /// the io_uring path this fix targets isn't reachable from a unit
    /// test on this platform. The fix's correctness for that path is
    /// instead established by reading `Source::drop` above: a `Dispatched`
    /// op is cancelled via `cancel_request` and its buffer reclaimed only
    /// once the completion arrives, so ownership is never ambiguous. This
    /// test accepts either outcome and checks the invariant that matters
    /// for each: if the first send is still in flight, dropping it there
    /// must not lose the not-yet-submitted remainder; if the yolo path
    /// completed everything synchronously (the case this platform always
    /// takes), every packet
    /// must have actually reached the peer.
    #[test]
    fn drain_outputs_bounded_loses_nothing_whether_cancelled_or_completed() {
        glommio::LocalExecutorBuilder::default()
            .spawn(|| async move {
                let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
                let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
                local
                    .connect(peer.local_addr().expect("peer address"))
                    .expect("local connects to peer");
                peer.set_nonblocking(true).expect("peer is nonblocking");
                let sock = from_std(local).expect("glommio adopts the socket");

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
                let not_yet_submitted: Vec<_> =
                    conn.pending_outputs.iter().skip(1).cloned().collect();

                let budget = OutputDrainBudget::new(usize::MAX, usize::MAX, usize::MAX);
                let polled = futures_lite::future::poll_once(
                    conn.drain_outputs_bounded(Timestamp::from_micros(0), budget),
                )
                .await;
                match polled {
                    None => {
                        let after: Vec<_> = conn.pending_outputs.iter().cloned().collect();
                        assert_eq!(
                            after, not_yet_submitted,
                            "cancelling while the first send was in flight must leave \
                             every not-yet-submitted packet and timer action exactly \
                             as staged, in order"
                        );
                    }
                    Some(result) => {
                        result.expect("drain must not fail against a live loopback peer");
                        assert!(
                            !conn.has_pending_outputs(),
                            "a completed drain must not leave already-sent output queued"
                        );
                        let mut buf = [0u8; 64];
                        let mut received = Vec::new();
                        while let Ok(n) = peer.recv(&mut buf) {
                            received.push(buf[..n].to_vec());
                        }
                        assert_eq!(received, vec![b"first".to_vec(), b"second".to_vec()]);
                    }
                }
            })
            .expect("glommio executor spawns")
            .join()
            .expect("glommio executor runs to completion");
    }
}
