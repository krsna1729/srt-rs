use crate::{
    OutputDrainBudget, OutputDrainReport, OutputDrainStatus, PacedSendOutcome, collect_output_work,
    prepend_outputs,
};
use shiguredo_srt::{Bytes, ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

/// Per-connection state for monoio: protocol + owned-buffer socket + timer deadlines.
pub struct Conn {
    pub conn: SrtConnection,
    pub sock: monoio::net::udp::UdpSocket,
    timers: crate::ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
    output_drain: OutputDrainBudget,
}

impl Conn {
    pub fn new(conn: SrtConnection, sock: monoio::net::udp::UdpSocket) -> Self {
        Self::with_budgets(conn, sock, OutputDrainBudget::default())
    }

    /// Like [`Self::new`], but stores the given budget instead of the
    /// default (K02): [`Self::drain_outputs`] honors this, not a hardcoded
    /// `::default()`, on every call.
    pub fn with_budgets(
        conn: SrtConnection,
        sock: monoio::net::udp::UdpSocket,
        output_drain: OutputDrainBudget,
    ) -> Self {
        Self {
            conn,
            sock,
            timers: crate::ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
            output_drain,
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
        self.drain_outputs_bounded(now, self.output_drain).await
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
        // from directly below, one action at a time (bounded to exactly the
        // `budget`-capped count `collect_output_work` already computed --
        // `self.pending_outputs` itself may hold more behind these, left by
        // a prior cap), so a task cancelled while an owned-buffer send is in
        // flight loses at most the one buffer monoio's driver has already
        // taken ownership of -- never the not-yet-submitted remainder, which
        // stays durable throughout.
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
                ConnectionOutput::SendPacket(bytes) => {
                    let expected = bytes.len();
                    // Once submitted, monoio's driver owns `bytes` until the
                    // kernel completion arrives; a cancellation here (task
                    // dropped while this await is pending) hands the buffer
                    // to monoio's own cancel-on-drop path, and the datagram
                    // may or may not have already reached the wire. We
                    // deliberately do not try to recover or requeue it in
                    // that case -- SRT's own retransmission covers a
                    // genuinely lost packet, and requeuing a buffer that
                    // was already submitted risks sending a duplicate.
                    let (result, bytes) = self.sock.send(bytes).await;
                    match result {
                        Ok(sent) if sent == expected => {
                            report.actions += 1;
                            report.packets += 1;
                            report.bytes += sent;
                        }
                        Ok(_) => {
                            // The op completed (not cancelled): we observed
                            // the result, so it is safe to requeue exactly
                            // this datagram at the front.
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
                            return Err(error);
                        }
                    }
                }
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

    pub async fn recv_with_timeout(&mut self, timeout: Duration, now: Timestamp) {
        if let Ok((Ok(n), buf)) =
            monoio::time::timeout(timeout, self.sock.recv(vec![0u8; 2048])).await
        {
            let _ = self.conn.feed_recv_buf(&buf[..n], now);
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
}

/// Resolve and bind a listener using Monoio-native UDP sockets. Call from
/// the executor thread that will own them.
pub fn bind_listener(
    config: &crate::ListenerConfig,
) -> Result<crate::RuntimeListener<monoio::net::udp::UdpSocket>, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Monoio)?;
    let sockets = prepared
        .bind_sockets()?
        .into_iter()
        .map(monoio::net::udp::UdpSocket::from_std)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::RuntimeListener { prepared, sockets })
}

/// Build one configured caller connection and connected Monoio socket.
pub fn caller(
    config: &crate::CallerConfig,
    now: Timestamp,
) -> Result<Conn, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Monoio)?;
    let socket = monoio::net::udp::UdpSocket::from_std(prepared.bind_socket()?)?;
    Ok(Conn::with_budgets(
        prepared.connection(now)?,
        socket,
        prepared.transport.output_drain,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    /// K02: a `Conn` built via [`caller`] must actually drive with its
    /// configured `TransportConfig::output_drain`, not silently substitute
    /// [`OutputDrainBudget::default`] on every [`Conn::drain_outputs`] call.
    #[test]
    fn caller_constructs_a_conn_that_honors_its_configured_output_drain_budget() {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .build()
            .expect("monoio runtime builds");

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
        let remote = peer.local_addr().expect("peer address");

        let (status, pending_len) = runtime.block_on(async move {
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
            (report.status, conn.pending_outputs.len())
        });

        assert_eq!(status, OutputDrainStatus::BudgetExhausted);
        assert_eq!(
            pending_len, 1,
            "the second action must remain queued under a 1-action budget"
        );
    }

    /// S05 (Opus review): same fix and rationale as compio's
    /// `drain_outputs_bounded_does_not_exceed_the_budget_even_with_a_backlog`.
    #[test]
    fn drain_outputs_bounded_does_not_exceed_the_budget_even_with_a_backlog() {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .build()
            .expect("monoio runtime builds");

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
        let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
        local
            .connect(peer.local_addr().expect("peer address"))
            .expect("local connects to peer");
        peer.set_nonblocking(true).expect("peer is nonblocking");

        let (report, pending_len) = runtime.block_on(async move {
            let sock =
                monoio::net::udp::UdpSocket::from_std(local).expect("monoio adopts the socket");
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
            (report, conn.pending_outputs.len())
        });

        assert_eq!(
            report.packets, 2,
            "a budget of 2 packets must send exactly 2, not the whole backlog"
        );
        assert_eq!(report.status, OutputDrainStatus::BudgetExhausted);
        assert_eq!(
            pending_len, 3,
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
    }

    /// S05: same fix and rationale as compio's
    /// `drain_outputs_bounded_survives_cancellation_of_an_in_flight_send`.
    ///
    /// monoio has no public "enter the runtime without driving it" hook, so
    /// this drives the manual poll-then-drop from inside the one async
    /// block passed to `block_on`. `block_on`'s own loop polls that block
    /// first and only calls `driver.submit()`/`driver.park()` afterward, so
    /// as long as our block never awaits, it runs to completion (and we
    /// drop the drain future) before monoio ever flushes anything to
    /// io_uring -- the send is registered with the driver but never
    /// reaches the kernel.
    #[test]
    fn drain_outputs_bounded_survives_cancellation_of_an_in_flight_send() {
        let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
            .build()
            .expect("monoio runtime builds");

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
        let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
        local
            .connect(peer.local_addr().expect("peer address"))
            .expect("local connects to peer");
        peer.set_nonblocking(true).expect("peer is nonblocking");

        let (after, not_yet_submitted) = runtime.block_on(async move {
            let sock =
                monoio::net::udp::UdpSocket::from_std(local).expect("monoio adopts the socket");
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
            let not_yet_submitted: Vec<_> = conn.pending_outputs.iter().skip(1).cloned().collect();

            let budget = OutputDrainBudget::new(usize::MAX, usize::MAX, usize::MAX);
            let mut future =
                Box::pin(conn.drain_outputs_bounded(Timestamp::from_micros(0), budget));
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let polled = future.as_mut().poll(&mut cx);
            assert!(
                matches!(polled, Poll::Pending),
                "expected the first send to be registered with the driver but not yet \
                 flushed, got {polled:?}"
            );

            // Cancellation: drop the suspended future while the first send
            // is in flight and unobserved, before monoio's own loop ever
            // gets a chance to submit or reap it.
            drop(future);

            let after: Vec<_> = conn.pending_outputs.iter().cloned().collect();
            (after, not_yet_submitted)
        });

        assert_eq!(
            after, not_yet_submitted,
            "cancelling while the first send was in flight must leave every \
             not-yet-submitted packet and timer action exactly as staged, in order"
        );
    }
}
