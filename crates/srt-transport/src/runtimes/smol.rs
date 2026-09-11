use crate::{
    BatchIoStats, OutputDrainBudget, OutputDrainReport, OutputDrainStatus, PacedSendOutcome,
    RecvBatch, RecvBudget, RecvDrainReport, collect_output_work, drain_output_work, drain_recv_fd,
    prepend_outputs, sendmsg_connected_batch,
};
use shiguredo_srt::{Bytes, ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

pub type UdpSocket = smol::Async<std::net::UdpSocket>;

/// Per-connection state for smol: protocol + async socket + timer deadlines.
pub struct Conn {
    pub conn: SrtConnection,
    pub sock: UdpSocket,
    timers: crate::ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
    recv_batch: RecvBatch,
    io_stats: BatchIoStats,
}

impl Conn {
    pub fn new(conn: SrtConnection, sock: UdpSocket) -> Self {
        Self {
            conn,
            sock,
            timers: crate::ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
            recv_batch: RecvBatch::new(),
            io_stats: BatchIoStats::default(),
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
        let report = OutputDrainReport {
            status: if exhausted {
                OutputDrainStatus::BudgetExhausted
            } else {
                OutputDrainStatus::Drained
            },
            ..Default::default()
        };
        let has_packets = work
            .iter()
            .any(|output| matches!(output, ConnectionOutput::SendPacket(_)));
        let work = if has_packets {
            prepend_outputs(&mut self.pending_outputs, work.into_iter());
            self.sock.writable().await?;
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget).0
        } else {
            work
        };
        let fd = self.sock.get_ref().as_raw_fd();
        let report = drain_output_work(
            work,
            &mut self.pending_outputs,
            &mut self.timers,
            now,
            report,
            |batch| sendmsg_connected_batch(fd, batch),
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

    pub fn recv_ready(
        &mut self,
        now: Timestamp,
        budget: RecvBudget,
    ) -> io::Result<RecvDrainReport> {
        let report = drain_recv_fd(
            self.sock.get_ref().as_raw_fd(),
            &mut self.recv_batch,
            budget,
            |_, data| {
                let _ = self.conn.feed_recv_buf(data, now);
            },
        )?;
        self.io_stats.record_recv(report);
        Ok(report)
    }

    pub async fn recv_with_timeout(&mut self, buf: &mut [u8], timeout: Duration, now: Timestamp) {
        let _ = buf;
        let recv_fut = async {
            self.sock.readable().await.ok()?;
            Some(())
        };
        let timer_fut = async {
            smol::Timer::after(timeout).await;
            None
        };
        if futures_lite::future::or(recv_fut, timer_fut)
            .await
            .is_some()
        {
            let _ = self.recv_ready(now, RecvBudget::default());
        }
    }

    pub fn try_recv(&self, buf: &mut [u8]) -> Option<std::io::Result<usize>> {
        match self.sock.get_ref().recv(buf) {
            Ok(n) => Some(Ok(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(e) => Some(Err(e)),
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

/// Resolve and bind a listener using smol-native async sockets.
pub fn bind_listener(
    config: &crate::ListenerConfig,
) -> Result<crate::RuntimeListener<UdpSocket>, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Smol)?;
    let sockets = prepared
        .bind_sockets()?
        .into_iter()
        .map(smol::Async::new)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::RuntimeListener { prepared, sockets })
}

/// Build one configured caller connection and connected smol socket.
pub fn caller(
    config: &crate::CallerConfig,
    now: Timestamp,
) -> Result<Conn, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Smol)?;
    let socket = smol::Async::new(prepared.bind_socket()?)?;
    Ok(Conn::new(prepared.connection(now)?, socket))
}

pub struct TickResult {
    pub sent: u64,
    pub events: Vec<ConnectionEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    /// S04: same cancellation-safety fix and rationale as
    /// `tokio_transport::tests::drain_outputs_bounded_survives_cancellation_while_parked_on_writable`.
    ///
    /// `async-io`'s reactor runs on its own background thread rather than
    /// only when an executor drives it, so unlike Tokio, a single manual
    /// `poll()` here is not guaranteed to observe `Pending` -- the
    /// background thread can race ahead and confirm writability first.
    /// This test accepts either outcome and checks the invariant that
    /// matters for each: if the future is still parked, cancelling it must
    /// not drop the staged output; if it raced to completion instead,
    /// every packet must have actually reached the peer.
    #[test]
    fn drain_outputs_bounded_loses_nothing_whether_cancelled_or_completed() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
        let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("local binds");
        local
            .connect(peer.local_addr().expect("peer address"))
            .expect("local connects to peer");
        peer.set_nonblocking(true).expect("peer is nonblocking");
        let sock = smol::Async::new(local).expect("async-io adopts the socket");

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
        let poll = future.as_mut().poll(&mut cx);
        drop(future);
        match poll {
            Poll::Pending => {
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
            Poll::Ready(result) => {
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
    }

    /// T02 checkpoint 3: `recv_ready` drains via `drain_recv_fd` directly
    /// on the raw fd, entirely outside async-io's own readiness
    /// bookkeeping -- so a budget yield here must not depend on a fresh
    /// `readable()` edge to resume. Verify that empirically: after a
    /// budget-exhausted drain with no new datagram arriving, a *fresh*
    /// `sock.readable()` call still resolves promptly (not hung behind an
    /// edge that never re-fires), and the remaining data is still there.
    #[test]
    fn budget_exhausted_drain_keeps_readiness_armed_without_a_new_edge() {
        futures_lite::future::block_on(async {
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("receiver");
            receiver.set_nonblocking(true).expect("nonblocking");
            let dest = receiver.local_addr().expect("addr");
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
            const TOTAL: usize = RecvBatch::DEFAULT_CAPACITY + 5;
            for i in 0..TOTAL {
                sender.send_to(&[i as u8], dest).expect("send");
            }
            let sock = smol::Async::new(receiver).expect("async-io adopts");
            sock.readable().await.expect("readable");

            let mut batch = RecvBatch::new();
            let mut first = Vec::new();
            let report = drain_recv_fd(
                sock.get_ref().as_raw_fd(),
                &mut batch,
                RecvBudget::new(1, RecvBatch::DEFAULT_CAPACITY),
                |_, data| first.push(data[0]),
            )
            .expect("first drain");
            assert_eq!(first.len(), RecvBatch::DEFAULT_CAPACITY);
            assert!(!report.would_block);

            // No new datagram arrives here -- nothing generates a fresh
            // edge for whatever triggering mode the reactor uses.
            let recv_fut = async {
                sock.readable().await.ok()?;
                Some(())
            };
            let timer_fut = async {
                smol::Timer::after(Duration::from_secs(5)).await;
                None
            };
            assert!(
                futures_lite::future::or(recv_fut, timer_fut)
                    .await
                    .is_some(),
                "readiness must still be armed without a new edge"
            );

            let mut rest = Vec::new();
            drain_recv_fd(
                sock.get_ref().as_raw_fd(),
                &mut batch,
                RecvBudget::until_would_block(),
                |_, data| rest.push(data[0]),
            )
            .expect("second drain");
            first.extend(rest);
            assert_eq!(first, (0..TOTAL as u8).collect::<Vec<_>>());
        });
    }
}
