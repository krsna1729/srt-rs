use crate::{
    OutputDrainBudget, OutputDrainReport, OutputDrainStatus, collect_output_work, prepend_outputs,
};
use shiguredo_srt::{Bytes, ConnectionEvent, ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::time::Duration;

/// Per-connection state for monoio: protocol + owned-buffer socket + timer deadlines.
pub struct Conn {
    pub conn: SrtConnection,
    pub sock: monoio::net::udp::UdpSocket,
    timers: crate::ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
}

impl Conn {
    pub fn new(conn: SrtConnection, sock: monoio::net::udp::UdpSocket) -> Self {
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
        let (mut work, exhausted) =
            collect_output_work(&mut self.conn, &mut self.pending_outputs, budget);
        let mut report = OutputDrainReport {
            status: if exhausted {
                OutputDrainStatus::BudgetExhausted
            } else {
                OutputDrainStatus::Drained
            },
            ..Default::default()
        };
        while let Some(out) = work.pop_front() {
            match out {
                ConnectionOutput::SendPacket(bytes) => {
                    let expected = bytes.len();
                    let (result, bytes) = self.sock.send(bytes).await;
                    match result {
                        Ok(sent) if sent == expected => {
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

    pub async fn send_shared_paced(&mut self, payload: Bytes, now: Timestamp) -> Result<(), ()> {
        if self.has_pending_outputs() || !self.conn.can_send_with_pacing(now) {
            return Err(());
        }
        self.conn.send_shared(payload, now).map_err(|_| ())?;
        let report = self.drain_outputs(now).await.map_err(|_| ())?;
        (report.status == OutputDrainStatus::Drained)
            .then_some(())
            .ok_or(())
    }

    pub async fn tick(&mut self, payload: &[u8], now: Timestamp) -> io::Result<TickResult> {
        self.fire_expired(now);
        self.recv_with_timeout(Duration::from_micros(100), now)
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
    Ok(Conn::new(prepared.connection(now)?, socket))
}

pub struct TickResult {
    pub sent: u64,
    pub events: Vec<ConnectionEvent>,
}
