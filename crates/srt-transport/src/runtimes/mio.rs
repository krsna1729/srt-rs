use crate::{
    BatchIoStats, ManualTimerStore, OutputDrainBudget, OutputDrainReport, drain_connected_outputs,
    sendmsg_connected_batch,
};
use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

/// Per-connection state for mio: protocol + owned socket + manual timers.
pub struct Conn {
    pub conn: SrtConnection,
    pub socket: mio::net::UdpSocket,
    pub timers: ManualTimerStore,
    pending_outputs: VecDeque<ConnectionOutput>,
    io_stats: BatchIoStats,
}

impl Conn {
    pub fn new(conn: SrtConnection, socket: mio::net::UdpSocket) -> Self {
        Self {
            conn,
            socket,
            timers: ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
            io_stats: BatchIoStats::default(),
        }
    }

    /// Fire expired manual timers.
    pub fn fire_expired(&mut self, now: Timestamp) {
        self.timers.fire_expired(now, &mut self.conn);
    }

    /// Compatibility wrapper using [`OutputDrainBudget::default`].
    /// Returns true only for `ECONNREFUSED`; transient failures remain
    /// queued for the next tick.
    pub fn drain_outputs(&mut self, now: Timestamp) -> bool {
        self.drain_outputs_bounded(now, OutputDrainBudget::default())
            .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused)
    }

    /// Drain a bounded amount of output, retaining every unsent datagram
    /// in protocol order on `WouldBlock`, partial `sendmmsg`, or error.
    pub fn drain_outputs_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
    ) -> io::Result<OutputDrainReport> {
        let report = drain_connected_outputs(
            &mut self.conn,
            &mut self.timers,
            &mut self.pending_outputs,
            now,
            budget,
            |batch| sendmsg_connected_batch(self.socket.as_raw_fd(), batch),
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

    /// Compute poll timeout from next timer deadline.
    pub fn poll_timeout(&self, default: Duration, now: Timestamp) -> Duration {
        Duration::from_micros(
            self.timers
                .time_until_earliest(now, default.as_micros() as u64),
        )
    }
}

/// Resolve, bind, and convert a complete listener configuration to mio
/// sockets. Applications retain the prepared policy and may drive their
/// own poll/worker architecture around it.
pub fn bind_listener(
    config: &crate::ListenerConfig,
) -> Result<crate::RuntimeListener<mio::net::UdpSocket>, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
    let sockets = prepared
        .bind_sockets()?
        .into_iter()
        .map(mio::net::UdpSocket::from_std)
        .collect();
    Ok(crate::RuntimeListener { prepared, sockets })
}

/// Build one configured caller connection and connected mio socket.
pub fn caller(
    config: &crate::CallerConfig,
    now: Timestamp,
) -> Result<Conn, crate::RuntimeBuildError> {
    let prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
    let socket = mio::net::UdpSocket::from_std(prepared.bind_socket()?);
    Ok(Conn::new(prepared.connection(now)?, socket))
}
