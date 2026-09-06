use crate::{
    BatchIoStats, HighResWaiter, ManualTimerStore, MonotonicDeadline, OutputDrainBudget,
    OutputDrainReport, drain_connected_outputs, schedule_wait_micros, sendmsg_connected_batch,
};
use shiguredo_srt::{ConnectionOutput, SrtConnection, Timestamp};
use std::collections::VecDeque;
use std::hash::Hash;
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

    /// Relative delay until this connection's next paced send or protocol timer.
    ///
    /// The worker turns this into an absolute [`MonotonicDeadline`] on its
    /// shared [`HighResWaiter`] (issue #82 A2). This is not a per-connection
    /// tail-spin (A1).
    #[must_use]
    pub fn schedule_wait(&self, now: Timestamp) -> Duration {
        Duration::from_micros(schedule_wait_micros(
            self.conn.time_until_send(now),
            self.timers.time_until_earliest(now, u64::MAX),
        ))
    }

    /// Publish this connection onto a worker waiter and arm its next deadline.
    ///
    /// After [`HighResWaiter::wait`], the caller must service **every** due
    /// key. One packet per visit remains the contract; Route B multi-admit
    /// is out of scope.
    pub fn schedule_on<K>(
        &self,
        waiter: &mut HighResWaiter<K>,
        key: K,
        now: Timestamp,
    ) -> io::Result<()>
    where
        K: Clone + Eq + Hash,
    {
        waiter.register(key.clone(), self.socket.as_raw_fd())?;
        waiter.set_deadline(key, MonotonicDeadline::after(self.schedule_wait(now)));
        Ok(())
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

#[cfg(test)]
mod high_res_waiter_tests {
    use super::*;
    use shiguredo_srt::{ConnectionOptions, SrtConnection, Timestamp};
    use std::time::Duration;

    fn caller_conn() -> SrtConnection {
        let mut conn = SrtConnection::new_caller(ConnectionOptions::default());
        conn.connect(Timestamp::from_micros(0))
            .expect("connect starts");
        conn
    }

    #[test]
    fn schedule_on_arms_the_shared_worker_waiter() {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        std_sock.set_nonblocking(true).expect("nonblocking");
        let socket = mio::net::UdpSocket::from_std(std_sock);
        let conn = Conn::new(caller_conn(), socket);
        let mut waiter = HighResWaiter::<u32>::new().expect("waiter");
        conn.schedule_on(&mut waiter, 3, Timestamp::from_micros(0))
            .expect("schedule");
        assert_eq!(waiter.deadline_len(), 1);
        assert!(waiter.next_deadline().is_some());
        assert!(conn.schedule_wait(Timestamp::from_micros(0)) > Duration::ZERO);
    }
}
