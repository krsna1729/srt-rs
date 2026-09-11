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
    output_drain: OutputDrainBudget,
}

impl Conn {
    pub fn new(conn: SrtConnection, socket: mio::net::UdpSocket) -> Self {
        Self::with_budgets(conn, socket, OutputDrainBudget::default())
    }

    /// Like [`Self::new`], but stores the given budget instead of the
    /// default (K02): [`Self::drain_outputs`] honors this, not a hardcoded
    /// `::default()`, on every call.
    pub fn with_budgets(
        conn: SrtConnection,
        socket: mio::net::UdpSocket,
        output_drain: OutputDrainBudget,
    ) -> Self {
        Self {
            conn,
            socket,
            timers: ManualTimerStore::new(),
            pending_outputs: VecDeque::new(),
            io_stats: BatchIoStats::default(),
            output_drain,
        }
    }

    /// Fire expired manual timers.
    pub fn fire_expired(&mut self, now: Timestamp) {
        self.timers.fire_expired(now, &mut self.conn);
    }

    /// Compatibility wrapper using this `Conn`'s stored output budget.
    /// Returns true only for `ECONNREFUSED`; transient failures remain
    /// queued for the next tick.
    pub fn drain_outputs(&mut self, now: Timestamp) -> bool {
        self.drain_outputs_bounded(now, self.output_drain)
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
    Ok(Conn::with_budgets(
        prepared.connection(now)?,
        socket,
        prepared.transport.output_drain,
    ))
}

#[cfg(test)]
mod config_tests {
    use super::*;

    /// K02: a `Conn` built via [`caller`] must actually drive with its
    /// configured `TransportConfig::output_drain`, not silently substitute
    /// [`OutputDrainBudget::default`] on every [`Conn::drain_outputs`] call.
    #[test]
    fn caller_constructs_a_conn_that_honors_its_configured_output_drain_budget() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer binds");
        peer.set_nonblocking(true).expect("peer is nonblocking");
        let remote = peer.local_addr().expect("peer address");

        let distinctive = OutputDrainBudget::new(1, 1, 64 * 1024);
        let config = crate::CallerConfig::builder(remote)
            .configure_transport(|transport| {
                transport.output_drain = distinctive;
            })
            .build()
            .expect("caller config");
        let mut conn = super::caller(&config, Timestamp::from_micros(0)).expect("caller builds");

        conn.pending_outputs
            .push_back(ConnectionOutput::SendPacket(b"one".to_vec()));
        conn.pending_outputs
            .push_back(ConnectionOutput::SendPacket(b"two".to_vec()));

        // mio's `drain_outputs` wrapper returns only a bool (ECONNREFUSED),
        // not enough detail to observe budget exhaustion behaviorally, so
        // this checks the stored field directly -- the same thing every
        // other runtime's equivalent test proves by observing behavior.
        assert_eq!(
            conn.output_drain, distinctive,
            "Conn must store the configured budget, not silently keep the default"
        );
        let report = conn
            .drain_outputs_bounded(Timestamp::from_micros(0), conn.output_drain)
            .expect("drain succeeds");
        assert_eq!(report.status, crate::OutputDrainStatus::BudgetExhausted);
        assert_eq!(
            conn.pending_outputs.len(),
            1,
            "the second action must remain queued under a 1-action budget"
        );
    }
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
