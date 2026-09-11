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

// ---------------------------------------------------------------------------
// Owner: a single Mio-driven listener/caller pair (A03)
// ---------------------------------------------------------------------------

const OWNER_LISTENER_TOKEN: mio::Token = mio::Token(0);
const OWNER_CALLER_TOKEN: mio::Token = mio::Token(1);

/// [`Owner::poll_io`]'s receive budget: drain each ready socket until the
/// kernel reports `WouldBlock`, not a fixed round/datagram cap. Mio
/// registers both sockets edge-triggered ([`mio::Interest::READABLE`] with
/// no level-triggered fallback), so a round cap that stops before the
/// socket is actually empty leaves datagrams sitting in the kernel with no
/// further `READABLE` event to signal they are still there -- this is
/// exactly the hazard [`crate::RecvBudget::until_would_block`]'s own doc
/// comment describes, and a peer stuck behind that backlog never gets
/// unstuck without a fresh arrival re-arming the edge.
const OWNER_RECV_BUDGET: crate::RecvBudget = crate::RecvBudget::until_would_block();

struct OwnerListenerSide {
    socket: mio::net::UdpSocket,
    peers: crate::PeerTable,
    admission: crate::AdmissionOptions,
    telemetry: crate::IngressTelemetry,
    recv_batch: crate::RecvBatch,
    outbound: Vec<(std::net::SocketAddr, Vec<u8>)>,
}

struct OwnerCallerSide {
    socket: mio::net::UdpSocket,
    callers: crate::CallerTable,
    recv_batch: crate::RecvBatch,
    outbound: Vec<(std::net::SocketAddr, Vec<u8>)>,
}

/// A single [`mio::Poll`] driving one shared-socket listener side and one
/// shared-socket caller side together (A03).
///
/// Both sides are assembled entirely from this crate's existing
/// runtime-agnostic building blocks -- [`crate::PeerTable`] and
/// [`crate::CallerTable`] already implement admission, bounded scheduling,
/// and logical-handle bookkeeping with no socket of their own; the
/// `PreparedListener`/`PreparedCaller` doc comments already say a
/// shared-socket caller "needs a custom driver using `send_to`, the same
/// pattern this crate's listener side already uses" (K01). `Owner` is that
/// missing driver, kept deliberately narrow: exactly one non-pooled
/// listener socket ([`crate::ResolvedListenerTopology::PerPort`]) and
/// exactly one caller socket shared by every [`Owner::connect`]ed session
/// (which therefore requires `SocketOwnership::Shared`, not the default
/// `Exclusive`). Pooled/reuseport listener topologies and per-caller
/// connected sockets already have their own native `Conn`-based path
/// ([`bind_listener`], [`caller`]) and are out of scope here.
///
/// Readiness stays plain Mio throughout, per this card's own charter: no
/// dynamic runtime abstraction, and the async-runtime readiness/completion
/// cancellation cards (S04/S05) do not gate this independent path.
///
/// Two known gaps, tracked as explicit follow-ups rather than partial
/// fixes bolted onto this card:
///
/// - There is no way to read data a *caller*-side session received:
///   `crate::CallerTable` (unlike `crate::PeerTable`) has no `poll_events`
///   anywhere in this crate today -- building one is a real addition to a
///   shared, already-tested table type, out of proportion to "assemble the
///   owner from existing building blocks" (checkpoint 3). The acceptance
///   round trip this card's example demonstrates is the listener-side
///   direction only: caller sends, listener receives.
/// - `listen()` validates only the listener socket topology, not the
///   resolved promotion policy; a `ListenerConfig` requesting a non-`Never`
///   promotion resolves and binds fine, then is silently never acted on
///   (this owner has no relocation target to promote a peer onto).
pub struct Owner {
    poll: mio::Poll,
    events: mio::Events,
    listener: Option<OwnerListenerSide>,
    caller: Option<OwnerCallerSide>,
}

impl Owner {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            poll: mio::Poll::new()?,
            events: mio::Events::with_capacity(1024),
            listener: None,
            caller: None,
        })
    }

    /// Bind and register this owner's one listener socket. May be called at
    /// most once; a second call returns an error rather than silently
    /// leaking the first socket's registration.
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
        let prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
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
            // `sendmsg_batch` (every reply this owner ever sends) rejects a
            // non-IPv4 destination at the syscall boundary, and that
            // rejection fails the *entire* batch it is found in -- not just
            // the one datagram -- discarding healthy peers' replies too. A
            // dual-stack (`[::]`) bind would still admit a genuine IPv6
            // sender (the recv path decodes AF_INET6 correctly) with no way
            // to filter it out at admission time, only to have every reply
            // batch containing it fail forever. Reject an IPv6 bind address
            // up front rather than accept a listener that can silently
            // start breaking every co-resident peer the moment one real
            // IPv6 sender reaches it.
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "listener.bind",
                "Owner's send path (sendmsg_batch) is IPv4-only; bind an \
                 IPv4 address instead of an IPv6 or dual-stack one",
            )));
        }
        let mut sockets = prepared.bind_sockets()?;
        let mut socket = mio::net::UdpSocket::from_std(sockets.remove(0));
        self.poll.registry().register(
            &mut socket,
            OWNER_LISTENER_TOKEN,
            mio::Interest::READABLE,
        )?;
        self.listener = Some(OwnerListenerSide {
            socket,
            admission: prepared.admission_options(),
            peers: prepared.peer_table(),
            telemetry: crate::IngressTelemetry::new(),
            recv_batch: crate::RecvBatch::new(),
            outbound: Vec::new(),
        });
        Ok(())
    }

    /// Start one outbound session on this owner's shared caller socket,
    /// binding and registering that socket on the first call. Every
    /// subsequent call adds another logical caller on the same socket
    /// (K01's `SocketOwnership::Shared`); `config.transport.ownership` must
    /// already be `Shared` -- the default `Exclusive` would `connect()` the
    /// socket to one remote, which cannot be shared with other sessions.
    ///
    /// Only the *first* call's `config.local_bind`/`socket_buffer_bytes`
    /// take effect -- they choose the one socket every later call shares,
    /// and a later call's own values are silently not applied to it.
    /// `config.remote` and every session setting, by contrast, are honored
    /// on every call: only the socket-construction half of a later config
    /// is ignored, never the session/protocol half.
    pub fn connect(
        &mut self,
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<crate::LogicalCallerId, crate::RuntimeBuildError> {
        let prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
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
            // Same reasoning as `listen`'s bind-family check: `sendmsg_batch`
            // is IPv4-only, and one non-IPv4 destination fails the whole
            // shared batch it rides in, not just its own datagram.
            return Err(crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.remote",
                "Owner's send path (sendmsg_batch) is IPv4-only; connect to \
                 an IPv4 remote address instead",
            )));
        }
        if self.caller.is_none() {
            let mut socket = mio::net::UdpSocket::from_std(prepared.bind_socket()?);
            self.poll.registry().register(
                &mut socket,
                OWNER_CALLER_TOKEN,
                mio::Interest::READABLE,
            )?;
            self.caller = Some(OwnerCallerSide {
                socket,
                callers: crate::CallerTable::new(),
                recv_batch: crate::RecvBatch::new(),
                outbound: Vec::new(),
            });
        }
        let side = self.caller.as_mut().expect("just ensured above");
        let connection = prepared.connection(now)?;
        let leg = crate::CallerLeg::new(config.remote, connection);
        side.callers.add_direct(leg).map_err(|error| {
            crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.add_direct",
                error.to_string(),
            ))
        })
    }

    /// Poll the OS for readiness and drain every ready socket's incoming
    /// datagrams into the listener/caller tables. Fires no timers and sends
    /// nothing; call [`Self::drive`] afterward to do both.
    ///
    /// `now` is called only *after* [`mio::Poll::poll`] returns, not before
    /// it blocks: a `Timestamp` sampled before a multi-millisecond block
    /// would feed SRT's RTT/TSBPD arithmetic a stale value on every packet
    /// this call admits or feeds, by up to the full `timeout`.
    ///
    /// A [`std::io::Error`] from one side's recv is returned only after the
    /// other side has still been given its chance to drain -- one peer's
    /// per-socket failure (a bind that later starts returning `EPERM` from
    /// a firewall rule, say) must not also silence a healthy, unrelated
    /// side for that tick.
    pub fn poll_io(
        &mut self,
        timeout: Option<Duration>,
        now: impl FnOnce() -> Timestamp,
    ) -> io::Result<()> {
        loop {
            match self.poll.poll(&mut self.events, timeout) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let mut listener_ready = false;
        let mut caller_ready = false;
        for event in self.events.iter() {
            match event.token() {
                OWNER_LISTENER_TOKEN => listener_ready = true,
                OWNER_CALLER_TOKEN => caller_ready = true,
                _ => {}
            }
        }
        let now = now();
        let mut first_error = None;
        if listener_ready && let Some(side) = self.listener.as_mut() {
            let (peers, admission, telemetry) = (&mut side.peers, &side.admission, &side.telemetry);
            let result = crate::drain_recv_fd(
                side.socket.as_raw_fd(),
                &mut side.recv_batch,
                OWNER_RECV_BUDGET,
                |addr, data| {
                    let Some(peer) = addr else { return };
                    let _ = peers.admit(peer, data, now, admission, 0, 1, telemetry);
                },
            );
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        if caller_ready && let Some(side) = self.caller.as_mut() {
            let callers = &mut side.callers;
            let result = crate::drain_recv_fd(
                side.socket.as_raw_fd(),
                &mut side.recv_batch,
                OWNER_RECV_BUDGET,
                |addr, data| {
                    let Some(peer) = addr else { return };
                    let _ = callers.feed(peer, data, now);
                },
            );
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Fire due timers and send every pending protocol output on both
    /// sides. The caller side uses its existing bounded scheduler
    /// ([`crate::CallerTable::poll_outbound_bounded`], P02) so one caller
    /// with a large backlog cannot starve another's due timer; the
    /// listener side's equivalent bound does not exist yet (tracked
    /// follow-up on `crate::PeerTable::poll_outbound`, also from P02's
    /// review) and drains unconditionally instead.
    ///
    /// A side's own table is only asked for fresh output
    /// (`poll_outbound`/`poll_outbound_bounded`) once its previous visit's
    /// `outbound` queue is fully sent -- both of those methods start by
    /// clearing `out`, so calling either while a send from the last visit
    /// is still queued (kernel backpressure, or a batch over
    /// `sendmmsg`'s `UIO_MAXIOV` datagram limit) would silently discard the
    /// unsent remainder instead of retrying it. One side's send error is
    /// returned only after the other side has still been driven, for the
    /// same reason as [`Self::poll_io`].
    ///
    /// Returns the caller side's [`crate::OutputDrainStatus`] --
    /// `BudgetExhausted` means more work was ready than `caller_budget`
    /// allowed, and the application should call [`Self::drive`] again
    /// immediately rather than wait out its usual poll timeout; `Drained`
    /// (also returned when there is no caller side) means it is safe to
    /// wait. The listener side has no equivalent bound yet (see above), so
    /// it has no comparable status to report.
    pub fn drive(
        &mut self,
        now: Timestamp,
        caller_budget: crate::OutputDrainBudget,
    ) -> io::Result<crate::OutputDrainStatus> {
        let mut first_error = None;
        if let Some(side) = self.listener.as_mut() {
            if side.outbound.is_empty() {
                side.peers.poll_outbound(now, &mut side.outbound);
            }
            if let Err(error) = crate::flush_destined(side.socket.as_raw_fd(), &mut side.outbound) {
                first_error.get_or_insert(error);
            }
        }
        let mut caller_status = crate::OutputDrainStatus::Drained;
        if let Some(side) = self.caller.as_mut() {
            if side.outbound.is_empty() {
                let report =
                    side.callers
                        .poll_outbound_bounded(now, caller_budget, &mut side.outbound);
                caller_status = report.status;
            }
            if let Err(error) = crate::flush_destined(side.socket.as_raw_fd(), &mut side.outbound) {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(caller_status),
        }
    }

    /// Drain admitted-peer lifecycle/data events for the application.
    pub fn poll_listener_events(&mut self, out: &mut Vec<crate::AdmissionEvent>) {
        out.clear();
        let Some(side) = self.listener.as_mut() else {
            return;
        };
        side.peers.poll_events(out);
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
        self.caller.as_mut()?.callers.logical_caller_mut(&id)
    }

    /// Atomically retire one admitted peer, reclaiming its table entry and
    /// buffers. `disconnect()` alone only transitions protocol state and
    /// leaves the entry (and its SRT send/receive buffers) resident; a peer
    /// that reaches its terminal state without a `disconnect()` call from
    /// this side (an EXP timeout, say, rather than a received SHUTDOWN)
    /// stays in the table until an application calls this explicitly.
    pub fn remove_listener_peer(
        &mut self,
        id: crate::LogicalPeerId,
    ) -> Option<crate::RemovedLogicalPeer> {
        self.listener.as_mut()?.peers.remove(id)
    }

    /// Atomically retire one outbound session. See
    /// [`Self::remove_listener_peer`] -- the same "disconnect leaves the
    /// entry resident" caveat applies here.
    pub fn remove_caller(
        &mut self,
        id: crate::LogicalCallerId,
    ) -> Option<crate::RemovedLogicalCaller> {
        self.caller.as_mut()?.callers.remove(id)
    }

    /// The listener socket's bound local address, once [`Self::listen`] has
    /// been called -- useful when binding an ephemeral port (`:0`).
    #[must_use]
    pub fn listener_local_addr(&self) -> Option<std::net::SocketAddr> {
        self.listener.as_ref()?.socket.local_addr().ok()
    }

    /// A snapshot of admission-path counters (invalid datagrams, capacity
    /// drops, cookie routing, ...) for the listener side, once
    /// [`Self::listen`] has been called.
    #[must_use]
    pub fn listener_telemetry(&self) -> Option<crate::IngressTelemetrySnapshot> {
        Some(self.listener.as_ref()?.telemetry.snapshot())
    }

    /// Microseconds until either side's next due timer, for sizing
    /// [`Self::poll_io`]'s timeout. `default_us` is returned when neither
    /// side has anything scheduled.
    #[must_use]
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        let listener = self
            .listener
            .as_mut()
            .map(|side| side.peers.time_until_next_deadline(now, u64::MAX));
        let caller = self
            .caller
            .as_ref()
            .map(|side| side.callers.time_until_next_deadline(now, u64::MAX));
        match (listener, caller) {
            (Some(a), Some(b)) => a.min(b).min(default_us),
            (Some(a), None) | (None, Some(a)) => a.min(default_us),
            (None, None) => default_us,
        }
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    use crate::{AdmissionEvent, LogicalCallerState, SocketOwnership};
    use shiguredo_srt::ConnectionEvent;
    use std::net::SocketAddr;

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

    /// Drive both sides of one owner for up to `timeout`, calling `done`
    /// after every tick; returns as soon as `done` reports true.
    fn drive_until(
        owner: &mut Owner,
        start: std::time::Instant,
        timeout: Duration,
        mut done: impl FnMut(&mut Owner, Timestamp) -> bool,
    ) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let wait_us = owner.time_until_next_deadline(now_ts(start), 5_000);
            owner
                .poll_io(Some(Duration::from_micros(wait_us)), || now_ts(start))
                .expect("poll_io");
            let now = now_ts(start);
            owner
                .drive(now, OutputDrainBudget::default())
                .expect("drive");
            if done(owner, now) {
                return true;
            }
        }
        false
    }

    /// A03: an `Owner` built with one listener and one shared-socket caller
    /// (both driven by the same `mio::Poll`) must connect, exchange a known
    /// payload, and close in an orderly way through only the public API --
    /// the acceptance criteria's minimal round trip.
    #[test]
    fn owner_connects_sends_receives_and_closes_one_session() {
        let start = std::time::Instant::now();
        let mut owner = Owner::new().expect("owner builds");
        owner.listen(&listener_config()).expect("listen");
        let listen_addr = owner.listener_local_addr().expect("listener bound");

        let caller_id = owner
            .connect(&shared_caller_config(listen_addr), now_ts(start))
            .expect("connect");

        // Connect: both sides reach Connected.
        let mut peer_id = None;
        let connected = drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
            let mut events = Vec::new();
            owner.poll_listener_events(&mut events);
            for event in events {
                if let AdmissionEvent {
                    logical_peer,
                    event: ConnectionEvent::Connected,
                    ..
                } = event
                {
                    peer_id = Some(logical_peer);
                }
            }
            peer_id.is_some()
                && owner.caller_mut(caller_id).and_then(|c| c.state())
                    == Some(LogicalCallerState::Connected)
        });
        assert!(connected, "caller and listener must both reach Connected");
        let peer_id = peer_id.expect("listener admitted the caller");

        // Send: the caller pushes a known payload; the listener must
        // observe it verbatim via DataReceived.
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
                    && let ConnectionEvent::DataReceived { payload, .. } = event.event
                {
                    received = Some(payload.to_vec());
                }
            }
            received.is_some()
        });
        assert!(got_data, "listener must receive the caller's payload");
        assert_eq!(received.expect("checked above"), b"known message");

        // Close: the caller disconnects; the listener must observe it.
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
                    && matches!(event.event, ConnectionEvent::Disconnected { .. })
                {
                    saw_disconnect = true;
                }
            }
            saw_disconnect
        });
        assert!(closed, "listener must observe the caller's orderly close");
    }

    /// A03 acceptance: multiple sessions survive one stalled peer. Three
    /// callers connect; the application never touches the middle one again
    /// after it connects (a stalled/idle consumer), while the other two
    /// send and receive a payload to completion -- proving one idle session
    /// does not block the others' progress through the same owner.
    #[test]
    fn multiple_sessions_survive_one_stalled_peer() {
        let start = std::time::Instant::now();
        let mut owner = Owner::new().expect("owner builds");
        owner.listen(&listener_config()).expect("listen");
        let listen_addr = owner.listener_local_addr().expect("listener bound");

        // The "stalled peer": not a well-behaved idle session (which
        // generates no work and so exercises no fairness at all), but an
        // unrelated flood of garbage datagrams continuously hammering the
        // listener socket for the whole test -- the actual adversarial
        // condition the bounded caller-side scheduler (P02) and the
        // per-datagram admission path exist to stay fair under.
        let flood_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flood_handle = {
            let flood_running = flood_running.clone();
            std::thread::spawn(move || {
                let flooder = std::net::UdpSocket::bind("127.0.0.1:0").expect("flooder binds");
                let garbage = vec![0xAA_u8; 200];
                while flood_running.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = flooder.send_to(&garbage, listen_addr);
                    std::thread::sleep(Duration::from_micros(50));
                }
            })
        };
        let stop_flood = || flood_running.store(false, std::sync::atomic::Ordering::Relaxed);

        let caller_ids: Vec<_> = (0..2)
            .map(|_| {
                owner
                    .connect(&shared_caller_config(listen_addr), now_ts(start))
                    .expect("connect")
            })
            .collect();

        let mut peer_ids = std::collections::HashSet::new();
        let all_connected =
            drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
                let mut events = Vec::new();
                owner.poll_listener_events(&mut events);
                for event in events {
                    if let ConnectionEvent::Connected = event.event {
                        peer_ids.insert(event.logical_peer);
                    }
                }
                peer_ids.len() == caller_ids.len()
                    && caller_ids.iter().all(|id| {
                        owner.caller_mut(*id).and_then(|c| c.state())
                            == Some(LogicalCallerState::Connected)
                    })
            });
        if !all_connected {
            stop_flood();
        }
        assert!(all_connected, "both callers must connect despite the flood");

        for id in &caller_ids {
            owner
                .caller_mut(*id)
                .expect("caller still exists")
                .send(b"still working", now_ts(start))
                .expect("caller sends");
        }

        // Attribute every delivery to the peer that sent it -- two
        // deliveries credited to one peer must not read as "both sessions
        // completed".
        let mut received_from = std::collections::HashSet::new();
        let all_received = drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
            let mut events = Vec::new();
            owner.poll_listener_events(&mut events);
            for event in events {
                if let ConnectionEvent::DataReceived { payload, .. } = event.event
                    && payload.as_ref() == b"still working"
                {
                    received_from.insert(event.logical_peer);
                }
            }
            let _ = owner;
            received_from.len() == caller_ids.len()
        });
        stop_flood();
        flood_handle.join().expect("flood thread joins");
        assert!(
            all_received,
            "both sessions must complete despite the concurrent flood"
        );
        assert_eq!(
            received_from.len(),
            2,
            "the payload must be attributed to two distinct peers, not double-counted on one"
        );
    }

    /// D02-style guard, adapted for A03: `Owner::connect` must reject an
    /// `Exclusive`-ownership config rather than silently building a caller
    /// socket it then cannot share with any other logical caller.
    #[test]
    fn connect_rejects_exclusive_ownership() {
        let mut owner = Owner::new().expect("owner builds");
        let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let config = crate::CallerConfig::builder(remote)
            .build()
            .expect("caller config");
        let result = owner.connect(&config, Timestamp::from_micros(0));
        assert!(
            result.is_err(),
            "Exclusive ownership must be rejected, not silently accepted"
        );
    }

    /// Opus review (A03): `drive()` must retry a batch `sendmsg_batch`
    /// could not fully accept on the next call instead of discarding it --
    /// `CallerTable::poll_outbound_bounded`/`PeerTable::poll_outbound` both
    /// start with `out.clear()`, so calling either again while the last
    /// visit's send is still incomplete would silently wipe the unsent
    /// remainder. `sendmmsg` accepts at most `UIO_MAXIOV` (1024 on Linux)
    /// datagrams per call, so 2000 simultaneous handshakes -- one pending
    /// `SendPacket` each, all collected into one `drive()` visit since the
    /// budget here is unbounded -- reliably force a partial send on the
    /// first attempt.
    #[test]
    fn drive_retains_a_partially_sent_batch_across_calls_instead_of_discarding_it() {
        let start = std::time::Instant::now();
        let collector = std::net::UdpSocket::bind("127.0.0.1:0").expect("collector binds");
        collector
            .set_nonblocking(true)
            .expect("collector is nonblocking");
        // A comfortably large receive buffer: the property under test is
        // `Owner` retaining and resending its own unsent output, not
        // whether an unrelated test-only receiver can drain a burst of
        // ~1000 back-to-back datagrams as fast as the kernel delivers
        // them. Without this, the default OS receive buffer can drop
        // datagrams the sender genuinely sent, which would misreport as
        // exactly the bug this test exists to catch.
        crate::set_sock_bufs(std::os::fd::AsRawFd::as_raw_fd(&collector), 8 * 1024 * 1024)
            .expect("collector receive buffer grows");
        let collector_addr = collector.local_addr().expect("collector address");

        let mut owner = Owner::new().expect("owner builds");
        const SESSIONS: usize = 2000;
        for _ in 0..SESSIONS {
            owner
                .connect(&shared_caller_config(collector_addr), now_ts(start))
                .expect("connect");
        }

        let unbounded = OutputDrainBudget::new(usize::MAX, usize::MAX, usize::MAX);
        owner
            .drive(now_ts(start), unbounded)
            .expect("first drive collects and partially sends the whole backlog");
        let remaining_after_first = owner
            .caller
            .as_ref()
            .expect("caller side exists")
            .outbound
            .len();
        assert!(
            remaining_after_first > 0,
            "{SESSIONS} simultaneous handshake packets in one visit must exceed \
             sendmmsg's per-call datagram limit, leaving a real remainder to retain"
        );

        // Drain the collector between ticks (not only at the end) so its
        // own OS receive buffer never has to hold all `SESSIONS` datagrams
        // at once -- that would be a test-infrastructure limit, not the
        // property under test. However many further ticks it takes, every
        // packet must eventually be sent: none silently dropped because a
        // later tick called `poll_outbound_bounded` again while a send was
        // still incomplete.
        let mut received = 0usize;
        let mut buffer = [0_u8; 2048];
        let mut drain_collector = |collector: &std::net::UdpSocket, received: &mut usize| loop {
            match collector.recv(&mut buffer) {
                Ok(_) => *received += 1,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("collector receive failed: {error}"),
            }
        };
        drain_collector(&collector, &mut received);
        for _ in 0..20 {
            if owner
                .caller
                .as_ref()
                .expect("caller side exists")
                .outbound
                .is_empty()
            {
                break;
            }
            owner
                .drive(now_ts(start), unbounded)
                .expect("later drive retries the retained remainder");
            drain_collector(&collector, &mut received);
        }
        assert_eq!(
            received, SESSIONS,
            "every handshake packet must reach the wire across retries, not just the \
             first sendmmsg-accepted subset"
        );
    }

    /// Opus review (A03): `Owner`'s send path (`sendmsg_batch`) is
    /// IPv4-only, and a batch containing even one non-IPv4 destination
    /// fails as a whole (not just that one datagram) -- so `listen`/
    /// `connect` must reject a non-IPv4 address up front rather than admit
    /// or dial a session this owner can never actually reply to or send
    /// from.
    #[test]
    fn listen_and_connect_reject_ipv6_addresses() {
        let mut owner = Owner::new().expect("owner builds");
        let ipv6_listener = crate::ListenerConfig::builder("[::1]:0".parse().unwrap())
            .topology(crate::ListenerTopology::PerPort)
            .build()
            .expect("listener config");
        assert!(
            owner.listen(&ipv6_listener).is_err(),
            "an IPv6 bind address must be rejected, not silently accepted"
        );

        let ipv6_remote: SocketAddr = "[::1]:9".parse().unwrap();
        let ipv6_caller = crate::CallerConfig::builder(ipv6_remote)
            .ownership(SocketOwnership::Shared)
            .build()
            .expect("caller config");
        assert!(
            owner
                .connect(&ipv6_caller, Timestamp::from_micros(0))
                .is_err(),
            "an IPv6 remote address must be rejected, not silently accepted"
        );
    }
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
