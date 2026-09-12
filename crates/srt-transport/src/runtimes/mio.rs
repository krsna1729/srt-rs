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
    prepared.require_exclusive()?;
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

struct OwnerListenerSide {
    socket: mio::net::UdpSocket,
    peers: crate::PeerTable,
    admission: crate::AdmissionOptions,
    telemetry: crate::IngressTelemetry,
    recv_batch: crate::RecvBatch,
    outbound: Vec<(std::net::SocketAddr, Vec<u8>)>,
    idle_timeout: Duration,
    transport: crate::ResolvedTransportConfig,
    recv_pending: bool,
    output_pending: bool,
    event_pending: bool,
    write_blocked: bool,
}

struct OwnerCallerSide {
    socket: mio::net::UdpSocket,
    callers: crate::CallerPool,
    recv_batch: crate::RecvBatch,
    outbound: Vec<(std::net::SocketAddr, Vec<u8>)>,
    transport: crate::ResolvedTransportConfig,
    local_bind: Option<std::net::SocketAddr>,
    connect_config: crate::ConnectConfig,
    recv_pending: bool,
    output_pending: bool,
    event_pending: bool,
    write_blocked: bool,
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
/// Caller concurrency and attempt deadlines come from the first caller's
/// `ConnectConfig`, unless explicitly overridden before connecting. Each
/// socket visit has finite receive, output and event budgets. Readiness
/// continuations survive budget exhaustion, including Mio's edge-triggered
/// receive path. A socket blocked on output waits for writable readiness.
pub struct Owner {
    poll: mio::Poll,
    events: mio::Events,
    listener: Option<OwnerListenerSide>,
    caller: Option<OwnerCallerSide>,
    caller_pool_policy: Option<(std::num::NonZeroUsize, Duration)>,
}

impl Owner {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            poll: mio::Poll::new()?,
            events: mio::Events::with_capacity(1024),
            listener: None,
            caller: None,
            caller_pool_policy: None,
        })
    }

    /// Override the first caller's pool policy before binding the caller socket.
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
        Ok(())
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
        if prepared.transport.promotion != srt_lifecycle::Promotion::Never {
            return Err(crate::ConfigError::new(
                "listener.transport.promotion",
                "Owner has no relocation target; set promotion to Never",
            )
            .into());
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
            idle_timeout: prepared.admission.idle_timeout,
            peers: prepared.peer_table(),
            telemetry: crate::IngressTelemetry::new(),
            recv_batch: crate::RecvBatch::with_capacity(
                prepared.transport.recv_batch_capacity(),
                crate::RecvBatch::DEFAULT_BUF_LEN,
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
    /// binding and registering that socket on the first call. Every
    /// subsequent call adds another logical caller on the same socket
    /// (K01's `SocketOwnership::Shared`); `config.transport.ownership` must
    /// already be `Shared` -- the default `Exclusive` would `connect()` the
    /// socket to one remote, which cannot be shared with other sessions.
    ///
    /// Later calls must use compatible shared socket settings and pool policy.
    /// A full pool queues within its configured finite queue limit; applications
    /// observe queued outcomes through the caller pool.
    pub fn connect(
        &mut self,
        config: &crate::CallerConfig,
        now: Timestamp,
    ) -> Result<crate::PoolOutcome, crate::RuntimeBuildError> {
        let mut prepared = config.prepare(crate::RuntimeFlavor::Mio)?;
        if let Some((max_in_flight, attempt_deadline)) = self.caller_pool_policy {
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
            // Same reasoning as `listen`'s bind-family check: `sendmsg_batch`
            // is IPv4-only, and one non-IPv4 destination fails the whole
            // shared batch it rides in, not just its own datagram.
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
            let mut socket = mio::net::UdpSocket::from_std(prepared.bind_socket()?);
            self.poll.registry().register(
                &mut socket,
                OWNER_CALLER_TOKEN,
                mio::Interest::READABLE,
            )?;
            let crate::ConnectConfig {
                max_in_flight,
                attempt_deadline,
            } = prepared.connect;
            self.caller = Some(OwnerCallerSide {
                socket,
                callers: crate::CallerPool::new(max_in_flight, attempt_deadline),
                recv_batch: crate::RecvBatch::with_capacity(
                    prepared.transport.recv_batch_capacity(),
                    crate::RecvBatch::DEFAULT_BUF_LEN,
                ),
                outbound: Vec::new(),
                transport: prepared.transport,
                local_bind: prepared.local_bind,
                connect_config: prepared.connect,
                recv_pending: false,
                output_pending: false,
                event_pending: false,
                write_blocked: false,
            });
        }
        let side = self.caller.as_mut().expect("just ensured above");
        side.callers.connect(prepared, now).map_err(|error| {
            crate::RuntimeBuildError::from(crate::ConfigError::new(
                "caller.connect",
                error.to_string(),
            ))
        })
    }

    /// Poll readiness and receive within each socket's configured budget.
    /// Remember unfinished receive work across visits. Fires no timers and sends
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
        // Continue known work without relying on another readiness edge.
        let pending = self.listener.as_ref().is_some_and(|side| {
            side_has_continuation_work(
                side.recv_pending,
                side.event_pending,
                side.write_blocked,
                side.output_pending,
                side.outbound.is_empty(),
            )
        }) || self.caller.as_ref().is_some_and(|side| {
            side_has_continuation_work(
                side.recv_pending,
                side.event_pending,
                side.write_blocked,
                side.output_pending,
                side.outbound.is_empty(),
            )
        });
        let timeout = if pending {
            Some(Duration::ZERO)
        } else {
            timeout
        };
        let started = std::time::Instant::now();
        loop {
            let remaining = timeout.map(|timeout| timeout.saturating_sub(started.elapsed()));
            match self.poll.poll(&mut self.events, remaining) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        for event in self.events.iter() {
            let side = match event.token() {
                OWNER_LISTENER_TOKEN => self.listener.as_mut().map(|side| {
                    (
                        &mut side.recv_pending,
                        &mut side.write_blocked,
                        &mut side.socket,
                    )
                }),
                OWNER_CALLER_TOKEN => self.caller.as_mut().map(|side| {
                    (
                        &mut side.recv_pending,
                        &mut side.write_blocked,
                        &mut side.socket,
                    )
                }),
                _ => None,
            };
            if let Some((recv_pending, write_blocked, socket)) = side {
                apply_readiness_event(&self.poll, event, recv_pending, write_blocked, socket)?;
            }
        }
        let now = now();
        let mut first_error = None;
        if let Some(side) = self.listener.as_mut()
            && side.recv_pending
        {
            let (peers, admission, telemetry) = (&mut side.peers, &side.admission, &side.telemetry);
            if let Err(error) = drain_side_recv(
                &mut side.recv_pending,
                side.socket.as_raw_fd(),
                &mut side.recv_batch,
                side.transport.recv_budget,
                |addr, data| {
                    let Some(peer) = addr else { return };
                    let _ = peers.admit(peer, data, now, admission, 0, 1, telemetry);
                },
            ) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(side) = self.caller.as_mut()
            && side.recv_pending
        {
            let callers = side.callers.table_mut();
            if let Err(error) = drain_side_recv(
                &mut side.recv_pending,
                side.socket.as_raw_fd(),
                &mut side.recv_batch,
                side.transport.recv_budget,
                |addr, data| {
                    let Some(peer) = addr else { return };
                    let _ = callers.feed(peer, data, now);
                },
            ) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Service both sides with finite per-side limits. The visit budget is
    /// capped by each side's transport configuration. Idle/pool maintenance
    /// has the same action limit; receive and application event visits have
    /// their own configured limits.
    ///
    /// `BudgetExhausted` requests another immediate visit. `Backpressured`
    /// requests a writable wait; the unsent suffix remains owned here.
    pub fn drive(
        &mut self,
        now: Timestamp,
        budget: crate::OutputDrainBudget,
    ) -> io::Result<crate::OutputDrainStatus> {
        let mut first_error = None;
        let mut status = crate::OutputDrainStatus::Drained;
        if let Some(side) = self.listener.as_mut() {
            let budget = budget.intersect(side.transport.output_drain);
            side.peers
                .prune_idle_bounded(now, side.idle_timeout, budget.max_actions);
            if side.outbound.is_empty() {
                let report = side
                    .peers
                    .poll_outbound_bounded(now, budget, &mut side.outbound);
                side.output_pending = report.status == crate::OutputDrainStatus::BudgetExhausted;
            }
            let side_status = flush_owner_side(
                &self.poll,
                &mut side.socket,
                OWNER_LISTENER_TOKEN,
                &mut side.outbound,
                side.recv_pending,
                side.output_pending,
                &mut side.write_blocked,
                &mut first_error,
            );
            status = status.combine(side_status);
        }
        if let Some(side) = self.caller.as_mut() {
            let budget = budget.intersect(side.transport.output_drain);
            side.callers
                .poll_expirations_bounded(now, budget.max_actions);
            if side.outbound.is_empty() {
                let report =
                    side.callers
                        .table_mut()
                        .poll_outbound_bounded(now, budget, &mut side.outbound);
                side.output_pending = report.status == crate::OutputDrainStatus::BudgetExhausted;
            }
            let side_status = flush_owner_side(
                &self.poll,
                &mut side.socket,
                OWNER_CALLER_TOKEN,
                &mut side.outbound,
                side.recv_pending,
                side.output_pending,
                &mut side.write_blocked,
                &mut first_error,
            );
            status = status.combine(side_status);
        }
        first_error.map_or(Ok(status), Err)
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

    /// Effective, currently-observable caller-pool state (A04) -- in
    /// flight/queued counts and lifetime started/expired totals -- once
    /// [`Self::connect`] has been called at least once.
    #[must_use]
    pub fn caller_pool_stats(&self) -> Option<crate::CallerPoolStats> {
        Some(self.caller.as_ref()?.callers.stats())
    }

    /// Microseconds until either side's next due timer, for sizing
    /// [`Self::poll_io`]'s timeout. `default_us` is returned when neither
    /// side has anything scheduled.
    #[must_use]
    pub fn time_until_next_deadline(&mut self, now: Timestamp, default_us: u64) -> u64 {
        let mut wait = default_us;
        if let Some(side) = self.listener.as_mut() {
            match listener_time_until_deadline(side, now) {
                None => return 0,
                Some(side_wait) => wait = wait.min(side_wait),
            }
        }
        if let Some(side) = self.caller.as_mut() {
            match caller_time_until_deadline(side, now) {
                None => return 0,
                Some(side_wait) => wait = wait.min(side_wait),
            }
        }
        wait
    }
}

/// The listener side's contribution to [`Owner::time_until_next_deadline`],
/// or `None` if it already has work that must run immediately (equivalent
/// to the caller-visible `0`) -- split out to keep the combining function
/// itself a plain two-branch dispatcher.
fn listener_time_until_deadline(side: &mut OwnerListenerSide, now: Timestamp) -> Option<u64> {
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

/// The caller side's counterpart to [`listener_time_until_deadline`].
/// `CallerPool::time_until_next_deadline` already combines the pool's own
/// attempt deadlines with the underlying table's protocol timers, unlike
/// the listener side's genuinely separate idle/protocol indexes.
fn caller_time_until_deadline(side: &mut OwnerCallerSide, now: Timestamp) -> Option<u64> {
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

/// Whether a side has known work that must be revisited without waiting
/// for a new readiness edge -- the identical predicate [`Owner::poll_io`]
/// applies to both the listener and caller side.
fn side_has_continuation_work(
    recv_pending: bool,
    event_pending: bool,
    write_blocked: bool,
    output_pending: bool,
    outbound_empty: bool,
) -> bool {
    recv_pending || event_pending || (!write_blocked && (output_pending || !outbound_empty))
}

/// Apply one readiness event to a side's `recv_pending`/`write_blocked`
/// bookkeeping -- split out of [`Owner::poll_io`]'s own event loop, since
/// the listener and caller side otherwise repeat this identically.
fn apply_readiness_event(
    poll: &mio::Poll,
    event: &mio::event::Event,
    recv_pending: &mut bool,
    write_blocked: &mut bool,
    socket: &mut mio::net::UdpSocket,
) -> io::Result<()> {
    *recv_pending |= event.is_readable() || event.is_error();
    if event.is_writable() && *write_blocked {
        poll.registry()
            .reregister(socket, event.token(), mio::Interest::READABLE)?;
        *write_blocked = false;
    }
    Ok(())
}

/// Drain one side's receive path and update its `recv_pending` flag from
/// the resulting [`crate::RecvDrainReport`] -- split out of
/// [`Owner::poll_io`]'s own body, since the listener and caller side
/// otherwise repeat this identically apart from `on_datagram`.
fn drain_side_recv(
    recv_pending: &mut bool,
    fd: std::os::fd::RawFd,
    recv_batch: &mut crate::RecvBatch,
    recv_budget: crate::RecvBudget,
    on_datagram: impl FnMut(Option<std::net::SocketAddr>, &[u8]),
) -> io::Result<()> {
    match crate::drain_recv_fd(fd, recv_batch, recv_budget, on_datagram) {
        Ok(report) => {
            *recv_pending = !report.would_block;
            Ok(())
        }
        Err(error) => {
            *recv_pending = false;
            Err(error)
        }
    }
}

/// Flush one side's already-collected `outbound` queue and fold the result
/// into that side's [`crate::OutputDrainStatus`] -- the identical tail
/// half of [`Owner::drive`]'s listener and caller branches, extracted so
/// `drive` itself stays a plain two-branch dispatcher.
#[allow(clippy::too_many_arguments)]
fn flush_owner_side(
    poll: &mio::Poll,
    socket: &mut mio::net::UdpSocket,
    token: mio::Token,
    outbound: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    recv_pending: bool,
    output_pending: bool,
    write_blocked: &mut bool,
    first_error: &mut Option<io::Error>,
) -> crate::OutputDrainStatus {
    if !*write_blocked {
        match crate::flush_destined(socket.as_raw_fd(), outbound) {
            Ok(report) => {
                // A positive partial send is runnable immediately; only a
                // zero-progress WouldBlock needs writable readiness.
                if report.sent == 0 && report.would_block {
                    if let Err(error) = poll.registry().reregister(
                        socket,
                        token,
                        mio::Interest::READABLE.add(mio::Interest::WRITABLE),
                    ) {
                        first_error.get_or_insert(error);
                    }
                    *write_blocked = true;
                }
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    owner_side_status(
        recv_pending,
        output_pending || !outbound.is_empty(),
        *write_blocked,
    )
}

fn owner_side_status(
    recv_pending: bool,
    output_pending: bool,
    write_blocked: bool,
) -> crate::OutputDrainStatus {
    if recv_pending || (output_pending && !write_blocked) {
        crate::OutputDrainStatus::BudgetExhausted
    } else if write_blocked {
        crate::OutputDrainStatus::Backpressured
    } else {
        crate::OutputDrainStatus::Drained
    }
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    use crate::{AdmissionEvent, LogicalCallerState, PoolOutcome, SocketOwnership};
    use shiguredo_srt::ConnectionEvent;
    use std::net::SocketAddr;
    use std::num::NonZeroUsize;

    fn now_ts(start: std::time::Instant) -> Timestamp {
        Timestamp::from_micros(start.elapsed().as_micros() as u64)
    }

    fn listener_config() -> crate::ListenerConfig {
        crate::ListenerConfig::builder("127.0.0.1:0".parse().unwrap())
            .topology(crate::ListenerTopology::PerPort)
            .configure_transport(|transport| transport.promotion = crate::PromotionPolicy::Never)
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

        let crate::PoolOutcome::Admitted(caller_id) = owner
            .connect(&shared_caller_config(listen_addr), now_ts(start))
            .expect("connect")
        else {
            panic!("the first caller fits the pool limit")
        };

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
        owner
            .set_caller_pool_policy(NonZeroUsize::new(2).unwrap(), Duration::from_secs(5))
            .unwrap();
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
                let crate::PoolOutcome::Admitted(id) = owner
                    .connect(&shared_caller_config(listen_addr), now_ts(start))
                    .expect("connect")
                else {
                    panic!("the first caller fits the pool limit")
                };
                id
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

    /// A05, ponytail review: `poll_caller_events` (added to
    /// `mio_transport::Owner` for parity with the Tokio facade, which
    /// genuinely needs it) must actually surface a direct caller's
    /// `Connected` and `Disconnected` transitions, not sit unexercised.
    #[test]
    fn poll_caller_events_surfaces_connected_and_disconnected() {
        let start = std::time::Instant::now();
        let mut owner = Owner::new().expect("owner builds");
        owner.listen(&listener_config()).expect("listen");
        let listen_addr = owner.listener_local_addr().expect("listener bound");

        let PoolOutcome::Admitted(caller_id) = owner
            .connect(&shared_caller_config(listen_addr), now_ts(start))
            .expect("connect")
        else {
            panic!("the first caller fits the pool limit")
        };

        let mut caller_events = Vec::new();
        let connected = drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
            let mut events = Vec::new();
            owner.poll_listener_events(&mut events); // drive the handshake to completion
            owner.poll_caller_events(&mut caller_events);
            caller_events.iter().any(|event| {
                event.id == caller_id && matches!(event.event, ConnectionEvent::Connected)
            })
        });
        assert!(
            connected,
            "poll_caller_events must surface the caller's own Connected transition"
        );

        owner
            .caller_mut(caller_id)
            .expect("caller session still exists")
            .disconnect(now_ts(start));
        let mut caller_events = Vec::new();
        let closing = drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
            owner.poll_caller_events(&mut caller_events);
            caller_events.iter().any(|event| {
                event.id == caller_id
                    && matches!(
                        event.event,
                        ConnectionEvent::StateChanged(shiguredo_srt::ConnectionState::Closing)
                    )
            })
        });
        assert!(
            closing,
            "poll_caller_events must surface the caller's own close starting"
        );
    }

    /// A04, Opus review's judgment call: `CallerPool`'s max_in_flight/
    /// attempt_deadline enforcement must be reachable through the one
    /// driver this crate ships, not merely usable as a standalone library
    /// type nothing ever exercises. `set_caller_pool_policy` bounds
    /// `Owner::connect` to one in-flight attempt; a second request must
    /// queue, and once the first attempt (pointed at an address nothing is
    /// listening on, so its handshake can never complete) misses its
    /// deadline, the queued request must be admitted in its place --
    /// through the exact same `connect`/`drive` calls every other `Owner`
    /// test uses, with no separate opt-out code path.
    #[test]
    fn set_caller_pool_policy_bounds_and_enforces_owner_connect() {
        let start = std::time::Instant::now();
        let mut owner = Owner::new().expect("owner builds");
        owner
            .set_caller_pool_policy(NonZeroUsize::new(1).unwrap(), Duration::from_millis(50))
            .expect("policy set before any connect() call");

        // Nothing listens here; the handshake can never complete on its own.
        let dead_end: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = crate::CallerConfig::builder(dead_end)
            .ownership(SocketOwnership::Shared)
            .build()
            .expect("caller config");

        let first = owner
            .connect(&config, now_ts(start))
            .expect("connect first");
        assert!(matches!(first, PoolOutcome::Admitted(_)));
        let second = owner
            .connect(&config, now_ts(start))
            .expect("connect second");
        assert!(
            matches!(second, PoolOutcome::Queued(_)),
            "max_in_flight=1 must queue the second request through Owner::connect itself"
        );
        assert_eq!(owner.caller_pool_stats().expect("pool exists").queued, 1);

        let admitted = drive_until(&mut owner, start, Duration::from_secs(5), |owner, _now| {
            owner
                .caller_pool_stats()
                .is_some_and(|stats| stats.queued == 0 && stats.expired >= 1)
        });
        assert!(
            admitted,
            "the stalled first attempt must expire and the queued second one must be \
             admitted in its place, purely by driving Owner as normal"
        );
    }

    #[test]
    fn receive_budget_continues_backlog_without_a_new_edge() {
        let mut owner = Owner::new().unwrap();
        let mut config = listener_config();
        // A PerPort listener's `RecvBatch` capacity is always 1 datagram:
        // `TransportConfig::resolve_batch_size` only ever elevates it
        // above that for a *shared*-listener topology, which a single
        // PerPort `Owner` listener never is -- so `max_datagrams` above 1
        // has no effect here regardless of its value. What this test
        // actually exercises is `recv_pending` correctly carrying a
        // remembered backlog across *multiple* `poll_io` calls with no
        // new readiness edge in between, not a multi-datagram batch
        // within one call.
        config.transport.recv_budget = crate::RecvBudget::new(1, 1);
        owner.listen(&config).unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        const SENT: u64 = 7;
        for _ in 0..SENT {
            sender
                .send_to(&[0], owner.listener_local_addr().unwrap())
                .unwrap();
        }
        let now = Timestamp::from_micros(0);
        owner
            .poll_io(Some(Duration::from_millis(50)), || now)
            .unwrap();
        assert_eq!(owner.listener_telemetry().unwrap().invalid_datagrams, 1);
        assert!(owner.listener.as_ref().unwrap().recv_pending);
        // No new packets arrive. Each visit still finds the remembered
        // backlog without needing a fresh edge-triggered readiness event,
        // one datagram at a time, until the whole backlog drains.
        for _ in 0..SENT - 1 {
            owner
                .poll_io(Some(Duration::from_millis(50)), || now)
                .unwrap();
        }
        assert_eq!(owner.listener_telemetry().unwrap().invalid_datagrams, SENT);
        owner.poll_io(Some(Duration::ZERO), || now).unwrap();
        assert!(!owner.listener.as_ref().unwrap().recv_pending);
    }

    #[test]
    fn blocked_output_waits_for_writable_then_resumes() {
        let mut owner = Owner::new().unwrap();
        let collector = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        collector.set_nonblocking(true).unwrap();
        let address = collector.local_addr().unwrap();
        let now = Timestamp::from_micros(0);
        owner.connect(&shared_caller_config(address), now).unwrap();
        owner.poll_caller_events(&mut Vec::new());
        let side = owner.caller.as_mut().unwrap();
        side.outbound.push((address, vec![9]));
        side.write_blocked = true;
        owner
            .poll
            .registry()
            .reregister(
                &mut side.socket,
                OWNER_CALLER_TOKEN,
                mio::Interest::READABLE.add(mio::Interest::WRITABLE),
            )
            .unwrap();
        assert_eq!(
            owner.drive(now, OutputDrainBudget::default()).unwrap(),
            crate::OutputDrainStatus::Backpressured
        );
        assert!(owner.time_until_next_deadline(now, 10_000) > 0);
        owner
            .poll_io(Some(Duration::from_millis(50)), || now)
            .unwrap();
        assert!(!owner.caller.as_ref().unwrap().write_blocked);
        owner.drive(now, OutputDrainBudget::default()).unwrap();
        assert!(owner.caller.as_ref().unwrap().outbound.is_empty());
        let mut packet = [0; 1];
        assert_eq!(collector.recv(&mut packet).unwrap(), 1);
        assert_eq!(packet, [9]);
    }

    #[test]
    fn configured_pool_limit_and_shared_socket_compatibility_are_enforced() {
        let mut owner = Owner::new().unwrap();
        let sink = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let config = shared_caller_config(sink.local_addr().unwrap());
        let now = Timestamp::from_micros(0);
        assert!(matches!(
            owner.connect(&config, now).unwrap(),
            PoolOutcome::Admitted(_)
        ));
        assert!(matches!(
            owner.connect(&config, now).unwrap(),
            PoolOutcome::Queued(_)
        ));
        assert_eq!(owner.caller_pool_stats().unwrap().in_flight, 1);
        let mut different = config.clone();
        different.transport.socket_buffers =
            crate::SocketBufferConfig::Bytes(std::num::NonZeroUsize::new(65536).unwrap());
        assert!(owner.connect(&different, now).is_err());
        assert_eq!(owner.caller_pool_stats().unwrap().queued, 1);
        let mut unsupported = listener_config();
        unsupported.transport.promotion = crate::PromotionPolicy::All;
        assert!(owner.listen(&unsupported).is_err());
    }

    #[test]
    fn drive_retains_unsent_output_and_reports_continuation() {
        let mut owner = Owner::new().unwrap();
        let collector = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        collector.set_nonblocking(true).unwrap();
        crate::set_sock_bufs(collector.as_raw_fd(), 8 * 1024 * 1024).unwrap();
        let address = collector.local_addr().unwrap();
        owner
            .connect(&shared_caller_config(address), Timestamp::from_micros(0))
            .unwrap();
        // Inject a retained suffix to exercise the owner independently of
        // protocol scheduling. This exceeds Linux's per-sendmmsg iovec cap.
        const PACKETS: usize = 1100;
        owner.caller.as_mut().unwrap().outbound =
            (0..PACKETS).map(|_| (address, vec![7])).collect();
        let status = owner
            .drive(Timestamp::from_micros(0), OutputDrainBudget::default())
            .unwrap();
        assert_eq!(status, crate::OutputDrainStatus::BudgetExhausted);
        assert!(!owner.caller.as_ref().unwrap().outbound.is_empty());
        assert_eq!(
            owner.time_until_next_deadline(Timestamp::from_micros(0), 100_000),
            0
        );
        let mut received = 0;
        let mut buf = [0; 2048];
        for _ in 0..PACKETS {
            while let Ok(size) = collector.recv(&mut buf) {
                if size == 1 && buf[0] == 7 {
                    received += 1;
                }
            }
            if owner.caller.as_ref().unwrap().outbound.is_empty() {
                break;
            }
            owner
                .drive(Timestamp::from_micros(0), OutputDrainBudget::default())
                .unwrap();
        }
        while let Ok(size) = collector.recv(&mut buf) {
            if size == 1 && buf[0] == 7 {
                received += 1;
            }
        }
        assert_eq!(received, PACKETS);
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
            .configure_transport(|transport| transport.promotion = crate::PromotionPolicy::Never)
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
