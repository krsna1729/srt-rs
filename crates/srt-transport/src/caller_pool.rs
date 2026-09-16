//! A bounded outbound connection pool (A04): applies `ConnectConfig`'s
//! `max_in_flight`/`attempt_deadline` to a real [`CallerTable`], which on
//! its own admits every [`CallerTable::add_direct`] call unconditionally
//! and never expires a stalled handshake. Both knobs were already validated
//! by `ConnectConfig::validate` (see config.rs) but nothing actually
//! enforced them -- exactly the "advertised no-op knob" this card exists
//! to close.
//!
//! Deliberately socket-agnostic, like [`CallerTable`] itself: this is pure
//! admission-control/scheduling state, with no socket of its own. An
//! application (or [`crate::mio_transport::Owner`]) still owns the actual
//! egress socket and drives [`CallerPool::feed`] and
//! [`CallerPool::poll_outbound_bounded`] exactly as it would against a bare
//! [`CallerTable`].

use crate::{
    CallerEvent, CallerLeg, CallerTable, DEFAULT_MAX_CALLERS, DatagramSink, LogicalCaller,
    LogicalCallerId, LogicalCallerMut, MAX_CALLERS, OutputDrainBudget, OutputDrainReport,
    PreparedCaller, RemovedLogicalCaller,
};
use srt_proto::Timestamp;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::time::Duration;

/// Hard cap for concurrent caller attempts owned by one pool. It matches the
/// maximum logical caller-table shard size, so the pool cannot accept a limit
/// its underlying table cannot represent without allocation growth.
pub const MAX_CALLER_POOL_IN_FLIGHT: usize = MAX_CALLERS;
/// Hard cap for queued caller requests retained by one pool.
pub const MAX_CALLER_POOL_QUEUE: usize = MAX_CALLERS;

/// Stable identity for a request retained by the legacy queue. IDs never
/// wrap, so a cancelled queue entry cannot alias a later request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PoolRequestId(u64);

impl PoolRequestId {
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// What [`CallerPool::connect`] did with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolOutcome {
    /// Admitted immediately: a real `SrtConnection` was built and its
    /// handshake started, with its own `attempt_deadline` clock starting
    /// now -- not from whenever this request was first made.
    Admitted(LogicalCallerId),
    /// The pool was at `max_in_flight`; this request is queued and will be
    /// admitted (with a fresh deadline) as soon as a permit frees up. The
    /// request ID makes the legacy queue observable and cancellable.
    Queued(PoolRequestId),
    /// No in-flight permit or queue slot was available. `try_connect` and a
    /// full legacy queue return this immediately without retaining the input.
    Full,
}

/// Identifiable lifecycle transitions retained by [`CallerPool`]. Poll these
/// separately from the protocol's [`crate::CallerEvent`] stream so a queued request
/// can be correlated with its eventual admission, failure, expiry, or
/// cancellation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolEvent {
    Queued {
        request_id: PoolRequestId,
    },
    Admitted {
        request_id: PoolRequestId,
        caller_id: LogicalCallerId,
    },
    Expired {
        request_id: PoolRequestId,
        caller_id: LogicalCallerId,
    },
    Failed {
        request_id: PoolRequestId,
        reason: String,
    },
    Cancelled {
        request_id: PoolRequestId,
    },
}

/// Effective, currently-observable state of one [`CallerPool`] -- checkpoint
/// 3/4's "return effective configuration", not advertised config values
/// that may not reflect what is actually enforced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallerPoolStats {
    /// Attempts admitted and still short of `Connected` (subject to
    /// `attempt_deadline`).
    pub in_flight: usize,
    /// Requests waiting for a permit.
    pub queued: usize,
    /// Maximum number of retained queued requests.
    pub queue_capacity: usize,
    /// Lifetime count of requests admitted (whether they went on to
    /// connect, expire, or are still in flight).
    pub started: u64,
    /// Lifetime count of attempts that reached `attempt_deadline` before
    /// `Connected` and were retired.
    pub expired: u64,
    /// Number of queued/admitted requests that failed before connecting.
    pub failed: u64,
    /// Number of queued or admitted requests cancelled by the application.
    pub cancelled: u64,
    /// Number of lifecycle events currently waiting in the outcome queue.
    pub pending_outcomes: usize,
    /// Lifecycle events discarded after the bounded outcome queue filled.
    pub dropped_outcomes: u64,
}

struct QueuedConnect {
    request_id: PoolRequestId,
    prepared: PreparedCaller,
}

#[derive(Clone, Copy)]
struct InFlightAttempt {
    request_id: PoolRequestId,
    deadline_micros: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PoolDeadline {
    deadline_micros: u64,
    caller_id: LogicalCallerId,
}

pub struct CallerPool {
    callers: CallerTable,
    max_in_flight: usize,
    attempt_deadline_micros: u64,
    /// Deadline (protocol micros) for each admitted attempt that has not
    /// yet reached `Connected`. An id present here counts toward
    /// `max_in_flight`; removed once the attempt connects (no longer
    /// subject to `attempt_deadline`, it is now an ordinary established
    /// session) or is retired for missing its deadline.
    in_flight: HashMap<LogicalCallerId, InFlightAttempt>,
    deadlines: BTreeSet<PoolDeadline>,
    queue: VecDeque<QueuedConnect>,
    queue_capacity: usize,
    next_request_id: u64,
    outcomes: VecDeque<PoolEvent>,
    outcome_capacity: usize,
    dropped_outcomes: u64,
    started: u64,
    expired: u64,
    failed: u64,
    cancelled: u64,
    /// Table-owned reusable scratch for bounded expiration visits. Holds at
    /// most `max_actions` candidates per visit; retained across visits so
    /// the production path never allocates.
    visit_scratch: Vec<PoolDeadline>,
}

impl CallerPool {
    #[must_use]
    pub fn new(max_in_flight: NonZeroUsize, attempt_deadline: Duration) -> Self {
        Self::with_queue_capacity(
            max_in_flight,
            attempt_deadline,
            max_in_flight.get().min(1024),
        )
    }

    /// Build a pool with an explicit finite queue bound. A zero capacity is
    /// valid and turns the pool into a non-queueing admission gate while
    /// retaining the old `connect` API.
    #[must_use]
    pub fn with_queue_capacity(
        max_in_flight: NonZeroUsize,
        attempt_deadline: Duration,
        queue_capacity: usize,
    ) -> Self {
        let max_in_flight = max_in_flight.get().min(MAX_CALLER_POOL_IN_FLIGHT);
        let queue_capacity = queue_capacity.min(MAX_CALLER_POOL_QUEUE);
        Self {
            callers: CallerTable::with_max_callers(max_in_flight.max(DEFAULT_MAX_CALLERS)),
            max_in_flight,
            attempt_deadline_micros: u64::try_from(attempt_deadline.as_micros())
                .unwrap_or(u64::MAX),
            in_flight: HashMap::new(),
            deadlines: BTreeSet::new(),
            queue: VecDeque::new(),
            queue_capacity,
            next_request_id: 1,
            outcomes: VecDeque::new(),
            outcome_capacity: queue_capacity.max(1),
            dropped_outcomes: 0,
            started: 0,
            expired: 0,
            failed: 0,
            cancelled: 0,
            visit_scratch: Vec::new(),
        }
    }

    /// Immutable access to the underlying table, for read-only operations
    /// (`logical_caller`, `time_until_next_deadline`, ...).
    #[must_use]
    pub fn table(&self) -> &CallerTable {
        &self.callers
    }

    /// Internal mutable access for runtime adapters. Application code should
    /// use the forwarding methods below so pool admission bookkeeping cannot
    /// be bypassed accidentally.
    #[cfg(any(
        test,
        feature = "mio",
        feature = "tokio",
        feature = "compio",
        feature = "bench-internals"
    ))]
    #[allow(dead_code)]
    pub(crate) fn table_mut(&mut self) -> &mut CallerTable {
        &mut self.callers
    }

    #[cfg(any(test, feature = "bench-internals"))]
    /// Internal mutable access for harness benchmarks only.
    pub fn bench_table_mut(&mut self) -> &mut CallerTable {
        &mut self.callers
    }

    /// Feed one datagram into the pooled caller table.
    pub fn feed(
        &mut self,
        peer: std::net::SocketAddr,
        data: &[u8],
        now: Timestamp,
    ) -> Result<bool, srt_proto::Error> {
        self.callers.feed(peer, data, now)
    }

    /// Drain caller output for the application-owned socket.
    pub fn poll_outbound(
        &mut self,
        now: Timestamp,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) {
        self.callers.poll_outbound(now, out);
    }

    /// Drain caller output with an explicit work budget.
    pub fn poll_outbound_bounded(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
        out: &mut Vec<(std::net::SocketAddr, Vec<u8>)>,
    ) -> OutputDrainReport {
        self.callers.poll_outbound_bounded(now, budget, out)
    }

    /// Drain caller output with an explicit work budget into any [`DatagramSink`].
    pub fn poll_outbound_bounded_to<S: DatagramSink + ?Sized>(
        &mut self,
        now: Timestamp,
        budget: OutputDrainBudget,
        sink: &mut S,
    ) -> OutputDrainReport {
        self.callers.poll_outbound_bounded_to(now, budget, sink)
    }

    /// Drain caller protocol events with an explicit event bound.
    pub fn poll_events_bounded(&mut self, max_events: usize, out: &mut Vec<CallerEvent>) -> bool {
        self.callers.poll_events_bounded(max_events, out)
    }

    /// Drain caller protocol events using the default finite work bound.
    pub fn poll_events(&mut self, out: &mut Vec<CallerEvent>) {
        self.callers.poll_events(out);
    }

    /// Borrow one logical caller without exposing the table itself.
    #[must_use]
    pub fn logical_caller(&self, id: &LogicalCallerId) -> Option<LogicalCaller<'_>> {
        self.callers.logical_caller(id)
    }

    /// Mutably borrow one logical caller without exposing admission methods.
    pub fn logical_caller_mut(&mut self, id: &LogicalCallerId) -> Option<LogicalCallerMut<'_>> {
        self.callers.logical_caller_mut(id)
    }

    fn allocate_request_id(&mut self) -> Result<PoolRequestId, srt_proto::Error> {
        let id = PoolRequestId(self.next_request_id);
        self.next_request_id = self.next_request_id.checked_add(1).ok_or_else(|| {
            srt_proto::Error::with_reason(
                srt_proto::ErrorKind::InvalidState,
                "caller pool request ID space exhausted",
            )
        })?;
        Ok(id)
    }

    /// Retain a lifecycle event (finding 9), dropping the oldest once the
    /// bounded outcome queue is full -- a request identity that already
    /// resolved is more useful to a consumer than one still pending.
    fn push_outcome(&mut self, event: PoolEvent) {
        if self.outcomes.len() >= self.outcome_capacity {
            self.outcomes.pop_front();
            self.dropped_outcomes = self.dropped_outcomes.saturating_add(1);
        }
        self.outcomes.push_back(event);
    }

    /// Drain retained lifecycle events: correlates a request with its
    /// eventual admission, failure, expiry, or cancellation (finding 9).
    pub fn poll_outcomes(&mut self, out: &mut Vec<PoolEvent>) {
        self.poll_outcomes_bounded(crate::OutputDrainBudget::default().max_actions, out);
    }

    /// Drain at most `max_events` retained lifecycle outcomes.
    pub fn poll_outcomes_bounded(&mut self, max_events: usize, out: &mut Vec<PoolEvent>) {
        out.clear();
        let count = max_events.min(self.outcomes.len());
        out.extend(self.outcomes.drain(..count));
    }

    /// Request one outbound connection. Admits it immediately (starting
    /// its own `attempt_deadline` clock now) if under `max_in_flight`,
    /// otherwise queues it -- the queue wait itself never counts against
    /// `attempt_deadline`, only the time after admission does. A queue
    /// already at `queue_capacity` returns [`PoolOutcome::Full`]
    /// immediately rather than growing without bound.
    pub fn connect(
        &mut self,
        prepared: PreparedCaller,
        now: Timestamp,
    ) -> Result<PoolOutcome, srt_proto::Error> {
        let request_id = self.allocate_request_id()?;
        if self.in_flight.len() < self.max_in_flight {
            let id = self.admit(request_id, prepared, now)?;
            self.push_outcome(PoolEvent::Admitted {
                request_id,
                caller_id: id,
            });
            return Ok(PoolOutcome::Admitted(id));
        }
        if self.queue.len() >= self.queue_capacity {
            return Ok(PoolOutcome::Full);
        }
        self.queue.push_back(QueuedConnect {
            request_id,
            prepared,
        });
        self.push_outcome(PoolEvent::Queued { request_id });
        Ok(PoolOutcome::Queued(request_id))
    }

    fn admit(
        &mut self,
        request_id: PoolRequestId,
        prepared: PreparedCaller,
        now: Timestamp,
    ) -> Result<LogicalCallerId, srt_proto::Error> {
        let connection = prepared.connection(now).map_err(|error| {
            srt_proto::Error::with_reason(srt_proto::ErrorKind::InvalidState, error.to_string())
        })?;
        let leg = CallerLeg::new(prepared.remote, connection);
        let id = self.callers.add_direct(leg)?;
        let deadline_micros = now.as_micros().saturating_add(self.attempt_deadline_micros);
        self.in_flight.insert(
            id,
            InFlightAttempt {
                request_id,
                deadline_micros,
            },
        );
        self.deadlines.insert(PoolDeadline {
            deadline_micros,
            caller_id: id,
        });
        self.started = self.started.saturating_add(1);
        Ok(id)
    }

    /// Admit queued requests into whatever permits are currently free,
    /// each with its deadline starting now (not whenever it was
    /// originally requested).
    fn admit_queued(&mut self, now: Timestamp, max_actions: usize) -> usize {
        let mut actions = 0;
        while actions < max_actions && self.in_flight.len() < self.max_in_flight {
            let Some(QueuedConnect {
                request_id,
                prepared,
            }) = self.queue.pop_front()
            else {
                break;
            };
            actions += 1;
            match self.admit(request_id, prepared, now) {
                Ok(id) => self.push_outcome(PoolEvent::Admitted {
                    request_id,
                    caller_id: id,
                }),
                // A queued request that fails to admit (a malformed config
                // that should have been caught earlier) is retired rather
                // than retried forever against the same error.
                Err(error) => {
                    self.failed += 1;
                    self.push_outcome(PoolEvent::Failed {
                        request_id,
                        reason: error.to_string(),
                    });
                }
            }
        }
        actions
    }

    /// Retire every in-flight attempt that reached `attempt_deadline`
    /// before `Connected`, release its permit, and admit the next queued
    /// request. Also drops any id that has already reached `Connected`
    /// from deadline tracking -- it is no longer an "attempt", it is an
    /// ordinary established session the table itself now owns for as long
    /// as the application keeps it.
    ///
    /// Returns the ids retired for missing their deadline.
    pub fn poll_expirations(&mut self, now: Timestamp) -> Vec<LogicalCallerId> {
        self.poll_expirations_bounded(now, crate::OutputDrainBudget::default().max_actions)
    }

    /// Bounded counterpart to [`Self::poll_expirations`] (finding 3/10):
    /// visits at most `max_actions` deadline-ordered entries per call
    /// (earliest first, via the `deadlines` `BTreeSet`) instead of
    /// scanning every in-flight attempt unconditionally.
    pub fn poll_expirations_bounded(
        &mut self,
        now: Timestamp,
        max_actions: usize,
    ) -> Vec<LogicalCallerId> {
        self.poll_expirations_bounded_with_visits(now, max_actions)
            .0
    }

    /// Count-only maintenance: identical bounded work to
    /// [`Self::poll_expirations_bounded_with_visits`], without materializing
    /// the retired ids.
    ///
    /// The production Compio Owner only needs the visit count (it surfaces
    /// retired sessions through `PoolEvent`s it already drains), so this path
    /// allocates nothing at all -- an `Option<&mut Vec>` that stays `None`
    /// rather than a fresh `Vec` the caller would immediately discard.
    pub(crate) fn poll_expirations_count_only(
        &mut self,
        now: Timestamp,
        max_actions: usize,
    ) -> usize {
        self.expire_due(now, max_actions, None)
    }

    pub(crate) fn poll_expirations_bounded_with_visits(
        &mut self,
        now: Timestamp,
        max_actions: usize,
    ) -> (Vec<LogicalCallerId>, usize) {
        let mut retired = Vec::new();
        let visits = self.expire_due(now, max_actions, Some(&mut retired));
        (retired, visits)
    }

    /// The single bounded expiration pass. `retired` is `None` for the
    /// count-only path, which is what keeps that path allocation-free.
    fn expire_due(
        &mut self,
        now: Timestamp,
        max_actions: usize,
        mut retired: Option<&mut Vec<LogicalCallerId>>,
    ) -> usize {
        use srt_proto::ConnectionState;
        if max_actions == 0 {
            return 0;
        }
        let now_micros = now.as_micros();
        // Non-allocating production path: reuse table-owned scratch for
        self.visit_scratch.clear();
        self.visit_scratch
            .extend(self.deadlines.iter().take(max_actions).copied());
        let candidate_actions = self.visit_scratch.len();
        let mut expired_count = 0usize;
        let mut idx = 0;
        while idx < self.visit_scratch.len() {
            let candidate = self.visit_scratch[idx];
            idx += 1;
            // `raw_direct_state`, not `LogicalCallerState`: the latter
            // folds `Closing` into the same `Connecting` value as a
            // session that has never connected at all, which would make a
            // session that connected and is now gracefully closing
            // indistinguishable from a stalled attempt -- and destroy it,
            // pending SHUTDOWN and all, the moment its original
            // `attempt_deadline` (irrelevant to it by now) passes.
            match self.callers.raw_direct_state(&candidate.caller_id) {
                // Resolved one way or another -- succeeded, or already
                // closing/closed on its own -- so no longer a stalled
                // attempt this pool should retire. A rejected handshake
                // (straight to `Disconnected` without ever reaching
                // `Connected`) also releases its permit immediately here
                // rather than holding it for the rest of `attempt_deadline`.
                None
                | Some(
                    ConnectionState::Connected
                    | ConnectionState::Disconnected
                    | ConnectionState::Closing,
                ) => {
                    self.deadlines.remove(&candidate);
                    self.in_flight.remove(&candidate.caller_id);
                }
                Some(_) if candidate.deadline_micros <= now_micros => {
                    self.deadlines.remove(&candidate);
                    if let Some(attempt) = self.in_flight.remove(&candidate.caller_id) {
                        self.callers.remove(candidate.caller_id);
                        self.push_outcome(PoolEvent::Expired {
                            request_id: attempt.request_id,
                            caller_id: candidate.caller_id,
                        });
                        if let Some(out) = retired.as_deref_mut() {
                            out.push(candidate.caller_id);
                        }
                    }
                    expired_count += 1;
                }
                Some(_) => {}
            }
        }
        self.visit_scratch.clear();
        self.expired = self.expired.saturating_add(expired_count as u64);
        let admitted = self.admit_queued(now, max_actions.saturating_sub(candidate_actions));
        candidate_actions.saturating_add(admitted)
    }

    /// Atomically retire one pooled attempt or established session,
    /// releasing its permit and any pending-deadline bookkeeping. The
    /// caller table counterpart to [`CallerTable::remove`]; use this
    /// instead of `table_mut().remove(...)` for anything this pool ever
    /// admitted, or `in_flight`/`deadlines` silently drift from the
    /// table's real contents.
    pub fn remove(&mut self, id: LogicalCallerId) -> Option<RemovedLogicalCaller> {
        if let Some(attempt) = self.in_flight.remove(&id) {
            self.deadlines.remove(&PoolDeadline {
                deadline_micros: attempt.deadline_micros,
                caller_id: id,
            });
            self.cancelled = self.cancelled.saturating_add(1);
            self.push_outcome(PoolEvent::Cancelled {
                request_id: attempt.request_id,
            });
        }
        self.callers.remove(id)
    }

    /// Microseconds until either this pool's own earliest attempt
    /// deadline or the underlying table's next protocol timer, whichever
    /// is sooner.
    #[must_use]
    pub fn time_until_next_deadline(&self, now: Timestamp, default_micros: u64) -> u64 {
        let table_us = self.callers.time_until_next_deadline(now, default_micros);
        let Some(entry) = self.deadlines.iter().next() else {
            return table_us;
        };
        let pool_us = entry
            .deadline_micros
            .saturating_sub(now.as_micros())
            .min(default_micros);
        pool_us.min(table_us)
    }

    /// Effective, currently-observable pool state (checkpoint 3/4).
    #[must_use]
    pub fn stats(&self) -> CallerPoolStats {
        CallerPoolStats {
            in_flight: self.in_flight.len(),
            queued: self.queue.len(),
            queue_capacity: self.queue_capacity,
            started: self.started,
            expired: self.expired,
            failed: self.failed,
            cancelled: self.cancelled,
            pending_outcomes: self.outcomes.len(),
            dropped_outcomes: self.dropped_outcomes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdmissionOptions, IngressTelemetry, LogicalCallerState, PeerTable, RuntimeFlavor};
    use std::net::SocketAddr;

    fn prepared_caller(remote: SocketAddr) -> PreparedCaller {
        crate::CallerConfig::builder(remote)
            .build()
            .expect("caller config")
            .prepare(RuntimeFlavor::Mio)
            .expect("prepared caller")
    }

    #[test]
    fn pool_clamps_adversarial_capacities() {
        let pool = CallerPool::with_queue_capacity(
            NonZeroUsize::new(usize::MAX).expect("non-zero"),
            Duration::from_secs(1),
            usize::MAX,
        );
        let stats = pool.stats();
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.queued, 0);
        assert_eq!(stats.queue_capacity, MAX_CALLER_POOL_QUEUE);
        assert_eq!(pool.table().max_callers(), MAX_CALLER_POOL_IN_FLIGHT);
    }

    /// One round trip between a pool's caller side and a fake listener,
    /// using `peer` as a fixed stand-in source address for both directions
    /// (no real socket exists in this test, so there is nothing else to key
    /// routing on) -- mirrors `caller::tests::pump_caller_table`.
    fn pump(
        pool: &mut CallerPool,
        listener: &mut PeerTable,
        peer: SocketAddr,
        options: &AdmissionOptions,
        telemetry: &IngressTelemetry,
        now: Timestamp,
    ) {
        let mut outbound = Vec::new();
        pool.poll_outbound(now, &mut outbound);
        for (_, packet) in outbound.drain(..) {
            let _ = listener.admit(peer, &packet, now, options, 0, 1, telemetry);
        }
        listener.poll_outbound(now, &mut outbound);
        for (_, packet) in outbound {
            let _ = pool.feed(peer, &packet, now);
        }
    }

    /// A04: the pool must never admit more than `max_in_flight` attempts
    /// at once, queuing the rest instead of silently oversubscribing
    /// `CallerTable`.
    #[test]
    fn pool_never_exceeds_max_in_flight_and_queues_the_rest() {
        let mut pool = CallerPool::new(NonZeroUsize::new(2).unwrap(), Duration::from_secs(5));
        let remote: SocketAddr = "127.0.0.1:19000".parse().unwrap();
        let now = Timestamp::from_micros(0);

        let a = pool
            .connect(prepared_caller(remote), now)
            .expect("connect a");
        let b = pool
            .connect(prepared_caller(remote), now)
            .expect("connect b");
        let c = pool
            .connect(prepared_caller(remote), now)
            .expect("connect c");

        assert!(matches!(a, PoolOutcome::Admitted(_)));
        assert!(matches!(b, PoolOutcome::Admitted(_)));
        assert!(
            matches!(c, PoolOutcome::Queued(_)),
            "a third request over budget must queue, not admit"
        );
        assert_eq!(pool.stats().in_flight, 2);
        assert_eq!(pool.stats().queued, 1);
    }

    #[test]
    fn queued_request_outcomes_keep_the_request_identity() {
        let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap(), Duration::from_secs(1));
        let remote: SocketAddr = "127.0.0.1:19005".parse().unwrap();
        let now = Timestamp::from_micros(0);
        let first = pool
            .connect(prepared_caller(remote), now)
            .expect("first connect");
        let first_id = match first {
            PoolOutcome::Admitted(id) => id,
            other => panic!("first request must admit, got {other:?}"),
        };
        let queued = pool
            .connect(prepared_caller(remote), now)
            .expect("queued connect");
        let request_id = match queued {
            PoolOutcome::Queued(id) => id,
            other => panic!("second request must queue, got {other:?}"),
        };

        let mut events = Vec::new();
        pool.poll_outcomes(&mut events);
        assert!(events.iter().any(|event| {
            matches!(event, PoolEvent::Queued { request_id: id } if *id == request_id)
        }));

        pool.poll_expirations(Timestamp::from_micros(2_000_000));
        pool.poll_outcomes(&mut events);
        assert!(events.iter().any(|event| {
            matches!(
                event,
                PoolEvent::Admitted {
                    request_id: id,
                    caller_id,
                } if *id == request_id && *caller_id != first_id
            )
        }));
    }

    /// A04: a stalled attempt (never reaches `Connected`) must be retired
    /// once it passes `attempt_deadline`, releasing its permit so the
    /// queued request behind it is admitted.
    #[test]
    fn stalled_attempt_expires_and_releases_its_permit_for_the_next_queued_request() {
        let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap(), Duration::from_micros(1_000));
        let remote: SocketAddr = "127.0.0.1:19001".parse().unwrap();
        let start = Timestamp::from_micros(0);

        let PoolOutcome::Admitted(first_id) = pool
            .connect(prepared_caller(remote), start)
            .expect("connect first")
        else {
            panic!("first request must admit under budget")
        };
        let second = pool
            .connect(prepared_caller(remote), start)
            .expect("connect second");
        assert!(matches!(second, PoolOutcome::Queued(_)));

        // `first_id` is never fed a response -- it just sits half-open.
        let expired = pool.poll_expirations(Timestamp::from_micros(2_000));
        assert_eq!(expired, vec![first_id]);
        assert_eq!(
            pool.stats().in_flight,
            1,
            "the queued request must now be admitted in the expired one's place"
        );
        assert_eq!(pool.stats().queued, 0);
        assert!(
            pool.table().logical_caller(&first_id).is_none(),
            "the expired attempt must be removed from the table, not just forgotten by the pool"
        );
    }

    /// A04: a request's attempt-deadline clock must start when it is
    /// actually admitted, not when it was first requested -- a long queue
    /// wait must not eat into (or already exceed) the attempt it is
    /// eventually given.
    #[test]
    fn a_queued_requests_deadline_starts_at_its_own_admission_not_the_original_request() {
        let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap(), Duration::from_micros(1_000));
        let remote: SocketAddr = "127.0.0.1:19002".parse().unwrap();
        let start = Timestamp::from_micros(0);

        let PoolOutcome::Admitted(first_id) = pool
            .connect(prepared_caller(remote), start)
            .expect("connect first")
        else {
            panic!("first request must admit under budget")
        };
        let second = pool
            .connect(prepared_caller(remote), start)
            .expect("connect second");
        assert!(matches!(second, PoolOutcome::Queued(_)));

        // The queued request waits far longer than `attempt_deadline`
        // before a permit ever frees up -- none of that queue wait may
        // count against the deadline it is given once admitted.
        let admission_time = Timestamp::from_micros(50_000);
        let expired = pool.poll_expirations(admission_time);
        assert_eq!(
            expired,
            vec![first_id],
            "only the stalled first attempt expires"
        );
        assert_eq!(
            pool.stats().in_flight,
            1,
            "the queued request must now be admitted"
        );

        // Immediately re-checking at the same instant it was admitted must
        // not expire it -- if the deadline had wrongly been computed from
        // the original request time (0), it would already be overdue here.
        let expired_again = pool.poll_expirations(admission_time);
        assert!(
            expired_again.is_empty(),
            "an attempt admitted this instant must not read back as already expired"
        );
    }

    /// A04: once an attempt actually reaches `Connected`, it is an
    /// ordinary established session, not a stalled attempt -- it must
    /// never be retired by `poll_expirations` no matter how much later
    /// that is called, even long past `attempt_deadline`.
    #[test]
    fn a_connected_attempt_is_never_treated_as_expired() {
        let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap(), Duration::from_micros(1_000));
        let remote: SocketAddr = "127.0.0.1:19003".parse().unwrap();
        let options = AdmissionOptions::basic(0xC0DE, 20, false);
        let telemetry = IngressTelemetry::new();
        let mut listener = PeerTable::new();

        let PoolOutcome::Admitted(id) = pool
            .connect(prepared_caller(remote), Timestamp::from_micros(0))
            .expect("connect")
        else {
            panic!("must admit under budget")
        };

        for round in 0..10 {
            let now = Timestamp::from_micros(round * 100);
            pump(&mut pool, &mut listener, remote, &options, &telemetry, now);
            if pool.table().logical_caller(&id).and_then(|c| c.state())
                == Some(LogicalCallerState::Connected)
            {
                break;
            }
        }
        assert_eq!(
            pool.table().logical_caller(&id).and_then(|c| c.state()),
            Some(LogicalCallerState::Connected),
            "the handshake must actually complete for this test to prove anything"
        );

        let expired = pool.poll_expirations(Timestamp::from_micros(1_000_000));
        assert!(
            expired.is_empty(),
            "a connected session must never be expired as a stalled attempt"
        );
        assert!(
            pool.table().logical_caller(&id).is_some(),
            "the connected session must remain in the table"
        );
    }

    /// Opus review (A04): a session that reached `Connected` and is now
    /// gracefully closing must never be expired, even if `poll_expirations`
    /// is never called while it was still `Connected` to "notice" the
    /// success first -- `LogicalCallerState` folds `Closing` into the same
    /// `Connecting` value as a session that never connected at all, so a
    /// naive check keyed on that coarse enum cannot tell the two apart and
    /// would destroy a legitimately closing session's pending SHUTDOWN
    /// once its (by-then-irrelevant) original attempt_deadline passes.
    #[test]
    fn a_gracefully_closing_session_is_never_treated_as_an_expired_attempt() {
        let mut pool = CallerPool::new(NonZeroUsize::new(1).unwrap(), Duration::from_micros(1_000));
        let remote: SocketAddr = "127.0.0.1:19004".parse().unwrap();
        let options = AdmissionOptions::basic(0xC0FE, 20, false);
        let telemetry = IngressTelemetry::new();
        let mut listener = PeerTable::new();

        let PoolOutcome::Admitted(id) = pool
            .connect(prepared_caller(remote), Timestamp::from_micros(0))
            .expect("connect")
        else {
            panic!("must admit under budget")
        };

        for round in 0..10 {
            let now = Timestamp::from_micros(round * 100);
            pump(&mut pool, &mut listener, remote, &options, &telemetry, now);
            if pool.table().logical_caller(&id).and_then(|c| c.state())
                == Some(LogicalCallerState::Connected)
            {
                break;
            }
        }
        assert_eq!(
            pool.table().logical_caller(&id).and_then(|c| c.state()),
            Some(LogicalCallerState::Connected),
            "the handshake must actually complete for this test to prove anything"
        );

        // Start an orderly close immediately -- `poll_expirations` is
        // never called while this session reads back as `Connected`.
        pool.logical_caller_mut(&id)
            .expect("session still exists")
            .disconnect(Timestamp::from_micros(500));

        // Long past the original attempt_deadline.
        let expired = pool.poll_expirations(Timestamp::from_micros(1_000_000));
        assert!(
            expired.is_empty(),
            "a gracefully closing session must never be expired as a stalled attempt, \
             even though poll_expirations never observed it as Connected first"
        );
        assert!(
            pool.table().logical_caller(&id).is_some(),
            "the closing session must remain in the table, not be silently destroyed"
        );
    }
}
