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
//! egress socket and drives `feed`/`poll_outbound_bounded` on
//! [`CallerPool::table`]/[`CallerPool::table_mut`] exactly as it would
//! against a bare [`CallerTable`].

use crate::{CallerLeg, CallerTable, LogicalCallerId, PreparedCaller};
use shiguredo_srt::Timestamp;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::time::Duration;

/// What [`CallerPool::connect`] did with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolOutcome {
    /// Admitted immediately: a real `SrtConnection` was built and its
    /// handshake started, with its own `attempt_deadline` clock starting
    /// now -- not from whenever this request was first made.
    Admitted(LogicalCallerId),
    /// The pool was at `max_in_flight`; this request is queued and will be
    /// admitted (with a fresh deadline) as soon as a permit frees up.
    Queued,
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
    /// Lifetime count of requests admitted (whether they went on to
    /// connect, expire, or are still in flight).
    pub started: u64,
    /// Lifetime count of attempts that reached `attempt_deadline` before
    /// `Connected` and were retired.
    pub expired: u64,
}

struct QueuedConnect {
    prepared: PreparedCaller,
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
    in_flight: HashMap<LogicalCallerId, u64>,
    queue: VecDeque<QueuedConnect>,
    started: u64,
    expired: u64,
}

impl CallerPool {
    #[must_use]
    pub fn new(max_in_flight: NonZeroUsize, attempt_deadline: Duration) -> Self {
        Self {
            callers: CallerTable::new(),
            max_in_flight: max_in_flight.get(),
            attempt_deadline_micros: u64::try_from(attempt_deadline.as_micros())
                .unwrap_or(u64::MAX),
            in_flight: HashMap::new(),
            queue: VecDeque::new(),
            started: 0,
            expired: 0,
        }
    }

    /// Immutable access to the underlying table, for read-only operations
    /// (`logical_caller`, `time_until_next_deadline`, ...).
    #[must_use]
    pub fn table(&self) -> &CallerTable {
        &self.callers
    }

    /// Mutable access to the underlying table, for the parts of its API
    /// this pool does not need to intercept (`feed`, `poll_outbound_bounded`,
    /// `logical_caller_mut`, ...). Do not call `add_direct`/`remove` on it
    /// directly for a pooled attempt -- use [`Self::connect`] and
    /// [`Self::poll_expirations`] instead, or `in_flight`/`queue` here will
    /// silently drift from the table's real contents.
    pub fn table_mut(&mut self) -> &mut CallerTable {
        &mut self.callers
    }

    /// Request one outbound connection. Admits it immediately (starting
    /// its own `attempt_deadline` clock now) if under `max_in_flight`,
    /// otherwise queues it -- the queue wait itself never counts against
    /// `attempt_deadline`, only the time after admission does.
    pub fn connect(
        &mut self,
        prepared: PreparedCaller,
        now: Timestamp,
    ) -> Result<PoolOutcome, shiguredo_srt::Error> {
        if self.in_flight.len() >= self.max_in_flight {
            self.queue.push_back(QueuedConnect { prepared });
            return Ok(PoolOutcome::Queued);
        }
        self.admit(prepared, now).map(PoolOutcome::Admitted)
    }

    fn admit(
        &mut self,
        prepared: PreparedCaller,
        now: Timestamp,
    ) -> Result<LogicalCallerId, shiguredo_srt::Error> {
        let connection = prepared.connection(now).map_err(|error| {
            shiguredo_srt::Error::with_reason(
                shiguredo_srt::ErrorKind::InvalidState,
                error.to_string(),
            )
        })?;
        let leg = CallerLeg::new(prepared.remote, connection);
        let id = self.callers.add_direct(leg)?;
        self.in_flight.insert(
            id,
            now.as_micros().saturating_add(self.attempt_deadline_micros),
        );
        self.started += 1;
        Ok(id)
    }

    /// Retire every in-flight attempt that reached `attempt_deadline`
    /// before `Connected`, release its permit, and admit the next queued
    /// request (with a deadline starting now, not whenever it was
    /// originally requested). Also drops any id that has already reached
    /// `Connected` from deadline tracking -- it is no longer an "attempt",
    /// it is an ordinary established session the table itself now owns
    /// for as long as the application keeps it.
    ///
    /// Returns the ids retired for missing their deadline.
    pub fn poll_expirations(&mut self, now: Timestamp) -> Vec<LogicalCallerId> {
        use shiguredo_srt::ConnectionState;
        let now_micros = now.as_micros();
        let mut expired = Vec::new();
        self.in_flight.retain(|&id, &mut deadline_micros| {
            // `raw_direct_state`, not `LogicalCallerState`: the latter
            // folds `Closing` into the same `Connecting` value as a
            // session that has never connected at all, which would make a
            // session that connected and is now gracefully closing
            // indistinguishable from a stalled attempt -- and destroy it,
            // pending SHUTDOWN and all, the moment its original
            // `attempt_deadline` (irrelevant to it by now) passes.
            match self.callers.raw_direct_state(&id) {
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
                ) => false,
                Some(_) if deadline_micros <= now_micros => {
                    expired.push(id);
                    false
                }
                Some(_) => true,
            }
        });
        for id in &expired {
            self.callers.remove(*id);
        }
        self.expired += expired.len() as u64;
        while self.in_flight.len() < self.max_in_flight {
            let Some(QueuedConnect { prepared }) = self.queue.pop_front() else {
                break;
            };
            // A queued request that fails to admit (a malformed config that
            // should have been caught earlier) is dropped rather than
            // retried forever against the same error.
            let _ = self.admit(prepared, now);
        }
        expired
    }

    /// Effective, currently-observable pool state (checkpoint 3/4).
    #[must_use]
    pub fn stats(&self) -> CallerPoolStats {
        CallerPoolStats {
            in_flight: self.in_flight.len(),
            queued: self.queue.len(),
            started: self.started,
            expired: self.expired,
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
        pool.table_mut().poll_outbound(now, &mut outbound);
        for (_, packet) in outbound.drain(..) {
            let _ = listener.admit(peer, &packet, now, options, 0, 1, telemetry);
        }
        listener.poll_outbound(now, &mut outbound);
        for (_, packet) in outbound {
            let _ = pool.table_mut().feed(peer, &packet, now);
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
        assert_eq!(
            c,
            PoolOutcome::Queued,
            "a third request over budget must queue, not admit"
        );
        assert_eq!(pool.stats().in_flight, 2);
        assert_eq!(pool.stats().queued, 1);
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
        assert_eq!(second, PoolOutcome::Queued);

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
        assert_eq!(second, PoolOutcome::Queued);

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
        pool.table_mut()
            .logical_caller_mut(&id)
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
