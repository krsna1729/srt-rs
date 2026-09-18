//! Sender retransmission-timeout (RTO) state.
//!
//! # Why the sender needs its own timer
//!
//! SRT's ordinary recovery path is receiver-driven: the receiver NAKs a loss
//! it has evidence for, and the sender re-sends exactly those sequences. That
//! path cannot recover a lost *suffix* of a flight, because no later sequence
//! number ever arrives to expose the gap -- the receiver reports no loss while
//! the payload is simply absent. The sender's retransmission timer is the only
//! party left that can notice, so it has to be a real elapsed-time timer that
//! the transport arms and fires on its own.
//!
//! That distinction is the whole point of this module: queuing the right
//! recovery *action* is not the same property as *arming* and *firing* the
//! trigger. A probe that only runs when a test calls the timer handler by hand
//! proves the action, not the recovery.
//!
//! # Relationship to the other retransmission timer
//!
//! `TimerId::RetransmitContinue` is not this timer. It is a zero-delay
//! continuation of an already-existing NAK-driven retransmission queue, used to
//! bound work per visit; it carries no notion of elapsed time or loss. Mixing
//! the two is what made the recovery action unreachable in production: a timer
//! that is only ever armed by the code that drains a queue can never fire
//! because nothing filled the queue.
//!
//! # Timeout formula
//!
//! The SRT specification (`draft-sharabayko-srt`) defines a sender
//! retransmission timeout directly:
//!
//! ```text
//! RTO = RTT + 4*RTTVar + 2*SYN
//!
//! continuous timeout: RTO = RexmitCount * (RTT + 4*RTTVar + 2*SYN) + SYN
//! ```
//!
//! where `SYN` is the spec's 10 ms control-packet synchronization interval
//! (`COMM_SYN`, [`crate::receiver::ACK_INTERVAL_MICROS`]) -- not a compatibility
//! choice this crate invented, but the constant the draft itself names. `RTT`
//! and `RTTVar` are this *sender's own* §4.10 estimator state
//! (`SenderBuffer::sender_rtt_micros`/`sender_rtt_var_micros`), smoothed by
//! the same EWMA the receiver half of this crate uses for its own raw
//! round-trip samples -- not the peer's Full-ACK report substituted
//! outright. A Full ACK's reported RTT (see `SrtConnection::handle_ack`) is
//! the *input* to that smoothing, folded in as one more sample each time,
//! because the draft specifies estimation at whichever node is doing the
//! estimating, not a wholesale replacement with the peer's own already-
//! smoothed figure. Before the first Full ACK the estimator starts at the
//! same 100 ms / 50 ms the receiver starts from, so the initial timeout is
//! `100 + 4*50 + 2*10 = 320` ms.
//!
//! This module doubles the whole quantity per consecutive expiry rather than
//! implementing the draft's `RexmitCount` continuous-timeout term literally --
//! that is an explicit implementation deviation, not a compatibility claim,
//! and is not itself mandated or forbidden by the draft. libsrt has no
//! sender-side DATA timeout at all (its retransmission is entirely
//! NAK-driven), so there is no libsrt formula to match either; what is
//! attributable to the independent reference implementation audited in
//! `docs/differential-audit-robotweax.md` is the tail-probe recovery policy
//! and the non-progress-ACK starvation fix, not the existence of a
//! retransmission timeout or its base formula, both of which come from the
//! spec.

/// `SYN` / `COMM_SYN` control-packet synchronization interval, in
/// microseconds, exactly as `draft-sharabayko-srt` names it in the sender RTO
/// formula. Equal to [`crate::receiver::ACK_INTERVAL_MICROS`] -- the same
/// constant, not a coincidentally matching duplicate -- since both are the
/// spec's one `COMM_SYN` value.
pub const COMM_SYN_MICROS: u64 = crate::receiver::ACK_INTERVAL_MICROS;

/// Peer-reported smoothed RTT used before the first Full ACK arrives.
pub const INITIAL_SRTT_MICROS: u32 = 100_000;

/// Peer-reported RTT variance used before the first Full ACK arrives.
pub const INITIAL_RTT_VAR_MICROS: u32 = 50_000;

/// Ceiling on the timeout, after any backoff.
///
/// The timer is a backstop for a sender that has no evidence left, not a
/// retransmission policy: past this point TLPKTDROP (`max(latency * 1.25, 1 s)`)
/// and the 5 s inactivity timeout have already decided the packet's fate, so a
/// longer wait would only delay the probe that exposes the stall.
pub const MAX_RTO_MICROS: u64 = 4_000_000;

/// Largest backoff shift applied. `2^6` reaches the ceiling from the initial
/// 320 ms timeout, so further shifts cannot change the result.
const MAX_BACKOFF_SHIFT: u32 = 6;

/// What a DATA submission means for the sender's retransmission timeout.
///
/// Produced by [`crate::sender::SenderBuffer::note_data_submitted`], the boundary
/// at which the protocol learns a datagram really left it. Three outcomes,
/// because "submission" covers three different events and only two of them may
/// touch the deadline:
///
/// * an ordinary submission while an epoch is running changes nothing --
///   restarting on submission would let a busy sender postpone its own timeout
///   forever while one early packet stayed stranded, which is the failure this
///   timer exists to catch;
/// * the first submission after an empty flight starts a fresh epoch;
/// * the pending blind probe actually crossing the submission boundary
///   reprograms the epoch from that instant (see [`SenderRto::rearm`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtoArm {
    Nothing,
    Start,
    Rearm,
}

/// Sender-side retransmission timeout.
///
/// Holds only what the protocol owns: whether an epoch is running, how many
/// consecutive expiries have gone without cumulative ACK progress, and
/// whether a blind probe this epoch queued is still waiting to actually leave
/// the protocol. Absolute time belongs to the transport's timer store, which
/// programs a deadline from the duration this type returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenderRto {
    armed: bool,
    backoffs: u32,
    /// Sequence of a blind probe queued for retransmission but not yet
    /// confirmed to have actually been submitted to the transport (see
    /// [`Self::probe_pending`]).
    probe_pending: Option<u32>,
}

impl SenderRto {
    /// A disarmed timeout (nothing submitted is outstanding).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            armed: false,
            backoffs: 0,
            probe_pending: None,
        }
    }

    /// Whether an epoch is running.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Consecutive expiries without cumulative ACK progress.
    #[must_use]
    pub const fn backoffs(&self) -> u32 {
        self.backoffs
    }

    /// Sequence of a blind probe this epoch queued for retransmission that
    /// has not yet been confirmed to have actually left the protocol.
    ///
    /// `queue_retransmission_of_newest_submitted` and `process_retransmit`
    /// only *queue* the probe into the connection's output queue; a
    /// transport with no TX capacity left can leave it sitting there,
    /// un-submitted, indefinitely. `has_retransmit()` alone cannot tell that
    /// apart from "already submitted", because the retransmit-membership
    /// queue is dequeued the moment the datagram is materialized into
    /// output, not when it actually leaves the protocol. Tracking the
    /// pending sequence separately, cleared only by
    /// [`Self::confirm_probe_submitted`], is what keeps a subsequent expiry
    /// from queuing a second blind probe behind the first one -- an
    /// unbounded accumulation during prolonged TX starvation, and exactly
    /// the "one probe" property this timer exists to guarantee.
    #[must_use]
    pub const fn probe_pending(&self) -> Option<u32> {
        self.probe_pending
    }

    /// Record that a blind probe of `sequence` was just queued.
    pub fn set_probe_pending(&mut self, sequence: u32) {
        self.probe_pending = Some(sequence);
    }

    /// Confirm that `sequence` actually left the protocol, clearing the
    /// pending marker if it matches. A submission of a *different* sequence
    /// (an ordinary first transmission, or NAK-driven recovery running
    /// alongside) must not clear a still-outstanding probe.
    ///
    /// Returns whether this submission *was* the pending blind probe, which is
    /// the event that has to reprogram the epoch (see [`Self::rearm`]).
    pub fn confirm_probe_submitted(&mut self, sequence: u32) -> bool {
        if self.probe_pending == Some(sequence) {
            self.probe_pending = None;
            true
        } else {
            false
        }
    }

    /// Base timeout from the peer's most recent Full-ACK measurements.
    ///
    /// `None` (no Full ACK yet) uses the receiver's own initial constants.
    #[must_use]
    pub fn base_timeout_micros(reported_rtt: Option<(u32, u32)>) -> u64 {
        let (srtt, rtt_var) = match reported_rtt {
            Some((rtt, var)) if rtt > 0 => (u64::from(rtt), u64::from(var)),
            _ => (
                u64::from(INITIAL_SRTT_MICROS),
                u64::from(INITIAL_RTT_VAR_MICROS),
            ),
        };
        (srtt + 4 * rtt_var + 2 * COMM_SYN_MICROS).min(MAX_RTO_MICROS)
    }

    /// The timeout this epoch would program right now.
    #[must_use]
    pub fn timeout_micros(&self, base_micros: u64) -> u64 {
        let shift = self.backoffs.min(MAX_BACKOFF_SHIFT);
        base_micros
            .saturating_mul(1u64 << shift)
            .min(MAX_RTO_MICROS)
    }

    /// Start a fresh epoch: the first DATA datagram after an empty flight, or
    /// cumulative ACK progress with a flight still outstanding.
    ///
    /// Clears any accumulated backoff -- progress is exactly the evidence that
    /// the previous expiries were not a persistent stall.
    ///
    /// Only these two events may start an epoch. Restarting on *submission*
    /// would let a busy sender postpone the timeout forever while one early
    /// packet stays stranded, which is the failure this timer exists to catch.
    pub fn start(&mut self, base_micros: u64) -> u64 {
        self.armed = true;
        self.backoffs = 0;
        self.timeout_micros(base_micros)
    }

    /// Stop the epoch: nothing that was actually submitted is outstanding.
    pub fn stop(&mut self) {
        self.armed = false;
        self.backoffs = 0;
        self.probe_pending = None;
    }

    /// Record an expiry and return the next timeout to program.
    pub fn expire(&mut self, base_micros: u64) -> u64 {
        self.armed = true;
        self.backoffs = self.backoffs.saturating_add(1);
        self.timeout_micros(base_micros)
    }

    /// Reprogram the epoch from the instant a blind probe actually left the
    /// protocol, returning the timeout to program.
    ///
    /// The timeout is defined as elapsed time **after DATA is sent**, and a
    /// probe queued into the connection's output is not DATA sent: a transport
    /// with no TX capacity can leave it sitting until shortly before the
    /// deadline it was queued under. Left alone, that deadline then fires a few
    /// microseconds after the probe finally goes out and permits another blind
    /// probe with essentially no elapsed-time evidence behind it -- two probes
    /// in a row, which is the thing the one-probe bound exists to prevent.
    /// Reprogramming here restarts the *measurement*, not the policy:
    /// `backoffs` is preserved, because a submission is not the ACK progress
    /// that is allowed to reset the backoff.
    pub fn rearm(&mut self, base_micros: u64) -> u64 {
        self.armed = true;
        self.timeout_micros(base_micros)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_timeout_uses_the_receiver_starting_constants() {
        // 100 ms SRTT + 4 x 50 ms RTTVar + 2 x 10 ms SYN = 320 ms, per the
        // spec's `RTO = RTT + 4*RTTVar + 2*SYN`.
        assert_eq!(SenderRto::base_timeout_micros(None), 320_000);
        // A zero RTT is not a measurement; it falls back rather than collapsing
        // the timeout to the sync interval.
        assert_eq!(SenderRto::base_timeout_micros(Some((0, 0))), 320_000);
    }

    #[test]
    fn base_timeout_tracks_peer_reported_measurements() {
        // 20 ms SRTT + 4 x 1 ms + 2 x 10 ms SYN = 44 ms.
        assert_eq!(
            SenderRto::base_timeout_micros(Some((20_000, 1_000))),
            44_000
        );
        // A reported RTT larger than the ceiling pins to the ceiling.
        assert_eq!(
            SenderRto::base_timeout_micros(Some((9_000_000, 0))),
            MAX_RTO_MICROS
        );
    }

    #[test]
    fn backoff_doubles_and_saturates_at_the_ceiling() {
        let base = 320_000;
        let mut rto = SenderRto::new();
        assert!(!rto.is_armed());
        assert_eq!(rto.start(base), 320_000);
        assert!(rto.is_armed());
        assert_eq!(rto.expire(base), 640_000);
        assert_eq!(rto.expire(base), 1_280_000);
        assert_eq!(rto.expire(base), 2_560_000);
        assert_eq!(rto.expire(base), MAX_RTO_MICROS);
        assert_eq!(rto.backoffs(), 4);
    }

    #[test]
    fn start_clears_backoff_and_stop_disarms() {
        let base = 320_000;
        let mut rto = SenderRto::new();
        rto.expire(base);
        rto.expire(base);
        assert_eq!(rto.backoffs(), 2);
        assert_eq!(rto.start(base), base, "progress restarts from the base");
        assert_eq!(rto.backoffs(), 0);
        rto.stop();
        assert!(!rto.is_armed());
        assert_eq!(rto.backoffs(), 0);
    }

    /// The epoch a late probe leaves behind: measured from the submission (which
    /// is what the caller does with the returned duration), and still backed off,
    /// because a submission is not the ACK progress that may reset the backoff.
    #[test]
    fn rearm_returns_the_backed_off_interval_and_keeps_the_backoff() {
        let base = 320_000;
        let mut rto = SenderRto::new();
        rto.start(base);
        rto.expire(base);
        assert_eq!(rto.backoffs(), 1);

        rto.set_probe_pending(7);
        assert!(
            !rto.confirm_probe_submitted(8),
            "a different sequence must not clear a still-outstanding probe"
        );
        assert_eq!(rto.probe_pending(), Some(7));
        assert!(rto.confirm_probe_submitted(7));
        assert_eq!(rto.probe_pending(), None);

        assert_eq!(rto.rearm(base), 2 * base);
        assert_eq!(rto.backoffs(), 1, "a submission must not reset the backoff");
        assert!(rto.is_armed());
        assert_eq!(
            rto.rearm(base),
            2 * base,
            "rearming twice from the same submission state is idempotent"
        );
    }
}
