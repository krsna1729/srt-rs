//! Differential tests of srt-proto's receive buffer against libsrt 1.5.7.
//!
//! The same synthetic packet and time sequence drives srt-proto's
//! [`ReceiverBuffer`](srt_proto::receiver::ReceiverBuffer) and libsrt's own
//! `CRcvBuffer`, `CTsbpdTime` and `CRcvLossList`, compiled from a libsrt source
//! checkout named by `LIBSRT_SRC` (see `docs/live-interop-validation.md`). After
//! every step the normalized observations ([`model`]) must be equal.
//!
//! Without `LIBSRT_SRC` no native code is built: [`libsrt_receiver`] returns
//! `None` and the tests report that they were skipped.

pub mod model;
pub mod scenario;
mod srt_rs;

#[cfg(libsrt_oracle)]
mod libsrt;

use std::fmt;

pub use model::{Admission, Delivered, Packet, Profile, Receiver, SeqRange, Snapshot};
pub use srt_rs::SrtRsReceiver;

/// Set to `1` to make a missing oracle a test failure instead of a skip
/// (the dedicated CI job does).
pub const REQUIRE_ORACLE_ENV: &str = "SRT_DIFF_REQUIRE_ORACLE";

/// libsrt's receiver for `profile`, if this build compiled the oracle.
#[must_use]
pub fn libsrt_receiver(profile: Profile) -> Option<Box<dyn Receiver>> {
    #[cfg(libsrt_oracle)]
    {
        Some(Box::new(libsrt::LibsrtReceiver::new(profile)))
    }
    #[cfg(not(libsrt_oracle))]
    {
        let _ = profile;
        None
    }
}

/// Whether the oracle is available; otherwise prints why `test` is skipped.
///
/// # Panics
/// If the oracle is missing while [`REQUIRE_ORACLE_ENV`] is `1`.
#[must_use]
pub fn oracle_available(test: &str) -> bool {
    if cfg!(libsrt_oracle) {
        return true;
    }
    let required = std::env::var(REQUIRE_ORACLE_ENV).is_ok_and(|value| value == "1");
    assert!(
        !required,
        "{test}: libsrt oracle not built but {REQUIRE_ORACLE_ENV}=1; set LIBSRT_SRC to a libsrt 1.5.7 checkout"
    );
    eprintln!(
        "{test}: SKIPPED -- LIBSRT_SRC is unset, so the libsrt 1.5.7 oracle was not built \
         (see docs/live-interop-validation.md)"
    );
    false
}

/// One step of a scenario.
#[derive(Clone, Debug)]
pub enum Action {
    /// A packet arrives now.
    Insert(Packet),
    /// Time moves forward by this many microseconds.
    Advance(u64),
    /// The application reads one message if one is ready.
    Read,
    /// One TLPKTDROP service pass.
    Service,
}

/// The first observation on which the two receivers disagree.
#[derive(Clone, Debug)]
pub struct Divergence {
    /// Index of the step after which they disagreed.
    pub step: usize,
    /// That step.
    pub action: Action,
    /// Synthetic time of the step.
    pub now_us: u64,
    /// The observation that differs.
    pub observable: &'static str,
    /// libsrt's value.
    pub libsrt: String,
    /// srt-rs's value.
    pub srt_rs: String,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "step {} {:?} at t={}us: {} differs\n  libsrt: {}\n  srt-rs: {}",
            self.step, self.action, self.now_us, self.observable, self.libsrt, self.srt_rs
        )
    }
}

/// What a scenario produced, identical on both sides when it returns `Ok`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    /// Admission of every inserted packet, in order.
    pub admissions: Vec<Admission>,
    /// Messages delivered, in order.
    pub delivered: Vec<Delivered>,
    /// Positions TLPKTDROP gave up, one entry per service step that dropped.
    pub drops: Vec<Vec<SeqRange>>,
    /// Snapshot after every step.
    pub snapshots: Vec<Snapshot>,
    /// Whether libsrt closed the connection, ending the scenario early.
    pub closed: bool,
}

/// Outcome of one step on one receiver.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StepOutcome {
    None,
    Admission(Admission),
    Read(Option<Delivered>),
    Dropped(Vec<SeqRange>),
}

/// Apply `action` to `receiver` at `now_us`.
fn apply(receiver: &mut dyn Receiver, action: &Action, now_us: u64, origin: u32) -> StepOutcome {
    match action {
        Action::Insert(packet) => StepOutcome::Admission(receiver.insert(packet, now_us)),
        Action::Advance(_) => StepOutcome::None,
        Action::Read => StepOutcome::Read(receiver.read(now_us)),
        Action::Service => {
            StepOutcome::Dropped(model::canonical_ranges(origin, receiver.service(now_us)))
        }
    }
}

fn snapshot(receiver: &dyn Receiver, now_us: u64, origin: u32) -> Snapshot {
    let mut snapshot = receiver.snapshot(now_us);
    snapshot.losses = model::canonical_ranges(origin, snapshot.losses);
    snapshot
}

fn record(trace: &mut Trace, outcome: StepOutcome) {
    match outcome {
        StepOutcome::None | StepOutcome::Read(None) => {}
        StepOutcome::Admission(admission) => trace.admissions.push(admission),
        StepOutcome::Read(Some(delivered)) => trace.delivered.push(delivered),
        StepOutcome::Dropped(dropped) => {
            if !dropped.is_empty() {
                trace.drops.push(dropped);
            }
        }
    }
}

/// Run `actions` on both receivers, comparing every step's outcome and the
/// snapshot after it. Time starts at the profile's TSBPD time base.
///
/// # Errors
/// The first [`Divergence`].
pub fn run(
    profile: Profile,
    actions: &[Action],
    libsrt: &mut dyn Receiver,
    srt_rs: &mut dyn Receiver,
) -> Result<Trace, Divergence> {
    let origin = profile.initial_seq;
    let mut now_us = profile.time_base_us;
    let mut trace = Trace::default();
    for (step, action) in actions.iter().enumerate() {
        if let Action::Advance(by) = action {
            now_us += by;
        }
        let diverge = |observable, libsrt: &dyn fmt::Debug, srt_rs: &dyn fmt::Debug| Divergence {
            step,
            action: action.clone(),
            now_us,
            observable,
            libsrt: format!("{libsrt:?}"),
            srt_rs: format!("{srt_rs:?}"),
        };
        let expected = apply(libsrt, action, now_us, origin);
        let actual = apply(srt_rs, action, now_us, origin);
        if expected != actual {
            return Err(diverge("step outcome", &expected, &actual));
        }
        record(&mut trace, expected);
        if libsrt.closed() {
            trace.closed = true;
            return Ok(trace);
        }
        let expected = snapshot(libsrt, now_us, origin);
        let actual = snapshot(srt_rs, now_us, origin);
        if expected != actual {
            return Err(diverge("snapshot", &expected, &actual));
        }
        trace.snapshots.push(expected);
    }
    Ok(trace)
}

/// [`run`] against a fresh pair of receivers for `profile`, or `None` when
/// the oracle is not built.
///
/// # Errors
/// The first [`Divergence`].
pub fn run_fresh(profile: Profile, actions: &[Action]) -> Option<Result<Trace, Divergence>> {
    let mut libsrt = libsrt_receiver(profile)?;
    let mut srt_rs = SrtRsReceiver::new(profile);
    Some(run(profile, actions, libsrt.as_mut(), &mut srt_rs))
}
