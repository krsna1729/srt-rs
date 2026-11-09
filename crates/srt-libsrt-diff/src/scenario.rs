//! Random action streams for the differential proptest.
//!
//! A stream is a list of [`Step`]s, each a small instruction that a pure fold
//! ([`Scenario::build`]) turns into concrete [`Action`]s. The fold tracks
//! only what the *sender* has sent (next new sequence, each packet's
//! timestamp); it never consults either receiver, so neither implementation
//! steers its own input.

use std::collections::BTreeMap;

use crate::Action;
use crate::model::{Packet, Profile, SEQUENCE_MASK};

/// Nominal sender spacing between consecutive packets, microseconds.
pub const PACKET_INTERVAL_US: i64 = 1_000;

/// One generator instruction.
#[derive(Clone, Copy, Debug)]
pub enum Step {
    /// Send the next new packet after skipping `skip` sequences (which become
    /// losses), with this timestamp jitter around the nominal schedule.
    Send {
        /// Sequences skipped before this one.
        skip: u32,
        /// Timestamp offset from the nominal schedule, microseconds.
        jitter_us: i32,
    },
    /// Resend an already-sent or skipped sequence `back` positions behind
    /// the next new one, with its original timestamp when it was sent.
    Resend {
        /// Distance behind the next new sequence, at least 1.
        back: u32,
        /// Whether the copy carries a payload different from the original.
        conflicting: bool,
    },
    /// Advance time by this many microseconds.
    Advance(u32),
    /// Advance to `delta_us` around the deadline of the packet `back`
    /// positions behind the next new one, if that is in the future.
    AdvanceToDeadline {
        /// Distance behind the next new sequence, at least 1.
        back: u32,
        /// Offset from that deadline, microseconds.
        delta_us: i8,
    },
    /// The application reads one message.
    Read,
    /// One TLPKTDROP service pass.
    Service,
}

/// A profile plus generator steps.
#[derive(Clone, Debug)]
pub struct Scenario {
    /// Receiver configuration.
    pub profile: Profile,
    /// Generator steps.
    pub steps: Vec<Step>,
}

struct Sender {
    profile: Profile,
    /// Offset of the next new sequence from the initial sequence.
    next: u32,
    /// Timestamp of every sequence offset sent or skipped so far.
    timestamps: BTreeMap<u32, u32>,
    now_us: u64,
}

impl Sender {
    fn seq(&self, offset: u32) -> u32 {
        self.profile.initial_seq.wrapping_add(offset) & SEQUENCE_MASK
    }

    fn nominal(offset: u32) -> i64 {
        i64::from(offset) * PACKET_INTERVAL_US + 100_000
    }

    fn jittered(offset: u32, jitter_us: i32) -> u32 {
        u32::try_from((Self::nominal(offset) + i64::from(jitter_us)).max(0)).unwrap_or(0)
    }

    fn send(&mut self, skip: u32, jitter_us: i32) -> Action {
        for gap in self.next..self.next + skip {
            self.timestamps.insert(gap, Self::jittered(gap, 0));
        }
        let offset = self.next + skip;
        let timestamp = Self::jittered(offset, jitter_us);
        self.timestamps.insert(offset, timestamp);
        self.next = offset + 1;
        Action::Insert(Packet::solo(self.seq(offset), timestamp))
    }

    fn behind(&self, back: u32) -> Option<(u32, u32)> {
        let offset = self.next.checked_sub(back.max(1))?;
        Some((offset, *self.timestamps.get(&offset)?))
    }

    fn resend(&self, back: u32, conflicting: bool) -> Option<Action> {
        let (offset, timestamp) = self.behind(back)?;
        let mut packet = Packet::solo(self.seq(offset), timestamp);
        packet.retransmitted = true;
        if conflicting {
            packet.payload = vec![0xC0; 3];
        }
        Some(Action::Insert(packet))
    }

    fn advance_to_deadline(&mut self, back: u32, delta_us: i8) -> Option<Action> {
        let (_, timestamp) = self.behind(back)?;
        let target = self
            .profile
            .deadline(timestamp)
            .checked_add_signed(i64::from(delta_us))?;
        let by = target.checked_sub(self.now_us).filter(|&by| by > 0)?;
        Some(self.advance(by))
    }

    fn advance(&mut self, by: u64) -> Action {
        self.now_us += by;
        Action::Advance(by)
    }

    fn action(&mut self, step: Step) -> Option<Action> {
        match step {
            Step::Send { skip, jitter_us } => Some(self.send(skip, jitter_us)),
            Step::Resend { back, conflicting } => self.resend(back, conflicting),
            Step::Advance(by) => Some(self.advance(u64::from(by))),
            Step::AdvanceToDeadline { back, delta_us } => self.advance_to_deadline(back, delta_us),
            Step::Read => Some(Action::Read),
            Step::Service => Some(Action::Service),
        }
    }
}

impl Scenario {
    /// The concrete actions of this scenario. Steps that name nothing yet
    /// sent, or a deadline already passed, are skipped.
    #[must_use]
    pub fn build(&self) -> Vec<Action> {
        let mut sender = Sender {
            profile: self.profile,
            next: 0,
            timestamps: BTreeMap::new(),
            now_us: self.profile.time_base_us,
        };
        let mut actions: Vec<_> = self
            .steps
            .iter()
            .filter_map(|&step| sender.action(step))
            .collect();
        // Check eventual delivery too, not only the generated prefix. A
        // buffer contains at most `capacity` packets, and one service/read
        // pair either releases its head gap and packet or finds it empty.
        let last_deadline = sender
            .timestamps
            .values()
            .map(|&timestamp| self.profile.deadline(timestamp))
            .max()
            .unwrap_or(sender.now_us);
        if last_deadline > sender.now_us {
            actions.push(sender.advance(last_deadline - sender.now_us));
        }
        for _ in 0..=self.profile.capacity {
            actions.extend([Action::Service, Action::Read]);
        }
        actions
    }
}
