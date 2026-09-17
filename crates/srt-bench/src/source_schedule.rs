//! The source schedule, as a pure function so it can be tested.
//!
//! The qualification source offers wall-clock tick boundaries. A visit that
//! arrives late has several boundaries overdue at once, and the policy for that
//! case is the difference between a measurement and a fiction:
//!
//! * catching up *unbounded* turns a stall into a burst the shard never saw;
//! * catching up *lazily* -- emitting some now and the rest on later visits --
//!   means the effective cap is not the declared cap, and boundaries documented
//!   as "declared lost" keep becoming `generated_ticks` after all;
//! * declaring them lost and moving on is the behaviour the gate's
//!   `generated + missed == expected` identity is supposed to describe.
//!
//! This module is the third option, in one place, with tests. It lives in the
//! library rather than the bench because a `harness = false` bench has no test
//! harness to run assertions in.

/// Greatest number of overdue boundaries one visit may catch up on.
///
/// Bounded so a stall cannot become an unbounded burst. Boundaries beyond it are
/// declared lost *in the same visit*, never carried forward.
pub const MAX_TICK_CATCHUP: u64 = 64;

/// What one visit does with its overdue boundaries.
#[derive(Debug, PartialEq, Eq)]
pub struct CatchUp {
    /// Boundaries to offer now (0..=cap).
    pub offer: u64,
    /// Boundaries declared lost this visit: overdue beyond the cap, or left
    /// behind by a stall longer than one cap. Never carried to a later visit.
    pub missed: u64,
    /// Boundaries accounted for after this visit; the next visit starts here.
    pub offered_through: u64,
}

/// Decide one visit, given how many boundaries are due and how far the schedule
/// has already advanced.
///
/// `passed` is the count of boundaries whose deadline has elapsed since the
/// epoch; `offered_through` is how many of them have been accounted for (as
/// offered or as missed). The caller offers `offer` boundaries and then records
/// `missed`.
pub fn catch_up(offered_through: u64, passed: u64, cap: u64) -> CatchUp {
    let overdue = passed.saturating_sub(offered_through);
    let offer = overdue.min(cap);
    let missed = overdue - offer;
    CatchUp {
        offer,
        missed,
        offered_through: passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(offered_through: u64, passed: u64) -> (u64, u64) {
        let c = catch_up(offered_through, passed, MAX_TICK_CATCHUP);
        (c.offer, c.missed + c.offer)
    }

    #[test]
    fn nothing_due_offers_nothing() {
        assert_eq!(step(10, 10), (0, 0));
        assert_eq!(step(10, 9), (0, 0), "the schedule never runs backwards");
    }

    #[test]
    fn one_boundary_is_offered_and_nothing_is_lost() {
        assert_eq!(step(10, 11), (1, 1));
    }

    /// The review case: exactly at the cap, nothing is lost and nothing is
    /// carried forward.
    #[test]
    fn exactly_the_cap_is_offered() {
        assert_eq!(step(0, 64), (64, 64));
    }

    /// The defect this replaced: 65 overdue boundaries used to emit 64 and leave
    /// one outstanding for a later visit, so the effective cap was not the
    /// declared cap and a boundary documented as lost could later become
    /// `generated_ticks` anyway.
    #[test]
    fn one_over_the_cap_is_lost_in_the_same_visit() {
        assert_eq!(step(0, 65), (64, 65));
        let c = catch_up(0, 65, MAX_TICK_CATCHUP);
        assert_eq!(c.offer, 64);
        assert_eq!(c.missed, 1);
        assert_eq!(c.offered_through, 65, "nothing is carried forward");
    }

    #[test]
    fn one_hundred_and_twenty_seven_is_capped_and_the_rest_lost() {
        let c = catch_up(0, 127, MAX_TICK_CATCHUP);
        assert_eq!(c.offer, 64);
        assert_eq!(c.missed, 63);
        assert_eq!(c.offered_through, 127);
    }

    #[test]
    fn one_hundred_and_twenty_eight_is_two_caps_twice_bounded() {
        let c = catch_up(0, 128, MAX_TICK_CATCHUP);
        assert_eq!(c.offer, 64);
        assert_eq!(c.missed, 64);
        assert_eq!(c.offered_through, 128);
    }

    /// Across a sequence of visits, every elapsed boundary is accounted for
    /// exactly once -- the identity the gate relies on.
    #[test]
    fn every_elapsed_boundary_is_accounted_for_exactly_once() {
        let mut offered_through = 0u64;
        let mut offered = 0u64;
        let mut missed = 0u64;
        // A stall of 300 boundaries, then smooth progress.
        for passed in [0u64, 5, 300, 301, 302, 400, 460] {
            let c = catch_up(offered_through, passed, MAX_TICK_CATCHUP);
            offered += c.offer;
            missed += c.missed;
            offered_through = c.offered_through;
            assert_eq!(offered + missed, passed, "at passed={passed}");
        }
        assert_eq!(offered_through, 460);
        assert_eq!(offered + missed, 460);
    }
}
