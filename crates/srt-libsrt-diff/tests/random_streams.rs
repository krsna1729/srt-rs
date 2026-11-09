//! Random action streams: inserts with random gaps, duplicates and
//! conflicting retransmissions, timestamp jitter including non-monotone
//! values, time advances (also exactly around deadlines), reads, TLPKTDROP
//! passes and sequence wrap, compared after every step.
//!
//! `PROPTEST_CASES` sets the case count (default 256).

use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use srt_libsrt_diff::model::SEQUENCE_MASK;
use srt_libsrt_diff::scenario::{Scenario, Step};
use srt_libsrt_diff::{Profile, oracle_available, run_fresh};

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        8 => (prop_oneof![6 => Just(0u32), 3 => 1u32..4, 1 => 4u32..40], jitter())
            .prop_map(|(skip, jitter_us)| Step::Send { skip, jitter_us }),
        3 => (1u32..48, prop::bool::weighted(0.2))
            .prop_map(|(back, conflicting)| Step::Resend { back, conflicting }),
        3 => prop_oneof![0u32..2_000, 2_000u32..40_000, 40_000u32..400_000].prop_map(Step::Advance),
        2 => (1u32..32, -2i8..=2)
            .prop_map(|(back, delta_us)| Step::AdvanceToDeadline { back, delta_us }),
        4 => Just(Step::Read),
        3 => Just(Step::Service),
    ]
}

/// Mostly small jitter, sometimes large enough to reorder deadlines.
fn jitter() -> impl Strategy<Value = i32> {
    prop_oneof![
        4 => Just(0i32),
        4 => -3_000i32..3_000,
        2 => -60_000i32..60_000,
    ]
}

fn initial_seq() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        (0u32..64).prop_map(|back| SEQUENCE_MASK - back),
        0u32..=SEQUENCE_MASK,
    ]
}

fn scenario() -> impl Strategy<Value = Scenario> {
    (
        initial_seq(),
        prop_oneof![8u32..32, 32u32..257],
        prop_oneof![Just(120u16), 20u16..400],
        prop::collection::vec(step(), 1..300),
    )
        .prop_map(|(initial_seq, capacity, latency_ms, steps)| Scenario {
            profile: Profile {
                latency_ms,
                ..Profile::live(initial_seq, capacity)
            },
            steps,
        })
}

#[test]
fn random_action_streams_agree_with_libsrt() {
    if !oracle_available("random_action_streams_agree_with_libsrt") {
        return;
    }
    let mut runner = TestRunner::new(Config {
        failure_persistence: None,
        ..Config::default()
    });
    let result = runner.run(&scenario(), |scenario| {
        let actions = scenario.build();
        let outcome = run_fresh(scenario.profile, &actions).expect("oracle available");
        if let Err(divergence) = outcome {
            return Err(TestCaseError::fail(format!(
                "{divergence}\nprofile: {:?}\nactions: {actions:#?}",
                scenario.profile
            )));
        }
        Ok(())
    });
    if let Err(error) = result {
        panic!("{error}");
    }
}
