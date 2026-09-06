//! Pin the full-matrix Cartesian product against the production filter.
//!
//! The prose historically claimed 67,200 retained cells. That number is
//! not an input to the filter and must not be copied back into logic.
//! This test parses the checked-in plan, walks
//! [`srt_bench::harness::enumerate_plan`] (the same
//! `filtered_cartesian_cells` path `srt-bench matrix` uses), and pins the
//! current raw/kept/reason totals.

use std::path::PathBuf;

use srt_bench::Cli;
use srt_bench::harness::enumerate_plan;

const FULL_MATRIX_RAW: usize = 4_423_680;
/// Documented retained count from an older filter baseline. Must not match
/// the live product; the pin below is the source of truth.
const STALE_DOCUMENTED_KEPT: usize = 67_200;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn full_matrix_cli() -> Cli {
    let plan = workspace_root().join("docs/plans/full-matrix.plan");
    assert!(
        plan.is_file(),
        "full-matrix.plan must exist at {}",
        plan.display()
    );
    Cli::parse(&[
        "srt-bench".to_string(),
        format!("--plan={}", plan.display()),
    ])
}

#[test]
fn full_matrix_plan_uses_production_filter_and_pins_current_kept_count() {
    let enumeration = enumerate_plan(&full_matrix_cli()).expect("enumerate full-matrix.plan");

    assert_eq!(
        enumeration.raw_cells, FULL_MATRIX_RAW,
        "raw product of the checked-in full-matrix.plan axes"
    );
    assert_eq!(
        enumeration.kept_cells + enumeration.filter_summary.total(),
        enumeration.raw_cells,
        "kept + per-reason removals must reconstruct the raw product: {enumeration:?}"
    );
    assert_ne!(
        enumeration.kept_cells, STALE_DOCUMENTED_KEPT,
        "live filter must not be the stale documented 67,200"
    );

    // Current production filter on this plan (recomputed at tip; the older
    // 57,984 figure is a historical baseline). Update this pin when the
    // filter changes, not to match prose.
    assert_eq!(
        enumeration.kept_cells, 66_048,
        "kept count drifted; update this pin and the filter-summary docs together: {enumeration:?}"
    );
    let reasons: Vec<(&str, usize)> = enumeration
        .filter_summary
        .by_reason
        .iter()
        .map(|(reason, count)| (*reason, *count))
        .collect();
    assert_eq!(
        reasons,
        [
            ("batch-inert", 85_888),
            ("bond-capacity", 61_440),
            ("bonded-cc-requires-2", 245_760),
            ("bonded-egress-unsupported", 1_474_560),
            ("bonded-ingress-unsupported", 147_456),
            ("cookie-routing-inert", 102_912),
            ("pin-inert", 49_280),
            ("promotion-inert", 715_776),
            ("shared-egress-workers-inert", 1_474_560),
        ],
        "per-reason filter counts drifted: {reasons:?}"
    );

    let table = enumeration.render_table();
    assert!(table.contains("kept"), "{table}");
    assert!(table.contains("raw"), "{table}");
    let json = enumeration.render_json();
    assert!(json.contains("\"raw\":4423680"), "{json}");
    assert!(json.contains("\"kept\":66048"), "{json}");
    assert!(json.contains("by_reason"), "{json}");
}
