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

const FULL_MATRIX_RAW: usize = 1_105_920;
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

    // Current production filter on this plan (recomputed after the
    // smol/monoio/glommio runtimes and the pin axis were retired). Update this pin when the
    // filter changes, not to match prose.
    assert_eq!(
        enumeration.kept_cells, 30_464,
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
            ("batch-inert", 16_768),
            ("bond-capacity", 15_360),
            ("bonded-cc-requires-2", 61_440),
            ("bonded-egress-unsupported", 368_640),
            ("bonded-ingress-unsupported", 36_864),
            ("cookie-routing-inert", 25_728),
            ("promotion-inert", 129_024),
            ("promotion-inert-shared-egress", 52_992),
            ("shared-egress-workers-inert", 368_640),
        ],
        "per-reason filter counts drifted: {reasons:?}"
    );

    let table = enumeration.render_table();
    assert!(table.contains("kept"), "{table}");
    assert!(table.contains("raw"), "{table}");
    let json = enumeration.render_json();
    assert!(json.contains("\"raw\":1105920"), "{json}");
    assert!(json.contains("\"kept\":30464"), "{json}");
    assert!(json.contains("by_reason"), "{json}");
}
