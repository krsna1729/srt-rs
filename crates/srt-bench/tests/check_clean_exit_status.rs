use std::process::Command;

const BENCH_EXE: &str = env!("CARGO_BIN_EXE_srt-bench");

#[test]
fn missing_path_is_usage_error() {
    let output = Command::new(BENCH_EXE).arg("check-clean").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}

#[test]
fn unreadable_results_fail_the_gate() {
    let missing = std::env::temp_dir().join(format!(
        "srt-bench-check-clean-missing-{}",
        std::process::id()
    ));
    let output = Command::new(BENCH_EXE)
        .args(["check-clean", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("check-clean:"));
}

/// A NaN loss count must fail the gate at the binary boundary, not just in
/// library unit tests: the exit status is what automation gates on.
#[test]
fn nan_loss_count_fails_the_gate() {
    use srt_bench::harness::COLUMNS;
    let dir =
        std::env::temp_dir().join(format!("srt-bench-check-clean-nan-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("nan.tsv");
    let set = |row: &mut [String], col: &str, val: &str| {
        if let Some(pos) = COLUMNS.iter().position(|&c| c == col) {
            row[pos] = val.to_string();
        }
    };
    let mut rows = Vec::new();
    for role in ["caller", "listener"] {
        let mut row = vec!["0".to_string(); COLUMNS.len()];
        set(&mut row, "runtime", "mio");
        set(&mut row, "role", role);
        set(&mut row, "rep", "1");
        set(&mut row, "conns", "10");
        set(&mut row, "source_bps", "1000000");
        set(&mut row, "secs", "10");
        set(&mut row, "established", "10");
        set(
            &mut row,
            "torn_down",
            if role == "listener" { "NaN" } else { "0" },
        );
        set(&mut row, "core_total", "9499");
        set(&mut row, "udp_rcvbuf_err", "0");
        set(&mut row, "src_overflow", "0");
        set(&mut row, "datapath_q_dropped", "0");
        set(&mut row, "local_dropped", "0");
        rows.push(row.join("\t"));
    }
    std::fs::write(
        &path,
        format!("{}\n{}\n{}\n", COLUMNS.join("\t"), rows[0], rows[1]),
    )
    .unwrap();
    let output = Command::new(BENCH_EXE)
        .args(["check-clean", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("FAIL"));
    let _ = std::fs::remove_dir_all(&dir);
}
