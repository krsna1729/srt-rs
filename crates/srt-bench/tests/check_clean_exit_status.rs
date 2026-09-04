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
