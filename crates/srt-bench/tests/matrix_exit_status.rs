//! `srt-bench matrix` must exit 0 **only** when every required cell and
//! role completed successfully (issue #39).
//!
//! These are process-level tests on purpose. The bug being fixed was not
//! "an internal boolean was wrong": it was that the harness logged a
//! child's non-zero exit, carried on, and returned status 0, so a CI job
//! could report a green benchmark campaign over a sweep whose sender had
//! crashed. Only the real exit code proves that is gone.
//!
//! The children are shell stubs rather than real bench processes: the
//! contract under test is entirely "what did the child's exit status and
//! result row say", and a stub can produce a crash, a signal, a silent
//! success, or a corrupt row on demand -- none of which a real run can be
//! asked for reliably.

use std::path::{Path, PathBuf};
use std::process::Command;

const MATRIX_EXE: &str = env!("CARGO_BIN_EXE_srt-bench");

/// A scratch directory unique to one test.
fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("srt-bench-matrix-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create workdir");
    dir
}

fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write stub");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod stub");
    path
}

/// Shell prelude shared by every stub: pull `--out=`, `--rep=` and the
/// role out of the argv the harness actually passes.
const PARSE_ARGS: &str = r#"
out=""; rep=""; role=""; attempt=""
for a in "$@"; do
  case "$a" in
    --out=*) out=${a#--out=} ;;
    --rep=*) rep=${a#--rep=} ;;
    --attempt=*) attempt=${a#--attempt=} ;;
    mode=sender) role=caller ;;
    mode=receiver) role=listener ;;
  esac
done
"#;

/// The axis values this test pins on the command line, as the columns a
/// result row records them under.
///
/// Every axis is given explicitly so the cell identity is owned by the
/// test rather than inherited from harness defaults that may move. If an
/// axis is ever added, the stub row stops matching the cell key and the
/// clean-matrix test fails loudly (as a missing result row) rather than
/// quietly passing against a stale identity.
fn recorded_cell_values(runtime: &str) -> Vec<(&'static str, String)> {
    vec![
        ("runtime", runtime.to_string()),
        ("workers", "1".into()),
        ("ingress", "per-port".into()),
        ("egress", "per-connection".into()),
        ("encryption", "plain".into()),
        ("promotion", "relocate".into()),
        ("cookie", "on".into()),
        ("batch", "on".into()),
        ("sock_buf_requested_bytes", "0".into()),
        (
            "cpus",
            srt_transport::current_cpu_spec().expect("read test CPU affinity"),
        ),
        ("datapath_q_horizon_ms", "250".into()),
        ("retry_horizon_ms", "250".into()),
        ("pin", "off".into()),
        ("conns", "1".into()),
        ("connect_cc", "1".into()),
        ("bond", "none".into()),
        ("source_bps", "8000000".into()),
        ("srt_bw_mode", "legacy-source-fixed".into()),
        ("source_backlog_ms", "250".into()),
        ("recv_rounds", "8".into()),
        ("would_block_policy", "retain".into()),
    ]
}

/// The flags that pin those values on `srt-bench matrix`'s command line.
fn pinning_flags(runtimes: &str) -> Vec<String> {
    [
        format!("--runtimes={runtimes}"),
        "--workers=1".into(),
        "--ingress=per-port".into(),
        "--egress=per-connection".into(),
        "--encryption=plain".into(),
        "--promotion=relocate".into(),
        "--cookie-routing=on".into(),
        "--batch=on".into(),
        "--sock-buf=default".into(),
        "--pin=off".into(),
        "--connections=1".into(),
        "--connect-concurrency=1".into(),
        "--bond=none".into(),
        "--bitrate=8000000".into(),
        "--srt-bandwidth=legacy-source-fixed".into(),
        "--source-backlog-ms=250".into(),
        "--recv-rounds=8".into(),
        "--would-block=retain".into(),
        "--datapath-queue-horizon-ms=250".into(),
        "--outbound-retry-horizon-ms=250".into(),
    ]
    .into_iter()
    .collect()
}

/// A stub body that appends a well-formed result row for its own role and
/// runtime, then reports LISTENING. The row is written *before* the marker
/// so the harness cannot start the sender while the header is half-written.
fn row_writing_body(runtime: &str) -> String {
    let header = srt_bench::harness::COLUMNS.join("\t");
    let cell = recorded_cell_values(runtime);
    let row: Vec<String> = srt_bench::harness::COLUMNS
        .iter()
        .map(|column| match *column {
            "role" => "@ROLE@".to_string(),
            "rep" => "@REP@".to_string(),
            "attempt" => "@ATTEMPT@".to_string(),
            // Measurements are irrelevant here; only cell identity is.
            other => cell
                .iter()
                .find(|(name, _)| *name == other)
                .map_or_else(String::new, |(_, value)| value.clone()),
        })
        .collect();
    let row = row.join("\t");
    format!(
        r#"{PARSE_ARGS}
if [ -n "$out" ]; then
  if [ ! -s "$out" ]; then printf '%s\n' '{header}' >> "$out"; fi
  printf '%s\n' '{row}' \
    | sed -e "s/@ROLE@/$role/" -e "s/@REP@/$rep/" -e "s/@ATTEMPT@/$attempt/" >> "$out"
fi
if [ "$role" = listener ]; then echo LISTENING; fi
exit 0"#
    )
}

struct MatrixRun {
    status: std::process::ExitStatus,
    stderr: String,
}

fn run_matrix(dir: &Path, sender: &Path, receiver: &Path, extra: &[String]) -> MatrixRun {
    let out = dir.join("results.tsv");
    let mut command = Command::new(MATRIX_EXE);
    command
        .arg("matrix")
        .arg(format!("--sender-exe={}", sender.display()))
        .arg(format!("--receiver-exe={}", receiver.display()))
        .arg(format!("--out={}", out.display()))
        .arg("--reps=1")
        .arg("--secs=1")
        .args(extra)
        // Keeps the parent's host-diagnostics banner out of the captured
        // stderr; it has nothing to do with what is asserted here.
        .env("SRT_BENCH_CHILD", "1");
    let output = command.output().expect("run srt-bench matrix");
    MatrixRun {
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn sender_failure_fails_the_matrix() {
    let dir = workdir("sender-fail");
    let sender = write_script(&dir, "sender.sh", "exit 3");
    let receiver = write_script(&dir, "receiver.sh", &row_writing_body("mio"));
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(
        !run.status.success(),
        "a crashed sender must fail the matrix\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("sender child failed"),
        "failure summary must name the sender\n{}",
        run.stderr
    );
}

#[test]
fn receiver_failure_fails_the_matrix() {
    let dir = workdir("receiver-fail");
    let sender = write_script(&dir, "sender.sh", &row_writing_body("mio"));
    let receiver = write_script(&dir, "receiver.sh", "echo LISTENING\nexit 4");
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(
        !run.status.success(),
        "a crashed receiver must fail the matrix\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("receiver child failed"),
        "failure summary must name the receiver\n{}",
        run.stderr
    );
}

#[test]
fn both_roles_failing_fails_the_matrix() {
    let dir = workdir("both-fail");
    let sender = write_script(&dir, "sender.sh", "exit 3");
    let receiver = write_script(&dir, "receiver.sh", "echo LISTENING\nexit 4");
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(!run.status.success(), "{}", run.stderr);
    assert!(
        run.stderr.contains("sender child failed") && run.stderr.contains("receiver child failed"),
        "both roles must be reported\n{}",
        run.stderr
    );
}

#[test]
fn signalled_child_fails_the_matrix() {
    let dir = workdir("signal");
    // A child killed by a signal exits with no status code at all; the
    // old `status.success()`-only log line treated it the same as any
    // other line of noise.
    let sender = write_script(&dir, "sender.sh", "kill -9 $$");
    let receiver = write_script(&dir, "receiver.sh", &row_writing_body("mio"));
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(!run.status.success(), "{}", run.stderr);
    assert!(run.stderr.contains("sender child failed"), "{}", run.stderr);
}

#[test]
fn missing_required_output_fails_the_matrix() {
    let dir = workdir("missing-row");
    // Exits 0 and writes nothing. The child's deliverable is a result
    // row, so a silent success is still a failed cell.
    let sender = write_script(&dir, "sender.sh", "exit 0");
    let receiver = write_script(&dir, "receiver.sh", &row_writing_body("mio"));
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(
        !run.status.success(),
        "a row-less success must fail the matrix\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("sender recorded no result row"),
        "{}",
        run.stderr
    );
}

#[test]
fn malformed_required_output_fails_the_matrix() {
    let dir = workdir("malformed-row");
    let sender = write_script(
        &dir,
        "sender.sh",
        &format!("{PARSE_ARGS}\nprintf 'not\\ta\\tresult\\trow\\n' >> \"$out\"\nexit 0"),
    );
    let receiver = write_script(&dir, "receiver.sh", &row_writing_body("mio"));
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(
        !run.status.success(),
        "an unreadable result file must fail the matrix\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("result file unreadable"),
        "{}",
        run.stderr
    );
}

#[test]
fn clean_multi_cell_matrix_exits_zero() {
    let dir = workdir("clean");
    let body = format!(
        r#"{PARSE_ARGS}
runtime=mio
for a in "$@"; do case "$a" in runtime=*) runtime=${{a#runtime=}} ;; esac; done
case "$runtime" in
  mio) {mio_body} ;;
  tokio) {tokio_body} ;;
esac"#,
        mio_body = shell_case(&row_writing_body("mio")),
        tokio_body = shell_case(&row_writing_body("tokio")),
    );
    let sender = write_script(&dir, "sender.sh", &body);
    let receiver = write_script(&dir, "receiver.sh", &body);
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio,tokio"));
    assert!(
        run.status.success(),
        "a matrix whose children all succeeded must exit 0\n{}",
        run.stderr
    );
    let rows = srt_bench::harness::read_results(&dir.join("results.tsv")).expect("read results");
    assert_eq!(rows.len(), 4, "two cells x two roles");
}

/// A failed cell must not stop the sweep: later cells are independent
/// experiments and their data is still worth having. The failure is
/// remembered and surfaced at the end instead.
#[test]
fn failed_cell_does_not_stop_later_cells() {
    let dir = workdir("continue");
    let body = format!(
        r#"{PARSE_ARGS}
runtime=mio
for a in "$@"; do case "$a" in runtime=*) runtime=${{a#runtime=}} ;; esac; done
if [ "$runtime" = mio ]; then exit 5; fi
{tokio_body}"#,
        tokio_body = row_writing_body("tokio"),
    );
    let sender = write_script(&dir, "sender.sh", &body);
    let receiver = write_script(&dir, "receiver.sh", &body);
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio,tokio"));
    assert!(!run.status.success(), "{}", run.stderr);
    // The tokio cell ran anyway and recorded both roles.
    let rows = srt_bench::harness::read_results(&dir.join("results.tsv")).expect("read results");
    let tokio_rows = rows
        .iter()
        .filter(|r| r.get("runtime") == Some("tokio"))
        .count();
    assert_eq!(
        tokio_rows, 2,
        "the later independent cell must still have run\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("1 of 2 attempted runs failed"),
        "{}",
        run.stderr
    );
}

/// Reindent a stub body so it can be nested inside a `case` arm.
fn shell_case(body: &str) -> String {
    body.replace('\n', "\n  ")
}

// --- freshness: a previous attempt's rows are not this attempt's output ---

/// Write a result row for `role` as though an earlier, interrupted attempt
/// had produced it.
fn seed_stale_row(out: &Path, role: &str, runtime: &str, attempt: &str) {
    let exists = out.exists() && std::fs::metadata(out).map(|m| m.len() > 0).unwrap_or(false);
    let mut text = String::new();
    if !exists {
        text.push_str(&srt_bench::harness::COLUMNS.join("\t"));
        text.push('\n');
    }
    let cell = recorded_cell_values(runtime);
    let row: Vec<String> = srt_bench::harness::COLUMNS
        .iter()
        .map(|column| match *column {
            "role" => role.to_string(),
            "rep" => "1".to_string(),
            "attempt" => attempt.to_string(),
            other => cell
                .iter()
                .find(|(name, _)| *name == other)
                .map_or_else(String::new, |(_, value)| value.clone()),
        })
        .collect();
    text.push_str(&row.join("\t"));
    text.push('\n');
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out)
        .expect("open results");
    file.write_all(text.as_bytes()).expect("seed row");
}

/// The stale-row hole: an append-only result file routinely contains a
/// half-finished pair from an interrupted attempt. A caller row left by
/// that attempt must not stand in for a current sender that exited 0 and
/// wrote nothing.
#[test]
fn a_stale_caller_row_does_not_excuse_a_rowless_sender() {
    let dir = workdir("stale-caller");
    seed_stale_row(&dir.join("results.tsv"), "caller", "mio", "earlier-attempt");
    let sender = write_script(&dir, "sender.sh", "exit 0");
    let receiver = write_script(&dir, "receiver.sh", &row_writing_body("mio"));
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(
        !run.status.success(),
        "an earlier attempt's caller row must not satisfy this attempt\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("sender recorded no result row"),
        "{}",
        run.stderr
    );
}

#[test]
fn a_stale_listener_row_does_not_excuse_a_rowless_receiver() {
    let dir = workdir("stale-listener");
    seed_stale_row(
        &dir.join("results.tsv"),
        "listener",
        "mio",
        "earlier-attempt",
    );
    let sender = write_script(&dir, "sender.sh", &row_writing_body("mio"));
    // Announces, exits cleanly, records nothing.
    let receiver = write_script(&dir, "receiver.sh", "echo LISTENING\nexit 0");
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(
        !run.status.success(),
        "an earlier attempt's listener row must not satisfy this attempt\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("receiver recorded no result row"),
        "{}",
        run.stderr
    );
}

/// The other side of the same rule: a genuinely complete earlier attempt
/// still resumes, and neither child runs again.
#[test]
fn a_complete_previous_attempt_is_still_resumed() {
    let dir = workdir("resume-complete");
    let out = dir.join("results.tsv");
    seed_stale_row(&out, "caller", "mio", "earlier-attempt");
    seed_stale_row(&out, "listener", "mio", "earlier-attempt");
    // Both children would fail if they ran at all.
    let sender = write_script(&dir, "sender.sh", "exit 9");
    let receiver = write_script(&dir, "receiver.sh", "exit 9");
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(
        run.status.success(),
        "a complete previous attempt must resume, not re-run\n{}",
        run.stderr
    );
    let rows = srt_bench::harness::read_results(&out).expect("read results");
    assert_eq!(rows.len(), 2, "no new rows should have been written");
}

/// A caller row from one interrupted attempt plus a listener row from
/// another is a complete-looking cell whose halves never ran together.
/// It must be re-run rather than resumed.
#[test]
fn two_different_partial_attempts_do_not_add_up_to_a_done_cell() {
    let dir = workdir("resume-mismatched");
    let out = dir.join("results.tsv");
    seed_stale_row(&out, "caller", "mio", "attempt-a");
    seed_stale_row(&out, "listener", "mio", "attempt-b");
    let sender = write_script(&dir, "sender.sh", "exit 9");
    let receiver = write_script(&dir, "receiver.sh", "exit 9");
    let run = run_matrix(&dir, &sender, &receiver, &pinning_flags("mio"));
    assert!(
        !run.status.success(),
        "halves from two attempts must not resume as one done cell\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("sender child failed"),
        "the cell must actually have been re-run\n{}",
        run.stderr
    );
}
