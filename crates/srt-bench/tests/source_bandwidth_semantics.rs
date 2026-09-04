//! The source payload rate and SRT's pacing policy are different
//! variables, and a result row has to be readable as such.
//!
//! Before this, srt-bench had one number called `bitrate` that was both
//! the workload rate and `SRTO_MAXBW`, and the sender had no source clock
//! at all -- it pushed payload whenever pacing allowed. "Did the sender
//! offer its configured load?" was therefore a question about the pacing
//! ceiling that produced the load, and it could not fail.
//!
//! These tests pin the separation at three levels: the resolution from a
//! policy to protocol options, the target a report computes, and one live
//! localhost run showing that changing MAXBW changes what the protocol
//! accepts without changing what the source was asked to produce.

use srt_bench::harness::{Record, source_target_packets};
use srt_bench::source::{BandwidthPolicy, SourceClock};
use std::time::Duration;

fn record(pairs: &[(&str, &str)]) -> Record {
    Record {
        fields: pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    }
}

/// The headline invariant: the source target depends on the source rate
/// and nothing else. Same source, three pacing ceilings, one target.
#[test]
fn the_same_source_rate_has_the_same_target_under_every_maxbw() {
    let targets: Vec<f64> = ["4000000", "8000000", "12000000"]
        .iter()
        .map(|maxbw| {
            let row = record(&[
                ("conns", "1"),
                ("source_bps", "8000000"),
                ("secs", "10"),
                ("srt_maxbw_bps", maxbw),
            ]);
            source_target_packets(&row).expect("target")
        })
        .collect();
    assert!(
        targets.windows(2).all(|w| w[0] == w[1]),
        "MAXBW must not move the source target: {targets:?}"
    );
    // 8 Mbit/s of 1316-byte payload for 10 s.
    let expected = 8_000_000.0 / 8.0 * 10.0 / srt_bench::PAYLOAD_SIZE as f64;
    assert!((targets[0] - expected).abs() < 1e-9);
}

/// And the target is *not* computed from MAXBW, which is what made it a
/// tautology. A row whose pacing ceiling is half its source rate keeps the
/// full source target and therefore visibly falls short.
#[test]
fn a_pacing_ceiling_below_the_source_does_not_lower_the_target() {
    let row = record(&[
        ("conns", "1"),
        ("source_bps", "8000000"),
        ("secs", "10"),
        ("srt_maxbw_bps", "4000000"),
    ]);
    let target = source_target_packets(&row).expect("target");
    // What a 4 Mbit/s ceiling can actually pace, in payload packets:
    // wire-byte pacing over (1316 + 16)-byte packets.
    let paced = 4_000_000.0 / 8.0 * 10.0
        / (srt_bench::PAYLOAD_SIZE + shiguredo_srt::SRT_HEADER_SIZE) as f64;
    assert!(
        paced / target < 0.55,
        "a half-rate ceiling must read as ~50% offered, not 100%: {paced}/{target}"
    );
}

#[test]
fn every_policy_maps_onto_the_protocol_options_it_names() {
    let source = 8_000_000;

    let default = BandwidthPolicy::parse("protocol-default")
        .unwrap()
        .resolve(source)
        .resolve();
    assert_eq!(
        default.max_bytes_per_sec, None,
        "protocol keeps its ceiling"
    );
    assert_eq!(default.input_bytes_per_sec, None);

    // The legacy mode's whole purpose is bit-exact reproduction of what
    // srt-bench did before the split.
    let legacy = BandwidthPolicy::parse("legacy-source-fixed")
        .unwrap()
        .resolve(source)
        .resolve();
    assert_eq!(legacy.max_bytes_per_sec, Some(source / 8));

    let fixed = BandwidthPolicy::parse("fixed:4000000")
        .unwrap()
        .resolve(source)
        .resolve();
    assert_eq!(fixed.max_bytes_per_sec, Some(500_000));
    assert!(
        fixed.max_bytes_per_sec.is_some(),
        "an explicit ceiling is independent of the source rate"
    );

    let relative = BandwidthPolicy::parse("input-relative:25")
        .unwrap()
        .resolve(source)
        .resolve();
    assert_eq!(relative.input_bytes_per_sec, Some(source / 8));
    assert_eq!(relative.overhead_percent, 25);
    assert_eq!(relative.max_bytes_per_sec, None, "INPUTBW, not MAXBW");
}

/// The source clock is driven by the configured rate, not by anything the
/// policy resolved to.
#[test]
fn the_source_clock_ignores_the_bandwidth_policy_entirely() {
    let mut generated = Vec::new();
    for policy in [
        "protocol-default",
        "legacy-source-fixed",
        "fixed:4000000",
        "fixed:12000000",
        "input-relative:25",
    ] {
        let policy = BandwidthPolicy::parse(policy).unwrap();
        // Resolving is a pure function of the source rate; it cannot feed
        // back into the clock.
        let _ = policy.resolve(8_000_000);
        let mut clock = SourceClock::new(std::num::NonZeroU64::new(8_000_000).unwrap(), u32::MAX);
        clock.tick(Duration::ZERO);
        clock.tick(Duration::from_secs(2));
        generated.push(clock.stats().generated);
    }
    assert!(
        generated.windows(2).all(|w| w[0] == w[1]),
        "the source produced different amounts under different pacing: {generated:?}"
    );
}

/// A result file written before the split cannot be read as either
/// quantity, and must say so by name rather than as a column-count
/// mismatch.
#[test]
fn legacy_result_files_are_rejected_explicitly() {
    let dir = std::env::temp_dir().join(format!("srt-bench-legacy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("workdir");
    let path = dir.join("legacy.tsv");
    std::fs::write(
        &path,
        "runtime\trole\tconns\tbitrate\tsecs\nmio\tcaller\t1\t8000000\t10\n",
    )
    .expect("write legacy file");
    let error = srt_bench::harness::read_results(&path).expect_err("must reject");
    let message = error.to_string();
    assert!(
        message.contains("legacy result schema") && message.contains("source_bps"),
        "the rejection must name the schema change: {message}"
    );
}

// --- live localhost evidence -------------------------------------------

mod live {
    use std::path::Path;
    use std::process::Command;

    const EXE: &str = env!("CARGO_BIN_EXE_srt-bench");

    fn workdir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("srt-bench-orth-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("workdir");
        dir
    }

    fn free_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port()
    }

    /// One localhost cell at a fixed source rate with the given SRT
    /// bandwidth policy. Returns (caller row, listener row).
    fn run_cell(dir: &Path, policy: &str, source_bps: u64, secs: u64) -> (f64, f64, f64, f64, f64) {
        let out = dir.join(format!("{}.tsv", policy.replace(':', "-")));
        let port = free_port();
        let mut receiver = Command::new(EXE)
            .args([
                "runtime=mio",
                "mode=receiver",
                &port.to_string(),
                &(secs + 30).to_string(),
                "120",
                &source_bps.to_string(),
            ])
            .arg(format!("--srt-bandwidth={policy}"))
            .arg(format!("--out={}", out.display()))
            .arg(format!("--stream-secs={secs}"))
            .env("SRT_BENCH_CHILD", "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn receiver");
        wait_for_listening(&mut receiver);

        let sender = Command::new(EXE)
            .args([
                "runtime=mio",
                "mode=sender",
                "127.0.0.1",
                &port.to_string(),
                &secs.to_string(),
                "120",
                &source_bps.to_string(),
            ])
            .arg(format!("--srt-bandwidth={policy}"))
            .arg(format!("--out={}", out.display()))
            .env("SRT_BENCH_CHILD", "1")
            .stdout(std::process::Stdio::null())
            .status()
            .expect("run sender");
        assert!(sender.success(), "sender failed for {policy}");

        // SIGTERM asks the listener to flush and write its row.
        // SAFETY: the child is still owned here, so its pid is not reaped.
        unsafe { libc::kill(receiver.id() as libc::pid_t, libc::SIGTERM) };
        let status = receiver.wait().expect("wait receiver");
        assert!(status.success(), "receiver failed for {policy}");

        let rows = srt_bench::harness::read_results(&out).expect("read results");
        let caller = rows
            .iter()
            .find(|r| r.get("role") == Some("caller"))
            .expect("caller row");
        let target = srt_bench::harness::source_target_packets(caller).expect("target");
        (
            target,
            caller.number("core_total").unwrap_or(0.0),
            caller.number("src_blocked_streaks").unwrap_or(0.0),
            caller.number("src_overflow").unwrap_or(0.0),
            caller.number("src_generated").unwrap_or(0.0),
        )
    }

    fn wait_for_listening(child: &mut std::process::Child) {
        use std::io::{BufRead, BufReader};
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if line.contains("LISTENING") {
                    let _ = tx.send(());
                }
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(30))
            .expect("listener announced");
    }

    /// Live evidence for the whole commit: one source rate, three SRT
    /// bandwidth policies. The source target is identical in all three,
    /// while what the protocol accepts -- and how much the source is
    /// pushed back on -- tracks the pacing ceiling.
    #[test]
    #[ignore = "live localhost run; takes ~15s"]
    fn changing_maxbw_changes_pacing_but_not_the_source_target() {
        let dir = workdir("orthogonality");
        let source_bps = 8_000_000;
        let secs = 4;

        let (t_half, sent_half, bp_half, overflow_half, generated_half) =
            run_cell(&dir, "fixed:4000000", source_bps, secs);
        let (t_match, sent_match, _, _, generated_match) =
            run_cell(&dir, "fixed:8000000", source_bps, secs);
        let (t_over, sent_over, bp_over, overflow_over, generated_over) =
            run_cell(&dir, "fixed:12000000", source_bps, secs);

        assert_eq!(
            (t_half, t_match),
            (t_match, t_over),
            "the source target must not move with MAXBW"
        );

        // The debug-build live harness includes connection ramp-up, so do
        // not pretend this short sentinel is a steady-state capacity run.
        // It only needs to prove that the half-rate ceiling is binding.
        let half_ratio = sent_half / t_half;
        assert!(
            half_ratio < 0.6,
            "fixed:4000000 should constrain an 8 Mbit/s source, got {half_ratio}"
        );
        assert!(
            sent_over > sent_match && sent_match > sent_half && sent_over > sent_half * 1.5,
            "accepted payload must track the ceiling: {sent_half} {sent_match} {sent_over}"
        );
        // All three source clocks generated the same workload (allowing a
        // scheduler tick at either endpoint), while the constrained cell
        // accumulated substantially more bounded backlog overflow.
        assert!(
            (generated_half - generated_match).abs() <= 20.0
                && (generated_match - generated_over).abs() <= 20.0,
            "MAXBW changed source generation: {generated_half} {generated_match} {generated_over}"
        );
        assert!(
            overflow_half > overflow_over,
            "the constrained cell must expose more overflow: {overflow_half} vs {overflow_over}"
        );
        assert!(
            bp_half > 0.0 && bp_over > 0.0 && bp_half != bp_over,
            "changing MAXBW must change observed source backpressure: {bp_half} vs {bp_over}"
        );
    }
}
