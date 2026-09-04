//! Live evidence that an ordinary queued runtime stays below its explicit
//! packet-channel bound without hiding drops.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

const EXE: &str = env!("CARGO_BIN_EXE_srt-bench");

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

#[test]
#[ignore = "live compio localhost sentinel; requires io_uring"]
fn normal_compio_run_stays_below_the_datapath_queue_bound() {
    let dir = std::env::temp_dir().join(format!("srt-bench-queue-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("workdir");
    let out = dir.join("results.tsv");
    let port = free_port();

    let mut receiver = Command::new(EXE)
        .args([
            "runtime=compio",
            "mode=receiver",
            &port.to_string(),
            "32",
            "120",
            "1000000",
            "--stream-secs=2",
            "--srt-bandwidth=fixed:2000000",
        ])
        .arg(format!("--out={}", out.display()))
        .env("SRT_BENCH_CHILD", "1")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn receiver");
    let stdout = receiver.stdout.take().expect("stdout");
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut announced = false;
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if !announced && line.contains("LISTENING") {
                announced = true;
                let _ = ready_tx.send(true);
            }
        }
        if !announced {
            let _ = ready_tx.send(false);
        }
    });
    assert_eq!(
        ready_rx.recv_timeout(std::time::Duration::from_secs(30)),
        Ok(true),
        "listener never announced"
    );

    let sender = Command::new(EXE)
        .args([
            "runtime=compio",
            "mode=sender",
            "127.0.0.1",
            &port.to_string(),
            "2",
            "120",
            "1000000",
            "--srt-bandwidth=fixed:2000000",
        ])
        .arg(format!("--out={}", out.display()))
        .env("SRT_BENCH_CHILD", "1")
        .status()
        .expect("run sender");
    assert!(sender.success());

    // SAFETY: this process still owns and has not reaped the child.
    unsafe { libc::kill(receiver.id() as libc::pid_t, libc::SIGTERM) };
    assert!(receiver.wait().expect("wait receiver").success());

    let rows = srt_bench::harness::read_results(&out).expect("results");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let per_queue = row
            .number("datapath_q_cap_per_queue")
            .expect("per-queue capacity");
        let queues = row.number("datapath_q_count").expect("queue count");
        let total_capacity = row.number("datapath_q_total_cap").expect("pool capacity");
        let peak_single = row
            .number("datapath_q_peak_depth_max")
            .expect("worst single queue");
        let peak_total = row
            .number("datapath_q_peak_total_depth")
            .expect("process-wide peak");

        // Capacity is derived from the horizon and this socket's fan-in,
        // not a constant, so assert the relations rather than a number.
        assert!(per_queue >= 64.0, "capacity floor: {per_queue}");
        assert_eq!(
            total_capacity,
            per_queue * queues,
            "the pool is every queue's capacity"
        );
        // A normal sentinel stays well below capacity and drops nothing.
        assert!(
            peak_single > 0.0 && peak_single < per_queue,
            "peak {peak_single} of {per_queue}"
        );
        assert!(
            peak_total >= peak_single,
            "the process-wide peak cannot be below the worst single queue: {peak_total} < {peak_single}"
        );
        assert!(
            peak_total <= total_capacity,
            "process-wide depth cannot exceed the pool: {peak_total} > {total_capacity}"
        );
        assert_eq!(row.number("datapath_q_full"), Some(0.0));
        assert_eq!(row.number("datapath_q_dropped"), Some(0.0));
    }
}
