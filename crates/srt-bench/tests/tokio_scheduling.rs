//! Live evidence for Tokio receive quanta and outbound retry policy.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};

const EXE: &str = env!("CARGO_BIN_EXE_srt-bench");

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_listening(child: &mut std::process::Child) {
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut ready = false;
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if !ready && line.contains("LISTENING") {
                ready = true;
                let _ = tx.send(true);
            }
        }
        if !ready {
            let _ = tx.send(false);
        }
    });
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(30)),
        Ok(true)
    );
}

fn run_cell(out: &std::path::Path, connections: usize, rounds: usize) {
    let port = free_port();
    let common = [
        format!("--connections={connections}"),
        "--ingress=shared-pool=1".to_string(),
        format!("--recv-rounds={rounds}"),
        "--srt-bandwidth=fixed:4000000".to_string(),
        "--sock-buf=4m".to_string(),
        format!("--out={}", out.display()),
    ];
    let mut receiver = Command::new(EXE)
        .args([
            "runtime=tokio",
            "mode=receiver",
            &port.to_string(),
            "30",
            "120",
            "2000000",
            "--stream-secs=2",
        ])
        .args(&common)
        .env("SRT_BENCH_CHILD", "1")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn Tokio receiver");
    wait_for_listening(&mut receiver);

    let sender = Command::new(EXE)
        .args([
            "runtime=tokio",
            "mode=sender",
            "127.0.0.1",
            &port.to_string(),
            "2",
            "120",
            "2000000",
            "--egress=shared-socket",
            &format!("--connect-concurrency={connections}"),
        ])
        .args(&common)
        .env("SRT_BENCH_CHILD", "1")
        .stdout(Stdio::null())
        .status()
        .expect("run Tokio sender");
    assert!(
        sender.success(),
        "sender failed for c={connections} r={rounds}"
    );

    // SAFETY: this process still owns and has not reaped the child.
    unsafe { libc::kill(receiver.id() as libc::pid_t, libc::SIGTERM) };
    assert!(receiver.wait().expect("wait receiver").success());
}

fn list_from_env(name: &str, default: &[usize]) -> Vec<usize> {
    std::env::var(name).map_or_else(
        |_| default.to_vec(),
        |value| {
            value
                .split(',')
                .map(|part| part.parse().expect("positive integer list"))
                .collect()
        },
    )
}

#[test]
#[ignore = "live 1/4/8/16/32 receive-round sweep at medium/high concurrency"]
fn receive_round_sweep_records_timer_drift_and_batch_efficiency() {
    let dir = std::env::temp_dir().join(format!("srt-bench-recv-sweep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("results.tsv");
    let connections = list_from_env("SRT_BENCH_SWEEP_CONNECTIONS", &[16, 64]);
    let rounds = list_from_env("SRT_BENCH_SWEEP_ROUNDS", &[1, 4, 8, 16, 32]);
    for connection_count in connections {
        for &round_count in &rounds {
            run_cell(&out, connection_count, round_count);
        }
    }

    let rows = srt_bench::harness::read_results(&out).unwrap();
    assert!(!rows.is_empty());
    for row in rows
        .iter()
        .filter(|row| row.get("role") == Some("listener"))
    {
        assert!(row.number("recv_packets").unwrap_or(0.0) > 0.0);
        assert!(row.number("recv_syscalls").unwrap_or(0.0) > 0.0);
        assert!(row.number("datagrams_per_syscall").unwrap_or(0.0) >= 1.0);
        assert!(row.number("timer_late_max_us").is_some());
        assert_eq!(row.number("retry_overflow"), Some(0.0));
        assert_eq!(row.number("local_dropped"), Some(0.0));
    }
    eprintln!("receive-round sweep results: {}", out.display());
}

fn force_kernel_would_block(
    policy: srt_bench::scheduling::WouldBlockPolicy,
) -> srt_bench::scheduling::RetryStats {
    let target: SocketAddr = std::env::var("SRT_BENCH_WOULDBLOCK_TARGET")
        .expect("set SRT_BENCH_WOULDBLOCK_TARGET to an unused on-link IPv4 address")
        .parse()
        .expect("socket address");
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    srt_transport::set_sock_bufs(socket.as_raw_fd(), 1024).unwrap();
    let mut queue = srt_bench::scheduling::RetryQueue::new(policy, 4096);
    for _ in 0..128 {
        let mut generated = (0..32).map(|_| (target, vec![0; 1316])).collect();
        queue.append(&mut generated);
        queue
            .flush_with(|batch| {
                let refs: Vec<(std::net::SocketAddr, &[u8])> = batch
                    .iter()
                    .map(|(address, packet)| (*address, packet.as_slice()))
                    .collect();
                srt_transport::sendmsg_batch(socket.as_raw_fd(), &refs)
            })
            .unwrap();
        if queue.stats().would_block > 0 {
            return queue.stats();
        }
    }
    panic!("selected target did not produce outbound WouldBlock")
}

#[test]
#[ignore = "requires an unused on-link address supplied in SRT_BENCH_WOULDBLOCK_TARGET"]
fn actual_kernel_would_block_distinguishes_retain_from_drop() {
    let retained = force_kernel_would_block(srt_bench::scheduling::WouldBlockPolicy::Retain);
    let dropped = force_kernel_would_block(srt_bench::scheduling::WouldBlockPolicy::Drop);
    eprintln!("retain={retained:?} drop={dropped:?}");
    assert!(retained.would_block > 0 && dropped.would_block > 0);
    assert!(retained.high_water > 0);
    assert_eq!(retained.local_dropped, 0);
    assert!(dropped.local_dropped > 0);
    assert_eq!(retained.overflow, 0);
    assert_eq!(dropped.overflow, 0);
}
