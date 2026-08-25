use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

// cargo test's default runner runs #[test] fns in this file concurrently on
// separate threads. Each one spawns real bench-binary child processes that
// do real protocol handshakes over real loopback sockets within
// CONNECT_TIMEOUT (15s); three of these competing for the same CPU
// (especially on a small shared CI runner) can push a cell past that
// deadline on pure host contention, not a real regression -- confirmed by
// running the failing test alone (71.7s, no timeout headroom issue at all)
// versus concurrently with its siblings (fails at the 15s mark). Serialize
// just this file's three tests rather than a blunt `--test-threads=1` for
// the whole workspace, which would also slow down every fast, unrelated
// test elsewhere.
static SERIAL: Mutex<()> = Mutex::new(());

fn free_port() -> u16 {
    UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("reserve loopback port")
        .local_addr()
        .expect("read reserved address")
        .port()
}

fn stats(output: &[u8]) -> &str {
    std::str::from_utf8(output)
        .expect("UTF-8 benchmark output")
        .lines()
        .find(|line| line.starts_with("STATS "))
        .expect("final STATS line")
}

fn smoke(runtime: &str, mode: &str, encryption: &str, egress: &str) {
    let bin = std::env::var_os("CARGO_BIN_EXE_srt-bench").expect("bench binary path");
    let port = free_port().to_string();
    let receiver = Command::new(&bin)
        .args([
            &format!("runtime={runtime}"),
            "mode=receiver",
            &port,
            "1",
            "120",
            "1000000",
            "--connections=2",
            "--ingress",
            "shared-pool=1",
            "--egress",
            egress,
            &format!("--bond={mode}:1"),
            &format!("--encryption={encryption}"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start bonded receiver");
    thread::sleep(Duration::from_millis(300));
    let sender = Command::new(&bin)
        .args([
            &format!("runtime={runtime}"),
            "mode=sender",
            "127.0.0.1",
            &port,
            "1",
            "120",
            "1000000",
            "--connections=2",
            "--ingress",
            "shared-pool=1",
            "--egress",
            egress,
            &format!("--bond={mode}:1"),
            &format!("--encryption={encryption}"),
        ])
        .output()
        .expect("run bonded sender");
    let receiver = receiver
        .wait_with_output()
        .expect("collect bonded receiver");

    assert!(
        sender.status.success(),
        "sender stderr: {}",
        String::from_utf8_lossy(&sender.stderr)
    );
    assert!(
        receiver.status.success(),
        "receiver stderr: {}",
        String::from_utf8_lossy(&receiver.stderr)
    );
    let sender_stats = stats(&sender.stdout);
    let receiver_stats = stats(&receiver.stdout);
    assert!(sender_stats.contains("established=2"), "{sender_stats}");
    assert!(receiver_stats.contains("established=1"), "{receiver_stats}");
    assert!(
        receiver_stats
            .split_whitespace()
            .find_map(|field| field.strip_prefix("pkt_sent="))
            .and_then(|count| count.parse::<u64>().ok())
            .is_some_and(|count| count > 0),
        "{receiver_stats}"
    );
}

#[test]
fn bond_axis_forms_one_logical_broadcast_stream() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for runtime in ["mio", "tokio", "smol", "monoio", "glommio", "compio"] {
        smoke(runtime, "broadcast", "plain", "per-connection");
    }
}

#[test]
fn bond_axis_forms_one_logical_encrypted_backup_stream() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for runtime in ["mio", "tokio", "smol", "monoio", "glommio", "compio"] {
        smoke(runtime, "backup", "256", "per-connection");
    }
}

#[test]
fn shared_egress_uses_logical_broadcast_and_backup_callers_on_every_runtime() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for runtime in ["mio", "tokio", "smol", "monoio", "glommio", "compio"] {
        smoke(runtime, "broadcast", "plain", "shared-socket");
        smoke(runtime, "backup", "256", "shared-socket");
    }
}
