use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

// cargo test's default runner runs #[test] fns in this file concurrently on
// separate threads. Each one spawns real bench-binary child processes that
// do real protocol handshakes over real loopback sockets. Serialize just this
// file's three tests rather than a blunt `--test-threads=1` for the whole
// workspace, which would also slow down every fast, unrelated test elsewhere.
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
    let mut last_failure = None;
    for attempt in 1..=2 {
        match smoke_once(runtime, mode, encryption, egress) {
            Ok(()) => return,
            Err(failure) => last_failure = Some(failure),
        }
        // A one-second benchmark cell can end with one physical leg pending
        // when a busy shared runner delays process startup. Retry the complete
        // independent cell once; a persistent incomplete handshake still
        // fails with both attempts' diagnostics.
        if attempt == 1 {
            thread::sleep(Duration::from_millis(100));
        }
    }
    panic!(
        "bonded smoke cell failed twice: {}",
        last_failure.expect("failed smoke attempt records diagnostics")
    );
}

fn smoke_once(runtime: &str, mode: &str, encryption: &str, egress: &str) -> Result<(), String> {
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

    if !sender.status.success() {
        return Err(format!(
            "sender stderr: {}",
            String::from_utf8_lossy(&sender.stderr)
        ));
    }
    if !receiver.status.success() {
        return Err(format!(
            "receiver stderr: {}",
            String::from_utf8_lossy(&receiver.stderr)
        ));
    }
    let sender_stats = stats(&sender.stdout);
    let receiver_stats = stats(&receiver.stdout);
    if !sender_stats.contains("established=2") {
        return Err(sender_stats.to_owned());
    }
    if !receiver_stats.contains("established=1") {
        return Err(receiver_stats.to_owned());
    }
    if receiver_stats
        .split_whitespace()
        .find_map(|field| field.strip_prefix("pkt_sent="))
        .and_then(|count| count.parse::<u64>().ok())
        .is_none_or(|count| count == 0)
    {
        return Err(receiver_stats.to_owned());
    }
    Ok(())
}

#[test]
fn bond_axis_forms_one_logical_broadcast_stream() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for runtime in ["mio", "tokio", "smol", "monoio", "glommio", "compio"] {
        smoke(runtime, "broadcast", "plain", "shared-socket");
    }
}

#[test]
fn bond_axis_forms_one_logical_encrypted_backup_stream() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for runtime in ["mio", "tokio", "smol", "monoio", "glommio", "compio"] {
        smoke(runtime, "backup", "256", "shared-socket");
    }
}
