use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

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

fn smoke(runtime: &str, mode: &str, encryption: &str) {
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
    for runtime in ["mio", "tokio", "smol", "monoio", "glommio", "compio"] {
        smoke(runtime, "broadcast", "plain");
    }
}

#[test]
fn bond_axis_forms_one_logical_encrypted_backup_stream() {
    for runtime in ["mio", "tokio", "smol", "monoio", "glommio", "compio"] {
        smoke(runtime, "backup", "256");
    }
}
