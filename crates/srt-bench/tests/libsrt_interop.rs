//! Interop tests against real libsrt (Haivision/srt), via the
//! `srt-file-transmit` CLI (Ubuntu/Debian package `srt-tools`; ships the
//! real SRT protocol implementation, not this workspace's).
//!
//! Skips (does not fail) if `srt-file-transmit` isn't on PATH, so local
//! `cargo test` runs on a machine without libsrt installed still pass. CI
//! installs it explicitly before running this suite.

use shiguredo_srt::{ConnectionOptions, SrtConnection, Timestamp};
use srt_bench::driver;
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn libsrt_available() -> bool {
    Command::new("srt-file-transmit")
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn free_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("reserve loopback port")
        .local_addr()
        .expect("read reserved address")
        .port()
}

fn test_payload() -> Vec<u8> {
    (0..4000u32).map(|i| (i % 256) as u8).collect()
}

/// Real libsrt (`srt-file-transmit`, as caller) sends a file; this crate's
/// pure-Rust `SrtConnection` (as listener, driven via `srt_bench::driver`)
/// receives it. Proves a real libsrt peer's wire output is byte-exact
/// decodable by this implementation -- not just internally self-consistent.
#[test]
fn libsrt_caller_sends_file_to_rust_listener() {
    if !libsrt_available() {
        eprintln!(
            "skipping libsrt_caller_sends_file_to_rust_listener: srt-file-transmit not on PATH"
        );
        return;
    }

    let tmp = std::env::temp_dir().join(format!(
        "srt-interop-a-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).expect("create temp dir");
    let payload = test_payload();
    let payload_path = tmp.join("payload.bin");
    std::fs::write(&payload_path, &payload).expect("write payload file");

    let port = free_port();
    let socket = UdpSocket::bind(("127.0.0.1", port)).expect("bind listener socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set_read_timeout");

    let child = Command::new("srt-file-transmit")
        .arg(format!("file://{}", payload_path.display()))
        .arg(format!("srt://127.0.0.1:{port}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn srt-file-transmit caller");

    let start = Instant::now();
    let mut buf = [0u8; 2048];
    let (n, peer_addr) = loop {
        match socket.recv_from(&mut buf) {
            Ok(r) => break r,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "timed out waiting for libsrt's first datagram"
                );
            }
            Err(e) => panic!("recv_from failed: {e}"),
        }
    };
    socket
        .connect(peer_addr)
        .expect("connect socket to libsrt caller's address");

    // srt-file-transmit uses libsrt's Buffer/File API and declares "file"
    // congctl; matching it here is required for interop -- otherwise real
    // libsrt refuses to transmit (see ConnectionOptions::congestion_control).
    let mut conn = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2000_0001,
        congestion_control: "file".to_string(),
        ..Default::default()
    });
    // driver::run's loop calls socket.recv() next; the first datagram was
    // already consumed by recv_from above (needed to learn the peer's
    // address before socket.connect()), so feed it in directly.
    conn.feed_recv_buf(&buf[..n], Timestamp::from_micros(0))
        .expect("feed first packet (INDUCTION) into the listener");

    let result = driver::run(
        &mut conn,
        &socket,
        start,
        Duration::from_secs(10),
        Duration::from_millis(500),
        |_, _, _| {},
    );

    let output = child
        .wait_with_output()
        .expect("wait for srt-file-transmit caller");
    let status = output.status;
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        result.connected,
        "Rust listener never reached Connected: {:?}",
        result.events
    );
    assert!(
        status.success(),
        "srt-file-transmit caller exited with failure, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let received: Vec<u8> = result.received_payloads.into_iter().flatten().collect();
    assert_eq!(
        received, payload,
        "payload received from real libsrt does not match the file sent byte-for-byte; driver events: {:?}",
        result.events
    );
}
