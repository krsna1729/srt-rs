//! Interop tests against real libsrt (Haivision/srt), via the Ubuntu/Debian
//! package `srt-tools` (ships the real SRT protocol implementation, not this
//! workspace's): `srt-file-transmit` and `srt-live-transmit`.
//!
//! Skips (does not fail) if the relevant binary isn't on PATH, so local
//! `cargo test` runs on a machine without libsrt installed still pass. CI
//! installs `srt-tools` explicitly before running this suite.

use shiguredo_srt::{ConnectionOptions, SrtConnection, Timestamp};
use srt_bench::driver;
use std::net::UdpSocket;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

fn command_available(binary: &str) -> bool {
    Command::new(binary)
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

fn scratch_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "srt-interop-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn wait_for_child(mut child: Child, binary: &str) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().expect("poll libsrt process").is_some() {
            let output = child
                .wait_with_output()
                .unwrap_or_else(|e| panic!("collect {binary} output: {e}"));
            return output;
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .unwrap_or_else(|e| panic!("kill stuck {binary}: {e}"));
            let output = child
                .wait_with_output()
                .unwrap_or_else(|e| panic!("collect killed {binary} output: {e}"));
            panic!(
                "{binary} did not exit within 5 seconds; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Spawn `binary <source_uri> srt://127.0.0.1:<port>` as a real libsrt
/// caller, and drive this crate's pure-Rust `SrtConnection` as the listener
/// (via `srt_bench::driver`). If `stdin_payload` is given, it's written to
/// the child's stdin and the write end is then closed (EOF) -- needed for
/// `srt-live-transmit`, whose `file:` scheme only supports `file://con`
/// (stdin/stdout), not an arbitrary path. Returns the driver's result plus
/// the caller process's exit status and stderr.
fn receive_from_libsrt_caller(
    binary: &str,
    source_uri: &str,
    congestion_control: &str,
    stdin_payload: Option<&[u8]>,
) -> (driver::DriverResult, ExitStatus, String) {
    let port = free_port();
    let socket = UdpSocket::bind(("127.0.0.1", port)).expect("bind listener socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set_read_timeout");

    let mut command = Command::new(binary);
    command
        .arg(source_uri)
        .arg(format!("srt://127.0.0.1:{port}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_payload.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {binary} caller: {e}"));

    if let Some(payload) = stdin_payload {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("child stdin was piped");
        stdin.write_all(payload).expect("write payload to stdin");
        // Drop closes the write end, delivering EOF to the child.
    }

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
                    "timed out waiting for {binary}'s first datagram"
                );
            }
            Err(e) => panic!("recv_from failed: {e}"),
        }
    };
    socket
        .connect(peer_addr)
        .expect("connect socket to libsrt caller's address");

    let mut conn = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2000_0001,
        congestion_control: congestion_control.to_string(),
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

    let output = wait_for_child(child, binary);
    (
        result,
        output.status,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Run a live libsrt caller with a loopback UDP source. `srt-live-transmit`
/// cannot reliably poll `file://con` in this environment, while its UDP
/// source is a normal production input and gives this test a bounded EOF-free
/// process lifetime through `-timeout`.
fn receive_live_from_udp_source(payload: &[u8]) -> (driver::DriverResult, ExitStatus, String) {
    let port = free_port();
    let source_port = free_port();
    let socket = UdpSocket::bind(("127.0.0.1", port)).expect("bind listener socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set_read_timeout");

    let child = Command::new("srt-live-transmit")
        .args(["-q", "-timeout:3"])
        .arg(format!("udp://127.0.0.1:{source_port}"))
        .arg(format!("srt://127.0.0.1:{port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn srt-live-transmit caller: {e}"));

    let payload = payload.to_vec();
    let source_sender = std::thread::spawn(move || {
        // Give srt-live-transmit time to bind its UDP source and complete the
        // SRT handshake. It buffers the following datagrams for the peer.
        std::thread::sleep(Duration::from_millis(500));
        let source = UdpSocket::bind(("127.0.0.1", 0)).expect("bind UDP payload sender");
        for chunk in payload.chunks(1_000) {
            source
                .send_to(chunk, ("127.0.0.1", source_port))
                .expect("send payload into live UDP source");
        }
    });

    let start = Instant::now();
    let mut buf = [0u8; 2048];
    let (n, peer_addr) = loop {
        match socket.recv_from(&mut buf) {
            Ok(received) => break received,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "timed out waiting for srt-live-transmit's first datagram"
                );
            }
            Err(e) => panic!("recv_from failed: {e}"),
        }
    };
    socket
        .connect(peer_addr)
        .expect("connect socket to libsrt caller's address");

    let mut conn = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2000_0001,
        congestion_control: "live".to_string(),
        ..Default::default()
    });
    conn.feed_recv_buf(&buf[..n], Timestamp::from_micros(0))
        .expect("feed first packet (INDUCTION) into the listener");
    let result = driver::run(
        &mut conn,
        &socket,
        start,
        Duration::from_secs(10),
        Duration::from_secs(2),
        |_, _, _| {},
    );
    source_sender.join().expect("UDP source sender panicked");
    let output = wait_for_child(child, "srt-live-transmit");
    (
        result,
        output.status,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Run a live libsrt listener and send it a byte stream from a Rust caller.
/// The test uses the same live congestion control and a bounded process
/// lifetime as the forward-direction live test.
fn send_to_libsrt_listener(payload: &[u8]) -> (driver::DriverResult, Output) {
    let port = free_port();
    let child = Command::new("srt-live-transmit")
        .args(["-q", "-timeout:3"])
        .arg(format!("srt://:{port}?mode=listener"))
        .arg("file://con")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn srt-live-transmit listener: {e}"));

    // The listener's port is opened synchronously during its process startup,
    // but UDP reports ICMP refusal if the caller wins that small race.
    std::thread::sleep(Duration::from_millis(100));
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind Rust caller socket");
    socket
        .connect(("127.0.0.1", port))
        .expect("connect Rust caller socket");
    let start = Instant::now();
    let mut conn = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x2000_0002,
        congestion_control: "live".to_string(),
        ..Default::default()
    });
    conn.connect(Timestamp::from_micros(0))
        .expect("start Rust caller handshake");

    let payload = payload.to_vec();
    let result = driver::run(
        &mut conn,
        &socket,
        start,
        Duration::from_secs(10),
        Duration::from_secs(2),
        move |conn, _, now| {
            for chunk in payload.chunks(1_000) {
                conn.send(chunk, now)
                    .expect("send payload from Rust caller");
            }
        },
    );
    let output = wait_for_child(child, "srt-live-transmit");
    (result, output)
}

/// Real libsrt (`srt-file-transmit`, as caller) sends a file; this crate's
/// pure-Rust `SrtConnection` (as listener, driven via `srt_bench::driver`)
/// receives it. Proves a real libsrt peer's wire output is byte-exact
/// decodable by this implementation -- not just internally self-consistent.
#[test]
fn libsrt_file_transmit_caller_sends_file_to_rust_listener() {
    if !command_available("srt-file-transmit") {
        eprintln!(
            "skipping libsrt_file_transmit_caller_sends_file_to_rust_listener: srt-file-transmit not on PATH"
        );
        return;
    }

    let tmp = scratch_dir("file");
    let payload = test_payload();
    let payload_path = tmp.join("payload.bin");
    std::fs::write(&payload_path, &payload).expect("write payload file");

    // srt-file-transmit uses libsrt's Buffer/File API and declares "file"
    // congctl; matching it here is required for interop -- otherwise real
    // libsrt refuses to transmit (see ConnectionOptions::congestion_control).
    let (result, status, stderr) = receive_from_libsrt_caller(
        "srt-file-transmit",
        &format!("file://{}", payload_path.display()),
        "file",
        None,
    );
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        result.connected,
        "Rust listener never reached Connected: {:?}",
        result.events
    );
    assert!(
        status.success(),
        "srt-file-transmit caller exited with failure, stderr: {stderr}"
    );
    let received: Vec<u8> = result.received_payloads.into_iter().flatten().collect();
    assert_eq!(
        received, payload,
        "payload received from real libsrt does not match the file sent byte-for-byte; driver events: {:?}",
        result.events
    );
}

/// Real libsrt (`srt-live-transmit`, as caller, live/streaming semantics --
/// the mode this workspace's own implementation actually matches, and the
/// one it prioritizes for interop) reads a UDP source and streams it; this
/// crate's pure-Rust `SrtConnection` (as listener) receives it. Complements
/// the `srt-file-transmit` test above, which exercises libsrt's
/// Buffer/File API instead.
#[test]
fn libsrt_live_transmit_caller_sends_udp_to_rust_listener() {
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_live_transmit_caller_sends_udp_to_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();

    let (result, status, stderr) = receive_live_from_udp_source(&payload);

    assert!(
        result.connected,
        "Rust listener never reached Connected: {:?}",
        result.events
    );
    assert!(
        status.success(),
        "srt-live-transmit caller exited with failure, stderr: {stderr}"
    );
    let received: Vec<u8> = result.received_payloads.into_iter().flatten().collect();
    assert_eq!(
        received, payload,
        "payload received from real libsrt does not match the file sent byte-for-byte; driver events: {:?}",
        result.events
    );
}

/// A Rust live caller sends a byte-exact stream to a real libsrt live
/// listener. This covers the inverse handshake and DATA direction from the
/// UDP-source test above.
#[test]
fn rust_live_caller_sends_stream_to_libsrt_listener() {
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_live_caller_sends_stream_to_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();
    let (result, output) = send_to_libsrt_listener(&payload);

    assert!(
        result.connected,
        "Rust caller never reached Connected: {:?}; libsrt stderr: {}",
        result.events,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "srt-live-transmit listener exited with failure, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, payload,
        "libsrt listener output does not match Rust caller payload byte-for-byte; driver events: {:?}",
        result.events
    );
}
