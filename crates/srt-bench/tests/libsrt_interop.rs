//! Interop tests against real libsrt (Haivision/srt), via the Ubuntu/Debian
//! package `srt-tools` (ships the real SRT protocol implementation, not this
//! workspace's): `srt-file-transmit` and `srt-live-transmit`.
//!
//! Skips (does not fail) if the relevant binary isn't on PATH, so local
//! `cargo test` runs on a machine without libsrt installed still pass. CI
//! installs `srt-tools` explicitly before running this suite.

use shiguredo_srt::{ConnectionOptions, KeyLength, SrtConnection, Timestamp};
use srt_bench::driver;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
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
    test_payload_bytes(4_000)
}

fn test_payload_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

#[derive(Clone, Copy, Default)]
struct LiveOptions<'a> {
    encryption: Option<(&'a str, KeyLength)>,
    stream_id: Option<&'a str>,
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
fn lossy_udp_proxy_thread(
    listen: UdpSocket,
    listener: SocketAddr,
    drop_every: u32,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        listen
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("set proxy read timeout");
        let mut caller = None;
        let mut forwarded_data_packets = 0_u32;
        let mut buf = [0_u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            let (n, from) = match listen.recv_from(&mut buf) {
                Ok(packet) => packet,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => panic!("proxy receive failed: {error}"),
            };
            if from == listener {
                if let Some(caller) = caller {
                    listen
                        .send_to(&buf[..n], caller)
                        .expect("proxy sends reply");
                }
                continue;
            }

            caller = Some(from);
            // SRT data packets have a clear high bit; control traffic must not
            // be dropped, or a handshake/NAK test could become a timing test.
            let is_data = buf.first().is_some_and(|first| first & 0x80 == 0);
            if is_data {
                forwarded_data_packets += 1;
                if forwarded_data_packets.is_multiple_of(drop_every) {
                    continue;
                }
            }
            listen
                .send_to(&buf[..n], listener)
                .expect("proxy forwards packet to listener");
        }
    })
}

fn receive_live_from_udp_source(
    payload: &[u8],
    encryption: Option<(&str, KeyLength)>,
    drop_every: Option<u32>,
) -> (driver::DriverResult, ExitStatus, String) {
    let port = free_port();
    let source_port = free_port();
    let socket = UdpSocket::bind(("127.0.0.1", port)).expect("bind listener socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set_read_timeout");

    let proxy_stop = Arc::new(AtomicBool::new(false));
    let proxy = drop_every.map(|drop_every| {
        let proxy = UdpSocket::bind(("127.0.0.1", 0)).expect("bind lossy UDP proxy");
        let proxy_addr = proxy.local_addr().expect("read proxy address");
        let listener = socket.local_addr().expect("read listener address");
        (
            proxy_addr,
            lossy_udp_proxy_thread(proxy, listener, drop_every, Arc::clone(&proxy_stop)),
        )
    });
    let output_port = proxy.as_ref().map_or(port, |(addr, _)| addr.port());
    let loss_recovery = proxy.is_some();
    let mut output_uri = match encryption {
        Some((passphrase, key_length)) => format!(
            "srt://127.0.0.1:{output_port}?passphrase={passphrase}&pbkeylen={}",
            key_length.len()
        ),
        None => format!("srt://127.0.0.1:{output_port}"),
    };
    if loss_recovery {
        let separator = if output_uri.contains('?') { '&' } else { '?' };
        output_uri.push_str(&format!("{separator}latency=500&peerlatency=500"));
    }
    let child = Command::new("srt-live-transmit")
        .args([
            "-q",
            if loss_recovery {
                "-timeout:8"
            } else {
                "-timeout:3"
            },
        ])
        .arg(format!("udp://127.0.0.1:{source_port}"))
        .arg(output_uri)
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
            if loss_recovery {
                // Leave time for NAK feedback before the source reaches EOF;
                // the no-loss tests deliberately remain a fast burst.
                std::thread::sleep(Duration::from_millis(2));
            }
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
    // The proxy is the listener's peer under loss; without it, connect to the
    // actual libsrt caller directly as the baseline tests do.
    socket
        .connect(proxy.as_ref().map_or(peer_addr, |(addr, _)| *addr))
        .expect("connect listener socket to peer");

    let mut conn = SrtConnection::new_listener(ConnectionOptions {
        socket_id: 0x2000_0001,
        congestion_control: "live".to_string(),
        passphrase: encryption.map(|(passphrase, _)| passphrase.to_string()),
        key_length: encryption.map_or(KeyLength::Aes128, |(_, key_length)| key_length),
        tsbpd_delay: if loss_recovery { 500 } else { 120 },
        ..Default::default()
    });
    conn.feed_recv_buf(&buf[..n], Timestamp::from_micros(0))
        .expect("feed first packet (INDUCTION) into the listener");
    let result = driver::run(
        &mut conn,
        &socket,
        start,
        Duration::from_secs(if loss_recovery { 15 } else { 10 }),
        Duration::from_secs(if loss_recovery { 8 } else { 2 }),
        |_, _, _| {},
    );
    source_sender.join().expect("UDP source sender panicked");
    proxy_stop.store(true, Ordering::Relaxed);
    if let Some((_, proxy)) = proxy {
        proxy.join().expect("lossy UDP proxy panicked");
    }
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
fn send_to_libsrt_listener(
    payload: &[u8],
    caller: LiveOptions<'_>,
    listener: LiveOptions<'_>,
    deadline: Duration,
) -> (driver::DriverResult, Output) {
    let port = free_port();
    let mut input_uri = format!("srt://:{port}?mode=listener");
    if let Some((passphrase, key_length)) = listener.encryption {
        input_uri.push_str(&format!(
            "&passphrase={passphrase}&pbkeylen={}",
            key_length.len()
        ));
    }
    if let Some(stream_id) = listener.stream_id {
        input_uri.push_str(&format!("&streamid={stream_id}"));
    }
    let child = Command::new("srt-live-transmit")
        .args(["-q", "-timeout:3"])
        .arg(input_uri)
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
        passphrase: caller
            .encryption
            .map(|(passphrase, _)| passphrase.to_string()),
        key_length: caller
            .encryption
            .map_or(KeyLength::Aes128, |(_, key_length)| key_length),
        stream_id: caller.stream_id.map(str::to_owned),
        ..Default::default()
    });
    conn.connect(Timestamp::from_micros(0))
        .expect("start Rust caller handshake");

    let payload = payload.to_vec();
    let result = driver::run(
        &mut conn,
        &socket,
        start,
        deadline,
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
    let received: Vec<u8> = result.received_payloads.into_iter().flatten().collect();
    assert_eq!(
        received, payload,
        "payload received from real libsrt does not match the file sent byte-for-byte; driver events: {:?}",
        result.events
    );
    // Debian sid's libsrt 1.5.6 returns non-zero after printing both of these
    // successful-completion markers when the test listener has already
    // closed. Byte equality above is the protocol assertion; retain the exit
    // check so a genuine sender failure cannot be hidden by this quirk.
    assert!(
        status.success() || (stderr.contains("File sent") && stderr.contains("Buffers flushed")),
        "srt-file-transmit caller exited before completing the transfer, stderr: {stderr}"
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

    let (result, status, stderr) = receive_live_from_udp_source(&payload, None, None);

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

/// Exercises real SRT ARQ end-to-end, rather than merely unit-testing NAK
/// handling: a deterministic proxy drops every twentieth DATA packet on the
/// libsrt-to-Rust path while forwarding all control traffic unchanged.
#[test]
#[ignore = "loss recovery is timing-sensitive; run with --ignored"]
fn libsrt_caller_recovers_payload_under_5pct_loss() {
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_caller_recovers_payload_under_5pct_loss: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload_bytes(120_000);
    let (result, status, stderr) = receive_live_from_udp_source(&payload, None, Some(20));
    assert!(
        result.connected,
        "Rust listener never reached Connected through the lossy proxy: {:?}",
        result.events
    );
    assert!(
        status.success(),
        "srt-live-transmit caller exited with failure through the lossy proxy, stderr: {stderr}"
    );
    let received: Vec<u8> = result.received_payloads.into_iter().flatten().collect();
    assert_eq!(
        received, payload,
        "libsrt payload did not recover byte-for-byte after deterministic 5% loss; driver events: {:?}",
        result.events
    );
}

#[test]
fn libsrt_live_caller_aes128_to_rust_listener() {
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_live_caller_aes128_to_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();
    let (result, status, stderr) = receive_live_from_udp_source(
        &payload,
        Some(("interop-passphrase", KeyLength::Aes128)),
        None,
    );
    assert!(
        result.connected,
        "Rust listener never connected: {:?}",
        result.events
    );
    assert!(status.success(), "libsrt caller failed: {stderr}");
    let received: Vec<u8> = result.received_payloads.into_iter().flatten().collect();
    assert_eq!(
        received, payload,
        "AES-128 payload mismatch: {:?}",
        result.events
    );
}

#[test]
fn libsrt_live_caller_aes256_to_rust_listener() {
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_live_caller_aes256_to_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();
    let (result, status, stderr) = receive_live_from_udp_source(
        &payload,
        Some(("interop-passphrase", KeyLength::Aes256)),
        None,
    );
    assert!(
        result.connected,
        "Rust listener never connected: {:?}",
        result.events
    );
    assert!(status.success(), "libsrt caller failed: {stderr}");
    let received: Vec<u8> = result.received_payloads.into_iter().flatten().collect();
    assert_eq!(
        received, payload,
        "AES-256 payload mismatch: {:?}",
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
    let (result, output) = send_to_libsrt_listener(
        &payload,
        LiveOptions::default(),
        LiveOptions::default(),
        Duration::from_secs(10),
    );

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

#[test]
fn rust_live_caller_aes128_to_libsrt_listener() {
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_live_caller_aes128_to_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();
    let encrypted = LiveOptions {
        encryption: Some(("interop-passphrase", KeyLength::Aes128)),
        ..Default::default()
    };
    let (result, output) =
        send_to_libsrt_listener(&payload, encrypted, encrypted, Duration::from_secs(10));
    assert!(
        result.connected,
        "Rust caller never connected: {:?}; libsrt stderr: {}",
        result.events,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "libsrt listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, payload,
        "AES-128 payload mismatch: {:?}",
        result.events
    );
}

/// A listener with a different passphrase must reject a Rust caller before
/// either side accepts application data. The successful AES-128 test above is
/// the matching-passphrase control for this exact live listener path.
#[test]
fn rust_live_caller_wrong_passphrase_is_rejected_by_libsrt_listener() {
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_live_caller_wrong_passphrase_is_rejected_by_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let caller = LiveOptions {
        encryption: Some(("wrong-interop-passphrase", KeyLength::Aes128)),
        ..Default::default()
    };
    let listener = LiveOptions {
        encryption: Some(("interop-passphrase", KeyLength::Aes128)),
        ..Default::default()
    };
    let (result, output) = send_to_libsrt_listener(
        b"must never be delivered",
        caller,
        listener,
        Duration::from_secs(5),
    );

    assert!(
        !result.connected,
        "Rust caller unexpectedly connected with a wrong passphrase: {:?}; libsrt stderr: {}",
        result.events,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        result
            .events
            .iter()
            .any(|event| event.contains("reason=10")),
        "wrong passphrase did not surface the SRT BADSECRET rejection (reason=10): {:?}; libsrt stderr: {}",
        result.events,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "libsrt emitted data after rejection"
    );
}

#[test]
fn rust_live_caller_with_stream_id_connects_to_libsrt_listener() {
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_live_caller_with_stream_id_connects_to_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let stream_id = "mypass/stream1";
    let options = LiveOptions {
        stream_id: Some(stream_id),
        ..Default::default()
    };
    let payload = test_payload();
    let (result, output) =
        send_to_libsrt_listener(&payload, options, options, Duration::from_secs(10));

    assert!(
        result.connected,
        "Rust caller with StreamID did not connect: {:?}; libsrt stderr: {}",
        result.events,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "libsrt listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, payload,
        "StreamID payload mismatch: {:?}",
        result.events
    );
}
