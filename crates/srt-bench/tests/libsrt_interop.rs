//! Interop tests against real libsrt (Haivision/srt), via the Ubuntu/Debian
//! package `srt-tools` (ships the real SRT protocol implementation, not this
//! workspace's): `srt-file-transmit` and `srt-live-transmit`.
//!
//! Skips (does not fail) if the relevant binary isn't on PATH, so local
//! `cargo test` runs on a machine without libsrt installed still pass. CI
//! installs `srt-tools` explicitly before running this suite.

use shiguredo_srt::{CipherMode, ConnectionOptions, KeyLength, SrtConnection, Timestamp};
use srt_bench::driver;
use srt_transport::{
    AdmissionOptions, AdmissionResolution, CallerConfig, GroupCallerLeg, GroupConfig, GroupConn,
    IngressTelemetry, OutputDrainBudget, PeerTable, RejectionReason, RuntimeFlavor,
};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

/// Real libsrt processes have process-global initialization and timing-sensitive
/// teardown. Keep this black-box suite independent of the Rust test harness's
/// scheduling; unit and property tests remain fully parallel.
fn interop_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn received_payloads_match(received_payloads: &[bytes::Bytes], expected: &[u8]) -> bool {
    received_payloads
        .iter()
        .flat_map(|payload| payload.iter())
        .eq(expected.iter())
}

fn command_available(binary: &str) -> bool {
    Command::new(binary)
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// AES-GCM (AEAD) is a preview feature in libsrt 1.5.x, gated behind the
/// `ENABLE_AEAD_API_PREVIEW` build flag and requiring the OpenSSL-EVP or Botan
/// crypto backend (not GnuTLS). Most distro packages lack it.
fn libsrt_supports_gcm() -> bool {
    // AEAD requires both: (1) OpenSSL-EVP or Botan backend (not GnuTLS), AND
    // (2) ENABLE_AEAD_API_PREVIEW set at cmake time.  Check (2) by looking for
    // the "cryptomode" URL-parameter string in the binary — it's only compiled
    // in when the preview flag is on.
    let path = Command::new("which")
        .arg("srt-live-transmit")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned());
    let Some(slt) = path else { return false };
    let strings = Command::new("strings")
        .arg(&slt)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match strings {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.contains("cryptomode")
        }
        Err(_) => false,
    }
}

fn free_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("reserve loopback port")
        .local_addr()
        .expect("read reserved address")
        .port()
}

/// Start a black-box libsrt endpoint on a dynamically chosen UDP port.
///
/// Rust-owned endpoints keep their port-0 socket open.  A command-line libsrt
/// listener/source must bind the port itself, so its handoff has an
/// unavoidable tiny gap.  Retry only an immediate child startup failure,
/// which makes concurrent test cases independent without serializing them.
fn spawn_with_free_udp_port(label: &str, mut spawn: impl FnMut(u16) -> Child) -> (Child, u16) {
    let mut last_stderr = String::new();
    for _ in 0..3 {
        let port = free_port();
        let mut child = spawn(port);
        std::thread::sleep(Duration::from_millis(50));
        match child.try_wait().expect("poll libsrt startup") {
            None => return (child, port),
            Some(_) => {
                let output = child
                    .wait_with_output()
                    .expect("collect failed libsrt startup");
                last_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            }
        }
    }
    panic!("{label} exited during startup after three dynamic-port attempts: {last_stderr}");
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
    cipher_mode: CipherMode,
    stream_id: Option<&'a str>,
    input_bandwidth: Option<(u64, u8)>,
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

fn wait_for_child_with_timeout(mut child: Child, binary: &str, timeout: Duration) -> Output {
    let deadline = Instant::now() + timeout;
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
                "{binary} did not exit within {} seconds; stderr: {}",
                timeout.as_secs(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_child(child: Child, binary: &str) -> Output {
    wait_for_child_with_timeout(child, binary, Duration::from_secs(5))
}

/// Live listeners are intentionally long-running services. Tests that own one
/// stop it after their bounded transfer window rather than treating that normal
/// listener lifecycle as a timeout failure.
fn stop_live_listener(mut child: Child) -> Output {
    if child
        .try_wait()
        .expect("poll srt-live-transmit listener")
        .is_none()
    {
        child
            .kill()
            .expect("stop srt-live-transmit listener after test transfer");
    }
    child
        .wait_with_output()
        .expect("collect stopped srt-live-transmit listener")
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
    // Bind once to port 0 and keep the socket open.  Selecting a port first
    // then binding it was the direct EADDRINUSE race observed in CI.
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind listener socket");
    let port = socket.local_addr().expect("read listener address").port();
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
    caller_encryption: Option<(&str, KeyLength)>,
    listener_encryption: Option<(&str, KeyLength)>,
    drop_every: Option<u32>,
    output_options: Option<&str>,
) -> (driver::DriverResult, ExitStatus, String) {
    // Keep this listener's OS-assigned port reserved for the entire transfer.
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind listener socket");
    let port = socket.local_addr().expect("read listener address").port();
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
    let mut output_uri = match caller_encryption {
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
    if let Some(options) = output_options {
        let separator = if output_uri.contains('?') { '&' } else { '?' };
        output_uri.push(separator);
        output_uri.push_str(options);
    }
    let (child, source_port) =
        spawn_with_free_udp_port("srt-live-transmit caller", |source_port| {
            Command::new("srt-live-transmit")
                .args([
                    "-q",
                    if loss_recovery {
                        "-timeout:8"
                    } else {
                        "-timeout:3"
                    },
                ])
                .arg(format!("udp://127.0.0.1:{source_port}"))
                .arg(&output_uri)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("spawn srt-live-transmit caller: {error}"))
        });

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
        passphrase: listener_encryption.map(|(passphrase, _)| passphrase.to_string()),
        key_length: listener_encryption.map_or(KeyLength::Aes128, |(_, key_length)| key_length),
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

struct StreamIdPolicyResult {
    policy_calls: usize,
    connected: bool,
    received: Vec<u8>,
    output: Output,
}

/// Accept a real libsrt live caller only when its claimed StreamID matches the
/// listener policy. This drives the public shared-listener `PeerTable`, rather
/// than asserting propagation into the stock permissive sample listener.
fn receive_live_with_stream_id_policy(
    payload: &[u8],
    caller_stream_id: &str,
    allowed_stream_id: &str,
) -> StreamIdPolicyResult {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind policy listener socket");
    let port = socket
        .local_addr()
        .expect("read policy listener address")
        .port();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set policy listener read timeout");

    let (child, source_port) =
        spawn_with_free_udp_port("srt-live-transmit policy caller", |source_port| {
            Command::new("srt-live-transmit")
                .args(["-q", "-timeout:3"])
                .arg(format!("udp://127.0.0.1:{source_port}"))
                .arg(format!(
                    "srt://127.0.0.1:{port}?streamid={caller_stream_id}"
                ))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("spawn srt-live-transmit policy caller: {error}"))
        });
    let payload_len = payload.len();
    let payload = payload.to_vec();
    let source_sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        let source = UdpSocket::bind(("127.0.0.1", 0)).expect("bind UDP policy payload sender");
        for chunk in payload.chunks(1_000) {
            source
                .send_to(chunk, ("127.0.0.1", source_port))
                .expect("send payload into policy caller source");
        }
    });

    let start = Instant::now();
    let mut table = PeerTable::new();
    let options = AdmissionOptions::basic(0x2000_0001, 120, true);
    let telemetry = IngressTelemetry::new();
    let policy_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut connected = false;
    let mut received = Vec::new();
    let mut outbound = Vec::new();
    let mut events = Vec::new();
    let mut buf = [0_u8; 2048];

    while start.elapsed() < Duration::from_secs(10) {
        let now = Timestamp::from_micros(start.elapsed().as_micros() as u64);
        if let Ok((size, peer)) = socket.recv_from(&mut buf) {
            let policy_calls = Arc::clone(&policy_calls);
            table.admit_with_resolver(
                peer,
                &buf[..size],
                now,
                &options,
                0,
                1,
                &telemetry,
                |request| {
                    policy_calls.fetch_add(1, Ordering::Relaxed);
                    if request.claimed_identity.stream_id.as_deref() == Some(allowed_stream_id) {
                        AdmissionResolution::Accept
                    } else {
                        AdmissionResolution::Reject {
                            reason: RejectionReason::UNAUTHORIZED,
                        }
                    }
                },
            );
        }
        let now = Timestamp::from_micros(start.elapsed().as_micros() as u64);
        table.poll_outbound(now, &mut outbound);
        for (peer, packet) in outbound.drain(..) {
            socket
                .send_to(&packet, peer)
                .expect("send policy-listener output");
        }
        table.poll_events(&mut events);
        for event in events.drain(..) {
            match event.event {
                shiguredo_srt::ConnectionEvent::Connected => connected = true,
                shiguredo_srt::ConnectionEvent::DataReceived { payload, .. } => {
                    received.extend(payload);
                }
                _ => {}
            }
        }
        if connected && received.len() == payload_len {
            break;
        }
        if policy_calls.load(Ordering::Relaxed) != 0 && caller_stream_id != allowed_stream_id {
            // The rejection was queued and sent above. Let libsrt process it
            // before collecting the child result, without keeping CI idle.
            std::thread::sleep(Duration::from_millis(100));
            break;
        }
    }

    source_sender
        .join()
        .expect("UDP policy source sender panicked");
    let output = wait_for_child(child, "srt-live-transmit");
    StreamIdPolicyResult {
        policy_calls: policy_calls.load(Ordering::Relaxed),
        connected,
        received,
        output,
    }
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
    let payload = payload.to_vec();
    send_to_libsrt_listener_with_on_connect(caller, listener, deadline, move |conn, now| {
        for chunk in payload.chunks(1_000) {
            conn.send(chunk, now)
                .expect("send payload from Rust caller");
        }
    })
}

fn send_to_libsrt_listener_with_on_connect(
    caller: LiveOptions<'_>,
    listener: LiveOptions<'_>,
    deadline: Duration,
    mut on_connect: impl FnMut(&mut SrtConnection, Timestamp),
) -> (driver::DriverResult, Output) {
    let (child, port) = spawn_with_free_udp_port("srt-live-transmit listener", |port| {
        let mut input_uri = format!("srt://:{port}?mode=listener");
        if let Some((passphrase, key_length)) = listener.encryption {
            input_uri.push_str(&format!(
                "&passphrase={passphrase}&pbkeylen={}",
                key_length.len()
            ));
        }
        if listener.cipher_mode == CipherMode::Gcm {
            input_uri.push_str("&cryptomode=aes-gcm");
        }
        if let Some(stream_id) = listener.stream_id {
            input_uri.push_str(&format!("&streamid={stream_id}"));
        }
        Command::new("srt-live-transmit")
            .args(["-q", "-timeout:3"])
            .arg(input_uri)
            .arg("file://con")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn srt-live-transmit listener: {error}"))
    });

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
        cipher_mode: caller.cipher_mode,
        stream_id: caller.stream_id.map(str::to_owned),
        input_bandwidth_bytes_per_sec: caller.input_bandwidth.map(|(input, _)| input),
        overhead_bandwidth_percent: caller.input_bandwidth.map_or(25, |(_, overhead)| overhead),
        ..Default::default()
    });
    conn.connect(Timestamp::from_micros(0))
        .expect("start Rust caller handshake");

    let result = driver::run(
        &mut conn,
        &socket,
        start,
        deadline,
        Duration::from_secs(2),
        |conn, _, now| on_connect(conn, now),
    );
    let output = wait_for_child(child, "srt-live-transmit");
    (result, output)
}

/// Mirror the caller-to-listener live path through the same deterministic
/// DATA-only loss proxy used for libsrt-to-Rust recovery. This keeps control
/// traffic intact while requiring real ARQ in the Rust-to-libsrt direction.
fn send_to_libsrt_listener_through_lossy_proxy(payload: &[u8]) -> (driver::DriverResult, Output) {
    let (child, listener_port) =
        spawn_with_free_udp_port("lossy srt-live-transmit listener", |port| {
            Command::new("srt-live-transmit")
                .args(["-q", "-timeout:3"])
                .arg(format!(
                    "srt://:{port}?mode=listener&latency=500&peerlatency=500"
                ))
                .arg("file://con")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("spawn lossy srt-live-transmit listener: {error}"))
        });
    std::thread::sleep(Duration::from_millis(100));

    let proxy = UdpSocket::bind(("127.0.0.1", 0)).expect("bind reverse lossy UDP proxy");
    let proxy_addr = proxy.local_addr().expect("read reverse proxy address");
    let stop = Arc::new(AtomicBool::new(false));
    let proxy_thread = lossy_udp_proxy_thread(
        proxy,
        SocketAddr::from(([127, 0, 0, 1], listener_port)),
        20,
        Arc::clone(&stop),
    );

    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind Rust lossy caller socket");
    socket
        .connect(proxy_addr)
        .expect("connect Rust caller to proxy");
    let start = Instant::now();
    let mut conn = SrtConnection::new_caller(ConnectionOptions {
        socket_id: 0x2000_0003,
        congestion_control: "live".to_string(),
        tsbpd_delay: 500,
        ..Default::default()
    });
    conn.connect(Timestamp::from_micros(0))
        .expect("start Rust caller handshake through proxy");
    let payload = payload.to_vec();
    let result = driver::run(
        &mut conn,
        &socket,
        start,
        Duration::from_secs(15),
        Duration::from_secs(8),
        move |conn, _, now| {
            for chunk in payload.chunks(1_000) {
                conn.send(chunk, now)
                    .expect("send Rust payload through lossy proxy");
            }
        },
    );
    drop(socket);
    stop.store(true, Ordering::Relaxed);
    proxy_thread
        .join()
        .expect("reverse lossy UDP proxy panicked");
    let output = stop_live_listener(child);
    (result, output)
}

/// Real libsrt (`srt-file-transmit`, as caller) sends a file; this crate's
/// pure-Rust `SrtConnection` (as listener, driven via `srt_bench::driver`)
/// receives it. Proves a real libsrt peer's wire output is byte-exact
/// decodable by this implementation -- not just internally self-consistent.
#[test]
fn libsrt_file_transmit_caller_sends_file_to_rust_listener() {
    let _guard = interop_test_lock();
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
        received_payloads_match(&result.received_payloads, &payload),
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
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_live_transmit_caller_sends_udp_to_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();

    let (result, status, stderr) = receive_live_from_udp_source(&payload, None, None, None, None);

    assert!(
        result.connected,
        "Rust listener never reached Connected: {:?}",
        result.events
    );
    assert!(
        status.success(),
        "srt-live-transmit caller exited with failure, stderr: {stderr}"
    );
    assert!(
        received_payloads_match(&result.received_payloads, &payload),
        "payload received from real libsrt does not match the file sent byte-for-byte; driver events: {:?}",
        result.events
    );
}

/// A real libsrt caller using INPUTBW/OHEADBW reaches the Rust listener. The
/// sender-side calculation is asserted exactly in `srt_sender`; this confirms
/// the corresponding live URI mode remains wire-compatible in the reverse
/// direction.
#[test]
fn libsrt_input_bandwidth_caller_sends_stream_to_rust_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_input_bandwidth_caller_sends_stream_to_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();
    let (result, status, stderr) = receive_live_from_udp_source(
        &payload,
        None,
        None,
        None,
        Some("maxbw=0&inputbw=1000000&oheadbw=25"),
    );
    assert!(
        result.connected,
        "Rust listener never reached Connected for libsrt INPUTBW: {:?}",
        result.events
    );
    assert!(status.success(), "libsrt INPUTBW caller failed: {stderr}");
    assert!(
        received_payloads_match(&result.received_payloads, &payload),
        "libsrt INPUTBW payload mismatch"
    );
}

/// Configure a tiny libsrt refresh cadence to prove its KMREQ and subsequent
/// encrypted data are accepted by the Rust listener without a 2²⁵-packet CI
/// transfer.
#[test]
fn libsrt_live_caller_refreshes_key_with_rust_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_live_caller_refreshes_key_with_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload_bytes(4_000);
    let (result, status, stderr) = receive_live_from_udp_source(
        &payload,
        Some(("interop-passphrase", KeyLength::Aes128)),
        Some(("interop-passphrase", KeyLength::Aes128)),
        None,
        Some("kmrefreshrate=8&kmpreannounce=3"),
    );
    assert!(
        result.connected,
        "Rust listener never reached Connected through libsrt key refresh: {:?}",
        result.events
    );
    assert!(
        status.success(),
        "libsrt key-refresh caller failed: {stderr}"
    );
    assert!(
        received_payloads_match(&result.received_payloads, &payload),
        "Rust listener did not decrypt through the libsrt key refresh"
    );
}

/// Exercises real SRT ARQ end-to-end, rather than merely unit-testing NAK
/// handling: a deterministic proxy drops every twentieth DATA packet on the
/// libsrt-to-Rust path while forwarding all control traffic unchanged.
#[test]
fn libsrt_caller_recovers_payload_under_5pct_loss() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_caller_recovers_payload_under_5pct_loss: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload_bytes(120_000);
    let (result, status, stderr) =
        receive_live_from_udp_source(&payload, None, None, Some(20), None);
    assert!(
        result.connected,
        "Rust listener never reached Connected through the lossy proxy: {:?}",
        result.events
    );
    assert!(
        status.success(),
        "srt-live-transmit caller exited with failure through the lossy proxy, stderr: {stderr}"
    );
    assert!(
        received_payloads_match(&result.received_payloads, &payload),
        "libsrt payload did not recover byte-for-byte after deterministic 5% loss; driver events: {:?}",
        result.events
    );
}

#[test]
fn libsrt_live_caller_aes128_to_rust_listener() {
    let _guard = interop_test_lock();
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
        Some(("interop-passphrase", KeyLength::Aes128)),
        None,
        None,
    );
    assert!(
        result.connected,
        "Rust listener never connected: {:?}",
        result.events
    );
    assert!(status.success(), "libsrt caller failed: {stderr}");
    assert!(
        received_payloads_match(&result.received_payloads, &payload),
        "AES-128 payload mismatch: {:?}",
        result.events
    );
}

#[test]
fn libsrt_live_caller_aes256_to_rust_listener() {
    let _guard = interop_test_lock();
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
        Some(("interop-passphrase", KeyLength::Aes256)),
        None,
        None,
    );
    assert!(
        result.connected,
        "Rust listener never connected: {:?}",
        result.events
    );
    assert!(status.success(), "libsrt caller failed: {stderr}");
    assert!(
        received_payloads_match(&result.received_payloads, &payload),
        "AES-256 payload mismatch: {:?}",
        result.events
    );
}

/// The inverse wrong-passphrase path: a real libsrt caller must receive the
/// Rust listener's BADSECRET response and no application data may be admitted.
#[test]
fn libsrt_live_caller_wrong_passphrase_is_rejected_by_rust_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_live_caller_wrong_passphrase_is_rejected_by_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let (result, _status, stderr) = receive_live_from_udp_source(
        b"must never be delivered",
        Some(("wrong-interop-passphrase", KeyLength::Aes128)),
        Some(("interop-passphrase", KeyLength::Aes128)),
        None,
        None,
    );

    assert!(
        !result.connected,
        "libsrt caller unexpectedly connected with a wrong passphrase: {:?}; libsrt stderr: {stderr}",
        result.events
    );
    assert!(
        result.received_payloads.is_empty(),
        "Rust listener admitted data after rejecting the passphrase"
    );
    assert!(
        result
            .events
            .iter()
            .any(|event| event.contains("incorrect passphrase")),
        "Rust listener did not report the passphrase rejection: {:?}; libsrt stderr: {stderr}",
        result.events
    );
    assert!(
        stderr.contains("BADSECRET") || stderr.contains("Incorrect passphrase"),
        "libsrt did not decode the Rust KMRSP as BADSECRET: {stderr}"
    );
}

/// A Rust live caller sends a byte-exact stream to a real libsrt live
/// listener. This covers the inverse handshake and DATA direction from the
/// UDP-source test above.
#[test]
fn rust_live_caller_sends_stream_to_libsrt_listener() {
    let _guard = interop_test_lock();
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

/// The inverse of `libsrt_caller_recovers_payload_under_5pct_loss`: Rust
/// drives recovery while a real libsrt live listener receives the recovered
/// byte stream through the same deterministic 5% DATA loss pattern.
#[test]
fn rust_caller_recovers_payload_under_5pct_loss() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_caller_recovers_payload_under_5pct_loss: srt-live-transmit not on PATH"
        );
        return;
    }

    // Keep the burst below the loopback UDP receive queue. This test isolates
    // deterministic 5% SRT DATA loss; overflowing the host UDP queue would
    // add unrelated, scheduler-dependent loss before the proxy sees a packet.
    let mut payload = test_payload_bytes(60_000);
    // The final deliberately dropped DATA packet needs a later sequence
    // number before a receiver can report it in a NAK.
    payload.extend_from_slice(b"recovery-tail");
    let (result, output) = send_to_libsrt_listener_through_lossy_proxy(&payload);
    assert!(
        result.connected,
        "Rust caller never reached Connected through the lossy proxy: {:?}; libsrt stderr: {}",
        result.events,
        String::from_utf8_lossy(&output.stderr)
    );
    // The helper terminates the deliberately persistent listener after its
    // bounded recovery window; byte-exact stdout is the live-delivery result.
    assert!(
        output.stdout == payload,
        "libsrt recovered {} of {} Rust bytes after deterministic 5% loss; driver events: {:?}",
        output.stdout.len(),
        payload.len(),
        result.events,
    );
}

/// Source-relative pacing remains a local send-side concern, but its caller
/// path still interoperates byte-for-byte with the real live listener. The
/// precise 25% calculation is covered deterministically in `srt_sender`.
#[test]
fn rust_input_bandwidth_caller_sends_stream_to_libsrt_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_input_bandwidth_caller_sends_stream_to_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();
    let caller = LiveOptions {
        input_bandwidth: Some((1_000_000, 25)),
        ..Default::default()
    };
    let (result, output) = send_to_libsrt_listener(
        &payload,
        caller,
        LiveOptions::default(),
        Duration::from_secs(10),
    );

    assert!(
        result.connected,
        "input-bandwidth Rust caller never reached Connected: {:?}; libsrt stderr: {}",
        result.events,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "srt-live-transmit listener exited with failure, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, payload, "input-bandwidth payload mismatch");
}

#[test]
fn rust_live_caller_aes128_to_libsrt_listener() {
    let _guard = interop_test_lock();
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

/// Verify the inverse AES-256 direction as well: the Rust caller derives and
/// encrypts with a 256-bit SEK that a real libsrt listener must accept.
#[test]
fn rust_live_caller_aes256_to_libsrt_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_live_caller_aes256_to_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();
    let encrypted = LiveOptions {
        encryption: Some(("interop-passphrase", KeyLength::Aes256)),
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
        "AES-256 payload mismatch: {:?}",
        result.events
    );
}

/// Exercise a real KMREQ and key switchover against libsrt without making CI
/// transmit the normal 2²⁵-packet refresh interval. The test-only counter
/// seed preserves the production cadence; the actual preannounce, KMREQ,
/// switch, encryption, and libsrt decryption are all on the wire.
#[test]
fn rust_live_caller_refreshes_key_with_libsrt_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_live_caller_refreshes_key_with_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    const PACKETS_TO_SWITCH: usize = 4_000;
    let payload = test_payload_bytes(PACKETS_TO_SWITCH);
    let encrypted = LiveOptions {
        encryption: Some(("interop-passphrase", KeyLength::Aes128)),
        ..Default::default()
    };
    let mut refresh_requested = false;
    let (result, output) = send_to_libsrt_listener_with_on_connect(
        encrypted,
        encrypted,
        Duration::from_secs(20),
        |conn, now| {
            conn.seed_encrypted_packet_count_for_test(
                shiguredo_srt::CryptoContext::KM_REFRESH_PERIOD - PACKETS_TO_SWITCH as u64,
            )
            .expect("seed encrypted packet count for accelerated key refresh");
            for chunk in payload.chunks(1) {
                conn.send(chunk, now).expect("send encrypted test payload");
                while let Some(event) = conn.poll_event() {
                    if matches!(
                        event,
                        shiguredo_srt::ConnectionEvent::KeyRefreshNeeded { .. }
                    ) {
                        refresh_requested = true;
                        conn.provide_new_sek(&[0x5a; 16], now)
                            .expect("preannounce replacement SEK");
                    }
                }
            }
        },
    );

    assert!(refresh_requested, "Rust caller never requested key refresh");
    assert!(
        result.connected,
        "Rust caller never connected: {:?}",
        result.events
    );
    assert!(
        result
            .events
            .iter()
            .all(|event| !event.starts_with("Error:") && !event.starts_with("Disconnected:")),
        "Rust caller reported a protocol failure: {:?}",
        result.events
    );
    assert!(
        output.status.success(),
        "libsrt listener failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout, payload,
        "libsrt did not decrypt through key refresh"
    );
}

/// A listener with a different passphrase must reject a Rust caller before
/// either side accepts application data. The successful AES-128 test above is
/// the matching-passphrase control for this exact live listener path.
#[test]
fn rust_live_caller_wrong_passphrase_is_rejected_by_libsrt_listener() {
    let _guard = interop_test_lock();
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
    let _guard = interop_test_lock();
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

/// A real libsrt caller is admitted only after the Rust shared listener's
/// StreamID policy accepts its CONCLUSION; a different StreamID gets the
/// standard SRT `UNAUTHORIZED` rejection before it can connect or deliver.
#[test]
fn libsrt_caller_obeys_rust_stream_id_policy() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_caller_obeys_rust_stream_id_policy: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload();
    let accepted =
        receive_live_with_stream_id_policy(&payload, "publish/allowed", "publish/allowed");
    assert!(
        accepted.policy_calls > 0,
        "listener never resolved StreamID policy"
    );
    assert!(accepted.connected, "allowed caller was not admitted");
    assert_eq!(
        accepted.received, payload,
        "allowed caller payload mismatch"
    );
    assert!(
        accepted.output.status.success(),
        "allowed libsrt caller failed: {}",
        String::from_utf8_lossy(&accepted.output.stderr)
    );

    let rejected = receive_live_with_stream_id_policy(
        b"must never be delivered",
        "publish/denied",
        "publish/allowed",
    );
    assert!(
        rejected.policy_calls > 0,
        "listener never evaluated denied StreamID"
    );
    assert!(!rejected.connected, "denied caller reached Connected state");
    assert!(
        rejected.received.is_empty(),
        "denied caller delivered application data"
    );
    let stderr = String::from_utf8_lossy(&rejected.output.stderr);
    assert!(
        stderr.contains("REJECT") || stderr.contains("rejection"),
        "denied libsrt caller did not report the listener rejection (status {:?}): {stderr}",
        rejected.output.status
    );
}

fn compile_libsrt_fixture(name: &str) -> Option<std::path::PathBuf> {
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{name}.c"));
    let output = scratch_dir("libsrt-bonding").join(name);
    let mut diagnostics = Vec::new();
    for library in ["srt-gnutls", "srt-openssl", "srt"] {
        let result = Command::new("cc")
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&output)
            .arg(format!("-l{library}"))
            .output();
        match result {
            Ok(result) if result.status.success() => return Some(output),
            Ok(result) => diagnostics.push(format!(
                "-l{library}: {}",
                String::from_utf8_lossy(&result.stderr).trim()
            )),
            Err(error) => diagnostics.push(format!("-l{library}: {error}")),
        }
    }
    let message = format!(
        "a C compiler and bonding-enabled libsrt development library are required ({})",
        diagnostics.join("; ")
    );
    if std::env::var_os("SRT_REQUIRE_BONDING").is_some() {
        panic!("bonding is required but {message}");
    }
    eprintln!("skipping bonding interop: {message}");
    None
}

fn compile_libsrt_bonded_caller() -> Option<std::path::PathBuf> {
    compile_libsrt_fixture("libsrt_bonded_caller")
}

fn compile_libsrt_bonded_listener() -> Option<std::path::PathBuf> {
    compile_libsrt_fixture("libsrt_bonded_listener")
}

fn spawn_libsrt_bonded_listener(listener: &std::path::Path) -> Option<(Child, u16)> {
    let mut last_stderr = String::new();
    for _ in 0..3 {
        let port = free_port();
        let mut child = Command::new(listener)
            .arg(port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn libsrt bonded listener: {error}"));
        std::thread::sleep(Duration::from_millis(50));
        match child
            .try_wait()
            .expect("poll libsrt bonded listener startup")
        {
            None => return Some((child, port)),
            Some(status) => {
                let output = child
                    .wait_with_output()
                    .expect("collect failed libsrt bonded listener startup");
                if status.code() == Some(77) {
                    if std::env::var_os("SRT_REQUIRE_BONDING").is_some() {
                        panic!(
                            "bonding is required but unavailable: {}",
                            String::from_utf8_lossy(&output.stderr).trim()
                        );
                    }
                    eprintln!(
                        "skipping bonding interop: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                    return None;
                }
                last_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            }
        }
    }
    panic!(
        "libsrt bonded listener exited during startup after three dynamic-port attempts: {last_stderr}"
    );
}

/// A real libsrt broadcast group opens two physical legs to the public Rust
/// listener and produces exactly one logical payload after deduplication.
#[test]
fn libsrt_broadcast_group_interoperates_with_rust_listener() {
    let _guard = interop_test_lock();
    let Some(caller) = compile_libsrt_bonded_caller() else {
        return;
    };

    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind bonded Rust listener");
    let port = socket
        .local_addr()
        .expect("read bonded listener address")
        .port();
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .expect("set bonded listener timeout");
    let mut child = Command::new(caller)
        .args(["127.0.0.1", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn libsrt bonded caller");

    let start = Instant::now();
    let mut table = PeerTable::new();
    let mut options = AdmissionOptions::basic(0x2000_0001, 120, true);
    options.bonded_inputs = srt_transport::BondedInputPolicy::Accept;
    let telemetry = IngressTelemetry::new();
    let mut outbound = Vec::new();
    let mut events = Vec::new();
    let mut received = Vec::new();
    let mut buffer = [0_u8; 2048];
    let mut max_legs = 0;

    while start.elapsed() < Duration::from_secs(15) {
        if child
            .try_wait()
            .expect("poll libsrt bonded caller")
            .is_some()
        {
            break;
        }
        let now = Timestamp::from_micros(start.elapsed().as_micros() as u64);
        if let Ok((size, peer)) = socket.recv_from(&mut buffer) {
            table.admit_with_connection_hook(
                peer,
                &buffer[..size],
                now,
                &options,
                0,
                1,
                &telemetry,
                |request, connection| {
                    // Libsrt requires the accepting listener to return the
                    // caller's GROUP metadata in CONCLUSION. A real service
                    // would authorize this value before echoing it.
                    if let Some(group) = request.handshake.get_group_extension() {
                        connection.set_group_extension(group);
                    }
                    AdmissionResolution::Accept
                },
            );
        }
        let now = Timestamp::from_micros(start.elapsed().as_micros() as u64);
        table.poll_outbound(now, &mut outbound);
        for (peer, packet) in outbound.drain(..) {
            socket
                .send_to(&packet, peer)
                .expect("send bonded listener output");
        }
        table.poll_events(&mut events);
        for event in events.drain(..) {
            if let shiguredo_srt::ConnectionEvent::DataReceived { payload, .. } = event.event {
                received.extend(payload);
            }
        }
        max_legs = max_legs.max(
            table
                .bonded_stats()
                .first()
                .map_or(0, |stats| stats.connection.legs.len()),
        );
        if received == b"libsrt-bonded-group-payload" && max_legs == 2 {
            break;
        }
    }

    let output = wait_for_child(child, "libsrt bonded caller");
    if output.status.code() == Some(77) && std::env::var_os("SRT_REQUIRE_BONDING").is_none() {
        eprintln!(
            "skipping bonding interop: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return;
    }
    assert!(
        output.status.success(),
        "libsrt bonded caller failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(max_legs, 2, "libsrt group did not establish two Rust legs");
    assert_eq!(
        received, b"libsrt-bonded-group-payload",
        "Rust listener did not deduplicate the libsrt group payload"
    );
}

/// Rust's public Broadcast group caller opens two legs to a real libsrt
/// listener. The fixture is necessary because srt-live-transmit closes its
/// listener after accepting one client and therefore cannot host a group.
#[test]
fn rust_broadcast_group_interoperates_with_libsrt_listener() {
    let _guard = interop_test_lock();
    let Some(listener) = compile_libsrt_bonded_listener() else {
        return;
    };
    let Some((child, port)) = spawn_libsrt_bonded_listener(&listener) else {
        return;
    };
    std::thread::sleep(Duration::from_millis(100));

    let remote = SocketAddr::from(([127, 0, 0, 1], port));
    let caller = CallerConfig::builder(remote)
        .build()
        .expect("build bonded caller config");
    let mut group = GroupConn::caller(
        GroupConfig::new(0x1234, shiguredo_srt::GroupType::Broadcast),
        [
            GroupCallerLeg::new(1, 10, caller.clone()),
            GroupCallerLeg::new(2, 20, caller),
        ],
        RuntimeFlavor::Mio,
        Timestamp::from_micros(0),
    )
    .expect("build Rust broadcast group");

    let payload = b"rust-bonded-group-payload";
    let start = Instant::now();
    let mut sent = false;
    let mut sent_on_two_legs = false;
    let mut max_active_legs = 0;
    while start.elapsed() < Duration::from_secs(15) {
        let now = Timestamp::from_micros(start.elapsed().as_micros() as u64);
        group
            .drive(now, OutputDrainBudget::default())
            .expect("drive Rust broadcast group");
        let active_legs = group.stats().aggregate.active_legs;
        max_active_legs = max_active_legs.max(active_legs);
        // The native mirror group attaches each leg independently. Send only
        // once both sides have completed the data-plane handshake, then drain
        // that exact two-leg payload before the fixture exits its UDP port.
        if active_legs == 2 {
            let selected = group
                .send(payload, now)
                .expect("send Rust broadcast payload");
            sent_on_two_legs |= selected == 2;
            sent = true;
            group
                .drive(now, OutputDrainBudget::default())
                .expect("drain Rust broadcast payload");
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let output =
        wait_for_child_with_timeout(child, "libsrt bonded listener", Duration::from_secs(15));
    if output.status.code() == Some(77) && std::env::var_os("SRT_REQUIRE_BONDING").is_none() {
        eprintln!(
            "skipping bonding interop: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return;
    }
    let final_stats = group.stats();
    assert!(
        output.status.success(),
        "libsrt bonded listener failed: {}; sent={sent}; max_active_legs={max_active_legs}; \
         sent_on_two_legs={sent_on_two_legs}; final Rust group stats: {final_stats:#?}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(sent, "Rust broadcast group never activated a libsrt leg");
    assert_eq!(
        max_active_legs, 2,
        "Rust broadcast group did not activate both libsrt legs"
    );
    assert!(
        sent_on_two_legs,
        "Rust broadcast group never selected both active legs"
    );
    assert_eq!(
        output.stdout, payload,
        "libsrt did not receive Rust broadcast payload"
    );
}

/// AES-GCM interop: Rust caller encrypts with GCM, libsrt listener decrypts.
/// Skips when libsrt lacks AEAD support (GnuTLS backend or missing preview flag).
#[test]
fn rust_gcm_caller_sends_to_libsrt_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_gcm_caller_sends_to_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }
    if !libsrt_supports_gcm() {
        eprintln!(
            "skipping rust_gcm_caller_sends_to_libsrt_listener: libsrt not built with ENABLE_AEAD_API_PREVIEW"
        );
        return;
    }

    let payload = test_payload();
    let gcm_caller = LiveOptions {
        encryption: Some(("interop-passphrase", KeyLength::Aes128)),
        cipher_mode: CipherMode::Gcm,
        ..Default::default()
    };
    let gcm_listener = LiveOptions {
        encryption: Some(("interop-passphrase", KeyLength::Aes128)),
        ..Default::default()
    };
    let (result, output) =
        send_to_libsrt_listener(&payload, gcm_caller, gcm_listener, Duration::from_secs(10));
    assert!(
        result.connected,
        "Rust GCM caller never reached Connected: {:?}",
        result.events
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "libsrt GCM listener failed: {stderr}"
    );
    assert_eq!(
        output.stdout, payload,
        "libsrt did not decrypt Rust GCM caller's payload"
    );
}

/// AES-GCM interop (reverse): libsrt caller encrypts with GCM, Rust listener decrypts.
/// Skips when libsrt lacks AEAD support (GnuTLS backend or missing preview flag).
#[test]
fn libsrt_gcm_caller_sends_to_rust_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_gcm_caller_sends_to_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }
    if !libsrt_supports_gcm() {
        eprintln!(
            "skipping libsrt_gcm_caller_sends_to_rust_listener: libsrt not built with ENABLE_AEAD_API_PREVIEW"
        );
        return;
    }

    let payload = test_payload();
    let (result, status, stderr) = receive_live_from_udp_source(
        &payload,
        Some(("interop-passphrase", KeyLength::Aes128)),
        Some(("interop-passphrase", KeyLength::Aes128)),
        None,
        Some("cryptomode=aes-gcm"),
    );
    assert!(
        result.connected,
        "Rust listener never connected: {:?}",
        result.events
    );
    assert!(status.success(), "libsrt GCM caller failed: {stderr}");
    assert!(
        received_payloads_match(&result.received_payloads, &payload),
        "Rust listener did not decrypt libsrt GCM caller's payload"
    );
}

/// Rust caller sends multiple messages via `send_message()` that collectively
/// total 8 KB. Each message fits within `srt-live-transmit`'s 1456-byte
/// receive buffer (`SRT_LIVE_MAX_PLSIZE`), so this tests the `send_message()`
/// API path end-to-end without hitting the tool's per-read ceiling.
#[test]
fn rust_caller_sends_messages_via_send_message_to_libsrt_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping rust_caller_sends_messages_via_send_message_to_libsrt_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload_bytes(8_192);
    let payload_clone = payload.clone();
    let (result, output) = send_to_libsrt_listener_with_on_connect(
        LiveOptions::default(),
        LiveOptions::default(),
        Duration::from_secs(10),
        move |conn, now| {
            for chunk in payload_clone.chunks(1_000) {
                conn.send_message(chunk, now)
                    .expect("send message from Rust caller");
            }
        },
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
        "libsrt did not receive the Rust send_message() data; driver events: {:?}",
        result.events
    );
}

/// A real libsrt caller sends a 1316-byte (`SRT_LIVE_DEF_PLSIZE`) payload —
/// the largest message `srt-live-transmit` accepts from its UDP source —
/// and the Rust listener receives it via the `MessageAssembler` passthrough
/// path. Multi-fragment reassembly cannot be exercised through
/// `srt-live-transmit` because it caps both its UDP `recvfrom` buffer and
/// its `srt_recvmsg2` buffer at `SRT_LIVE_MAX_PLSIZE` (1456 bytes);
/// multi-fragment coverage lives in `test_srt_connection.rs` and
/// `pbt/tests/prop_message.rs`.
#[test]
fn libsrt_live_transmit_max_payload_received_by_rust_listener() {
    let _guard = interop_test_lock();
    if !command_available("srt-live-transmit") {
        eprintln!(
            "skipping libsrt_live_transmit_max_payload_received_by_rust_listener: srt-live-transmit not on PATH"
        );
        return;
    }

    let payload = test_payload_bytes(1_316);

    let (result, status, stderr) = receive_live_from_udp_source(&payload, None, None, None, None);
    assert!(
        result.connected,
        "Rust listener never reached Connected: {:?}",
        result.events
    );
    assert!(
        status.success(),
        "srt-live-transmit caller exited with failure, stderr: {stderr}"
    );
    assert!(
        received_payloads_match(&result.received_payloads, &payload),
        "Rust listener did not receive the max-size libsrt message; driver events: {:?}",
        result.events
    );
}
