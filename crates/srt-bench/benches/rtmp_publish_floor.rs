//! RTMP-over-TCP reference path, written entirely in this crate's runtime.
//!
//! The comparison this exists for: our SRT qualification is a Rust/Compio
//! sender against a Rust/Compio receiver over UDP, one datagram per payload.
//! RTMP is the incumbent protocol in this space. A number taken from
//! `ffmpeg -> mediamtx` would confound language (C/Go), runtime (epoll/Go
//! scheduler) and muxer with the transport, so both ends here are Rust on the
//! same Compio ring, in two processes, exactly like the SRT pair:
//!
//! * `sink` -- a Compio TCP listener that performs the RTMP server handshake,
//!   parses chunk headers and discards payloads, counting bytes and messages.
//!   It is a sink, not a relay: it does not validate AMF or forward streams,
//!   matching what our SRT receiver does with payloads.
//! * `pub`  -- a Compio RTMP publisher: handshake, `connect`, `createStream`,
//!   `publish`, then a fixed-rate stream of video messages.
//! * no role -- the driver: spawns the sink as a child process, publishes, and
//!   prints both sides' accounting.
//!
//! `--mode tcp` runs the identical socket path with the identical write sizes
//! and no RTMP framing, so the framing cost is the difference between the two
//! modes.
//!
//! ```text
//! cargo bench -p srt-bench --bench rtmp_publish_floor -- --mbit 6 --seconds 5
//! ```

use std::process::{Command, Stdio};
use std::time::Instant;

use compio::io::{AsyncRead, AsyncWriteExt};
use srt_bench::cpu_stats::process_stats;

/// AMF0 type markers.
const AMF_NUMBER: u8 = 0x00;
const AMF_STRING: u8 = 0x02;
const AMF_OBJECT: u8 = 0x03;
const AMF_NULL: u8 = 0x05;
const AMF_OBJECT_END: u8 = 0x09;

const MSG_SET_CHUNK_SIZE: u8 = 1;
const MSG_VIDEO: u8 = 9;
const MSG_AMF0_COMMAND: u8 = 20;

fn amf_string(out: &mut Vec<u8>, s: &str) {
    out.push(AMF_STRING);
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn amf_number(out: &mut Vec<u8>, n: f64) {
    out.push(AMF_NUMBER);
    out.extend_from_slice(&n.to_be_bytes());
}

fn amf_null(out: &mut Vec<u8>) {
    out.push(AMF_NULL);
}

fn amf_object(out: &mut Vec<u8>, pairs: &[(&str, &str)]) {
    out.push(AMF_OBJECT);
    for (key, value) in pairs {
        out.extend_from_slice(&(key.len() as u16).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        amf_string(out, value);
    }
    out.extend_from_slice(&[0, 0, AMF_OBJECT_END]);
}

/// The `_result` / `onStatus` reply a server sends for command number
/// `index` (0 = connect, 1 = createStream, 2 = publish).
fn server_reply(index: usize, stream: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    let (label, transaction) = match index {
        0 => ("_result", 1.0),
        1 => ("_result", 2.0),
        _ => ("onStatus", 3.0),
    };
    amf_string(&mut payload, label);
    amf_number(&mut payload, transaction);
    match index {
        0 => {
            amf_object(
                &mut payload,
                &[("fmsVer", "FMS/3,5,7,7009"), ("capabilities", "31")],
            );
            amf_string(&mut payload, "level");
            amf_string(&mut payload, "status");
            amf_string(&mut payload, "code");
            amf_string(&mut payload, "NetConnection.Connect.Success");
        }
        1 => amf_number(&mut payload, 1.0),
        _ => {
            amf_string(&mut payload, "level");
            amf_string(&mut payload, "status");
            amf_string(&mut payload, "code");
            amf_string(&mut payload, "NetStream.Publish.Start");
            amf_string(&mut payload, "description");
            amf_string(&mut payload, stream);
        }
    }
    let mut message = Vec::new();
    chunk(
        &mut message,
        3,
        MSG_AMF0_COMMAND,
        if index == 2 { 1 } else { 0 },
        &payload,
    );
    message
}

/// Offset of the 3-byte message length inside a type-0 chunk header.
const HEADER: usize = 12;

/// Append one RTMP message as a single fmt-0 chunk: 12-byte header plus
/// payload, so a publisher writes header and body in one syscall.
///
/// Layout per the RTMP specification: basic header (fmt 0 + chunk stream id),
/// 3-byte timestamp, 3-byte message length, 1-byte message type, then the
/// message stream id -- the one little-endian field in RTMP.
fn chunk(buf: &mut Vec<u8>, csid: u8, kind: u8, stream_id: u32, payload: &[u8]) {
    let length = payload.len() as u32;
    buf.push(csid & 0x3F);
    buf.extend_from_slice(&[0, 0, 0]);
    buf.extend_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
    buf.push(kind);
    buf.extend_from_slice(&stream_id.to_le_bytes());
    buf.extend_from_slice(payload);
}

fn parse_arg<T: std::str::FromStr>(args: &[String], flag: &str, default: T) -> T {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn string_arg(args: &[String], flag: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

/// Read exactly `n` bytes, looping because a stream read may return short.
async fn read_exact_n(socket: &mut compio::net::TcpStream, n: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; n];
    let mut filled = 0usize;
    while filled < n {
        let out = socket.read(buffer[filled..].to_vec()).await;
        let (result, returned) = (out.0, out.1);
        match result {
            Ok(count) if count > 0 => {
                buffer[filled..filled + count].copy_from_slice(&returned[..count]);
                filled += count;
            }
            _ => return None,
        }
    }
    Some(buffer)
}

/// Drain whatever the peer has already sent, without waiting for more.
async fn read_some(socket: &mut compio::net::TcpStream, n: usize) {
    let out = socket.read(vec![0u8; n]).await;
    let _ = out.0;
}

fn cpu_ms() -> f64 {
    let s = process_stats();
    s.cpu_user_ms + s.cpu_sys_ms
}

struct Settings {
    mode: String,
    mbit: f64,
    seconds: u64,
    /// Pace to `mbit` (a real media publisher does) or run transport-bound.
    ///
    /// Paced runs measure the *timer*: compio's per-chunk sleep costs ~290 us
    /// of CPU per write here, which swamps the transport. Unpaced runs are
    /// transport-bound after the first few milliseconds of socket buffering,
    /// which is the comparison this bench exists for.
    pace: bool,
    chunk: usize,
    port: u16,
    app: String,
    stream: String,
}

impl Settings {
    fn from_args(args: &[String]) -> Self {
        Self {
            mode: string_arg(args, "--mode", "rtmp"),
            mbit: parse_arg(args, "--mbit", 6.0),
            seconds: parse_arg(args, "--seconds", 5),
            pace: parse_arg(args, "--pace", false),
            chunk: parse_arg(args, "--chunk", 4096),
            port: parse_arg(args, "--port", 19_350),
            app: string_arg(args, "--app", "live"),
            stream: string_arg(args, "--stream", "test"),
        }
    }

    /// Byte budget: the paced target, or a ceiling high enough that an
    /// unpaced run ends on the clock rather than the byte count.
    fn total_bytes(&self) -> usize {
        if self.pace {
            (self.mbit * 1e6 / 8.0 * self.seconds as f64) as usize
        } else {
            // 1 GiB ceiling; the deadline below stops the loop first.
            usize::MAX / 2
        }
    }
}

// --------------------------------------------------------------------------
// sink: RTMP server side, Compio TCP
// --------------------------------------------------------------------------

fn run_sink(settings: &Settings) {
    let stream_name = settings.stream.clone();
    let runtime = compio::runtime::Runtime::new().expect("compio runtime");
    let report = runtime.block_on(async {
        let listener = compio::net::TcpListener::bind(("127.0.0.1", settings.port))
            .await
            .expect("bind sink");
        println!("RTMP_SINK_READY port={}", settings.port);
        let (mut socket, _peer) = listener.accept().await.expect("accept");

        // Server handshake, in the order the protocol actually requires:
        // read C0+C1 (1537), write S0+S1+S2 (3073), then read C2 (1536).
        //
        // Reading all 3073 client bytes up front deadlocks, because the client
        // waits for S0S1S2 before it will send C2 and the server is not yet
        // sending anything: the first version of this sink did exactly that
        // and hung, which is the kind of thing a bench has to get right rather
        // than paper over with a timeout.
        let _c0c1 = read_exact_n(&mut socket, 1537).await;
        let mut server_hello = vec![0x03u8];
        server_hello.extend(std::iter::repeat_n(0x22u8, 3072));
        socket
            .write_all(server_hello)
            .await
            .0
            .expect("write S0S1S2");
        let _c2 = read_exact_n(&mut socket, 1536).await;

        // Chunk parse loop: header, then discard `length` payload bytes.
        let cpu0 = cpu_ms();
        let wall0 = Instant::now();
        let mut bytes = 0usize;
        let mut messages = 0usize;
        let scratch = vec![0u8; 65_536];
        // A real RTMP server answers `connect`, `createStream` and `publish`
        // before the publisher streams. Without these replies the publisher
        // blocks on its own handshake waits forever -- which is what the first
        // version of this bench did. The replies are written in command order
        // rather than from parsed AMF: the sink is a transport endpoint, and
        // the publisher's real waits are what belongs in the measurement.
        let mut replies_sent = 0;
        loop {
            let Some(header) = read_exact_n(&mut socket, HEADER).await else {
                break;
            };
            let length =
                ((header[5] as usize) << 16) | ((header[6] as usize) << 8) | header[7] as usize;
            // Extended timestamp: a fmt-0 header whose 3-byte timestamp is
            // 0xFFFFFF carries 4 more bytes before the payload.
            if header[1] == 0xFF
                && header[2] == 0xFF
                && header[3] == 0xFF
                && read_exact_n(&mut socket, 4).await.is_none()
            {
                break;
            }
            let mut remaining = length;
            while remaining > 0 {
                let take = remaining.min(scratch.len());
                match socket.read(scratch[..take].to_vec()).await.0 {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        remaining -= n;
                        bytes += n;
                    }
                }
            }
            if remaining > 0 {
                break;
            }
            messages += 1;
            if messages == replies_sent + 1 && replies_sent < 3 {
                let reply = server_reply(replies_sent, &stream_name);
                socket.write_all(reply).await.0.ok();
                replies_sent += 1;
            }
        }
        let wall_s = wall0.elapsed().as_secs_f64();
        (bytes, messages, cpu_ms() - cpu0, wall_s)
    });

    let (bytes, messages, cpu_ms, wall_s) = report;
    let mbits = bytes as f64 * 8.0 / 1e6;
    println!(
        "RTMP_SINK mode={} bytes_MB={:.2} messages={} wall_s={:.3} achieved_mbit_s={:.2} \
         cpu_ms={:.1} cpu_ms_per_Mbit={:.3}",
        settings.mode,
        bytes as f64 / 1e6,
        messages,
        wall_s,
        mbits / wall_s.max(1e-9),
        cpu_ms,
        cpu_ms / mbits.max(1e-9),
    );
}

// --------------------------------------------------------------------------
// publisher: RTMP client side, Compio TCP
// --------------------------------------------------------------------------

fn run_publisher(settings: &Settings) {
    let runtime = compio::runtime::Runtime::new().expect("compio runtime");
    let report = runtime.block_on(async {
        let mut socket = compio::net::TcpStream::connect(("127.0.0.1", settings.port))
            .await
            .expect("connect to sink");

        if settings.mode == "rtmp" {
            let mut handshake = Vec::with_capacity(1537);
            handshake.push(0x03);
            handshake.extend(std::iter::repeat_n(0x11u8, 1536));
            socket.write_all(handshake).await.0.expect("write C0C1");
            let reply = read_exact_n(&mut socket, 3073)
                .await
                .unwrap_or_else(|| vec![0u8; 3073]);
            socket
                .write_all(reply[1..1537].to_vec())
                .await
                .0
                .expect("write C2");

            let mut set_chunk = Vec::new();
            chunk(
                &mut set_chunk,
                2,
                MSG_SET_CHUNK_SIZE,
                0,
                &(settings.chunk as u32).to_be_bytes(),
            );
            socket
                .write_all(set_chunk)
                .await
                .0
                .expect("write set chunk size");

            let mut payload = Vec::new();
            amf_string(&mut payload, "connect");
            amf_number(&mut payload, 1.0);
            amf_object(
                &mut payload,
                &[
                    ("app", settings.app.as_str()),
                    ("type", "nonprivate"),
                    ("flashVer", "FMLE/3.0 (compatible; srt-bench)"),
                    (
                        "tcUrl",
                        &format!("rtmp://127.0.0.1:{}/{}", settings.port, settings.app),
                    ),
                ],
            );
            let mut message = Vec::new();
            chunk(&mut message, 3, MSG_AMF0_COMMAND, 0, &payload);
            socket.write_all(message).await.0.expect("write connect");
            read_some(&mut socket, 4096).await;

            let mut payload = Vec::new();
            amf_string(&mut payload, "createStream");
            amf_number(&mut payload, 2.0);
            amf_null(&mut payload);
            let mut message = Vec::new();
            chunk(&mut message, 3, MSG_AMF0_COMMAND, 0, &payload);
            socket
                .write_all(message)
                .await
                .0
                .expect("write createStream");
            read_some(&mut socket, 4096).await;

            let mut payload = Vec::new();
            amf_string(&mut payload, "publish");
            amf_number(&mut payload, 3.0);
            amf_null(&mut payload);
            amf_string(&mut payload, settings.stream.as_str());
            amf_string(&mut payload, "live");
            let mut message = Vec::new();
            chunk(&mut message, 4, MSG_AMF0_COMMAND, 1, &payload);
            socket.write_all(message).await.0.expect("write publish");
            read_some(&mut socket, 4096).await;
        }

        let body = vec![0x42u8; settings.chunk];
        let mut framed = Vec::with_capacity(settings.chunk + HEADER);
        let total = settings.total_bytes();
        // Pace to the target bitrate: media is real-time, and an unpaced
        // publisher measures socket buffering rather than sustained cost. The
        // interval is per chunk, so the same code serves any write size.
        let interval =
            std::time::Duration::from_secs_f64(settings.chunk as f64 * 8.0 / (settings.mbit * 1e6));
        let epoch = Instant::now();
        let cpu0 = cpu_ms();
        let wall0 = Instant::now();
        let deadline = epoch + std::time::Duration::from_secs(settings.seconds);
        let mut written = 0usize;
        let mut writes = 0usize;
        while written < total {
            if settings.pace {
                let due = epoch + interval * writes as u32;
                let now = Instant::now();
                if due > now {
                    compio::time::sleep(due - now).await;
                }
            } else if Instant::now() >= deadline {
                break;
            }
            let buffer = if settings.mode == "rtmp" {
                framed.clear();
                chunk(&mut framed, 6, MSG_VIDEO, 1, &body);
                framed.clone()
            } else {
                body.clone()
            };
            match socket.write_all(buffer).await.0 {
                Ok(_) => {
                    written += settings.chunk;
                    writes += 1;
                }
                Err(e) => {
                    eprintln!("publisher: write failed after {written} bytes: {e}");
                    break;
                }
            }
        }
        let wall_s = wall0.elapsed().as_secs_f64();
        (written, writes, cpu_ms() - cpu0, wall_s)
    });

    let (written, writes, cpu_ms, wall_s) = report;
    let mbits = written as f64 * 8.0 / 1e6;
    println!(
        "RTMP_PUB mode={} chunk={} written_MB={:.2} writes={} wall_s={:.3} \
         achieved_mbit_s={:.2} cpu_ms={:.1} cpu_ms_per_Mbit={:.3} us_cpu_per_write={:.3} paced={}",
        settings.mode,
        settings.chunk,
        written as f64 / 1e6,
        writes,
        wall_s,
        mbits / wall_s.max(1e-9),
        cpu_ms,
        cpu_ms / mbits.max(1e-9),
        cpu_ms * 1000.0 / writes.max(1) as f64,
        settings.pace,
    );
}

// --------------------------------------------------------------------------
// driver: spawn the sink, publish, then report both sides
// --------------------------------------------------------------------------

fn run_driver(settings: &Settings) {
    let self_path = std::env::current_exe().expect("current exe");
    let sink = Command::new(self_path)
        .args([
            "sink",
            "--port",
            &settings.port.to_string(),
            "--mode",
            &settings.mode,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn sink");

    // Give the sink time to bind before the publisher connects. A fixed sleep
    // is enough for a listener that only has to reach `bind`, and the
    // publisher's connect failure would be reported rather than hidden.
    std::thread::sleep(std::time::Duration::from_millis(700));
    run_publisher(settings);
    let output = sink.wait_with_output().expect("sink output");
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let settings = Settings::from_args(&args);
    match args.get(1).map(String::as_str) {
        Some("sink") => run_sink(&settings),
        Some("pub") => run_publisher(&settings),
        _ => run_driver(&settings),
    }
}
